"""
AEGIS FastAPI Server
======================

REST API + WebSocket for the AEGIS Web UI.
Provides endpoints for starting pentests, monitoring progress,
and retrieving reports.
"""

import asyncio
import json
import uuid
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from loguru import logger

from aegis import __version__
from aegis.config import config
from aegis.core.agent import PentestAgent
from aegis.core.ai_engine import AIEngine
from aegis.reporting.generator import ReportGenerator


# ─── State Management ─────────────────────────────────────────────

class AppState:
    """Application-level state for tracking active pentests."""
    def __init__(self):
        self.active_pentests: dict[str, PentestAgent] = {}
        self.completed_pentests: dict[str, dict] = {}
        self.websocket_connections: dict[str, list[WebSocket]] = {}
        self.ai_engine = AIEngine()

app_state = AppState()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    logger.info("AEGIS API Server starting")
    yield
    logger.info("AEGIS API Server shutting down")
    # Stop all active pentests
    for agent in app_state.active_pentests.values():
        agent.stop()


# ─── FastAPI App ───────────────────────────────────────────────────

app = FastAPI(
    title="AEGIS API",
    description="AI-Augmented Penetration Testing Assistant",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Serve Web UI Static Files ────────────────────────────────────

UI_DIR = config.project_root / "ui"
if UI_DIR.exists():
    @app.get("/dashboard", include_in_schema=False)
    async def serve_dashboard():
        """Serve the AEGIS dashboard UI."""
        return FileResponse(UI_DIR / "index.html")

    # Mount static assets (CSS, JS) — must come after API routes
    # so API paths take priority
    app.mount("/ui", StaticFiles(directory=str(UI_DIR)), name="ui")


# ─── Request/Response Models ──────────────────────────────────────

class PentestRequest(BaseModel):
    target: str = Field(..., description="Target IP, domain, or URL")
    scope: str = Field(default="full", description="Scan scope: full, web, network, recon")
    depth: str = Field(default="standard", description="Scan depth: quick, standard, deep")
    max_iterations: Optional[int] = Field(default=None, description="Max AI iterations")
    interactive: bool = Field(default=True, description="Interactive mode (confirm each step)")

class ConfirmRequest(BaseModel):
    choice: int = Field(default=0, description="Index of the chosen suggestion (0-based)")

class PentestStatus(BaseModel):
    id: str
    target: str
    scope: str
    is_running: bool
    interactive: bool = True
    total_steps: int
    total_findings: int
    overall_risk: str
    risk_summary: dict
    pending_confirmation: bool = False

class ModelInfo(BaseModel):
    name: str
    status: str


# ─── REST Endpoints ───────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "name": "AEGIS API",
        "version": __version__,
        "status": "running",
        "active_pentests": len(app_state.active_pentests),
    }


@app.post("/api/pentest/start", response_model=dict)
async def start_pentest(request: PentestRequest):
    """Start a new autonomous penetration test."""
    pentest_id = str(uuid.uuid4())[:12]

    agent = PentestAgent(
        target=request.target,
        scope=request.scope,
        ai_engine=app_state.ai_engine,
        interactive=request.interactive,
    )

    if request.max_iterations:
        agent.max_iterations = request.max_iterations

    # Register WebSocket broadcast callback
    async def broadcast_event(event):
        event["pentest_id"] = pentest_id
        connections = app_state.websocket_connections.get(pentest_id, [])
        for ws in connections:
            try:
                await ws.send_json(event)
            except Exception:
                pass

    agent.on_event(broadcast_event)

    app_state.active_pentests[pentest_id] = agent

    # Run pentest in background
    asyncio.create_task(_run_pentest_task(pentest_id, agent))

    return {
        "id": pentest_id,
        "target": request.target,
        "scope": request.scope,
        "interactive": request.interactive,
        "status": "started",
        "message": f"Pentest started. Connect to WebSocket /ws/{pentest_id} for live updates.",
    }


async def _run_pentest_task(pentest_id: str, agent: PentestAgent):
    """Background task to run a pentest."""
    try:
        results = await agent.run()

        # Generate report
        report_gen = ReportGenerator(ai_engine=agent.ai)
        report = await report_gen.generate(chain=agent.chain, format="both")

        app_state.completed_pentests[pentest_id] = {
            "results": results,
            "report": report,
        }
    except Exception as e:
        logger.error(f"Pentest {pentest_id} failed: {e}")
    finally:
        app_state.active_pentests.pop(pentest_id, None)


@app.get("/api/pentest/{pentest_id}/status")
async def get_pentest_status(pentest_id: str):
    """Get status of a running or completed pentest."""
    if pentest_id in app_state.active_pentests:
        return app_state.active_pentests[pentest_id].get_status()
    if pentest_id in app_state.completed_pentests:
        return app_state.completed_pentests[pentest_id]["results"]
    raise HTTPException(status_code=404, detail="Pentest not found")


@app.post("/api/pentest/{pentest_id}/stop")
async def stop_pentest(pentest_id: str):
    """Stop a running pentest."""
    if pentest_id not in app_state.active_pentests:
        raise HTTPException(status_code=404, detail="Pentest not found or already stopped")
    app_state.active_pentests[pentest_id].stop()
    return {"status": "stopping", "id": pentest_id}


@app.get("/api/pentest/{pentest_id}/report")
async def get_report(pentest_id: str):
    """Get the generated report for a completed pentest."""
    if pentest_id in app_state.completed_pentests:
        return app_state.completed_pentests[pentest_id]["report"]
    if pentest_id in app_state.active_pentests:
        raise HTTPException(status_code=202, detail="Pentest still running")
    raise HTTPException(status_code=404, detail="Pentest not found")


@app.get("/api/pentests")
async def list_pentests():
    """List all active and completed pentests."""
    return {
        "active": [
            {"id": pid, **agent.get_status()}
            for pid, agent in app_state.active_pentests.items()
        ],
        "completed": list(app_state.completed_pentests.keys()),
    }


@app.get("/api/models")
async def list_models():
    """List available AI models."""
    models = await app_state.ai_engine.list_available_models()
    return {
        "models": [{"name": m, "status": "available"} for m in models],
        "configured": {
            "reasoning": config.ai.reasoning_model,
            "code": config.ai.code_model,
            "report": config.ai.report_model,
            "vulnerability": config.ai.vuln_model,
        },
    }


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": __version__}


# ─── Step Confirmation Endpoints ──────────────────────────────────

@app.post("/api/pentest/{pentest_id}/confirm")
async def confirm_step(pentest_id: str, request: ConfirmRequest):
    """Confirm a suggested step — the agent will execute the chosen option."""
    if pentest_id not in app_state.active_pentests:
        raise HTTPException(status_code=404, detail="Pentest not found or not running")
    agent = app_state.active_pentests[pentest_id]
    if not agent.interactive:
        raise HTTPException(status_code=400, detail="Pentest is in auto mode, no confirmation needed")
    agent.confirm_step(request.choice)
    return {"status": "confirmed", "choice": request.choice, "id": pentest_id}


@app.post("/api/pentest/{pentest_id}/skip")
async def skip_step(pentest_id: str):
    """Skip the current suggested step."""
    if pentest_id not in app_state.active_pentests:
        raise HTTPException(status_code=404, detail="Pentest not found or not running")
    agent = app_state.active_pentests[pentest_id]
    agent.skip_step()
    return {"status": "skipped", "id": pentest_id}


@app.post("/api/pentest/{pentest_id}/auto")
async def toggle_auto_mode(pentest_id: str):
    """Toggle interactive/auto mode for a running pentest."""
    if pentest_id not in app_state.active_pentests:
        raise HTTPException(status_code=404, detail="Pentest not found or not running")
    agent = app_state.active_pentests[pentest_id]
    new_mode = not agent.interactive
    agent.set_interactive(new_mode)
    return {
        "status": "toggled",
        "interactive": new_mode,
        "id": pentest_id,
        "message": f"Interactive mode {'enabled' if new_mode else 'disabled (full auto)'}.",
    }


# ─── WebSocket for Live Updates ───────────────────────────────────

@app.websocket("/ws/{pentest_id}")
async def websocket_endpoint(websocket: WebSocket, pentest_id: str):
    """WebSocket for live pentest updates and step confirmations."""
    await websocket.accept()

    if pentest_id not in app_state.websocket_connections:
        app_state.websocket_connections[pentest_id] = []
    app_state.websocket_connections[pentest_id].append(websocket)

    logger.info(f"WebSocket connected for pentest {pentest_id}")

    try:
        while True:
            data = await websocket.receive_text()

            if data == "ping":
                await websocket.send_json({"type": "pong"})
                continue

            # Handle JSON messages for step confirmation
            try:
                msg = json.loads(data)
                msg_type = msg.get("type", "")

                if pentest_id in app_state.active_pentests:
                    agent = app_state.active_pentests[pentest_id]

                    if msg_type == "confirm":
                        choice = msg.get("choice", 0)
                        agent.confirm_step(choice)
                        await websocket.send_json({
                            "type": "confirmation_ack",
                            "choice": choice,
                        })
                    elif msg_type == "skip":
                        agent.skip_step()
                        await websocket.send_json({"type": "skip_ack"})
                    elif msg_type == "auto":
                        agent.set_interactive(not agent.interactive)
                        await websocket.send_json({
                            "type": "auto_ack",
                            "interactive": agent.interactive,
                        })
            except (json.JSONDecodeError, KeyError):
                pass  # Not JSON or missing fields — ignore

    except WebSocketDisconnect:
        app_state.websocket_connections[pentest_id].remove(websocket)
        logger.info(f"WebSocket disconnected for pentest {pentest_id}")


# ─── Server Entry Point ──────────────────────────────────────────

def start_server():
    """Start the AEGIS API server."""
    import uvicorn
    uvicorn.run(
        "aegis.api.server:app",
        host=config.web_ui.host,
        port=config.web_ui.port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    start_server()
