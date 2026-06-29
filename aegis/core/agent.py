"""
AEGIS Pentest Agent — Main Autonomous Loop
============================================

Orchestrates the full autonomous penetration test:
  1. Reconnaissance
  2. AI-driven attack planning
  3. Command execution
  4. Result analysis and chaining
  5. Report generation

Supports interactive mode where the user confirms each step
before execution, with AI-ranked suggestions to choose from.
"""

import asyncio
import json
import time
from typing import Optional
from loguru import logger

from aegis.config import config
from aegis.core.ai_engine import AIEngine
from aegis.core.executor import TerminalExecutor
from aegis.core.chain import (
    AttackChain, AttackStep, Finding, StepStatus, Severity,
)


class PentestAgent:
    """
    The main autonomous penetration testing agent.
    Coordinates AI reasoning, tool execution, and attack chaining.

    Supports interactive mode: after each step, AI suggests ranked
    next actions and waits for user confirmation before proceeding.
    """

    def __init__(
        self,
        target: str,
        scope: str = "full",
        ai_engine: Optional[AIEngine] = None,
        executor: Optional[TerminalExecutor] = None,
        interactive: bool = True,
    ):
        self.target = target
        self.scope = scope
        self.ai = ai_engine or AIEngine()
        self.executor = executor or TerminalExecutor()
        self.chain = AttackChain(target, scope)
        self.session_id = f"pentest_{self.chain.id}"
        self.max_iterations = config.execution.max_attack_iterations
        self.is_running = False
        self._callbacks: list = []

        # ─── Tool Availability ───────────────────────────────────
        self._available_tools_info: str = ""
        self._failed_tools: set[str] = set()  # Tools that failed due to not being installed

        # ─── Interactive Mode State ───────────────────────────────
        self.interactive = interactive
        self._confirmation_event = asyncio.Event()
        self._user_choice: Optional[int] = None  # index of chosen suggestion
        self._user_skipped: bool = False
        self._pending_suggestions: list[dict] = []

        logger.info(f"PentestAgent created — target={target}, scope={scope}, interactive={interactive}")

    # ─── Event Callbacks ──────────────────────────────────────────

    def on_event(self, callback):
        """Register a callback for agent events (for UI updates)."""
        self._callbacks.append(callback)

    async def _emit(self, event_type: str, data: dict):
        """Emit an event to all registered callbacks."""
        event = {"type": event_type, "timestamp": time.time(), **data}
        for cb in self._callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(event)
                else:
                    cb(event)
            except Exception as e:
                logger.error(f"Event callback error: {e}")

    # ─── Interactive Confirmation API ─────────────────────────────

    def confirm_step(self, choice_index: int = 0):
        """
        User confirms a suggested step.

        Args:
            choice_index: Index of the chosen suggestion (0-based).
        """
        self._user_choice = choice_index
        self._user_skipped = False
        self._confirmation_event.set()
        logger.info(f"User confirmed suggestion #{choice_index + 1}")

    def skip_step(self):
        """User skips all current suggestions."""
        self._user_skipped = True
        self._user_choice = None
        self._confirmation_event.set()
        logger.info("User skipped current suggestions")

    def set_interactive(self, enabled: bool):
        """Toggle interactive mode on/off during a pentest."""
        self.interactive = enabled
        if not enabled:
            # Unblock any pending confirmation
            self._confirmation_event.set()
        logger.info(f"Interactive mode {'enabled' if enabled else 'disabled (auto mode)'}")

    async def _wait_for_confirmation(self) -> tuple[Optional[int], bool]:
        """
        Wait for user to confirm or skip.
        Returns (choice_index, was_skipped).
        """
        self._confirmation_event.clear()
        self._user_choice = None
        self._user_skipped = False
        await self._confirmation_event.wait()
        return self._user_choice, self._user_skipped

    # ─── Main Pentest Loop ────────────────────────────────────────

    async def run(self) -> dict:
        """
        Execute the full autonomous penetration test.

        Returns:
            dict with complete pentest results
        """
        self.is_running = True
        logger.info(f"{'='*60}")
        logger.info(f"AEGIS AUTONOMOUS PENTEST STARTING")
        logger.info(f"Target: {self.target}")
        logger.info(f"Scope: {self.scope}")
        logger.info(f"Max Iterations: {self.max_iterations}")
        logger.info(f"Interactive Mode: {self.interactive}")
        logger.info(f"{'='*60}")

        # ─── Check Tool Availability ─────────────────────────────
        tool_paths = self.executor.check_tool_availability()
        self._available_tools_info = self.executor.get_available_tools_info()
        available_tools = self.executor.get_available_tools()

        logger.info(f"Available security tools: {available_tools or ['none — will use Python fallbacks']}")

        await self._emit("tool_check", {
            "available_tools": available_tools,
            "tools_info": self._available_tools_info,
        })

        await self._emit("pentest_start", {
            "target": self.target,
            "scope": self.scope,
            "interactive": self.interactive,
        })

        try:
            # Phase 1: Initial Reconnaissance
            await self._phase_recon()

            # Phase 2: AI-Driven Attack Loop
            await self._phase_attack_loop()

            # Phase 3: Compile Results
            self.chain.complete()

            await self._emit("pentest_complete", {
                "chain": self.chain.to_dict(),
            })

        except Exception as e:
            logger.error(f"Pentest error: {e}")
            self.chain.status = "error"
            await self._emit("pentest_error", {"error": str(e)})
            raise
        finally:
            self.is_running = False

        return self.chain.to_dict()

    # ─── Phase 1: Reconnaissance ──────────────────────────────────

    async def _phase_recon(self):
        """Execute initial reconnaissance scans with interactive confirmation."""
        logger.info("[Phase 1] Starting Reconnaissance")
        await self._emit("phase_start", {"phase": "reconnaissance"})

        recon_commands = self._get_recon_commands()

        if not recon_commands:
            logger.warning("[Phase 1] No recon commands available — no security tools found")
            await self._emit("phase_warning", {
                "phase": "reconnaissance",
                "message": "No security scanning tools found. The AI will use Python-based alternatives.",
            })

        for i, cmd_info in enumerate(recon_commands):
            # In interactive mode, show the upcoming recon step and ask for confirmation
            if self.interactive:
                remaining = recon_commands[i:]
                suggestions = []
                for j, cmd in enumerate(remaining):
                    suggestions.append({
                        "rank": j + 1,
                        "reasoning": cmd["reason"],
                        "tool": cmd["tool"],
                        "command": cmd["command"],
                        "expected_result": cmd["expected"],
                        "risk_level": "low",
                        "confidence": 0.95 - (j * 0.1),
                        "category": "recon",
                    })

                self._pending_suggestions = suggestions

                await self._emit("step_suggestions", {
                    "phase": "reconnaissance",
                    "suggestions": suggestions,
                    "overall_assessment": f"Reconnaissance phase: {len(remaining)} scans remaining",
                    "step_number": len(self.chain.steps) + 1,
                })

                choice, skipped = await self._wait_for_confirmation()

                if not self.is_running:
                    return

                if skipped:
                    await self._emit("step_skipped", {
                        "step_number": len(self.chain.steps) + 1,
                        "phase": "reconnaissance",
                    })
                    continue

                # If user picked a different suggestion, use that command
                if choice is not None and choice < len(suggestions):
                    cmd_info = {
                        "tool": suggestions[choice]["tool"],
                        "command": suggestions[choice]["command"],
                        "reason": suggestions[choice]["reasoning"],
                        "expected": suggestions[choice]["expected_result"],
                    }

                await self._emit("step_confirmed", {
                    "step_number": len(self.chain.steps) + 1,
                    "choice": choice if choice is not None else 0,
                })

            # Execute the recon step
            step = self.chain.add_step({
                "reasoning": cmd_info["reason"],
                "tool": cmd_info["tool"],
                "command": cmd_info["command"],
                "expected_result": cmd_info["expected"],
                "risk_level": "low",
            })

            await self._emit("step_start", {
                "step": step.step_number,
                "command": step.command,
                "reasoning": step.reasoning,
            })

            result = await self.executor.execute(cmd_info["command"])

            # Track tools that failed because they're not installed
            if result.error and ("not installed" in result.error.lower() or "not found" in result.error.lower()):
                tool_name = cmd_info.get("tool", "")
                self._failed_tools.add(tool_name)
                logger.warning(f"Tool '{tool_name}' is not available, marking as failed")

            self.chain.complete_step(
                step,
                result=result.output,
                status=StepStatus.SUCCESS if result.success else StepStatus.FAILED,
                duration=result.duration,
            )

            await self._emit("step_complete", {
                "step": step.step_number,
                "status": step.status.value,
                "output_preview": result.stdout[:500],
            })

        logger.info("[Phase 1] Reconnaissance complete")

    def _get_recon_commands(self) -> list[dict]:
        """
        Get reconnaissance commands based on scope.
        Only includes commands for tools that are actually available.
        Falls back to Python-based alternatives when tools are missing.
        """
        commands = []

        # ─── Port Scanning ───────────────────────────────────────
        if self.executor.is_tool_available("nmap"):
            nmap_path = self.executor._tool_paths.get("nmap", "nmap")
            commands.append({
                "tool": "nmap",
                "command": f"{nmap_path} -sV -sC -T4 --open {self.target}",
                "reason": "Initial port scan with version detection, default scripts, and OS detection",
                "expected": "Open ports, service versions, and OS fingerprint",
            })
        else:
            # Python-based fallback port scanner
            commands.append({
                "tool": "python",
                "command": (
                    f'python -c "'
                    f"import socket, ssl, sys; "
                    f"target='{self.target}'.replace('https://','').replace('http://','').rstrip('/'); "
                    f"ports=[21,22,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443]; "
                    f"print(f'Scanning {{target}}...'); "
                    f"[print(f'  Port {{p}}: OPEN') for p in ports if (lambda p: (lambda s: (s.settimeout(2), not s.connect_ex((target,p)), s.close())[-2])(socket.socket()))(p)]; "
                    f"print('Scan complete')"
                    f'"'
                ),
                "reason": "Python-based port scan (nmap not available) — checks common ports",
                "expected": "Open ports on the target",
            })

        # ─── Web Scanning ────────────────────────────────────────
        if self.scope in ("full", "web"):
            if self.executor.is_tool_available("nmap"):
                nmap_path = self.executor._tool_paths.get("nmap", "nmap")
                commands.append({
                    "tool": "nmap",
                    "command": f"{nmap_path} -sV --script=vuln -p 80,443,8080,8443 {self.target}",
                    "reason": "Vulnerability scan on common web ports",
                    "expected": "Known vulnerabilities in web services",
                })

            # Python/curl-based web fingerprinting (replaces whatweb)
            commands.append({
                "tool": "curl",
                "command": f"curl -sI -L --max-time 10 {self.target}",
                "reason": "HTTP header analysis for technology fingerprinting (replaces whatweb)",
                "expected": "Server headers, technology stack clues, security headers",
            })

        if self.scope == "full":
            if self.executor.is_tool_available("nmap"):
                nmap_path = self.executor._tool_paths.get("nmap", "nmap")
                commands.append({
                    "tool": "nmap",
                    "command": f"{nmap_path} -sU -sV --top-ports 20 -T4 {self.target}",
                    "reason": "UDP scan on top 20 ports for services like DNS, SNMP, TFTP",
                    "expected": "Open UDP services",
                })

        return commands

    # ─── Phase 2: AI Attack Loop ──────────────────────────────────

    async def _phase_attack_loop(self):
        """AI-driven attack loop with interactive confirmation."""
        logger.info("[Phase 2] Starting AI-Driven Attack Loop")
        await self._emit("phase_start", {"phase": "attack_loop"})

        iteration = 0
        consecutive_failures = 0
        max_consecutive_failures = 3
        # Track repeated identical commands to break infinite loops
        _recent_commands: list[str] = []

        while iteration < self.max_iterations and self.is_running:
            iteration += 1
            logger.info(f"\n--- Iteration {iteration}/{self.max_iterations} ---")

            # Get AI suggestions (ranked list)
            try:
                findings_data = [s.to_dict() for s in self.chain.steps]
                chain_data = [s.to_dict() for s in self.chain.get_successful_steps()]

                suggestions_result = await self.ai.suggest_next_steps(
                    target=self.target,
                    findings=findings_data,
                    attack_chain=chain_data,
                    session_id=self.session_id,
                    available_tools_info=self._available_tools_info,
                )
            except Exception as e:
                logger.error(f"AI suggestion error: {e}")
                consecutive_failures += 1
                if consecutive_failures >= max_consecutive_failures:
                    logger.warning("Too many AI failures, ending attack loop")
                    break
                # Wait a bit before retrying (helps with transient CUDA errors)
                await asyncio.sleep(2)
                continue

            suggestions = suggestions_result.get("suggestions", [])
            assessment = suggestions_result.get("overall_assessment", "")

            if not suggestions:
                logger.warning("AI returned no suggestions, checking completion")
                if await self._check_completion(iteration):
                    break
                continue

            # Filter out suggestions without commands
            suggestions = [s for s in suggestions if s.get("command")]
            if not suggestions:
                logger.warning("AI suggestions have no valid commands")
                if await self._check_completion(iteration):
                    break
                continue

            # ─── Filter out suggestions for failed/missing tools ──
            filtered_suggestions = []
            for s in suggestions:
                tool = s.get("tool", "").lower()
                cmd = s.get("command", "")
                # Skip if this tool already failed due to not being installed
                if tool in self._failed_tools:
                    logger.info(f"Skipping suggestion for unavailable tool: {tool}")
                    continue
                # Skip if this exact command was already tried recently
                if cmd in _recent_commands[-5:]:
                    logger.info(f"Skipping repeated command: {cmd[:60]}...")
                    continue
                filtered_suggestions.append(s)

            if not filtered_suggestions:
                logger.warning("All AI suggestions were filtered out (tools not available or repeated)")
                if await self._check_completion(iteration):
                    break
                # If we still have iterations, the AI needs to know it should try different approaches
                consecutive_failures += 1
                if consecutive_failures >= max_consecutive_failures:
                    logger.warning("Too many consecutive failures, ending attack loop")
                    break
                continue

            suggestions = filtered_suggestions

            # ─── Interactive: Show suggestions and wait ───────────
            if self.interactive:
                self._pending_suggestions = suggestions

                await self._emit("step_suggestions", {
                    "phase": "attack_loop",
                    "suggestions": suggestions,
                    "overall_assessment": assessment,
                    "step_number": len(self.chain.steps) + 1,
                    "iteration": iteration,
                    "max_iterations": self.max_iterations,
                })

                choice, skipped = await self._wait_for_confirmation()

                if not self.is_running:
                    break

                if skipped:
                    await self._emit("step_skipped", {
                        "step_number": len(self.chain.steps) + 1,
                        "iteration": iteration,
                    })
                    continue

                # Use the chosen suggestion (default to first)
                chosen_index = choice if choice is not None else 0
                if chosen_index >= len(suggestions):
                    chosen_index = 0
                ai_decision = suggestions[chosen_index]

                await self._emit("step_confirmed", {
                    "step_number": len(self.chain.steps) + 1,
                    "choice": chosen_index,
                    "command": ai_decision.get("command", ""),
                })
            else:
                # Auto mode: pick the top-ranked suggestion
                ai_decision = suggestions[0]

            # ─── Execute the chosen step ──────────────────────────
            step = self.chain.add_step(ai_decision, parent_step=iteration - 1)

            await self._emit("step_start", {
                "step": step.step_number,
                "command": step.command,
                "reasoning": step.reasoning,
                "tool": step.tool,
            })

            logger.info(f"[AI Reasoning] {step.reasoning}")
            logger.info(f"[Executing] {step.command}")

            # Track recent commands to detect loops
            _recent_commands.append(step.command)

            result = await self.executor.execute(step.command)

            # Determine step status
            if result.success:
                status = StepStatus.SUCCESS
                consecutive_failures = 0
            else:
                status = StepStatus.FAILED
                consecutive_failures += 1

                # Track tools that failed because they're not installed
                if result.error and ("not installed" in result.error.lower() or "not found" in result.error.lower()):
                    tool_name = ai_decision.get("tool", "").lower()
                    if tool_name:
                        self._failed_tools.add(tool_name)
                        logger.warning(
                            f"Tool '{tool_name}' is not available, will not suggest again. "
                            f"Failed tools: {self._failed_tools}"
                        )

            self.chain.complete_step(
                step,
                result=result.output,
                status=status,
                duration=result.duration,
            )

            await self._emit("step_complete", {
                "step": step.step_number,
                "status": status.value,
                "output_preview": result.stdout[:500],
            })

            # Check for completion periodically
            if iteration % 5 == 0 or consecutive_failures >= max_consecutive_failures:
                if await self._check_completion(iteration):
                    break

        logger.info(f"[Phase 2] Attack loop ended after {iteration} iterations")

    async def _check_completion(self, iteration: int) -> bool:
        """Ask AI if the pentest is complete."""
        try:
            findings_data = [s.to_dict() for s in self.chain.steps]
            chain_data = [s.to_dict() for s in self.chain.get_successful_steps()]

            result = await self.ai.check_completion(
                findings=findings_data,
                attack_chain=chain_data,
                iteration=iteration,
                max_iterations=self.max_iterations,
            )
            is_complete = result.get("is_complete", False)
            if is_complete:
                logger.info(f"AI says pentest is complete: {result.get('reason', 'N/A')}")
            return is_complete
        except Exception as e:
            logger.error(f"Completion check error: {e}")
            return False

    # ─── Utility ──────────────────────────────────────────────────

    def stop(self):
        """Stop the running pentest."""
        self.is_running = False
        # Unblock any pending confirmation wait
        self._confirmation_event.set()
        logger.info("Pentest stop requested")

    def get_status(self) -> dict:
        """Get current agent status."""
        return {
            "target": self.target,
            "scope": self.scope,
            "is_running": self.is_running,
            "interactive": self.interactive,
            "chain_status": self.chain.status,
            "total_steps": len(self.chain.steps),
            "total_findings": len(self.chain.findings),
            "risk_summary": self.chain.get_risk_summary(),
            "overall_risk": self.chain.get_overall_risk(),
            "pending_confirmation": not self._confirmation_event.is_set() and self.interactive,
            "pending_suggestions": self._pending_suggestions if not self._confirmation_event.is_set() else [],
        }
