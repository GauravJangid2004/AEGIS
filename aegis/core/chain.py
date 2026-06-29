"""
AEGIS Attack Chain Builder
===========================

Manages the attack chain — a sequence of linked attack steps where
each result feeds into the AI's decision for the next step.
"""

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any
from loguru import logger


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A vulnerability or interesting finding."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    cvss_score: float = 0.0
    cve_id: Optional[str] = None
    evidence: str = ""
    remediation: str = ""
    service: str = ""
    port: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id,
            "evidence": self.evidence[:2000],
            "remediation": self.remediation,
            "service": self.service,
            "port": self.port,
        }


@dataclass
class AttackStep:
    """A single step in the attack chain."""
    step_number: int
    reasoning: str
    tool: str
    command: str
    expected_result: str = ""
    actual_result: str = ""
    status: StepStatus = StepStatus.PENDING
    risk_level: str = "low"
    on_success: str = ""
    on_failure: str = ""
    findings: list[Finding] = field(default_factory=list)
    timestamp: str = ""
    duration: float = 0.0
    parent_step: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "step_number": self.step_number,
            "reasoning": self.reasoning,
            "tool": self.tool,
            "command": self.command,
            "expected_result": self.expected_result,
            "actual_result": self.actual_result[:2000],
            "status": self.status.value,
            "risk_level": self.risk_level,
            "on_success": self.on_success,
            "on_failure": self.on_failure,
            "findings": [f.to_dict() for f in self.findings],
            "timestamp": self.timestamp,
            "duration": round(self.duration, 2),
            "parent_step": self.parent_step,
        }


class AttackChain:
    """
    Manages the full attack chain for a penetration test.
    Tracks steps, findings, and provides chain analysis.
    """

    def __init__(self, target: str, scope: str = "full"):
        self.id = str(uuid.uuid4())[:12]
        self.target = target
        self.scope = scope
        self.steps: list[AttackStep] = []
        self.findings: list[Finding] = []
        self.start_time = time.strftime("%Y-%m-%d %H:%M:%S")
        self.end_time: Optional[str] = None
        self.status = "in_progress"
        logger.info(f"Attack chain initialized — target={target}, scope={scope}")

    def add_step(self, ai_decision: dict, parent_step: Optional[int] = None) -> AttackStep:
        """Create and add a new attack step from AI decision."""
        step = AttackStep(
            step_number=len(self.steps) + 1,
            reasoning=ai_decision.get("reasoning", ""),
            tool=ai_decision.get("tool", "unknown"),
            command=ai_decision.get("command", ""),
            expected_result=ai_decision.get("expected_result", ""),
            risk_level=ai_decision.get("risk_level", "low"),
            on_success=ai_decision.get("on_success", ""),
            on_failure=ai_decision.get("on_failure", ""),
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            parent_step=parent_step,
        )
        self.steps.append(step)
        logger.info(f"Step {step.step_number} added: [{step.tool}] {step.command[:80]}")
        return step

    def complete_step(
        self,
        step: AttackStep,
        result: str,
        status: StepStatus,
        duration: float = 0.0,
        findings: Optional[list[Finding]] = None,
    ):
        """Mark a step as completed with results."""
        step.actual_result = result
        step.status = status
        step.duration = duration
        if findings:
            step.findings = findings
            self.findings.extend(findings)
        logger.info(
            f"Step {step.step_number} completed — "
            f"status={status.value}, findings={len(findings or [])}"
        )

    def add_finding(self, finding: Finding):
        """Add a standalone finding."""
        self.findings.append(finding)
        logger.info(f"Finding added: [{finding.severity.value}] {finding.title}")

    def complete(self):
        """Mark the chain as complete."""
        self.end_time = time.strftime("%Y-%m-%d %H:%M:%S")
        self.status = "completed"
        logger.info(
            f"Attack chain completed — "
            f"steps={len(self.steps)}, findings={len(self.findings)}"
        )

    # ─── Analysis ──────────────────────────────────────────────────

    def get_risk_summary(self) -> dict:
        """Get a summary of findings by severity."""
        summary = {s.value: 0 for s in Severity}
        for f in self.findings:
            summary[f.severity.value] += 1
        return summary

    def get_successful_steps(self) -> list[AttackStep]:
        """Get all steps that succeeded."""
        return [s for s in self.steps if s.status == StepStatus.SUCCESS]

    def get_overall_risk(self) -> str:
        """Calculate overall risk rating."""
        risk = self.get_risk_summary()
        if risk.get("critical", 0) > 0:
            return "CRITICAL"
        if risk.get("high", 0) > 0:
            return "HIGH"
        if risk.get("medium", 0) > 0:
            return "MEDIUM"
        if risk.get("low", 0) > 0:
            return "LOW"
        return "INFORMATIONAL"

    # ─── Serialization ─────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target": self.target,
            "scope": self.scope,
            "status": self.status,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "overall_risk": self.get_overall_risk(),
            "risk_summary": self.get_risk_summary(),
            "total_steps": len(self.steps),
            "successful_steps": len(self.get_successful_steps()),
            "total_findings": len(self.findings),
            "steps": [s.to_dict() for s in self.steps],
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)
