"""
AEGIS Base Module
==================

Abstract base class for all attack modules.
Each module provides a set of attack techniques and tool wrappers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional
from aegis.core.executor import TerminalExecutor, CommandResult
from aegis.core.chain import Finding, Severity


@dataclass
class ModuleInfo:
    """Metadata about an attack module."""
    name: str
    description: str
    category: str
    tools_required: list[str]
    risk_level: str = "medium"


class BaseModule(ABC):
    """Base class for all AEGIS attack modules."""

    def __init__(self, executor: Optional[TerminalExecutor] = None):
        self.executor = executor or TerminalExecutor()
        self.findings: list[Finding] = []
        self.results: list[CommandResult] = []

    @abstractmethod
    def get_info(self) -> ModuleInfo:
        """Return module metadata."""
        ...

    @abstractmethod
    async def run(self, target: str, **kwargs) -> list[Finding]:
        """Execute the module's attack techniques."""
        ...

    def add_finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        evidence: str = "",
        cvss: float = 0.0,
        cve: Optional[str] = None,
        remediation: str = "",
        service: str = "",
        port: Optional[int] = None,
    ) -> Finding:
        """Helper to create and store a finding."""
        finding = Finding(
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss,
            cve_id=cve,
            evidence=evidence,
            remediation=remediation,
            service=service,
            port=port,
        )
        self.findings.append(finding)
        return finding

    async def check_tool(self, tool_name: str) -> bool:
        """Check if a required tool is installed."""
        result = await self.executor.execute(f"which {tool_name} 2>/dev/null || where {tool_name} 2>nul")
        return result.success
