"""
AEGIS Terminal Executor
========================

Provides safe, logged, async command execution with timeout management.
All commands are tracked with timestamps for the final report.

Includes tool availability detection and path resolution for Windows.
"""

import asyncio
import shutil
import subprocess
import time
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# pyrefly: ignore [missing-import]
from loguru import logger
from aegis.config import config


@dataclass
class CommandResult:
    """Result of a command execution."""
    command: str
    stdout: str
    stderr: str
    return_code: int
    duration: float
    timed_out: bool = False
    timestamp: str = ""
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "command": self.command,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "return_code": self.return_code,
            "duration": round(self.duration, 2),
            "timed_out": self.timed_out,
            "timestamp": self.timestamp,
            "error": self.error,
        }

    @property
    def success(self) -> bool:
        return self.return_code == 0 and not self.timed_out

    @property
    def output(self) -> str:
        """Combined stdout and stderr."""
        parts = []
        if self.stdout:
            parts.append(self.stdout)
        if self.stderr:
            parts.append(f"[STDERR] {self.stderr}")
        return "\n".join(parts) if parts else "(no output)"


# ─── Blocked Commands (Safety) ────────────────────────────────────

BLOCKED_COMMANDS = [
    "rm -rf /",
    "mkfs",
    "dd if=/dev/zero",
    ":(){:|:&};:",
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "init 0",
    "init 6",
    # Windows-specific dangerous commands
    "format c:",
    "del /f /s /q c:",
    "rd /s /q c:",
]

DANGEROUS_PATTERNS = [
    "rm -rf /",
    "mkfs.",
    "dd if=/dev/zero of=/dev/sd",
    "chmod -R 777 /",
    # Windows-specific
    "format c:",
    "del /f /s /q c:\\",
]


# ─── Tool Registry ───────────────────────────────────────────────
# Maps tool names to:
#   - Common Windows install paths to search
#   - Install instructions
#   - Optional Python-based fallback function name

TOOL_REGISTRY: dict[str, dict] = {
    "nmap": {
        "search_paths": [
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\nmap\nmap.exe",
        ],
        "install_hint": "Install nmap from https://nmap.org/download.html or run: winget install Insecure.Nmap",
        "has_fallback": True,
    },
    "nikto": {
        "search_paths": [],
        "install_hint": "nikto is a Linux tool. Install via WSL or use: pip install nikto (if available)",
        "has_fallback": False,
    },
    "whatweb": {
        "search_paths": [],
        "install_hint": "whatweb is a Linux-only tool. AEGIS will use a Python-based web fingerprinter instead.",
        "has_fallback": True,
    },
    "gobuster": {
        "search_paths": [
            r"C:\tools\gobuster.exe",
            r"C:\Program Files\gobuster\gobuster.exe",
        ],
        "install_hint": "Download gobuster from https://github.com/OJ/gobuster/releases",
        "has_fallback": False,
    },
    "dirb": {
        "search_paths": [],
        "install_hint": "dirb is a Linux-only tool. Use gobuster or ffuf as alternatives.",
        "has_fallback": False,
    },
    "ffuf": {
        "search_paths": [
            r"C:\tools\ffuf.exe",
            r"C:\Program Files\ffuf\ffuf.exe",
        ],
        "install_hint": "Download ffuf from https://github.com/ffuf/ffuf/releases",
        "has_fallback": False,
    },
    "sqlmap": {
        "search_paths": [],
        "install_hint": "Install sqlmap: pip install sqlmap",
        "has_fallback": False,
    },
    "hydra": {
        "search_paths": [],
        "install_hint": "hydra is a Linux-only tool. Consider using Medusa or Patator on Windows.",
        "has_fallback": False,
    },
    "wafw00f": {
        "search_paths": [],
        "install_hint": "Install wafw00f: pip install wafw00f",
        "has_fallback": False,
    },
    "searchsploit": {
        "search_paths": [],
        "install_hint": "searchsploit requires exploitdb. Clone from https://gitlab.com/exploit-database/exploitdb",
        "has_fallback": False,
    },
    "curl": {
        "search_paths": [
            r"C:\Windows\System32\curl.exe",
        ],
        "install_hint": "curl is typically pre-installed on Windows 10+.",
        "has_fallback": True,
    },
    "python3": {
        "search_paths": [],
        "install_hint": "Use 'python' on Windows instead of 'python3'.",
        "has_fallback": True,
    },
}


class TerminalExecutor:
    """
    Safe command executor with logging, timeout, and output limiting.
    Tracks all command history for report generation.
    Detects available tools and resolves paths on Windows.
    """

    def __init__(self):
        self.history: list[CommandResult] = []
        self.max_output_length = config.execution.max_output_length
        self.default_timeout = config.execution.command_timeout
        self.safe_mode = config.execution.safe_mode
        self.is_windows = platform.system() == "Windows"

        # Tool availability cache: tool_name -> resolved_path or None
        self._tool_paths: dict[str, Optional[str]] = {}
        self._tools_checked = False

        logger.info(
            f"Terminal Executor initialized — "
            f"timeout={self.default_timeout}s, safe_mode={self.safe_mode}"
        )

    # ─── Tool Availability ────────────────────────────────────────

    def check_tool_availability(self) -> dict[str, Optional[str]]:
        """
        Check which security tools are available on the system.

        Returns:
            Dict mapping tool_name -> resolved_path (or None if not found).
        """
        if self._tools_checked:
            return self._tool_paths

        logger.info("Checking security tool availability...")

        for tool_name, info in TOOL_REGISTRY.items():
            resolved = None

            # 1. Check if the tool is in PATH
            path_result = shutil.which(tool_name)
            if path_result:
                resolved = path_result
            else:
                # 2. Check known install locations (Windows)
                if self.is_windows:
                    for search_path in info.get("search_paths", []):
                        if Path(search_path).exists():
                            resolved = search_path
                            break

            self._tool_paths[tool_name] = resolved

            if resolved:
                logger.info(f"  ✓ {tool_name}: {resolved}")
            else:
                logger.warning(f"  ✗ {tool_name}: NOT FOUND — {info.get('install_hint', 'N/A')}")

        # Special case: on Windows, 'python3' is usually just 'python'
        if self.is_windows and not self._tool_paths.get("python3"):
            python_path = shutil.which("python")
            if python_path:
                self._tool_paths["python3"] = python_path
                self._tool_paths["python"] = python_path
                logger.info(f"  ✓ python3 (via python): {python_path}")

        self._tools_checked = True
        return self._tool_paths

    def get_available_tools(self) -> list[str]:
        """Get list of tool names that are available on the system."""
        if not self._tools_checked:
            self.check_tool_availability()
        return [name for name, path in self._tool_paths.items() if path is not None]

    def get_available_tools_info(self) -> str:
        """
        Get a formatted string describing available tools for AI context.
        This is injected into AI prompts so the AI only suggests available tools.
        """
        if not self._tools_checked:
            self.check_tool_availability()

        lines = []
        available = []
        unavailable = []

        for tool_name, path in self._tool_paths.items():
            if path:
                available.append(f"  - {tool_name} (path: {path})")
            else:
                hint = TOOL_REGISTRY.get(tool_name, {}).get("install_hint", "")
                unavailable.append(f"  - {tool_name} (NOT INSTALLED — {hint})")

        lines.append(f"Operating System: {platform.system()} {platform.release()}")
        lines.append(f"\nAVAILABLE TOOLS (use ONLY these):")
        if available:
            lines.extend(available)
        else:
            lines.append("  (no external security tools detected)")
            lines.append("  Use Python-based scanning with: python, curl, or built-in modules")

        lines.append(f"\nUNAVAILABLE TOOLS (do NOT suggest these):")
        if unavailable:
            lines.extend(unavailable)

        # Always-available tools
        lines.append(f"\nALWAYS AVAILABLE:")
        lines.append(f"  - python (for custom scripts using socket, requests, urllib)")
        lines.append(f"  - curl (for HTTP requests)")
        lines.append(f"  - powershell (for Windows-native commands)")

        return "\n".join(lines)

    def resolve_command(self, command: str) -> str:
        """
        Resolve a command by substituting tool names with full paths
        when the tool is found in a non-PATH location.

        E.g., 'nmap -sV target' -> '"C:\\Program Files\\Nmap\\nmap.exe" -sV target'
        """
        if not self._tools_checked:
            self.check_tool_availability()

        parts = command.strip().split(None, 1)
        if not parts:
            return command

        tool_name = parts[0].lower()
        # Strip .exe suffix for matching
        bare_name = tool_name.replace(".exe", "")

        resolved_path = self._tool_paths.get(bare_name)
        if resolved_path and resolved_path != tool_name:
            # Only substitute if the resolved path differs from what's already there
            # and the tool isn't directly callable
            if shutil.which(tool_name) is None:
                rest = parts[1] if len(parts) > 1 else ""
                # Quote the path if it contains spaces
                if " " in resolved_path:
                    resolved_cmd = f'"{resolved_path}" {rest}'.strip()
                else:
                    resolved_cmd = f'{resolved_path} {rest}'.strip()
                logger.debug(f"Resolved command: {command} -> {resolved_cmd}")
                return resolved_cmd

        return command

    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a specific tool is available."""
        if not self._tools_checked:
            self.check_tool_availability()
        return self._tool_paths.get(tool_name) is not None

    # ─── Safety Checks ────────────────────────────────────────────

    def _is_blocked(self, command: str) -> bool:
        """Check if a command is in the blocklist."""
        cmd_lower = command.lower().strip()
        for blocked in BLOCKED_COMMANDS:
            if blocked in cmd_lower:
                return True
        for pattern in DANGEROUS_PATTERNS:
            if pattern in cmd_lower:
                return True
        return False

    def _classify_risk(self, command: str) -> str:
        """Classify the risk level of a command."""
        cmd_lower = command.lower()
        high_risk = ["msfconsole", "exploit", "payload", "meterpreter"]
        medium_risk = ["hydra", "sqlmap", "nikto", "hashcat", "john"]
        for tool in high_risk:
            if tool in cmd_lower:
                return "high"
        for tool in medium_risk:
            if tool in cmd_lower:
                return "medium"
        return "low"

    def _detect_command_not_found(self, command: str, return_code: int,
                                  stdout: str, stderr: str) -> Optional[str]:
        """
        Detect if a command failed because the tool is not installed.
        On Windows, this often shows as rc=1 with empty or specific error output.

        Returns an error message if the tool is missing, None otherwise.
        """
        if return_code == 0:
            return None

        parts = command.strip().split(None, 1)
        if not parts:
            return None
        tool_name = parts[0].strip('"').split("\\")[-1].replace(".exe", "").lower()

        # Windows-specific patterns for "not found"
        not_found_patterns = [
            "is not recognized as an internal or external command",
            "not recognized as",
            "is not recognized",
            "the system cannot find",
            "not found",
            "no such file or directory",
            "command not found",
        ]

        combined_output = (stdout + stderr).lower()

        # Case 1: Explicit "not found" error messages
        for pattern in not_found_patterns:
            if pattern in combined_output:
                hint = TOOL_REGISTRY.get(tool_name, {}).get(
                    "install_hint", f"Ensure '{tool_name}' is installed and in your PATH."
                )
                return f"Tool '{tool_name}' is not installed or not in PATH. {hint}"

        # Case 2: rc=1 with completely empty output (typical Windows "not found")
        if return_code == 1 and not stdout.strip() and not stderr.strip():
            # Check if the tool exists
            if not self.is_tool_available(tool_name):
                hint = TOOL_REGISTRY.get(tool_name, {}).get(
                    "install_hint", f"Ensure '{tool_name}' is installed and in your PATH."
                )
                return f"Tool '{tool_name}' is not installed or not in PATH. {hint}"

        return None

    # ─── Async Execution ──────────────────────────────────────────

    async def execute(
        self,
        command: str,
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
    ) -> CommandResult:
        """
        Execute a command asynchronously with safety checks.

        Args:
            command: Shell command to execute
            timeout: Timeout in seconds (default from config)
            cwd: Working directory for the command

        Returns:
            CommandResult with output, errors, and metadata
        """
        timeout = timeout or self.default_timeout
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        if self._is_blocked(command):
            logger.warning(f"BLOCKED dangerous command: {command}")
            result = CommandResult(
                command=command,
                stdout="",
                stderr="Command blocked by safety filter",
                return_code=-1,
                duration=0.0,
                timestamp=timestamp,
                error="Command blocked: potentially destructive operation",
            )
            self.history.append(result)
            return result

        # Resolve tool paths before execution
        resolved_command = self.resolve_command(command)
        if resolved_command != command:
            logger.info(f"Command resolved: {command} -> {resolved_command}")

        risk = self._classify_risk(command)
        logger.info(f"Executing [{risk} risk]: {resolved_command}")
        start_time = time.time()

        try:
            proc = await asyncio.create_subprocess_shell(
                resolved_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
                stdout = stdout_bytes.decode("utf-8", errors="replace")
                stderr = stderr_bytes.decode("utf-8", errors="replace")

                if len(stdout) > self.max_output_length:
                    stdout = (
                        stdout[: self.max_output_length]
                        + f"\n\n[... OUTPUT TRUNCATED — {len(stdout)} chars total ...]"
                    )
                if len(stderr) > self.max_output_length:
                    stderr = stderr[: self.max_output_length] + "\n[... STDERR TRUNCATED ...]"

                # Detect "command not found" scenarios
                not_found_error = self._detect_command_not_found(
                    command, proc.returncode or 0, stdout, stderr
                )

                result = CommandResult(
                    command=command,
                    stdout=stdout,
                    stderr=stderr,
                    return_code=proc.returncode or 0,
                    duration=time.time() - start_time,
                    timestamp=timestamp,
                    error=not_found_error,
                )

            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                result = CommandResult(
                    command=command,
                    stdout="",
                    stderr=f"Command timed out after {timeout}s",
                    return_code=-1,
                    duration=timeout,
                    timed_out=True,
                    timestamp=timestamp,
                    error=f"Timeout after {timeout} seconds",
                )
                logger.warning(f"Command timed out: {command}")

        except FileNotFoundError:
            result = CommandResult(
                command=command,
                stdout="",
                stderr=f"Command not found: {command.split()[0]}",
                return_code=-1,
                duration=time.time() - start_time,
                timestamp=timestamp,
                error=f"Tool not installed: {command.split()[0]}",
            )
        except Exception as e:
            result = CommandResult(
                command=command,
                stdout="",
                stderr=str(e),
                return_code=-1,
                duration=time.time() - start_time,
                timestamp=timestamp,
                error=str(e),
            )
            logger.error(f"Execution error: {e}")

        self.history.append(result)
        logger.debug(
            f"Done — rc={result.return_code}, "
            f"duration={result.duration:.1f}s, output_len={len(result.stdout)}"
        )
        return result

    # ─── Sync Execution ───────────────────────────────────────────

    def execute_sync(
        self,
        command: str,
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
    ) -> CommandResult:
        """Synchronous version of execute for non-async contexts."""
        timeout = timeout or self.default_timeout
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        if self._is_blocked(command):
            result = CommandResult(
                command=command,
                stdout="",
                stderr="Command blocked by safety filter",
                return_code=-1,
                duration=0.0,
                timestamp=timestamp,
                error="Command blocked",
            )
            self.history.append(result)
            return result

        # Resolve tool paths
        resolved_command = self.resolve_command(command)

        start_time = time.time()
        try:
            proc = subprocess.run(
                resolved_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
            )

            not_found_error = self._detect_command_not_found(
                command, proc.returncode, proc.stdout, proc.stderr
            )

            result = CommandResult(
                command=command,
                stdout=proc.stdout[: self.max_output_length],
                stderr=proc.stderr[: self.max_output_length],
                return_code=proc.returncode,
                duration=time.time() - start_time,
                timestamp=timestamp,
                error=not_found_error,
            )
        except subprocess.TimeoutExpired:
            result = CommandResult(
                command=command,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                return_code=-1,
                duration=timeout,
                timed_out=True,
                timestamp=timestamp,
                error=f"Timeout after {timeout} seconds",
            )
        except Exception as e:
            result = CommandResult(
                command=command,
                stdout="",
                stderr=str(e),
                return_code=-1,
                duration=time.time() - start_time,
                timestamp=timestamp,
                error=str(e),
            )

        self.history.append(result)
        return result

    # ─── History ──────────────────────────────────────────────────

    def get_history(self) -> list[dict]:
        """Get full command history as list of dicts."""
        return [cmd.to_dict() for cmd in self.history]

    def get_last_result(self) -> Optional[CommandResult]:
        """Get the most recent command result."""
        return self.history[-1] if self.history else None

    def clear_history(self):
        """Clear command history."""
        self.history.clear()
