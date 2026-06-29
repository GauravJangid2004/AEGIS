"""
Tests for AEGIS Core Components
"""

import pytest
import json
from aegis.core.chain import AttackChain, AttackStep, Finding, Severity, StepStatus
from aegis.core.executor import TerminalExecutor, CommandResult


class TestAttackChain:
    """Tests for the AttackChain data model."""

    def test_create_chain(self):
        chain = AttackChain(target="192.168.1.100", scope="full")
        assert chain.target == "192.168.1.100"
        assert chain.scope == "full"
        assert chain.status == "in_progress"
        assert len(chain.steps) == 0

    def test_add_step(self):
        chain = AttackChain(target="10.0.0.1")
        step = chain.add_step({
            "reasoning": "Initial port scan",
            "tool": "nmap",
            "command": "nmap -sV 10.0.0.1",
            "expected_result": "Open ports",
            "risk_level": "low",
        })
        assert step.step_number == 1
        assert step.tool == "nmap"
        assert len(chain.steps) == 1

    def test_complete_step(self):
        chain = AttackChain(target="10.0.0.1")
        step = chain.add_step({
            "reasoning": "Test",
            "tool": "nmap",
            "command": "nmap 10.0.0.1",
        })
        chain.complete_step(
            step,
            result="PORT   STATE SERVICE\n22/tcp open  ssh",
            status=StepStatus.SUCCESS,
            duration=5.2,
        )
        assert step.status == StepStatus.SUCCESS
        assert step.duration == 5.2
        assert "ssh" in step.actual_result

    def test_add_finding(self):
        chain = AttackChain(target="10.0.0.1")
        finding = Finding(
            title="SSH Weak Password",
            description="SSH accepts default credentials",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
        )
        chain.add_finding(finding)
        assert len(chain.findings) == 1
        assert chain.get_overall_risk() == "CRITICAL"

    def test_risk_summary(self):
        chain = AttackChain(target="10.0.0.1")
        chain.add_finding(Finding(title="F1", severity=Severity.CRITICAL))
        chain.add_finding(Finding(title="F2", severity=Severity.HIGH))
        chain.add_finding(Finding(title="F3", severity=Severity.MEDIUM))
        chain.add_finding(Finding(title="F4", severity=Severity.LOW))

        summary = chain.get_risk_summary()
        assert summary["critical"] == 1
        assert summary["high"] == 1
        assert summary["medium"] == 1
        assert summary["low"] == 1

    def test_serialization(self):
        chain = AttackChain(target="10.0.0.1")
        chain.add_step({
            "reasoning": "Test",
            "tool": "nmap",
            "command": "nmap 10.0.0.1",
        })
        data = chain.to_dict()
        assert data["target"] == "10.0.0.1"
        assert data["total_steps"] == 1
        assert isinstance(data["steps"], list)

        # Ensure JSON serializable
        json_str = chain.to_json()
        parsed = json.loads(json_str)
        assert parsed["target"] == "10.0.0.1"

    def test_complete_chain(self):
        chain = AttackChain(target="10.0.0.1")
        chain.complete()
        assert chain.status == "completed"
        assert chain.end_time is not None


class TestCommandResult:
    """Tests for CommandResult."""

    def test_success(self):
        result = CommandResult(
            command="echo hello",
            stdout="hello\n",
            stderr="",
            return_code=0,
            duration=0.1,
        )
        assert result.success is True
        assert "hello" in result.output

    def test_failure(self):
        result = CommandResult(
            command="false",
            stdout="",
            stderr="error",
            return_code=1,
            duration=0.1,
        )
        assert result.success is False

    def test_timeout(self):
        result = CommandResult(
            command="sleep 999",
            stdout="",
            stderr="",
            return_code=-1,
            duration=30.0,
            timed_out=True,
        )
        assert result.success is False
        assert result.timed_out is True

    def test_to_dict(self):
        result = CommandResult(
            command="test",
            stdout="out",
            stderr="err",
            return_code=0,
            duration=1.5,
            timestamp="2024-01-01 00:00:00",
        )
        d = result.to_dict()
        assert d["command"] == "test"
        assert d["duration"] == 1.5


class TestTerminalExecutor:
    """Tests for TerminalExecutor safety features."""

    def test_blocked_commands(self):
        executor = TerminalExecutor()
        assert executor._is_blocked("rm -rf /") is True
        assert executor._is_blocked("shutdown -h now") is True
        assert executor._is_blocked("nmap 10.0.0.1") is False

    def test_risk_classification(self):
        executor = TerminalExecutor()
        assert executor._classify_risk("msfconsole -x exploit") == "high"
        assert executor._classify_risk("hydra -l admin -p pass") == "medium"
        assert executor._classify_risk("nmap -sV 10.0.0.1") == "low"


class TestFinding:
    """Tests for Finding data model."""

    def test_create_finding(self):
        f = Finding(
            title="SQL Injection",
            description="Input not sanitized",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            cve_id="CVE-2024-1234",
        )
        assert f.severity == Severity.CRITICAL
        assert f.cvss_score == 9.8

    def test_finding_serialization(self):
        f = Finding(
            title="Test",
            severity=Severity.HIGH,
        )
        d = f.to_dict()
        assert d["severity"] == "high"
        assert d["title"] == "Test"
