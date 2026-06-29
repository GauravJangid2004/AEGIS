"""
AEGIS Web Scanner Module
==========================

Automated web application attack techniques:
- Directory/file bruteforce
- SQL Injection detection
- XSS detection
- Technology fingerprinting
- WAF detection
- Authentication testing
"""

from typing import Optional
from loguru import logger

from aegis.modules.base import BaseModule, ModuleInfo
from aegis.core.executor import TerminalExecutor
from aegis.core.chain import Finding, Severity


class WebScanner(BaseModule):
    """Web application attack module."""

    def get_info(self) -> ModuleInfo:
        return ModuleInfo(
            name="web_scanner",
            description="Comprehensive web application vulnerability scanner",
            category="web",
            tools_required=["gobuster", "nikto", "sqlmap", "whatweb", "wafw00f", "curl"],
            risk_level="medium",
        )

    async def run(self, target: str, **kwargs) -> list[Finding]:
        """Run all web scanning techniques."""
        port = kwargs.get("port", 80)
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{target}:{port}" if port not in (80, 443) else f"{protocol}://{target}"

        logger.info(f"[WebScanner] Starting scan on {url}")

        await self.detect_waf(url)
        await self.fingerprint_tech(url)
        await self.directory_bruteforce(url)
        await self.nikto_scan(url)
        await self.check_headers(url)
        await self.check_sqli(url)

        logger.info(f"[WebScanner] Completed — {len(self.findings)} findings")
        return self.findings

    async def detect_waf(self, url: str):
        """Detect Web Application Firewalls."""
        result = await self.executor.execute(f"wafw00f {url}")
        if result.success and "is behind" in result.stdout.lower():
            self.add_finding(
                title="Web Application Firewall Detected",
                description=f"A WAF was detected protecting {url}",
                severity=Severity.INFO,
                evidence=result.stdout[:500],
                service="WAF",
            )

    async def fingerprint_tech(self, url: str):
        """Identify web technologies."""
        result = await self.executor.execute(f"whatweb -a 3 {url}")
        if result.success:
            self.add_finding(
                title="Technology Stack Identified",
                description="Web technology fingerprinting results",
                severity=Severity.INFO,
                evidence=result.stdout[:1000],
                service="web",
            )

    async def directory_bruteforce(self, url: str):
        """Discover hidden directories and files."""
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        result = await self.executor.execute(
            f"gobuster dir -u {url} -w {wordlist} -t 30 -q --no-error",
            timeout=180,
        )
        if result.success and result.stdout.strip():
            # Parse discovered paths
            interesting_paths = []
            for line in result.stdout.split("\n"):
                if any(kw in line.lower() for kw in [
                    "admin", "config", "backup", "upload", "api",
                    "login", "dashboard", "phpmyadmin", ".git",
                    ".env", "wp-admin", "console",
                ]):
                    interesting_paths.append(line.strip())

            if interesting_paths:
                self.add_finding(
                    title="Sensitive Directories Discovered",
                    description=f"Found {len(interesting_paths)} potentially sensitive paths",
                    severity=Severity.MEDIUM,
                    cvss=5.3,
                    evidence="\n".join(interesting_paths),
                    remediation="Restrict access to sensitive directories. Remove backup files and development artifacts from production.",
                    service="web",
                )

    async def nikto_scan(self, url: str):
        """Run Nikto vulnerability scanner."""
        result = await self.executor.execute(
            f"nikto -h {url} -maxtime 120s -Format txt",
            timeout=180,
        )
        if result.success:
            vuln_count = result.stdout.lower().count("osvdb")
            if vuln_count > 0:
                self.add_finding(
                    title=f"Nikto Found {vuln_count} Potential Vulnerabilities",
                    description="Nikto web server scanner detected potential security issues",
                    severity=Severity.MEDIUM if vuln_count < 5 else Severity.HIGH,
                    cvss=5.0 if vuln_count < 5 else 7.0,
                    evidence=result.stdout[:2000],
                    remediation="Review each finding and apply appropriate patches or configuration changes.",
                    service="web",
                )

    async def check_headers(self, url: str):
        """Check for missing security headers."""
        result = await self.executor.execute(f"curl -sI {url}")
        if result.success:
            headers_lower = result.stdout.lower()
            missing = []
            security_headers = {
                "strict-transport-security": "HSTS",
                "x-content-type-options": "X-Content-Type-Options",
                "x-frame-options": "X-Frame-Options",
                "content-security-policy": "CSP",
                "x-xss-protection": "X-XSS-Protection",
            }
            for header, name in security_headers.items():
                if header not in headers_lower:
                    missing.append(name)

            if missing:
                self.add_finding(
                    title="Missing Security Headers",
                    description=f"Missing headers: {', '.join(missing)}",
                    severity=Severity.LOW,
                    cvss=3.0,
                    evidence=result.stdout[:500],
                    remediation=f"Add the following security headers: {', '.join(missing)}",
                    service="web",
                )

    async def check_sqli(self, url: str):
        """Basic SQL injection detection with sqlmap."""
        result = await self.executor.execute(
            f"sqlmap -u {url} --batch --level=1 --risk=1 --crawl=2 --forms --smart --output-dir=/tmp/sqlmap_out",
            timeout=300,
        )
        if result.success and "is vulnerable" in result.stdout.lower():
            self.add_finding(
                title="SQL Injection Vulnerability Detected",
                description="sqlmap confirmed SQL injection vulnerability",
                severity=Severity.CRITICAL,
                cvss=9.8,
                evidence=result.stdout[:2000],
                remediation="Use parameterized queries/prepared statements. Implement input validation and WAF rules.",
                service="web",
            )
