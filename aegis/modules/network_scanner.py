"""
AEGIS Network Scanner Module
==============================

Network-level attack techniques:
- Port scanning with intelligent flag selection
- Service version exploitation
- SSL/TLS vulnerability checks
- SMB enumeration
- DNS zone transfer
- SNMP enumeration
- Default credential testing
"""

from loguru import logger

from aegis.modules.base import BaseModule, ModuleInfo
from aegis.core.chain import Finding, Severity


class NetworkScanner(BaseModule):
    """Network-level attack module."""

    def get_info(self) -> ModuleInfo:
        return ModuleInfo(
            name="network_scanner",
            description="Network service enumeration and vulnerability scanning",
            category="network",
            tools_required=["nmap", "smbclient", "enum4linux", "sslscan"],
            risk_level="medium",
        )

    async def run(self, target: str, **kwargs) -> list[Finding]:
        """Run all network scanning techniques."""
        ports = kwargs.get("ports", None)

        logger.info(f"[NetworkScanner] Starting scan on {target}")

        await self.deep_port_scan(target, ports)
        await self.ssl_check(target)
        await self.smb_enum(target)
        await self.dns_zone_transfer(target)
        await self.snmp_enum(target)

        logger.info(f"[NetworkScanner] Completed — {len(self.findings)} findings")
        return self.findings

    async def deep_port_scan(self, target: str, ports: str = None):
        """Comprehensive port scan with vulnerability scripts."""
        port_arg = f"-p {ports}" if ports else "-p-"
        result = await self.executor.execute(
            f"nmap -sV -sC --script=vuln,default {port_arg} -T4 {target}",
            timeout=600,
        )
        if result.success:
            output = result.stdout.lower()
            # Check for common vulnerabilities
            vuln_keywords = {
                "ms17-010": ("EternalBlue (MS17-010)", Severity.CRITICAL, 9.8,
                             "CVE-2017-0144", "Apply MS17-010 patch immediately"),
                "cve-2021-44228": ("Log4Shell", Severity.CRITICAL, 10.0,
                                   "CVE-2021-44228", "Update Log4j to 2.17.0+"),
                "cve-2021-41773": ("Apache Path Traversal", Severity.CRITICAL, 9.8,
                                   "CVE-2021-41773", "Update Apache to latest version"),
                "ssl-heartbleed": ("Heartbleed", Severity.HIGH, 7.5,
                                   "CVE-2014-0160", "Update OpenSSL"),
                "smb-vuln": ("SMB Vulnerability", Severity.HIGH, 8.0,
                             None, "Disable SMBv1 and apply patches"),
            }
            for keyword, (title, severity, cvss, cve, fix) in vuln_keywords.items():
                if keyword in output:
                    self.add_finding(
                        title=title,
                        description=f"Vulnerability detected via nmap script scan",
                        severity=severity,
                        cvss=cvss,
                        cve=cve,
                        evidence=result.stdout[:1500],
                        remediation=fix,
                        service="network",
                    )

    async def ssl_check(self, target: str):
        """Check SSL/TLS configuration."""
        result = await self.executor.execute(f"sslscan --no-colour {target}:443", timeout=60)
        if result.success:
            output = result.stdout.lower()
            issues = []
            if "sslv3" in output and "enabled" in output:
                issues.append("SSLv3 enabled (POODLE vulnerability)")
            if "tls1.0" in output or "tlsv1 " in output:
                issues.append("TLS 1.0 enabled (deprecated)")
            if "rc4" in output:
                issues.append("RC4 cipher in use (weak)")
            if "heartbleed" in output and "vulnerable" in output:
                issues.append("Heartbleed vulnerability detected")

            if issues:
                self.add_finding(
                    title="SSL/TLS Configuration Issues",
                    description=f"Found {len(issues)} SSL/TLS issues: {'; '.join(issues)}",
                    severity=Severity.MEDIUM,
                    cvss=5.9,
                    evidence=result.stdout[:1000],
                    remediation="Disable SSLv3 and TLS 1.0. Use only TLS 1.2+ with strong ciphers.",
                    service="ssl",
                    port=443,
                )

    async def smb_enum(self, target: str):
        """Enumerate SMB shares and users."""
        result = await self.executor.execute(
            f"enum4linux -a {target}", timeout=120
        )
        if result.success and "share" in result.stdout.lower():
            if "null session" in result.stdout.lower():
                self.add_finding(
                    title="SMB Null Session Allowed",
                    description="SMB allows null sessions for share and user enumeration",
                    severity=Severity.HIGH,
                    cvss=7.5,
                    evidence=result.stdout[:1500],
                    remediation="Disable null sessions. Restrict anonymous access to SMB shares.",
                    service="smb",
                    port=445,
                )

    async def dns_zone_transfer(self, target: str):
        """Attempt DNS zone transfer."""
        result = await self.executor.execute(
            f"dig axfr @{target} {target}", timeout=30
        )
        if result.success and "xfr size" in result.stdout.lower():
            self.add_finding(
                title="DNS Zone Transfer Allowed",
                description="DNS server allows unrestricted zone transfers",
                severity=Severity.HIGH,
                cvss=7.5,
                evidence=result.stdout[:1000],
                remediation="Restrict zone transfers to authorized secondary DNS servers only.",
                service="dns",
                port=53,
            )

    async def snmp_enum(self, target: str):
        """Enumerate SNMP with common community strings."""
        for community in ["public", "private", "community"]:
            result = await self.executor.execute(
                f"snmpwalk -v2c -c {community} {target} 1.3.6.1.2.1.1",
                timeout=15,
            )
            if result.success and result.stdout.strip():
                self.add_finding(
                    title=f"SNMP Default Community String: {community}",
                    description=f"SNMP v2c accessible with community string '{community}'",
                    severity=Severity.HIGH,
                    cvss=7.5,
                    evidence=result.stdout[:500],
                    remediation="Change default SNMP community strings. Use SNMPv3 with authentication.",
                    service="snmp",
                    port=161,
                )
                break
