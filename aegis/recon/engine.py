"""
AEGIS Reconnaissance Engine
==============================

Orchestrates all reconnaissance activities and builds a target profile.
Integrates: nmap, whois, DNS, Shodan, technology fingerprinting.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional
from loguru import logger

from aegis.core.executor import TerminalExecutor
from aegis.core.ai_engine import AIEngine


@dataclass
class ServiceInfo:
    """Information about a detected service."""
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    product: str = ""
    extra_info: str = ""
    cpe: str = ""

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "product": self.product,
            "extra_info": self.extra_info,
            "cpe": self.cpe,
        }


@dataclass
class TargetProfile:
    """Complete profile of a target built from recon data."""
    target: str
    ip_address: str = ""
    hostname: str = ""
    os_guess: str = ""
    services: list[ServiceInfo] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    whois_data: dict = field(default_factory=dict)
    dns_records: dict = field(default_factory=dict)
    waf_detected: Optional[str] = None
    raw_nmap_output: str = ""
    shodan_data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "os_guess": self.os_guess,
            "services": [s.to_dict() for s in self.services],
            "technologies": self.technologies,
            "subdomains": self.subdomains,
            "emails": self.emails,
            "whois_data": self.whois_data,
            "dns_records": self.dns_records,
            "waf_detected": self.waf_detected,
            "shodan_data": self.shodan_data,
        }

    @property
    def open_ports(self) -> list[int]:
        return [s.port for s in self.services]

    @property
    def has_web(self) -> bool:
        web_services = {"http", "https", "http-proxy", "ssl/http"}
        return any(s.service in web_services for s in self.services)

    @property
    def has_ssh(self) -> bool:
        return any(s.service == "ssh" for s in self.services)

    @property
    def has_database(self) -> bool:
        db_services = {"mysql", "postgresql", "mssql", "oracle", "mongodb", "redis"}
        return any(s.service in db_services for s in self.services)

    @property
    def attack_surface_summary(self) -> str:
        lines = [f"Target: {self.target} ({self.ip_address})"]
        if self.os_guess:
            lines.append(f"OS: {self.os_guess}")
        lines.append(f"Open Ports: {len(self.services)}")
        for s in self.services:
            lines.append(f"  - {s.port}/{s.protocol}: {s.service} {s.version}")
        if self.technologies:
            lines.append(f"Technologies: {', '.join(self.technologies)}")
        if self.waf_detected:
            lines.append(f"WAF: {self.waf_detected}")
        return "\n".join(lines)


class ReconEngine:
    """
    Orchestrates reconnaissance and builds a target profile.
    """

    def __init__(
        self,
        executor: Optional[TerminalExecutor] = None,
        ai_engine: Optional[AIEngine] = None,
    ):
        self.executor = executor or TerminalExecutor()
        self.ai = ai_engine or AIEngine()

    async def scan(self, target: str, depth: str = "standard") -> TargetProfile:
        """
        Run full reconnaissance on a target.

        Args:
            target: IP, domain, or URL
            depth: 'quick', 'standard', or 'deep'

        Returns:
            TargetProfile with all collected data
        """
        profile = TargetProfile(target=target)

        logger.info(f"[Recon] Starting {depth} scan on {target}")

        # Core scans (always run)
        await self._nmap_scan(profile, depth)
        await self._dns_lookup(profile)

        # Standard depth
        if depth in ("standard", "deep"):
            await self._whois_lookup(profile)
            await self._tech_fingerprint(profile)
            await self._waf_detect(profile)

        # Deep scan
        if depth == "deep":
            await self._subdomain_enum(profile)
            await self._shodan_lookup(profile)

        # AI analysis of recon data
        await self._ai_analyze_profile(profile)

        logger.info(f"[Recon] Complete — {len(profile.services)} services found")
        logger.info(f"[Recon] Attack surface:\n{profile.attack_surface_summary}")

        return profile

    async def _nmap_scan(self, profile: TargetProfile, depth: str):
        """Run nmap and parse results."""
        if depth == "quick":
            cmd = f"nmap -sV -T4 --top-ports 100 --open {profile.target}"
        elif depth == "deep":
            cmd = f"nmap -sV -sC -O -A -T4 -p- --open {profile.target}"
        else:
            cmd = f"nmap -sV -sC -O -T4 --open {profile.target}"

        result = await self.executor.execute(cmd, timeout=600)
        if not result.success:
            logger.error(f"Nmap scan failed: {result.stderr}")
            return

        profile.raw_nmap_output = result.stdout
        self._parse_nmap_output(profile, result.stdout)

    def _parse_nmap_output(self, profile: TargetProfile, output: str):
        """Parse nmap output to extract service information."""
        # Extract IP
        ip_match = re.search(r"Nmap scan report for [\w.-]+ \((\d+\.\d+\.\d+\.\d+)\)", output)
        if ip_match:
            profile.ip_address = ip_match.group(1)
        else:
            ip_match = re.search(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", output)
            if ip_match:
                profile.ip_address = ip_match.group(1)

        # Extract OS guess
        os_match = re.search(r"OS details?:\s*(.+)", output)
        if os_match:
            profile.os_guess = os_match.group(1).strip()

        # Extract services
        port_pattern = re.compile(
            r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)"
        )
        for match in port_pattern.finditer(output):
            port = int(match.group(1))
            proto = match.group(2)
            service = match.group(3)
            version_info = match.group(4).strip()

            svc = ServiceInfo(
                port=port,
                protocol=proto,
                service=service,
                version=version_info,
            )

            # Extract product and version from version_info
            ver_match = re.match(r"(\S+)\s+(\S+)", version_info)
            if ver_match:
                svc.product = ver_match.group(1)
                svc.version = ver_match.group(2)

            profile.services.append(svc)

    async def _dns_lookup(self, profile: TargetProfile):
        """DNS enumeration."""
        result = await self.executor.execute(
            f"nslookup {profile.target} 2>/dev/null || dig {profile.target} ANY +short",
            timeout=15,
        )
        if result.success:
            profile.dns_records["raw"] = result.stdout[:500]

    async def _whois_lookup(self, profile: TargetProfile):
        """WHOIS lookup."""
        result = await self.executor.execute(f"whois {profile.target}", timeout=15)
        if result.success:
            profile.whois_data["raw"] = result.stdout[:2000]
            # Extract key fields
            for field_name in ["Registrant", "Organization", "Creation Date", "Name Server"]:
                match = re.search(f"{field_name}[: ]+(.+)", result.stdout, re.IGNORECASE)
                if match:
                    profile.whois_data[field_name.lower().replace(" ", "_")] = match.group(1).strip()

    async def _tech_fingerprint(self, profile: TargetProfile):
        """Technology fingerprinting."""
        if not profile.has_web:
            return
        result = await self.executor.execute(f"whatweb -a 3 {profile.target}", timeout=30)
        if result.success:
            # Extract technology names
            tech_pattern = re.compile(r"\[(\w[\w.-]+)\]")
            techs = tech_pattern.findall(result.stdout)
            profile.technologies = list(set(techs))

    async def _waf_detect(self, profile: TargetProfile):
        """WAF detection."""
        if not profile.has_web:
            return
        result = await self.executor.execute(f"wafw00f {profile.target}", timeout=30)
        if result.success and "is behind" in result.stdout.lower():
            waf_match = re.search(r"is behind (.+)", result.stdout, re.IGNORECASE)
            if waf_match:
                profile.waf_detected = waf_match.group(1).strip()

    async def _subdomain_enum(self, profile: TargetProfile):
        """Subdomain enumeration."""
        result = await self.executor.execute(
            f"sublist3r -d {profile.target} -t 10 2>/dev/null || "
            f"amass enum -passive -d {profile.target} -timeout 2 2>/dev/null",
            timeout=120,
        )
        if result.success:
            subs = [
                line.strip() for line in result.stdout.split("\n")
                if line.strip() and "." in line.strip()
            ]
            profile.subdomains = list(set(subs))[:50]

    async def _shodan_lookup(self, profile: TargetProfile):
        """Shodan API lookup (requires API key)."""
        from aegis.config import config
        if not config.api_keys.shodan_api_key:
            logger.debug("Shodan API key not configured, skipping")
            return

        result = await self.executor.execute(
            f"shodan host {profile.ip_address or profile.target}",
            timeout=15,
        )
        if result.success:
            profile.shodan_data["raw"] = result.stdout[:2000]

    async def _ai_analyze_profile(self, profile: TargetProfile):
        """Have AI analyze the complete recon profile."""
        try:
            prompt = f"""Analyze this reconnaissance data and identify the most promising attack vectors:

{profile.attack_surface_summary}

Raw nmap output (first 2000 chars):
{profile.raw_nmap_output[:2000]}

Provide your analysis as a brief summary of the top 3-5 attack vectors to explore."""

            analysis = await self.ai.chat(prompt, "reasoning")
            logger.info(f"[AI Recon Analysis]\n{analysis}")
        except Exception as e:
            logger.warning(f"AI recon analysis failed: {e}")
