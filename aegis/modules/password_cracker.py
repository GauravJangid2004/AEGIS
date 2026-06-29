"""
AEGIS Password Cracker Module
===============================

Password attack techniques:
- Hash identification and cracking
- SSH/FTP/HTTP bruteforce
- Default credential testing
- Password spraying
"""

from loguru import logger

from aegis.modules.base import BaseModule, ModuleInfo
from aegis.core.chain import Finding, Severity


# Common default credentials to test
DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("administrator", "administrator"), ("admin", ""),
    ("guest", "guest"), ("user", "user"), ("test", "test"),
    ("admin", "12345"), ("admin", "123456"), ("admin", "P@ssw0rd"),
]


class PasswordCracker(BaseModule):
    """Password attack module."""

    def get_info(self) -> ModuleInfo:
        return ModuleInfo(
            name="password_cracker",
            description="Password cracking, bruteforce, and credential testing",
            category="password",
            tools_required=["hydra", "john", "hashcat", "hashid"],
            risk_level="medium",
        )

    async def run(self, target: str, **kwargs) -> list[Finding]:
        """Run password attack techniques."""
        services = kwargs.get("services", [])
        hash_file = kwargs.get("hash_file", None)

        logger.info(f"[PasswordCracker] Starting on {target}")

        # Test default credentials on detected services
        for service in services:
            svc_name = service.get("name", "").lower()
            port = service.get("port", 0)

            if svc_name in ("ssh", "ftp", "telnet"):
                await self.bruteforce_service(target, svc_name, port)
            elif svc_name in ("http", "https"):
                await self.test_web_defaults(target, port)
            elif svc_name in ("mysql", "postgresql", "mssql"):
                await self.test_db_defaults(target, svc_name, port)

        # Crack hashes if provided
        if hash_file:
            await self.identify_hash(hash_file)
            await self.crack_hashes(hash_file)

        logger.info(f"[PasswordCracker] Completed — {len(self.findings)} findings")
        return self.findings

    async def bruteforce_service(self, target: str, service: str, port: int):
        """Bruteforce a network service with hydra."""
        # First try default credentials
        for username, password in DEFAULT_CREDENTIALS[:5]:
            result = await self.executor.execute(
                f"hydra -l {username} -p {password} {target} -s {port} {service} -t 4 -f",
                timeout=30,
            )
            if result.success and "successfully completed" in result.stdout.lower():
                self.add_finding(
                    title=f"Default Credentials on {service.upper()}",
                    description=f"{service.upper()} accepts default credentials {username}:{password}",
                    severity=Severity.CRITICAL,
                    cvss=9.8,
                    evidence=result.stdout[:500],
                    remediation="Change default credentials immediately. Implement account lockout policies.",
                    service=service,
                    port=port,
                )
                return

        # Try a small wordlist
        result = await self.executor.execute(
            f"hydra -L /usr/share/wordlists/metasploit/default_users_for_{service}.txt "
            f"-P /usr/share/wordlists/metasploit/default_pass_for_{service}.txt "
            f"{target} -s {port} {service} -t 4 -f -I",
            timeout=120,
        )
        if result.success and "login:" in result.stdout.lower():
            self.add_finding(
                title=f"Weak Credentials on {service.upper()}",
                description=f"Weak credentials found for {service.upper()} service",
                severity=Severity.CRITICAL,
                cvss=9.8,
                evidence=result.stdout[:500],
                remediation="Enforce strong password policy. Implement account lockout after failed attempts.",
                service=service,
                port=port,
            )

    async def test_web_defaults(self, target: str, port: int):
        """Test web application default logins."""
        protocol = "https" if port == 443 else "http"
        common_paths = ["/admin", "/login", "/wp-admin", "/administrator", "/phpmyadmin"]

        for path in common_paths:
            url = f"{protocol}://{target}:{port}{path}"
            result = await self.executor.execute(f"curl -sIo /dev/null -w '%{{http_code}}' {url}", timeout=10)
            if result.success and result.stdout.strip() in ("200", "301", "302"):
                logger.info(f"Found login page at {url}")
                # Try default credentials on found login pages
                for username, password in DEFAULT_CREDENTIALS[:3]:
                    login_result = await self.executor.execute(
                        f"curl -s -o /dev/null -w '%{{http_code}}' -d 'username={username}&password={password}' {url}",
                        timeout=10,
                    )
                    if login_result.success and login_result.stdout.strip() in ("302", "200"):
                        self.add_finding(
                            title=f"Default Web Credentials at {path}",
                            description=f"Login page {url} accepts default credentials",
                            severity=Severity.CRITICAL,
                            cvss=9.8,
                            evidence=f"URL: {url}, Credentials: {username}:{password}",
                            remediation="Change default credentials. Implement MFA.",
                            service="web",
                            port=port,
                        )

    async def test_db_defaults(self, target: str, service: str, port: int):
        """Test database default credentials."""
        db_clients = {
            "mysql": "mysql -h {target} -P {port} -u {user} -p{password} -e 'SELECT version();'",
            "postgresql": "PGPASSWORD={password} psql -h {target} -p {port} -U {user} -c 'SELECT version();'",
        }
        cmd_template = db_clients.get(service)
        if not cmd_template:
            return

        for username, password in DEFAULT_CREDENTIALS[:5]:
            cmd = cmd_template.format(target=target, port=port, user=username, password=password)
            result = await self.executor.execute(cmd, timeout=10)
            if result.success and result.stdout.strip():
                self.add_finding(
                    title=f"Default {service.upper()} Credentials",
                    description=f"{service.upper()} accepts {username}:{password}",
                    severity=Severity.CRITICAL,
                    cvss=9.8,
                    evidence=result.stdout[:500],
                    remediation="Change default database credentials. Restrict remote access.",
                    service=service,
                    port=port,
                )
                return

    async def identify_hash(self, hash_file: str):
        """Identify hash types in a file."""
        result = await self.executor.execute(f"hashid -f {hash_file}", timeout=15)
        if result.success:
            logger.info(f"Hash identification:\n{result.stdout[:500]}")

    async def crack_hashes(self, hash_file: str):
        """Attempt to crack hashes using john."""
        result = await self.executor.execute(
            f"john --wordlist=/usr/share/wordlists/rockyou.txt {hash_file}",
            timeout=300,
        )
        if result.success:
            show_result = await self.executor.execute(f"john --show {hash_file}", timeout=10)
            if show_result.success and "password" in show_result.stdout.lower():
                self.add_finding(
                    title="Password Hashes Cracked",
                    description="Weak password hashes successfully cracked",
                    severity=Severity.HIGH,
                    cvss=7.5,
                    evidence=show_result.stdout[:500],
                    remediation="Enforce strong password policy. Use bcrypt/scrypt for hashing.",
                    service="credentials",
                )
