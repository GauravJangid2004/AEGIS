"""
AEGIS Knowledge Base
======================

CVE database, exploit information, and technique knowledge
stored in ChromaDB for semantic search by the AI engine.
"""

import json
import os
from pathlib import Path
from typing import Optional
from loguru import logger

from aegis.config import config

# Known CVE data for common services (embedded knowledge)
KNOWN_CVES = {
    "apache": [
        {"cve": "CVE-2021-41773", "cvss": 9.8, "versions": "2.4.49",
         "description": "Path Traversal and RCE in Apache HTTP Server",
         "exploit": "curl -s --path-as-is 'http://TARGET/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd'"},
        {"cve": "CVE-2021-42013", "cvss": 9.8, "versions": "2.4.49, 2.4.50",
         "description": "Path Traversal RCE bypass for CVE-2021-41773"},
        {"cve": "CVE-2019-0211", "cvss": 7.8, "versions": "2.4.17-2.4.38",
         "description": "Apache privilege escalation via scoreboard manipulation"},
    ],
    "nginx": [
        {"cve": "CVE-2021-23017", "cvss": 7.7, "versions": "0.6.18-1.20.0",
         "description": "DNS resolver off-by-one heap write"},
    ],
    "openssh": [
        {"cve": "CVE-2023-38408", "cvss": 9.8, "versions": "before 9.3p2",
         "description": "Remote code execution via ssh-agent forwarding"},
        {"cve": "CVE-2024-6387", "cvss": 8.1, "versions": "8.5p1-9.7p1",
         "description": "regreSSHion — Race condition in signal handling RCE"},
    ],
    "mysql": [
        {"cve": "CVE-2012-2122", "cvss": 7.5, "versions": "5.1.x, 5.5.x, 5.6.x",
         "description": "Authentication bypass via timing attack"},
    ],
    "vsftpd": [
        {"cve": "CVE-2011-2523", "cvss": 9.8, "versions": "2.3.4",
         "description": "Backdoor command execution (smiley face trigger)"},
    ],
    "samba": [
        {"cve": "CVE-2017-7494", "cvss": 9.8, "versions": "3.5.0-4.6.4",
         "description": "SambaCry — Remote code execution via writable share"},
    ],
    "tomcat": [
        {"cve": "CVE-2017-12617", "cvss": 8.1, "versions": "7.0.0-7.0.81, 9.0.0M1-9.0.1",
         "description": "Remote code execution via PUT method"},
    ],
    "log4j": [
        {"cve": "CVE-2021-44228", "cvss": 10.0, "versions": "2.0-2.14.1",
         "description": "Log4Shell — Remote code execution via JNDI lookup"},
    ],
    "redis": [
        {"cve": "CVE-2022-0543", "cvss": 10.0, "versions": "various",
         "description": "Lua sandbox escape leading to RCE"},
    ],
    "wordpress": [
        {"cve": "CVE-2023-2982", "cvss": 9.8, "versions": "various plugins",
         "description": "Multiple plugin vulnerabilities allowing RCE"},
    ],
}

# OWASP Top 10 mapping
OWASP_TOP_10 = {
    "A01": {"name": "Broken Access Control", "keywords": ["privilege escalation", "idor", "access control", "authorization"]},
    "A02": {"name": "Cryptographic Failures", "keywords": ["ssl", "tls", "encryption", "hash", "plaintext"]},
    "A03": {"name": "Injection", "keywords": ["sqli", "sql injection", "xss", "command injection", "xxe", "ldap"]},
    "A04": {"name": "Insecure Design", "keywords": ["design flaw", "business logic"]},
    "A05": {"name": "Security Misconfiguration", "keywords": ["default", "misconfiguration", "unnecessary", "verbose error"]},
    "A06": {"name": "Vulnerable Components", "keywords": ["cve", "outdated", "vulnerable version", "dependency"]},
    "A07": {"name": "Auth Failures", "keywords": ["authentication", "brute force", "credential", "password", "session"]},
    "A08": {"name": "Software & Data Integrity", "keywords": ["deserialization", "supply chain", "ci/cd"]},
    "A09": {"name": "Logging Failures", "keywords": ["logging", "monitoring", "audit"]},
    "A10": {"name": "SSRF", "keywords": ["ssrf", "server-side request"]},
}


class KnowledgeBase:
    """
    Knowledge base for CVEs, exploits, and security techniques.
    Uses embedded knowledge and optionally ChromaDB for semantic search.
    """

    def __init__(self):
        self.chromadb_client = None
        self.collection = None
        self._init_chromadb()

    def _init_chromadb(self):
        """Initialize ChromaDB if available."""
        try:
            import chromadb
            persist_dir = config.chromadb_dir
            os.makedirs(persist_dir, exist_ok=True)
            self.chromadb_client = chromadb.PersistentClient(path=persist_dir)
            self.collection = self.chromadb_client.get_or_create_collection(
                name="aegis_knowledge",
                metadata={"description": "AEGIS security knowledge base"},
            )
            logger.info(f"ChromaDB initialized — {self.collection.count()} documents")
        except ImportError:
            logger.warning("ChromaDB not installed, using embedded knowledge only")
        except Exception as e:
            logger.warning(f"ChromaDB init failed: {e}, using embedded knowledge")

    def lookup_cves(self, service: str, version: str = "") -> list[dict]:
        """Look up known CVEs for a service and version."""
        service_lower = service.lower()
        results = []

        for svc_key, cves in KNOWN_CVES.items():
            if svc_key in service_lower:
                for cve in cves:
                    if not version or version in cve.get("versions", ""):
                        results.append(cve)

        return results

    def map_to_owasp(self, finding_description: str) -> list[dict]:
        """Map a finding to OWASP Top 10 categories."""
        desc_lower = finding_description.lower()
        matches = []

        for code, info in OWASP_TOP_10.items():
            for keyword in info["keywords"]:
                if keyword in desc_lower:
                    matches.append({"code": code, "name": info["name"]})
                    break

        return matches

    def search(self, query: str, n_results: int = 5) -> list[dict]:
        """Semantic search across the knowledge base."""
        if self.collection and self.collection.count() > 0:
            try:
                results = self.collection.query(
                    query_texts=[query],
                    n_results=n_results,
                )
                return [
                    {"document": doc, "metadata": meta}
                    for doc, meta in zip(
                        results["documents"][0],
                        results["metadatas"][0],
                    )
                ]
            except Exception as e:
                logger.error(f"ChromaDB search error: {e}")

        # Fallback: keyword search in embedded knowledge
        return self._keyword_search(query)

    def _keyword_search(self, query: str) -> list[dict]:
        """Simple keyword search fallback."""
        query_lower = query.lower()
        results = []

        for service, cves in KNOWN_CVES.items():
            if service in query_lower:
                for cve in cves:
                    results.append({
                        "document": f"{cve['cve']}: {cve['description']}",
                        "metadata": {"service": service, "cvss": cve["cvss"]},
                    })

        return results[:5]

    def add_knowledge(self, documents: list[str], metadatas: list[dict], ids: list[str]):
        """Add documents to the knowledge base."""
        if self.collection:
            try:
                self.collection.add(
                    documents=documents,
                    metadatas=metadatas,
                    ids=ids,
                )
                logger.info(f"Added {len(documents)} documents to knowledge base")
            except Exception as e:
                logger.error(f"Failed to add knowledge: {e}")
