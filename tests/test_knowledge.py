"""
Tests for AEGIS Knowledge Base
"""

import pytest
from aegis.knowledge.cve_db import KnowledgeBase, KNOWN_CVES, OWASP_TOP_10


class TestKnowledgeBase:
    """Tests for the knowledge base."""

    def test_lookup_cves_apache(self):
        kb = KnowledgeBase()
        results = kb.lookup_cves("apache")
        assert len(results) > 0
        cve_ids = [r["cve"] for r in results]
        assert "CVE-2021-41773" in cve_ids

    def test_lookup_cves_with_version(self):
        kb = KnowledgeBase()
        results = kb.lookup_cves("apache", "2.4.49")
        assert len(results) > 0

    def test_lookup_cves_unknown(self):
        kb = KnowledgeBase()
        results = kb.lookup_cves("nonexistent_service_xyz")
        assert len(results) == 0

    def test_owasp_mapping(self):
        kb = KnowledgeBase()
        # SQL injection should map to A03
        results = kb.map_to_owasp("SQL injection vulnerability in login form")
        codes = [r["code"] for r in results]
        assert "A03" in codes

    def test_owasp_mapping_auth(self):
        kb = KnowledgeBase()
        results = kb.map_to_owasp("brute force password attack on SSH")
        codes = [r["code"] for r in results]
        assert "A07" in codes

    def test_keyword_search(self):
        kb = KnowledgeBase()
        results = kb.search("apache vulnerability")
        assert len(results) > 0

    def test_embedded_cve_data(self):
        """Verify embedded CVE data structure."""
        for service, cves in KNOWN_CVES.items():
            for cve in cves:
                assert "cve" in cve
                assert "cvss" in cve
                assert "description" in cve
                assert cve["cvss"] >= 0 and cve["cvss"] <= 10

    def test_owasp_data_structure(self):
        """Verify OWASP data structure."""
        assert len(OWASP_TOP_10) == 10
        for code, info in OWASP_TOP_10.items():
            assert code.startswith("A")
            assert "name" in info
            assert "keywords" in info
            assert len(info["keywords"]) > 0
