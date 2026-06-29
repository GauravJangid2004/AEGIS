"""
AEGIS Report Generator
========================

Generates professional penetration test reports in PDF and JSON formats.
Uses AI to write executive summaries, technical findings, and remediation plans.
"""

import json
import os
import datetime
from pathlib import Path
from typing import Optional
from loguru import logger

from aegis.config import config
from aegis.core.ai_engine import AIEngine
from aegis.core.chain import AttackChain
from aegis.knowledge.cve_db import KnowledgeBase


class ReportGenerator:
    """
    Generates comprehensive penetration test reports.
    Supports PDF (via ReportLab) and JSON output formats.
    """

    def __init__(self, ai_engine: Optional[AIEngine] = None):
        self.ai = ai_engine or AIEngine()
        self.kb = KnowledgeBase()
        self.output_dir = Path(config.report.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def generate(
        self,
        chain: AttackChain,
        target_profile: Optional[dict] = None,
        format: str = "both",
    ) -> dict:
        """
        Generate a complete pentest report.

        Args:
            chain: The completed attack chain
            target_profile: Optional recon profile data
            format: 'pdf', 'json', or 'both'

        Returns:
            dict with report data and file paths
        """
        logger.info(f"[Report] Generating report for target: {chain.target}")

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"AEGIS_Report_{chain.target}_{timestamp}"

        # Build report data
        report = await self._build_report(chain, target_profile)

        # Export
        paths = {}
        if format in ("json", "both"):
            json_path = self.output_dir / f"{report_name}.json"
            self._export_json(report, json_path)
            paths["json"] = str(json_path)
            logger.info(f"[Report] JSON saved: {json_path}")

        if format in ("pdf", "both"):
            pdf_path = self.output_dir / f"{report_name}.pdf"
            self._export_pdf(report, pdf_path)
            paths["pdf"] = str(pdf_path)
            logger.info(f"[Report] PDF saved: {pdf_path}")

        report["file_paths"] = paths
        return report

    async def _build_report(
        self,
        chain: AttackChain,
        target_profile: Optional[dict],
    ) -> dict:
        """Build the complete report data structure."""
        pentest_data = {
            "target": chain.target,
            "findings": [f.to_dict() for f in chain.findings],
            "attack_chain": [s.to_dict() for s in chain.steps],
            "target_profile": target_profile or {},
        }

        # AI-generated sections
        exec_summary = await self.ai.write_report_section("executive_summary", pentest_data)
        tech_findings = await self.ai.write_report_section("technical_findings", pentest_data)
        attack_narrative = await self.ai.write_report_section("attack_narrative", pentest_data)
        remediation = await self.ai.write_report_section("remediation", pentest_data)
        compliance = await self.ai.write_report_section("compliance_mapping", pentest_data)

        # OWASP mapping
        owasp_mapping = []
        for finding in chain.findings:
            mapped = self.kb.map_to_owasp(f"{finding.title} {finding.description}")
            if mapped:
                owasp_mapping.append({
                    "finding": finding.title,
                    "owasp": mapped,
                })

        report = {
            "metadata": {
                "title": "Penetration Test Report",
                "target": chain.target,
                "date": datetime.datetime.now().isoformat(),
                "tester": "AEGIS AI Pentest Agent v1.0",
                "classification": config.report.classification,
                "company": config.report.company_name,
                "chain_id": chain.id,
                "scope": chain.scope,
            },
            "executive_summary": exec_summary,
            "overall_risk": chain.get_overall_risk(),
            "risk_summary": chain.get_risk_summary(),
            "attack_surface": target_profile or {},
            "vulnerabilities": [f.to_dict() for f in chain.findings],
            "attack_chain": {
                "total_steps": len(chain.steps),
                "successful_steps": len(chain.get_successful_steps()),
                "narrative": attack_narrative,
                "steps": [s.to_dict() for s in chain.steps],
            },
            "technical_findings": tech_findings,
            "remediation": remediation,
            "compliance_mapping": {
                "narrative": compliance,
                "owasp_mapping": owasp_mapping,
            },
            "terminal_log": [
                {
                    "step": s.step_number,
                    "command": s.command,
                    "output": s.actual_result[:500],
                    "timestamp": s.timestamp,
                }
                for s in chain.steps
            ],
        }

        return report

    def _export_json(self, report: dict, path: Path):
        """Export report as JSON."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)

    def _export_pdf(self, report: dict, path: Path):
        """Export report as PDF using ReportLab."""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch, cm
            from reportlab.lib.colors import HexColor
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                PageBreak, HRFlowable,
            )
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
        except ImportError:
            logger.warning("ReportLab not installed, skipping PDF generation")
            return

        doc = SimpleDocTemplate(
            str(path), pagesize=A4,
            rightMargin=2*cm, leftMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm,
        )

        styles = getSampleStyleSheet()
        # Custom styles
        styles.add(ParagraphStyle(
            "AegisTitle", parent=styles["Title"],
            fontSize=28, textColor=HexColor("#1a1a2e"),
            spaceAfter=20, alignment=TA_CENTER,
        ))
        styles.add(ParagraphStyle(
            "AegisHeading", parent=styles["Heading1"],
            fontSize=16, textColor=HexColor("#16213e"),
            spaceAfter=12, spaceBefore=20,
        ))
        styles.add(ParagraphStyle(
            "AegisBody", parent=styles["Normal"],
            fontSize=10, leading=14, alignment=TA_JUSTIFY,
            spaceAfter=8,
        ))
        styles.add(ParagraphStyle(
            "AegisCode", parent=styles["Code"],
            fontSize=8, leading=10, backColor=HexColor("#f0f0f0"),
        ))

        elements = []

        # ─── Cover Page ───
        elements.append(Spacer(1, 3*inch))
        elements.append(Paragraph("🛡️ AEGIS", styles["AegisTitle"]))
        elements.append(Paragraph("PENETRATION TEST REPORT", styles["AegisTitle"]))
        elements.append(Spacer(1, 0.5*inch))

        meta = report["metadata"]
        cover_data = [
            ["Target", meta["target"]],
            ["Date", meta["date"][:10]],
            ["Classification", meta["classification"]],
            ["Tester", meta["tester"]],
            ["Overall Risk", report["overall_risk"]],
        ]
        cover_table = Table(cover_data, colWidths=[2*inch, 4*inch])
        risk_color = {
            "CRITICAL": HexColor("#e74c3c"),
            "HIGH": HexColor("#e67e22"),
            "MEDIUM": HexColor("#f39c12"),
            "LOW": HexColor("#27ae60"),
        }.get(report["overall_risk"], HexColor("#3498db"))

        cover_table.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 11),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("TEXTCOLOR", (-1, -1), (-1, -1), risk_color),
        ]))
        elements.append(cover_table)
        elements.append(PageBreak())

        # ─── Executive Summary ───
        elements.append(Paragraph("1. Executive Summary", styles["AegisHeading"]))
        elements.append(Paragraph(
            str(report.get("executive_summary", "N/A")).replace("\n", "<br/>"),
            styles["AegisBody"],
        ))

        # Risk summary table
        risk = report["risk_summary"]
        risk_data = [["Severity", "Count"]]
        for sev in ["critical", "high", "medium", "low", "info"]:
            risk_data.append([sev.upper(), str(risk.get(sev, 0))])
        risk_table = Table(risk_data, colWidths=[2*inch, 1*inch])
        risk_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#16213e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#f8f9fa"), HexColor("#ffffff")]),
        ]))
        elements.append(Spacer(1, 0.3*inch))
        elements.append(risk_table)
        elements.append(PageBreak())

        # ─── Vulnerabilities ───
        elements.append(Paragraph("2. Vulnerability Findings", styles["AegisHeading"]))
        for i, vuln in enumerate(report.get("vulnerabilities", []), 1):
            sev = vuln.get("severity", "info").upper()
            elements.append(Paragraph(
                f"<b>Finding #{i}: {vuln.get('title', 'N/A')}</b> [{sev}]",
                styles["AegisBody"],
            ))
            if vuln.get("cve_id"):
                elements.append(Paragraph(f"CVE: {vuln['cve_id']} | CVSS: {vuln.get('cvss_score', 'N/A')}", styles["AegisBody"]))
            elements.append(Paragraph(vuln.get("description", ""), styles["AegisBody"]))
            if vuln.get("evidence"):
                elements.append(Paragraph(f"<b>Evidence:</b><br/>{vuln['evidence'][:300]}", styles["AegisCode"]))
            if vuln.get("remediation"):
                elements.append(Paragraph(f"<b>Remediation:</b> {vuln['remediation']}", styles["AegisBody"]))
            elements.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#eeeeee")))
            elements.append(Spacer(1, 0.15*inch))

        elements.append(PageBreak())

        # ─── Attack Chain Narrative ───
        elements.append(Paragraph("3. Attack Chain Narrative", styles["AegisHeading"]))
        narrative = report.get("attack_chain", {}).get("narrative", "N/A")
        elements.append(Paragraph(
            str(narrative).replace("\n", "<br/>"),
            styles["AegisBody"],
        ))
        elements.append(PageBreak())

        # ─── Remediation ───
        elements.append(Paragraph("4. Remediation Roadmap", styles["AegisHeading"]))
        elements.append(Paragraph(
            str(report.get("remediation", "N/A")).replace("\n", "<br/>"),
            styles["AegisBody"],
        ))
        elements.append(PageBreak())

        # ─── Compliance ───
        elements.append(Paragraph("5. Compliance Mapping", styles["AegisHeading"]))
        elements.append(Paragraph(
            str(report.get("compliance_mapping", {}).get("narrative", "N/A")).replace("\n", "<br/>"),
            styles["AegisBody"],
        ))

        # ─── Terminal Log ───
        elements.append(PageBreak())
        elements.append(Paragraph("6. Complete Terminal Log", styles["AegisHeading"]))
        for entry in report.get("terminal_log", [])[:30]:
            elements.append(Paragraph(
                f"<b>Step {entry['step']}:</b> <font face='Courier' size='8'>{entry['command'][:100]}</font>",
                styles["AegisBody"],
            ))

        # Build PDF
        try:
            doc.build(elements)
            logger.info(f"PDF report generated: {path}")
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
