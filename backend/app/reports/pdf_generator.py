import os
from fpdf import FPDF
from typing import Dict, Any

def _clean_text(val: Any) -> str:
    """Sanitize strings to avoid FPDF Helvetica latin-1 encoding errors."""
    if val is None:
        return ""
    text = str(val)
    text = (
        text.replace('•', '-')
        .replace('—', '-')
        .replace('–', '-')
        .replace('“', '"')
        .replace('”', '"')
        .replace("‘", "'")
        .replace("’", "'")
        .replace('…', '...')
        .replace('→', '->')
        .replace('←', '<-')
        .replace('✓', '[PASS]')
        .replace('✗', '[FAIL]')
    )
    return text.encode('latin-1', 'replace').decode('latin-1')

class SentinelPDFReport(FPDF):
    def header(self):
        self.set_fill_color(24, 24, 27)
        self.rect(0, 0, 210, 20, 'F')
        self.set_text_color(255, 255, 255)
        self.set_font('Helvetica', 'B', 12)
        self.set_xy(10, 5)
        self.cell(0, 10, 'SENTINEL AI  |  Autonomous Security Operations Platform', 0, 0, 'L')
        self.set_font('Helvetica', '', 9)
        self.set_xy(10, 5)
        self.cell(190, 10, 'OFFICIAL INCIDENT REPORT', 0, 0, 'R')
        self.set_xy(10, 25)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()} | CONFIDENTIAL & PRIVILEGED | SENTINEL AI SOC', 0, 0, 'C')

def generate_incident_pdf(report: Dict[str, Any], output_path: str) -> str:
    pdf = SentinelPDFReport(orientation='P', unit='mm', format='A4')
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # Title & Metadata
    pdf.set_text_color(17, 24, 39)
    pdf.set_font('Helvetica', 'B', 16)
    pdf.multi_cell(0, 8, _clean_text(report.get("report_title", "SENTINEL AI Incident Report")), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # Metadata Grid
    pdf.set_font('Helvetica', 'B', 8.5)
    pdf.set_fill_color(243, 244, 246)
    pdf.set_text_color(55, 65, 81)
    
    inv_id = _clean_text(report.get("investigation_id", "N/A"))
    gen_time = _clean_text(report.get("generated_at", "N/A"))[:19]
    sev = _clean_text(report.get("severity", "MEDIUM"))
    val_status = _clean_text(report.get("validation_status", "PASSED"))

    pdf.cell(45, 8, f"ID: {inv_id}", 1, 0, 'L', fill=True)
    pdf.cell(50, 8, f"Time: {gen_time}", 1, 0, 'L', fill=True)
    pdf.cell(45, 8, f"Severity: {sev}", 1, 0, 'L', fill=True)
    pdf.cell(50, 8, f"Validation: {val_status}", 1, 1, 'L', fill=True)
    pdf.ln(5)

    # Section 1: Executive Summary
    _add_section(pdf, "1. Executive Summary", _clean_text(report.get("executive_summary", "N/A")))

    # Section 2: Severity Assessment & Rationale
    sev_text = f"Assigned Severity: {sev}\nRationale: {_clean_text(report.get('severity_rationale', 'N/A'))}"
    _add_section(pdf, "2. Severity Assessment", sev_text)

    # Section 3: Affected Assets
    assets = report.get("affected_assets", {}) or {}
    hosts_str = ", ".join(assets.get("hosts", [])) or "None"
    users_str = ", ".join(assets.get("users", [])) or "None"
    ips_str = ", ".join(assets.get("ips", [])) or "None"
    assets_text = f"- Affected Hosts: {_clean_text(hosts_str)}\n- Targeted Accounts: {_clean_text(users_str)}\n- Network Endpoints: {_clean_text(ips_str)}"
    _add_section(pdf, "3. Affected Assets", assets_text)

    # Section 4: MITRE ATT&CK Mappings
    mappings = report.get("mitre_attack_mappings", []) or []
    if mappings:
        pdf.set_font('Helvetica', 'B', 11)
        pdf.set_text_color(17, 24, 39)
        pdf.multi_cell(0, 7, "4. MITRE ATT&CK Technique Mappings", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
        for m in mappings:
            pdf.set_font('Helvetica', 'B', 8.5)
            tech_line = f"- [{_clean_text(m.get('technique_id'))}] {_clean_text(m.get('technique_name'))} (Tactic: {_clean_text(m.get('tactic'))}) - Confidence: {m.get('confidence')}"
            pdf.multi_cell(0, 5, tech_line, new_x="LMARGIN", new_y="NEXT")
            pdf.set_font('Helvetica', 'I', 8)
            pdf.multi_cell(0, 4, f"   Reason: {_clean_text(m.get('reason'))}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)
        pdf.ln(3)

    # Section 5: Threat Intelligence Findings
    intel = report.get("threat_intelligence_findings", []) or []
    if intel:
        pdf.set_font('Helvetica', 'B', 11)
        pdf.set_text_color(17, 24, 39)
        pdf.multi_cell(0, 7, "5. Threat Intelligence Findings", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
        for item in intel:
            pdf.set_font('Helvetica', '', 8.5)
            sim_flag = "[SIMULATED]" if item.get("is_simulated") else "[LIVE]"
            intel_line = f"- {sim_flag} Indicator: {_clean_text(item.get('indicator'))} | Reputation: {item.get('reputation_score')}/100 | Malicious: {item.get('is_malicious')}"
            pdf.multi_cell(0, 5, intel_line, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    # Section 6: Recommended Remediation (Human Approval Required)
    remediation = report.get("recommended_remediation", []) or []
    if remediation:
        pdf.set_font('Helvetica', 'B', 11)
        pdf.set_text_color(17, 24, 39)
        pdf.multi_cell(0, 7, "6. Recommended Remediation (Requires Human Authorization)", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
        for r in remediation:
            pdf.set_font('Helvetica', '', 8.5)
            rem_line = f"[{_clean_text(r.get('priority'))}] {_clean_text(r.get('title'))}: {_clean_text(r.get('description'))} (Human Approval Required: {r.get('requires_human_approval')})"
            pdf.multi_cell(0, 5, rem_line, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    # Section 7: Investigation Limitations
    _add_section(pdf, "7. Investigation Limitations", _clean_text(report.get("investigation_limitations", "None recorded.")))

    # Ensure output dir exists if path contains directories
    dirname = os.path.dirname(output_path)
    if dirname:
        os.makedirs(dirname, exist_ok=True)
    pdf.output(output_path)
    return output_path

def _add_section(pdf: FPDF, title: str, content: str):
    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(17, 24, 39)
    pdf.multi_cell(0, 7, _clean_text(title), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font('Helvetica', '', 8.5)
    pdf.set_text_color(55, 65, 81)
    pdf.multi_cell(0, 4.5, _clean_text(content), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
