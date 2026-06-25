from datetime import datetime
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak


def _p(text, style):
    return Paragraph(str(text or ""), style)


def _table(data, widths=None):
    tbl = Table(data, colWidths=widths, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
    ]))
    return tbl


def generate_audit_report(assets, risks, controls, findings=None) -> bytes:
    findings = findings or []
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), rightMargin=24, leftMargin=24, topMargin=24, bottomMargin=24)
    styles = getSampleStyleSheet()
    normal = styles["BodyText"]
    story = []
    critical = [r for r in risks if r.severity == "Critical"]
    open_risks = [r for r in risks if r.status == "Open"]
    open_findings = [f for f in findings if f.status != "Closed"]

    story.append(Paragraph("CyberRisk Manager - Audit Report", styles["Title"]))
    story.append(Paragraph(f"Date generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(Paragraph(f"The environment contains {len(assets)} assets, {len(risks)} risks, {len(critical)} critical risks, {len(open_risks)} open risks, and {len(open_findings)} open audit findings. This report summarizes the current cyber risk posture, security controls, audit findings, and prioritized recommendations.", normal))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Asset Overview", styles["Heading2"]))
    story.append(_table([["Name", "Type", "Owner", "Criticality", "Location"]] + [[_p(a.name, normal), a.asset_type, a.owner, a.criticality, a.location] for a in assets], widths=[150, 90, 100, 70, 100]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Risk Register", styles["Heading2"]))
    story.append(_table([["Title", "Asset", "L", "I", "Score", "Severity", "Status", "Treatment", "Owner", "Due", "Recommendation"]] + [[_p(r.title, normal), _p(r.asset.name if r.asset else "Unassigned", normal), r.likelihood, r.impact, r.calculated_risk_score, r.severity, r.status, r.treatment_plan, _p(r.risk_owner, normal), str(r.target_date or ""), _p(r.recommendation, normal)] for r in risks], widths=[130, 90, 22, 22, 35, 50, 55, 60, 75, 60, 190]))
    story.append(PageBreak())

    story.append(Paragraph("Critical Risks", styles["Heading2"]))
    critical_rows = [[_p(r.title, normal), _p(r.asset.name if r.asset else "Unassigned", normal), r.calculated_risk_score, _p(r.recommendation, normal)] for r in critical] or [["No critical risks", "", "", ""]]
    story.append(_table([["Risk", "Asset", "Score", "Recommendation"]] + critical_rows, widths=[190, 120, 50, 360]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Security Controls", styles["Heading2"]))
    story.append(_table([["Name", "ISO 27001", "NIST CSF", "Status", "Owner", "Related Risk", "Evidence"]] + [[_p(c.name, normal), c.iso27001_reference, c.nist_csf_function, c.implementation_status, c.owner, _p(c.risk.title if c.risk else "General", normal), _p(c.evidence_link, normal)] for c in controls], widths=[120, 65, 65, 85, 80, 180, 150]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Audit Findings", styles["Heading2"]))
    finding_rows = [[f.finding_id, _p(f.observation, normal), f.risk_rating, _p(f.owner, normal), str(f.due_date or ""), f.status, _p(f.recommendation, normal)] for f in findings] or [["No findings", "", "", "", "", "", ""]]
    story.append(_table([["ID", "Observation", "Rating", "Owner", "Due", "Status", "Recommendation"]] + finding_rows, widths=[65, 220, 55, 80, 60, 60, 240]))

    story.append(Paragraph("Recommendations", styles["Heading2"]))
    seen = set()
    for rec in [r.recommendation for r in risks if r.status in {"Open", "In Progress"}] + [f.recommendation for f in findings if f.status != "Closed"]:
        if rec and rec not in seen:
            story.append(Paragraph(f"• {rec}", normal))
            seen.add(rec)

    doc.build(story)
    buffer.seek(0)
    return buffer.read()
