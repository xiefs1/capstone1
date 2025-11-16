from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import json

def sca_json_to_pdf(json_file="outputs/sca_report.json", pdf_file="outputs/sca_report.pdf"):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(pdf_file, pagesize=A4)
    story = []

    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    story.append(Paragraph("<b>SCA Vulnerability Report</b>", styles['Title']))
    story.append(Spacer(1, 20))

    for item in data:
        story.append(Paragraph(f"<b>Package:</b> {item['package']}", styles['Normal']))
        story.append(Paragraph(f"<b>Version:</b> {item['version']}", styles['Normal']))
        story.append(Paragraph(f"<b>Ecosystem:</b> {item['ecosystem']}", styles['Normal']))
        story.append(Paragraph(f"<b>Status:</b> {item['rule_label']}", styles['Normal']))
        story.append(Paragraph(f"<b>OSV ID:</b> {item['osv_vuln_id']}", styles['Normal']))
        story.append(Spacer(1, 15))

    doc.build(story)
    print(f"PDF saved → {pdf_file}")


if __name__ == "__main__":
    sca_json_to_pdf()
