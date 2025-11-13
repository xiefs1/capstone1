import json
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.colors import red, orange, yellow, black, blue, lightblue
from reportlab.lib.utils import simpleSplit
from reportlab.pdfbase.pdfmetrics import stringWidth


def wrap_text(c, text, x, y, max_width, font="Helvetica", size=10, leading=13):
    """Draw wrapped text block and return new y."""
    c.setFont(font, size)
    if not text:
        return y
    lines = simpleSplit(text, font, size, max_width)
    for line in lines:
        c.drawString(x, y, line)
        y -= leading
    return y


def get_severity_color(sev: str):
    sev = (sev or "").lower()
    if sev == "high":
        return red
    if sev == "medium":
        return orange
    # default / low
    return blue


def json_to_pdf(json_path, pdf_path):
    with open(json_path, "r", encoding="utf-8") as f:
        findings = json.load(f)   # your JSON is a LIST

    # Page + layout settings
    page_size = A4
    c = canvas.Canvas(pdf_path, pagesize=page_size)
    width, height = page_size
    margin = 50
    content_width = width - 2 * margin
    label_indent = margin
    text_indent = margin + 18

    y = height - 60

    # === Report header ===
    c.setFont("Helvetica-Bold", 18)
    c.drawString(margin, y, "SAST Security Report")
    y -= 28

    c.setFont("Helvetica", 11)
    c.drawString(margin, y, f"Source JSON: {json_path}")
    y -= 18

    c.drawString(margin, y, f"Total Vulnerabilities Found: {len(findings)}")
    y -= 30

    # === Each finding ===
    for idx, item in enumerate(findings, start=1):
        vuln = item.get("vulnerability", {})
        name = vuln.get("name", "Unknown")
        severity = vuln.get("severity", "Unknown")
        snippet = item.get("code_snippet", "")
        description = item.get("issue_description", "")
        impact = item.get("impact", "")
        rec = item.get("recommendation", {})
        fixed_code = rec.get("fixed_code", "")
        explanation = rec.get("explanation", "")

        # New page if needed
        if y < 140:
            c.showPage()
            y = height - 60

        # Divider line
        c.setStrokeColor(black)
        c.line(margin, y, width - margin, y)
        y -= 16

        # === Row: index + name (left) | severity (right) ===
        title = f"{idx}. {name}"
        c.setFont("Helvetica-Bold", 13)
        c.drawString(margin, y, title)

        sev_text = f"Severity: {severity}"
        sev_width = stringWidth(sev_text, "Helvetica-Bold", 11)
        c.setFont("Helvetica-Bold", 11)
        c.setFillColor(get_severity_color(severity))
        c.drawString(width - margin - sev_width, y, sev_text)
        c.setFillColor(black)
        y -= 22

        # === Sections ===
        # Code Snippet
        c.setFont("Helvetica-Bold", 11)
        c.drawString(label_indent, y, "Code Snippet:")
        y -= 14
        y = wrap_text(c, snippet, text_indent, y, content_width - 18)

        # Description
        c.setFont("Helvetica-Bold", 11)
        c.drawString(label_indent, y, "Description:")
        y -= 14
        y = wrap_text(c, description, text_indent, y, content_width - 18)

        # Impact
        c.setFont("Helvetica-Bold", 11)
        c.drawString(label_indent, y, "Impact:")
        y -= 14
        y = wrap_text(c, impact, text_indent, y, content_width - 18)

        # Fix Recommendation
        c.setFont("Helvetica-Bold", 11)
        c.drawString(label_indent, y, "Fix Recommendation:")
        y -= 14
        y = wrap_text(c, fixed_code, text_indent, y, content_width - 18)

        # Explanation
        c.setFont("Helvetica-Bold", 11)
        c.drawString(label_indent, y, "Explanation:")
        y -= 14
        y = wrap_text(c, explanation, text_indent, y, content_width - 18)

        y -= 18   # space before next vuln

    c.save()
    print(f"PDF generated: {pdf_path}")


if __name__ == "__main__":
    json_to_pdf("sast_enhanced_report.json", "sast_report.pdf")
