#!/usr/bin/env python3
import json
import smtplib
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import encoders
import os

# ====================================================
# CONFIG
# ====================================================
JSON_FILE = "gl-dast-report.json"
OUTPUT_PDF = "ZAP-Security-Report.pdf"

GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_PASSWORD = os.getenv("GMAIL_PASSWORD")
GMAIL_RECIPIENT = os.getenv("GMAIL_RECIPIENT")

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# ====================================================
# LOAD JSON
# ====================================================
with open(JSON_FILE, "r", encoding="utf-8") as f:
    data = json.load(f)

vulns = data.get("vulnerabilities", [])

# ====================================================
# STYLES
# ====================================================
styles = getSampleStyleSheet()

title_style = ParagraphStyle(
    name="TitleStyle",
    parent=styles["Title"],
    fontSize=26,
    alignment=1,
    spaceAfter=20,
)

header_style = ParagraphStyle(
    name="HeaderStyle",
    parent=styles["Heading2"],
    fontSize=18,
    spaceAfter=10,
)

normal_style = ParagraphStyle(
    name="NormalStyle",
    parent=styles["BodyText"],
    fontSize=12,
    leading=16,
)

cell_style = ParagraphStyle(
    name="CellStyle",
    fontName="Helvetica",
    fontSize=10,
    leading=14,
    alignment=TA_LEFT,
)

severity_colors = {
    "Critical": colors.red,
    "High": colors.red,
    "Medium": colors.orange,
    "Low": colors.yellow,
    "Info": colors.blue,
}

# ====================================================
# BUILD PDF
# ====================================================
doc = SimpleDocTemplate(OUTPUT_PDF, pagesize=letter)
story = []

# TITLE PAGE
story.append(Paragraph("OWASP ZAP Security Scan Report", title_style))
story.append(Paragraph("Generated Automatically via GitLab CI/CD", header_style))
story.append(Spacer(1, 20))

story.append(Paragraph(
    f"<b>Total Vulnerabilities Found:</b> {len(vulns)}",
    normal_style
))
story.append(PageBreak())

# ====================================================
# VULNERABILITY SECTIONS
# ====================================================
for v in vulns:
    sev = v.get("severity", "Unknown").capitalize()
    desc = v.get("description", "No description provided.")
    msg = v.get("message", "No message provided.")
    identifier = v.get("id", "N/A")
    links = v.get("links", [])
    location = v.get("location", {}).get("url", "N/A")

    # Convert references
    ref_list = []
    for item in links:
        if isinstance(item, dict):
            ref_list.append(item.get("url") or item.get("href") or str(item))
        else:
            ref_list.append(str(item))
    references = ", ".join(ref_list) if ref_list else "None"

    # SEVERITY BANNER (auto text color)
    bg_color = severity_colors.get(sev, colors.grey)
    text_color = colors.white if sev in ["High", "Critical"] else colors.black

    banner = Table(
        [[f" SEVERITY: {sev} "]],
        colWidths=[480]
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg_color),
        ("TEXTCOLOR", (0, 0), (-1, -1), text_color),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 0), (-1, -1), 14),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(banner)
    story.append(Spacer(1, 15))

    # Wrap fields using Paragraph
    desc_p = Paragraph(desc.replace("\n", "<br/>"), cell_style)
    msg_p = Paragraph(msg.replace("\n", "<br/>"), cell_style)
    ref_p = Paragraph(references.replace("\n", "<br/>"), cell_style)
    url_p = Paragraph(location, cell_style)
    id_p = Paragraph(identifier, cell_style)

    # TABLE DATA
    table_data = [
        ["ID", id_p],
        ["URL", url_p],
        ["Description", desc_p],
        ["Message", msg_p],
        ["References", ref_p],
    ]

    table = Table(
        table_data,
        colWidths=[100, 380],
        hAlign="LEFT"
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.black),

        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),

        ("VALIGN", (0, 0), (-1, -1), "TOP"),

        ("BOX", (0, 0), (-1, -1), 1, colors.black),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.grey),

        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),

        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
    ]))

    story.append(table)
    story.append(Spacer(1, 20))
    story.append(PageBreak())

doc.build(story)
print(f"[+] PDF created successfully: {OUTPUT_PDF}")

# ====================================================
# SEND EMAIL
# ====================================================
msg = MIMEMultipart()
msg["From"] = GMAIL_USER
msg["To"] = GMAIL_RECIPIENT
msg["Subject"] = "ZAP Scan Report (PDF)"

msg.attach(MIMEText("Attached is your ZAP Security Scan PDF Report.", "plain"))

with open(OUTPUT_PDF, "rb") as f:
    part = MIMEBase("application", "octet-stream")
    part.set_payload(f.read())
    encoders.encode_base64(part)
    part.add_header(
        "Content-Disposition",
        f"attachment; filename={OUTPUT_PDF}"
    )
    msg.attach(part)

server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
server.starttls()
server.login(GMAIL_USER, GMAIL_PASSWORD)
server.sendmail(GMAIL_USER, GMAIL_RECIPIENT, msg.as_string())
server.quit()

print("[+] Email sent successfully!")
