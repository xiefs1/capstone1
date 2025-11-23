import pdfkit
import smtplib
import json
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import encoders
import os


# -----------------------------
# CONFIGURATION
# -----------------------------
HTML_FILE = "zap-report.html"
JSON_FILE = "zap-report.json"

HTML_PDF = "zap-report-html.pdf"
JSON_PDF = "zap-report-json.pdf"

# Gmail config
GMAIL_EMAIL = "minghau2003@gmail.com"
GMAIL_PASSWORD = "nrmlerkhtbbuokdh"      # Gmail App Password
GMAIL_RECIPIENT = "minghau2003@gmail.com"

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# Path to wkhtmltopdf (Windows)
WKHTMLTOPDF_PATH = r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"
config = pdfkit.configuration(wkhtmltopdf=WKHTMLTOPDF_PATH)


# -----------------------------
# STEP 1 — Convert HTML → PDF
# -----------------------------
print("[*] Converting HTML report to PDF...")

pdfkit.from_file(HTML_FILE, HTML_PDF, configuration=config)

print(f"[+] Saved {HTML_PDF}")


# -----------------------------
# STEP 2 — Convert JSON → PDF
# -----------------------------
print("[*] Converting JSON report to PDF...")

def json_to_pdf(json_file, output_pdf):
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.loads(f.read())

    c = canvas.Canvas(output_pdf, pagesize=letter)
    width, height = letter

    x = 40
    y = height - 40

    def write_line(text):
        nonlocal y
        if y < 50:  # New page
            c.showPage()
            y = height - 40
        c.drawString(x, y, text)
        y -= 14

    write_line("ZAP JSON REPORT")
    write_line("--------------------------------------------")

    # Dump top-level keys only (JSON can be huge)
    for key, value in data.items():
        line = f"{key}: {str(value)[:200]}"
        write_line(line)

    c.save()


json_to_pdf(JSON_FILE, JSON_PDF)
print(f"[+] Saved {JSON_PDF}")


# -----------------------------
# STEP 3 — Prepare Email
# -----------------------------
print("[*] Preparing email...")

msg = MIMEMultipart()
msg["From"] = GMAIL_EMAIL
msg["To"] = GMAIL_RECIPIENT
msg["Subject"] = "ZAP Scan Reports (HTML + JSON PDF)"

body = "Attached are your ZAP scan reports in PDF format."
msg.attach(MIMEText(body, "plain"))


def attach_file(filename):
    with open(filename, "rb") as f:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename={filename}")
        msg.attach(part)


# Attach PDFs
attach_file(HTML_PDF)
attach_file(JSON_PDF)


# -----------------------------
# STEP 4 — Send Email
# -----------------------------
print("[*] Sending email...")

server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
server.starttls()
server.login(GMAIL_EMAIL, GMAIL_PASSWORD)
server.sendmail(GMAIL_EMAIL, GMAIL_RECIPIENT, msg.as_string())
server.quit()

print("[+] Email sent successfully!")
