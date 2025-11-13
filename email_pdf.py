import os
import smtplib
from email.message import EmailMessage

def send_pdf_email():
    sender = os.getenv("GMAIL_USER")
    password = os.getenv("GMAIL_PASSWORD")
    recipient = os.getenv("GMAIL_RECIPIENT", sender)

    pdf_path = "outputs/sast_report.pdf"

    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"PDF not found at: {pdf_path}")

    msg = EmailMessage()
    msg["Subject"] = "GitLab CI – SAST PDF Report"
    msg["From"] = sender
    msg["To"] = recipient
    msg.set_content("Hi,\n\nYour SAST PDF report is attached.\n\nRegards,\nCI Pipeline")

    with open(pdf_path, "rb") as f:
        pdf_data = f.read()

    msg.add_attachment(
        pdf_data,
        maintype="application",
        subtype="pdf",
        filename="sast_report.pdf"
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(sender, password)
        smtp.send_message(msg)

    print(f"Email sent to {recipient}")

if __name__ == "__main__":
    send_pdf_email()
