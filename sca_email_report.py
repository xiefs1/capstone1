import os
import smtplib
from email.message import EmailMessage

def send_sca_pdf():
    SENDER = os.getenv("GMAIL_USER")
    PASSWORD = os.getenv("GMAIL_PASSWORD")
    RECEIVER = os.getenv("GMAIL_RECIPIENT")

    if not all([SENDER, PASSWORD, RECEIVER]):
        raise RuntimeError("Missing email environment variables!")

    msg = EmailMessage()
    msg["Subject"] = "SCA Report PDF"
    msg["From"] = SENDER
    msg["To"] = RECEIVER
    msg.set_content("Attached is your SCA Vulnerability PDF Report.")

    with open("outputs/sca_report.pdf", "rb") as f:
        msg.add_attachment(
            f.read(),
            maintype="application",
            subtype="pdf",
            filename="sca_report.pdf"
        )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(SENDER, PASSWORD)
        smtp.send_message(msg)

    print("Email sent successfully!")

if __name__ == "__main__":
    send_sca_pdf()
