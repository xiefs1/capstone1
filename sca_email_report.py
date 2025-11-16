import smtplib
from email.message import EmailMessage

SENDER = "minghau2003@gmail.com"
PASSWORD = "nrmlerkhtbbuokdh"
RECEIVER = "minghau2003@gmail.com"

def send_sca_pdf():
    msg = EmailMessage()
    msg["Subject"] = "SCA Report PDF"
    msg["From"] = SENDER
    msg["To"] = RECEIVER
    msg.set_content("Attached is your SCA Vulnerability PDF Report.")

    with open("outputs/sca_report.pdf", "rb") as f:
        pdf_data = f.read()

    msg.add_attachment(pdf_data, maintype="application", subtype="pdf", filename="sca_report.pdf")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(SENDER, PASSWORD)
        smtp.send_message(msg)

    print("Email sent successfully!")

if __name__ == "__main__":
    send_sca_pdf()
