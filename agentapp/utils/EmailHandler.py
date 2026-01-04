import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import aiosmtplib
from aiosmtplib import SMTPException
import logging

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)

class EmailHandler():
    def __init__(self, host: str, port: int, username: str, password: str, sender: str, tls: bool = True):
        self.smtp_host = host
        self.smtp_port = port
        self.username = username
        self.password = password
        self.sender = sender
        self.tls = tls
        self.logger = logging.getLogger(__name__)

    async def send_email(
        self,
        recipient: str,
        subject: str,
        message: str
    ):
        # Create MIME email
        msg = MIMEMultipart()
        msg["From"] = self.sender
        msg["To"] = recipient
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))

        try:

            # Connect and send
            eml_result = await aiosmtplib.send(
                msg,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.username,
                password=self.password,
                start_tls=self.tls, 
            )

            return eml_result
        except Exception as e:
            logging.error(f"Failed to send email: {e}")
        except SMTPException as smtp_e:
            logging.error(f"SMTP error occurred: {smtp_e}")

