import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import aiosmtplib

class EmailAlert():
    def __init__(self, host: str, port: int, username: str, password: str, sender: str, tls: bool = True):
        self.smtp_host = host
        self.smtp_port = port
        self.username = username
        self.password = password
        self.sender = sender
        self.tls = tls
    
    async def send_email_alert(
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

        # Connect and send
        await aiosmtplib.send(
            msg,
            hostname=self.smtp_host,
            port=self.smtp_port,
            username=self.username,
            password=self.password,
            start_tls=self.tls, 
        )
