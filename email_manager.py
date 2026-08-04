"""
Email Manager - sends one-time login codes via SMTP.

Uses only the Python standard library (smtplib + email) - no new pip
dependency needed.

>>> FILL IN YOUR SMTP SETTINGS BELOW before this can actually send mail <<<

Gmail: you need an "App Password", not your normal Google password.
  1. Turn on 2-Step Verification: https://myaccount.google.com/security
  2. Create an App Password: https://myaccount.google.com/apppasswords
  3. Use that 16-character code as SMTP_PASSWORD below.

Outlook/Office365: SMTP_HOST = "smtp.office365.com", SMTP_PORT = 587,
same idea (may also need an app password if 2FA is on).

College/organization SMTP: ask your IT/admin for host, port, and whether
it needs a login at all.
"""

import smtplib
import ssl
import logging
from email.mime.text import MIMEText
from typing import Tuple

logger = logging.getLogger(__name__)

# ---- EDIT THESE ----
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "your.sender.email@gmail.com"
SMTP_PASSWORD = "your-16-char-app-password"
FROM_NAME = "Webcam Spyware Security"
# ---------------------

# While True: if SMTP isn't configured yet (or a send fails), the OTP is
# shown in the app's login dialog instead of email, so you can keep testing
# the app without email set up. Set this to False once real SMTP credentials
# are in place and you're ready for real use.
DEBUG_PRINT_OTP = True

_NOT_CONFIGURED = SMTP_USERNAME.startswith("your.sender.email")


def send_otp_email(to_email: str, otp_code: str, username: str = "") -> Tuple[bool, str, bool]:
    """Sends the one-time login code.
    Returns (success, message, actually_emailed) - actually_emailed is False
    whenever SMTP isn't configured or the send failed, so the caller can
    show the code to the user directly instead of saying "check your email"."""

    if _NOT_CONFIGURED:
        msg = ("SMTP is not configured yet - edit email_manager.py with real "
               "credentials. The code is shown in the app's login dialog instead.")
        logger.warning(msg)
        return (True, msg, False) if DEBUG_PRINT_OTP else (False, msg, False)

    subject = "Your Webcam Spyware Security login code"
    body = (
        f"Hi {username or 'there'},\n\n"
        f"Your one-time login code is: {otp_code}\n\n"
        f"This code expires in 5 minutes. If you didn't try to log in, "
        f"you can ignore this email.\n"
    )
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = f"{FROM_NAME} <{SMTP_USERNAME}>"
    msg["To"] = to_email

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls(context=context)
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_USERNAME, [to_email], msg.as_string())
        logger.info(f"OTP email sent to {to_email}")
        return True, "sent", True
    except Exception as e:
        logger.error(f"Failed to send OTP email: {e}")
        if DEBUG_PRINT_OTP:
            return True, f"Email send failed ({e}) - the code is shown in the app's login dialog.", False
        return False, str(e), False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ok, msg, actually_emailed = send_otp_email("test@example.com", "123456", "testuser")
    print(f"ok={ok}  msg={msg}  actually_emailed={actually_emailed}")
