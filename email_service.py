"""
Email service for Streamzy Chat Platform
Handles sending credentials and notifications
"""
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import os

logger = logging.getLogger(__name__)


class EmailService:
    """Service for sending emails via SMTP"""
    
    def __init__(self, app=None):
        self.app = app
        self.server = None
        self.port = None
        self.username = None
        self.password = None
        self.use_tls = True
        self.default_sender = None
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize with Flask app configuration"""
        self.app = app
        self.server = app.config.get('MAIL_SERVER', 'smtp.gmail.com')
        self.port = app.config.get('MAIL_PORT', 587)
        self.username = app.config.get('MAIL_USERNAME')
        self.password = app.config.get('MAIL_PASSWORD')
        self.use_tls = app.config.get('MAIL_USE_TLS', True)
        self.default_sender = app.config.get('MAIL_DEFAULT_SENDER', 'noreply@streamzy.io')
    
    def _create_connection(self):
        """Create SMTP connection"""
        try:
            if self.use_tls:
                context = ssl.create_default_context()
                server = smtplib.SMTP(self.server, self.port)
                server.starttls(context=context)
            else:
                server = smtplib.SMTP_SSL(self.server, self.port)
            
            if self.username and self.password:
                server.login(self.username, self.password)
            
            return server
        except Exception as e:
            logger.error(f"Failed to create SMTP connection: {e}")
            raise
    
    def send_email(self, to_email, subject, html_content, text_content=None):
        """
        Send an email
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML body content
            text_content: Plain text fallback (optional)
        """
        if not self.username or not self.password:
            logger.warning("Email credentials not configured. Email not sent.")
            logger.info(f"Would send to {to_email}: {subject}")
            return False
        
        try:
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = self.default_sender
            message["To"] = to_email
            
            # Add plain text version
            if text_content:
                part1 = MIMEText(text_content, "plain")
                message.attach(part1)
            
            # Add HTML version
            part2 = MIMEText(html_content, "html")
            message.attach(part2)
            
            # Send
            server = self._create_connection()
            server.sendmail(self.default_sender, to_email, message.as_string())
            server.quit()
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            return False
    
    def send_credentials(self, to_email, username, password):
        """
        Send login credentials to new user
        
        Args:
            to_email: User's email address
            username: Generated username
            password: Generated password
        """
        subject = "🔐 Your Streamzy Access Credentials"
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background-color: #0a0a0a;
            color: #00ff00;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: #111;
            border: 1px solid #00ff00;
            border-radius: 5px;
            padding: 30px;
        }}
        .header {{
            text-align: center;
            border-bottom: 1px solid #00ff00;
            padding-bottom: 20px;
            margin-bottom: 20px;
        }}
        .ascii-art {{
            font-size: 10px;
            line-height: 1.2;
            color: #00ff00;
            text-align: center;
            margin-bottom: 20px;
        }}
        .credentials {{
            background-color: #0a0a0a;
            border: 1px solid #00ff00;
            padding: 20px;
            margin: 20px 0;
        }}
        .credential-item {{
            margin: 10px 0;
        }}
        .label {{
            color: #888;
        }}
        .value {{
            color: #00ff00;
            font-weight: bold;
            font-size: 16px;
        }}
        .warning {{
            color: #ff6600;
            font-size: 12px;
            margin-top: 20px;
            padding: 10px;
            border: 1px solid #ff6600;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            font-size: 11px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <pre class="ascii-art">
 ███████╗████████╗██████╗ ███████╗ █████╗ ███╗   ███╗███████╗██╗   ██╗
 ██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔══██╗████╗ ████║╚══███╔╝╚██╗ ██╔╝
 ███████╗   ██║   ██████╔╝█████╗  ███████║██╔████╔██║  ███╔╝  ╚████╔╝ 
 ╚════██║   ██║   ██╔══██╗██╔══╝  ██╔══██║██║╚██╔╝██║ ███╔╝    ╚██╔╝  
 ███████║   ██║   ██║  ██║███████╗██║  ██║██║ ╚═╝ ██║███████╗   ██║   
 ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝   ╚═╝   
            </pre>
            <h2>ACCESS GRANTED</h2>
        </div>
        
        <p>Your application has been approved. Welcome to Streamzy.</p>
        
        <div class="credentials">
            <div class="credential-item">
                <span class="label">USERNAME:</span><br>
                <span class="value">{username}</span>
            </div>
            <div class="credential-item">
                <span class="label">PASSWORD:</span><br>
                <span class="value">{password}</span>
            </div>
        </div>
        
        <p>Use these credentials to access the terminal interface.</p>
        
        <div class="warning">
            ⚠️ SECURITY NOTICE:<br>
            • Store these credentials securely<br>
            • Do not share your login information<br>
            • Change your password after first login<br>
            • This message will not be sent again
        </div>
        
        <div class="footer">
            <p>End-to-end encrypted communications</p>
            <p>© Streamzy Secure Chat Platform</p>
        </div>
    </div>
</body>
</html>
"""
        
        text_content = f"""
═══════════════════════════════════════════════════════════════
                    STREAMZY - ACCESS GRANTED
═══════════════════════════════════════════════════════════════

Your application has been approved. Welcome to Streamzy.

YOUR CREDENTIALS:
─────────────────
USERNAME: {username}
PASSWORD: {password}

Use these credentials to access the terminal interface.

⚠️ SECURITY NOTICE:
• Store these credentials securely
• Do not share your login information
• Change your password after first login
• This message will not be sent again

═══════════════════════════════════════════════════════════════
                End-to-end encrypted communications
                  © Streamzy Secure Chat Platform
═══════════════════════════════════════════════════════════════
"""
        
        return self.send_email(to_email, subject, html_content, text_content)
    
    def send_password_reset(self, to_email, reset_token, reset_url):
        """
        Send password reset link
        
        Args:
            to_email: User's email address
            reset_token: Password reset token
            reset_url: Full URL for password reset
        """
        subject = "🔑 Streamzy Password Reset"
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background-color: #0a0a0a;
            color: #00ff00;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: #111;
            border: 1px solid #00ff00;
            border-radius: 5px;
            padding: 30px;
        }}
        .header {{
            text-align: center;
            border-bottom: 1px solid #00ff00;
            padding-bottom: 20px;
            margin-bottom: 20px;
        }}
        .reset-link {{
            background-color: #0a0a0a;
            border: 1px solid #00ff00;
            padding: 20px;
            text-align: center;
            margin: 20px 0;
        }}
        a {{
            color: #00ff00;
        }}
        .warning {{
            color: #ff6600;
            font-size: 12px;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>🔑 PASSWORD RESET REQUEST</h2>
        </div>
        
        <p>A password reset was requested for your Streamzy account.</p>
        
        <div class="reset-link">
            <p>Click the link below to reset your password:</p>
            <a href="{reset_url}">{reset_url}</a>
            <p style="font-size: 12px; color: #888;">
                Token: {reset_token[:8]}...
            </p>
        </div>
        
        <p class="warning">
            ⚠️ This link expires in 1 hour.<br>
            If you did not request this reset, ignore this email.
        </p>
    </div>
</body>
</html>
"""
        
        text_content = f"""
═══════════════════════════════════════════════════════════════
                    STREAMZY - PASSWORD RESET
═══════════════════════════════════════════════════════════════

A password reset was requested for your Streamzy account.

Reset your password at: {reset_url}

Token: {reset_token[:8]}...

⚠️ This link expires in 1 hour.
If you did not request this reset, ignore this email.

═══════════════════════════════════════════════════════════════
"""
        
        return self.send_email(to_email, subject, html_content, text_content)
    
    def send_application_received(self, to_email):
        """
        Send confirmation that application was received
        
        Args:
            to_email: Applicant's email address
        """
        subject = "📝 Streamzy Application Received"
        
        html_content = """
<!DOCTYPE html>
<html>
<head>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background-color: #0a0a0a;
            color: #00ff00;
            padding: 20px;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #111;
            border: 1px solid #00ff00;
            border-radius: 5px;
            padding: 30px;
        }
        .header {
            text-align: center;
            border-bottom: 1px solid #00ff00;
            padding-bottom: 20px;
            margin-bottom: 20px;
        }
        .status {
            background-color: #0a0a0a;
            border: 1px solid #ffaa00;
            padding: 20px;
            text-align: center;
            margin: 20px 0;
            color: #ffaa00;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>📝 APPLICATION RECEIVED</h2>
        </div>
        
        <p>Your application to join Streamzy has been received.</p>
        
        <div class="status">
            <p>STATUS: PENDING REVIEW</p>
        </div>
        
        <p>You will receive your login credentials via email once your application is approved.</p>
        
        <p style="color: #888; font-size: 12px;">
            Applications are typically reviewed within 24-48 hours.
        </p>
    </div>
</body>
</html>
"""
        
        text_content = """
═══════════════════════════════════════════════════════════════
                STREAMZY - APPLICATION RECEIVED
═══════════════════════════════════════════════════════════════

Your application to join Streamzy has been received.

STATUS: PENDING REVIEW

You will receive your login credentials via email once your 
application is approved.

Applications are typically reviewed within 24-48 hours.

═══════════════════════════════════════════════════════════════
"""
        
        return self.send_email(to_email, subject, html_content, text_content)


# Singleton instance
email_service = EmailService()
