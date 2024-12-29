# app/utils.py

import random, string, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from .config import Config


def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def create_email_body(company_name, admin_email, admin_password):
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to {company_name}!</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #372c2e;
                color: #ffffff;
                margin: 0;
                padding: 0;
            }}
            .email-container {{
                max-width: 600px;
                margin: 0 auto;
                background-color: #563727;
                border-radius: 10px;
                overflow: hidden;
            }}
            .header {{
                background-color: #de9e48;
                padding: 20px;
                text-align: center;
            }}
            .header h1 {{
                color: #ffffff;
                font-size: 24px;
                margin: 0;
            }}
            .content {{
                padding: 20px;
            }}
            .content p {{
                font-size: 16px;
                line-height: 1.5;
                color: #ffffff;
            }}
            .cta {{
                display: block;
                text-align: center;
                margin: 20px 0;
            }}
            .cta a {{
                display: inline-block;
                padding: 10px 20px;
                background-color: #de9e48;
                color: #ffffff;
                text-decoration: none;
                border-radius: 5px;
                font-weight: bold;
            }}
            .footer {{
                background-color: #7a431d;
                padding: 10px;
                text-align: center;
            }}
            .footer p {{
                font-size: 12px;
                color: rgba(255, 255, 255, 0.7);
                margin: 0;
            }}
        </style>
    </head>
    <body>
        <div class="email-container">
            <div class="header">
                <h1>Welcome to {company_name}!</h1>
            </div>
            <div class="content">
                <p>Dear Company Admin,</p>
                <p>Your company account has been successfully created!</p>
                <p><strong>Company Name:</strong> {company_name}</p>
                <p><strong>Admin Email:</strong> {admin_email}</p>
                <p><strong>Password:</strong> {admin_password}</p>
                <p>Please keep your login credentials secure and do not share them with others.</p>
                <div class="cta">
                    <a href="#">Login to Your Account</a>
                </div>
                <p>If you have any questions, feel free to reach out to our support team.</p>
                <p>Best regards,<br>Your Company Team</p>
            </div>
            <div class="footer">
                <p>© 2024 Your Company. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """

def send_email(recipient, subject, body):
    """Send an email with the given subject and body to the recipient."""
    try:
        msg = MIMEMultipart()
        msg['From'] = Config.MAIL_DEFAULT_SENDER
        msg['To'] = recipient
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'html'))

        with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT) as server:
            if Config.MAIL_USE_TLS:
                server.starttls()  # Upgrade to secure connection
            server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
            server.send_message(msg)

    except Exception as e:
        print(f"Failed to send email: {str(e)}")

def send_bulk_emails(recipients, subject):
    """Send bulk emails to a list of recipients."""
    for recipient in recipients:
        body = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Welcome to Your Company!</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #372c2e;
                    color: #ffffff;
                    margin: 0;
                    padding: 0;
                }}
                .email-container {{
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: #563727;
                    border-radius: 10px;
                    overflow: hidden;
                }}
                .header {{
                    background-color: #de9e48;
                    padding: 20px;
                    text-align: center;
                }}
                .header h1 {{
                    color: #ffffff;
                    font-size: 24px;
                    margin: 0;
                }}
                .content {{
                    padding: 20px;
                }}
                .content p {{
                    font-size: 16px;
                    line-height: 1.5;
                    color: #ffffff;
                }}
                .cta {{
                    display: block;
                    text-align: center;
                    margin: 20px 0;
                }}
                .cta a {{
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #de9e48;
                    color: #ffffff;
                    text-decoration: none;
                    border-radius: 5px;
                    font-weight: bold;
                }}
                .footer {{
                    background-color: #7a431d;
                    padding: 10px;
                    text-align: center;
                }}
                .footer p {{
                    font-size: 12px;
                    color: rgba(255, 255, 255, 0.7);
                    margin: 0;
                }}
            </style>
        </head>
        <body>
            <div class="email-container">
                <div class="header">
                    <h1>Welcome to Your Company!</h1>
                </div>
                <div class="content">
                    <p>Dear {recipient['name']},</p>
                    <p>Your company account has been successfully created!</p>
                    <p><strong>Email:</strong> {recipient['email']}</p>
                    <p><strong>Password:</strong> {recipient['password']}</p>
                    <p>Please keep your login credentials secure and do not share them with others.</p>
                    <div class="cta">
                        <a href="#">Login to Your Account</a>
                    </div>
                    <p>If you have any questions, feel free to reach out to our support team.</p>
                    <p>Best regards,<br>Your Company Team</p>
                </div>
                <div class="footer">
                    <p>© 2024 Your Company. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Send the email
        send_email(recipient['email'], subject, body)

def send_email_duplicate(recipient, subject, body):
    """Send an email with the given subject and body to the recipient."""
    try:
        msg = MIMEMultipart()
        msg['From'] = Config.MAIL_DEFAULT_SENDER
        msg['To'] = recipient
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'html'))

        with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT) as server:
            if Config.MAIL_USE_TLS:
                server.starttls()  # Upgrade to secure connection
            server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
            server.send_message(msg)

    except Exception as e:
        raise e  # Re-raise the exception for logging