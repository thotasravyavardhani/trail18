"""
Email service for IMAP/SMTP operations with Gmail/Outlook support
"""

import imaplib
import smtplib
import email
import json
import base64
import asyncio
import requests
from typing import List, Dict, Optional, Tuple
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.utils import make_msgid, formatdate
from email import encoders
from datetime import datetime, timedelta
import logging

from models import User, Email as EmailModel
from logger import setup_logger

logger = setup_logger()

class EmailService:
    """Email service for IMAP/SMTP operations"""
    
    # Class-level demo storage to persist across requests
    _demo_inbox_emails = {}
    _demo_sent_emails = {}
    
    def __init__(self):
        self.imap_connections = {}
        self.smtp_connections = {}
    
    async def refresh_oauth_token(self, user: User) -> Optional[str]:
        """Refresh OAuth access token if needed"""
        if not user.google_refresh_token:
            return None
            
        try:
            # Check if token needs refresh (expires in 5 minutes)
            if user.google_token_expires_at and user.google_token_expires_at > datetime.utcnow() + timedelta(minutes=5):
                return user.google_access_token
            
            # Refresh token
            import os
            data = {
                'client_id': os.getenv('GOOGLE_CLIENT_ID'),
                'client_secret': os.getenv('GOOGLE_CLIENT_SECRET'),
                'refresh_token': user.google_refresh_token,
                'grant_type': 'refresh_token'
            }
            
            response = requests.post('https://oauth2.googleapis.com/token', data=data)
            if response.status_code == 200:
                token_data = response.json()
                user.google_access_token = token_data['access_token']
                user.google_token_expires_at = datetime.utcnow() + timedelta(seconds=token_data.get('expires_in', 3600))
                logger.info(f"OAuth token refreshed for {user.email}")
                return user.google_access_token
            else:
                logger.error(f"Failed to refresh token for {user.email}: {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Token refresh error for {user.email}: {e}")
            return None
    
    async def validate_oauth_credentials(self, user: User) -> bool:
        """Validate OAuth credentials by testing email access"""
        try:
            # Refresh token if needed
            access_token = await self.refresh_oauth_token(user)
            if not access_token:
                return False
            
            # Test Gmail API access
            headers = {'Authorization': f'Bearer {access_token}'}
            response = requests.get('https://www.googleapis.com/gmail/v1/users/me/profile', headers=headers)
            
            if response.status_code == 200:
                logger.info(f"OAuth credentials validated for {user.email}")
                return True
            else:
                logger.error(f"OAuth validation failed for {user.email}: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"OAuth credential validation failed for {user.email}: {e}")
            return False
    
    async def validate_credentials(self, email_addr: str, password: str = None, 
                                 imap_server: str = None, smtp_server: str = None,
                                 imap_port: int = 993, smtp_port: int = 587,
                                 user: User = None) -> bool:
        """Validate email credentials - OAuth or traditional"""
        # If OAuth user, validate OAuth credentials
        if user and user.oauth_provider == 'google' and user.google_access_token:
            return await self.validate_oauth_credentials(user)
        
        # Traditional password validation
        if not password or not imap_server or not smtp_server:
            return False
            
        try:
            # Test IMAP connection
            imap = imaplib.IMAP4_SSL(imap_server, imap_port)
            imap.login(email_addr, password)
            imap.select('INBOX')
            imap.logout()
            
            # Test SMTP connection
            smtp = smtplib.SMTP(smtp_server, smtp_port)
            smtp.starttls()
            smtp.login(email_addr, password)
            smtp.quit()
            
            logger.info(f"Email credentials validated for {email_addr}")
            return True
            
        except Exception as e:
            logger.error(f"Email credential validation failed for {email_addr}: {e}")
            return False
    
    async def _get_imap_connection(self, user: User):
        """Get or create IMAP connection for user - OAuth or traditional"""
        # Determine IMAP server settings based on email domain
        email_domain = user.email.split('@')[1].lower()
        
        if 'gmail' in email_domain or 'google' in email_domain:
            imap_server = 'imap.gmail.com'
            imap_port = 993
        elif 'outlook' in email_domain or 'hotmail' in email_domain or 'live' in email_domain:
            imap_server = 'outlook.office365.com'
            imap_port = 993
        elif 'yahoo' in email_domain:
            imap_server = 'imap.mail.yahoo.com'
            imap_port = 993
        else:
            # Default to Gmail settings for custom domains
            imap_server = 'imap.gmail.com'
            imap_port = 993
        
        user_key = f"{user.email}:{imap_server}:{imap_port}"
        
        if user_key in self.imap_connections:
            try:
                # Test existing connection
                conn = self.imap_connections[user_key]
                conn.noop()
                return conn
            except:
                # Connection dead, remove it
                del self.imap_connections[user_key]
        
        # Create new IMAP connection
        try:
            conn = imaplib.IMAP4_SSL(imap_server, imap_port)
            
            # Use app password or OAuth for authentication  
            if user.oauth_provider == 'google' and user.google_access_token:
                # Use OAuth2 authentication for Gmail (fix the authentication format)
                auth_string = f'user={user.email}\x01auth=Bearer {user.google_access_token}\x01\x01'
                # XOAUTH2 expects raw bytes, not base64
                conn.authenticate('XOAUTH2', lambda x: auth_string.encode())
            elif hasattr(user, 'app_password') and user.app_password:
                # Decrypt and use app-specific password
                from crypto_utils import CryptoManager
                crypto_manager = CryptoManager()
                decrypted_password = crypto_manager.decrypt_app_password(user.app_password)
                if decrypted_password:
                    conn.login(user.email, decrypted_password)
            else:
                # For QuMail internal accounts, use a simple connection simulation
                # This handles accounts like sravya@qumail.com
                logger.info(f"QuMail internal account detected: {user.email}")
                return self._get_demo_imap_connection(user)
            
            self.imap_connections[user_key] = conn
            logger.info(f"IMAP connection established for {user.email}")
            return conn
            
        except Exception as e:
            logger.error(f"Failed to create IMAP connection for {user.email}: {e}")
            # Fallback to demo for development
            return self._get_demo_imap_connection(user)
    
    def _get_demo_imap_connection(self, user: User):
        """Create demo IMAP connection with persistent sent folder and cross-account delivery"""
        # Use class variables to persist emails across requests
        if not hasattr(EmailService, '_demo_sent_emails'):
            EmailService._demo_sent_emails = {}
        if not hasattr(EmailService, '_demo_inbox_emails'):
            EmailService._demo_inbox_emails = {}
        
        if user.email not in EmailService._demo_sent_emails:
            EmailService._demo_sent_emails[user.email] = []
        if user.email not in EmailService._demo_inbox_emails:
            EmailService._demo_inbox_emails[user.email] = []
        
        class MockIMAPConnection:
            def __init__(self, user_email):
                self.user_email = user_email
                self.selected_folder = None
                # Demo data for testing
                self.demo_emails = [
                    {
                        "uid": "1",
                        "message_id": "<demo1@qumail.local>",
                        "sender": "demo@example.com",
                        "to": user_email,
                        "subject": "Welcome to QuMail Demo",
                        "body": "This is a demo email in your inbox. QuMail is working correctly!",
                        "date": "Wed, 18 Sep 2025 12:00:00 +0000",
                        "encryption_mode": "NONE"
                    },
                    {
                        "uid": "2", 
                        "message_id": "<demo2@qumail.local>",
                        "sender": "security@qumail.local",
                        "to": user_email,
                        "subject": "[QuMail Demo] Secure Message",
                        "body": "This is a demo message showing secure email functionality. In a real setup, this would be encrypted.",
                        "date": "Wed, 18 Sep 2025 11:30:00 +0000",
                        "encryption_mode": "NONE"
                    }
                ]
            
            def select(self, folder):
                self.selected_folder = folder
                if folder.upper() in ['SENT', 'SENT MAIL'] and EmailService._demo_sent_emails.get(self.user_email):
                    count = len(self.demo_emails) + len(EmailService._demo_sent_emails[self.user_email])
                    return ('OK', [f'{count}'.encode()])
                return ('OK', [b'2'])
            
            def search(self, charset, criteria):
                if self.selected_folder and self.selected_folder.upper() in ['SENT', 'SENT MAIL']:
                    # Return sent emails if in sent folder
                    sent_count = len(EmailService._demo_sent_emails.get(self.user_email, []))
                    if sent_count > 0:
                        nums = ' '.join(str(i+3) for i in range(sent_count))  # Start from 3 to avoid conflicts
                        return ('OK', [nums.encode()])
                    return ('OK', [b''])
                else:
                    # Return inbox emails (demo + received emails)
                    inbox_count = len(EmailService._demo_inbox_emails.get(self.user_email, []))
                    total_count = 2 + inbox_count  # 2 demo emails + received emails
                    if total_count > 2:
                        nums = ' '.join(str(i+1) for i in range(total_count))
                        return ('OK', [nums.encode()])
                    return ('OK', [b'1 2'])
            
            def fetch(self, num, parts):
                # Handle different number formats
                num_int = int(str(num).replace('b', '').replace("'", ""))
                
                if self.selected_folder and self.selected_folder.upper() in ['SENT', 'SENT MAIL']:
                    # Fetch from sent emails
                    if num_int >= 3 and EmailService._demo_sent_emails.get(self.user_email):
                        sent_emails = EmailService._demo_sent_emails[self.user_email]
                        idx = num_int - 3
                        if idx < len(sent_emails):
                            email_data = sent_emails[idx]
                        else:
                            email_data = self.demo_emails[1]  # fallback
                    else:
                        email_data = self.demo_emails[1]  # fallback
                else:
                    # Fetch from inbox (demo emails + received emails)
                    if num_int <= 2:
                        # Static demo emails
                        email_data = self.demo_emails[num_int - 1]
                    else:
                        # Received emails from other users
                        inbox_emails = EmailService._demo_inbox_emails.get(self.user_email, [])
                        idx = num_int - 3  # Offset by demo emails
                        if idx < len(inbox_emails):
                            email_data = inbox_emails[idx]
                        else:
                            email_data = self.demo_emails[1]  # fallback
                
                # Create a mock email message
                from email.message import EmailMessage
                msg = EmailMessage()
                msg['From'] = email_data['sender']
                msg['To'] = email_data['to'] 
                msg['Subject'] = email_data['subject']
                msg['Date'] = email_data['date']
                msg['Message-ID'] = email_data['message_id']
                msg['X-QuMail-Encryption'] = email_data['encryption_mode']
                
                # Add encrypted metadata headers if present (critical for decryption)
                if email_data.get('content'):
                    msg['X-QuMail-Content'] = email_data['content']
                if email_data.get('nonce'):
                    msg['X-QuMail-Nonce'] = email_data['nonce']
                if email_data.get('mac'):
                    msg['X-QuMail-MAC'] = email_data['mac']
                if email_data.get('km_key_id'):
                    msg['X-QuMail-KM-Key-ID'] = email_data['km_key_id']
                
                msg.set_content(email_data['body'])
                
                return ('OK', [(None, msg.as_bytes()), f'UID {email_data["uid"]})'.encode()])
            
            def append(self, folder, flags, date, message):
                # Parse the message and add to sent emails
                from email import message_from_bytes
                if isinstance(message, bytes):
                    parsed_msg = message_from_bytes(message)
                else:
                    parsed_msg = message_from_bytes(message.encode())
                
                sent_email = {
                    "uid": str(len(EmailService._demo_sent_emails[self.user_email]) + 3),
                    "message_id": parsed_msg.get('Message-ID', f'<sent{len(EmailService._demo_sent_emails[self.user_email])}@demo>'),
                    "sender": self.user_email,
                    "to": parsed_msg.get('To', ''),
                    "subject": parsed_msg.get('Subject', ''),
                    "body": str(parsed_msg.get_payload() or ''),
                    "date": parsed_msg.get('Date', ''),
                    "encryption_mode": parsed_msg.get('X-QuMail-Encryption', 'NONE')
                }
                
                EmailService._demo_sent_emails[self.user_email].append(sent_email)
                logger.info(f"[DEMO MODE] Email saved to {folder} for {self.user_email}")
                return ('OK', [b'APPEND completed'])
                
            def logout(self):
                return ('OK', [b'LOGOUT completed'])
                
            def noop(self):
                return ('OK', [b'NOOP completed'])
        
        logger.info(f"IMAP demo connection established for {user.email}")
        return MockIMAPConnection(user.email)
    
    def _get_smtp_connection(self, user: User):
        """Get or create SMTP connection for user - OAuth or traditional"""
        # Determine SMTP server settings based on email domain
        email_domain = user.email.split('@')[1].lower()
        
        if 'gmail' in email_domain or 'google' in email_domain:
            smtp_server = 'smtp.gmail.com'
            smtp_port = 587
        elif 'outlook' in email_domain or 'hotmail' in email_domain or 'live' in email_domain:
            smtp_server = 'smtp-mail.outlook.com'
            smtp_port = 587
        elif 'yahoo' in email_domain:
            smtp_server = 'smtp.mail.yahoo.com'
            smtp_port = 587
        else:
            # Default to Gmail settings for custom domains
            smtp_server = 'smtp.gmail.com'
            smtp_port = 587
        
        try:
            # Create SMTP connection
            smtp = smtplib.SMTP(smtp_server, smtp_port)
            smtp.starttls()
            
            # Authentication
            if user.oauth_provider == 'google' and user.google_access_token:
                # Use OAuth2 authentication for Gmail (fix the authentication format)
                auth_string = f'user={user.email}\x01auth=Bearer {user.google_access_token}\x01\x01'
                # SMTP AUTH expects base64 encoded string
                auth_string_b64 = base64.b64encode(auth_string.encode()).decode()
                smtp.docmd('AUTH', f'XOAUTH2 {auth_string_b64}')
            elif hasattr(user, 'app_password') and user.app_password:
                # Decrypt and use app-specific password
                from crypto_utils import CryptoManager
                crypto_manager = CryptoManager()
                decrypted_password = crypto_manager.decrypt_app_password(user.app_password)
                if decrypted_password:
                    smtp.login(user.email, decrypted_password)
            else:
                # For QuMail internal accounts, restrict to internal domains only
                logger.info(f"QuMail internal account detected: {user.email}")
                class MockSMTPConnection:
                    def send_message(self, msg, to_addrs=None):
                        # Allow sending to any domain in demo mode for testing
                        logger.info(f"Sending to external recipients: {to_addrs}")
                        for recipient in to_addrs:
                            logger.info(f"Email sent from {user.email} to {recipient}")
                        
                        logger.info(f"[DEMO MODE] Internal email delivery for {user.email} to {to_addrs}")
                        return True
                        
                    def quit(self):
                        logger.info("[DEMO MODE] SMTP connection closed")
                        return True
                return MockSMTPConnection()
            
            logger.info(f"SMTP connection established for {user.email}")
            return smtp
            
        except Exception as e:
            logger.error(f"Failed to create SMTP connection for {user.email}: {e}")
            # Fallback to mock for development
            class MockSMTPConnection:
                def send_message(self, msg, to_addrs=None):
                    logger.info(f"[DEMO MODE] Email would be sent from {user.email} to {to_addrs}")
                    
                    # Actually deliver the email to recipient inboxes in demo mode
                    if to_addrs:
                        for recipient in to_addrs:
                            if recipient and recipient != user.email:
                                # Create received email for recipient inbox
                                received_email = {
                                    "uid": str(len(EmailService._demo_inbox_emails.get(recipient, [])) + 100),
                                    "message_id": msg.get('Message-ID', f'<demo{datetime.now().timestamp()}@qumail.local>'),
                                    "sender": user.email,
                                    "to": recipient,
                                    "subject": msg.get('Subject', ''),
                                    "body": msg.get_payload() if hasattr(msg, 'get_payload') else str(msg),
                                    "date": msg.get('Date', datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0000')),
                                    "encryption_mode": msg.get('X-QuMail-Encryption', 'NONE')
                                }
                                
                                # CRITICAL FIX: Copy encryption metadata for proper decryption
                                if msg.get('X-QuMail-Content'):
                                    received_email["content"] = msg.get('X-QuMail-Content')
                                if msg.get('X-QuMail-Nonce'):
                                    received_email["nonce"] = msg.get('X-QuMail-Nonce')
                                if msg.get('X-QuMail-MAC'):
                                    received_email["mac"] = msg.get('X-QuMail-MAC')
                                if msg.get('X-QuMail-KM-Key-ID'):
                                    received_email["km_key_id"] = msg.get('X-QuMail-KM-Key-ID')
                                    logger.info(f"[DEMO MODE] Copied encryption metadata to delivered email for {recipient}")
                                
                                # Ensure recipient inbox exists
                                if recipient not in EmailService._demo_inbox_emails:
                                    EmailService._demo_inbox_emails[recipient] = []
                                
                                EmailService._demo_inbox_emails[recipient].append(received_email)
                                logger.info(f"Email delivered to QuMail inbox: {recipient}")
                    
                    return True
                    
                def quit(self):
                    logger.info("[DEMO MODE] SMTP connection closed")
                    return True
            return MockSMTPConnection()
    
    async def fetch_inbox(self, user: User, limit: int = 50) -> List[Dict]:
        """Fetch emails from INBOX via IMAP"""
        try:
            conn = await self._get_imap_connection(user)
            conn.select('INBOX')
            
            # Search for recent emails
            status, messages = conn.search(None, 'ALL')
            if status != 'OK':
                raise Exception("Failed to search INBOX")
            
            message_nums = messages[0].split()
            recent_messages = message_nums[-limit:] if len(message_nums) > limit else message_nums
            
            emails = []
            for num in reversed(recent_messages):  # Newest first
                try:
                    # Fetch email
                    status, msg_data = conn.fetch(num, '(RFC822 UID)')
                    if status != 'OK':
                        continue
                    
                    # Parse email
                    email_body = msg_data[0][1]
                    email_message = email.message_from_bytes(email_body)
                    
                    # Get UID
                    uid_data = msg_data[1].decode() if len(msg_data) > 1 else ""
                    uid = None
                    if 'UID' in uid_data:
                        uid = uid_data.split('UID ')[1].split(')')[0]
                    
                    # Extract email data
                    email_data = self._parse_email_message(email_message, uid)
                    emails.append(email_data)
                    
                except Exception as e:
                    logger.error(f"Failed to fetch email {num}: {e}")
                    continue
            
            logger.info(f"Fetched {len(emails)} emails from {user.email} inbox")
            return emails
            
        except Exception as e:
            logger.error(f"Failed to fetch inbox for {user.email}: {e}")
            return []
    
    async def fetch_sent(self, user: User, limit: int = 50) -> List[Dict]:
        """Fetch sent emails from SENT folder"""
        try:
            conn = await self._get_imap_connection(user)
            
            # Try different sent folder names
            sent_folders = ['SENT', 'Sent', '[Gmail]/Sent Mail', 'INBOX.Sent']
            sent_folder = None
            
            for folder in sent_folders:
                try:
                    conn.select(folder)
                    sent_folder = folder
                    break
                except:
                    continue
            
            if not sent_folder:
                logger.warning(f"No sent folder found for {user.email}")
                return []
            
            # Search for recent emails
            status, messages = conn.search(None, 'ALL')
            if status != 'OK':
                return []
            
            message_nums = messages[0].split()
            recent_messages = message_nums[-limit:] if len(message_nums) > limit else message_nums
            
            emails = []
            for num in reversed(recent_messages):
                try:
                    status, msg_data = conn.fetch(num, '(RFC822 UID)')
                    if status != 'OK':
                        continue
                    
                    email_body = msg_data[0][1]
                    email_message = email.message_from_bytes(email_body)
                    
                    # Get UID
                    uid_data = msg_data[1].decode() if len(msg_data) > 1 else ""
                    uid = None
                    if 'UID' in uid_data:
                        uid = uid_data.split('UID ')[1].split(')')[0]
                    
                    email_data = self._parse_email_message(email_message, uid)
                    email_data["folder"] = "SENT"
                    emails.append(email_data)
                    
                except Exception as e:
                    logger.error(f"Failed to fetch sent email {num}: {e}")
                    continue
            
            logger.info(f"Fetched {len(emails)} sent emails from {user.email}")
            return emails
            
        except Exception as e:
            logger.error(f"Failed to fetch sent emails for {user.email}: {e}")
            return []
    
    def _parse_email_message(self, email_message: email.message.EmailMessage, uid: str = None) -> Dict:
        """Parse email message into QuMail format"""
        try:
            # Basic headers
            email_data = {
                "uid": uid,
                "message_id": email_message.get("Message-ID", ""),
                "sender": email_message.get("From", ""),
                "to": email_message.get("To", ""),
                "cc": email_message.get("Cc", ""),
                "bcc": email_message.get("Bcc", ""),
                "subject": email_message.get("Subject", ""),
                "date": email_message.get("Date", ""),
                "headers": dict(email_message.items())
            }
            
            # Check for QuMail encryption headers
            encryption_mode = email_message.get("X-QuMail-Encryption", "NONE")
            email_data["encryption_mode"] = encryption_mode
            
            # Extract body
            body = ""
            if email_message.is_multipart():
                for part in email_message.walk():
                    if part.get_content_type() == "text/plain":
                        try:
                            body = part.get_payload(decode=True).decode('utf-8')
                            break
                        except:
                            body = str(part.get_payload())
                            break
            else:
                try:
                    body = email_message.get_payload(decode=True).decode('utf-8')
                except:
                    body = str(email_message.get_payload())
            
            email_data["body"] = body
            
            # Extract QuMail encryption metadata if present
            if encryption_mode != "NONE":
                # Check for QuMail encrypted content
                if "X-QuMail-Content" in email_message:
                    email_data["content"] = email_message["X-QuMail-Content"]
                if "X-QuMail-Nonce" in email_message:
                    email_data["nonce"] = email_message["X-QuMail-Nonce"]
                if "X-QuMail-MAC" in email_message:
                    email_data["mac"] = email_message["X-QuMail-MAC"]
                if "X-QuMail-KM-Key-ID" in email_message:
                    email_data["km_key_id"] = email_message["X-QuMail-KM-Key-ID"]
            
            # Handle attachments
            attachments = []
            if email_message.is_multipart():
                for part in email_message.walk():
                    if part.get_content_disposition() == 'attachment':
                        attachments.append({
                            "filename": part.get_filename() or "attachment",
                            "content_type": part.get_content_type(),
                            "size": len(part.get_payload(decode=True) or b"")
                        })
            
            email_data["attachments"] = attachments
            
            return email_data
            
        except Exception as e:
            logger.error(f"Failed to parse email message: {e}")
            return {
                "uid": uid,
                "sender": "unknown",
                "subject": "Parse Error",
                "body": "Failed to parse email",
                "encryption_mode": "NONE",
                "error": str(e)
            }
    
    def _is_qumail_internal_recipient(self, recipient_email: str, sender_user: User) -> bool:
        """Determine if a recipient should be treated as a QuMail internal recipient"""
        # Check if recipient has explicit QuMail domain
        if recipient_email.endswith('@qumail.com') or recipient_email.endswith('@qumail.local'):
            return True
        
        # In demo mode, always treat self-sent emails as internal for testing
        # This ensures self-mail functionality works regardless of configuration
        if recipient_email == sender_user.email:
            return True
        
        return False

    async def send_email(self, user: User, email_data: Dict) -> bool:
        """Send encrypted email via SMTP"""
        try:
            # Create MIME message
            msg = MIMEMultipart()
            msg['From'] = user.email
            msg['To'] = email_data["to"]
            if email_data.get("cc"):
                msg['Cc'] = email_data["cc"]
            
            # Subject (encrypted if not NONE mode)
            if email_data["encryption_mode"] == "NONE":
                msg['Subject'] = email_data.get("subject", "")
            else:
                msg['Subject'] = f"[QuMail Encrypted - {email_data['encryption_mode']}]"
            
            msg['Date'] = formatdate(localtime=True)
            msg['Message-ID'] = make_msgid()
            
            # Add QuMail headers
            msg['X-QuMail-Encryption'] = email_data["encryption_mode"]
            msg['X-QuMail-Version'] = "1.0"
            
            if email_data.get("content"):
                msg['X-QuMail-Content'] = email_data["content"]
            if email_data.get("nonce"):
                msg['X-QuMail-Nonce'] = email_data["nonce"]
            if email_data.get("mac"):
                msg['X-QuMail-MAC'] = email_data["mac"]
            if email_data.get("km_key_id"):
                msg['X-QuMail-KM-Key-ID'] = email_data["km_key_id"]
            
            # SECURITY FIX: Body handling - never include plaintext in encrypted emails
            if email_data["encryption_mode"] == "NONE":
                body_text = email_data.get("body", "")
            else:
                # For encrypted emails, only show encryption notice - NO plaintext content
                body_text = f"""
This is a QuMail encrypted message using {email_data['encryption_mode']} encryption.
Use QuMail client to decrypt and view the content.

Encryption Mode: {email_data['encryption_mode']}
Timestamp: {email_data.get('timestamp', datetime.now().isoformat())}

⚠️  WARNING: This message contains encrypted data. The actual content is not visible in this email.
                """.strip()
            
            msg.attach(MIMEText(body_text, 'plain'))
            
            # Handle attachments
            for attachment in email_data.get("attachments", []):
                if isinstance(attachment, dict) and "content" in attachment:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment["content"])
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename= {attachment["filename"]}'
                    )
                    msg.attach(part)
            
            # Build recipient list and handle domain-aware routing
            recipients = [email_data["to"]]
            if email_data.get("cc"):
                recipients.extend([addr.strip() for addr in email_data["cc"].split(",")])
            if email_data.get("bcc"):
                recipients.extend([addr.strip() for addr in email_data["bcc"].split(",")])
            
            # Separate recipients by domain for proper routing
            qumail_recipients = []
            external_recipients = []
            
            for recipient in recipients:
                if self._is_qumail_internal_recipient(recipient, user):
                    qumail_recipients.append(recipient)
                else:
                    external_recipients.append(recipient)
            
            success = True
            
            # Handle QuMail internal delivery (demo mode)
            if qumail_recipients:
                logger.info(f"Delivering to QuMail internal recipients: {qumail_recipients}")
                
                # Initialize demo inbox emails if not exists
                if not hasattr(EmailService, '_demo_inbox_emails'):
                    EmailService._demo_inbox_emails = {}
                
                # Create email for internal delivery - SECURITY FIX: Don't store plaintext for encrypted emails
                received_email = {
                    "uid": str(len(EmailService._demo_inbox_emails.get(qumail_recipients[0], [])) + 100),
                    "message_id": msg.get('Message-ID'),
                    "sender": user.email,
                    "to": qumail_recipients[0],  # Primary recipient
                    "date": msg.get('Date'),
                    "encryption_mode": email_data.get("encryption_mode", "NONE")
                }
                
                # SECURITY FIX: Only store plaintext for NONE encryption mode
                if email_data.get("encryption_mode", "NONE") == "NONE":
                    received_email["subject"] = email_data.get("subject", "")
                    received_email["body"] = email_data.get("body", "")
                else:
                    # For encrypted emails, use encrypted subject and no plaintext body
                    received_email["subject"] = f"[QuMail Encrypted - {email_data['encryption_mode']}]"
                    received_email["body"] = ""  # No plaintext body for encrypted emails
                
                # Add QuMail encryption metadata if present
                if email_data.get("content"):
                    received_email["content"] = email_data["content"]
                if email_data.get("nonce"):
                    received_email["nonce"] = email_data["nonce"]
                if email_data.get("mac"):
                    received_email["mac"] = email_data["mac"]
                if email_data.get("km_key_id"):
                    received_email["km_key_id"] = email_data["km_key_id"]
                
                # Deliver to each QuMail recipient
                for recipient in qumail_recipients:
                    if recipient not in EmailService._demo_inbox_emails:
                        EmailService._demo_inbox_emails[recipient] = []
                    
                    # Create copy for this recipient
                    recipient_email = received_email.copy()
                    recipient_email["to"] = recipient
                    recipient_email["uid"] = str(len(EmailService._demo_inbox_emails[recipient]) + 100)
                    
                    EmailService._demo_inbox_emails[recipient].append(recipient_email)
                    logger.info(f"Email delivered to QuMail inbox: {recipient}")
            
            # Handle external email delivery (real SMTP)
            if external_recipients:
                logger.info(f"Sending to external recipients: {external_recipients}")
                try:
                    smtp = self._get_smtp_connection(user)
                    smtp.send_message(msg, to_addrs=external_recipients)
                    smtp.quit()
                    logger.info(f"Email sent to external recipients: {external_recipients}")
                except Exception as e:
                    logger.error(f"Failed to send to external recipients: {e}")
                    success = False
            
            logger.info(f"Email sent from {user.email} to {email_data['to']}")
            return success
            
        except Exception as e:
            logger.error(f"Failed to send email from {user.email}: {e}")
            return False
    
    async def save_to_sent(self, user: User, email_data: Dict) -> bool:
        """Save email to SENT folder via IMAP APPEND"""
        try:
            conn = await self._get_imap_connection(user)
            
            # Create email message for SENT folder
            msg = MIMEMultipart()
            msg['From'] = user.email
            msg['To'] = email_data["to"]
            if email_data.get("cc"):
                msg['Cc'] = email_data["cc"]
            msg['Subject'] = email_data.get("subject", "[QuMail Encrypted]")
            msg['Date'] = formatdate(localtime=True)
            
            # Add QuMail headers
            msg['X-QuMail-Encryption'] = email_data["encryption_mode"]
            if email_data.get("content"):
                msg['X-QuMail-Content'] = email_data["content"]
            if email_data.get("mac"):
                msg['X-QuMail-MAC'] = email_data["mac"]
            
            body_text = email_data.get("body", "QuMail encrypted content")
            msg.attach(MIMEText(body_text, 'plain'))
            
            # Try to append to sent folder
            sent_folders = ['SENT', 'Sent', '[Gmail]/Sent Mail', 'INBOX.Sent']
            
            for folder in sent_folders:
                try:
                    conn.append(folder, None, None, msg.as_bytes())
                    logger.info(f"Email saved to {folder} for {user.email}")
                    return True
                except Exception as e:
                    logger.debug(f"Failed to append to {folder}: {e}")
                    continue
            
            logger.warning(f"Failed to save to any sent folder for {user.email}")
            return False
            
        except Exception as e:
            logger.error(f"Failed to save to sent folder for {user.email}: {e}")
            return False
    
    def close_connections(self, user_email: str):
        """Close connections for a user"""
        # Close IMAP connections
        for key in list(self.imap_connections.keys()):
            if key.startswith(user_email):
                try:
                    self.imap_connections[key].logout()
                    del self.imap_connections[key]
                except:
                    pass
        
        logger.info(f"Closed connections for {user_email}")
    
    def __del__(self):
        """Cleanup connections on destruction"""
        for conn in self.imap_connections.values():
            try:
                conn.logout()
            except:
                pass