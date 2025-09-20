"""
Email service for IMAP/SMTP operations with Gmail/Outlook support
Handles quantum-secure email delivery and mock demo mode
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
from email.header import decode_header
from datetime import datetime, timedelta
import quopri
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
    
    def encode_email_header_content(self, content: str) -> str:
        """Encode content for safe transmission in email headers using quoted-printable encoding"""
        if not content:
            return content
            
        try:
            # Check if content needs encoding (contains non-ASCII or special characters)
            if all(ord(c) < 128 and c not in '=?_ \t\n\r' for c in content):
                # Content is safe ASCII, return as-is
                return content
            
            # Encode using quoted-printable format
            import quopri
            encoded_bytes = quopri.encodestring(content.encode('utf-8'))
            encoded_str = encoded_bytes.decode('ascii')
            
            # Wrap in email header format
            return f"=?utf-8?q?{encoded_str}?="
            
        except Exception as e:
            logger.error(f"Failed to encode email header content: {e}")
            # If encoding fails, return original content
            return content

    def decode_email_header_content(self, header_content: str) -> str:
        """Decode quoted-printable or other encoded email header content to clean base64"""
        if not header_content:
            return header_content
            
        try:
            # Check if it's quoted-printable encoded (=?utf-8?q?...?=)
            if header_content.startswith('=?') and '?q?' in header_content:
                # Decode header using email.header.decode_header
                decoded_parts = decode_header(header_content)
                decoded_content = ""
                
                for part, charset in decoded_parts:
                    if isinstance(part, bytes):
                        if charset:
                            decoded_content += part.decode(charset)
                        else:
                            # This is the quoted-printable part, decode it
                            decoded_content += quopri.decodestring(part).decode('utf-8')
                    else:
                        decoded_content += part
                        
                return decoded_content
            else:
                # Content is not encoded, return as-is
                return header_content
                
        except Exception as e:
            logger.error(f"Failed to decode email header content: {e}")
            # If decoding fails, return original content
            return header_content
    
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
                    count = len(EmailService._demo_sent_emails[self.user_email])
                    return ('OK', [f'{count}'.encode()])
                
                # Check for sent emails
                sent_count = len(EmailService._demo_sent_emails.get(self.user_email, []))
                inbox_count = len(EmailService._demo_inbox_emails.get(self.user_email, []))
                
                if folder.upper() in ['SENT', 'SENT MAIL']:
                    return ('OK', [str(sent_count).encode()])
                
                total_inbox = len(self.demo_emails) + inbox_count
                return ('OK', [str(total_inbox).encode()])
            
            def search(self, charset, criteria):
                if self.selected_folder and self.selected_folder.upper() in ['SENT', 'SENT MAIL']:
                    sent_count = len(EmailService._demo_sent_emails.get(self.user_email, []))
                    if sent_count > 0:
                        nums = ' '.join(str(i+1) for i in range(sent_count))
                        return ('OK', [nums.encode()])
                    return ('OK', [b''])
                else:
                    inbox_count = len(EmailService._demo_inbox_emails.get(self.user_email, []))
                    total_count = 2 + inbox_count  # 2 demo emails + received emails
                    if total_count > 0:
                        nums = ' '.join(str(i+1) for i in range(total_count))
                        return ('OK', [nums.encode()])
                    return ('OK', [b''])
            
            def fetch(self, num, parts):
                num_int = int(str(num).replace('b', '').replace("'", ""))
                
                if self.selected_folder and self.selected_folder.upper() in ['SENT', 'SENT MAIL']:
                    sent_emails = EmailService._demo_sent_emails.get(self.user_email, [])
                    if 0 < num_int <= len(sent_emails):
                        email_data = sent_emails[num_int - 1]
                    else:
                        return ('NO', [b'Invalid message number'])
                else:
                    # Fetch from inbox (demo emails + received emails)
                    inbox_emails = self.demo_emails + EmailService._demo_inbox_emails.get(self.user_email, [])
                    if 0 < num_int <= len(inbox_emails):
                        email_data = inbox_emails[num_int - 1]
                    else:
                        return ('NO', [b'Invalid message number'])

                from email.message import EmailMessage
                msg = EmailMessage()
                
                msg['From'] = email_data['sender']
                msg['To'] = email_data.get('to', '')
                if email_data.get('cc'):
                    msg['Cc'] = email_data['cc']
                if email_data.get('bcc'):
                    msg['Bcc'] = email_data['bcc']
                msg['Subject'] = email_data['subject']
                msg['Date'] = email_data['date']
                msg['Message-ID'] = email_data['message_id']
                
                # Reconstruct encrypted headers
                if email_data.get('encryption_mode') != 'NONE':
                    msg['X-QuMail-Encryption'] = email_data.get('encryption_mode', 'NONE')
                    msg['X-QuMail-Content'] = email_data.get('content', '')
                    if email_data.get('nonce'):
                        msg['X-QuMail-Nonce'] = email_data.get('nonce', '')
                    if email_data.get('mac'):
                        msg['X-QuMail-MAC'] = email_data.get('mac', '')
                    if email_data.get('km_key_id'):
                        msg['X-QuMail-KM-Key-ID'] = email_data.get('km_key_id', '')
                    
                    # CRITICAL FIX: Add PQC headers to reconstructed email
                    if email_data.get('pqc_public'):
                        msg['X-QuMail-PQC-Public'] = email_data.get('pqc_public', '')
                    if email_data.get('pqc_ciphertext'):
                        msg['X-QuMail-PQC-Ciphertext'] = email_data.get('pqc_ciphertext', '')
                    if email_data.get('pqc_secret'):
                        msg['X-QuMail-PQC-Secret'] = email_data.get('pqc_secret', '')
                    
                    # Set a generic placeholder body for encrypted mails
                    msg.set_content("This is a QuMail encrypted message. Please use a QuMail client to decrypt.")
                else:
                    # For NONE mode, set the actual body
                    msg.set_content(email_data.get('body', ''))

                return ('OK', [(None, msg.as_bytes()), f'UID {email_data["uid"]})'.encode()])
            
            def append(self, folder, flags, date, message):
                from email import message_from_bytes
                
                if isinstance(message, bytes):
                    parsed_msg = message_from_bytes(message)
                else:
                    parsed_msg = message_from_bytes(message.encode())
                
                # CRITICAL FIX: Decode quoted-printable content from email headers
                email_service = EmailService()  # Create instance to access decode method
                
                sent_email = {
                    "uid": str(len(EmailService._demo_sent_emails.get(self.user_email, [])) + 1),
                    "message_id": parsed_msg.get('Message-ID', f'<sent{len(EmailService._demo_sent_emails.get(self.user_email, []))}@demo>'),
                    "sender": self.user_email,
                    "to": parsed_msg.get('To', ''),
                    "cc": parsed_msg.get('Cc', ''),
                    "bcc": parsed_msg.get('Bcc', ''),
                    "subject": parsed_msg.get('Subject', ''),
                    "date": parsed_msg.get('Date', ''),
                    "encryption_mode": parsed_msg.get('X-QuMail-Encryption', 'NONE'),
                    "content": email_service.decode_email_header_content(parsed_msg.get('X-QuMail-Content', '')),
                    "nonce": email_service.decode_email_header_content(parsed_msg.get('X-QuMail-Nonce', '')),
                    "mac": email_service.decode_email_header_content(parsed_msg.get('X-QuMail-MAC', '')),
                    "km_key_id": parsed_msg.get('X-QuMail-KM-Key-ID', ''),
                    # Handle PQC headers for sent emails
                    "pqc_public": email_service.decode_email_header_content(parsed_msg.get('X-QuMail-PQC-Public', '')),
                    "pqc_ciphertext": email_service.decode_email_header_content(parsed_msg.get('X-QuMail-PQC-Ciphertext', '')),
                    "pqc_secret": email_service.decode_email_header_content(parsed_msg.get('X-QuMail-PQC-Secret', '')),
                    "body": str(parsed_msg.get_payload() or '')
                }
                
                if self.user_email not in EmailService._demo_sent_emails:
                    EmailService._demo_sent_emails[self.user_email] = []
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
                # For QuMail internal accounts, fallback to mock
                logger.info(f"QuMail internal account detected: {user.email}")
                return self._get_mock_smtp_connection(user)
            
            logger.info(f"SMTP connection established for {user.email}")
            return smtp
            
        except Exception as e:
            logger.error(f"Failed to create SMTP connection for {user.email}: {e}")
            # Fallback to mock for development
            return self._get_mock_smtp_connection(user)
    
    def _get_mock_smtp_connection(self, user: User):
        """Create mock SMTP connection with cross-account delivery"""
        class MockSMTPConnection:
            def __init__(self, sender_user):
                self.sender_user = sender_user
                
            def send_message(self, msg, to_addrs=None):
                logger.info(f"[DEMO MODE] Email would be sent from {self.sender_user.email} to {to_addrs}")
                
                # CRITICAL FIX: Actually deliver the email to recipient inboxes in demo mode
                if to_addrs:
                    for recipient in to_addrs:
                        if recipient and recipient != self.sender_user.email:
                            # Create received email for recipient inbox
                            received_email = {
                                "uid": str(len(EmailService._demo_inbox_emails.get(recipient, [])) + 100),
                                "message_id": msg.get('Message-ID', f'<demo{datetime.now().timestamp()}@qumail.local>'),
                                "sender": self.sender_user.email,
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
                            
                            # CRITICAL FIX: Copy PQC-specific headers
                            if msg.get('X-QuMail-PQC-Public'):
                                received_email["pqc_public"] = msg.get('X-QuMail-PQC-Public')
                            if msg.get('X-QuMail-PQC-Ciphertext'):
                                received_email["pqc_ciphertext"] = msg.get('X-QuMail-PQC-Ciphertext')
                            if msg.get('X-QuMail-PQC-Secret'):
                                received_email["pqc_secret"] = msg.get('X-QuMail-PQC-Secret')
                            
                            if msg.get('X-QuMail-KM-Key-ID') or msg.get('X-QuMail-PQC-Public'):
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
        return MockSMTPConnection(user)

    async def fetch_inbox(self, user: User) -> List[Dict]:
        """Fetch emails from inbox"""
        try:
            conn = await self._get_imap_connection(user)
            conn.select('INBOX')
            
            # Search for all messages
            status, messages = conn.search(None, 'ALL')
            if status != 'OK':
                logger.error(f"Failed to search inbox for {user.email}")
                return []
            
            message_nums = messages[0].split() if messages[0] else []
            emails = []
            
            # Fetch each message
            for num in message_nums:
                try:
                    status, msg_data = conn.fetch(num, '(RFC822)')
                    if status != 'OK':
                        continue
                    
                    # Parse email
                    raw_email = msg_data[0][1]
                    msg = email.message_from_bytes(raw_email)
                    
                    # Extract basic email info
                    email_dict = {
                        "uid": num.decode() if isinstance(num, bytes) else str(num),
                        "message_id": msg.get('Message-ID', ''),
                        "sender": msg.get('From', ''),
                        "to": user.email,
                        "cc": msg.get('Cc', ''),
                        "bcc": msg.get('Bcc', ''),
                        "subject": msg.get('Subject', ''),
                        "date": msg.get('Date', ''),
                        "body": self._extract_body(msg)
                    }
                    
                    # Extract QuMail encryption metadata
                    encryption_mode = msg.get('X-QuMail-Encryption', 'NONE')
                    email_dict["encryption_mode"] = encryption_mode
                    
                    if encryption_mode != 'NONE':
                        # This is an encrypted QuMail email
                        # CRITICAL FIX: Decode quoted-printable content from email headers
                        email_dict["content"] = self.decode_email_header_content(msg.get('X-QuMail-Content', ''))
                        email_dict["nonce"] = self.decode_email_header_content(msg.get('X-QuMail-Nonce', ''))
                        email_dict["mac"] = self.decode_email_header_content(msg.get('X-QuMail-MAC', ''))
                        email_dict["km_key_id"] = msg.get('X-QuMail-KM-Key-ID', '')
                        
                        # Handle PQC specific fields if present
                        if encryption_mode == 'PQC':
                            pqc_public_raw = msg.get('X-QuMail-PQC-Public', '')
                            pqc_ciphertext_raw = msg.get('X-QuMail-PQC-Ciphertext', '')
                            pqc_secret_raw = msg.get('X-QuMail-PQC-Secret', '')
                            
                            email_dict["pqc_public"] = self.decode_email_header_content(pqc_public_raw) if pqc_public_raw else ''
                            email_dict["pqc_ciphertext"] = self.decode_email_header_content(pqc_ciphertext_raw) if pqc_ciphertext_raw else ''
                            email_dict["pqc_secret"] = self.decode_email_header_content(pqc_secret_raw) if pqc_secret_raw else ''
                            
                            logger.info(f"[PQC FETCH] Raw headers - public: {bool(pqc_public_raw)}, ciphertext: {bool(pqc_ciphertext_raw)}, secret: {bool(pqc_secret_raw)}")
                            logger.info(f"[PQC FETCH] Decoded - public: {bool(email_dict['pqc_public'])}, ciphertext: {bool(email_dict['pqc_ciphertext'])}, secret: {bool(email_dict['pqc_secret'])}")
                        
                        logger.info(f"Fetched encrypted email: {email_dict['subject']} (Mode: {encryption_mode})")
                    else:
                        logger.info(f"Fetched regular email: {email_dict['subject']}")
                    
                    emails.append(email_dict)
                    
                except Exception as e:
                    logger.error(f"Error parsing email {num}: {e}")
                    continue
            
            logger.info(f"Fetched {len(emails)} emails from inbox for {user.email}")
            return emails
            
        except Exception as e:
            logger.error(f"Failed to fetch inbox for {user.email}: {e}")
            return []

    async def fetch_sent(self, user: User) -> List[Dict]:
        """Fetch emails from sent folder"""
        try:
            conn = await self._get_imap_connection(user)
            
            # Try different sent folder names
            sent_folders = ['SENT', '[Gmail]/Sent Mail', 'Sent', 'INBOX.Sent']
            
            for folder in sent_folders:
                try:
                    status, _ = conn.select(folder)
                    if status == 'OK':
                        logger.info(f"Using sent folder: {folder} for {user.email}")
                        break
                except:
                    continue
            else:
                logger.warning(f"No sent folder found for {user.email}, using INBOX")
                conn.select('INBOX')
            
            # Search for all messages
            status, messages = conn.search(None, 'ALL')
            if status != 'OK':
                return []
            
            message_nums = messages[0].split() if messages[0] else []
            emails = []
            
            # Fetch each message
            for num in message_nums:
                try:
                    status, msg_data = conn.fetch(num, '(RFC822)')
                    if status != 'OK':
                        continue
                    
                    # Parse email
                    raw_email = msg_data[0][1]
                    msg = email.message_from_bytes(raw_email)
                    
                    # Extract email info
                    email_dict = {
                        "uid": num.decode() if isinstance(num, bytes) else str(num),
                        "message_id": msg.get('Message-ID', ''),
                        "sender": msg.get('From', ''),
                        "to": msg.get('To', ''),
                        "cc": msg.get('Cc', ''),
                        "bcc": msg.get('Bcc', ''),
                        "subject": msg.get('Subject', ''),
                        "date": msg.get('Date', ''),
                        "encryption_mode": msg.get('X-QuMail-Encryption', 'NONE'),
                        "body": self._extract_body(msg)
                    }
                    
                    emails.append(email_dict)
                    
                except Exception as e:
                    logger.error(f"Error parsing sent email {num}: {e}")
                    continue
            
            logger.info(f"Fetched {len(emails)} sent emails for {user.email}")
            return emails
            
        except Exception as e:
            logger.error(f"Failed to fetch sent emails for {user.email}: {e}")
            return []

    async def send_email(self, user: User, email_data: Dict) -> bool:
        """Send email via SMTP with proper QuMail headers"""
        try:
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = user.email
            msg['To'] = email_data["to"]
            if email_data.get("cc"):
                msg['Cc'] = email_data["cc"]
            if email_data.get("bcc"):
                msg['Bcc'] = email_data["bcc"]
            msg['Subject'] = email_data.get("subject", "[QuMail Encrypted]")
            msg['Date'] = formatdate(localtime=True)
            msg['Message-ID'] = make_msgid()
            
            # Add QuMail headers for encrypted emails
            msg['X-QuMail-Encryption'] = email_data["encryption_mode"]
            
            # CRITICAL FIX: Always add KM Key-ID for encrypted modes (including PQC)
            if email_data.get("km_key_id"):
                msg['X-QuMail-KM-Key-ID'] = email_data["km_key_id"]
            
            # Standard encryption headers (AES, OTP)
            if email_data.get("content"):
                msg['X-QuMail-Content'] = email_data["content"]
            if email_data.get("nonce"):
                msg['X-QuMail-Nonce'] = email_data["nonce"]
            if email_data.get("mac"):
                msg['X-QuMail-MAC'] = email_data["mac"]
            
            # PQC-specific headers with proper encoding
            if email_data.get("pqc_public"):
                msg['X-QuMail-PQC-Public'] = self.encode_email_header_content(email_data["pqc_public"])
            if email_data.get("pqc_ciphertext"):
                msg['X-QuMail-PQC-Ciphertext'] = self.encode_email_header_content(email_data["pqc_ciphertext"])
            if email_data.get("pqc_secret"):
                msg['X-QuMail-PQC-Secret'] = self.encode_email_header_content(email_data["pqc_secret"])
            
            # Set body - for encrypted emails, use placeholder
            if email_data["encryption_mode"] != "NONE":
                body_text = "This is a QuMail encrypted message. Please use a QuMail client to decrypt."
            else:
                body_text = email_data.get("body", "")
            
            msg.attach(MIMEText(body_text, 'plain'))
            
            # Handle attachments if any
            for attachment in email_data.get("attachments", []):
                if isinstance(attachment, dict) and attachment.get("content"):
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment["content"])
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename= {attachment.get("filename", "attachment")}'
                    )
                    msg.attach(part)
            
            # Get recipients list
            recipients = [email_data["to"]]
            if email_data.get("cc"):
                recipients.extend([addr.strip() for addr in email_data["cc"].split(',') if addr.strip()])
            if email_data.get("bcc"):
                recipients.extend([addr.strip() for addr in email_data["bcc"].split(',') if addr.strip()])
            
            # Separate QuMail and external recipients
            qumail_recipients = []
            external_recipients = []
            
            for recipient in recipients:
                if '@qumail.com' in recipient.lower() or '@qumail.local' in recipient.lower():
                    qumail_recipients.append(recipient)
                else:
                    external_recipients.append(recipient)
            
            success = True
            
            # Handle QuMail internal delivery (demo mode)
            if qumail_recipients:
                logger.info(f"Delivering to QuMail recipients: {qumail_recipients}")
                
                # Prepare received email data with all encryption metadata
                received_email = {
                    "uid": "100",  # Will be updated per recipient
                    "message_id": msg.get('Message-ID'),
                    "sender": user.email,
                    "subject": email_data.get("subject", ""),
                    "body": email_data.get("body", ""),
                    "date": msg.get('Date'),
                    "encryption_mode": email_data["encryption_mode"]
                }
                
                # CRITICAL FIX: Copy all encryption metadata for proper decryption
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
            
            # CRITICAL FIX: Only add encryption headers for non-NONE modes
            if email_data["encryption_mode"] != "NONE":
                # Always include KM Key-ID for encrypted modes
                if email_data.get("km_key_id"):
                    msg['X-QuMail-KM-Key-ID'] = email_data["km_key_id"]
                
                # Standard encryption headers
                if email_data.get("content"):
                    msg['X-QuMail-Content'] = email_data["content"]
                if email_data.get("nonce"):
                    msg['X-QuMail-Nonce'] = email_data["nonce"]
                if email_data.get("mac"):
                    msg['X-QuMail-MAC'] = email_data["mac"]
                    
                # PQC-specific headers for SENT folder
                if email_data.get("pqc_public"):
                    msg['X-QuMail-PQC-Public'] = self.encode_email_header_content(email_data["pqc_public"])
                if email_data.get("pqc_ciphertext"):
                    msg['X-QuMail-PQC-Ciphertext'] = self.encode_email_header_content(email_data["pqc_ciphertext"])
            
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
    
    def _extract_body(self, msg):
        """Extract body text from email message"""
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True)
                    if isinstance(body, bytes):
                        body = body.decode('utf-8', errors='ignore')
                    break
        else:
            body = msg.get_payload(decode=True)
            if isinstance(body, bytes):
                body = body.decode('utf-8', errors='ignore')
        
        return body or ""
    
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