"""
Database models for QuMail secure email client
"""

from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime
import json

Base = declarative_base()

class User(Base):
    """User model for email accounts and KM sessions"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=True)  # For KM auth
    
    # OAuth 2.0 authentication
    google_access_token = Column(Text, nullable=True)  # Encrypted OAuth access token
    google_refresh_token = Column(Text, nullable=True)  # Encrypted OAuth refresh token
    google_token_expires_at = Column(DateTime, nullable=True)
    oauth_provider = Column(String, default="google")  # google, outlook, etc.
    
    # App-specific password for email providers
    app_password = Column(Text, nullable=True)  # For Gmail app passwords, etc.
    
    # Email server configuration (auto-configured from OAuth provider)
    imap_server = Column(String, nullable=True)  # Auto-set based on provider
    smtp_server = Column(String, nullable=True)  # Auto-set based on provider
    imap_port = Column(Integer, default=993)
    smtp_port = Column(Integer, default=587)
    
    # KM session
    km_session_id = Column(String, nullable=True)
    km_endpoint = Column(String, default="http://localhost:8001")
    
    # User preferences
    default_encryption_mode = Column(String, default="AES")  # OTP, AES, PQC, NONE
    auto_decrypt = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    last_login = Column(DateTime, nullable=True)
    
    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "imap_server": self.imap_server,
            "smtp_server": self.smtp_server,
            "imap_port": self.imap_port,
            "smtp_port": self.smtp_port,
            "default_encryption_mode": self.default_encryption_mode,
            "auto_decrypt": self.auto_decrypt,
            "oauth_provider": self.oauth_provider,
            "has_oauth_tokens": bool(self.google_access_token),
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class Email(Base):
    """Email model for storing encrypted email metadata"""
    __tablename__ = "emails"
    
    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String, nullable=True)  # IMAP UID
    message_id = Column(String, nullable=True)  # Email Message-ID header
    
    # Email participants
    sender = Column(String, nullable=False)
    recipients = Column(Text, nullable=False)  # JSON array of recipients
    cc = Column(Text, nullable=True)  # JSON array
    bcc = Column(Text, nullable=True)  # JSON array
    
    # Email content (encrypted)
    subject = Column(String, nullable=False)
    body = Column(Text, nullable=False)
    headers = Column(Text, nullable=True)  # JSON of email headers
    
    # Encryption metadata
    encryption_mode = Column(String, nullable=False)  # OTP, AES, PQC, NONE
    km_key_id = Column(String, nullable=True)  # KM key ID used
    mac_digest = Column(String, nullable=True)  # HMAC for integrity
    
    # Email status and metadata
    status = Column(String, default="received")  # received, sent, queued, failed
    folder = Column(String, default="INBOX")  # INBOX, SENT, OUTBOX
    read = Column(Boolean, default=False)
    flagged = Column(Boolean, default=False)
    
    # Timestamps
    date_sent = Column(DateTime, nullable=True)
    date_received = Column(DateTime, server_default=func.now())
    
    def _safe_json_loads(self, json_string, default_value):
        """Safely parse JSON string with fallback to default value"""
        if not json_string:
            return default_value
        try:
            return json.loads(json_string)
        except (json.JSONDecodeError, ValueError, TypeError):
            # If it's a simple string, try to convert it to appropriate format
            if isinstance(default_value, list):
                return [json_string.strip()] if json_string.strip() else []
            elif isinstance(default_value, dict):
                return {}
            return default_value

    def to_dict(self):
        return {
            "id": self.id,
            "uid": self.uid,
            "message_id": self.message_id,
            "sender": self.sender,
            "recipients": self._safe_json_loads(self.recipients, []),
            "cc": self._safe_json_loads(self.cc, []),
            "bcc": self._safe_json_loads(self.bcc, []),
            "subject": self.subject,
            "body": self.body,
            "headers": self._safe_json_loads(self.headers, {}),
            "encryption_mode": self.encryption_mode,
            "km_key_id": self.km_key_id,
            "mac_digest": self.mac_digest,
            "status": self.status,
            "folder": self.folder,
            "read": self.read,
            "flagged": self.flagged,
            "date_sent": self.date_sent.isoformat() if self.date_sent else None,
            "date_received": self.date_received.isoformat() if self.date_received else None
        }

class Attachment(Base):
    """Attachment model for encrypted file attachments"""
    __tablename__ = "attachments"
    
    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, nullable=False)  # Foreign key to Email
    
    # Attachment metadata
    filename = Column(String, nullable=False)
    content_type = Column(String, nullable=True)
    size = Column(Integer, nullable=False)
    
    # Encrypted content and integrity
    encrypted_content = Column(LargeBinary, nullable=False)
    mac_digest = Column(String, nullable=False)  # HMAC for integrity
    encryption_mode = Column(String, nullable=False)
    km_key_id = Column(String, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    
    def to_dict(self):
        return {
            "id": self.id,
            "email_id": self.email_id,
            "filename": self.filename,
            "content_type": self.content_type,
            "size": self.size,
            "mac_digest": self.mac_digest,
            "encryption_mode": self.encryption_mode,
            "km_key_id": self.km_key_id,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class KMSession(Base):
    """Key Manager session tracking"""
    __tablename__ = "km_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, nullable=False)
    user_email = Column(String, nullable=False)
    
    # Session metadata
    endpoint = Column(String, nullable=False)
    active = Column(Boolean, default=True)
    
    # Key usage tracking (metadata only)
    keys_requested = Column(Integer, default=0)
    keys_consumed = Column(Integer, default=0)
    last_key_request = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    expires_at = Column(DateTime, nullable=True)
    
    def to_dict(self):
        return {
            "id": self.id,
            "session_id": self.session_id,
            "user_email": self.user_email,
            "endpoint": self.endpoint,
            "active": self.active,
            "keys_requested": self.keys_requested,
            "keys_consumed": self.keys_consumed,
            "last_key_request": self.last_key_request.isoformat() if self.last_key_request else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None
        }

class JWTBlacklist(Base):
    """JWT token blacklist for revocation mechanism"""
    __tablename__ = "jwt_blacklist"
    
    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String, unique=True, nullable=False, index=True)  # JWT ID
    user_email = Column(String, nullable=False, index=True)
    token_hash = Column(String, nullable=False)  # SHA256 hash of token
    
    # Metadata
    reason = Column(String, default="logout")  # logout, security_breach, expired
    revoked_at = Column(DateTime, server_default=func.now())
    expires_at = Column(DateTime, nullable=False)  # Original token expiry
    
    def to_dict(self):
        return {
            "id": self.id,
            "jti": self.jti,
            "user_email": self.user_email,
            "reason": self.reason,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None
        }

class SecurityLog(Base):
    """Security event logging (metadata only, no sensitive data)"""
    __tablename__ = "security_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String, nullable=False)
    
    # Event details
    event_type = Column(String, nullable=False)  # login, send, receive, decrypt, error
    encryption_mode = Column(String, nullable=True)
    km_key_id = Column(String, nullable=True)
    
    # Participants (no content)
    sender = Column(String, nullable=True)
    recipient = Column(String, nullable=True)
    subject_hash = Column(String, nullable=True)  # SHA256 hash of subject for correlation
    
    # Status and metadata
    status = Column(String, nullable=False)  # success, failure, warning
    error_code = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    
    # Timestamp
    timestamp = Column(DateTime, server_default=func.now())
    
    def to_dict(self):
        return {
            "id": self.id,
            "user_email": self.user_email,
            "event_type": self.event_type,
            "encryption_mode": self.encryption_mode,
            "km_key_id": self.km_key_id,
            "sender": self.sender,
            "recipient": self.recipient,
            "subject_hash": self.subject_hash,
            "status": self.status,
            "error_code": self.error_code,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }