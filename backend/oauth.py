"""
OAuth 2.0 authentication service for QuMail
Supports Google Gmail API authentication
"""

import os
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs

# OAuth imports with fallback for development
try:
    import google.auth.transport.requests
    import google.oauth2.credentials
    from google_auth_oauthlib.flow import Flow
    from google.api_core import exceptions
    from googleapiclient.discovery import build
    GOOGLE_AUTH_AVAILABLE = True
except ImportError:
    GOOGLE_AUTH_AVAILABLE = False
    print("Warning: Google OAuth libraries not available, OAuth features disabled")

from cryptography.fernet import Fernet

from logger import setup_logger
from models import User

logger = setup_logger()

class OAuthService:
    """OAuth 2.0 service for Gmail authentication"""
    
    def __init__(self):
        # Google OAuth configuration
        self.google_client_id = os.getenv('GOOGLE_CLIENT_ID')
        self.google_client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
        self.redirect_uri = os.getenv('OAUTH_REDIRECT_URI', 'http://localhost:5000/auth/callback')
        
        # Gmail API scopes
        self.scopes = [
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/gmail.send',
            'https://www.googleapis.com/auth/gmail.modify',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile'
        ]
        
        # Encryption key for storing tokens (use persistent key)
        default_key = 'k-aJQ8r7VQx8r_3z3-QcFx7u5tZQaJc3p_7d2X9o-Vg='
        encryption_key_str = os.getenv('OAUTH_ENCRYPTION_KEY', default_key)
        if isinstance(encryption_key_str, str):
            self.encryption_key = encryption_key_str.encode()
        else:
            self.encryption_key = encryption_key_str
        self.cipher = Fernet(self.encryption_key)
        
        # State storage for OAuth flow (in production, use Redis or database)
        self.oauth_states = {}
    
    def generate_authorization_url(self, user_email: str = None) -> Tuple[str, str]:
        """Generate Google OAuth authorization URL"""
        try:
            if not GOOGLE_AUTH_AVAILABLE:
                raise RuntimeError("Google OAuth libraries not available")
                
            if not self.google_client_id or not self.google_client_secret:
                raise ValueError("Google OAuth credentials not configured")
            
            # Create OAuth flow
            flow = Flow.from_client_config(
                {
                    "web": {
                        "client_id": self.google_client_id,
                        "client_secret": self.google_client_secret,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": [self.redirect_uri]
                    }
                },
                scopes=self.scopes
            )
            flow.redirect_uri = self.redirect_uri
            
            # Generate state parameter for security
            state = secrets.token_urlsafe(32)
            
            # Store state with metadata
            self.oauth_states[state] = {
                'user_email': user_email,
                'created_at': datetime.utcnow(),
                'expires_at': datetime.utcnow() + timedelta(minutes=10)
            }
            
            # Generate authorization URL
            auth_url, _ = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true',
                state=state,
                prompt='consent'  # Force consent to get refresh token
            )
            
            logger.info(f"Generated OAuth authorization URL for user: {user_email}")
            return auth_url, state
            
        except Exception as e:
            logger.error(f"Failed to generate authorization URL: {e}")
            raise
    
    def exchange_code_for_tokens(self, authorization_code: str, state: str) -> Tuple[Dict, str]:
        """Exchange authorization code for access and refresh tokens"""
        try:
            if not GOOGLE_AUTH_AVAILABLE:
                raise RuntimeError("Google OAuth libraries not available")
            # Validate state parameter
            if state not in self.oauth_states:
                raise ValueError("Invalid or expired OAuth state")
            
            state_data = self.oauth_states[state]
            if datetime.utcnow() > state_data['expires_at']:
                del self.oauth_states[state]
                raise ValueError("OAuth state expired")
            
            # Create OAuth flow
            flow = Flow.from_client_config(
                {
                    "web": {
                        "client_id": self.google_client_id,
                        "client_secret": self.google_client_secret,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": [self.redirect_uri]
                    }
                },
                scopes=self.scopes
            )
            flow.redirect_uri = self.redirect_uri
            
            # Exchange code for tokens
            flow.fetch_token(code=authorization_code)
            credentials = flow.credentials
            
            # Get user info
            user_info = self._get_user_info(credentials)
            
            # Prepare token data
            token_data = {
                'access_token': credentials.token,
                'refresh_token': credentials.refresh_token,
                'expires_at': credentials.expiry.isoformat() if credentials.expiry else None,
                'scopes': credentials.scopes
            }
            
            # Clean up state
            del self.oauth_states[state]
            
            logger.info(f"Successfully exchanged OAuth code for tokens: {user_info['email']}")
            return token_data, user_info['email']
            
        except Exception as e:
            logger.error(f"Failed to exchange OAuth code: {e}")
            raise
    
    def _get_user_info(self, credentials) -> Dict:
        """Get user information from Google API"""
        try:
            if not GOOGLE_AUTH_AVAILABLE:
                raise RuntimeError("Google OAuth libraries not available")
            service = build('oauth2', 'v2', credentials=credentials)
            user_info = service.userinfo().get().execute()
            return {
                'email': user_info['email'],
                'name': user_info.get('name', ''),
                'picture': user_info.get('picture', ''),
                'verified_email': user_info.get('verified_email', False)
            }
        except Exception as e:
            logger.error(f"Failed to get user info: {e}")
            raise
    
    def encrypt_token(self, token: str) -> str:
        """Encrypt OAuth token for storage"""
        try:
            encrypted = self.cipher.encrypt(token.encode())
            return encrypted.decode()
        except Exception as e:
            logger.error(f"Failed to encrypt token: {e}")
            raise
    
    def decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt OAuth token from storage"""
        try:
            decrypted = self.cipher.decrypt(encrypted_token.encode())
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt token: {e}")
            raise
    
    def refresh_access_token(self, refresh_token: str) -> Dict:
        """Refresh expired access token"""
        try:
            if not GOOGLE_AUTH_AVAILABLE:
                raise RuntimeError("Google OAuth libraries not available")
            # Create credentials with refresh token
            credentials = google.oauth2.credentials.Credentials(
                token=None,  # Will be refreshed
                refresh_token=refresh_token,
                token_uri="https://oauth2.googleapis.com/token",
                client_id=self.google_client_id,
                client_secret=self.google_client_secret
            )
            
            # Refresh token
            request = google.auth.transport.requests.Request()
            credentials.refresh(request)
            
            return {
                'access_token': credentials.token,
                'expires_at': credentials.expiry.isoformat() if credentials.expiry else None
            }
            
        except Exception as e:
            logger.error(f"Failed to refresh access token: {e}")
            raise
    
    def validate_access_token(self, access_token: str) -> Dict:
        """Validate access token and get user info"""
        try:
            if not GOOGLE_AUTH_AVAILABLE:
                raise RuntimeError("Google OAuth libraries not available")
            credentials = google.oauth2.credentials.Credentials(token=access_token)
            user_info = self._get_user_info(credentials)
            return user_info
        except Exception as e:
            logger.error(f"Failed to validate access token: {e}")
            raise
    
    def get_gmail_service(self, access_token: str):
        """Get authenticated Gmail service"""
        try:
            if not GOOGLE_AUTH_AVAILABLE:
                raise RuntimeError("Google OAuth libraries not available")
            credentials = google.oauth2.credentials.Credentials(token=access_token)
            return build('gmail', 'v1', credentials=credentials)
        except Exception as e:
            logger.error(f"Failed to get Gmail service: {e}")
            raise
    
    def configure_email_settings(self, user: User, oauth_provider: str = "google"):
        """Auto-configure email settings based on OAuth provider"""
        try:
            if oauth_provider == "google":
                user.imap_server = "imap.gmail.com"
                user.smtp_server = "smtp.gmail.com"
                user.imap_port = 993
                user.smtp_port = 587
                user.oauth_provider = "google"
            
            logger.info(f"Configured email settings for {oauth_provider}: {user.email}")
            
        except Exception as e:
            logger.error(f"Failed to configure email settings: {e}")
            raise