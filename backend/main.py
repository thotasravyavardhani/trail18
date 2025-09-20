"""
QuMail Secure Email Client - Main FastAPI Application
Quantum-secure email client with OTP, AES-256-GCM, and PQC encryption
"""

from fastapi import FastAPI, HTTPException, Depends, File, UploadFile, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy.orm import Session
from typing import List, Optional
from contextlib import asynccontextmanager
from datetime import datetime
import logging
import asyncio
import json
import os

from db import get_db, init_db
from models import User, Email, Attachment, JWTBlacklist
from crypto_utils import CryptoManager
from email_service import EmailService
from km_mock import KeyManagerMock
from oauth import OAuthService
from logger import setup_logger

# Initialize services
crypto_manager = CryptoManager()
km_mock = KeyManagerMock()
email_service = EmailService()
oauth_service = OAuthService()
logger = setup_logger()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events"""
    # Startup
    await init_db()
    await km_mock.start()
    logger.info("QuMail backend started successfully")
    
    yield
    
    # Shutdown
    await km_mock.stop()
    logger.info("QuMail backend shutdown")

# Initialize FastAPI app
app = FastAPI(
    title="QuMail Secure Email Client",
    description="Quantum-secure email client with end-to-end encryption",
    version="1.0.0",
    lifespan=lifespan
)

# Add validation error handler
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.error(f"Validation error on {request.url}: {exc.errors()}")
    return JSONResponse(
        status_code=422,
        content={"detail": f"Validation error: {exc.errors()}"}
    )

# CORS middleware for React frontend - Allow all origins for Replit proxy
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# OAuth 2.0 Auth endpoints
@app.get("/api/auth/google/login")
async def google_oauth_login():
    """Initiate Google OAuth 2.0 flow"""
    try:
        # Generate authorization URL
        auth_url, state = oauth_service.generate_authorization_url()
        
        logger.info("Google OAuth login initiated successfully")
        return {
            "authorization_url": auth_url,
            "state": state
        }
        
    except Exception as e:
        logger.error(f"OAuth login failed: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to initiate Google OAuth login. Please ensure OAuth credentials are configured."
        )

@app.post("/api/auth/google/callback")
async def google_oauth_callback(
    code: str = Form(...),
    state: str = Form(...),
    db: Session = Depends(get_db)
):
    """Handle Google OAuth 2.0 callback"""
    try:
        # Exchange code for tokens
        token_data, user_email = oauth_service.exchange_code_for_tokens(code, state)
        
        # Encrypt tokens for storage
        encrypted_access_token = oauth_service.encrypt_token(token_data['access_token'])
        encrypted_refresh_token = oauth_service.encrypt_token(token_data['refresh_token']) if token_data['refresh_token'] else None
        
        # Create or update user
        user = db.query(User).filter(User.email == user_email).first()
        if not user:
            user = User(email=user_email)
            db.add(user)
        
        # Update OAuth tokens and configure email settings
        setattr(user, 'google_access_token', encrypted_access_token)
        setattr(user, 'google_refresh_token', encrypted_refresh_token)
        setattr(user, 'google_token_expires_at', datetime.fromisoformat(token_data['expires_at']) if token_data.get('expires_at') else None)
        setattr(user, 'last_login', datetime.utcnow())
        
        # Auto-configure email settings
        oauth_service.configure_email_settings(user, "google")
        
        # Authenticate with KM
        km_session = await km_mock.authenticate(user_email)
        user.km_session_id = km_session["session_id"]
        
        db.commit()
        
        # Generate JWT token with unique JTI for revocation
        import uuid
        jti = str(uuid.uuid4())
        token = crypto_manager.generate_jwt_token(user_email, jti=jti)
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "email": user.email,
                "oauth_provider": user.oauth_provider,
                "km_session_id": user.km_session_id
            }
        }
        
    except Exception as e:
        logger.error(f"OAuth callback failed: {e}")
        return {"error": "oauth_unavailable", "message": "OAuth authentication is not available in this environment"}

@app.post("/api/auth/logout")
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Logout user and revoke JWT token"""
    try:
        # Verify and decode token
        payload = crypto_manager.verify_jwt_token(credentials.credentials)
        
        # Add token to blacklist
        import hashlib
        token_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
        
        blacklist_entry = JWTBlacklist(
            jti=payload.get('jti', 'unknown'),
            user_email=payload.get('sub', ''),
            token_hash=token_hash,
            reason="logout",
            expires_at=datetime.fromtimestamp(payload.get('exp', 0))
        )
        
        db.add(blacklist_entry)
        db.commit()
        
        return {"message": "Logged out successfully"}
        
    except Exception as e:
        logger.error(f"Logout failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")

async def verify_jwt_not_blacklisted(token: str, db: Session) -> bool:
    """Check if JWT token is not in blacklist"""
    import hashlib
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    # Check for blacklisted token by hash or JTI
    payload = crypto_manager.verify_jwt_token(token, check_blacklist=False)
    jti = payload.get('jti')
    
    blacklisted = db.query(JWTBlacklist).filter(
        (JWTBlacklist.token_hash == token_hash) | 
        (JWTBlacklist.jti == jti if jti else False)
    ).first()
    
    return blacklisted is None

@app.get("/api/auth/me")
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Get current authenticated user with blacklist checking"""
    try:
        # Check if token is blacklisted
        if not await verify_jwt_not_blacklisted(credentials.credentials, db):
            raise HTTPException(status_code=401, detail="Token has been revoked")
        
        payload = crypto_manager.verify_jwt_token(credentials.credentials)
        email = payload.get("sub")
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return {
            "email": user.email, 
            "km_session_id": user.km_session_id,
            "oauth_provider": user.oauth_provider,
            "has_oauth_tokens": bool(user.google_access_token)
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token")

# Email endpoints
@app.get("/api/emails/inbox")
async def get_inbox(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Fetch and decrypt inbox emails"""
    try:
        user = await get_current_user(credentials, db)
        user_obj = db.query(User).filter(User.email == user["email"]).first()
        
        # Fetch emails from IMAP
        emails = await email_service.fetch_inbox(user_obj)
        
        # Decrypt emails
        decrypted_emails = []
        for email_data in emails:
            try:
                # Get KM key if needed - using message-specific key_id
                km_key = None
                if email_data.get("encryption_mode") in ["OTP", "AES", "PQC"] and user_obj:
                    # CRITICAL FIX: Use the key_id stored with the message
                    message_key_id = email_data.get("km_key_id")
                    if message_key_id:
                        try:
                            # Get the specific key used for this message
                            key_result = await km_mock.get_key_by_id(message_key_id)
                            km_key = key_result["key_data"] if isinstance(key_result, dict) else key_result
                            logger.info(f"Retrieved message-specific key {message_key_id} for decryption")
                            
                        except Exception as key_e:
                            logger.warning(f"Failed to get message key {message_key_id}, trying session key: {key_e}")
                            # Fallback to current session key
                            try:
                                if not getattr(user_obj, 'km_session_id', None):
                                    km_session = await km_mock.authenticate(user_obj.email)
                                    user_obj.km_session_id = km_session["session_id"]
                                    db.commit()
                                    
                                key_result = await km_mock.get_key(str(user_obj.km_session_id))
                                km_key = key_result["key_data"] if isinstance(key_result, dict) else key_result
                                
                            except Exception as session_e:
                                logger.error(f"Failed to get session key for decryption: {session_e}")
                                km_key = None
                    else:
                        logger.warning(f"No key_id found for encrypted message {email_data.get('uid', 'unknown')}")
                        km_key = None
                
                # Process email based on encryption mode
                encryption_mode = email_data.get('encryption_mode', 'NONE')
                logger.info(f"[INBOX DEBUG] Processing email {email_data.get('uid', 'unknown')} with encryption mode: {encryption_mode}")
                
                if encryption_mode == "NONE":
                    # NONE mode: Skip decryption, use email content directly  
                    decrypted = email_data.copy()
                    decrypted["decryption_status"] = "success"
                    # Ensure subject and body are properly set for display
                    if not decrypted.get("subject", "").strip():
                        decrypted["subject"] = "(No Subject)"
                    if not decrypted.get("body", "").strip():
                        decrypted["body"] = "This email has no content."
                    logger.info(f"[NONE DEBUG] NONE mode email processed directly with subject: '{decrypted.get('subject', 'MISSING')}'")
                else:
                    # Encrypted modes: Call decrypt_email
                    decrypted = await crypto_manager.decrypt_email(
                        email_data, km_key
                    )
                    logger.info(f"[INBOX DEBUG] Decrypted email has subject: '{decrypted.get('subject', 'MISSING')}'")
                
                decrypted_emails.append(decrypted)
                
            except Exception as e:
                logger.error(f"Failed to decrypt email {email_data.get('uid', 'unknown')}: {str(e)}")
                # Add with error status
                email_data["decryption_status"] = "error"
                email_data["decryption_error"] = "Failed to decrypt"
                decrypted_emails.append(email_data)
        
        return {"emails": decrypted_emails}
        
    except Exception as e:
        logger.error(f"Failed to fetch inbox: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch inbox")

@app.get("/api/emails/sent")
async def get_sent(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Fetch sent emails"""
    try:
        user = await get_current_user(credentials, db)
        user_obj = db.query(User).filter(User.email == user["email"]).first()
        
        emails = await email_service.fetch_sent(user_obj)
        return {"emails": emails}
        
    except Exception as e:
        logger.error(f"Failed to fetch sent emails: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch sent emails")

@app.get("/api/emails/outbox")
async def get_outbox(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Fetch outbox (queued) emails"""
    try:
        user = await get_current_user(credentials, db)
        
        # Get queued emails from database
        emails = db.query(Email).filter(
            Email.sender == user["email"],
            Email.status == "queued"
        ).all()
        
        return {"emails": [email.to_dict() for email in emails]}
        
    except Exception as e:
        logger.error(f"Failed to fetch outbox: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch outbox")

@app.post("/api/emails/compose")
async def compose_email(
    to: str = Form(...),
    cc: str = Form(""),
    bcc: str = Form(""),
    subject: str = Form(...),
    body: str = Form(...),
    encryption_mode: str = Form("AES"),
    attachments: List[UploadFile] = File(default=[]),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Compose and send encrypted email"""
    try:
        user = await get_current_user(credentials, db)
        user_obj = db.query(User).filter(User.email == user["email"]).first()
        
        # Get KM key if needed - with automatic session renewal  
        km_key = None
        km_key_id = None
        if encryption_mode in ["OTP", "AES", "PQC"] and user_obj:
            try:
                # Ensure valid KM session
                if not getattr(user_obj, 'km_session_id', None):
                    # Create new KM session if user doesn't have one
                    logger.info(f"Creating new KM session for {user_obj.email}")
                    km_session = await km_mock.authenticate(user_obj.email)
                    user_obj.km_session_id = km_session["session_id"]
                    db.commit()
                    
                # Get key from KM
                key_result = await km_mock.get_key(str(user_obj.km_session_id))
                km_key = key_result["key_data"]
                km_key_id = key_result["key_id"]
                logger.info(f"Successfully retrieved KM key for {user_obj.email} encryption: {encryption_mode}")
                
            except Exception as km_e:
                logger.warning(f"KM session invalid for {user_obj.email}, renewing session: {km_e}")
                try:
                    # Try to renew session
                    km_session = await km_mock.authenticate(user_obj.email)
                    user_obj.km_session_id = km_session["session_id"]
                    db.commit()
                    
                    # Retry key retrieval with new session
                    key_result = await km_mock.get_key(str(user_obj.km_session_id))
                    km_key = key_result["key_data"]
                    km_key_id = key_result["key_id"]
                    logger.info(f"Successfully renewed KM session and retrieved key for {user_obj.email}")
                    
                except Exception as renewal_e:
                    logger.error(f"Failed to renew KM session for {user_obj.email}, falling back to NONE encryption: {renewal_e}")
                    encryption_mode = "NONE"  # Fallback only after renewal attempt fails
        
        # Validate email content - prevent completely empty emails
        if not subject.strip() and not body.strip():
            raise HTTPException(status_code=400, detail="Email must have either a subject or body content")
        
        # Process attachments
        attachment_data = []
        for attachment in attachments:
            if attachment.filename:
                content = await attachment.read()
                attachment_data.append({
                    "filename": attachment.filename,
                    "content": content,
                    "content_type": attachment.content_type
                })
        
        # Encrypt email - SECURITY FIX: Pass the real key_id from KM
        logger.info(f"[COMPOSE DEBUG] Starting encryption - mode: {encryption_mode}, km_key_id: {km_key_id}")
        encrypted_email = await crypto_manager.encrypt_email(
            {
                "to": to,
                "cc": cc,
                "bcc": bcc,
                "subject": subject,
                "body": body,
                "attachments": attachment_data
            },
            encryption_mode,
            km_key,
            km_key_id=km_key_id
        )
        logger.info(f"[COMPOSE DEBUG] Encryption result keys: {list(encrypted_email.keys())}")
        if encryption_mode == "PQC":
            pqc_fields = {k: bool(v) for k, v in encrypted_email.items() if 'pqc' in k.lower()}
            logger.info(f"[COMPOSE DEBUG] PQC fields present: {pqc_fields}")
        
        # Send email
        success = await email_service.send_email(user_obj, encrypted_email)
        
        if success:
            # Save to sent folder
            await email_service.save_to_sent(user_obj, encrypted_email)
            return {"status": "sent", "message": "Email sent successfully"}
        else:
            # Save to outbox for retry
            email_record = Email(
                sender=str(user_obj.email) if user_obj and user_obj.email else "",
                recipients=to,
                subject=subject,
                body=encrypted_email.get("body", body),  # Use original body if encrypted doesn't have it
                encryption_mode=encryption_mode,
                status="queued"
            )
            db.add(email_record)
            db.commit()
            return {"status": "queued", "message": "Email queued for retry"}
            
    except Exception as e:
        import traceback
        error_details = f"{str(e)} | {traceback.format_exc()}"
        logger.error(f"Failed to compose email: {error_details}")
        raise HTTPException(status_code=500, detail="Failed to send email")

@app.post("/api/emails/retry-outbox")
async def retry_outbox(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Retry sending queued emails"""
    try:
        user = await get_current_user(credentials, db)
        user_obj = db.query(User).filter(User.email == user["email"]).first()
        
        # Get queued emails
        queued_emails = db.query(Email).filter(
            Email.sender == user["email"],
            Email.status == "queued"
        ).all()
        
        sent_count = 0
        for email in queued_emails:
            try:
                success = await email_service.send_email(user_obj, email.to_dict())
                if success:
                    setattr(email, 'status', 'sent')
                    sent_count += 1
            except Exception as e:
                logger.error(f"Failed to retry email {email.id}: {str(e)}")
        
        db.commit()
        return {"sent_count": sent_count, "total_queued": len(queued_emails)}
        
    except Exception as e:
        logger.error(f"Failed to retry outbox: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retry outbox")

# Settings endpoints
@app.get("/api/settings")
async def get_settings(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Get user settings"""
    try:
        user = await get_current_user(credentials, db)
        user_obj = db.query(User).filter(User.email == user["email"]).first()
        
        default_encryption = "AES"
        km_endpoint = "http://localhost:8001"
        auto_decrypt = True
        
        if user_obj:
            if hasattr(user_obj, 'default_encryption_mode') and user_obj.default_encryption_mode:
                default_encryption = str(user_obj.default_encryption_mode)
            if hasattr(user_obj, 'km_endpoint') and user_obj.km_endpoint:
                km_endpoint = str(user_obj.km_endpoint)
            if hasattr(user_obj, 'auto_decrypt') and user_obj.auto_decrypt is not None:
                auto_decrypt = bool(user_obj.auto_decrypt)
        
        return {
            "default_encryption": default_encryption,
            "km_endpoint": km_endpoint,
            "auto_decrypt": auto_decrypt
        }
        
    except Exception as e:
        logger.error(f"Failed to get settings: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get settings")

@app.post("/api/settings")
async def update_settings(
    default_encryption: str = Form(...),
    km_endpoint: str = Form(...),
    auto_decrypt: bool = Form(...),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Update user settings"""
    try:
        user = await get_current_user(credentials, db)
        user_obj = db.query(User).filter(User.email == user["email"]).first()
        
        setattr(user_obj, 'default_encryption_mode', default_encryption)
        setattr(user_obj, 'km_endpoint', km_endpoint)
        setattr(user_obj, 'auto_decrypt', auto_decrypt)
        
        db.commit()
        return {"message": "Settings updated successfully"}
        
    except Exception as e:
        logger.error(f"Failed to update settings: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update settings")

# Key Vault endpoints for offline resilience
@app.get("/api/keys/batch")
async def get_key_batch(
    batch_size: int = 15,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Get a batch of keys for client-side vault"""
    try:
        user = await get_current_user(credentials, db)
        user_obj = db.query(User).filter(User.email == user["email"]).first()
        
        if not user_obj or not user_obj.km_session_id:
            raise HTTPException(status_code=400, detail="No active KM session")
        
        # Get key batch from KM
        key_batch = await km_mock.get_key_batch(user_obj.km_session_id, batch_size)
        
        return {
            "key_batch": key_batch,
            "user_email": user["email"],
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get key batch: {e}")
        raise HTTPException(status_code=500, detail="Failed to get key batch")

@app.post("/api/keys/release")
async def release_keys(
    used_key_ids: List[str],
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Release used keys back to KM"""
    try:
        user = await get_current_user(credentials, db)
        user_obj = db.query(User).filter(User.email == user["email"]).first()
        
        if not user_obj or not user_obj.km_session_id:
            raise HTTPException(status_code=400, detail="No active KM session")
        
        # Release keys to KM
        result = await km_mock.release_keys(user_obj.km_session_id, used_key_ids)
        
        return {
            "result": result,
            "user_email": user["email"],
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to release keys: {e}")
        raise HTTPException(status_code=500, detail="Failed to release keys")

# Local Authentication Endpoints (fallback when OAuth is not available)
@app.post("/api/auth/local/login")
async def local_login(
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Local login with email and password"""
    try:
        # Find user
        user = db.query(User).filter(User.email == email).first()
        if not user:
            logger.warning(f"Login attempt for non-existent user: {email}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Verify password
        if not user.password_hash:
            logger.warning(f"User {email} has no password hash set")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Use proper password verification
        if not crypto_manager.verify_password(password, user.password_hash):
            logger.warning(f"Invalid password attempt for user: {email}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Authenticate with KM
        km_session = await km_mock.authenticate(email)
        user.km_session_id = km_session["session_id"]
        user.last_login = datetime.utcnow()
        db.commit()
        
        # Generate JWT token
        import uuid
        jti = str(uuid.uuid4())
        token = crypto_manager.generate_jwt_token(email, jti=jti)
        
        logger.info(f"User {email} logged in successfully")
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "email": user.email,
                "oauth_provider": None,
                "km_session_id": user.km_session_id
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Local login failed: {e}")
        raise HTTPException(status_code=401, detail="Authentication failed")

@app.post("/api/auth/local/register")
async def local_register(
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Create a new user account"""
    try:
        # Validate password strength
        if len(password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters long")
        
        # Check if user already exists
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            logger.warning(f"Registration attempt for existing user: {email}")
            raise HTTPException(status_code=400, detail="User already exists")
        
        # Create new user with hashed password
        user = User(
            email=email,
            password_hash=crypto_manager.hash_password(password),
            created_at=datetime.utcnow(),
            oauth_provider=None,  # Local account
            default_encryption_mode="AES",
            auto_decrypt=True
        )
        db.add(user)
        db.commit()
        
        logger.info(f"New user registered: {email}")
        return {"message": "User created successfully", "email": email}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User registration failed: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    km_status = await km_mock.health_check()
    return {
        "status": "healthy",
        "km_status": km_status,
        "version": "1.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="localhost", port=8000, reload=True)