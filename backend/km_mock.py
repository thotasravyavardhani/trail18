"""
Key Manager (KM) Mock Server - ETSI GS QKD 014 compliant simulation
Simulates quantum key distribution for QuMail encryption
"""

import asyncio
import secrets
import hashlib
import json
import time
from typing import Dict, Optional, List, Tuple, Union
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager
import threading
import logging

from logger import setup_logger

logger = setup_logger()

class EphemeralKey:
    """Ephemeral key with automatic expiry and secure wiping"""
    
    def __init__(self, key_id: str, key_data: bytes, expiry_seconds: int = 3600):
        self.key_id = key_id
        self.key_data = bytearray(key_data)  # Mutable for secure wiping
        self.created_at = datetime.utcnow()
        self.expires_at = self.created_at + timedelta(seconds=expiry_seconds)
        self.consumed = False
        self.session_id = None
    
    def is_expired(self) -> bool:
        """Check if key has expired"""
        return datetime.utcnow() > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if key is valid (not expired and not consumed)"""
        return not self.is_expired() and not self.consumed
    
    def consume(self) -> bytes:
        """Consume key (mark as used and return copy)"""
        if not self.is_valid():
            raise ValueError("Key is expired or already consumed")
        
        self.consumed = True
        return bytes(self.key_data)
    
    def secure_wipe(self):
        """Securely wipe key data from memory"""
        if self.key_data:
            # Zero out the key data
            for i in range(len(self.key_data)):
                self.key_data[i] = 0
            self.key_data = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary (without key data)"""
        return {
            "key_id": self.key_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "consumed": self.consumed,
            "session_id": self.session_id,
            "expired": self.is_expired(),
            "valid": self.is_valid()
        }

class KMSession:
    """Key Manager session for tracking user authentication and key usage"""
    
    def __init__(self, session_id: str, user_email: str):
        self.session_id = session_id
        self.user_email = user_email
        self.created_at = datetime.utcnow()
        self.last_activity = self.created_at
        self.active = True
        self.keys_requested = 0
        self.keys_consumed = 0
        self.current_keys: Dict[str, EphemeralKey] = {}
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.utcnow()
    
    def is_expired(self, session_timeout: int = 3600) -> bool:
        """Check if session has expired"""
        return (datetime.utcnow() - self.last_activity).total_seconds() > session_timeout
    
    def add_key(self, key: EphemeralKey):
        """Add key to session"""
        key.session_id = self.session_id
        self.current_keys[key.key_id] = key
        self.keys_requested += 1
        self.update_activity()
    
    def get_key(self, key_id: str) -> Optional[EphemeralKey]:
        """Get key from session"""
        self.update_activity()
        return self.current_keys.get(key_id)
    
    def consume_key(self, key_id: str) -> Optional[bytes]:
        """Consume a key from session"""
        key = self.get_key(key_id)
        if key and key.is_valid():
            key_data = key.consume()
            self.keys_consumed += 1
            return key_data
        return None
    
    def cleanup_expired_keys(self):
        """Remove and wipe expired keys"""
        expired_keys = []
        for key_id, key in self.current_keys.items():
            if key.is_expired():
                key.secure_wipe()
                expired_keys.append(key_id)
        
        for key_id in expired_keys:
            del self.current_keys[key_id]
    
    def to_dict(self) -> Dict:
        """Convert session to dictionary"""
        return {
            "session_id": self.session_id,
            "user_email": self.user_email,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "active": self.active,
            "keys_requested": self.keys_requested,
            "keys_consumed": self.keys_consumed,
            "current_keys": len(self.current_keys),
            "expired": self.is_expired()
        }

class KeyManagerMock:
    """ETSI GS QKD 014 compliant Key Manager simulation"""
    
    def __init__(self, port: int = 8001):
        self.port = port
        self.sessions: Dict[str, KMSession] = {}
        self.key_storage: Dict[str, EphemeralKey] = {}
        self.app = None
        self.server = None
        self.cleanup_task = None
        self.running = False
        
        # KM configuration
        self.default_key_size = 32  # 256 bits
        self.max_key_size = 64     # 512 bits
        self.key_expiry_seconds = 7200  # 2 hours 
        self.session_timeout = 86400    # 24 hours for demo mode
        self.max_keys_per_session = 1000
    
    async def start(self):
        """Start the KM mock server"""
        try:
            # Create FastAPI app for KM endpoints
            @asynccontextmanager
            async def lifespan(app: FastAPI):
                # Startup
                self.running = True
                self.cleanup_task = asyncio.create_task(self._cleanup_loop())
                logger.info("KM Mock server started")
                yield
                # Shutdown
                self.running = False
                if self.cleanup_task:
                    self.cleanup_task.cancel()
                logger.info("KM Mock server stopped")
            
            self.app = FastAPI(title="QuMail KM Mock", lifespan=lifespan)
            self._setup_routes()
            
            logger.info(f"KM Mock server starting on port {self.port}")
            
        except Exception as e:
            logger.error(f"Failed to start KM Mock server: {e}")
            raise
    
    async def stop(self):
        """Stop the KM mock server"""
        self.running = False
        if self.cleanup_task:
            self.cleanup_task.cancel()
        
        # Securely wipe all keys
        for session in self.sessions.values():
            for key in session.current_keys.values():
                key.secure_wipe()
        
        for key in self.key_storage.values():
            key.secure_wipe()
        
        self.sessions.clear()
        self.key_storage.clear()
        logger.info("KM Mock server stopped and keys wiped")
    
    def _setup_routes(self):
        """Setup ETSI GS QKD 014 compliant API routes"""
        
        @self.app.post("/api/v1/authenticate")
        async def authenticate(user_email: str):
            """Authenticate user and create KM session"""
            try:
                session_id = secrets.token_urlsafe(32)
                session = KMSession(session_id, user_email)
                self.sessions[session_id] = session
                
                logger.info(f"KM session created for {user_email}: {session_id}")
                
                return {
                    "session_id": session_id,
                    "user_email": user_email,
                    "expires_in": self.session_timeout,
                    "max_key_size": self.max_key_size,
                    "status": "authenticated"
                }
                
            except Exception as e:
                logger.error(f"KM authentication failed for {user_email}: {e}")
                raise HTTPException(status_code=500, detail="Authentication failed")
        
        @self.app.get("/api/v1/getKey")
        async def get_key(session_id: str, key_size: int = None):
            """Get ephemeral key - ETSI QKD 014 compliant"""
            try:
                # Validate session
                session = self.sessions.get(session_id)
                if not session or not session.active or session.is_expired(self.session_timeout):
                    raise HTTPException(status_code=401, detail="Invalid or expired session")
                
                # Update session activity
                session.update_activity()
                
                # Validate key size
                if key_size is None:
                    key_size = self.default_key_size
                
                if key_size > self.max_key_size or key_size < 16:
                    raise HTTPException(status_code=400, detail="Invalid key size")
                
                # Check session limits
                if len(session.current_keys) >= self.max_keys_per_session:
                    raise HTTPException(status_code=429, detail="Key limit exceeded")
                
                # Generate ephemeral key
                key_id = secrets.token_urlsafe(16)
                key_data = secrets.token_bytes(key_size)
                
                ephemeral_key = EphemeralKey(
                    key_id=key_id,
                    key_data=key_data,
                    expiry_seconds=self.key_expiry_seconds
                )
                
                # Store key in session
                session.add_key(ephemeral_key)
                self.key_storage[key_id] = ephemeral_key
                
                logger.info(f"Key generated for session {session_id}: {key_id}")
                
                return {
                    "key_id": key_id,
                    "key_data": key_data.hex(),  # In production, use secure transport
                    "size": key_size,
                    "expires_at": ephemeral_key.expires_at.isoformat(),
                    "session_id": session_id
                }
                
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Key generation failed for session {session_id}: {e}")
                raise HTTPException(status_code=500, detail="Key generation failed")
        
        @self.app.post("/api/v1/consumeKey")
        async def consume_key(session_id: str, key_id: str):
            """Consume (mark as used) an ephemeral key"""
            try:
                session = self.sessions.get(session_id)
                if not session or not session.active:
                    raise HTTPException(status_code=401, detail="Invalid session")
                
                key_data = session.consume_key(key_id)
                if not key_data:
                    raise HTTPException(status_code=404, detail="Key not found or expired")
                
                logger.info(f"Key consumed: {key_id}")
                
                return {
                    "key_id": key_id,
                    "status": "consumed",
                    "consumed_at": datetime.utcnow().isoformat()
                }
                
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Key consumption failed: {e}")
                raise HTTPException(status_code=500, detail="Key consumption failed")
        
        @self.app.get("/api/v1/session/{session_id}")
        async def get_session_info(session_id: str):
            """Get session information"""
            session = self.sessions.get(session_id)
            if not session:
                raise HTTPException(status_code=404, detail="Session not found")
            
            return session.to_dict()
        
        @self.app.delete("/api/v1/session/{session_id}")
        async def close_session(session_id: str):
            """Close KM session and wipe keys"""
            session = self.sessions.get(session_id)
            if not session:
                raise HTTPException(status_code=404, detail="Session not found")
            
            # Wipe all keys in session
            for key in session.current_keys.values():
                key.secure_wipe()
                if key.key_id in self.key_storage:
                    del self.key_storage[key.key_id]
            
            session.active = False
            del self.sessions[session_id]
            
            logger.info(f"KM session closed: {session_id}")
            
            return {"status": "closed", "session_id": session_id}
        
        @self.app.get("/api/v1/health")
        async def health_check():
            """Health check endpoint"""
            return {
                "status": "healthy",
                "active_sessions": len([s for s in self.sessions.values() if s.active]),
                "total_keys": len(self.key_storage),
                "uptime_seconds": (datetime.utcnow() - self.start_time).seconds if hasattr(self, 'start_time') else 0
            }
    
    async def _cleanup_loop(self):
        """Background cleanup task for expired keys and sessions"""
        self.start_time = datetime.utcnow()
        
        while self.running:
            try:
                # Cleanup expired keys
                expired_keys = []
                for key_id, key in self.key_storage.items():
                    if key.is_expired():
                        key.secure_wipe()
                        expired_keys.append(key_id)
                
                for key_id in expired_keys:
                    del self.key_storage[key_id]
                
                # Cleanup expired sessions
                expired_sessions = []
                for session_id, session in self.sessions.items():
                    session.cleanup_expired_keys()
                    if session.is_expired():
                        for key in session.current_keys.values():
                            key.secure_wipe()
                        expired_sessions.append(session_id)
                
                for session_id in expired_sessions:
                    del self.sessions[session_id]
                
                if expired_keys or expired_sessions:
                    logger.info(f"Cleanup: removed {len(expired_keys)} keys, {len(expired_sessions)} sessions")
                
                # Sleep for 60 seconds before next cleanup
                await asyncio.sleep(60)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup task error: {e}")
                await asyncio.sleep(60)
    
    # Public API methods for QuMail backend
    
    async def authenticate(self, user_email: str) -> Dict:
        """Authenticate user and create session"""
        session_id = secrets.token_urlsafe(32)
        session = KMSession(session_id, user_email)
        self.sessions[session_id] = session
        
        return {
            "session_id": session_id,
            "user_email": user_email,
            "status": "authenticated"
        }
    
    async def get_key(self, session_id: str, key_size: int = 32) -> Dict:
        """Get ephemeral key for encryption - FIXED: Return hex string consistently"""
        session = self.sessions.get(session_id)
        if not session or not session.active or session.is_expired():
            raise ValueError("Invalid or expired session")
        
        key_id = secrets.token_urlsafe(16)
        key_data = secrets.token_bytes(key_size)
        
        ephemeral_key = EphemeralKey(key_id, key_data, self.key_expiry_seconds)
        session.add_key(ephemeral_key)
        self.key_storage[key_id] = ephemeral_key
        
        return {
            "key_id": key_id,
            "key_data": key_data.hex()  # FIXED: Return hex string consistently
        }
    
    async def get_key_by_id(self, key_id: str) -> Dict:
        """Get key by key_id - FIXED: Return hex string to match get_key method"""
        ephemeral_key = self.key_storage.get(key_id)
        if not ephemeral_key or ephemeral_key.is_expired():
            raise ValueError(f"Key {key_id} not found or expired")
            
        return {
            "key_id": key_id,
            "key_data": bytes(ephemeral_key.key_data).hex()  # FIXED: Return hex like get_key
        }
    
    async def get_key_batch(self, session_id: str, batch_size: int = 15) -> Dict:
        """Get a batch of keys for client-side vault"""
        import base64
        
        session = self.sessions.get(session_id)
        if not session or not session.active or session.is_expired():
            raise ValueError("Invalid or expired session")
        
        keys = []
        for _ in range(batch_size):
            key_id = secrets.token_urlsafe(16)
            key_data = secrets.token_bytes(32)
            
            ephemeral_key = EphemeralKey(key_id, key_data, self.key_expiry_seconds)
            session.add_key(ephemeral_key)
            self.key_storage[key_id] = ephemeral_key
            
            keys.append({
                "key_id": key_id,
                "key": base64.b64encode(key_data).decode(),
                "expires_at": ephemeral_key.expires_at.isoformat()
            })
        
        logger.info(f"Generated key batch for session {session_id}: {batch_size} keys")
        return {
            "keys": keys,
            "batch_size": batch_size,
            "session_id": session_id
        }
    
    async def release_keys(self, session_id: str, used_key_ids: List[str]) -> Dict:
        """Mark keys as used and release them"""
        session = self.sessions.get(session_id)
        if not session or not session.active:
            raise ValueError("Invalid session")
        
        released_count = 0
        for key_id in used_key_ids:
            if key_id in self.key_storage:
                ephemeral_key = self.key_storage[key_id]
                if not ephemeral_key.consumed:
                    ephemeral_key.consumed = True
                    released_count += 1
                    
                # Remove old keys to free memory
                ephemeral_key.secure_wipe()
                del self.key_storage[key_id]
        
        logger.info(f"Released {released_count} keys for session {session_id}")
        return {
            "released_count": released_count,
            "session_id": session_id
        }
    
    async def health_check(self) -> Dict:
        """Check KM health status"""
        return {
            "status": "healthy" if self.running else "stopped",
            "active_sessions": len([s for s in self.sessions.values() if s.active]),
            "total_keys": len(self.key_storage)
        }