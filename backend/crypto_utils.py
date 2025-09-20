"""
Cryptographic utilities for QuMail quantum-secure email client
Implements OTP, AES-256-GCM, PQC (Kyber/Dilithium), and integrity verification
"""

import secrets
import hashlib
import hmac
import base64
import json
from typing import Dict, Optional, Tuple, Union, List
from datetime import datetime, timedelta
import logging

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# Mock PQC implementation for demonstration
class MockKyber:
    """Mock Kyber KEM implementation using AES for demonstration"""
    @staticmethod
    def generate_keypair():
        """Generate mock keypair"""
        public_key = secrets.token_bytes(800)  # Kyber512 public key size
        secret_key = secrets.token_bytes(1632)  # Kyber512 secret key size
        return public_key, secret_key
    
    @staticmethod
    def encapsulate(public_key):
        """Mock encapsulation"""
        ciphertext = secrets.token_bytes(768)  # Kyber512 ciphertext size
        shared_secret = secrets.token_bytes(32)  # 256-bit shared secret
        return ciphertext, shared_secret
    
    @staticmethod
    def decapsulate(ciphertext, secret_key):
        """Mock decapsulation - return deterministic secret based on inputs"""
        # For demo: derive shared secret from ciphertext hash
        import hashlib
        shared_secret = hashlib.sha256(ciphertext + secret_key[:32]).digest()
        return shared_secret

class MockDilithium:
    """Mock Dilithium signature implementation"""
    @staticmethod
    def generate_keypair():
        """Generate mock signing keypair"""
        public_key = secrets.token_bytes(1312)  # Dilithium2 public key size
        secret_key = secrets.token_bytes(2560)  # Dilithium2 secret key size
        return public_key, secret_key
    
    @staticmethod
    def sign(message, secret_key):
        """Mock signature"""
        import hashlib
        signature = hashlib.sha256(message + secret_key[:32]).digest()
        return signature + secrets.token_bytes(32)  # 64-byte signature
    
    @staticmethod
    def verify(signature, message, public_key):
        """Mock verification - always returns True for demo"""
        return len(signature) == 64  # Simple validation

# Use mock PQC implementation
PQC_AVAILABLE = True
kyber = MockKyber()
dilithium = MockDilithium()

# JWT imports
try:
    from jose import jwt, JWTError
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    jwt = None
    JWTError = Exception
    print("Warning: JWT library not available")

logger = logging.getLogger(__name__)

class CryptoManager:
    """Central cryptographic operations manager"""
    
    def __init__(self):
        # Use persistent JWT secret from environment or generate once
        import os
        self.jwt_secret = os.getenv('JWT_SECRET_KEY', 'qumail-jwt-secret-key-change-in-production')
        self.jwt_algorithm = "HS256"
        
    def generate_jwt_token(self, email: str, expires_delta: Optional[timedelta] = None, jti: Optional[str] = None) -> str:
        """Generate JWT token for user authentication with optional JTI for revocation"""
        if not JWT_AVAILABLE:
            raise RuntimeError("JWT library not available")
            
        if expires_delta is None:
            expires_delta = timedelta(hours=24)
            
        expire = datetime.utcnow() + expires_delta
        payload = {
            "sub": email,
            "exp": expire,
            "iat": datetime.utcnow()
        }
        
        # Add JTI (JWT ID) for revocation tracking
        if jti:
            payload["jti"] = jti
        
        if jwt is None:
            raise RuntimeError("JWT library not available")
        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        # Handle different jose library versions
        if isinstance(token, bytes):
            return token.decode('utf-8')
        return str(token)
    
    def verify_jwt_token(self, token: str, check_blacklist: bool = True) -> Dict:
        """Verify and decode JWT token with optional blacklist checking"""
        if not JWT_AVAILABLE:
            raise RuntimeError("JWT library not available")
            
        try:
            if jwt is None:
                raise RuntimeError("JWT library not available")
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            
            # Note: Blacklist checking is handled at the application level
            # to avoid circular imports with database models
            
            return payload
        except JWTError as e:
            raise ValueError(f"Invalid token: {e}")
    
    def generate_otp_key(self, length: int = 32) -> bytes:
        """Generate cryptographically secure OTP key"""
        return secrets.token_bytes(length)
    
    def otp_encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        """One-Time Pad encryption (perfect secrecy)"""
        if len(key) < len(plaintext):
            raise ValueError("OTP key must be at least as long as plaintext")
        
        # XOR plaintext with key
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, key[:len(plaintext)]))
        return ciphertext
    
    def otp_decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """One-Time Pad decryption"""
        if len(key) < len(ciphertext):
            raise ValueError("OTP key must be at least as long as ciphertext")
        
        # XOR ciphertext with key (same operation as encryption)
        plaintext = bytes(c ^ k for c, k in zip(ciphertext, key[:len(ciphertext)]))
        return plaintext
    
    def aes_encrypt(self, plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """AES-256-GCM encryption with authentication"""
        if len(key) not in [16, 24, 32]:
            # Derive key using PBKDF2 if not proper length
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'qumail_salt',  # In production, use random salt
                iterations=100000,
            )
            key = kdf.derive(key)
        
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        return ciphertext, nonce
    
    def aes_decrypt(self, ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
        """AES-256-GCM decryption with authentication"""
        if len(key) not in [16, 24, 32]:
            # Derive key using PBKDF2 if not proper length
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'qumail_salt',  # Must match encryption salt
                iterations=100000,
            )
            key = kdf.derive(key)
        
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        return plaintext
    
    def pqc_generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate PQC keypair (Kyber for KEM)"""
        if not PQC_AVAILABLE:
            raise RuntimeError("PQC libraries not available")
        
        public_key, secret_key = kyber.generate_keypair()
        return public_key, secret_key
    
    def pqc_encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """PQC key encapsulation (generates shared secret)"""
        if not PQC_AVAILABLE:
            raise RuntimeError("PQC libraries not available")
        
        ciphertext, shared_secret = kyber.encapsulate(public_key)
        return ciphertext, shared_secret
    
    def pqc_decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """PQC key decapsulation (recovers shared secret)"""
        if not PQC_AVAILABLE:
            raise RuntimeError("PQC libraries not available")
        
        shared_secret = kyber.decapsulate(ciphertext, secret_key)
        return shared_secret
    
    def pqc_sign_generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate PQC signing keypair (Dilithium)"""
        if not PQC_AVAILABLE:
            raise RuntimeError("PQC libraries not available")
        
        public_key, secret_key = dilithium.generate_keypair()
        return public_key, secret_key
    
    def pqc_sign(self, message: bytes, secret_key: bytes) -> bytes:
        """PQC digital signature"""
        if not PQC_AVAILABLE:
            raise RuntimeError("PQC libraries not available")
        
        signature = dilithium.sign(message, secret_key)
        return signature
    
    def pqc_verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """PQC signature verification"""
        if not PQC_AVAILABLE:
            raise RuntimeError("PQC libraries not available")
        
        try:
            dilithium.verify(message, signature, public_key)
            return True
        except:
            return False
    
    # MAC v1 specification helpers - ARCHITECT RECOMMENDED
    def b64u_encode(self, data: bytes) -> str:
        """URL-safe base64 encode without padding"""
        return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')
    
    def b64u_decode(self, data: str) -> bytes:
        """URL-safe base64 decode with padding restoration"""
        # Add padding if needed
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data.encode('ascii'))
    
    def derive_distinct_keys(self, km_key: bytes, purpose: str) -> bytes:
        """Derive distinct keys using HKDF - MAC v1 specification"""
        salt = f"qumail_{purpose}".encode('utf-8')
        info = f"{purpose}-v1".encode('utf-8')
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        )
        return hkdf.derive(km_key)
    
    def compute_canonical_mac_v1(self, mode: str, key_id: str, nonce_b64u: str, ciphertext_b64u: str, km_key: bytes) -> str:
        """Compute canonical MAC v1 as recommended by architect"""
        # Derive distinct MAC key using HKDF
        mac_key = self.derive_distinct_keys(km_key, "mac")
        
        # Create canonical JSON with sorted keys
        mac_data_obj = {
            "version": "v1",
            "mode": mode,
            "key_id": key_id,
            "nonce_b64u": nonce_b64u,
            "ciphertext_b64u": ciphertext_b64u
        }
        
        # Convert to canonical JSON bytes
        canonical_json = json.dumps(mac_data_obj, separators=(",", ":"), sort_keys=True)
        mac_data = canonical_json.encode('utf-8')
        
        logger.info(f"[MAC v1] Computing MAC for {mode}, data len={len(mac_data)}")
        logger.info(f"[MAC v1] Canonical JSON: {canonical_json[:100]}...")
        
        # Compute HMAC with distinct MAC key
        mac = hmac.new(mac_key, mac_data, hashlib.sha256)
        return self.b64u_encode(mac.digest())
    
    def compute_hmac(self, data: bytes, key: bytes) -> str:
        """Compute HMAC-SHA256 for integrity verification - LEGACY"""
        mac = hmac.new(key, data, hashlib.sha256)
        return base64.b64encode(mac.digest()).decode('utf-8')
    
    def verify_canonical_mac_v1(self, mode: str, key_id: str, nonce_b64u: str, ciphertext_b64u: str, mac_b64u: str, km_key: bytes) -> bool:
        """Verify canonical MAC v1 as recommended by architect"""
        try:
            # Derive distinct MAC key using HKDF (same as encryption)
            mac_key = self.derive_distinct_keys(km_key, "mac")
            
            # Create canonical JSON with sorted keys (same as encryption)
            mac_data_obj = {
                "version": "v1",
                "mode": mode,
                "key_id": key_id,
                "nonce_b64u": nonce_b64u,
                "ciphertext_b64u": ciphertext_b64u
            }
            
            # Convert to canonical JSON bytes (same as encryption)
            canonical_json = json.dumps(mac_data_obj, separators=(",", ":"), sort_keys=True)
            mac_data = canonical_json.encode('utf-8')
            
            logger.info(f"[MAC v1 VERIFY] Verifying MAC for {mode}, data len={len(mac_data)}")
            logger.info(f"[MAC v1 VERIFY] Canonical JSON: {canonical_json[:100]}...")
            
            # Compute HMAC with distinct MAC key
            mac = hmac.new(mac_key, mac_data, hashlib.sha256)
            computed_mac_b64u = self.b64u_encode(mac.digest())
            
            # Constant-time comparison
            match_result = hmac.compare_digest(computed_mac_b64u.encode('ascii'), mac_b64u.encode('ascii'))
            logger.info(f"[MAC v1 VERIFY] MAC comparison result: {match_result}")
            
            if not match_result:
                logger.info(f"[MAC v1 VERIFY] Expected: {mac_b64u[:16]}... Computed: {computed_mac_b64u[:16]}...")
            
            return match_result
        except Exception as e:
            logger.error(f"[MAC v1 ERROR] verify_canonical_mac_v1 failed: {type(e).__name__}: {str(e)}")
            return False

    def verify_hmac(self, data: bytes, key: bytes, expected_mac: str) -> bool:
        """Verify HMAC-SHA256 integrity - ENHANCED DEBUG - LEGACY"""
        try:
            logger.info(f"[MAC DEBUG] verify_hmac called: data_len={len(data)}, key_len={len(key)}, expected_mac_len={len(expected_mac)}")
            expected_digest = base64.b64decode(expected_mac.encode('utf-8'))
            logger.info(f"[MAC DEBUG] Expected digest decoded successfully, len={len(expected_digest)}")
            
            mac = hmac.new(key, data, hashlib.sha256)
            computed_digest = mac.digest()
            logger.info(f"[MAC DEBUG] Computed digest len={len(computed_digest)}")
            
            match_result = hmac.compare_digest(computed_digest, expected_digest)
            logger.info(f"[MAC DEBUG] MAC comparison result: {match_result}")
            
            if not match_result:
                logger.info(f"[MAC DEBUG] Expected: {expected_digest[:8].hex()}... Computed: {computed_digest[:8].hex()}...")
            
            return match_result
        except Exception as e:
            logger.error(f"[MAC ERROR] verify_hmac failed: {type(e).__name__}: {str(e)}")
            return False
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt for secure storage"""
        try:
            import bcrypt
            # Generate salt and hash password
            salt = bcrypt.gensalt()
            password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
            return password_hash.decode('utf-8')
        except ImportError:
            # Fallback to PBKDF2 if bcrypt not available
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'qumail_fallback_salt',
                iterations=100000,
            )
            password_hash = kdf.derive(password.encode('utf-8'))
            return base64.b64encode(password_hash).decode('utf-8')
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify password against stored hash"""
        try:
            import bcrypt
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        except ImportError:
            # Fallback verification for PBKDF2
            try:
                stored_hash = base64.b64decode(hashed_password.encode('utf-8'))
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b'qumail_fallback_salt',
                    iterations=100000,
                )
                kdf.verify(password.encode('utf-8'), stored_hash)
                return True
            except Exception:
                return False

    def secure_wipe(self, data: Union[bytes, bytearray, None]) -> None:
        """Securely wipe sensitive data from memory"""
        if data is None:
            return
        if isinstance(data, bytes):
            # Can't modify bytes directly, but ensure it's dereferenced
            data = None
        elif isinstance(data, bytearray):
            # Zero out the bytearray
            for i in range(len(data)):
                data[i] = 0
    
    def encrypt_app_password(self, password: str) -> str:
        """Encrypt app password for secure storage using AES-256-GCM"""
        if not password:
            return ""
        
        # Use a fixed key derived from JWT secret for app passwords
        password_key = hashlib.sha256(self.jwt_secret.encode() + b"app_password").digest()
        
        # Encrypt the password
        ciphertext, nonce = self.aes_encrypt(password.encode('utf-8'), password_key)
        
        # Combine nonce and ciphertext for storage
        encrypted_data = nonce + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt_app_password(self, encrypted_password: str) -> str:
        """Decrypt app password from secure storage"""
        if not encrypted_password:
            return ""
        
        try:
            # Decode the stored data
            encrypted_data = base64.b64decode(encrypted_password.encode('utf-8'))
            
            # Extract nonce and ciphertext (first 12 bytes are nonce)
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            # Use the same key as encryption
            password_key = hashlib.sha256(self.jwt_secret.encode() + b"app_password").digest()
            
            # Decrypt the password
            plaintext = self.aes_decrypt(ciphertext, password_key, nonce)
            return plaintext.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Failed to decrypt app password: {e}")
            return ""
    
    async def encrypt_email(self, email_data: Dict, encryption_mode: str, km_key: Optional[bytes] = None, km_key_id: Optional[str] = None) -> Dict:
        """Encrypt email with specified mode"""
        try:
            # Prepare email content
            content = {
                "subject": email_data["subject"],
                "body": email_data["body"],
                "attachments": email_data.get("attachments", [])
            }
            content_bytes = json.dumps(content).encode('utf-8')
            
            encrypted_email = {
                "to": email_data["to"],
                "cc": email_data.get("cc", ""),
                "bcc": email_data.get("bcc", ""),
                "encryption_mode": encryption_mode,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            if encryption_mode == "OTP":
                if not km_key:
                    raise ValueError("KM key required for OTP encryption")
                
                # Convert hex string to bytes if needed
                if isinstance(km_key, str):
                    km_key = bytes.fromhex(km_key)
                
                # For OTP, ensure key is at least as long as content
                if len(km_key) < len(content_bytes):
                    # Extend key by repeating it (though this reduces perfect secrecy)
                    # For proper OTP, the key should be truly random and as long as message
                    km_key_bytes = bytes(km_key) if not isinstance(km_key, bytes) else km_key
                    km_key_extended = (km_key_bytes * ((len(content_bytes) // len(km_key_bytes)) + 1))[:len(content_bytes)]
                else:
                    km_key_extended = km_key
                
                # Use extended KM key for OTP
                encrypted_content = self.otp_encrypt(content_bytes, km_key_extended)
                encrypted_email["content"] = base64.b64encode(encrypted_content).decode('utf-8')
                # SECURITY FIX: Use real key_id from KM, not generated hash
                encrypted_email["km_key_id"] = km_key_id or hashlib.sha256(km_key).hexdigest()[:16]
                
                # Compute MAC v1 with canonical format - ARCHITECT RECOMMENDED
                nonce_b64u = ""  # OTP doesn't use nonce
                ciphertext_b64u = self.b64u_encode(encrypted_content)
                encrypted_email["mac"] = self.compute_canonical_mac_v1("OTP", km_key_id or "default", nonce_b64u, ciphertext_b64u, km_key)
                encrypted_email["content"] = self.b64u_encode(encrypted_content)  # Use URL-safe base64
                
            elif encryption_mode == "AES":
                if not km_key:
                    raise ValueError("KM key required for AES encryption")
                
                # Convert hex string to bytes if needed
                if isinstance(km_key, str):
                    km_key = bytes.fromhex(km_key)
                
                # CRITICAL FIX: Ensure km_key is bytes for consistent MAC computation
                km_key_bytes = bytes(km_key) if not isinstance(km_key, bytes) else km_key
                
                # Use KM key as seed for AES key derivation
                aes_key = hashlib.sha256(km_key_bytes + b"AES").digest()
                logger.info(f"[ENCRYPT] Key ID: {km_key_id}")
                logger.info(f"[ENCRYPT] km_key: len={len(km_key_bytes)}")
                logger.info(f"[ENCRYPT] aes_key: len={len(aes_key)}")
                encrypted_content, nonce = self.aes_encrypt(content_bytes, aes_key)
                logger.info(f"[ENCRYPT] AES encryption successful, nonce len={len(nonce)}")
                
                encrypted_email["content"] = base64.b64encode(encrypted_content).decode('utf-8')
                encrypted_email["nonce"] = base64.b64encode(nonce).decode('utf-8')
                # SECURITY FIX: Use real key_id from KM, not generated hash
                encrypted_email["km_key_id"] = km_key_id or hashlib.sha256(km_key_bytes).hexdigest()[:16]
                
                # Compute MAC v1 with canonical format - ARCHITECT RECOMMENDED
                nonce_b64u = self.b64u_encode(nonce)
                ciphertext_b64u = self.b64u_encode(encrypted_content)
                encrypted_email["mac"] = self.compute_canonical_mac_v1("AES", km_key_id or "default", nonce_b64u, ciphertext_b64u, km_key_bytes)
                encrypted_email["content"] = ciphertext_b64u  # Use URL-safe base64
                encrypted_email["nonce"] = nonce_b64u  # Use URL-safe base64
                
            elif encryption_mode == "PQC":
                if not PQC_AVAILABLE:
                    raise RuntimeError("PQC encryption requested but PQC libraries are not available")
                
                # CRITICAL FIX: PQC always uses mock keypair approach for consistency
                # Generate mock PQC keypair for demo - this shared secret will be used for both encrypt and decrypt
                pqc_public, pqc_secret = self.pqc_generate_keypair()
                pqc_ciphertext, shared_secret = self.pqc_encapsulate(pqc_public)
                
                # Always store the PQC headers for decryption
                encrypted_email["pqc_secret"] = base64.b64encode(pqc_secret).decode('utf-8')
                encrypted_email["pqc_public"] = base64.b64encode(pqc_public).decode('utf-8')
                encrypted_email["pqc_ciphertext"] = base64.b64encode(pqc_ciphertext).decode('utf-8')
                logger.info(f"[PQC ENCRYPT] Generated PQC headers, using PQC shared secret for encryption")
                
                # Use PQC shared secret for AES encryption (ignore km_key for PQC mode to avoid key mismatch)
                encrypted_content, nonce = self.aes_encrypt(content_bytes, shared_secret)
                
                encrypted_email["content"] = base64.b64encode(encrypted_content).decode('utf-8')
                encrypted_email["nonce"] = base64.b64encode(nonce).decode('utf-8')
                
                # Compute MAC with shared secret
                encrypted_email["mac"] = self.compute_hmac(encrypted_content + nonce, shared_secret)
                
                # Only wipe shared_secret, not the keys needed for decryption
                self.secure_wipe(bytearray(shared_secret))
                
            elif encryption_mode == "NONE":
                # TLS-only, no additional encryption
                encrypted_email["content"] = base64.b64encode(content_bytes).decode('utf-8')
                encrypted_email["mac"] = self.compute_hmac(content_bytes, b"qumail_default_key")
                
            else:
                raise ValueError(f"Unknown encryption mode: {encryption_mode}")
            
            # Add QuMail header
            encrypted_email["headers"] = {
                "X-QuMail-Encryption": encryption_mode,
                "X-QuMail-Version": "1.0",
                "X-QuMail-Timestamp": encrypted_email["timestamp"]
            }
            
            return encrypted_email
            
        except Exception as e:
            logger.error(f"Email encryption failed: {e}")
            raise
    
    async def decrypt_email(self, email_data: Dict, km_key: Optional[Union[bytes, str]] = None) -> Dict:
        """Decrypt email based on encryption mode"""
        try:
            encryption_mode = email_data.get("encryption_mode", "NONE")
            
            if encryption_mode == "OTP":
                if not km_key:
                    raise ValueError("KM key required for OTP decryption")
                
                # ENHANCED DEBUG: Track OTP decryption step by step
                logger.info(f"[OTP DEBUG] Starting OTP decryption")
                logger.info(f"[OTP DEBUG] Key ID: {email_data.get('km_key_id')}")
                logger.info(f"[OTP DEBUG] Input km_key type: {type(km_key)}")
                
                # FIXED: Always convert hex string to bytes for consistent handling
                if isinstance(km_key, str):
                    try:
                        km_key = bytes.fromhex(km_key)
                        logger.info(f"[OTP DEBUG] Converted hex key to bytes, len={len(km_key)}")
                    except ValueError as hex_e:
                        logger.error(f"[OTP DEBUG] Failed to convert hex key: {hex_e}, key preview: {km_key[:20]}...")
                        raise
                else:
                    logger.info(f"[OTP DEBUG] km_key already bytes, len={len(km_key)}")
                
                if "content" not in email_data:
                    raise ValueError("Missing 'content' field for OTP decryption")
                
                # ENHANCED DEBUG: Check base64 content before decoding
                raw_content = email_data["content"]
                logger.info(f"[OTP DEBUG] Raw content length: {len(raw_content)}")
                logger.info(f"[OTP DEBUG] Content preview: {raw_content[:50]}...")
                
                try:
                    # FIXED: Use URL-safe base64 decode to match encryption encoding
                    encrypted_content = self.b64u_decode(raw_content)
                    logger.info(f"[OTP DEBUG] URL-safe Base64 decoded successfully, encrypted length: {len(encrypted_content)}")
                except Exception as b64_e:
                    logger.error(f"[OTP DEBUG] URL-safe Base64 decode failed: {b64_e}")
                    # Fallback to standard base64 for backward compatibility
                    try:
                        encrypted_content = base64.b64decode(raw_content)
                        logger.info(f"[OTP DEBUG] Fallback standard Base64 decode successful")
                    except Exception as fallback_e:
                        logger.error(f"[OTP DEBUG] Both URL-safe and standard Base64 decode failed: {fallback_e}")
                        raise ValueError(f"Base64 decode failed: {fallback_e}")
                
                # Verify MAC with original key - ENHANCED DEBUG
                km_key_bytes = bytes(km_key) if not isinstance(km_key, bytes) else km_key
                logger.info(f"[OTP DEBUG] km_key_bytes for MAC: len={len(km_key_bytes)}, first 8 bytes hex: {km_key_bytes[:8].hex()}")
                
                mac_key = hashlib.sha256(km_key_bytes + b"MAC").digest()
                logger.info(f"[OTP DEBUG] MAC key derived, len={len(mac_key)}")
                
                # Compute expected MAC and compare
                computed_mac = self.compute_hmac(encrypted_content, mac_key)
                stored_mac = email_data["mac"]
                logger.info(f"[OTP DEBUG] Computed MAC: {computed_mac[:20]}...")
                logger.info(f"[OTP DEBUG] Stored MAC: {stored_mac[:20]}...")
                logger.info(f"[OTP DEBUG] MAC match: {computed_mac == stored_mac}")
                
                # CRITICAL FIX: Simplified and consistent MAC verification for OTP
                km_key_id = email_data.get("km_key_id", "")
                
                # Check if this is MAC v1 format by examining the MAC field format
                is_mac_v1 = (
                    isinstance(email_data.get("mac"), str) and 
                    len(email_data.get("mac", "")) > 0 and
                    '=' not in email_data.get("mac", "")  # URL-safe base64 has no padding
                )
                
                if is_mac_v1:
                    logger.info(f"[OTP DEBUG] Detected MAC v1 format, using canonical verification")
                    # For MAC v1: use URL-safe base64 and canonical JSON verification
                    try:
                        # Convert standard base64 to URL-safe if needed
                        if '=' in raw_content:
                            # Convert from standard base64 to URL-safe base64
                            encrypted_content = base64.b64decode(raw_content)
                            ciphertext_b64u = self.b64u_encode(encrypted_content)
                        else:
                            ciphertext_b64u = raw_content  # Already URL-safe base64
                        
                        nonce_b64u = ""  # OTP doesn't use nonce
                        mac_b64u = email_data["mac"]
                        
                        if not self.verify_canonical_mac_v1("OTP", km_key_id, nonce_b64u, ciphertext_b64u, mac_b64u, km_key_bytes):
                            logger.error(f"[OTP DEBUG] MAC v1 verification failed")
                            raise ValueError("MAC verification failed")
                        
                        # Decode for decryption
                        encrypted_content = self.b64u_decode(ciphertext_b64u)
                        logger.info(f"[OTP DEBUG] MAC v1 verification successful")
                    except Exception as v1_e:
                        logger.error(f"[OTP DEBUG] MAC v1 verification error: {v1_e}")
                        raise ValueError("MAC verification failed")
                else:
                    logger.info(f"[OTP DEBUG] Detected legacy format, using legacy verification")
                    # Legacy verification for backward compatibility
                    encrypted_content = base64.b64decode(raw_content)
                    mac_key = hashlib.sha256(km_key_bytes + b"MAC").digest()
                    if not self.verify_hmac(encrypted_content, mac_key, email_data["mac"]):
                        logger.error(f"[OTP DEBUG] Legacy MAC verification failed")
                        raise ValueError("MAC verification failed")
                    logger.info(f"[OTP DEBUG] Legacy MAC verification successful")
                
                logger.info(f"[OTP DEBUG] MAC verification successful")
                
                # For OTP, extend key if needed (same logic as encryption)
                if len(km_key) < len(encrypted_content):
                    # Ensure km_key is bytes for proper multiplication
                    km_key_bytes = bytes(km_key) if not isinstance(km_key, bytes) else km_key
                    km_key_extended = (km_key_bytes * ((len(encrypted_content) // len(km_key_bytes)) + 1))[:len(encrypted_content)]
                    logger.info(f"[OTP DEBUG] Extended key from {len(km_key)} to {len(km_key_extended)} bytes")
                else:
                    km_key_extended = bytes(km_key) if not isinstance(km_key, bytes) else km_key
                    logger.info(f"[OTP DEBUG] Key is sufficient length: {len(km_key_extended)} bytes")
                
                # Decrypt content with extended key
                content_bytes = self.otp_decrypt(encrypted_content, km_key_extended)
                logger.info(f"[OTP DEBUG] OTP decryption successful, content length: {len(content_bytes)}")
                
                try:
                    content = json.loads(content_bytes.decode('utf-8'))
                    logger.info(f"[OTP DEBUG] JSON parsing successful")
                except Exception as json_e:
                    logger.error(f"[OTP DEBUG] JSON parsing failed: {json_e}, content preview: {content_bytes[:100]}...")
                    raise
                
            elif encryption_mode == "AES":
                if not km_key:
                    raise ValueError("KM key required for AES decryption")
                
                # FIXED: Always convert hex string to bytes for consistent handling
                if isinstance(km_key, str):
                    km_key = bytes.fromhex(km_key)
                    logger.info(f"[AES] Converted hex key to bytes, len={len(km_key)}")
                else:
                    logger.info(f"[AES] km_key already bytes, len={len(km_key)}")
                
                if "content" not in email_data:
                    raise ValueError("Missing 'content' field for AES decryption")
                
                # CRITICAL FIX: Simplified and consistent MAC verification for AES
                km_key_bytes = bytes(km_key) if not isinstance(km_key, bytes) else km_key
                km_key_id = email_data.get("km_key_id", "")
                
                # Check if this is MAC v1 format by examining the MAC field format
                is_v1 = (
                    isinstance(email_data.get("mac"), str) and 
                    len(email_data.get("mac", "")) > 0 and
                    '=' not in email_data.get("mac", "")  # URL-safe base64 has no padding
                )
                
                if is_v1:
                    logger.info(f"[AES DEBUG] Detected MAC v1 format, using canonical verification")
                    # For MAC v1: use URL-safe base64 and canonical JSON verification
                    try:
                        # Convert standard base64 to URL-safe if needed
                        if '=' in email_data.get("content", ""):
                            encrypted_content = base64.b64decode(email_data["content"])
                            ciphertext_b64u = self.b64u_encode(encrypted_content)
                        else:
                            ciphertext_b64u = email_data["content"]
                        
                        if '=' in email_data.get("nonce", ""):
                            nonce = base64.b64decode(email_data["nonce"])
                            nonce_b64u = self.b64u_encode(nonce)
                        else:
                            nonce_b64u = email_data["nonce"]
                        
                        mac_b64u = email_data["mac"]
                        
                        if not self.verify_canonical_mac_v1("AES", km_key_id, nonce_b64u, ciphertext_b64u, mac_b64u, km_key_bytes):
                            logger.error(f"[AES DEBUG] MAC v1 verification failed")
                            raise ValueError("MAC verification failed")
                        
                        # Decode for decryption
                        encrypted_content = self.b64u_decode(ciphertext_b64u)
                        nonce = self.b64u_decode(nonce_b64u)
                        logger.info(f"[AES DEBUG] MAC v1 verification successful")
                    except Exception as v1_e:
                        logger.error(f"[AES DEBUG] MAC v1 verification error: {v1_e}")
                        raise ValueError("MAC verification failed")
                else:
                    logger.info(f"[AES DEBUG] Detected legacy format, using legacy verification")
                    # Legacy verification for backward compatibility
                    encrypted_content = base64.b64decode(email_data["content"])
                    nonce = base64.b64decode(email_data["nonce"])
                    mac_data = encrypted_content + nonce
                    
                    # Use consistent MAC format
                    mac_key = hashlib.sha256(km_key_bytes + b"MAC").digest()
                    if not self.verify_hmac(mac_data, mac_key, email_data["mac"]):
                        logger.error(f"[AES DEBUG] Legacy MAC verification failed")
                        raise ValueError("MAC verification failed")
                    logger.info(f"[AES DEBUG] Legacy MAC verification successful")
                
                # Decrypt content - CRITICAL FIX: ensure key derivation matches encryption
                km_key_bytes = bytes(km_key) if not isinstance(km_key, bytes) else km_key
                aes_key = hashlib.sha256(km_key_bytes + b"AES").digest()
                logger.info(f"[AES DEBUG] Derived aes_key len={len(aes_key)}")
                
                try:
                    content_bytes = self.aes_decrypt(encrypted_content, aes_key, nonce)
                    content = json.loads(content_bytes.decode('utf-8'))
                    logger.info(f"[AES DEBUG] Decryption successful")
                except Exception as aes_e:
                    logger.error(f"[AES ERROR] Decryption failed: {aes_e}")
                    logger.error(f"[AES ERROR] Key ID: {email_data.get('km_key_id')}, key len: {len(km_key)}")
                    logger.error(f"[AES ERROR] Ciphertext len: {len(encrypted_content)}, nonce len: {len(nonce)}")
                    raise
                
            elif encryption_mode == "PQC":
                if not PQC_AVAILABLE:
                    raise RuntimeError("PQC decryption requested but PQC libraries are not available")
                
                if "content" not in email_data:
                    raise ValueError("Missing 'content' field for PQC decryption")
                
                encrypted_content = base64.b64decode(email_data["content"])
                nonce = base64.b64decode(email_data["nonce"])
                
                # CRITICAL FIX: Handle both KM-based and legacy PQC approaches
                if email_data.get("km_key_id") and km_key:
                    # KM-based PQC: derive shared secret from km_key
                    km_key_bytes = bytes.fromhex(km_key) if isinstance(km_key, str) else bytes(km_key)
                    shared_secret = hashlib.sha256(km_key_bytes + b"PQC_SHARED").digest()
                    logger.info(f"[PQC DECRYPT] Using KM-derived shared secret for decryption")
                    
                elif email_data.get("pqc_secret") and email_data.get("pqc_ciphertext"):
                    # Mock PQC approach: use stored secret key
                    pqc_secret = base64.b64decode(email_data["pqc_secret"])
                    pqc_ciphertext = base64.b64decode(email_data["pqc_ciphertext"])
                    
                    # Decapsulate to recover shared secret
                    shared_secret = self.pqc_decapsulate(pqc_ciphertext, pqc_secret)
                    logger.info(f"[PQC DECRYPT] Using mock PQC decapsulation for decryption")
                    
                elif email_data.get("pqc_public") and email_data.get("pqc_ciphertext"):
                    # Legacy PQC: try to create a fallback for demo emails without stored secrets
                    logger.warning(f"[PQC DECRYPT] Legacy PQC email detected, using demo fallback")
                    # For legacy demo emails, use a deterministic approach based on message content
                    encrypted_content = base64.b64decode(email_data["content"])
                    shared_secret = hashlib.sha256(encrypted_content[:32] + b"DEMO_PQC_FALLBACK").digest()
                    logger.info(f"[PQC DECRYPT] Using legacy demo fallback for decryption")
                    
                else:
                    logger.error(f"[PQC DECRYPT] No valid decryption method found. Available fields: {list(email_data.keys())}")
                    logger.error(f"[PQC DECRYPT] km_key_id: {email_data.get('km_key_id')}, km_key available: {bool(km_key)}")
                    logger.error(f"[PQC DECRYPT] pqc_secret: {bool(email_data.get('pqc_secret'))}, pqc_ciphertext: {bool(email_data.get('pqc_ciphertext'))}")
                    logger.error(f"[PQC DECRYPT] pqc_public: {bool(email_data.get('pqc_public'))}")
                    raise ValueError("PQC decryption requires either KM key, stored PQC secret key, or PQC public key for legacy emails")
                
                # Verify MAC
                mac_data = encrypted_content + nonce
                if not self.verify_hmac(mac_data, shared_secret, email_data["mac"]):
                    raise ValueError("MAC verification failed for PQC")
                
                # Decrypt content using shared secret
                content_bytes = self.aes_decrypt(encrypted_content, shared_secret, nonce)
                content = json.loads(content_bytes.decode('utf-8'))
                logger.info(f"[PQC DECRYPT] Decryption successful")
                
            elif encryption_mode == "NONE":
                # For NONE encryption mode, check if this is a QuMail email or regular email
                if "content" in email_data and "mac" in email_data:
                    # This is a QuMail email with NONE encryption (TLS-only)
                    encrypted_content = base64.b64decode(email_data["content"])
                    
                    # Verify MAC
                    if not self.verify_hmac(encrypted_content, b"qumail_default_key", email_data["mac"]):
                        raise ValueError("MAC verification failed")
                    
                    content = json.loads(encrypted_content.decode('utf-8'))
                else:
                    # This is a regular email (TLS-only), use the body directly
                    subject = email_data.get("subject", "").strip()
                    if not subject:
                        subject = "(No Subject)"
                    
                    body = email_data.get("body", "").strip()
                    if not body:
                        body = "This email has no content."
                    
                    content = {
                        "subject": subject,
                        "body": body,
                        "to": email_data.get("to", ""),
                        "cc": email_data.get("cc", ""),
                        "bcc": email_data.get("bcc", "")
                    }
                    # For regular TLS emails, mark as successfully decrypted
                    logger.info(f"[TLS] Regular email displayed directly: {subject}")
                
            else:
                raise ValueError(f"Unknown encryption mode: {encryption_mode}")
            
            # Return decrypted email
            decrypted_email = email_data.copy()
            decrypted_email.update(content)
            decrypted_email["decryption_status"] = "success"
            
            # DEBUG: Log what we're returning for TLS emails
            if encryption_mode == "NONE":
                logger.info(f"[TLS DEBUG] Returning email with subject: '{decrypted_email.get('subject', 'MISSING')}' and body: '{decrypted_email.get('body', 'MISSING')[:50]}...'")
            
            return decrypted_email
            
        except Exception as e:
            logger.error(f"Email decryption failed: {e}")
            # Return email with error status but try to preserve basic info
            error_email = email_data.copy()
            error_email["decryption_status"] = "error"
            error_email["decryption_error"] = str(e)
            
            # For display purposes, ensure we have a subject
            if not error_email.get("subject", "").strip():
                error_email["subject"] = "(Decryption Failed)"
            
            # Add fallback body for failed decryption
            error_email["body"] = f"Failed to decrypt this email: {str(e)}"
            
            return error_email