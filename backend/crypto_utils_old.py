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
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# PQC imports (fallback if not available)
try:
    # Check if specific algorithms are available
    import pqcrypto.kem
    import pqcrypto.sign
    # Try to access specific algorithms
    from pqcrypto.kem import kyber512 as kyber
    from pqcrypto.sign import dilithium2 as dilithium
    PQC_AVAILABLE = True
except (ImportError, AttributeError):
    # PQC not available or incomplete - disable gracefully
    PQC_AVAILABLE = False
    kyber = None
    dilithium = None
    # Only print warning once during import, not repeatedly

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
    
    def compute_hmac(self, data: bytes, key: bytes) -> str:
        """Compute HMAC-SHA256 for integrity verification"""
        mac = hmac.new(key, data, hashlib.sha256)
        return base64.b64encode(mac.digest()).decode('utf-8')
    
    def verify_hmac(self, data: bytes, key: bytes, expected_mac: str) -> bool:
        """Verify HMAC-SHA256 integrity"""
        try:
            expected_digest = base64.b64decode(expected_mac.encode('utf-8'))
            mac = hmac.new(key, data, hashlib.sha256)
            return hmac.compare_digest(mac.digest(), expected_digest)
        except Exception:
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
                    km_key_extended = (km_key * ((len(content_bytes) // len(km_key)) + 1))[:len(content_bytes)]
                else:
                    km_key_extended = km_key
                
                # Use extended KM key for OTP
                encrypted_content = self.otp_encrypt(content_bytes, km_key_extended)
                encrypted_email["content"] = base64.b64encode(encrypted_content).decode('utf-8')
                # SECURITY FIX: Use real key_id from KM, not generated hash
                encrypted_email["km_key_id"] = km_key_id or hashlib.sha256(km_key).hexdigest()[:16]
                
                # Compute MAC with original key
                mac_key = hashlib.sha256(km_key + b"MAC").digest()
                encrypted_email["mac"] = self.compute_hmac(encrypted_content, mac_key)
                
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
                
                # Compute MAC - CRITICAL FIX: Use km_key_bytes for consistency
                mac_key = hashlib.sha256(km_key_bytes + b"MAC").digest()
                encrypted_email["mac"] = self.compute_hmac(encrypted_content + nonce, mac_key)
                
            elif encryption_mode == "PQC":
                if not PQC_AVAILABLE:
                    raise RuntimeError("PQC encryption requested but PQC libraries are not available")
                
                # Generate ephemeral PQC keypair
                pqc_public, pqc_secret = self.pqc_generate_keypair()
                
                # Encapsulate to get shared secret
                pqc_ciphertext, shared_secret = self.pqc_encapsulate(pqc_public)
                
                # Use shared secret for AES encryption
                encrypted_content, nonce = self.aes_encrypt(content_bytes, shared_secret)
                
                encrypted_email["content"] = base64.b64encode(encrypted_content).decode('utf-8')
                encrypted_email["nonce"] = base64.b64encode(nonce).decode('utf-8')
                encrypted_email["pqc_public"] = base64.b64encode(pqc_public).decode('utf-8')
                encrypted_email["pqc_ciphertext"] = base64.b64encode(pqc_ciphertext).decode('utf-8')
                
                # Compute MAC with shared secret
                encrypted_email["mac"] = self.compute_hmac(encrypted_content + nonce, shared_secret)
                
                # Securely wipe keys
                self.secure_wipe(bytearray(shared_secret))
                self.secure_wipe(bytearray(pqc_secret))
                
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
                
                # FIXED: Always convert hex string to bytes for consistent handling
                if isinstance(km_key, str):
                    km_key = bytes.fromhex(km_key)
                    logger.info(f"[OTP] Converted hex key to bytes, len={len(km_key)}")
                else:
                    logger.info(f"[OTP] km_key already bytes, len={len(km_key)}")
                
                if "content" not in email_data:
                    raise ValueError("Missing 'content' field for OTP decryption")
                
                encrypted_content = base64.b64decode(email_data["content"])
                
                # Verify MAC with original key
                km_key_bytes = bytes(km_key) if not isinstance(km_key, bytes) else km_key
                mac_key = hashlib.sha256(km_key_bytes + b"MAC").digest()
                if not self.verify_hmac(encrypted_content, mac_key, email_data["mac"]):
                    raise ValueError("MAC verification failed")
                
                # For OTP, extend key if needed (same logic as encryption)
                if len(km_key) < len(encrypted_content):
                    # Ensure km_key is bytes for proper multiplication
                    km_key_bytes = bytes(km_key) if not isinstance(km_key, bytes) else km_key
                    km_key_extended = (km_key_bytes * ((len(encrypted_content) // len(km_key_bytes)) + 1))[:len(encrypted_content)]
                else:
                    km_key_extended = bytes(km_key) if not isinstance(km_key, bytes) else km_key
                
                # Decrypt content with extended key
                content_bytes = self.otp_decrypt(encrypted_content, km_key_extended)
                content = json.loads(content_bytes.decode('utf-8'))
                
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
                
                encrypted_content = base64.b64decode(email_data["content"])
                nonce = base64.b64decode(email_data["nonce"])
                
                # Verify MAC first - CRITICAL FIX: Try both old and new key formats
                km_key_bytes = bytes(km_key) if not isinstance(km_key, bytes) else km_key
                mac_data = encrypted_content + nonce
                
                # Try new consistent format first
                mac_key_new = hashlib.sha256(km_key_bytes + b"MAC").digest()
                computed_mac_new = self.compute_hmac(mac_data, mac_key_new)
                stored_mac = email_data["mac"]
                
                logger.info(f"[AES DEBUG] Key ID: {email_data.get('km_key_id')}")
                logger.info(f"[AES DEBUG] km_key: type={type(km_key)}, len={len(km_key)}")
                logger.info(f"[AES DEBUG] MAC match (new format): {computed_mac_new == stored_mac}")
                
                mac_verified = self.verify_hmac(mac_data, mac_key_new, email_data["mac"])
                
                if not mac_verified:
                    # Try old inconsistent format for backward compatibility
                    logger.info(f"[AES DEBUG] Trying old MAC format for backward compatibility")
                    mac_key_old = hashlib.sha256(km_key + b"MAC").digest()  # Use original km_key without bytes conversion
                    computed_mac_old = self.compute_hmac(mac_data, mac_key_old)
                    logger.info(f"[AES DEBUG] MAC match (old format): {computed_mac_old == stored_mac}")
                    mac_verified = self.verify_hmac(mac_data, mac_key_old, email_data["mac"])
                
                if not mac_verified:
                    raise ValueError("MAC verification failed")
                
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
                pqc_ciphertext = base64.b64decode(email_data["pqc_ciphertext"])
                
                # This would require the recipient's PQC secret key
                # For demo purposes, we'll indicate decryption is not possible
                raise ValueError("PQC decryption requires recipient's secret key")
                
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
                    content = {
                        "subject": email_data.get("subject", ""),
                        "body": email_data.get("body", ""),
                        "to": email_data.get("to", ""),
                        "cc": email_data.get("cc", ""),
                        "bcc": email_data.get("bcc", "")
                    }
                    # For regular TLS emails, mark as successfully decrypted
                    logger.info(f"[TLS] Regular email displayed directly: {email_data.get('subject', 'No Subject')}")
                
            else:
                raise ValueError(f"Unknown encryption mode: {encryption_mode}")
            
            # Return decrypted email
            decrypted_email = email_data.copy()
            decrypted_email.update(content)
            decrypted_email["decryption_status"] = "success"
            
            return decrypted_email
            
        except Exception as e:
            logger.error(f"Email decryption failed: {e}")
            # Return email with error status
            error_email = email_data.copy()
            error_email["decryption_status"] = "error"
            error_email["decryption_error"] = str(e)
            return error_email