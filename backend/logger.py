"""
Security-focused logging for QuMail
Logs only metadata, never sensitive content or cryptographic keys
"""

import logging
import sys
import json
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path

class QuMailFormatter(logging.Formatter):
    """Custom formatter for QuMail security logs"""
    
    def format(self, record):
        # Create log entry with metadata only
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
            "component": getattr(record, 'component', 'unknown')
        }
        
        # Add request context if available
        if hasattr(record, 'user_email'):
            log_entry["user_email"] = record.user_email
        if hasattr(record, 'request_id'):
            log_entry["request_id"] = record.request_id
        if hasattr(record, 'encryption_mode'):
            log_entry["encryption_mode"] = record.encryption_mode
        if hasattr(record, 'km_key_id'):
            log_entry["km_key_id"] = record.km_key_id
        
        # Add error details if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry, ensure_ascii=False)

class SecurityLogger:
    """Security-focused logger that never logs sensitive data"""
    
    def __init__(self, name: str = "qumail"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Remove existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(QuMailFormatter())
        self.logger.addHandler(console_handler)
        
        # File handler for security events
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        file_handler = logging.FileHandler(log_dir / "qumail_security.log")
        file_handler.setFormatter(QuMailFormatter())
        self.logger.addHandler(file_handler)
        
        self.logger.propagate = False
    
    def info(self, message: str, extra: Dict[str, Any] = None):
        """Log info message"""
        self.logger.info(message, extra=extra or {})
    
    def error(self, message: str, extra: Dict[str, Any] = None):
        """Log error message"""
        self.logger.error(message, extra=extra or {})
    
    def warning(self, message: str, extra: Dict[str, Any] = None):
        """Log warning message"""
        self.logger.warning(message, extra=extra or {})
    
    def debug(self, message: str, extra: Dict[str, Any] = None):
        """Log debug message"""
        self.logger.debug(message, extra=extra or {})
    
    def hash_sensitive_data(self, data: str) -> str:
        """Create SHA256 hash of sensitive data for correlation"""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()[:16]
    
    def log_authentication(self, user_email: str, success: bool, method: str = "email"):
        """Log authentication attempt"""
        self.info(
            f"Authentication {'successful' if success else 'failed'}: {method}",
            extra={
                "component": "auth",
                "user_email": user_email,
                "auth_method": method,
                "success": success
            }
        )
    
    def log_email_operation(self, operation: str, user_email: str, 
                          recipient: str = None, encryption_mode: str = None,
                          success: bool = True, error: str = None):
        """Log email operation (send, receive, decrypt)"""
        extra = {
            "component": "email",
            "user_email": user_email,
            "operation": operation,
            "success": success
        }
        
        if recipient:
            extra["recipient"] = recipient
        if encryption_mode:
            extra["encryption_mode"] = encryption_mode
        if error:
            extra["error"] = error
        
        message = f"Email {operation} {'completed' if success else 'failed'}"
        
        if success:
            self.info(message, extra=extra)
        else:
            self.error(message, extra=extra)
    
    def log_km_operation(self, operation: str, user_email: str, 
                        session_id: str = None, key_id: str = None,
                        success: bool = True, error: str = None):
        """Log Key Manager operation"""
        extra = {
            "component": "km",
            "user_email": user_email,
            "operation": operation,
            "success": success
        }
        
        if session_id:
            extra["km_session_id"] = session_id
        if key_id:
            extra["km_key_id"] = key_id
        if error:
            extra["error"] = error
        
        message = f"KM {operation} {'completed' if success else 'failed'}"
        
        if success:
            self.info(message, extra=extra)
        else:
            self.error(message, extra=extra)
    
    def log_crypto_operation(self, operation: str, encryption_mode: str,
                           user_email: str = None, success: bool = True,
                           error: str = None):
        """Log cryptographic operation"""
        extra = {
            "component": "crypto",
            "operation": operation,
            "encryption_mode": encryption_mode,
            "success": success
        }
        
        if user_email:
            extra["user_email"] = user_email
        if error:
            extra["error"] = error
        
        message = f"Crypto {operation} ({encryption_mode}) {'completed' if success else 'failed'}"
        
        if success:
            self.info(message, extra=extra)
        else:
            self.error(message, extra=extra)
    
    def log_security_event(self, event_type: str, details: Dict[str, Any],
                          severity: str = "INFO"):
        """Log security event with metadata only"""
        # Ensure no sensitive data is logged
        safe_details = {}
        for key, value in details.items():
            if key.lower() in ['password', 'key', 'token', 'secret', 'private']:
                # Hash sensitive fields
                safe_details[f"{key}_hash"] = self.hash_sensitive_data(str(value))
            else:
                safe_details[key] = value
        
        safe_details["component"] = "security"
        safe_details["event_type"] = event_type
        
        level = getattr(logging, severity.upper(), logging.INFO)
        if level == logging.INFO:
            self.info(f"Security event: {event_type}", extra=safe_details)
        else:
            self.error(f"Security event: {event_type}", extra=safe_details)
    
    def log_error(self, message: str, error: Exception = None, 
                 user_email: str = None, component: str = "general"):
        """Log error with context"""
        extra = {
            "component": component,
            "error_type": type(error).__name__ if error else "Unknown"
        }
        
        if user_email:
            extra["user_email"] = user_email
        if error:
            extra["error_details"] = str(error)
        
        self.error(message, extra=extra)
    
    def log_performance(self, operation: str, duration_ms: float,
                       user_email: str = None, component: str = "performance"):
        """Log performance metrics"""
        extra = {
            "component": component,
            "operation": operation,
            "duration_ms": duration_ms
        }
        
        if user_email:
            extra["user_email"] = user_email
        
        self.info(f"Performance: {operation} took {duration_ms:.2f}ms", extra=extra)

# Global security logger instance
_security_logger = None

def setup_logger(name: str = "qumail") -> SecurityLogger:
    """Get or create the global security logger"""
    global _security_logger
    if _security_logger is None:
        _security_logger = SecurityLogger(name)
    return _security_logger

def get_logger() -> SecurityLogger:
    """Get the global security logger"""
    global _security_logger
    if _security_logger is None:
        _security_logger = setup_logger()
    return _security_logger