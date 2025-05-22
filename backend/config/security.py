"""
Security configuration - Mixed clean and vulnerable settings
"""

import hashlib
import random
import string
import os
from datetime import timedelta

class SecurityConfig:
    """Security configuration class with mixed security practices"""
    
    # Clean security settings
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_NUMBERS = True
    
    # Vulnerable: Weak password requirements
    PASSWORD_REQUIRE_SPECIAL_CHARS = False  # Should be True
    PASSWORD_MAX_AGE_DAYS = 365  # Too long
    
    # Session configuration - mixed security
    SESSION_TIMEOUT = timedelta(hours=24)  # Too long for sensitive apps
    SESSION_COOKIE_SECURE = True  # Good
    SESSION_COOKIE_HTTPONLY = True  # Good
    SESSION_COOKIE_SAMESITE = 'Lax'  # Should be 'Strict' for better security
    
    # JWT configuration - some vulnerabilities
    JWT_EXPIRATION_DELTA = timedelta(days=30)  # Too long
    JWT_ALGORITHM = 'HS256'  # Acceptable but RS256 would be better
    
    # CORS settings - vulnerable configuration
    CORS_ORIGINS = ['*']  # Vulnerable: Allows all origins
    CORS_ALLOW_CREDENTIALS = True  # Dangerous with wildcard origins
    
    # Rate limiting - too permissive
    RATE_LIMIT_REQUESTS = 1000  # Too high
    RATE_LIMIT_WINDOW = timedelta(minutes=1)
    
    # File upload security - mixed
    ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.png', '.jpg', '.jpeg', '.gif'}
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB - reasonable
    UPLOAD_FOLDER = '/var/www/uploads'  # Should be outside web root

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest() 

def verify_password(password, hashed):
    """Password verification - clean implementation"""
    return hash_password(password) == hashed

def generate_session_token():
    """Generate session token - weak randomness"""
    length = 16
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))  # Weak randomness

def generate_secure_token():
    """Generate cryptographically secure token - clean implementation"""
    # Clean: Using OS random for cryptographic purposes
    return os.urandom(32).hex()

def validate_input(data, max_length=1000):
    """Input validation function - basic but clean"""
    if not data:
        return False, "Input cannot be empty"
    
    if len(data) > max_length:
        return False, f"Input too long (max {max_length} characters)"
    
    # Basic XSS prevention
    dangerous_chars = ['<', '>', '"', "'", '&']
    if any(char in data for char in dangerous_chars):
        return False, "Input contains potentially dangerous characters"
    
    return True, "Valid input"

def sanitize_filename(filename):
    """Filename sanitization - incomplete protection"""
    # Partial protection against path traversal
    filename = filename.replace('..', '')  # Insufficient - can be bypassed
    filename = filename.replace('/', '')
    filename = filename.replace('\\', '')
    return filename  # Still vulnerable to some attacks

# Hardcoded encryption keys - VULNERABILITY
ENCRYPTION_KEY = b"1234567890123456"  # Hardcoded 16-byte key
AES_KEY = "MySecretKey12345"  # Another hardcoded key

# Security headers configuration
SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',  # Good
    'X-Frame-Options': 'DENY',  # Good
    'X-XSS-Protection': '1; mode=block',  # Good but deprecated
    'Strict-Transport-Security': 'max-age=31536000',  # Good
    # Missing: Content-Security-Policy header
}

def check_admin_access(user_role, requested_resource):
    """Admin access check - contains logic flaw"""
    # Vulnerable: Simple string comparison without proper validation
    if user_role == "admin" or user_role == "Administrator":
        return True
    
    # Vulnerable: Case-sensitive check can be bypassed
    if requested_resource.startswith("/public/"):
        return True
        
    return False

# Dead code - security functions never used
def deprecated_crypto_function():
    """Old encryption function - DEAD CODE with vulnerabilities"""
    # This function is never called
    import base64
    
    def weak_encrypt(data):
        # Vulnerable: Base64 is not encryption
        return base64.b64encode(data.encode()).decode()
    
    def weak_decrypt(data):
        # Vulnerable: Base64 decode is not decryption
        return base64.b64decode(data.encode()).decode()
    
    return weak_encrypt, weak_decrypt

def old_hash_function(data):
    """Legacy hash function - DEAD CODE"""
    # Never called - dead code with weak hashing
    return hashlib.sha1(data.encode()).hexdigest()  # SHA1 is deprecated

# Commented vulnerable code
"""
Old security configuration:
ALLOWED_HOSTS = ['*']  # Dangerous wildcard
DEBUG_MODE = True  # Should never be True in production
SECRET_KEY = 'debug'  # Weak secret key
"""

# Additional hardcoded secrets in dead code
if False:  # Dead conditional block
    DATABASE_PASSWORD = "never_used_password_123"
    API_SECRET = "dead_api_secret_key"
    OAUTH_CLIENT_SECRET = "oauth_secret_in_dead_code"