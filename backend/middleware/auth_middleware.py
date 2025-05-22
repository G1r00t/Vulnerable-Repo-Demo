"""
Authentication Middleware
========================

JWT-based authentication middleware with various security vulnerabilities
for SAST demonstration purposes.
"""

import jwt
import json
import base64
import hashlib
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Callable
from functools import wraps


# =============================================================================
# SECURE JWT FUNCTIONS - Currently in use
# =============================================================================

class JWTAuthMiddleware:
    """
    Main JWT authentication middleware class.
    Contains both secure and vulnerable implementations.
    """
    
    def __init__(self, secret_key: str, algorithm: str = 'HS256'):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.token_expiry = timedelta(hours=1)
    
    def generate_token(self, user_id: int, username: str, role: str = 'user') -> str:
        """
        Generate secure JWT token.
        ACTIVELY USED - Secure implementation.
        """
        if not self.secret_key or len(self.secret_key) < 32:
            raise ValueError("JWT secret key must be at least 32 characters")
        
        payload = {
            'user_id': user_id,
            'username': username,
            'role': role,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + self.token_expiry,
            'iss': 'secure-app',
            'aud': 'api-users'
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify JWT token securely.
        ACTIVELY USED - Secure implementation with proper validation.
        """
        try:
            # Decode with signature verification and expiration check
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm],
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_iat': True,
                    'require_exp': True,
                    'require_iat': True
                }
            )
            
            # Additional validation
            if not payload.get('user_id') or not payload.get('username'):
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except Exception:
            return None


def authenticate_request(request_headers: Dict[str, str], secret_key: str) -> Optional[Dict[str, Any]]:
    """
    Authenticate HTTP request using JWT.
    ACTIVELY USED - Secure implementation.
    """
    auth_header = request_headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return None
    
    token = auth_header.split(' ', 1)[1]
    
    middleware = JWTAuthMiddleware(secret_key)
    return middleware.verify_token(token)


# =============================================================================
# VULNERABLE JWT FUNCTIONS - Security issues for SAST demonstration
# =============================================================================

def weak_jwt_generate(user_id: int, username: str) -> str:
    """
    Generate JWT with weak secret - WEAK CRYPTOGRAPHY!
    VULNERABILITY: Uses weak, predictable secret key.
    """
    # Weak secret key
    weak_secret = "jwt_secret"
    
    payload = {
        'user_id': user_id,
        'username': username,
        'role': 'admin',  # Dangerous default role
        'exp': time.time() + 86400  # 24 hours, no iat field
    }
    
    # Using weak secret
    return jwt.encode(payload, weak_secret, algorithm='HS256')


def insecure_jwt_decode(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode JWT without signature verification - AUTHENTICATION BYPASS!
    VULNERABILITY: Disabled signature verification allows token tampering.
    """
    try:
        # Decode without signature verification - MAJOR VULNERABILITY!
        payload = jwt.decode(
            token, 
            options={
                'verify_signature': False,  # DANGEROUS!
                'verify_exp': False  # No expiration check
            }
        )
        return payload
    except Exception:
        return None


def vulnerable_jwt_with_none_algorithm(user_data: Dict[str, Any]) -> str:
    """
    Generate JWT allowing 'none' algorithm - AUTHENTICATION BYPASS!
    VULNERABILITY: 'none' algorithm allows unsigned tokens.
    """
    payload = {
        'user_id': user_data.get('user_id'),
        'username': user_data.get('username'),
        'role': user_data.get('role', 'admin'),
        'exp': time.time() + 3600
    }
    
    # Allow 'none' algorithm - major security issue
    return jwt.encode(payload, '', algorithm='none')


def jwt_with_hardcoded_secret(user_id: int) -> str:
    """
    Generate JWT with hardcoded secret - HARDCODED SECRETS!
    VULNERABILITY: Hardcoded JWT signing secret.
    """
    # Hardcoded secret in source code
    HARDCODED_SECRET = "super_secret_jwt_key_2023"
    
    payload = {
        'user_id': user_id,
        'admin': True,  # All users get admin access
        'exp': time.time() + 86400
    }
    
    return jwt.encode(payload, HARDCODED_SECRET, algorithm='HS256')


def weak_jwt_validation(token: str) -> bool:
    """
    Weak JWT validation - INSUFFICIENT VALIDATION!
    VULNERABILITY: Inadequate token validation allows bypasses.
    """
    if not token:
        return False
    
    # Only check if token looks like JWT format
    parts = token.split('.')
    if len(parts) != 3:
        return False
    
    # No signature verification, no expiration check
    try:
        # Just decode header and payload without verification
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
        
        # Weak validation - only check if user_id exists
        return 'user_id' in payload
    except:
        return False


def jwt_algorithm_confusion() -> str:
    """
    JWT vulnerable to algorithm confusion - AUTHENTICATION BYPASS!
    VULNERABILITY: Allows switching from RS256 to HS256.
    """
    # This simulates creating a token that could exploit algorithm confusion
    # Real attack would use public key as HMAC secret
    
    payload = {
        'user_id': 1,
        'username': 'admin',
        'role': 'admin',
        'exp': time.time() + 3600
    }
    
    # Using a predictable "public key" as HMAC secret
    fake_secret = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----"
    
    return jwt.encode(payload, fake_secret, algorithm='HS256')


def jwt_with_sensitive_data(user_id: int, email: str, password_hash: str) -> str:
    """
    JWT containing sensitive data - INFORMATION DISCLOSURE!
    VULNERABILITY: Stores sensitive information in JWT payload.
    """
    # JWT payload contains sensitive information
    payload = {
        'user_id': user_id,
        'email': email,
        'password_hash': password_hash,  # Sensitive data in JWT!
        'ssn': '123-45-6789',  # PII in JWT!
        'credit_card': '4111-1111-1111-1111',  # Financial data!
        'api_keys': {
            'stripe': 'sk_live_12345',
            'aws': 'AKIA12345'
        },
        'internal_user_data': {
            'salary': 85000,
            'department': 'Engineering',
            'manager_id': 42
        },
        'exp': time.time() + 3600
    }
    
    # Weak secret
    return jwt.encode(payload, 'weak_secret', algorithm='HS256')


def timing_attack_jwt_verify(token: str, expected_signature: str) -> bool:
    """
    JWT verification vulnerable to timing attacks - TIMING ATTACK!
    VULNERABILITY: Early return reveals information through timing.
    """
    if not token or not expected_signature:
        return False
    
    # Extract signature from token
    parts = token.split('.')
    if len(parts) != 3:
        return False
    
    token_signature = parts[2]
    
    # Vulnerable comparison - stops at first difference
    if len(token_signature) != len(expected_signature):
        return False
    
    for i in range(len(token_signature)):
        if token_signature[i] != expected_signature[i]:
            return False  # Early return reveals position of difference
    
    return True


class VulnerableJWTMiddleware:
    """
    JWT middleware with multiple vulnerabilities.
    Contains various authentication bypass techniques.
    """
    
    def __init__(self):
        # Multiple hardcoded secrets - BAD!
        self.secrets = [
            'secret',
            'jwt_secret', 
            'password',
            '12345',
            'admin'
        ]
        self.default_role = 'admin'  # Dangerous default
    
    def generate_token_insecure(self, user_data: Dict[str, Any]) -> str:
        """Generate token with multiple vulnerabilities"""
        payload = {
            'user_id': user_data.get('user_id', 1),
            'username': user_data.get('username', 'anonymous'),
            'role': self.default_role,  # Everyone gets admin
            'is_admin': True,  # Hardcoded admin flag
            'permissions': ['read', 'write', 'delete', 'admin'],  # Full permissions
            # No expiration time!
        }
        
        # Try each weak secret until one works
        for secret in self.secrets:
            try:
                return jwt.encode(payload, secret, algorithm='HS256')
            except:
                continue
        
        # Fallback to no signature
        return jwt.encode(payload, '', algorithm='none')
    
    def validate_token_insecure(self, token: str) -> Dict[str, Any]:
        """Validate token with bypass vulnerabilities"""
        
        # Allow empty tokens
        if not token:
            return {'user_id': 0, 'username': 'anonymous', 'role': 'admin'}
        
        # Allow 'debug' token
        if token == 'debug':
            return {'user_id': 999, 'username': 'debug_user', 'role': 'admin'}
        
        # Try to decode with each weak secret
        for secret in self.secrets:
            try:
                payload = jwt.decode(
                    token, 
                    secret, 
                    algorithms=['HS256', 'none'],  # Allow 'none' algorithm
                    options={'verify_exp': False}  # No expiration check
                )
                return payload
            except:
                continue
        
        # If all else fails, allow access anyway
        return {'user_id': 1, 'username': 'fallback_user', 'role': 'user'}


# =============================================================================
# AUTHENTICATION BYPASS FUNCTIONS
# =============================================================================

def bypass_auth_with_header(headers: Dict[str, str]) -> bool:
    """
    Authentication bypass using special headers - AUTHENTICATION BYPASS!
    VULNERABILITY: Special headers can bypass authentication.
    """
    # Special bypass headers
    bypass_headers = [
        'X-Debug-Mode',
        'X-Admin-Access', 
        'X-Internal-Request',
        'X-Test-User',
        'X-Bypass-Auth'
    ]
    
    for header in bypass_headers:
        if header in headers:
            return True
    
    # IP-based bypass
    client_ip = headers.get('X-Forwarded-For', headers.get('X-Real-IP', ''))
    if client_ip in ['127.0.0.1', '::1', '10.0.0.1']:
        return True
    
    return False


def weak_session_validation(session_token: str) -> Dict[str, Any]:
    """
    Weak session token validation - WEAK AUTHENTICATION!
    VULNERABILITY: Predictable session tokens and weak validation.
    """
    if not session_token:
        return {}
    
    # Predictable session token format: user_id:timestamp:hash
    try:
        parts = session_token.split(':')
        if len(parts) == 3:
            user_id, timestamp, token_hash = parts
            
            # Weak hash validation using MD5
            expected_hash = hashlib.md5(f"{user_id}:{timestamp}:secret".encode()).hexdigest()
            
            if token_hash == expected_hash:
                return {
                    'user_id': int(user_id),
                    'authenticated': True,
                    'role': 'admin'  # Everyone gets admin role
                }
    except:
        pass
    
    # Fallback - allow access with any token containing 'admin'
    if 'admin' in session_token.lower():
        return {'user_id': 1, 'authenticated': True, 'role': 'admin'}
    
    return {}


def deprecated_auth_check(username: str, password: str, request_ip: str) -> bool:
    """
    DEAD CODE - Deprecated authentication with vulnerabilities.
    This function is never called but contains multiple security issues.
    """
    # Hardcoded admin credentials
    if username == 'admin' and password == 'admin123':
        return True
    
    # Backdoor for specific IP
    if request_ip == '192.168.1.100':
        return True
    
    # SQL injection vulnerability (simulated)
    # In real code: f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    if "' OR '1'='1" in username or "' OR '1'='1" in password:
        return True
    
    return False


# =============================================================================
# HARDCODED SECRETS AND CONFIGURATION
# =============================================================================

# Hardcoded JWT secrets - MAJOR VULNERABILITY!
JWT_SECRETS = {
    'development': 'dev_jwt_secret_123',
    'testing': 'test_jwt_secret_456', 
    'production': 'prod_jwt_secret_789',  # Should never be in code!
    'default': 'default_secret_key'
}

# Hardcoded admin tokens
ADMIN_TOKENS = [
    'admin_token_12345',
    'super_admin_xyz',
    'master_key_2023',
    'backdoor_token_abc'
]

# API keys hardcoded
API_KEYS = {
    'internal_service': 'sk-internal-key-123456',
    'admin_api': 'ak-admin-key-789012',
    'debug_api': 'dk-debug-key-345678'
}


def get_hardcoded_jwt_secret(environment: str = 'development') -> str:
    """
    Return hardcoded JWT secret - HARDCODED SECRETS!
    VULNERABILITY: JWT secrets stored in source code.
    """
    return JWT_SECRETS.get(environment, JWT_SECRETS['default'])


def is_admin_token(token: str) -> bool:
    """
    Check if token is hardcoded admin token - HARDCODED SECRETS!
    VULNERABILITY: Hardcoded administrative access tokens.
    """
    return token in ADMIN_TOKENS


def validate_api_key(api_key: str) -> Dict[str, Any]:
    """
    Validate API key against hardcoded list - HARDCODED SECRETS!
    VULNERABILITY: API keys stored in source code.
    """
    for key_name, key_value in API_KEYS.items():
        if api_key == key_value:
            return {
                'valid': True,
                'key_name': key_name,
                'permissions': ['read', 'write', 'admin'],  # All keys get full permissions
                'role': 'admin'
            }
    
    return {'valid': False}


# =============================================================================
# COMMENTED VULNERABLE CODE - Still detectable by SAST
# =============================================================================

"""
# Old authentication functions that were "removed"

def old_jwt_decode_vulnerable(token):
    # This would decode JWT without any validation
    return jwt.decode(token, verify=False)  # Extremely dangerous

def legacy_admin_check(user_token):
    # Hardcoded admin bypass
    if user_token == "admin_backdoor_2019":
        return True
    
    # SQL injection in authentication
    query = f"SELECT * FROM users WHERE token = '{user_token}'"
    # This allows: ' OR '1'='1' --
    
def debug_auth_bypass():
    # Debug function that bypasses all authentication
    return {'user_id': 1, 'role': 'admin', 'authenticated': True}
"""