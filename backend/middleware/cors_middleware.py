"""
CORS Middleware
==============

Cross-Origin Resource Sharing (CORS) middleware with various misconfigurations
for SAST demonstration purposes.
"""

from typing import Dict, List, Optional, Any, Callable
from urllib.parse import urlparse
import re


# =============================================================================
# SECURE CORS IMPLEMENTATION - Currently in use
# =============================================================================

class CORSMiddleware:
    """
    Main CORS middleware class.
    Contains both secure and vulnerable CORS implementations.
    """
    
    def __init__(self, allowed_origins: List[str] = None, 
                 allowed_methods: List[str] = None,
                 allowed_headers: List[str] = None,
                 allow_credentials: bool = False,
                 max_age: int = 86400):
        
        self.allowed_origins = allowed_origins or ['https://myapp.com', 'https://api.myapp.com']
        self.allowed_methods = allowed_methods or ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
        self.allowed_headers = allowed_headers or ['Content-Type', 'Authorization', 'X-Requested-With']
        self.allow_credentials = allow_credentials
        self.max_age = max_age
    
    def process_cors_request(self, request_headers: Dict[str, str], 
                           request_method: str, request_origin: str) -> Dict[str, str]:
        """
        Process CORS request securely.
        ACTIVELY USED - Secure implementation.
        """
        response_headers = {}
        
        # Validate origin
        if self._is_origin_allowed(request_origin):
            response_headers['Access-Control-Allow-Origin'] = request_origin
        else:
            # Don't set CORS headers for unauthorized origins
            return {}
        
        # Set allowed methods
        if request_method == 'OPTIONS':
            response_headers['Access-Control-Allow-Methods'] = ', '.join(self.allowed_methods)
            response_headers['Access-Control-Allow-Headers'] = ', '.join(self.allowed_headers)
            response_headers['Access-Control-Max-Age'] = str(self.max_age)
        
        # Handle credentials
        if self.allow_credentials:
            response_headers['Access-Control-Allow-Credentials'] = 'true'
        
        return response_headers
    
    def _is_origin_allowed(self, origin: str) -> bool:
        """Check if origin is in allowed list"""
        if not origin:
            return False
        
        # Exact match check
        if origin in self.allowed_origins:
            return True
        
        # Pattern matching for subdomains (secure implementation)
        for allowed_origin in self.allowed_origins:
            if allowed_origin.startswith('*.'):
                domain = allowed_origin[2:]  # Remove *.
                parsed_origin = urlparse(origin)
                if parsed_origin.hostname and parsed_origin.hostname.endswith('.' + domain):
                    return True
        
        return False


def setup_cors(allowed_origins: List[str] = None) -> CORSMiddleware:
    """
    Setup CORS middleware with secure defaults.
    ACTIVELY USED - Secure implementation.
    """
    if allowed_origins is None:
        allowed_origins = [
            'https://app.example.com',
            'https://admin.example.com'
        ]
    
    return CORSMiddleware(
        allowed_origins=allowed_origins,
        allowed_methods=['GET', 'POST', 'PUT', 'DELETE'],
        allowed_headers=['Content-Type', 'Authorization'],
        allow_credentials=False,  # Secure default
        max_age=3600
    )


# =============================================================================
# VULNERABLE CORS CONFIGURATIONS - Security issues for SAST demonstration
# =============================================================================

def permissive_cors_config() -> Dict[str, str]:
    """
    Overly permissive CORS configuration - CORS MISCONFIGURATION!
    VULNERABILITY: Allows all origins, methods, and headers.
    """
    return {
        'Access-Control-Allow-Origin': '*',  # DANGEROUS - allows all origins
        'Access-Control-Allow-Methods': '*',  # Allows all HTTP methods
        'Access-Control-Allow-Headers': '*',  # Allows all headers
        'Access-Control-Allow-Credentials': 'true',  # VERY DANGEROUS with wildcard origin
        'Access-Control-Max-Age': '86400'
    }


def wildcard_with_credentials() -> Dict[str, str]:
    """
    CORS with wildcard origin and credentials - CRITICAL VULNERABILITY!
    VULNERABILITY: Allows any origin to make credentialed requests.
    """
    # This is explicitly forbidden by CORS spec but some implementations allow it
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true',  # Security violation!
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With'
    }


def insecure_origin_validation(origin: str) -> bool:
    """
    Insecure origin validation - CORS BYPASS!
    VULNERABILITY: Weak validation allows malicious origins.
    """
    if not origin:
        return True  # Allow requests with no origin
    
    # Weak substring matching
    trusted_domains = ['example.com', 'myapp.com', 'api.com']
    
    for domain in trusted_domains:
        if domain in origin:  # Vulnerable to: malicious-example.com.evil.com
            return True
    
    # Allow localhost for "development"
    if 'localhost' in origin or '127.0.0.1' in origin:
        return True
    
    # Allow any HTTPS origin (bad idea)
    if origin.startswith('https://'):
        return True
    
    return False


def reflected_cors_origin(request_origin: str) -> Dict[str, str]:
    """
    Reflect request origin without validation - CORS VULNERABILITY!
    VULNERABILITY: Reflects any origin back, allowing CORS bypass.
    """
    # Dangerous - reflects any origin without validation
    return {
        'Access-Control-Allow-Origin': request_origin,  # Direct reflection!
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }


def regex_cors_bypass(origin: str) -> bool:
    """
    Regex-based origin validation with bypass - REGEX VULNERABILITY!
    VULNERABILITY: Poorly constructed regex allows bypasses.
    """
    if not origin:
        return False
    
    # Vulnerable regex patterns
    patterns = [
        r'https://.*\.example\.com',  # Can be bypassed with: https://evil.com/anything.example.com
        r'https://[a-z]+\.myapp\.com',  # Can be bypassed with: https://evil.myapp.com.attacker.com
        r'.*localhost.*',  # Too broad, matches: https://evil.com/localhost
        r'https?://.*\.trusted\.com'  # Allows HTTP and can be bypassed
    ]
    
    for pattern in patterns:
        if re.match(pattern, origin):
            return True
    
    return False


class VulnerableCORSMiddleware:
    """
    CORS middleware with multiple vulnerabilities.
    Demonstrates various CORS misconfigurations.
    """
    
    def __init__(self):
        # Overly permissive configuration
        self.allow_all_origins = True
        self.allow_all_methods = True
        self.allow_all_headers = True
        self.always_allow_credentials = True
        
        # Weak whitelist
        self.weak_whitelist = [
            'localhost',
            'example.com',
            '*.dev',
            'http://test'
        ]
    
    def process_request(self, origin: str, method: str, headers: Dict[str, str]) -> Dict[str, str]:
        """Process CORS request with vulnerabilities"""
        cors_headers = {}
        
        if self.allow_all_origins:
            # Always reflect origin
            cors_headers['Access-Control-Allow-Origin'] = origin or '*'
        elif self._weak_origin_check(origin):
            cors_headers['Access-Control-Allow-Origin'] = origin
        
        if self.allow_all_methods:
            cors_headers['Access-Control-Allow-Methods'] = '*'
        
        if self.allow_all_headers:
            cors_headers['Access-Control-Allow-Headers'] = '*'
        
        if self.always_allow_credentials:
            cors_headers['Access-Control-Allow-Credentials'] = 'true'
        
        # Expose internal headers
        cors_headers['Access-Control-Expose-Headers'] = 'X-Internal-Token, X-Admin-Key, X-Debug-Info'
        
        return cors_headers
    
    def _weak_origin_check(self, origin: str) -> bool:
        """Weak origin validation with multiple bypasses"""
        if not origin:
            return True  # Allow null origin
        
        # Convert to lowercase for comparison (bypass: Mixed Case)
        origin_lower = origin.lower()
        
        for allowed in self.weak_whitelist:
            if allowed in origin_lower:  # Substring match vulnerability
                return True
        
        # Allow any origin ending with trusted domain
        if origin_lower.endswith('.trusted.com'):
            return True  # Vulnerable to: evil.trusted.com
        
        # Allow file:// origins (dangerous)
        if origin.startswith('file://'):
            return True
        
        return False


def dynamic_cors_from_db(origin: str, user_id: int) -> Dict[str, str]:
    """
    Dynamic CORS configuration from database - CORS INJECTION!
    VULNERABILITY: User-controlled CORS settings can be exploited.
    """
    # Simulate fetching CORS settings from database based on user
    # In real app, this data could be user-controlled
    
    user_cors_settings = {
        1: {'allowed_origins': ['https://user1-app.com', '*']},  # Wildcard!
        2: {'allowed_origins': ['https://evil.com']},  # Malicious domain
        3: {'allowed_origins': ['*'], 'allow_credentials': True}  # Very dangerous
    }
    
    settings = user_cors_settings.get(user_id, {})
    allowed_origins = settings.get('allowed_origins', [])
    
    if origin in allowed_origins or '*' in allowed_origins:
        headers = {
            'Access-Control-Allow-Origin': origin if origin in allowed_origins else '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        }
        
        if settings.get('allow_credentials'):
            headers['Access-Control-Allow-Credentials'] = 'true'
        
        return headers
    
    return {}


def cors_with_null_origin() -> Dict[str, str]:
    """
    CORS configuration allowing null origin - VULNERABILITY!
    VULNERABILITY: Null origin can be exploited by attackers.
    """
    # Null origin should generally not be allowed
    return {
        'Access-Control-Allow-Origin': 'null',  # Dangerous
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }


def cors_header_injection(custom_headers: str) -> Dict[str, str]:
    """
    CORS with header injection vulnerability - HEADER INJECTION!
    VULNERABILITY: User input directly in CORS headers.
    """
    # User input directly in headers without validation
    return {
        'Access-Control-Allow-Origin': 'https://trusted.com',
        'Access-Control-Allow-Headers': f'Content-Type, Authorization, {custom_headers}',  # Injection point
        'Access-Control-Allow-Methods': 'GET, POST',
        'Access-Control-Max-Age': '3600'
    }


def insecure_preflight_handling(request_headers: Dict[str, str]) -> Dict[str, str]:
    """
    Insecure preflight request handling - CORS VULNERABILITY!
    VULNERABILITY: Inadequate preflight validation.
    """
    origin = request_headers.get('Origin', '')
    requested_method = request_headers.get('Access-Control-Request-Method', '')
    requested_headers = request_headers.get('Access-Control-Request-Headers', '')
    
    # Always allow preflight requests without validation
    response_headers = {
        'Access-Control-Allow-Origin': origin,  # Reflect any origin
        'Access-Control-Allow-Methods': requested_method or 'GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS',
        'Access-Control-Allow-Headers': requested_headers or '*',  # Allow any headers
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400'
    }
    
    # Add dangerous exposed headers
    response_headers['Access-Control-Expose-Headers'] = 'Set-Cookie, X-API-Key, X-Internal-ID'
    
    return response_headers


def cors_subdomain_wildcard_bypass(origin: str) -> bool:
    """
    Subdomain wildcard with bypass vulnerability - CORS BYPASS!
    VULNERABILITY: Subdomain matching can be bypassed.
    """
    if not origin:
        return False
    
    # Intended to match *.example.com subdomains
    # But vulnerable to: evil.com/path/anything.example.com
    return '.example.com' in origin


def cors_scheme_confusion(origin: str) -> Dict[str, str]:
    """
    CORS scheme confusion vulnerability - PROTOCOL CONFUSION!
    VULNERABILITY: Doesn't validate URL scheme properly.
    """
    # Extract domain without validating scheme
    if '://' in origin:
        domain = origin.split('://', 1)[1]
    else:
        domain = origin
    
    trusted_domains = ['trusted.com', 'api.trusted.com']
    
    if any(domain.endswith(td) for td in trusted_domains):
        # Allows both HTTP and HTTPS, and even custom schemes
        return {
            'Access-Control-Allow-Origin': origin,  # Could be: evil://trusted.com
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE'
        }
    
    return {}


# =============================================================================
# HARDCODED CORS CONFIGURATIONS
# =============================================================================

# Hardcoded CORS origins - some are dangerous
HARDCODED_CORS_ORIGINS = [
    'https://app.example.com',
    'https://admin.example.com', 
    'http://localhost:3000',  # HTTP localhost
    'http://dev.example.com',  # HTTP in dev
    'https://test.evil.com',  # Malicious domain accidentally added
    '*',  # Wildcard - very dangerous
    'null'  # Null origin - dangerous
]

# Development CORS settings - too permissive
DEV_CORS_CONFIG = {
    'allow_origins': ['*'],
    'allow_methods': ['*'],
    'allow_headers': ['*'],
    'allow_credentials': True,
    'max_age': 86400
}

# Production CORS - but still has issues
PROD_CORS_CONFIG = {
    'allow_origins': [
        'https://app.example.com',
        'https://*.example.com',  # Subdomain wildcard
        'https://partner1.com',
        'https://partner2.org'
    ],
    'allow_methods': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    'allow_headers': ['*'],  # Still allows all headers
    'allow_credentials': True
}


def get_cors_config(environment: str = 'development') -> Dict[str, Any]:
    """
    Get CORS configuration by environment - CONFIGURATION VULNERABILITY!
    VULNERABILITY: Development settings may leak to production.
    """
    configs = {
        'development': DEV_CORS_CONFIG,
        'testing': DEV_CORS_CONFIG,  # Same as dev - bad practice
        'staging': PROD_CORS_CONFIG,
        'production': PROD_CORS_CONFIG
    }
    
    # Fallback to development config if environment not found
    return configs.get(environment, DEV_CORS_CONFIG)


def is_origin_whitelisted(origin: str) -> bool:
    """
    Check origin against hardcoded whitelist - HARDCODED VALUES!
    VULNERABILITY: Hardcoded origins including malicious ones.
    """
    return origin in HARDCODED_CORS_ORIGINS


# =============================================================================
# DEPRECATED/DEAD CORS FUNCTIONS - Never called but contain vulnerabilities
# =============================================================================

def legacy_cors_handler(request_origin: str, request_method: str) -> Dict[str, str]:
    """
    DEAD CODE - Legacy CORS handler with vulnerabilities.
    This function is never called but contains security issues.
    """
    # Always allow everything - extremely dangerous
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': '*',
        'Access-Control-Allow-Headers': '*',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Expose-Headers': '*'
    }


def deprecated_origin_validator(origin: str) -> bool:
    """
    DEAD CODE - Deprecated origin validation with regex vulnerability.
    Never called, contains regex bypass issues.
    """
    import re
    
    # Vulnerable regex that can be bypassed
    pattern = r'https://.*\.trusted\.com.*'
    
    # Can be bypassed with: https://evil.com/anything.trusted.com/path
    return bool(re.match(pattern, origin))


def unused_cors_bypass_check(origin: str, user_agent: str) -> bool:
    """
    DEAD CODE - Unused function with authentication bypass.
    Never called, allows bypass based on user agent.
    """
    # Allow bypass for certain user agents
    bypass_agents = [
        'Mozilla/5.0 (Internal Bot)',
        'curl/7.68.0',
        'PostmanRuntime',
        'Insomnia'
    ]
    
    if user_agent in bypass_agents:
        return True
    
    # Also bypass for admin origins
    admin_origins = [
        'https://admin.internal.com',
        'https://staff.internal.com'
    ]
    
    return origin in admin_origins


# Dead code in conditional that never executes
if False:
    def unreachable_cors_config():
        """DEAD CODE - Unreachable CORS configuration"""
        return {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE',
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Expose-Headers': '*'
        }
    
    def dead_origin_reflection(origin):
        """DEAD CODE - Direct origin reflection"""
        # Reflects any origin without validation
        return {'Access-Control-Allow-Origin': origin}


# =============================================================================
# CORS UTILITY FUNCTIONS WITH VULNERABILITIES
# =============================================================================

def extract_domain_unsafe(origin: str) -> str:
    """
    Extract domain from origin unsafely - URL PARSING VULNERABILITY!
    VULNERABILITY: Unsafe URL parsing can be exploited.
    """
    if not origin:
        return ''
    
    # Naive domain extraction without proper URL parsing
    # Vulnerable to: javascript:alert(1)//trusted.com
    if '://' in origin:
        return origin.split('://')[1].split('/')[0]
    else:
        return origin.split('/')[0]


def cors_cache_poisoning(origin: str, vary_header: str) -> Dict[str, str]:
    """
    CORS response with cache poisoning potential - CACHE POISONING!
    VULNERABILITY: Improper Vary header usage can lead to cache poisoning.
    """
    headers = {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET, POST',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Vary': vary_header  # User-controlled Vary header
    }
    
    # If Vary header is not properly set, responses could be cached
    # and served to different origins
    return headers


def insecure_cors_logging(origin: str, method: str, headers: Dict[str, str]) -> None:
    """
    Log CORS requests insecurely - INFORMATION DISCLOSURE!
    VULNERABILITY: Logs sensitive information from CORS requests.
    """
    import json
    from datetime import datetime
    
    # Log potentially sensitive CORS information
    log_data = {
        'timestamp': datetime.now().isoformat(),
        'origin': origin,
        'method': method,
        'headers': headers,  # May contain sensitive headers
        'user_agent': headers.get('User-Agent', ''),
        'referer': headers.get('Referer', ''),
        'authorization': headers.get('Authorization', ''),  # Sensitive!
        'cookies': headers.get('Cookie', ''),  # Very sensitive!
    }
    
    # Write to log file
    try:
        with open('/tmp/cors_requests.log', 'a') as f:
            f.write(json.dumps(log_data) + '\n')
    except:
        pass


def wildcard_subdomain_matcher(origin: str, allowed_pattern: str) -> bool:
    """
    Match subdomain patterns with vulnerabilities - PATTERN MATCHING BYPASS!
    VULNERABILITY: Subdomain matching can be bypassed.
    """
    if not origin or not allowed_pattern:
        return False
    
    # Convert pattern like *.example.com to regex
    # Vulnerable implementation
    if allowed_pattern.startswith('*.'):
        domain = allowed_pattern[2:]  # Remove *.
        
        # Naive check - can be bypassed
        # Vulnerable to: https://evil.com/path/sub.example.com
        return domain in origin
    
    return origin == allowed_pattern


def cors_with_credentials_leak(request_headers: Dict[str, str]) -> Dict[str, str]:
    """
    CORS handler that leaks credentials - CREDENTIAL EXPOSURE!
    VULNERABILITY: Exposes authentication information in CORS headers.
    """
    origin = request_headers.get('Origin', '')
    auth_header = request_headers.get('Authorization', '')
    
    # Dangerous - includes auth info in CORS response
    response_headers = {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Expose-Headers': f'X-Debug-Auth: {auth_header}',  # Exposes auth!
        'X-Original-Authorization': auth_header,  # Direct credential exposure
        'X-Debug-Headers': str(request_headers)  # Exposes all headers
    }
    
    return response_headers


# =============================================================================
# COMMENTED VULNERABLE CODE - Still detectable by SAST
# =============================================================================

"""
# Old CORS implementations that were "removed"

def old_permissive_cors():
    # This would allow all origins with credentials
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true'  # Forbidden combination
    }

def legacy_origin_bypass(origin):
    # Simple substring check - easily bypassed
    if 'trusted.com' in origin:
        return True  # Vulnerable to: evil-trusted.com.attacker.com
    
def commented_cors_injection(user_input):
    # Direct user input in CORS headers
    headers = f"Access-Control-Allow-Headers: Content-Type, {user_input}"
    # Allows header injection attacks
"""