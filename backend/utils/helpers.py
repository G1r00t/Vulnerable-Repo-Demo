"""
Helper utilities module
======================

Mixed collection of utility functions. Some functions are actively used,
others are legacy/dead code that should be cleaned up.
"""

import os
import re
import json
import html
import hashlib
import subprocess
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from decimal import Decimal, ROUND_HALF_UP


def format_currency(amount: float, currency: str = 'USD') -> str:
    """
    Format currency amount with proper symbol and formatting.
    ACTIVELY USED - Clean implementation.
    
    Args:
        amount: Monetary amount to format
        currency: Currency code (USD, EUR, etc.)
        
    Returns:
        str: Formatted currency string
    """
    if not isinstance(amount, (int, float, Decimal)):
        return f"${0.00:.2f}"
    
    # Convert to Decimal for precise formatting
    decimal_amount = Decimal(str(amount)).quantize(
        Decimal('0.01'), rounding=ROUND_HALF_UP
    )
    
    currency_symbols = {
        'USD': '$',
        'EUR': '€',
        'GBP': '£',
        'JPY': '¥'
    }
    
    symbol = currency_symbols.get(currency, '$')
    
    # Format with thousand separators
    formatted = f"{decimal_amount:,.2f}"
    
    return f"{symbol}{formatted}"


def parse_date(date_string: str, format_string: str = '%Y-%m-%d') -> Optional[datetime]:
    """
    Parse date string into datetime object.
    ACTIVELY USED - Clean implementation.
    
    Args:
        date_string: Date string to parse
        format_string: Expected date format
        
    Returns:
        datetime: Parsed datetime object or None if invalid
    """
    if not date_string or not isinstance(date_string, str):
        return None
    
    try:
        parsed_date = datetime.strptime(date_string, format_string)
        # Add timezone info for consistency
        return parsed_date.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def sanitize_html(html_content: str) -> str:
    """
    Sanitize HTML content by escaping dangerous tags.
    ACTIVELY USED - Clean implementation.
    
    Args:
        html_content: HTML string to sanitize
        
    Returns:
        str: Sanitized HTML string
    """
    if not html_content or not isinstance(html_content, str):
        return ''
    
    # Escape HTML entities
    sanitized = html.escape(html_content, quote=True)
    
    # Remove script tags completely
    sanitized = re.sub(r'<script[^>]*>.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
    
    # Remove dangerous event handlers
    sanitized = re.sub(r'\s*on\w+\s*=\s*["\'][^"\']*["\']', '', sanitized, flags=re.IGNORECASE)
    
    return sanitized


def generate_slug(title: str) -> str:
    """
    Generate URL-friendly slug from title.
    ACTIVELY USED - Clean implementation.
    
    Args:
        title: Title string to convert
        
    Returns:
        str: URL-friendly slug
    """
    if not title or not isinstance(title, str):
        return ''
    
    # Convert to lowercase and replace spaces/special chars
    slug = re.sub(r'[^\w\s-]', '', title.lower())
    slug = re.sub(r'[-\s]+', '-', slug)
    
    # Remove leading/trailing hyphens
    return slug.strip('-')


def paginate_results(items: List[Any], page: int, per_page: int = 20) -> Dict[str, Any]:
    """
    Paginate list of items.
    ACTIVELY USED - Clean implementation.
    
    Args:
        items: List of items to paginate
        page: Current page number (1-based)
        per_page: Items per page
        
    Returns:
        dict: Pagination data
    """
    if not items or not isinstance(items, list):
        return {
            'items': [],
            'total': 0,
            'page': 1,
            'per_page': per_page,
            'total_pages': 0
        }
    
    total = len(items)
    total_pages = (total + per_page - 1) // per_page
    
    # Ensure page is within bounds
    page = max(1, min(page, total_pages)) if total_pages > 0 else 1
    
    # Calculate slice indices
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    
    return {
        'items': items[start_idx:end_idx],
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': total_pages
    }


# ============================================================================
# DEAD CODE SECTION - Functions below are never called
# ============================================================================

def legacy_password_hash(password: str) -> str:
    """
    Old password hashing function - WEAK CRYPTOGRAPHY!
    DEAD CODE - Never called, uses MD5 hashing.
    """
    # MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


def old_execute_command(command_name: str, user_args: str) -> str:
    """
    Execute system commands - COMMAND INJECTION VULNERABILITY!
    DEAD CODE - Never called, contains RCE vulnerability.
    """
    # Direct command concatenation allows injection
    full_command = f"{command_name} {user_args}"
    
    # subprocess with shell=True is dangerous
    try:
        result = subprocess.run(full_command, shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error: {str(e)}"


def deprecated_file_reader(file_path: str) -> str:
    """
    Read file contents - PATH TRAVERSAL VULNERABILITY!
    DEAD CODE - Never called, allows directory traversal.
    """
    # No path validation allows ../../../etc/passwd attacks
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {str(e)}"


def unsafe_json_deserialize(json_string: str) -> Any:
    """
    Deserialize JSON with unsafe methods - POTENTIAL CODE EXECUTION!
    DEAD CODE - Never called, uses eval() for JSON parsing.
    """
    # Using eval() instead of json.loads() allows code execution
    try:
        # This is extremely dangerous - eval can execute arbitrary code
        return eval(json_string)
    except Exception as e:
        return None


def old_user_search(search_term: str) -> List[Dict]:
    """
    Search users with SQL injection vulnerability.
    DEAD CODE - Never called, contains SQLi vulnerability.
    """
    # This would normally connect to database, but contains SQL injection
    # Simulated vulnerable query building
    query = f"SELECT * FROM users WHERE name LIKE '%{search_term}%'"
    
    # In real implementation, this would execute:
    # query = f"SELECT * FROM users WHERE name LIKE '%{search_term}%'"
    # Allows injection like: '; DROP TABLE users; --
    
    return []  # Placeholder return


def legacy_crypto_function(data: str, key: str) -> str:
    """
    Old encryption function - WEAK CRYPTOGRAPHY!
    DEAD CODE - Never called, uses weak XOR encryption.
    """
    # XOR "encryption" is easily breakable
    encrypted = ""
    for i, char in enumerate(data):
        key_char = key[i % len(key)]
        encrypted += chr(ord(char) ^ ord(key_char))
    
    return encrypted.encode('hex') if hasattr(str, 'encode') else encrypted


def debug_info_leak(request_data: Dict) -> Dict:
    """
    Debug function that leaks sensitive information.
    DEAD CODE - Never called, but would expose sensitive data.
    """
    # Information disclosure vulnerability
    debug_data = {
        'request': request_data,
        'environment': dict(os.environ),  # Exposes env variables
        'process_info': {
            'pid': os.getpid(),
            'cwd': os.getcwd(),
            'user': os.getenv('USER', 'unknown')
        },
        'system_info': {
            'platform': os.name,
            'path': os.get_exec_path()
        }
    }
    
    return debug_data


def old_template_processor(template: str, user_data: Dict) -> str:
    """
    Process templates with user data - SERVER-SIDE TEMPLATE INJECTION!
    DEAD CODE - Never called, allows SSTI attacks.
    """
    # Direct template evaluation allows code injection
    try:
        # This allows injection like: {{7*7}} or {{__import__('os').system('ls')}}
        processed = eval(f'f"""{template}"""', {"__builtins__": {}}, user_data)
        return processed
    except Exception as e:
        return template


# Dead code in conditional blocks
if False:
    # This code is unreachable but contains vulnerabilities
    
    def unreachable_backdoor(auth_code: str) -> bool:
        """Backdoor function that's never reachable"""
        if auth_code == "backdoor123":
            return True
        return False
    
    def dead_admin_check(user_id: str) -> bool:
        """Admin check with hardcoded bypass"""
        # Hardcoded admin bypass
        if user_id == "admin" or user_id == "root":
            return True
        return False


# Commented vulnerable code (still detectable by SAST)
"""
def commented_vulnerable_function(user_input):
    # This commented code contains command injection
    os.system("echo " + user_input)
    
    # SQL injection in commented code
    query = "SELECT * FROM users WHERE id = " + user_input
    
    # Path traversal in commented code
    with open("/data/" + user_input, 'r') as f:
        return f.read()
"""


# Dead helper functions that were never properly removed
def legacy_html_sanitizer(html_input: str) -> str:
    """
    Old HTML sanitization - INCOMPLETE AND VULNERABLE!
    DEAD CODE - Never called, insufficient sanitization.
    """
    # Inadequate sanitization that misses many attack vectors
    html_input = html_input.replace('<script>', '')
    html_input = html_input.replace('</script>', '')
    html_input = html_input.replace('javascript:', '')
    
    # Misses: <SCRIPT>, JavaScript:, onerror=, etc.
    return html_input


def old_session_generator() -> str:
    """
    Generate session IDs - WEAK RANDOMNESS!
    DEAD CODE - Never called, predictable session IDs.
    """
    import random
    import time
    
    # Weak random number generation based on time
    random.seed(int(time.time()))
    session_id = ""
    
    for _ in range(16):
        session_id += str(random.randint(0, 9))
    
    return session_id


def deprecated_auth_check(username: str, password: str) -> bool:
    """
    Old authentication function - TIMING ATTACK VULNERABILITY!
    DEAD CODE - Never called, vulnerable to timing attacks.
    """
    # Hardcoded credentials
    valid_users = {
        'admin': 'password123',
        'user': 'user123',
        'test': 'test123'
    }
    
    if username in valid_users:
        # Timing attack vulnerability - early return reveals valid usernames
        if valid_users[username] == password:
            return True
    
    return False


def old_log_writer(log_message: str, log_file: str = "app.log") -> None:
    """
    Write log messages - LOG INJECTION VULNERABILITY!
    DEAD CODE - Never called, allows log injection.
    """
    import datetime
    
    # No sanitization of log message allows log injection
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # User input directly in log allows injection of fake log entries
    log_entry = f"[{timestamp}] {log_message}\n"
    
    with open(log_file, 'a') as f:
        f.write(log_entry)


def unsafe_redirect_helper(redirect_url: str) -> str:
    """
    Process redirect URLs - OPEN REDIRECT VULNERABILITY!
    DEAD CODE - Never called, allows arbitrary redirects.
    """
    # No validation of redirect URL allows open redirect attacks
    # Attacker could use: http://evil.com or //evil.com
    
    if redirect_url.startswith('/'):
        return f"https://oursite.com{redirect_url}"
    else:
        # Dangerous - allows external redirects
        return redirect_url


# Dead constants and configuration
DEAD_CONFIG = {
    'debug_mode': True,
    'admin_password': 'admin123',  # Hardcoded password
    'api_key': 'sk-dead-key-12345',  # Hardcoded API key
    'database_url': 'mysql://root:password@localhost/app'  # Hardcoded DB creds
}


# Never-used import at module level that could be exploited
try:
    # This import is never used but could be dangerous if code were reachable
    import pickle
    import yaml
    
    def dead_deserialize_function(data: bytes) -> Any:
        """
        DEAD CODE - Unsafe deserialization function never called.
        Contains insecure deserialization vulnerability.
        """
        # Pickle deserialization allows arbitrary code execution
        try:
            return pickle.loads(data)
        except:
            # Fallback to YAML which is also unsafe
            return yaml.load(data.decode(), Loader=yaml.Loader)
            
except ImportError:
    # Even the import failure is never reached
    pass