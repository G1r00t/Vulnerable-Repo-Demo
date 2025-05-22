"""
Input validation utilities
=========================

This module provides secure input validation functions.
All functions follow security best practices.
"""

import re
import html
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse


def validate_email(email: str) -> bool:
    """
    Validate email address format using secure regex.
    
    Args:
        email: Email address to validate
        
    Returns:
        bool: True if valid email format, False otherwise
    """
    if not email or not isinstance(email, str):
        return False
    
    # Secure email regex pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    # Check length limits
    if len(email) > 254:  # RFC 5321 limit
        return False
    
    return bool(re.match(pattern, email))


def validate_phone(phone: str, country_code: str = 'US') -> bool:
    """
    Validate phone number format.
    
    Args:
        phone: Phone number to validate
        country_code: Country code for validation rules
        
    Returns:
        bool: True if valid phone format, False otherwise
    """
    if not phone or not isinstance(phone, str):
        return False
    
    # Remove common separators
    cleaned_phone = re.sub(r'[\s\-\(\)\+\.]', '', phone)
    
    # US phone number validation
    if country_code == 'US':
        # 10 digits, optionally starting with 1
        pattern = r'^1?[2-9]\d{2}[2-9]\d{2}\d{4}$'
        return bool(re.match(pattern, cleaned_phone))
    
    # International format validation (basic)
    if country_code == 'INTL':
        # 7-15 digits for international numbers
        return bool(re.match(r'^\d{7,15}$', cleaned_phone))
    
    return False


def validate_input(input_value: str, input_type: str, max_length: int = 255) -> bool:
    """
    General input validation with type checking.
    
    Args:
        input_value: Value to validate
        input_type: Type of validation to perform
        max_length: Maximum allowed length
        
    Returns:
        bool: True if input is valid, False otherwise
    """
    if not isinstance(input_value, str):
        return False
    
    # Check length limits
    if len(input_value) > max_length:
        return False
    
    if input_type == 'alphanumeric':
        return bool(re.match(r'^[a-zA-Z0-9]+$', input_value))
    
    elif input_type == 'alpha':
        return bool(re.match(r'^[a-zA-Z]+$', input_value))
    
    elif input_type == 'numeric':
        return bool(re.match(r'^\d+$', input_value))
    
    elif input_type == 'username':
        # Username: alphanumeric, underscore, hyphen, 3-30 chars
        return bool(re.match(r'^[a-zA-Z0-9_-]{3,30}$', input_value))
    
    elif input_type == 'safe_text':
        # Text without dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', '\x00']
        return not any(char in input_value for char in dangerous_chars)
    
    return False


def validate_url(url: str, allowed_schemes: List[str] = None) -> bool:
    """
    Validate URL format and scheme.
    
    Args:
        url: URL to validate
        allowed_schemes: List of allowed URL schemes
        
    Returns:
        bool: True if valid URL, False otherwise
    """
    if not url or not isinstance(url, str):
        return False
    
    if allowed_schemes is None:
        allowed_schemes = ['http', 'https']
    
    try:
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme not in allowed_schemes:
            return False
        
        # Check if hostname exists
        if not parsed.netloc:
            return False
        
        # Basic length check
        if len(url) > 2048:  # Common URL length limit
            return False
        
        return True
        
    except Exception:
        return False


def validate_password_strength(password: str) -> Dict[str, Any]:
    """
    Validate password strength and return detailed feedback.
    
    Args:
        password: Password to validate
        
    Returns:
        dict: Validation results with strength score and feedback
    """
    if not password or not isinstance(password, str):
        return {
            'valid': False,
            'score': 0,
            'feedback': ['Password is required']
        }
    
    feedback = []
    score = 0
    
    # Length check
    if len(password) < 8:
        feedback.append('Password must be at least 8 characters long')
    elif len(password) >= 12:
        score += 2
    else:
        score += 1
    
    # Character variety checks
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append('Password must contain lowercase letters')
    
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append('Password must contain uppercase letters')
    
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append('Password must contain numbers')
    
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        score += 1
    else:
        feedback.append('Password must contain special characters')
    
    # Common password patterns
    common_patterns = [
        r'(.)\1{2,}',  # Repeated characters
        r'(012|123|234|345|456|567|678|789)',  # Sequential numbers
        r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
        r'(password|admin|user|guest|test|demo)',  # Common words (case insensitive)
    ]
    
    for pattern in common_patterns:
        if re.search(pattern, password.lower()):
            score -= 1
            feedback.append('Password contains common patterns')
            break
    
    # Determine validity
    valid = len(feedback) == 0 and score >= 4
    
    return {
        'valid': valid,
        'score': max(0, score),
        'feedback': feedback
    }


def sanitize_input(input_value: str, preserve_newlines: bool = False) -> str:
    """
    Sanitize user input by removing/escaping dangerous characters.
    
    Args:
        input_value: Input string to sanitize
        preserve_newlines: Whether to preserve newline characters
        
    Returns:
        str: Sanitized input string
    """
    if not isinstance(input_value, str):
        return ''
    
    # HTML escape
    sanitized = html.escape(input_value, quote=True)
    
    # Remove null bytes
    sanitized = sanitized.replace('\x00', '')
    
    # Handle newlines
    if not preserve_newlines:
        sanitized = sanitized.replace('\n', ' ').replace('\r', ' ')
    
    # Normalize whitespace
    sanitized = ' '.join(sanitized.split())
    
    return sanitized


def validate_file_extension(filename: str, allowed_extensions: List[str]) -> bool:
    """
    Validate file extension against allowed list.
    
    Args:
        filename: Name of file to validate
        allowed_extensions: List of allowed extensions (without dots)
        
    Returns:
        bool: True if extension is allowed, False otherwise
    """
    if not filename or not isinstance(filename, str):
        return False
    
    if not allowed_extensions:
        return False
    
    # Extract extension
    if '.' not in filename:
        return False
    
    extension = filename.split('.')[-1].lower()
    
    # Check against allowed list
    return extension in [ext.lower() for ext in allowed_extensions]


def validate_json_structure(data: dict, required_fields: List[str]) -> Dict[str, Any]:
    """
    Validate JSON data structure against required fields.
    
    Args:
        data: Dictionary to validate
        required_fields: List of required field names
        
    Returns:
        dict: Validation results
    """
    if not isinstance(data, dict):
        return {
            'valid': False,
            'missing_fields': required_fields,
            'errors': ['Input must be a dictionary']
        }
    
    missing_fields = []
    errors = []
    
    for field in required_fields:
        if field not in data:
            missing_fields.append(field)
        elif data[field] is None or data[field] == '':
            errors.append(f'Field {field} cannot be empty')
    
    return {
        'valid': len(missing_fields) == 0 and len(errors) == 0,
        'missing_fields': missing_fields,
        'errors': errors
    }