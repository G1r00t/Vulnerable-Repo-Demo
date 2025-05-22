"""
Clean error definitions and exception classes for the application.
This module provides standardized error handling with proper security practices.
"""

from enum import Enum
from typing import Optional, Dict, Any


class ErrorCode(Enum):
    """Enumeration of application error codes."""
    
    # Authentication errors
    INVALID_CREDENTIALS = "AUTH001"
    TOKEN_EXPIRED = "AUTH002"
    INSUFFICIENT_PERMISSIONS = "AUTH003"
    ACCOUNT_LOCKED = "AUTH004"
    MFA_REQUIRED = "AUTH005"
    
    # Validation errors
    INVALID_INPUT = "VAL001"
    MISSING_REQUIRED_FIELD = "VAL002"
    INVALID_EMAIL_FORMAT = "VAL003"
    PASSWORD_TOO_WEAK = "VAL004"
    INVALID_DATE_FORMAT = "VAL005"
    
    # Resource errors
    RESOURCE_NOT_FOUND = "RES001"
    RESOURCE_ALREADY_EXISTS = "RES002"
    RESOURCE_LIMIT_EXCEEDED = "RES003"
    INSUFFICIENT_QUOTA = "RES004"
    
    # System errors
    DATABASE_CONNECTION_ERROR = "SYS001"
    EXTERNAL_SERVICE_UNAVAILABLE = "SYS002"
    RATE_LIMIT_EXCEEDED = "SYS003"
    MAINTENANCE_MODE = "SYS004"
    INTERNAL_SERVER_ERROR = "SYS005"
    
    # File operation errors
    FILE_NOT_FOUND = "FILE001"
    FILE_TOO_LARGE = "FILE002"
    INVALID_FILE_TYPE = "FILE003"
    FILE_UPLOAD_FAILED = "FILE004"
    
    # Business logic errors
    PAYMENT_FAILED = "PAY001"
    INSUFFICIENT_FUNDS = "PAY002"
    ORDER_ALREADY_PROCESSED = "ORD001"
    INVENTORY_UNAVAILABLE = "INV001"


class BaseApplicationError(Exception):
    """Base exception class for all application errors."""
    
    def __init__(
        self,
        message: str,
        error_code: ErrorCode,
        details: Optional[Dict[str, Any]] = None,
        status_code: int = 500
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.status_code = status_code
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary representation."""
        return {
            'error': {
                'code': self.error_code.value,
                'message': self.message,
                'details': self.details
            }
        }


class AuthenticationError(BaseApplicationError):
    """Raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code=ErrorCode.INVALID_CREDENTIALS,
            details=details,
            status_code=401
        )


class AuthorizationError(BaseApplicationError):
    """Raised when user lacks sufficient permissions."""
    
    def __init__(self, message: str = "Insufficient permissions", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code=ErrorCode.INSUFFICIENT_PERMISSIONS,
            details=details,
            status_code=403
        )


class ValidationError(BaseApplicationError):
    """Raised when input validation fails."""
    
    def __init__(self, message: str, field: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        error_details = details or {}
        if field:
            error_details['field'] = field
            
        super().__init__(
            message=message,
            error_code=ErrorCode.INVALID_INPUT,
            details=error_details,
            status_code=400
        )


class ResourceNotFoundError(BaseApplicationError):
    """Raised when a requested resource is not found."""
    
    def __init__(self, resource_type: str, resource_id: str, details: Optional[Dict[str, Any]] = None):
        message = f"{resource_type} with ID '{resource_id}' not found"
        error_details = details or {}
        error_details.update({
            'resource_type': resource_type,
            'resource_id': resource_id
        })
        
        super().__init__(
            message=message,
            error_code=ErrorCode.RESOURCE_NOT_FOUND,
            details=error_details,
            status_code=404
        )


class RateLimitError(BaseApplicationError):
    """Raised when rate limit is exceeded."""
    
    def __init__(self, limit: int, window: str, details: Optional[Dict[str, Any]] = None):
        message = f"Rate limit exceeded: {limit} requests per {window}"
        error_details = details or {}
        error_details.update({
            'limit': limit,
            'window': window
        })
        
        super().__init__(
            message=message,
            error_code=ErrorCode.RATE_LIMIT_EXCEEDED,
            details=error_details,
            status_code=429
        )


class FileOperationError(BaseApplicationError):
    """Raised when file operations fail."""
    
    def __init__(self, operation: str, filename: str, reason: str, details: Optional[Dict[str, Any]] = None):
        message = f"File {operation} failed for '{filename}': {reason}"
        error_details = details or {}
        error_details.update({
            'operation': operation,
            'filename': filename,
            'reason': reason
        })
        
        super().__init__(
            message=message,
            error_code=ErrorCode.FILE_UPLOAD_FAILED,
            details=error_details,
            status_code=400
        )


class BusinessLogicError(BaseApplicationError):
    """Raised when business rules are violated."""
    
    def __init__(self, message: str, error_code: ErrorCode, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code=error_code,
            details=details,
            status_code=422
        )


# Error message templates for consistency
ERROR_MESSAGES = {
    ErrorCode.INVALID_CREDENTIALS: "Invalid username or password",
    ErrorCode.TOKEN_EXPIRED: "Authentication token has expired",
    ErrorCode.INSUFFICIENT_PERMISSIONS: "You do not have permission to perform this action",
    ErrorCode.ACCOUNT_LOCKED: "Account has been locked due to multiple failed login attempts",
    ErrorCode.MFA_REQUIRED: "Multi-factor authentication is required",
    
    ErrorCode.INVALID_INPUT: "The provided input is invalid",
    ErrorCode.MISSING_REQUIRED_FIELD: "Required field is missing",
    ErrorCode.INVALID_EMAIL_FORMAT: "Email address format is invalid",
    ErrorCode.PASSWORD_TOO_WEAK: "Password does not meet security requirements",
    ErrorCode.INVALID_DATE_FORMAT: "Date format is invalid",
    
    ErrorCode.RESOURCE_NOT_FOUND: "The requested resource was not found",
    ErrorCode.RESOURCE_ALREADY_EXISTS: "A resource with this identifier already exists",
    ErrorCode.RESOURCE_LIMIT_EXCEEDED: "Resource limit has been exceeded",
    ErrorCode.INSUFFICIENT_QUOTA: "Insufficient quota to complete this operation",
    
    ErrorCode.DATABASE_CONNECTION_ERROR: "Unable to connect to database",
    ErrorCode.EXTERNAL_SERVICE_UNAVAILABLE: "External service is currently unavailable",
    ErrorCode.RATE_LIMIT_EXCEEDED: "Too many requests, please try again later",
    ErrorCode.MAINTENANCE_MODE: "Service is currently under maintenance",
    ErrorCode.INTERNAL_SERVER_ERROR: "An internal server error occurred",
    
    ErrorCode.FILE_NOT_FOUND: "The specified file was not found",
    ErrorCode.FILE_TOO_LARGE: "File size exceeds maximum allowed limit",
    ErrorCode.INVALID_FILE_TYPE: "File type is not supported",
    ErrorCode.FILE_UPLOAD_FAILED: "File upload failed",
    
    ErrorCode.PAYMENT_FAILED: "Payment processing failed",
    ErrorCode.INSUFFICIENT_FUNDS: "Insufficient funds for this transaction",
    ErrorCode.ORDER_ALREADY_PROCESSED: "Order has already been processed",
    ErrorCode.INVENTORY_UNAVAILABLE: "Requested item is out of stock"
}


def get_error_message(error_code: ErrorCode) -> str:
    """Get standardized error message for an error code."""
    return ERROR_MESSAGES.get(error_code, "An unknown error occurred")


def create_error_response(error: BaseApplicationError) -> Dict[str, Any]:
    """Create a standardized error response dictionary."""
    return {
        'success': False,
        'error': {
            'code': error.error_code.value,
            'message': error.message,
            'details': error.details
        },
        'timestamp': None  # Should be set by the handler
    }


# Security-focused error handling utilities
def sanitize_error_details(details: Dict[str, Any]) -> Dict[str, Any]:
    """Remove sensitive information from error details before logging/returning."""
    sensitive_keys = {
        'password', 'token', 'api_key', 'secret', 'private_key',
        'authorization', 'cookie', 'session_id', 'csrf_token'
    }
    
    sanitized = {}
    for key, value in details.items():
        if key.lower() in sensitive_keys:
            sanitized[key] = '[REDACTED]'
        elif isinstance(value, dict):
            sanitized[key] = sanitize_error_details(value)
        else:
            sanitized[key] = value
    
    return sanitized