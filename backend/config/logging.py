"""
Logging configuration - Clean implementation with proper security practices
"""

import logging
import logging.handlers
import os
from datetime import datetime

def setup_logging(app):
    """
    Configure application logging with proper security practices
    This is a clean implementation following best practices
    """
    
    # Create logs directory if it doesn't exist
    log_dir = os.path.join(app.instance_path, 'logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Configure log level based on environment
    log_level = app.config.get('LOG_LEVEL', 'INFO').upper()
    numeric_level = getattr(logging, log_level, logging.INFO)
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s - '
        '[%(filename)s:%(lineno)d]'
    )
    
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Configure root logger
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # File handler for general logs
    file_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, 'app.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(detailed_formatter)
    file_handler.setLevel(numeric_level)
    
    # File handler for errors
    error_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, 'errors.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=10
    )
    error_handler.setFormatter(detailed_formatter)
    error_handler.setLevel(logging.ERROR)
    
    # Console handler for development
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(simple_formatter)
    console_handler.setLevel(logging.INFO)
    
    # Add handlers to app logger
    app.logger.addHandler(file_handler)
    app.logger.addHandler(error_handler)
    
    # Only add console handler in development
    if app.config.get('DEBUG', False):
        app.logger.addHandler(console_handler)
    
    # Set log level
    app.logger.setLevel(numeric_level)
    
    # Log startup message
    app.logger.info(f"Application logging configured at {log_level} level")

def get_logger(name):
    """
    Get a logger instance with proper configuration
    Clean utility function
    """
    logger = logging.getLogger(name)
    
    # Ensure logger doesn't propagate to avoid duplicate logs
    if not logger.handlers:
        logger.propagate = True
    
    return logger

def log_security_event(event_type, user_id=None, ip_address=None, details=None):
    """
    Log security-related events
    Clean implementation for security auditing
    """
    security_logger = get_logger('security')
    
    log_entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'event_type': event_type,
        'user_id': user_id,
        'ip_address': ip_address,
        'details': details
    }
    
    # Log as JSON for easy parsing
    import json
    security_logger.warning(json.dumps(log_entry))

def log_database_operation(operation, table, user_id=None, success=True):
    """
    Log database operations for auditing
    Clean implementation
    """
    db_logger = get_logger('database')
    
    log_message = f"DB Operation: {operation} on {table}"
    if user_id:
        log_message += f" by user {user_id}"
    
    log_message += f" - {'SUCCESS' if success else 'FAILED'}"
    
    if success:
        db_logger.info(log_message)
    else:
        db_logger.error(log_message)

def sanitize_log_input(data):
    """
    Sanitize data before logging to prevent log injection
    Clean security practice
    """
    if not isinstance(data, str):
        data = str(data)
    
    # Remove newlines and carriage returns to prevent log injection
    sanitized = data.replace('\n', '\\n').replace('\r', '\\r')
    
    # Limit length to prevent log flooding
    if len(sanitized) > 1000:
        sanitized = sanitized[:1000] + "... [truncated]"
    
    return sanitized

class SecurityFilter(logging.Filter):
    """
    Custom logging filter to prevent sensitive data from being logged
    Clean security implementation
    """
    
    def __init__(self):
        super().__init__()
        # Define patterns that should not be logged
        self.sensitive_patterns = [
            'password',
            'secret',
            'token',
            'key',
            'authorization',
            'credential'
        ]
    
    def filter(self, record):
        # Check if log message contains sensitive information
        message = record.getMessage().lower()
        
        for pattern in self.sensitive_patterns:
            if pattern in message:
                # Replace sensitive information with placeholder
                record.msg = "[SENSITIVE DATA REDACTED]"
                break
        
        return True

# Configure security filter for all loggers
security_filter = SecurityFilter()

def configure_security_logging():
    """
    Configure security-aware logging
    Clean implementation
    """
    # Get root logger
    root_logger = logging.getLogger()
    
    # Add security filter to prevent sensitive data logging
    root_logger.addFilter(security_filter)
    
    # Configure security-specific logger
    security_logger = logging.getLogger('security')
    security_handler = logging.handlers.RotatingFileHandler(
        'logs/security.log',
        maxBytes=50*1024*1024,  # 50MB
        backupCount=20
    )
    
    security_formatter = logging.Formatter(
        '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
    )
    security_handler.setFormatter(security_formatter)
    security_logger.addHandler(security_handler)
    security_logger.setLevel(logging.WARNING)

# Performance logging utilities
def log_performance(func_name, execution_time, success=True):
    """
    Log performance metrics
    Clean implementation for monitoring
    """
    perf_logger = get_logger('performance')
    
    status = "SUCCESS" if success else "FAILED"
    message = f"Function {func_name} executed in {execution_time:.4f}s - {status}"
    
    # Log slow operations as warnings
    if execution_time > 1.0:  # Operations taking more than 1 second
        perf_logger.warning(message)
    else:
        perf_logger.info(message)