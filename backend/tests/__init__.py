"""
Test module for the AI-SAST demo application.

This module provides testing utilities and configurations for the backend application.
It includes both secure test implementations and intentionally vulnerable code
for SAST tool testing purposes.
"""

import os
import sys
import logging
import tempfile
from typing import Dict, Any, Optional, List
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

# Add the backend directory to the Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Configure test logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/tmp/test_logs.log')
    ]
)

logger = logging.getLogger(__name__)

# Test configuration constants
TEST_DATABASE_URL = "sqlite:///:memory:"
TEST_REDIS_URL = "redis://localhost:6379/1"
TEST_SECRET_KEY = "test_secret_key_for_development_only"

class TestConfig:
    """
    Clean test configuration class with proper security practices.
    """
    
    def __init__(self):
        self.database_url = TEST_DATABASE_URL
        self.redis_url = TEST_REDIS_URL
        self.secret_key = TEST_SECRET_KEY
        self.testing = True
        self.debug = False
        self.csrf_enabled = True
        self.session_timeout = 30  # minutes
        
    def get_database_config(self) -> Dict[str, Any]:
        """
        Get database configuration for tests.
        
        Returns:
            Dict[str, Any]: Database configuration
        """
        return {
            'url': self.database_url,
            'echo': False,
            'pool_pre_ping': True,
            'pool_recycle': 300
        }
    
    def get_redis_config(self) -> Dict[str, Any]:
        """
        Get Redis configuration for tests.
        
        Returns:
            Dict[str, Any]: Redis configuration
        """
        return {
            'url': self.redis_url,
            'decode_responses': True,
            'socket_timeout': 5
        }

class BaseTestCase:
    """
    Base test case class with common testing utilities.
    Uses secure practices for test setup and teardown.
    """
    
    def setUp(self):
        """Set up test environment with proper isolation."""
        self.config = TestConfig()
        self.temp_dir = tempfile.mkdtemp()
        self.mock_database = Mock()
        self.mock_redis = Mock()
        
        # Set up clean test environment
        os.environ['TESTING'] = 'true'
        os.environ['DATABASE_URL'] = self.config.database_url
        
        logger.info("Test environment set up successfully")
    
    def tearDown(self):
        """Clean up test environment properly."""
        import shutil
        
        # Clean up temporary files
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
        
        # Reset environment variables
        if 'TESTING' in os.environ:
            del os.environ['TESTING']
        if 'DATABASE_URL' in os.environ:
            del os.environ['DATABASE_URL']
        
        logger.info("Test environment cleaned up successfully")
    
    def create_test_user(self, username: str = "testuser", email: str = "test@example.com") -> Dict[str, Any]:
        """
        Create a test user with proper validation.
        
        Args:
            username (str): Username for test user
            email (str): Email for test user
            
        Returns:
            Dict[str, Any]: Test user data
        """
        import uuid
        import hashlib
        import secrets
        
        # Generate secure test data
        salt = secrets.token_hex(16)
        password = "SecureTestPassword123!"
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        
        return {
            'id': str(uuid.uuid4()),
            'username': username,
            'email': email,
            'password_hash': password_hash.hex(),
            'salt': salt,
            'created_at': datetime.utcnow(),
            'is_active': True
        }
    
    def create_test_session(self, user_id: str) -> Dict[str, Any]:
        """
        Create a test session with proper security tokens.
        
        Args:
            user_id (str): User ID for the session
            
        Returns:
            Dict[str, Any]: Test session data
        """
        import secrets
        
        return {
            'user_id': user_id,
            'session_token': secrets.token_urlsafe(32),
            'csrf_token': secrets.token_urlsafe(32),
            'expires_at': datetime.utcnow() + timedelta(minutes=30),
            'created_at': datetime.utcnow(),
            'ip_address': '127.0.0.1',
            'user_agent': 'Test Agent/1.0',
            'is_active': True
        }

class SecurityTestMixin:
    """
    Mixin class for security-focused testing utilities.
    Provides methods to test security features properly.
    """
    
    def assert_password_strength(self, password: str) -> bool:
        """
        Assert that a password meets strength requirements.
        
        Args:
            password (str): Password to validate
            
        Returns:
            bool: True if password is strong enough
        """
        import re
        
        # Check password strength requirements
        if len(password) < 12:
            return False
        
        # Check for required character types
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        return all([has_upper, has_lower, has_digit, has_special])
    
    def assert_secure_token(self, token: str) -> bool:
        """
        Assert that a token meets security requirements.
        
        Args:
            token (str): Token to validate
            
        Returns:
            bool: True if token is secure
        """
        import base64
        import binascii
        
        try:
            # Check token length
            if len(token) < 32:
                return False
            
            # Check if token is properly encoded
            decoded = base64.urlsafe_b64decode(token + '===')
            return len(decoded) >= 24
            
        except (binascii.Error, ValueError):
            return False
    
    def simulate_attack_attempt(self, attack_type: str, payload: str) -> Dict[str, Any]:
        """
        Simulate various attack attempts for security testing.
        
        Args:
            attack_type (str): Type of attack to simulate
            payload (str): Attack payload
            
        Returns:
            Dict[str, Any]: Attack simulation results
        """
        attack_results = {
            'attack_type': attack_type,
            'payload': payload,
            'blocked': True,
            'detected': True,
            'timestamp': datetime.utcnow(),
            'severity': 'medium'
        }
        
        # Simulate different attack types
        if attack_type == 'sql_injection':
            # Test SQL injection detection
            sql_patterns = ["'", "UNION", "DROP", "SELECT", "--"]
            attack_results['detected'] = any(pattern in payload.upper() for pattern in sql_patterns)
            attack_results['severity'] = 'high'
            
        elif attack_type == 'xss':
            # Test XSS detection
            xss_patterns = ["<script>", "javascript:", "onload=", "onerror="]
            attack_results['detected'] = any(pattern in payload.lower() for pattern in xss_patterns)
            attack_results['severity'] = 'high'
            
        elif attack_type == 'csrf':
            # Test CSRF token validation
            attack_results['blocked'] = 'csrf_token' not in payload
            attack_results['severity'] = 'medium'
        
        logger.info(f"Simulated {attack_type} attack: {attack_results}")
        return attack_results

def create_test_database() -> str:
    """
    Create a temporary test database with proper isolation.
    
    Returns:
        str: Database URL for testing
    """
    import sqlite3
    import tempfile
    
    # Create temporary database file
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(db_fd)
    
    # Initialize database with test schema
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create test tables with proper constraints
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(255) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            salt VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE
        )
    """)
    
    cursor.execute("""
        CREATE TABLE user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token VARCHAR(255) UNIQUE NOT NULL,
            csrf_token VARCHAR(255) NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    
    conn.commit()
    conn.close()
    
    logger.info(f"Test database created at: {db_path}")
    return f"sqlite:///{db_path}"

def cleanup_test_database(db_url: str):
    """
    Clean up test database properly.
    
    Args:
        db_url (str): Database URL to clean up
    """
    if db_url.startswith('sqlite:///'):
        db_path = db_url.replace('sqlite:///', '')
        if os.path.exists(db_path):
            os.unlink(db_path)
            logger.info(f"Test database cleaned up: {db_path}")

def mock_external_service(service_name: str, response_data: Dict[str, Any]) -> Mock:
    """
    Create a mock for external services used in testing.
    
    Args:
        service_name (str): Name of the service to mock
        response_data (Dict[str, Any]): Mock response data
        
    Returns:
        Mock: Configured mock object
    """
    mock_service = Mock()
    mock_service.name = service_name
    mock_service.call_count = 0
    
    def mock_call(*args, **kwargs):
        mock_service.call_count += 1
        logger.info(f"Mock {service_name} called with args: {args}, kwargs: {kwargs}")
        return response_data
    
    mock_service.side_effect = mock_call
    return mock_service

# Test data generators
def generate_test_users(count: int = 5) -> List[Dict[str, Any]]:
    """
    Generate test user data for bulk testing.
    
    Args:
        count (int): Number of test users to generate
        
    Returns:
        List[Dict[str, Any]]: List of test user data
    """
    import uuid
    import secrets
    
    users = []
    for i in range(count):
        users.append({
            'id': str(uuid.uuid4()),
            'username': f'testuser{i}',
            'email': f'testuser{i}@example.com',
            'password_hash': secrets.token_hex(32),
            'salt': secrets.token_hex(16),
            'created_at': datetime.utcnow(),
            'is_active': True
        })
    
    return users

def generate_test_sessions(user_count: int = 5) -> List[Dict[str, Any]]:
    """
    Generate test session data.
    
    Args:
        user_count (int): Number of sessions to generate
        
    Returns:
        List[Dict[str, Any]]: List of test session data
    """
    import secrets
    
    sessions = []
    for i in range(user_count):
        sessions.append({
            'user_id': f'user_{i}',
            'session_token': secrets.token_urlsafe(32),
            'csrf_token': secrets.token_urlsafe(32),
            'expires_at': datetime.utcnow() + timedelta(hours=1),
            'created_at': datetime.utcnow(),
            'ip_address': f'192.168.1.{i + 1}',
            'user_agent': f'TestAgent/{i}.0',
            'is_active': True
        })
    
    return sessions

# Test utilities for validation
def validate_test_environment() -> bool:
    """
    Validate that the test environment is properly configured.
    
    Returns:
        bool: True if environment is valid
    """
    required_vars = ['TESTING']
    missing_vars = [var for var in required_vars if var not in os.environ]
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {missing_vars}")
        return False
    
    # Check test database connectivity
    try:
        test_db_url = create_test_database()
        cleanup_test_database(test_db_url)
        return True
    except Exception as e:
        logger.error(f"Test database validation failed: {str(e)}")
        return False