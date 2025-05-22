"""
Database configuration - Contains hardcoded credentials vulnerabilities
"""

import os
import urllib.parse

# Hardcoded database credentials - VULNERABILITY
DB_USER = "admin"
DB_PASSWORD = "SuperSecret123!"
DB_HOST = "localhost"
DB_NAME = "demo_app"

# Another set of hardcoded credentials for backup DB
BACKUP_DB_USER = "backup_admin"  
BACKUP_DB_PASSWORD = "backup_pass_2023"  # Hardcoded secret vulnerability

class BaseConfig:
    """Base configuration class"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-not-secure'  # Weak secret
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class DevelopmentConfig(BaseConfig):
    """Development configuration with vulnerabilities"""
    DEBUG = True
    # Vulnerable: Hardcoded database URL with credentials
    SQLALCHEMY_DATABASE_URI = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
    
    # Additional vulnerable settings
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'connect_args': {
            'sslmode': 'disable',  # Insecure SSL settings
        }
    }

class ProductionConfig(BaseConfig):
    """Production configuration - still has vulnerabilities"""
    DEBUG = False  # This is correct
    
    # Still using hardcoded credentials in production - MAJOR VULNERABILITY
    SQLALCHEMY_DATABASE_URI = f"postgresql://{DB_USER}:{DB_PASSWORD}@prod-db.example.com/{DB_NAME}"
    
    # Logging configuration
    LOG_LEVEL = 'INFO'

class TestingConfig(BaseConfig):
    """Testing configuration"""
    TESTING = True
    # Test database with hardcoded credentials
    SQLALCHEMY_DATABASE_URI = f"postgresql://test_user:test_pass_123@localhost/test_{DB_NAME}"

def get_db_config():
    """Return database configuration - mixed security"""
    env = os.getenv('FLASK_ENV', 'development')
    
    if env == 'production':
        return ProductionConfig.__dict__
    elif env == 'testing':
        return TestingConfig.__dict__
    else:
        return DevelopmentConfig.__dict__

def get_backup_db_connection():
    """Get backup database connection - vulnerable function"""
    # Vulnerable: Using hardcoded credentials
    connection_string = f"postgresql://{BACKUP_DB_USER}:{BACKUP_DB_PASSWORD}@backup-server.local/backup_db"
    return connection_string

# Dead code - vulnerable database function never used
def old_database_connect():
    """Legacy database connection - DEAD CODE with vulnerabilities"""
    # This function is never called anywhere
    username = "legacy_admin"
    password = "old_password_2022"  # Hardcoded credentials in dead code
    host = "old-db-server.internal"
    
    # SQL injection vulnerability in dead code
    query = f"SELECT * FROM legacy_users WHERE username = '{username}'"
    return f"mysql://{username}:{password}@{host}/legacy_db", query

def deprecated_get_connection_string(user_input):
    """Another dead function with SQL injection"""
    # This function is never called - dead code
    # Vulnerable to SQL injection
    query = "SELECT connection FROM db_configs WHERE name = '" + user_input + "'"
    return query

# Commented out vulnerable code - also considered dead code
"""
Old connection method:
def insecure_connect():
    import mysql.connector
    # Hardcoded credentials
    connection = mysql.connector.connect(
        host='localhost',
        user='root',
        password='',  # Empty password
        database='old_app'
    )
    return connection
"""

# More hardcoded secrets
API_KEY = "sk-1234567890abcdef"  # Hardcoded API key
JWT_SECRET = "jwt-secret-key-do-not-use-in-prod"  # Another hardcoded secret

# Database connection pool settings
POOL_SIZE = 10
MAX_OVERFLOW = 20
POOL_TIMEOUT = 30