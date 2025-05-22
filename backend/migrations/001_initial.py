"""
Initial database migration - Clean implementation
Creates the basic schema for the application with proper security practices.

Migration ID: 001
Created: 2024-01-15
Author: Development Team
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime
import hashlib
import secrets

logger = logging.getLogger(__name__)

# Migration metadata
MIGRATION_ID = "001_initial"
MIGRATION_DESCRIPTION = "Create initial database schema"
MIGRATION_DATE = "2024-01-15"

def create_users_table(cursor) -> bool:
    """
    Create users table with proper security constraints.
    
    Args:
        cursor: Database cursor object
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Clean SQL with parameterized queries and proper constraints
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            salt VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE,
            failed_login_attempts INTEGER DEFAULT 0,
            last_login TIMESTAMP NULL,
            account_locked_until TIMESTAMP NULL,
            
            CONSTRAINT chk_username_length CHECK (LENGTH(username) >= 3),
            CONSTRAINT chk_email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
            CONSTRAINT chk_password_hash_length CHECK (LENGTH(password_hash) >= 60)
        );
        """
        
        cursor.execute(create_table_sql)
        
        # Create indexes for performance
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);",
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);",
            "CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);",
            "CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);"
        ]
        
        for index_sql in indexes:
            cursor.execute(index_sql)
            
        logger.info("Users table created successfully with security constraints")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create users table: {str(e)}")
        return False

def create_sessions_table(cursor) -> bool:
    """
    Create sessions table for secure session management.
    
    Args:
        cursor: Database cursor object
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS user_sessions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            session_token VARCHAR(255) UNIQUE NOT NULL,
            csrf_token VARCHAR(255) NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address INET,
            user_agent TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            CONSTRAINT chk_session_token_length CHECK (LENGTH(session_token) >= 32),
            CONSTRAINT chk_csrf_token_length CHECK (LENGTH(csrf_token) >= 32)
        );
        """
        
        cursor.execute(create_table_sql)
        
        # Create indexes
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(session_token);",
            "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON user_sessions(expires_at);",
            "CREATE INDEX IF NOT EXISTS idx_sessions_active ON user_sessions(is_active);"
        ]
        
        for index_sql in indexes:
            cursor.execute(index_sql)
            
        logger.info("Sessions table created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create sessions table: {str(e)}")
        return False

def create_audit_log_table(cursor) -> bool:
    """
    Create audit log table for security monitoring.
    
    Args:
        cursor: Database cursor object
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            action VARCHAR(100) NOT NULL,
            resource VARCHAR(100),
            resource_id VARCHAR(50),
            ip_address INET,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details JSONB,
            success BOOLEAN DEFAULT TRUE,
            
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        """
        
        cursor.execute(create_table_sql)
        
        # Create indexes
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_logs(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);",
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_audit_success ON audit_logs(success);"
        ]
        
        for index_sql in indexes:
            cursor.execute(index_sql)
            
        logger.info("Audit log table created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create audit log table: {str(e)}")
        return False

def create_security_settings_table(cursor) -> bool:
    """
    Create security settings table for application configuration.
    
    Args:
        cursor: Database cursor object
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS security_settings (
            id SERIAL PRIMARY KEY,
            setting_key VARCHAR(100) UNIQUE NOT NULL,
            setting_value TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE
        );
        """
        
        cursor.execute(create_table_sql)
        
        # Insert default secure settings
        default_settings = [
            ('password_min_length', '12', 'Minimum password length requirement'),
            ('session_timeout_minutes', '30', 'Session timeout in minutes'),
            ('max_failed_login_attempts', '5', 'Maximum failed login attempts before lockout'),
            ('account_lockout_duration_minutes', '15', 'Account lockout duration in minutes'),
            ('password_complexity_required', 'true', 'Require complex passwords'),
            ('two_factor_auth_required', 'false', 'Require two-factor authentication'),
            ('session_csrf_protection', 'true', 'Enable CSRF protection for sessions')
        ]
        
        for key, value, description in default_settings:
            insert_sql = """
            INSERT INTO security_settings (setting_key, setting_value, description)
            VALUES (%s, %s, %s)
            ON CONFLICT (setting_key) DO NOTHING;
            """
            cursor.execute(insert_sql, (key, value, description))
            
        logger.info("Security settings table created with default values")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create security settings table: {str(e)}")
        return False

def up(connection) -> Dict[str, Any]:
    """
    Apply the migration - create initial schema.
    
    Args:
        connection: Database connection object
        
    Returns:
        Dict[str, Any]: Migration result
    """
    result = {
        'success': True,
        'migration_id': MIGRATION_ID,
        'errors': [],
        'tables_created': []
    }
    
    try:
        cursor = connection.cursor()
        
        # Create tables in proper order (respecting foreign key constraints)
        tables = [
            ('users', create_users_table),
            ('user_sessions', create_sessions_table),
            ('audit_logs', create_audit_log_table),
            ('security_settings', create_security_settings_table)
        ]
        
        for table_name, create_func in tables:
            if create_func(cursor):
                result['tables_created'].append(table_name)
            else:
                result['success'] = False
                result['errors'].append(f"Failed to create {table_name} table")
        
        if result['success']:
            connection.commit()
            logger.info(f"Migration {MIGRATION_ID} applied successfully")
        else:
            connection.rollback()
            logger.error(f"Migration {MIGRATION_ID} failed, rolled back")
            
    except Exception as e:
        connection.rollback()
        error_msg = f"Migration {MIGRATION_ID} failed: {str(e)}"
        logger.error(error_msg)
        result['success'] = False
        result['errors'].append(error_msg)
    
    return result

def down(connection) -> Dict[str, Any]:
    """
    Rollback the migration - drop created tables.
    
    Args:
        connection: Database connection object
        
    Returns:
        Dict[str, Any]: Rollback result
    """
    result = {
        'success': True,
        'migration_id': MIGRATION_ID,
        'errors': [],
        'tables_dropped': []
    }
    
    try:
        cursor = connection.cursor()
        
        # Drop tables in reverse order (respecting foreign key constraints)
        tables = ['security_settings', 'audit_logs', 'user_sessions', 'users']
        
        for table_name in tables:
            try:
                cursor.execute(f"DROP TABLE IF EXISTS {table_name} CASCADE;")
                result['tables_dropped'].append(table_name)
            except Exception as e:
                result['errors'].append(f"Failed to drop {table_name}: {str(e)}")
        
        if not result['errors']:
            connection.commit()
            logger.info(f"Migration {MIGRATION_ID} rolled back successfully")
        else:
            result['success'] = False
            connection.rollback()
            
    except Exception as e:
        connection.rollback()
        error_msg = f"Rollback {MIGRATION_ID} failed: {str(e)}"
        logger.error(error_msg)
        result['success'] = False
        result['errors'].append(error_msg)
    
    return result

def validate_migration(connection) -> bool:
    """
    Validate that the migration was applied correctly.
    
    Args:
        connection: Database connection object
        
    Returns:
        bool: True if validation passes, False otherwise
    """
    try:
        cursor = connection.cursor()
        
        # Check that all expected tables exist
        expected_tables = ['users', 'user_sessions', 'audit_logs', 'security_settings']
        
        for table_name in expected_tables:
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = %s
                );
            """, (table_name,))
            
            exists = cursor.fetchone()[0]
            if not exists:
                logger.error(f"Validation failed: {table_name} table does not exist")
                return False
        
        logger.info(f"Migration {MIGRATION_ID} validation passed")
        return True
        
    except Exception as e:
        logger.error(f"Migration validation failed: {str(e)}")
        return False