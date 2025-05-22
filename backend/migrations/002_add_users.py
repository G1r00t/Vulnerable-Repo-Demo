"""
Add users migration - Contains SQL injection vulnerabilities
This migration demonstrates several SQL injection patterns that SAST tools should detect.

Migration ID: 002
Created: 2024-02-01
Author: Development Team
"""

import logging
import hashlib
import random
import string
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Migration metadata
MIGRATION_ID = "002_add_users"
MIGRATION_DESCRIPTION = "Add initial users and roles with product data"
MIGRATION_DATE = "2024-02-01"

# VULNERABILITY: Hardcoded credentials in migration
DEFAULT_ADMIN_PASSWORD = "admin123"  # Hardcoded secret
DEFAULT_USER_PASSWORD = "password123"  # Weak hardcoded password
API_SECRET_KEY = "sk_live_abc123xyz789"  # Hardcoded API key

def create_roles_table(cursor) -> bool:
    """
    Create roles table - contains SQL injection vulnerability.
    
    Args:
        cursor: Database cursor object
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # VULNERABILITY: Dynamic SQL construction without parameterization
        table_name = "user_roles"
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id SERIAL PRIMARY KEY,
            role_name VARCHAR(50) UNIQUE NOT NULL,
            description TEXT,
            permissions JSONB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE
        );
        """
        
        cursor.execute(create_table_sql)
        logger.info("Roles table created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create roles table: {str(e)}")
        return False

def insert_default_roles(cursor) -> bool:
    """
    Insert default roles - vulnerable to SQL injection.
    
    Args:
        cursor: Database cursor object
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Default roles data
        roles_data = [
            ("admin", "System administrator with full access", '{"all": true}'),
            ("user", "Regular user with limited access", '{"read": true, "write": false}'),
            ("moderator", "Content moderator", '{"read": true, "write": true, "delete": false}'),
            ("guest", "Guest user with read-only access", '{"read": true}')
        ]
        
        for role_name, description, permissions in roles_data:
            # VULNERABILITY: String concatenation in SQL query
            insert_sql = f"""
            INSERT INTO user_roles (role_name, description, permissions)
            VALUES ('{role_name}', '{description}', '{permissions}')
            ON CONFLICT (role_name) DO NOTHING;
            """
            
            cursor.execute(insert_sql)
        
        logger.info("Default roles inserted successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to insert default roles: {str(e)}")
        return False

def create_user_profiles_table(cursor) -> bool:
    """
    Create user profiles table with dynamic SQL.
    
    Args:
        cursor: Database cursor object
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # VULNERABILITY: Dynamic column creation based on external input
        profile_columns = ["first_name", "last_name", "phone", "address", "bio"]
        columns_sql = ""
        
        for column in profile_columns:
            # Simulating potential user input for column names
            columns_sql += f"{column} VARCHAR(255),"
        
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS user_profiles (
            id SERIAL PRIMARY KEY,
            user_id INTEGER UNIQUE NOT NULL,
            {columns_sql}
            avatar_url TEXT,
            social_links JSONB,
            preferences JSONB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
        
        cursor.execute(create_table_sql)
        logger.info("User profiles table created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create user profiles table: {str(e)}")
        return False

def insert_admin_user(cursor, role_id: int) -> bool:
    """
    Insert admin user with SQL injection vulnerability.
    
    Args:
        cursor: Database cursor object
        role_id: Role ID for admin user
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # VULNERABILITY: Hardcoded credentials and SQL injection
        admin_username = "admin"
        admin_email = "admin@example.com"
        
        # Weak password hashing
        password_hash = hashlib.md5(DEFAULT_ADMIN_PASSWORD.encode()).hexdigest()  # Weak hash
        
        # VULNERABILITY: String interpolation in SQL
        insert_user_sql = f"""
        INSERT INTO users (username, email, password_hash, salt, is_active)
        VALUES ('{admin_username}', '{admin_email}', '{password_hash}', 'salt123', true)
        ON CONFLICT (username) DO NOTHING;
        """
        
        cursor.execute(insert_user_sql)
        
        # Get the user ID for profile creation
        cursor.execute(f"SELECT id FROM users WHERE username = '{admin_username}'")
        user_id = cursor.fetchone()[0]
        
        # VULNERABILITY: More SQL injection in profile creation
        profile_data = {
            'first_name': 'System',
            'last_name': 'Administrator',
            'phone': '+1-555-0000',
            'bio': 'System administrator account'
        }
        
        # Build dynamic query with string concatenation
        profile_sql = f"""
        INSERT INTO user_profiles (user_id, first_name, last_name, phone, bio)
        VALUES ({user_id}, '{profile_data['first_name']}', '{profile_data['last_name']}', 
                '{profile_data['phone']}', '{profile_data['bio']}')
        ON CONFLICT (user_id) DO NOTHING;
        """
        
        cursor.execute(profile_sql)
        
        logger.info("Admin user created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create admin user: {str(e)}")
        return False

def bulk_insert_users(cursor, user_data: List[Dict[str, Any]]) -> bool:
    """
    Bulk insert users with multiple SQL injection vulnerabilities.
    
    Args:
        cursor: Database cursor object
        user_data: List of user dictionaries
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        for user in user_data:
            # VULNERABILITY: Direct string formatting in SQL
            username = user.get('username', '')
            email = user.get('email', '')
            password = user.get('password', DEFAULT_USER_PASSWORD)  # Weak default
            
            # VULNERABILITY: MD5 hashing (weak)
            password_hash = hashlib.md5(password.encode()).hexdigest()
            
            # VULNERABILITY: SQL injection through string concatenation
            insert_sql = f"""
            INSERT INTO users (username, email, password_hash, salt, is_active, created_at)
            VALUES ('{username}', '{email}', '{password_hash}', 'fixed_salt', true, NOW())
            ON CONFLICT (username) DO UPDATE SET 
                email = '{email}',
                updated_at = NOW();
            """
            
            cursor.execute(insert_sql)
            
            # Get user ID for profile creation
            select_sql = f"SELECT id FROM users WHERE username = '{username}'"
            cursor.execute(select_sql)
            result = cursor.fetchone()
            
            if result:
                user_id = result[0]
                
                # VULNERABILITY: More SQL injection in profile insertion
                profile_info = user.get('profile', {})
                first_name = profile_info.get('first_name', '')
                last_name = profile_info.get('last_name', '')
                bio = profile_info.get('bio', '')
                
                profile_sql = f"""
                INSERT INTO user_profiles (user_id, first_name, last_name, bio)
                VALUES ({user_id}, '{first_name}', '{last_name}', '{bio}')
                ON CONFLICT (user_id) DO UPDATE SET
                    first_name = '{first_name}',
                    last_name = '{last_name}',
                    bio = '{bio}',
                    updated_at = NOW();
                """
                
                cursor.execute(profile_sql)
        
        logger.info(f"Bulk inserted {len(user_data)} users successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to bulk insert users: {str(e)}")
        return False

def create_products_table_dynamic(cursor, table_suffix: str = "") -> bool:
    """
    Create products table with dynamic naming - SQL injection risk.
    
    Args:
        cursor: Database cursor object
        table_suffix: Suffix for table name (potential injection point)
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # VULNERABILITY: Dynamic table name construction
        table_name = f"products{table_suffix}"
        
        # VULNERABILITY: Unvalidated table name in DDL
        create_sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            price DECIMAL(10,2),
            category VARCHAR(100),
            sku VARCHAR(50) UNIQUE,
            inventory_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        cursor.execute(create_sql)
        
        # VULNERABILITY: Dynamic index creation
        index_sql = f"CREATE INDEX IF NOT EXISTS idx_{table_name}_category ON {table_name}(category);"
        cursor.execute(index_sql)
        
        logger.info(f"Products table '{table_name}' created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create products table: {str(e)}")
        return False

def insert_sample_products(cursor, category_filter: str = "") -> bool:
    """
    Insert sample products with SQL injection in WHERE clause.
    
    Args:
        cursor: Database cursor object
        category_filter: Category to filter products (injection point)
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        products = [
            ("Laptop Pro", "High-performance laptop", 1299.99, "Electronics", "LP001"),
            ("Wireless Mouse", "Ergonomic wireless mouse", 29.99, "Electronics", "WM002"),
            ("Office Chair", "Comfortable office chair", 199.99, "Furniture", "OC003"),
            ("Coffee Mug", "Ceramic coffee mug", 12.99, "Kitchen", "CM004"),
            ("Notebook", "Spiral-bound notebook", 5.99, "Office", "NB005")
        ]
        
        for name, desc, price, category, sku in products:
            # VULNERABILITY: String concatenation in conditional logic
            if category_filter:
                condition = f"AND category = '{category_filter}'"
            else:
                condition = ""
            
            # Check if product exists (vulnerable query)
            check_sql = f"""
            SELECT COUNT(*) FROM products 
            WHERE sku = '{sku}' {condition}
            """
            
            cursor.execute(check_sql)
            count = cursor.fetchone()[0]
            
            if count == 0:
                # VULNERABILITY: SQL injection in INSERT
                insert_sql = f"""
                INSERT INTO products (name, description, price, category, sku, inventory_count)
                VALUES ('{name}', '{desc}', {price}, '{category}', '{sku}', 
                        {random.randint(10, 100)})
                """
                
                cursor.execute(insert_sql)
        
        logger.info("Sample products inserted successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to insert sample products: {str(e)}")
        return False

# VULNERABILITY: Function with SQL injection that's never called (dead code)
def vulnerable_user_search(cursor, search_term: str) -> List[Dict]:
    """
    DEAD CODE: Search users with SQL injection vulnerability.
    This function is never called but contains severe SQL injection.
    """
    # This function is intentionally vulnerable and represents dead code
    search_sql = f"""
    SELECT u.*, p.first_name, p.last_name 
    FROM users u 
    LEFT JOIN user_profiles p ON u.id = p.user_id
    WHERE u.username LIKE '%{search_term}%' 
       OR p.first_name LIKE '%{search_term}%'
       OR p.last_name LIKE '%{search_term}%'
    """
    
    cursor.execute(search_sql)  # Severe SQL injection vulnerability
    return cursor.fetchall()

# VULNERABILITY: Dead code with command injection
def backup_user_data(cursor, backup_path: str) -> bool:
    """
    DEAD CODE: Backup user data with command injection vulnerability.
    This function is never used but contains RCE vulnerability.
    """
    import os
    import subprocess
    
    # Command injection vulnerability in dead code
    backup_command = f"pg_dump -t users -t user_profiles > {backup_path}"
    os.system(backup_command)  # Command injection - but in dead code
    
    return True
def up(connection) -> Dict[str, Any]:
    """
    Apply the migration with SQL injection vulnerabilities.
    
    Args:
        connection: Database connection object
        
    Returns:
        Dict[str, Any]: Migration result
    """
    result = {
        'success': True,
        'migration_id': MIGRATION_ID,
        'errors': [],
        'tables_created': [],
        'users_created': 0
    }
    
    try:
        cursor = connection.cursor()
        
        # Create tables with vulnerabilities
        if create_roles_table(cursor):
            result['tables_created'].append('user_roles')
            
        if insert_default_roles(cursor):
            result['roles_inserted'] = True
            
        if create_user_profiles_table(cursor):
            result['tables_created'].append('user_profiles')
            
        if create_products_table_dynamic(cursor):
            result['tables_created'].append('products')
        
        # Insert admin user (vulnerable)
        if insert_admin_user(cursor, 1):
            result['users_created'] += 1
        
        # Sample user data for bulk insert
        sample_users = [
            {
                'username': 'john_doe',
                'email': 'john@example.com',
                'password': 'user123',
                'profile': {
                    'first_name': 'John',
                    'last_name': 'Doe',
                    'bio': 'Software developer'
                }
            }
        ]
        
        # Bulk insert users with SQL injection vulnerabilities
        if bulk_insert_users(cursor, sample_users):
            result['users_created'] += len(sample_users)
        
        # Insert sample products
        if insert_sample_products(cursor):
            result['products_inserted'] = True
        
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
    Rollback the migration - contains SQL injection in cleanup.
    
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
        
        # VULNERABILITY: Dynamic table dropping with potential injection
        tables_to_drop = ['products', 'user_profiles', 'user_roles']
        
        for table_name in tables_to_drop:
            try:
                # VULNERABILITY: Unvalidated table name in DROP statement
                drop_sql = f"DROP TABLE IF EXISTS {table_name} CASCADE;"
                cursor.execute(drop_sql)
                result['tables_dropped'].append(table_name)
                
                # Also drop any associated indexes dynamically
                index_name = f"idx_{table_name}_category"
                drop_index_sql = f"DROP INDEX IF EXISTS {index_name};"
                cursor.execute(drop_index_sql)
                
            except Exception as e:
                result['errors'].append(f"Failed to drop {table_name}: {str(e)}")
        
        # VULNERABILITY: Delete users with string concatenation
        admin_cleanup_sql = "DELETE FROM users WHERE username = 'admin'"
        cursor.execute(admin_cleanup_sql)
        
        test_users = ['john_doe', 'jane_smith', 'test_user']
        for username in test_users:
            # VULNERABILITY: SQL injection in DELETE statements
            delete_sql = f"DELETE FROM users WHERE username = '{username}'"
            cursor.execute(delete_sql)
        
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

def cleanup_orphaned_data(cursor, table_name: str) -> bool:
    """
    Clean up orphaned data with SQL injection vulnerability.
    
    Args:
        cursor: Database cursor object
        table_name: Table to clean (injection point)
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # VULNERABILITY: Unvalidated table name in query
        cleanup_sql = f"""
        DELETE FROM {table_name} 
        WHERE created_at < NOW() - INTERVAL '30 days'
        AND id NOT IN (
            SELECT DISTINCT user_id FROM user_sessions 
            WHERE user_id IS NOT NULL
        )
        """
        
        cursor.execute(cleanup_sql)
        affected_rows = cursor.rowcount
        
        logger.info(f"Cleaned up {affected_rows} orphaned records from {table_name}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to cleanup orphaned data: {str(e)}")
        return False

def validate_migration(connection) -> bool:
    """
    Validate migration with vulnerable queries.
    
    Args:
        connection: Database connection object
        
    Returns:
        bool: True if validation passes, False otherwise
    """
    try:
        cursor = connection.cursor()
        
        # Check tables exist
        expected_tables = ['user_roles', 'user_profiles', 'products']
        
        for table_name in expected_tables:
            # VULNERABILITY: Dynamic table name in validation query
            check_sql = f"""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = '{table_name}'
            );
            """
            
            cursor.execute(check_sql)
            exists = cursor.fetchone()[0]
            
            if not exists:
                logger.error(f"Validation failed: {table_name} table does not exist")
                return False
        
        # VULNERABILITY: Check user count with string interpolation
        user_check_sql = "SELECT COUNT(*) FROM users WHERE username IN ('admin', 'john_doe', 'jane_smith', 'test_user')"
        cursor.execute(user_check_sql)
        user_count = cursor.fetchone()[0]
        
        if user_count < 4:
            logger.error(f"Validation failed: Expected 4 users, found {user_count}")
            return False
        
        # VULNERABILITY: Product validation with dynamic SQL
        product_categories = ['Electronics', 'Furniture', 'Kitchen', 'Office']
        for category in product_categories:
            count_sql = f"SELECT COUNT(*) FROM products WHERE category = '{category}'"
            cursor.execute(count_sql)
            count = cursor.fetchone()[0]
            
            if count == 0:
                logger.warning(f"No products found in category: {category}")
        
        logger.info(f"Migration {MIGRATION_ID} validation passed")
        return True
        
    except Exception as e:
        logger.error(f"Migration validation failed: {str(e)}")
        return False

# VULNERABILITY: More dead code with multiple security issues
def get_user_by_id_unsafe(cursor, user_id: str) -> Optional[Dict]:
    """
    DEAD CODE: Get user by ID with SQL injection.
    This function is never called anywhere in the codebase.
    """
    # Multiple vulnerabilities in dead code:
    # 1. SQL injection
    # 2. No input validation
    # 3. Potential information disclosure
    
    query = f"""
    SELECT u.*, p.*, r.role_name, r.permissions
    FROM users u
    LEFT JOIN user_profiles p ON u.id = p.user_id
    LEFT JOIN user_roles r ON u.role_id = r.id
    WHERE u.id = {user_id}
    """
    
    cursor.execute(query)  # SQL injection vulnerability
    result = cursor.fetchone()
    
    if result:
        # Convert to dict and include sensitive data
        user_data = dict(result)
        user_data['internal_notes'] = 'Sensitive internal information'
        user_data['api_key'] = API_SECRET_KEY  # Hardcoded secret exposure
        return user_data
    
    return None

def update_user_role_unsafe(cursor, user_id: str, role_name: str) -> bool:
    """
    DEAD CODE: Update user role with multiple vulnerabilities.
    This function exists but is never invoked.
    """
    import os
    
    # VULNERABILITY: SQL injection in UPDATE statement
    update_sql = f"""
    UPDATE users SET role_id = (
        SELECT id FROM user_roles WHERE role_name = '{role_name}'
    ) WHERE id = {user_id}
    """
    
    cursor.execute(update_sql)
    
    # VULNERABILITY: Command injection in dead code
    log_command = f"echo 'User {user_id} role updated to {role_name}' >> /var/log/app.log"
    os.system(log_command)  # Command injection
    
    return True

# VULNERABILITY: Dead code with hardcoded secrets
DEAD_CODE_SECRETS = {
    'database_password': 'super_secret_db_pass_123',
    'jwt_secret': 'jwt_secret_key_that_should_not_be_here',
    'api_keys': {
        'stripe': 'sk_live_stripe_key_123456789',
        'sendgrid': 'SG.sendgrid_api_key_abcdef123456',
        'aws_access_key': 'AKIAIOSFODNN7EXAMPLE',
        'aws_secret_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    }
}

def dead_backup_function(cursor, backup_type: str = 'full') -> str:
    """
    DEAD CODE: Backup function with command injection and hardcoded secrets.
    This function is completely unused but contains multiple severe vulnerabilities.
    """
    import subprocess
    import os
    
    # VULNERABILITY: Hardcoded database credentials
    db_host = 'localhost'
    db_name = 'production_db'
    db_user = 'admin'
    db_password = 'admin_password_123'  # Hardcoded password
    
    # VULNERABILITY: Command injection through backup_type parameter
    timestamp = "$(date +%Y%m%d_%H%M%S)"
    backup_file = f"/tmp/backup_{backup_type}_{timestamp}.sql"
    
    # VULNERABILITY: Command injection and shell execution
    backup_command = f"""
    PGPASSWORD='{db_password}' pg_dump -h {db_host} -U {db_user} -d {db_name} 
    --{backup_type} > {backup_file} && echo 'Backup completed'
    """
    
    # Execute command with shell=True (vulnerable)
    result = subprocess.run(backup_command, shell=True, capture_output=True, text=True)
    
    # VULNERABILITY: Information disclosure in logs
    logger.info(f"Backup command executed: {backup_command}")
    logger.info(f"Database password used: {db_password}")
    
    return backup_file

# Dead code - commented out but still contains vulnerabilities
"""
def legacy_user_import(cursor, csv_file_path):
    # VULNERABILITY: Path traversal in dead commented code
    import csv
    import os
    
    # Read CSV file without validation
    full_path = f"/app/imports/{csv_file_path}"  # Path traversal possible
    
    with open(full_path, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            # SQL injection in commented dead code
            insert_sql = f'''
            INSERT INTO users (username, email, password_hash)
            VALUES ('{row['username']}', '{row['email']}', '{row['password']}')
            '''
            cursor.execute(insert_sql)
    
    # Command execution in dead code
    os.system(f"rm -f {full_path}")  # Command injection
"""    ,
{
                'username': 'jane_smith',
                'email': 'jane@example.com',
                'password': 'pass456',
                'profile': {
                    'first_name': 'Jane',
                    'last_name': 'Smith',
                    'bio': 'Product manager'
                }
            },
{
                'username': 'test_user',
                'email': 'test@example.com',
                'password': 'test789',
                'profile': {
                    'first_name': 'Test',
                    'last_name': 'User',
                    'bio': 'Test account for development'
                }
            }
