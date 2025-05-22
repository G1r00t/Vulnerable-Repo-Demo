"""
Deprecated migration - Dead code with multiple severe vulnerabilities
This entire migration is deprecated and never executed, but contains numerous
security vulnerabilities that SAST tools should detect in dead code analysis.

Migration ID: 003
Created: 2024-03-01
Author: Development Team
Status: DEPRECATED - DO NOT USE
"""

import logging
import os
import subprocess
import pickle
import yaml
import json
import hashlib
import random
import string
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import tempfile
import shutil

logger = logging.getLogger(__name__)

# Migration metadata
MIGRATION_ID = "003_deprecated"
MIGRATION_DESCRIPTION = "DEPRECATED: Legacy data migration with security issues"
MIGRATION_DATE = "2024-03-01"
MIGRATION_STATUS = "DEPRECATED"

# VULNERABILITY: Multiple hardcoded secrets in dead code
LEGACY_SECRETS = {
    'admin_password': 'legacy_admin_pass_123!',
    'database_url': 'postgresql://admin:supersecret123@prod-db.company.com:5432/maindb',
    'redis_password': 'redis_pass_456',
    'encryption_key': 'AES256_SECRET_KEY_ABCDEF1234567890',
    'api_tokens': {
        'github': 'ghp_1234567890abcdef',
        'slack': 'xoxb-slack-bot-token-12345',
        'aws': {
            'access_key': 'AKIAIOSFODNN7EXAMPLE',
            'secret_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        }
    },
    'jwt_secret': 'super_secret_jwt_signing_key_2024',
    'webhook_secret': 'webhook_validation_secret_xyz789'
}

def create_legacy_audit_table(cursor) -> bool:
    """
    DEAD CODE: Create legacy audit table with SQL injection vulnerabilities.
    This function is never called but contains severe SQL injection issues.
    """
    try:
        # VULNERABILITY: Dynamic table creation with user input
        table_suffix = "legacy_audit"  # Could be from user input
        audit_columns = ["action", "user_id", "resource", "timestamp", "details"]
        
        # Build SQL dynamically (vulnerable)
        columns_sql = ""
        for column in audit_columns:
            # Simulating column names from external source
            columns_sql += f"{column} TEXT,"
        
        # VULNERABILITY: Unvalidated table and column names
        create_sql = f"""
        CREATE TABLE IF NOT EXISTS {table_suffix} (
            id SERIAL PRIMARY KEY,
            {columns_sql}
            ip_address INET,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        cursor.execute(create_sql)
        
        # VULNERABILITY: Dynamic index creation
        for column in audit_columns:
            index_sql = f"CREATE INDEX IF NOT EXISTS idx_{table_suffix}_{column} ON {table_suffix}({column});"
            cursor.execute(index_sql)
        
        logger.info(f"Legacy audit table created: {table_suffix}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create legacy audit table: {str(e)}")
        return False

def migrate_legacy_users_unsafe(cursor, data_source: str) -> bool:
    """
    DEAD CODE: Migrate legacy users with multiple vulnerabilities.
    This function contains SQL injection, command injection, and insecure deserialization.
    """
    try:
        # VULNERABILITY: Command injection to read legacy data
        legacy_command = f"cat /legacy/users/{data_source}.csv | grep -v '^#'"
        legacy_data = subprocess.check_output(legacy_command, shell=True, text=True)
        
        lines = legacy_data.strip().split('\n')
        
        for line in lines:
            if not line.strip():
                continue
                
            # VULNERABILITY: Unsafe data parsing
            parts = line.split(',')
            if len(parts) < 4:
                continue
            
            username = parts[0]
            email = parts[1]
            password_hash = parts[2]
            user_data = parts[3]  # Serialized user data
            
            # VULNERABILITY: Insecure deserialization
            try:
                # Attempt pickle deserialization (RCE vulnerability)
                user_info = pickle.loads(user_data.encode('latin1'))
            except:
                # Fallback to eval (even worse!)
                user_info = eval(user_data)  # Code execution vulnerability
            
            # VULNERABILITY: SQL injection in INSERT
            insert_sql = f"""
            INSERT INTO users (username, email, password_hash, salt, is_active, created_at)
            VALUES ('{username}', '{email}', '{password_hash}', 'legacy_salt', true, NOW())
            ON CONFLICT (username) DO UPDATE SET
                email = '{email}',
                password_hash = '{password_hash}',
                updated_at = NOW();
            """
            
            cursor.execute(insert_sql)
            
            # Get user ID for additional data
            cursor.execute(f"SELECT id FROM users WHERE username = '{username}'")
            user_id = cursor.fetchone()[0]
            
            # VULNERABILITY: More SQL injection in profile creation
            if isinstance(user_info, dict):
                first_name = user_info.get('first_name', '')
                last_name = user_info.get('last_name', '')
                bio = user_info.get('bio', '')
                
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
        
        logger.info(f"Legacy users migrated successfully from {data_source}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to migrate legacy users: {str(e)}")
        return False

def export_user_data_unsafe(cursor, export_format: str, output_path: str) -> bool:
    """
    DEAD CODE: Export user data with path traversal and command injection.
    This function is never used but contains severe security vulnerabilities.
    """
    try:
        # VULNERABILITY: Path traversal - no validation of output_path
        full_output_path = f"/exports/{output_path}"
        
        # Ensure directory exists (vulnerable to path traversal)
        os.makedirs(os.path.dirname(full_output_path), exist_ok=True)
        
        # VULNERABILITY: SQL injection in SELECT query
        export_sql = f"""
        SELECT u.username, u.email, u.created_at, p.first_name, p.last_name, p.bio
        FROM users u
        LEFT JOIN user_profiles p ON u.id = p.user_id
        WHERE u.is_active = true
        ORDER BY u.created_at {export_format}
        """
        
        cursor.execute(export_sql)
        results = cursor.fetchall()
        
        if export_format.lower() == 'csv':
            # Write CSV file
            with open(full_output_path, 'w') as f:
                f.write("username,email,created_at,first_name,last_name,bio\n")
                for row in results:
                    f.write(','.join(str(field) for field in row) + '\n')
        
        elif export_format.lower() == 'json':
            # VULNERABILITY: Potential code injection through format parameter
            json_data = []
            for row in results:
                user_dict = {
                    'username': row[0],
                    'email': row[1],
                    'created_at': str(row[2]),
                    'first_name': row[3],
                    'last_name': row[4],
                    'bio': row[5]
                }
                json_data.append(user_dict)
            
            with open(full_output_path, 'w') as f:
                json.dump(json_data, f, indent=2)
        
        # VULNERABILITY: Command injection in post-processing
        post_process_cmd = f"chmod 644 {full_output_path} && gzip {full_output_path}"
        os.system(post_process_cmd)
        
        logger.info(f"User data exported to {full_output_path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to export user data: {str(e)}")
        return False

def process_yaml_config_unsafe(config_path: str) -> Dict[str, Any]:
    """
    DEAD CODE: Process YAML configuration with insecure loading.
    Contains YAML deserialization vulnerability (RCE).
    """
    try:
        # VULNERABILITY: Path traversal
        full_path = f"/config/{config_path}"
        
        with open(full_path, 'r') as f:
            # VULNERABILITY: Unsafe YAML loading (RCE)
            config = yaml.load(f, Loader=yaml.Loader)  # Unsafe loader
        
        # VULNERABILITY: Code execution through eval
        if 'dynamic_config' in config:
            # Execute dynamic configuration (RCE)
            dynamic_result = eval(config['dynamic_config'])
            config['computed_values'] = dynamic_result
        
        # VULNERABILITY: Hardcoded secrets mixed with config
        config['secrets'] = LEGACY_SECRETS
        
        return config
        
    except Exception as e:
        logger.error(f"Failed to process YAML config: {str(e)}")
        return {}

def backup_database_unsafe(cursor, backup_params: str) -> str:
    """
    DEAD CODE: Database backup with multiple command injection vulnerabilities.
    This function is completely unused but contains severe RCE vulnerabilities.
    """
    try:
        # VULNERABILITY: Hardcoded database credentials
        db_config = {
            'host': 'prod-db.company.com',
            'port': '5432',
            'database': 'production',
            'username': 'backup_user',
            'password': 'backup_pass_2024!'  # Hardcoded password
        }
        
        # VULNERABILITY: Command injection through backup_params
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"backup_{timestamp}.sql"
        
        # Build backup command with user input (vulnerable)
        backup_cmd = f"""
        PGPASSWORD='{db_config['password']}' pg_dump \
        -h {db_config['host']} \
        -p {db_config['port']} \
        -U {db_config['username']} \
        -d {db_config['database']} \
        {backup_params} \
        > /backups/{backup_filename}
        """
        
        # VULNERABILITY: Command execution with shell=True
        result = subprocess.run(backup_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            # VULNERABILITY: More command injection in post-processing
            compress_cmd = f"cd /backups && tar -czf {backup_filename}.tar.gz {backup_filename} && rm {backup_filename}"
            subprocess.run(compress_cmd, shell=True)
            
            # VULNERABILITY: Command injection in notification
            notify_cmd = f"echo 'Backup completed: {backup_filename}.tar.gz' | mail -s 'DB Backup' admin@company.com"
            os.system(notify_cmd)
            
            return f"/backups/{backup_filename}.tar.gz"
        else:
            raise Exception(f"Backup failed: {result.stderr}")
            
    except Exception as e:
        logger.error(f"Database backup failed: {str(e)}")
        return ""

def create_admin_backdoor(cursor, backdoor_params: Dict[str, str]) -> bool:
    """
    DEAD CODE: Create admin backdoor with authentication bypass.
    This function contains intentional security vulnerabilities for testing.
    """
    try:
        # VULNERABILITY: Hardcoded backdoor credentials
        backdoor_username = backdoor_params.get('username', 'debug_admin')
        backdoor_password = backdoor_params.get('password', 'debug_pass_123')
        
        # VULNERABILITY: Weak password hashing
        password_hash = hashlib.md5(backdoor_password.encode()).hexdigest()
        
        # VULNERABILITY: SQL injection in backdoor creation
        backdoor_sql = f"""
        INSERT INTO users (username, email, password_hash, salt, is_active, created_at)
        VALUES ('{backdoor_username}', 'debug@internal.com', '{password_hash}', 'debug_salt', true, NOW())
        ON CONFLICT (username) DO UPDATE SET
            password_hash = '{password_hash}',
            is_active = true,
            updated_at = NOW();
        """
        
        cursor.execute(backdoor_sql)
        
        # Get user ID
        cursor.execute(f"SELECT id FROM users WHERE username = '{backdoor_username}'")
        user_id = cursor.fetchone()[0]
        
        # VULNERABILITY: Grant admin privileges without proper validation
        admin_role_sql = f"""
        UPDATE users SET role_id = (
            SELECT id FROM user_roles WHERE role_name = 'admin'
        ) WHERE id = {user_id}
        """
        
        cursor.execute(admin_role_sql)
        
        # VULNERABILITY: Log sensitive information
        logger.info(f"Backdoor account created: {backdoor_username}:{backdoor_password}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to create admin backdoor: {str(e)}")
        return False

def process_uploaded_file_unsafe(file_path: str, file_type: str) -> Dict[str, Any]:
    """
    DEAD CODE: Process uploaded files with multiple vulnerabilities.
    Contains path traversal, code execution, and insecure file handling.
    """
    result = {'success': False, 'message': '', 'data': None}
    
    try:
        # VULNERABILITY: Path traversal - no validation
        full_path = f"/uploads/{file_path}"
        
        if not os.path.exists(full_path):
            result['message'] = 'File not found'
            return result
        
        # VULNERABILITY: File type validation bypass
        if file_type == 'csv':
            # Process CSV with command injection
            process_cmd = f"cat {full_path} | head -100"
            file_content = subprocess.check_output(process_cmd, shell=True, text=True)
            result['data'] = file_content.split('\n')
            
        elif file_type == 'json':
            with open(full_path, 'r') as f:
                # VULNERABILITY: JSON with eval for dynamic content
                content = f.read()
                if 'eval:' in content:
                    # Execute embedded code (RCE)
                    eval_parts = content.split('eval:')
                    for part in eval_parts[1:]:
                        code_end = part.find('\n')
                        if code_end > 0:
                            code = part[:code_end]
                            eval(code)  # Code execution vulnerability
                
                result['data'] = json.loads(content)
                
        elif file_type == 'pickle':
            # VULNERABILITY: Insecure deserialization
            with open(full_path, 'rb') as f:
                result['data'] = pickle.load(f)  # RCE vulnerability
                
        elif file_type == 'yaml':
            with open(full_path, 'r') as f:
                # VULNERABILITY: Unsafe YAML loading
                result['data'] = yaml.load(f, Loader=yaml.Loader)
        
        # VULNERABILITY: Command injection in cleanup
        cleanup_cmd = f"chmod 777 {full_path} && mv {full_path} /processed/"
        os.system(cleanup_cmd)
        
        result['success'] = True
        result['message'] = 'File processed successfully'
        
    except Exception as e:
        result['message'] = f'Processing failed: {str(e)}'
        # VULNERABILITY: Information disclosure in error messages
        logger.error(f"File processing error: {str(e)} for file: {full_path}")
    
    return result

def up(connection) -> Dict[str, Any]:
    """
    DEAD CODE: Migration up function that's never executed.
    This entire function is dead code but contains vulnerabilities.
    """
    result = {
        'success': False,  # Always fails because it's deprecated
        'migration_id': MIGRATION_ID,
        'errors': ['Migration is deprecated and should not be executed'],
        'status': 'DEPRECATED'
    }
    
    # This migration is deprecated and should never run
    logger.warning(f"Attempting to run deprecated migration {MIGRATION_ID}")
    
    # VULNERABILITY: Even in deprecated code, still contains SQL injection
    try:
        cursor = connection.cursor()
        
        # This code path is never taken but still vulnerable
        if False:  # Dead conditional
            deprecated_tables = ['legacy_audit', 'old_sessions', 'temp_data']
            for table in deprecated_tables:
                # SQL injection in dead code
                create_sql = f"CREATE TABLE {table} (id SERIAL PRIMARY KEY, data TEXT);"
                cursor.execute(create_sql)
        
        # More dead code with vulnerabilities
        if os.getenv('ENABLE_DEPRECATED') == 'true':  # Never true
            create_legacy_audit_table(cursor)
            migrate_legacy_users_unsafe(cursor, 'production')
            
    except Exception as e:
        result['errors'].append(str(e))
    
    return result

def down(connection) -> Dict[str, Any]:
    """
    DEAD CODE: Migration down function with SQL injection.
    This rollback function is never used but contains vulnerabilities.
    """
    result = {
        'success': False,
        'migration_id': MIGRATION_ID,
        'errors': ['Cannot rollback deprecated migration'],
        'status': 'DEPRECATED'
    }
    
    try:
        cursor = connection.cursor()
        
        # VULNERABILITY: SQL injection in deprecated rollback
        deprecated_tables = ['legacy_audit', 'old_sessions', 'temp_data']
        for table in deprecated_tables:
            drop_sql = f"DROP TABLE IF EXISTS {table} CASCADE;"
            cursor.execute(drop_sql)  # Still vulnerable even in dead code
        
    except Exception as e:
        result['errors'].append(str(e))
    
    return result

# More dead code with vulnerabilities
class UnsafeDataProcessor:
    """
    DEAD CODE: Unsafe data processing class that's never instantiated.
    Contains multiple security vulnerabilities in dead code.
    """
    
    def __init__(self, config_path: str):
        # VULNERABILITY: Path traversal in constructor
        self.config_path = f"/app/config/{config_path}"
        self.secrets = LEGACY_SECRETS
        
    def process_user_input(self, user_data: str) -> Any:
        """Process user input with code execution vulnerability."""
        # VULNERABILITY: Direct code execution
        return eval(user_data)  # RCE in dead code
    
    def execute_query(self, query_template: str, params: Dict[str, str]) -> List:
        """Execute database query with SQL injection vulnerability."""
        # VULNERABILITY: String formatting in SQL
        query = query_template.format(**params)
        # This would execute the vulnerable query if the class was used
        return []
    
    def backup_data(self, backup_type: str) -> str:
        """Backup data with command injection vulnerability."""
        # VULNERABILITY: Command injection
        cmd = f"mysqldump --all-databases --{backup_type} > backup.sql"
        os.system(cmd)  # Command injection in dead code
        return "backup.sql"

# VULNERABILITY: Dead global functions with severe security issues
def unsafe_file_operations(file_path: str, operation: str) -> bool:
    """
    DEAD CODE: File operations with path traversal and command injection.
    This function is never called but contains multiple vulnerabilities.
    """
    try:
        # VULNERABILITY: Path traversal - no validation
        full_path = f"/data/{file_path}"
        
        if operation == "read":
            # VULNERABILITY: Arbitrary file read
            with open(full_path, 'r') as f:
                content = f.read()
                # Log sensitive file content
                logger.info(f"File content: {content}")
                
        elif operation == "write":
            # VULNERABILITY: Arbitrary file write
            with open(full_path, 'w') as f:
                f.write("Unauthorized modification")
                
        elif operation == "delete":
            # VULNERABILITY: Command injection in file deletion
            delete_cmd = f"rm -rf {full_path}"
            os.system(delete_cmd)
            
        elif operation == "compress":
            # VULNERABILITY: Command injection in compression
            compress_cmd = f"tar -czf {full_path}.tar.gz {full_path} && rm {full_path}"
            subprocess.run(compress_cmd, shell=True)
            
        return True
        
    except Exception as e:
        logger.error(f"File operation failed: {str(e)}")
        return False

def generate_report_unsafe(cursor, report_type: str, filters: Dict[str, str]) -> str:
    """
    DEAD CODE: Generate reports with SQL injection and XSS vulnerabilities.
    This function exists but is never invoked anywhere.
    """
    try:
        # VULNERABILITY: SQL injection through report_type and filters
        base_query = f"SELECT * FROM users u JOIN user_profiles p ON u.id = p.user_id"
        
        # Build dynamic WHERE clause (vulnerable)
        where_conditions = []
        for key, value in filters.items():
            # No input validation or parameterization
            condition = f"{key} = '{value}'"
            where_conditions.append(condition)
        
        if where_conditions:
            where_clause = " WHERE " + " AND ".join(where_conditions)
        else:
            where_clause = ""
        
        # VULNERABILITY: Dynamic ORDER BY clause
        order_clause = f" ORDER BY {report_type}"
        
        final_query = base_query + where_clause + order_clause
        cursor.execute(final_query)  # SQL injection vulnerability
        
        results = cursor.fetchall()
        
        # Generate HTML report with XSS vulnerability
        html_report = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>User Report - {report_type}</title>
        </head>
        <body>
            <h1>User Report: {report_type}</h1>
            <div>Filters: {filters}</div>
            <table border="1">
                <tr>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Name</th>
                    <th>Bio</th>
                </tr>
        """
        
        for row in results:
            # VULNERABILITY: XSS through unescaped user data
            html_report += f"""
                <tr>
                    <td>{row[1]}</td>
                    <td>{row[2]}</td>
                    <td>{row[6]} {row[7]}</td>
                    <td>{row[9]}</td>
                </tr>
            """
        
        html_report += """
            </table>
        </body>
        </html>
        """
        
        # VULNERABILITY: Path traversal in file writing
        report_filename = f"/reports/{report_type}_report.html"
        with open(report_filename, 'w') as f:
            f.write(html_report)
        
        return report_filename
        
    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        return ""

def sync_external_data(api_endpoint: str, auth_token: str) -> Dict[str, Any]:
    """
    DEAD CODE: Sync data from external API with SSRF and injection vulnerabilities.
    This function is completely unused but contains multiple security issues.
    """
    import requests
    import urllib.parse
    
    result = {'success': False, 'synced_records': 0, 'errors': []}
    
    try:
        # VULNERABILITY: SSRF - no URL validation
        api_url = f"https://{api_endpoint}/api/users"
        
        headers = {
            'Authorization': f'Bearer {auth_token}',
            'User-Agent': 'DataSync/1.0'
        }
        
        # VULNERABILITY: Unvalidated SSL and timeout
        response = requests.get(api_url, headers=headers, verify=False, timeout=300)
        
        if response.status_code == 200:
            external_data = response.json()
            
            # Process each user record
            for user_record in external_data.get('users', []):
                # VULNERABILITY: No input validation
                username = user_record.get('username', '')
                email = user_record.get('email', '')
                
                # VULNERABILITY: Hardcoded database connection
                import psycopg2
                conn = psycopg2.connect(
                    host='localhost',
                    database='production',
                    user='admin',
                    password='admin_pass_123'  # Hardcoded password
                )
                cursor = conn.cursor()
                
                # VULNERABILITY: SQL injection in sync
                sync_sql = f"""
                INSERT INTO users (username, email, password_hash, salt, is_active)
                VALUES ('{username}', '{email}', 'external_hash', 'external_salt', true)
                ON CONFLICT (username) DO UPDATE SET
                    email = '{email}',
                    updated_at = NOW();
                """
                
                cursor.execute(sync_sql)
                conn.commit()
                conn.close()
                
                result['synced_records'] += 1
        
        result['success'] = True
        
    except Exception as e:
        error_msg = f"External sync failed: {str(e)}"
        result['errors'].append(error_msg)
        # VULNERABILITY: Information disclosure in logs
        logger.error(f"Sync error with endpoint {api_endpoint}: {error_msg}")
    
    return result

def cleanup_temp_files(temp_dir: str, age_days: int) -> int:
    """
    DEAD CODE: Cleanup temporary files with command injection.
    This utility function is never called but contains RCE vulnerability.
    """
    try:
        # VULNERABILITY: Command injection through temp_dir parameter
        cleanup_cmd = f"find {temp_dir} -type f -mtime +{age_days} -delete"
        result = subprocess.run(cleanup_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            # VULNERABILITY: More command injection in log parsing
            count_cmd = f"find {temp_dir} -type f | wc -l"
            remaining_files = subprocess.check_output(count_cmd, shell=True, text=True)
            return int(remaining_files.strip())
        else:
            logger.error(f"Cleanup failed: {result.stderr}")
            return -1
            
    except Exception as e:
        logger.error(f"Temp file cleanup error: {str(e)}")
        return -1

# VULNERABILITY: More hardcoded secrets in dead code constants
DEAD_CODE_DATABASE_CONFIGS = {
    'production': {
        'host': 'prod-db.company.internal',
        'port': 5432,
        'database': 'main_prod',
        'username': 'prod_user',
        'password': 'Pr0d_P@ssw0rd_2024!',  # Hardcoded production password
        'ssl_mode': 'disable'  # Insecure SSL configuration
    },
    'staging': {
        'host': 'staging-db.company.internal',
        'port': 5432,
        'database': 'main_staging',
        'username': 'staging_user',
        'password': 'St@g1ng_P@ss_123',  # Hardcoded staging password
        'ssl_mode': 'require'
    },
    'development': {
        'host': 'localhost',
        'port': 5432,
        'database': 'main_dev',
        'username': 'dev_user',
        'password': 'dev123',  # Weak development password
        'ssl_mode': 'disable'
    }
}

def execute_raw_sql_unsafe(sql_query: str, db_config: str = 'production') -> List[Dict]:
    """
    DEAD CODE: Execute raw SQL with multiple vulnerabilities.
    This function allows arbitrary SQL execution and is never used.
    """
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        
        # VULNERABILITY: Use hardcoded database credentials
        config = DEAD_CODE_DATABASE_CONFIGS.get(db_config, {})
        
        # VULNERABILITY: Insecure database connection
        conn = psycopg2.connect(
            host=config['host'],
            port=config['port'],
            database=config['database'],
            user=config['username'],
            password=config['password'],
            sslmode=config['ssl_mode']
        )
        
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # VULNERABILITY: Execute arbitrary SQL without validation
        cursor.execute(sql_query)  # Direct SQL execution
        
        if sql_query.strip().upper().startswith('SELECT'):
            results = cursor.fetchall()
            return [dict(row) for row in results]
        else:
            conn.commit()
            return [{'affected_rows': cursor.rowcount}]
        
    except Exception as e:
        logger.error(f"Raw SQL execution failed: {str(e)}")
        # VULNERABILITY: Log potentially sensitive SQL queries
        logger.error(f"Failed query: {sql_query}")
        return []
    finally:
        if 'conn' in locals():
            conn.close()

# Dead code - Never executed migration validation
def validate_deprecated_migration(connection) -> bool:
    """
    DEAD CODE: Validation function that's never called.
    Contains SQL injection vulnerabilities in validation logic.
    """
    try:
        cursor = connection.cursor()
        
        # VULNERABILITY: Dynamic table checking with injection risk
        deprecated_tables = ['legacy_audit', 'old_sessions', 'temp_data']
        
        for table_name in deprecated_tables:
            # VULNERABILITY: Unvalidated table name in query
            check_sql = f"""
            SELECT COUNT(*) FROM information_schema.tables 
            WHERE table_name = '{table_name}'
            AND table_schema = 'public'
            """
            
            cursor.execute(check_sql)
            count = cursor.fetchone()[0]
            
            if count > 0:
                # VULNERABILITY: More SQL injection in record counting
                record_count_sql = f"SELECT COUNT(*) FROM {table_name}"
                cursor.execute(record_count_sql)
                records = cursor.fetchone()[0]
                
                logger.info(f"Deprecated table {table_name} has {records} records")
        
        return True
        
    except Exception as e:
        logger.error(f"Deprecated migration validation failed: {str(e)}")
        return False

"""
DEAD CODE SECTION: Commented out but still contains vulnerabilities
This entire section is commented out but SAST tools should still detect
the vulnerabilities within the comments.

def legacy_password_reset(cursor, user_identifier, new_password):
    # VULNERABILITY: SQL injection in commented dead code
    reset_sql = f'''
    UPDATE users SET 
        password_hash = '{hashlib.md5(new_password.encode()).hexdigest()}',
        updated_at = NOW()
    WHERE username = '{user_identifier}' OR email = '{user_identifier}'
    '''
    cursor.execute(reset_sql)
    
    # VULNERABILITY: Command injection in email notification
    notify_cmd = f"echo 'Password reset for {user_identifier}' | mail -s 'Password Reset' {user_identifier}"
    os.system(notify_cmd)
    
    return True

def backup_user_files(user_id, backup_location):
    # VULNERABILITY: Path traversal and command injection in comments
    user_dir = f"/users/{user_id}/files"
    backup_cmd = f"tar -czf {backup_location}/user_{user_id}_backup.tar.gz {user_dir}"
    subprocess.run(backup_cmd, shell=True)
    
    # VULNERABILITY: Hardcoded FTP credentials in dead code
    ftp_upload_cmd = f"curl -T {backup_location}/user_{user_id}_backup.tar.gz ftp://backup:backup123@ftp.company.com/backups/"
    os.system(ftp_upload_cmd)

def import_user_data_from_xml(xml_file_path):
    # VULNERABILITY: XXE vulnerability in commented code
    import xml.etree.ElementTree as ET
    
    tree = ET.parse(xml_file_path)  # XXE vulnerability
    root = tree.getroot()
    
    for user_elem in root.findall('user'):
        username = user_elem.find('username').text
        email = user_elem.find('email').text
        
        # SQL injection in XML import
        insert_sql = f"INSERT INTO users (username, email) VALUES ('{username}', '{email}')"
        # This would be executed if the code wasn't commented
"""

# Final dead code block with multiple vulnerability types
if __name__ == "__main__":
    # This block never executes but contains vulnerabilities
    
    # VULNERABILITY: Hardcoded sensitive data
    test_config = {
        'database_url': 'postgresql://admin:supersecret@localhost/test',
        'redis_url': 'redis://default:redispass@localhost:6379',
        'secret_key': 'flask_secret_key_12345',
        'api_keys': {
            'stripe': 'sk_test_stripe_key_123',
            'sendgrid': 'SG.test_key_456'
        }
    }
    
    # VULNERABILITY: Command injection in test setup
    setup_cmd = "createdb test_db && psql test_db < schema.sql"
    os.system(setup_cmd)
    
    # VULNERABILITY: Insecure file operations
    test_files = [
        "../../../etc/passwd",  # Path traversal attempt
        "/tmp/test_data.pkl",   # Pickle file for deserialization
        "config/secrets.yaml"   # Configuration file
    ]
    
    for file_path in test_files:
        if os.path.exists(file_path):
            # Process files unsafely
            if file_path.endswith('.pkl'):
                with open(file_path, 'rb') as f:
                    data = pickle.load(f)  # Insecure deserialization
            elif file_path.endswith('.yaml'):
                with open(file_path, 'r') as f:
                    config = yaml.load(f, Loader=yaml.Loader)  # Unsafe YAML
    
    print("Dead code test setup completed")