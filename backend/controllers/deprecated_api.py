"""
Deprecated API Controller - Contains mostly dead code with multiple vulnerabilities
This file represents legacy API endpoints that are no longer in use
All functions here are dead code and should not be detected as live vulnerabilities
"""

import os
import pickle
import subprocess
import hashlib
import base64
import sqlite3
import requests
import xml.etree.ElementTree as ET
from flask import request, jsonify
import yaml
import json

# Dead code - Old authentication system
def legacy_authenticate_user():
    """
    DEAD CODE: Old authentication system with multiple vulnerabilities
    This function is never called in the current application
    """
    username = request.json.get('username')
    password = request.json.get('password')
    
    # VULNERABILITY: Hardcoded credentials
    if username == "admin" and password == "admin123":
        return True
    
    # VULNERABILITY: SQL injection in dead code
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    
    # VULNERABILITY: Weak password hashing
    if result:
        stored_hash = hashlib.md5(password.encode()).hexdigest()
        return stored_hash == result[2]
    
    return False

# Dead code - Commented out API endpoint
"""
def old_user_management_api():
    # DEAD CODE: Legacy user management with privilege escalation
    action = request.json.get('action')
    user_data = request.json.get('user_data')
    
    if action == 'create':
        # VULNERABILITY: Insecure deserialization
        user_obj = pickle.loads(base64.b64decode(user_data))
        
        # VULNERABILITY: Command injection
        os.system(f"useradd {user_obj.username}")
        
    elif action == 'delete':
        # VULNERABILITY: No authorization check
        username = user_data.get('username')
        os.system(f"userdel {username}")
    
    elif action == 'elevate':
        # VULNERABILITY: Privilege escalation
        username = user_data.get('username')
        os.system(f"usermod -aG sudo {username}")
"""

# Dead code - Unreachable conditional
if False:  # This entire block is dead code
    def vulnerable_file_processor():
        """Process files with multiple vulnerabilities"""
        file_path = request.json.get('file_path')
        
        # VULNERABILITY: Path traversal
        full_path = f"/app/files/{file_path}"
        
        # VULNERABILITY: Command injection
        file_type = subprocess.check_output(f"file {full_path}", shell=True)
        
        # VULNERABILITY: Insecure file permissions
        os.chmod(full_path, 0o777)
        
        return file_type.decode()

# Dead code - Old data export functionality
def legacy_export_data():
    """
    DEAD CODE: Old data export with multiple vulnerabilities
    Never called in current application
    """
    export_type = request.args.get('type')
    table_name = request.args.get('table')
    
    # VULNERABILITY: SQL injection
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM {table_name}"
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()
    
    if export_type == 'xml':
        # VULNERABILITY: XXE vulnerability
        xml_data = request.data
        root = ET.fromstring(xml_data)
        
    elif export_type == 'yaml':
        # VULNERABILITY: Insecure YAML loading
        yaml_data = request.data
        config = yaml.load(yaml_data, Loader=yaml.Loader)
    
    # VULNERABILITY: Hardcoded secret
    api_key = "sk-1234567890abcdef"
    
    return jsonify({'data': data, 'key': api_key})

# Dead code - Deprecated webhook handler
class DeprecatedWebhookHandler:
    """
    DEAD CODE: Old webhook handler with multiple vulnerabilities
    This entire class is never instantiated
    """
    
    def __init__(self):
        # VULNERABILITY: Hardcoded credentials
        self.webhook_secret = "webhook123"
        self.admin_token = "admin_token_123"
    
    def handle_webhook(self, webhook_data):
        """Handle incoming webhook with vulnerabilities"""
        # VULNERABILITY: Insecure deserialization
        payload = pickle.loads(base64.b64decode(webhook_data))
        
        # VULNERABILITY: SSRF
        callback_url = payload.get('callback_url')
        if callback_url:
            response = requests.get(callback_url)
        
        # VULNERABILITY: Command injection
        if payload.get('action') == 'deploy':
            branch = payload.get('branch')
            os.system(f"git checkout {branch} && ./deploy.sh")
        
        # VULNERABILITY: Path traversal
        if payload.get('action') == 'backup':
            backup_path = payload.get('path')
            os.system(f"tar -czf /backups/backup.tar.gz {backup_path}")
    
    def validate_signature(self, signature, payload):
        """Validate webhook signature with weak crypto"""
        # VULNERABILITY: Weak cryptographic implementation
        expected = hashlib.md5(payload + self.webhook_secret.encode()).hexdigest()
        return signature == expected

# Dead code - Never instantiated
webhook_handler = None  # DeprecatedWebhookHandler()

# Dead code - Old file upload processor
def legacy_process_upload():
    """
    DEAD CODE: Old file upload processor with multiple vulnerabilities
    This function is never called
    """
    uploaded_file = request.files.get('file')
    if not uploaded_file:
        return jsonify({'error': 'No file uploaded'})
    
    # VULNERABILITY: No file type validation
    filename = uploaded_file.filename
    
    # VULNERABILITY: Path traversal
    upload_path = os.path.join('/app/uploads', filename)
    uploaded_file.save(upload_path)
    
    # VULNERABILITY: Command injection
    if filename.endswith('.zip'):
        os.system(f"unzip {upload_path} -d /app/extracted/")
    elif filename.endswith('.tar.gz'):
        os.system(f"tar -xzf {upload_path} -C /app/extracted/")
    
    # VULNERABILITY: Insecure file permissions
    os.chmod(upload_path, 0o777)
    
    # VULNERABILITY: Information disclosure
    return jsonify({
        'message': 'File uploaded',
        'path': upload_path,
        'system_info': os.uname()
    })

# Dead code - Commented out class
"""
class LegacyAuthManager:
    # DEAD CODE: Old authentication manager
    
    def __init__(self):
        self.secret_key = "super_secret_key_123"
        self.db_password = "db_pass_456"
    
    def authenticate(self, username, password):
        # VULNERABILITY: SQL injection
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        # VULNERABILITY: Hardcoded database credentials
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()
        
        return result is not None
    
    def generate_token(self, user_id):
        # VULNERABILITY: Weak token generation
        token = hashlib.md5(f"{user_id}{self.secret_key}".encode()).hexdigest()
        return token
    
    def reset_password(self, email):
        # VULNERABILITY: Command injection
        os.system(f"echo 'Password reset for {email}' | mail {email}")
"""

# Dead code - Old API versioning
def v1_api_handler():
    """
    DEAD CODE: Version 1 API handler with multiple vulnerabilities
    This API version is no longer supported
    """
    endpoint = request.json.get('endpoint')
    params = request.json.get('params', {})
    
    # VULNERABILITY: Code injection
    if endpoint == 'eval':
        result = eval(params.get('code'))
        return jsonify({'result': result})
    
    # VULNERABILITY: SQL injection
    elif endpoint == 'query':
        conn = sqlite3.connect('api.db')
        cursor = conn.cursor()
        sql = params.get('sql')
        cursor.execute(sql)
        data = cursor.fetchall()
        conn.close()
        return jsonify({'data': data})
    
    # VULNERABILITY: SSRF
    elif endpoint == 'fetch':
        url = params.get('url')
        response = requests.get(url)
        return jsonify({'content': response.text})
    
    # VULNERABILITY: Path traversal
    elif endpoint == 'read':
        filename = params.get('filename')
        with open(f"/app/data/{filename}", 'r') as f:
            content = f.read()
        return jsonify({'content': content})

# Dead code - Never called utility functions
def deprecated_crypto_utils():
    """
    DEAD CODE: Old cryptographic utilities with vulnerabilities
    """
    # VULNERABILITY: Weak random generation
    import random
    key = ''.join([str(random.randint(0, 9)) for _ in range(16)])
    
    # VULNERABILITY: Weak encryption
    def weak_encrypt(data):
        return base64.b64encode(data.encode()).decode()
    
    # VULNERABILITY: Hardcoded IV
    iv = "1234567890123456"
    
    return key, weak_encrypt, iv

# Dead code - Exception handling that's never reached
try:
    # This import will fail, making all code in this block dead
    import nonexistent_module
    
    def vulnerable_data_processor():
        """Process data with multiple vulnerabilities"""
        # VULNERABILITY: Insecure deserialization
        data = request.json.get('serialized_data')
        obj = pickle.loads(base64.b64decode(data))
        
        # VULNERABILITY: Command injection
        if obj.get('action') == 'cleanup':
            path = obj.get('path')
            os.system(f"rm -rf {path}")
        
        return jsonify({'status': 'processed'})
        
except ImportError:
    # All code above is dead due to failed import
    pass

# Dead code - Configuration that's never used
DEPRECATED_CONFIG = {
    'secret_key': 'deprecated_secret_123',  # Hardcoded secret
    'database_url': 'postgresql://admin:admin@localhost/olddb',  # Hardcoded credentials
    'debug_mode': True,  # Insecure configuration
    'allowed_hosts': ['*'],  # Overly permissive
}

# Dead code - Old migration functions
def run_legacy_migrations():
    """
    DEAD CODE: Old database migration with vulnerabilities
    Never called in current application
    """
    migration_file = request.json.get('migration_file')
    
    # VULNERABILITY: Path traversal
    with open(f"/app/migrations/{migration_file}", 'r') as f:
        sql_commands = f.read()
    
    # VULNERABILITY: SQL injection through file content
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.executescript(sql_commands)
    conn.close()
    
    # VULNERABILITY: Command injection
    os.system(f"echo 'Migration {migration_file} completed' >> /var/log/migrations.log")

# Dead code - Cleanup function that's never called
def cleanup_old_sessions():
    """
    DEAD CODE: Session cleanup with vulnerabilities
    """
    # VULNERABILITY: Command injection
    cutoff_date = request.args.get('cutoff_date')
    os.system(f"find /app/sessions -type f -not -newermt '{cutoff_date}' -delete")
    
    # VULNERABILITY: Information disclosure
    return jsonify({
        'message': 'Sessions cleaned',
        'system_load': os.getloadavg(),
        'disk_usage': os.statvfs('/'),
    })

# Dead code - Development helper functions
if os.environ.get('FLASK_ENV') == 'development':
    # This condition is never true in production, making this code dead
    
    def debug_execute_command():
        """
        DEAD CODE: Debug command execution with RCE vulnerability
        """
        # VULNERABILITY: Remote code execution
        command = request.json.get('command')
        result = subprocess.run(command, shell=True, capture_output=True)
        
        return jsonify({
            'stdout': result.stdout.decode(),
            'stderr': result.stderr.decode(),
            'return_code': result.returncode
        })
    
    def debug_read_file():
        """
        DEAD CODE: Debug file reader with path traversal
        """
        # VULNERABILITY: Path traversal
        filename = request.args.get('file')
        with open(filename, 'r') as f:
            return f.read()

# Dead code - Never registered routes
"""
@app.route('/legacy/auth', methods=['POST'])
def legacy_auth_route():
    return legacy_authenticate_user()

@app.route('/legacy/export')
def legacy_export_route():
    return legacy_export_data()

@app.route('/v1/api', methods=['POST'])
def v1_api_route():
    return v1_api_handler()
"""