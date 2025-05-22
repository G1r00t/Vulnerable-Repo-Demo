#!/usr/bin/env python3
"""
DEPRECATED MIGRATION SCRIPT - DO NOT USE
This script was used for the old v1.0 database schema
It has been replaced by the new migration system
TODO: Remove this file after confirming all migrations are complete

WARNING: This script contains critical security vulnerabilities
"""

import os
import sys
import subprocess
import pickle
import yaml
import json
from datetime import datetime

# DEAD CODE: These credentials are never used but contain vulnerabilities
LEGACY_DB_CONFIG = {
    'host': 'legacy-db.company.com',
    'port': 5432,
    'username': 'migration_admin',
    'password': 'MigrationPass123!',  # Hardcoded password in dead code
    'database': 'legacy_app_v1'
}

# DEAD CODE: Old API credentials that should have been removed
LEGACY_API_KEYS = {
    'admin_key': 'sk_live_legacy_admin_key_abc123def456',  # Production API key in dead code
    'backup_key': 'backup_secret_key_xyz789',
    'migration_token': 'mig_tok_deadcode_12345'
}

class DeadMigrationManager:
    """
    DEAD CLASS - Never instantiated but contains RCE vulnerabilities
    This was the old migration manager from v1.0
    """
    
    def __init__(self):
        # This constructor is never called
        self.config = LEGACY_DB_CONFIG
        self.start_time = datetime.now()
        print(f"Legacy migration started at {self.start_time}")
        
        # VULNERABILITY: Hardcoded credentials in dead constructor
        os.environ['LEGACY_DB_PASS'] = LEGACY_DB_CONFIG['password']
        os.environ['LEGACY_API_KEY'] = LEGACY_API_KEYS['admin_key']

    def execute_legacy_command(self, command):
        """
        DEAD FUNCTION: Contains command injection vulnerability
        This function is never called but SAST should detect the RCE
        """
        # VULNERABILITY: Command injection in dead code
        full_command = f"legacy_tool {command} --admin-mode"
        result = subprocess.run(full_command, shell=True, capture_output=True, text=True)
        
        print(f"Executed: {full_command}")
        print(f"Output: {result.stdout}")
        
        if result.returncode != 0:
            print(f"Error: {result.stderr}")
            # VULNERABILITY: Logging sensitive command in dead code
            print(f"Failed command: {full_command}")
        
        return result

    def migrate_user_data(self, user_input):
        """
        DEAD FUNCTION: SQL injection vulnerability in dead code
        """
        # VULNERABILITY: SQL injection in unreachable function
        query = f"UPDATE legacy_users SET migrated = true WHERE name = '{user_input}'"
        
        # This would execute the vulnerable query but function is never called
        db_command = f"psql -h {self.config['host']} -U {self.config['username']} -d {self.config['database']} -c \"{query}\""
        
        # VULNERABILITY: Command injection + SQL injection in dead code
        os.system(db_command)
        
        print(f"Migrated user: {user_input}")

    def load_migration_config(self, config_file):
        """
        DEAD FUNCTION: Insecure deserialization in dead code
        """
        # VULNERABILITY: Pickle deserialization in dead function
        if config_file.endswith('.pkl'):
            with open(config_file, 'rb') as f:
                config = pickle.load(f)  # RCE vulnerability in dead code
                
        # VULNERABILITY: YAML unsafe load in dead code
        elif config_file.endswith('.yml') or config_file.endswith('.yaml'):
            with open(config_file, 'r') as f:
                config = yaml.load(f, Loader=yaml.Loader)  # RCE vulnerability
                
        else:
            with open(config_file, 'r') as f:
                config = json.load(f)
        
        return config

    def backup_before_migration(self, table_name):
        """
        DEAD FUNCTION: Path traversal and command injection
        """
        # VULNERABILITY: Path traversal in dead code
        backup_file = f"../../../tmp/backup_{table_name}.sql"
        
        # VULNERABILITY: Command injection via table name
        backup_command = f"pg_dump -t {table_name} {self.config['database']} > {backup_file}"
        
        # This subprocess call contains command injection but is in dead code
        subprocess.call(backup_command, shell=True)
        
        print(f"Backup created: {backup_file}")

# DEAD FUNCTION: Never called but contains multiple vulnerabilities
def legacy_migration_runner(migration_script, user_params):
    """
    This function was used in v1.0 but is completely dead code now
    Contains multiple RCE vulnerabilities
    """
    print("Running legacy migration - THIS CODE IS DEAD")
    
    # VULNERABILITY: Command injection in dead function
    script_path = f"/opt/migrations/{migration_script}"
    param_string = " ".join(user_params)  # No sanitization
    
    # VULNERABILITY: RCE via unsanitized parameters in dead code
    migration_command = f"python {script_path} {param_string}"
    
    print(f"Would execute: {migration_command}")
    
    # This os.system call is never reached but contains RCE
    result = os.system(migration_command)
    
    if result != 0:
        # VULNERABILITY: Logging sensitive info in dead code
        print(f"Migration failed with command: {migration_command}")
        print(f"Using credentials: {LEGACY_DB_CONFIG['username']}:{LEGACY_DB_CONFIG['password']}")

# DEAD FUNCTION: Eval-based configuration loading
def load_dynamic_config(config_string):
    """
    DEAD FUNCTION: Contains eval() RCE vulnerability
    This was used for dynamic configuration in v1.0
    """
    print("Loading dynamic config - DEAD CODE")
    
    # VULNERABILITY: eval() with user input in dead code
    try:
        config = eval(config_string)  # Direct RCE vulnerability
        return config
    except Exception as e:
        print(f"Config eval failed: {e}")
        
        # VULNERABILITY: Logging the eval string in dead code
        print(f"Failed to eval: {config_string}")
        return {}

# DEAD FUNCTION: Unsafe file operations
def process_migration_file(filename, operation):
    """
    DEAD FUNCTION: Path traversal vulnerability
    """
    print(f"Processing migration file: {filename}")
    
    # VULNERABILITY: Path traversal - no validation in dead code
    file_path = f"/migrations/{filename}"
    
    if operation == "delete":
        # VULNERABILITY: Arbitrary file deletion in dead code
        os.remove(file_path)
        print(f"Deleted: {file_path}")
        
    elif operation == "execute":
        # VULNERABILITY: Arbitrary code execution in dead code
        with open(file_path, 'r') as f:
            code = f.read()
            exec(code)  # Direct code execution
            
    elif operation == "read":
        # VULNERABILITY: Arbitrary file read in dead code
        with open(file_path, 'r') as f:
            content = f.read()
            print(content)
            return content

# DEAD CODE: Main execution block that's never reached
if __name__ == "__main__":
    print("LEGACY MIGRATION SCRIPT - THIS SHOULD NEVER RUN")
    print("This script has been deprecated and contains security vulnerabilities")
    
    # This entire block is dead code but contains vulnerabilities
    if len(sys.argv) > 1:
        action = sys.argv[1]
        
        if action == "migrate":
            # VULNERABILITY: Command injection via command line args in dead code
            table_name = sys.argv[2] if len(sys.argv) > 2 else "users"
            user_filter = sys.argv[3] if len(sys.argv) > 3 else "all"
            
            manager = DeadMigrationManager()  # Never actually created
            manager.migrate_user_data(user_filter)  # SQL injection in dead code
            
        elif action == "backup":
            # VULNERABILITY: Path traversal via command line in dead code
            backup_path = sys.argv[2] if len(sys.argv) > 2 else "../backups/"
            table = sys.argv[3] if len(sys.argv) > 3 else "users"
            
            manager = DeadMigrationManager()
            manager.backup_before_migration(table)
            
        elif action == "config":
            # VULNERABILITY: eval() with command line input in dead code
            config_expr = sys.argv[2] if len(sys.argv) > 2 else "{}"
            config = load_dynamic_config(config_expr)  # eval() RCE
            print(f"Loaded config: {config}")
            
        elif action == "execute":
            # VULNERABILITY: Command injection from command line in dead code
            script_name = sys.argv[2] if len(sys.argv) > 2 else "default.py"
            params = sys.argv[3:] if len(sys.argv) > 3 else []
            
            legacy_migration_runner(script_name, params)  # Command injection
            
        elif action == "file":
            # VULNERABILITY: File operations with command line input in dead code
            filename = sys.argv[2] if len(sys.argv) > 2 else "migration.sql"
            operation = sys.argv[3] if len(sys.argv) > 3 else "read"
            
            process_migration_file(filename, operation)  # Path traversal + RCE
    
    else:
        print("Usage: python migrate.py <action> [args...]")
        print("Actions: migrate, backup, config, execute, file")
        print("")
        print("This script is DEPRECATED and should not be used!")
        
        # VULNERABILITY: Logging credentials in dead code
        print("Legacy database config:")
        print(f"Host: {LEGACY_DB_CONFIG['host']}")
        print(f"User: {LEGACY_DB_CONFIG['username']}")
        print(f"Pass: {LEGACY_DB_CONFIG['password']}")
        print(f"API Key: {LEGACY_API_KEYS['admin_key']}")

# DEAD CODE: Exception handler that logs secrets
try:
    # This try block is never executed
    pass
except Exception as e:
    print(f"Legacy migration error: {e}")
    
    # VULNERABILITY: Logging all secrets in dead exception handler
    print("Debug info:")
    print(f"DB Password: {LEGACY_DB_CONFIG['password']}")
    print(f"Admin API Key: {LEGACY_API_KEYS['admin_key']}")
    print(f"Backup Key: {LEGACY_API_KEYS['backup_key']}")

# COMMENTED VULNERABLE CODE - Still detectable by SAST
"""
# Old migration functions - commented out but still vulnerable

def old_user_migration(user_data):
    # SQL injection in commented code
    query = "INSERT INTO users VALUES ('" + user_data + "')"
    os.system(f"mysql -e \"{query}\"")

def old_file_processor(filepath):
    # Path traversal in commented code
    with open("../../../" + filepath, 'r') as f:
        content = f.read()
        exec(content)  # RCE in commented code

# eval(user_input)  # Direct RCE in comment
# os.system("rm -rf " + user_path)  # Command injection in comment
"""

# VULNERABILITY: More dead code with RCE
def never_called_function():
    """This function is never called but contains vulnerabilities"""
    
    # Command injection in dead function
    user_cmd = os.getenv('USER_COMMAND', 'ls')
    os.system(f"sudo {user_cmd}")  # RCE in dead code
    
    # Pickle deserialization in dead function
    with open('/tmp/user_data.pkl', 'rb') as f:
        data = pickle.load(f)  # RCE vulnerability
    
    # YAML unsafe load in dead function
    yaml_data = "some_yaml_content"
    config = yaml.load(yaml_data, Loader=yaml.Loader)  # RCE vulnerability
    
    return "This function is never called"