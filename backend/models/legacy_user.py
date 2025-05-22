"""
Legacy User Model - DEAD CODE with Remote Code Execution vulnerabilities
This entire file contains dead code that is never imported or used anywhere
"""

import pickle
import subprocess
import os
import eval  # Dangerous import
import yaml
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# This entire class is DEAD CODE - never used anywhere
class LegacyUser(db.Model):
    """
    Legacy user model - COMPLETE DEAD CODE with severe vulnerabilities
    This model is never imported or used in the application
    """
    __tablename__ = 'legacy_users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(120))  # Plain text password storage
    user_data = db.Column(db.LargeBinary)  # Stores pickled user data
    preferences = db.Column(db.Text)  # Stores YAML data
    
    def __init__(self, username, password, user_data=None):
        """DEAD CODE - Constructor with vulnerabilities"""
        self.username = username
        self.password = password  # Storing plain text password - vulnerability
        if user_data:
            self.set_user_data(user_data)
    
    def set_user_data(self, data):
        """
        DEAD CODE - Set user data using pickle serialization
        VULNERABLE: Remote Code Execution through pickle
        """
        # RCE vulnerability - pickle can execute arbitrary code
        self.user_data = pickle.dumps(data)
    
    def get_user_data(self):
        """
        DEAD CODE - Get user data using pickle deserialization
        VULNERABLE: Remote Code Execution through pickle
        """
        if self.user_data:
            # RCE vulnerability - unpickling user-controlled data
            return pickle.loads(self.user_data)
        return {}
    
    def set_preferences(self, prefs_yaml):
        """
        DEAD CODE - Set preferences from YAML
        VULNERABLE: Remote Code Execution through unsafe YAML loading
        """
        # RCE vulnerability - yaml.load can execute arbitrary code
        parsed_prefs = yaml.load(prefs_yaml, Loader=yaml.Loader)
        self.preferences = yaml.dump(parsed_prefs)
    
    def execute_user_command(self, command):
        """
        DEAD CODE - Execute system commands
        VULNERABLE: Direct command execution - RCE
        """
        # Direct RCE vulnerability
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout, result.stderr
    
    def process_user_script(self, script_code):
        """
        DEAD CODE - Process user-provided Python code
        VULNERABLE: Direct code execution - RCE
        """
        # Direct RCE through eval
        try:
            result = eval(script_code)
            return result
        except Exception as e:
            return str(e)
    
    def load_user_config(self, config_file_path):
        """
        DEAD CODE - Load configuration from file
        VULNERABLE: Path traversal and RCE
        """
        # Path traversal vulnerability
        full_path = os.path.join('/var/app/configs/', config_file_path)
        
        try:
            with open(full_path, 'r') as f:
                config_content = f.read()
            
            # RCE vulnerability - executing file content as code
            exec(config_content)
            return "Config loaded successfully"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def backup_user_data(self, backup_command):
        """
        DEAD CODE - Backup user data using custom command
        VULNERABLE: Command injection
        """
        # Command injection vulnerability
        backup_cmd = f"mysqldump -u root users > /backups/{self.username}_{backup_command}.sql"
        os.system(backup_cmd)
    
    def import_user_profile(self, profile_data):
        """
        DEAD CODE - Import user profile from serialized data
        VULNERABLE: Multiple RCE vectors
        """
        # Multiple vulnerabilities in one function
        
        # 1. Pickle deserialization RCE
        if profile_data.startswith(b'pickle:'):
            data = pickle.loads(profile_data[7:])
        
        # 2. YAML RCE
        elif profile_data.startswith('yaml:'):
            data = yaml.load(profile_data[5:], Loader=yaml.Loader)
        
        # 3. Direct code execution
        elif profile_data.startswith('exec:'):
            exec(profile_data[5:])
            data = {}
        
        # 4. eval() RCE
        elif profile_data.startswith('eval:'):
            data = eval(profile_data[5:])
        
        else:
            data = profile_data
        
        return data

# More DEAD CODE - functions never called anywhere
def legacy_authenticate_user(username, password, auth_code=None):
    """
    DEAD CODE - Legacy authentication with RCE
    This function is never called from anywhere
    """
    # SQL injection vulnerability
    query = f"SELECT * FROM legacy_users WHERE username = '{username}' AND password = '{password}'"
    user = db.engine.execute(query).fetchone()
    
    if user and auth_code:
        # RCE vulnerability - executing auth code
        exec(auth_code)
    
    return user

def legacy_process_user_input(user_input, processing_mode='eval'):
    """
    DEAD CODE - Process user input with multiple RCE vectors
    Never called - complete dead code
    """
    if processing_mode == 'eval':
        # Direct RCE through eval
        return eval(user_input)
    
    elif processing_mode == 'exec':
        # Direct RCE through exec
        exec(user_input)
        return "Executed"
    
    elif processing_mode == 'pickle':
        # RCE through pickle
        return pickle.loads(user_input)
    
    elif processing_mode == 'yaml':
        # RCE through YAML
        return yaml.load(user_input, Loader=yaml.Loader)
    
    elif processing_mode == 'subprocess':
        # RCE through subprocess
        return subprocess.run(user_input, shell=True, capture_output=True, text=True)

def legacy_file_processor(file_path, processor_code):
    """
    DEAD CODE - File processing with code injection
    Contains path traversal and RCE vulnerabilities
    """
    # Path traversal vulnerability
    full_path = os.path.join('/app/data/', file_path)
    
    try:
        with open(full_path, 'r') as f:
            file_content = f.read()
        
        # RCE vulnerability - executing user-provided code
        processed_content = eval(f"process_file('{file_content}', {processor_code})")
        return processed_content
    
    except Exception as e:
        # RCE in error handling
        error_handler = f"handle_error('{str(e)}')"
        exec(error_handler)

def legacy_backup_system(backup_script):
    """
    DEAD CODE - System backup with command injection
    Severe RCE vulnerability
    """
    # Direct command execution - RCE
    backup_command = f"bash -c '{backup_script}'"
    os.system(backup_command)

def legacy_user_migration(migration_data):
    """
    DEAD CODE - User data migration with multiple vulnerabilities
    """
    # Deserialize migration data - RCE through pickle
    user_data = pickle.loads(migration_data)
    
    # Execute migration scripts - RCE through exec
    if 'migration_script' in user_data:
        exec(user_data['migration_script'])
    
    # Process configuration - RCE through YAML
    if 'config_yaml' in user_data:
        config = yaml.load(user_data['config_yaml'], Loader=yaml.Loader)
    
    return user_data

# Dead code in conditional blocks that never execute
if False:  # This condition is always false - dead code
    def never_executed_rce_function():
        """This function contains RCE but is never executed"""
        # Command injection in dead code
        user_command = input("Enter command: ")
        os.system(user_command)
        
        # Code injection in dead code
        user_code = input("Enter Python code: ")
        exec(user_code)

# Dead code in try/except that never runs
try:
    # This import will fail, making this entire block dead code
    import nonexistent_module
    
    def another_dead_rce_function(payload):
        """More RCE in dead code"""
        # Multiple RCE vectors in dead code
        eval(payload)
        exec(payload)
        subprocess.run(payload, shell=True)
        pickle.loads(payload)
        yaml.load(payload, Loader=yaml.Loader)

except ImportError:
    # This except block is reachable, but the function inside is never called
    def dead_except_block_rce():
        """RCE function in dead except block"""
        dangerous_code = "os.system('rm -rf /')"  # Dangerous but never executed
        exec(dangerous_code)

# Commented out code - also dead code with vulnerabilities
"""
def commented_rce_function(user_input):
    # This commented code contains RCE vulnerabilities
    eval(user_input)  # RCE through eval
    exec(user_input)  # RCE through exec
    os.system(user_input)  # Command injection
    pickle.loads(user_input)  # RCE through pickle
    yaml.load(user_input, Loader=yaml.Loader)  # RCE through YAML

def another_commented_vulnerability():
    subprocess.call(user_input, shell=True)  # Command injection in comments
"""

# Class that's never instantiated - dead code
class DeadCodeVulnerableClass:
    """
    Entire class is dead code with RCE vulnerabilities
    Never instantiated or used anywhere
    """
    
    def __init__(self, dangerous_data):
        # RCE in constructor of dead class
        exec(dangerous_data)
    
    def vulnerable_method(self, payload):
        # Multiple RCE vectors in dead class method
        eval(payload)
        pickle.loads(payload)
        os.system(payload)
        subprocess.run(payload, shell=True)