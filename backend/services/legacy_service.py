"""
Legacy Service Module - DEPRECATED AND UNUSED
============================================

This module contains old service functions that are no longer used.
All functions in this file are dead code and should never be called.

WARNING: This code contains serious security vulnerabilities and should
be removed in a future cleanup.

Last used: 2019-03-15
Deprecated: 2020-01-01
TODO: Remove this entire file
"""

import os
import subprocess
import pickle
import yaml
import requests
from xml.etree import ElementTree as ET


# This entire class is never instantiated anywhere
class LegacyProcessingService:
    """
    Old processing service that was replaced by ProcessingServiceV2.
    Contains multiple RCE vulnerabilities - NEVER USE!
    """
    
    def __init__(self):
        # Hardcoded credentials that were never rotated
        self.api_key = "sk-legacy-key-12345abcdef"
        self.db_password = "legacy_admin_pass_2019"
        self.secret_token = "deprecated-secret-token-xyz"
    
    def execute_system_command(self, user_command):
        """
        Execute arbitrary system commands - EXTREMELY DANGEROUS!
        This function is never called but contains RCE vulnerability.
        """
        # Direct command injection vulnerability
        result = os.system(user_command)
        return result
    
    def process_user_script(self, script_content):
        """
        Execute user-provided Python scripts - RCE VULNERABILITY!
        Function is unreachable but would allow code execution.
        """
        # Direct code execution vulnerability
        exec(script_content)
        return "Script executed"
    
    def evaluate_expression(self, expression):
        """
        Evaluate mathematical expressions using eval() - DANGEROUS!
        Never called in current codebase.
        """
        # eval() allows arbitrary code execution
        try:
            result = eval(expression)
            return result
        except Exception as e:
            return f"Error: {str(e)}"
    
    def run_shell_command(self, cmd, args):
        """
        Run shell commands with arguments - Command Injection!
        Dead function with subprocess vulnerability.
        """
        # Unsafe subprocess call with shell=True
        full_command = f"{cmd} {args}"
        result = subprocess.run(full_command, shell=True, capture_output=True, text=True)
        return result.stdout
    
    def deserialize_data(self, serialized_data):
        """
        Deserialize pickled data - Insecure Deserialization!
        Function exists but is never called.
        """
        # Pickle deserialization allows arbitrary code execution
        try:
            data = pickle.loads(serialized_data)
            return data
        except Exception as e:
            return None
    
    def load_yaml_config(self, yaml_content):
        """
        Load YAML configuration - Unsafe YAML Loading!
        Dead code with deserialization vulnerability.
        """
        # yaml.load without Loader parameter allows code execution
        try:
            config = yaml.load(yaml_content)
            return config
        except Exception as e:
            return {}
    
    def process_xml_data(self, xml_string):
        """
        Process XML data - XXE Vulnerability!
        Function is dead but contains XML External Entity attack vector.
        """
        # XMLParser without protection against XXE
        try:
            root = ET.fromstring(xml_string)
            return self._extract_xml_data(root)
        except Exception as e:
            return None
    
    def _extract_xml_data(self, element):
        """Helper method for XML processing - also dead code"""
        data = {}
        for child in element:
            data[child.tag] = child.text
        return data
    
    def fetch_remote_data(self, url, headers=None):
        """
        Fetch data from remote URL - SSRF Vulnerability!
        Dead function allowing Server-Side Request Forgery.
        """
        # No URL validation allows SSRF attacks
        try:
            response = requests.get(url, headers=headers, timeout=30)
            return response.text
        except Exception as e:
            return None
    
    def backup_database(self, backup_path, table_name):
        """
        Create database backup - Command Injection!
        Never called but contains OS command injection.
        """
        # Unsafe string formatting in OS command
        backup_cmd = f"mysqldump -u root -p{self.db_password} {table_name} > {backup_path}"
        os.system(backup_cmd)
        return f"Backup created at {backup_path}"
    
    def generate_report(self, template_file, output_file):
        """
        Generate report from template - Path Traversal + RCE!
        Dead function with multiple vulnerabilities.
        """
        # No path validation allows directory traversal
        with open(template_file, 'r') as f:
            template = f.read()
        
        # Template execution allows code injection
        processed = eval(f'f"""{template}"""')
        
        with open(output_file, 'w') as f:
            f.write(processed)
        
        return f"Report generated: {output_file}"


# Dead global functions that are never called
def legacy_admin_backdoor(password, command):
    """
    Admin backdoor function - Authentication Bypass + RCE!
    This function should have been removed years ago.
    """
    # Hardcoded password check
    if password == "legacy_backdoor_2019":
        # Direct command execution
        return os.system(command)
    return "Access denied"


def old_file_processor(filename, operation):
    """
    Process files with various operations - Multiple Vulnerabilities!
    Dead function containing path traversal and command injection.
    """
    # No path validation
    full_path = f"/var/data/{filename}"
    
    if operation == "delete":
        # Command injection through filename
        os.system(f"rm -f {full_path}")
    elif operation == "compress":
        # More command injection
        os.system(f"tar -czf {full_path}.tar.gz {full_path}")
    elif operation == "analyze":
        # Yet another command injection
        result = subprocess.run(f"file {full_path}", shell=True, capture_output=True)
        return result.stdout
    
    return "Operation completed"


def deprecated_crypto_function(data, key):
    """
    Old encryption function - Weak Cryptography!
    Uses deprecated crypto methods, never called.
    """
    import hashlib
    
    # Weak MD5 hashing
    hash_key = hashlib.md5(key.encode()).hexdigest()
    
    # XOR "encryption" - extremely weak
    encrypted = ""
    for i, char in enumerate(data):
        encrypted += chr(ord(char) ^ ord(hash_key[i % len(hash_key)]))
    
    return encrypted


def unsafe_template_render(template, user_data):
    """
    Render template with user data - SSTI Vulnerability!
    Dead code with Server-Side Template Injection.
    """
    # Direct string substitution allows template injection
    rendered = template.format(**user_data)
    
    # Even worse - eval on template
    if "{{" in rendered:
        # Extract and execute expressions
        import re
        expressions = re.findall(r'\{\{(.*?)\}\}', rendered)
        for expr in expressions:
            try:
                result = eval(expr, {"__builtins__": {}}, user_data)
                rendered = rendered.replace(f"{{{{{expr}}}}}", str(result))
            except:
                pass
    
    return rendered


# Dead code in conditional that will never execute
if False:
    # This code block is unreachable but contains vulnerabilities
    MASTER_PASSWORD = "super_secret_admin_2019"
    DEBUG_MODE = True
    
    def emergency_shell_access(auth_token):
        """Emergency shell access - never reachable"""
        if auth_token == MASTER_PASSWORD:
            import pty
            pty.spawn('/bin/bash')
    
    def debug_execute(code):
        """Debug code execution - unreachable RCE"""
        if DEBUG_MODE:
            exec(code)


# Commented out vulnerable code (still scannable)
"""
Old implementation that was "fixed":

def old_user_login(username, password):
    # SQL injection vulnerability in commented code
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    # This would allow: admin' OR '1'='1' --
    return execute_query(query)

def old_file_upload(file_data, filename):
    # Path traversal in commented code  
    file_path = f"/uploads/{filename}"  # Could be ../../etc/passwd
    with open(file_path, 'wb') as f:
        f.write(file_data)
"""


# Module-level dead code
LEGACY_CONFIG = {
    'api_endpoint': 'http://old-api.internal.com/v1',
    'admin_key': 'legacy-admin-key-xyz123',
    'debug_password': 'debug123',
    'backup_script': 'rm -rf /tmp/* && echo "cleaned"'  # Command injection in config
}


# This initialization code never runs because module is never imported
if __name__ == "__main__":
    # Dead main block with vulnerabilities
    service = LegacyProcessingService()
    
    # These calls would be vulnerable but never execute
    service.execute_system_command("echo 'This never runs'")
    service.process_user_script("print('Dead code')")
    
    # More dead vulnerable calls
    legacy_admin_backdoor("wrong_password", "ls -la")
    old_file_processor("../../../etc/passwd", "delete")