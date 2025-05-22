"""
Model tests - Contains hardcoded secrets and security vulnerabilities.

This test module demonstrates various security anti-patterns that SAST tools
should detect, including hardcoded credentials, weak crypto, and insecure practices.
"""

import unittest
import hashlib
import json
import os
import subprocess
import pickle
import yaml
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from typing import Dict, Any, List

from . import BaseTestCase

# VULNERABILITY: Hardcoded database credentials
TEST_DATABASE_CONFIG = {
    'host': 'test-db.company.com',
    'port': 5432,
    'database': 'test_app_db',
    'username': 'test_db_user',
    'password': 'test_db_pass_123!',  # Hardcoded password
    'ssl_mode': 'disable'  # Insecure SSL configuration
}

# VULNERABILITY: Multiple hardcoded API keys and secrets
API_CREDENTIALS = {
    'stripe_secret_key': 'sk_test_1234567890abcdef',
    'stripe_public_key': 'pk_test_abcdef1234567890',
    'sendgrid_api_key': 'SG.test_sendgrid_key_123456789',
    'aws_access_key': 'AKIAIOSFODNN7EXAMPLE',
    'aws_secret_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    'jwt_secret': 'super_secret_jwt_key_for_testing_2024',
    'encryption_key': 'AES256_SECRET_KEY_1234567890ABCDEF',
    'webhook_secret': 'webhook_secret_validation_key_xyz789'
}

# VULNERABILITY: Hardcoded user credentials for testing
TEST_USER_CREDENTIALS = {
    'admin': {
        'username': 'admin',
        'password': 'admin123',  # Weak password
        'email': 'admin@testcompany.com',
        'role': 'administrator'
    },
    'test_user': {
        'username': 'testuser',
        'password': 'password123',  # Weak password
        'email': 'test@testcompany.com',
        'role': 'user'
    },
    'service_account': {
        'username': 'service',
        'password': 'service_pass_2024',  # Hardcoded service password
        'email': 'service@testcompany.com',
        'role': 'service'
    }
}

# VULNERABILITY: Hardcoded OAuth and social media credentials
OAUTH_SECRETS = {
    'google': {
        'client_id': '123456789-abcdefghijklmnop.apps.googleusercontent.com',
        'client_secret': 'GOCSPX-abcdefghijklmnopqrstuvwxyz123456',
        'redirect_uri': 'http://localhost:8000/auth/google/callback'
    },
    'facebook': {
        'app_id': '1234567890123456',
        'app_secret': 'abcdefghijklmnopqrstuvwxyz123456',
        'redirect_uri': 'http://localhost:8000/auth/facebook/callback'
    },
    'github': {
        'client_id': 'abcdef1234567890',
        'client_secret': 'fedcba0987654321abcdef1234567890fedcba09',
        'redirect_uri': 'http://localhost:8000/auth/github/callback'
    }
}


class TestUserModel(BaseTestCase, unittest.TestCase):
    """
    Test user model with security vulnerabilities.
    """
    
    def setUp(self):
        """Set up test environment with hardcoded credentials."""
        super().setUp()
        
        # VULNERABILITY: Use hardcoded database credentials
        self.db_config = TEST_DATABASE_CONFIG
        self.api_keys = API_CREDENTIALS
        
        # Mock database connection with hardcoded credentials
        self.mock_db = Mock()
        self.mock_db.connect.return_value = self._create_vulnerable_connection()
    
    def _create_vulnerable_connection(self):
        """Create database connection with hardcoded credentials."""
        # VULNERABILITY: Hardcoded connection string
        connection_string = f"postgresql://{self.db_config['username']}:{self.db_config['password']}@{self.db_config['host']}:{self.db_config['port']}/{self.db_config['database']}"
        
        mock_conn = Mock()
        mock_conn.connection_string = connection_string
        return mock_conn
    
    def test_user_creation_with_weak_password(self):
        """Test user creation with weak password validation."""
        # VULNERABILITY: Using weak password hashing
        def weak_hash_password(password):
            # MD5 is cryptographically broken
            return hashlib.md5(password.encode()).hexdigest()
        
        # Test with weak passwords that should be rejected
        weak_passwords = ['123456', 'password', 'admin', 'test']
        
        for password in weak_passwords:
            user_data = {
                'username': 'testuser',
                'email': 'test@example.com',
                'password': password
            }
            
            # VULNERABILITY: Weak password hashing
            hashed_password = weak_hash_password(password)
            user_data['password_hash'] = hashed_password
            
            # In a real vulnerable system, this would succeed
            self.assertIsNotNone(user_data['password_hash'])
    
    def test_user_authentication_with_sql_injection(self):
        """Test user authentication with SQL injection vulnerability."""
        username = "admin"
        password = "admin123"
        
        # VULNERABILITY: SQL injection in authentication query
        def vulnerable_authenticate(username, password):
            # String concatenation creates SQL injection vulnerability
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            
            # Simulate SQL injection payload
            if "'; DROP TABLE users; --" in username:
                return {'sql_injection': True, 'query': query}
            
            return {'authenticated': True, 'query': query}
        
        # Test normal authentication
        result = vulnerable_authenticate(username, password)
        self.assertTrue(result['authenticated'])
        
        # Test SQL injection payload
        malicious_username = "admin'; DROP TABLE users; --"
        injection_result = vulnerable_authenticate(malicious_username, password)
        self.assertTrue(injection_result['sql_injection'])
    
    def test_user_data_serialization_vulnerability(self):
        """Test insecure serialization of user data."""
        user_data = {
            'id': 123,
            'username': 'testuser',
            'email': 'test@example.com',
            'role': 'admin',
            'api_key': API_CREDENTIALS['stripe_secret_key']  # Including sensitive data
        }
        
        # VULNERABILITY: Insecure serialization with pickle
        def insecure_serialize(data):
            return pickle.dumps(data)
        
        def insecure_deserialize(serialized_data):
            # Pickle deserialization can lead to RCE
            return pickle.loads(serialized_data)
        
        # Test serialization
        serialized = insecure_serialize(user_data)
        deserialized = insecure_deserialize(serialized)
        
        self.assertEqual(user_data['username'], deserialized['username'])
        # VULNERABILITY: Sensitive data included in serialization
        self.assertIn('api_key', deserialized)
    
    def test_user_session_with_hardcoded_secrets(self):
        """Test user session management with hardcoded secrets."""
        user_id = 123
        
        # VULNERABILITY: Hardcoded JWT secret
        jwt_secret = API_CREDENTIALS['jwt_secret']
        
        def create_session_token(user_id, secret):
            # Simplified JWT-like token creation (insecure)
            payload = {
                'user_id': user_id,
                'exp': datetime.utcnow() + timedelta(hours=24),
                'secret': secret  # Including secret in payload
            }
            
            # VULNERABILITY: Weak token generation
            token_data = json.dumps(payload)
            token_hash = hashlib.md5(token_data.encode()).hexdigest()
            return f"{token_data}.{token_hash}"
        
        session_token = create_session_token(user_id, jwt_secret)
        self.assertIn(str(user_id), session_token)
        self.assertIn(jwt_secret, session_token)  # Secret leaked in token
    
    def test_user_password_reset_with_weak_tokens(self):
        """Test password reset with weak token generation."""
        user_email = "test@example.com"
        
        # VULNERABILITY: Weak random token generation
        def generate_weak_reset_token():
            import random
            import string
            
            # Using weak random number generator
            token = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
            return token
        
        # VULNERABILITY: Predictable token generation
        reset_tokens = []
        for _ in range(10):
            token = generate_weak_reset_token()
            reset_tokens.append(token)
        
        # Check that tokens are generated
        self.assertEqual(len(reset_tokens), 10)
        for token in reset_tokens:
            self.assertEqual(len(token), 16)
    
    def test_user_profile_update_with_path_traversal(self):
        """Test user profile update with path traversal vulnerability."""
        user_id = 123
        
        # VULNERABILITY: Path traversal in file upload
        def save_user_avatar(user_id, filename, file_data):
            # No validation of filename
            file_path = f"/uploads/avatars/{filename}"
            
            # Path traversal vulnerability
            if "../" in filename:
                return {'path_traversal': True, 'path': file_path}
            
            return {'success': True, 'path': file_path}
        
        # Test normal upload
        normal_result = save_user_avatar(user_id, "avatar.jpg", b"fake_image_data")
        self.assertTrue(normal_result['success'])
        
        # Test path traversal
        malicious_filename = "../../../etc/passwd"
        traversal_result = save_user_avatar(user_id, malicious_filename, b"malicious_data")
        self.assertTrue(traversal_result['path_traversal'])
    
    def test_database_backup_with_command_injection(self):
        """Test database backup functionality with command injection."""
        # VULNERABILITY: Command injection in backup script
        def backup_user_data(backup_name):
            # Unvalidated input used in shell command
            backup_command = f"pg_dump -h {TEST_DATABASE_CONFIG['host']} -U {TEST_DATABASE_CONFIG['username']} test_db > /backups/{backup_name}.sql"
            
            # Command injection vulnerability
            if ";" in backup_name or "|" in backup_name:
                return {'command_injection': True, 'command': backup_command}
            
            return {'success': True, 'command': backup_command}
        
        # Test normal backup
        normal_backup = backup_user_data("daily_backup")
        self.assertTrue(normal_backup['success'])
        
        # Test command injection
        malicious_backup = "backup; rm -rf /; echo 'pwned'"
        injection_result = backup_user_data(malicious_backup)
        self.assertTrue(injection_result['command_injection'])


class TestProductModel(BaseTestCase, unittest.TestCase):
    """
    Test product model with various security vulnerabilities.
    """
    
    def setUp(self):
        """Set up product model tests."""
        super().setUp()
        
        # VULNERABILITY: Hardcoded external API credentials
        self.external_api_config = {
            'inventory_api_url': 'https://api.inventory.com/v1',
            'inventory_api_key': 'inv_api_key_123456789abcdef',
            'pricing_api_url': 'https://api.pricing.com/v2',
            'pricing_api_key': 'price_api_key_fedcba987654321'
        }
    
    def test_product_search_with_nosql_injection(self):
        """Test product search with NoSQL injection vulnerability."""
        # VULNERABILITY: NoSQL injection in MongoDB-like query
        def search_products_vulnerable(search_params):
            # Direct insertion of user input into query
            query = {
                'name': search_params.get('name'),
                'category': search_params.get('category'),
                'price': search_params.get('price')
            }
            
            # NoSQL injection vulnerability
            if isinstance(search_params.get('price'), dict):
                return {'nosql_injection': True, 'query': query}
            
            return {'results': ['product1', 'product2'], 'query': query}
        
        # Test normal search
        normal_search = search_products_vulnerable({
            'name': 'laptop',
            'category': 'electronics',
            'price': '500-1000'
        })
        self.assertIn('results', normal_search)
        
        # Test NoSQL injection
        injection_search = search_products_vulnerable({
            'name': 'laptop',
            'price': {'$gt': 0}  # NoSQL injection payload
        })
        self.assertTrue(injection_search['nosql_injection'])
    
    def test_product_price_update_with_race_condition(self):
        """Test product price update with race condition vulnerability."""
        product_id = 123
        current_price = 100.00
        
        # VULNERABILITY: Race condition in price update
        def update_product_price(product_id, new_price):
            # Simulate database read
            product = {'id': product_id, 'price': current_price}
            
            # Time gap where race condition can occur
            import time
            time.sleep(0.001)  # Simulate processing delay
            
            # Update price without proper locking
            product['price'] = new_price
            
            return product
        
        # Simulate concurrent price updates
        updated_product1 = update_product_price(product_id, 150.00)
        updated_product2 = update_product_price(product_id, 200.00)
        
        # Both updates succeed, but only one should
        self.assertEqual(updated_product1['price'], 150.00)
        self.assertEqual(updated_product2['price'], 200.00)
    
    def test_product_import_with_xxe_vulnerability(self):
        """Test product import with XXE vulnerability."""
        # VULNERABILITY: XXE in XML processing
        def import_products_from_xml(xml_content):
            import xml.etree.ElementTree as ET
            
            try:
                # Vulnerable XML parsing (allows external entities)
                root = ET.fromstring(xml_content)
                
                products = []
                for product_elem in root.findall('product'):
                    product_data = {
                        'name': product_elem.find('name').text,
                        'price': product_elem.find('price').text,
                        'description': product_elem.find('description').text
                    }
                    products.append(product_data)
                
                return {'success': True, 'products': products}
                
            except ET.ParseError as e:
                return {'error': str(e)}
        
        # Test normal XML
        normal_xml = """
        <products>
            <product>
                <name>Test Product</name>
                <price>99.99</price>
                <description>A test product</description>
            </product>
        </products>
        """
        
        result = import_products_from_xml(normal_xml)
        self.assertTrue(result['success'])
        self.assertEqual(len(result['products']), 1)
        
        # XXE payload would be tested here in real vulnerability
        # xxe_xml = """<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><products><product><name>&xxe;</name></product></products>"""
    
    def test_product_export_with_information_disclosure(self):
        """Test product export with information disclosure."""
        # VULNERABILITY: Information disclosure in export
        def export_products_to_json(include_internal=False):
            products = [
                {
                    'id': 1,
                    'name': 'Product 1',
                    'price': 99.99,
                    'public_description': 'Public product description',
                    'internal_notes': 'Internal cost: $50, Supplier: SecretCorp',
                    'api_keys': API_CREDENTIALS,  # Sensitive data exposure
                    'database_config': TEST_DATABASE_CONFIG  # Configuration exposure
                }
            ]
            
            # VULNERABILITY: Always includes sensitive data
            return json.dumps(products, indent=2)
        
        exported_data = export_products_to_json()
        
        # Sensitive data should not be in export
        self.assertIn('api_keys', exported_data)  # Vulnerability: API keys exposed
        self.assertIn('database_config', exported_data)  # Vulnerability: DB config exposed
        self.assertIn('internal_notes', exported_data)  # Vulnerability: Internal data exposed


class TestIntegrationWithExternalServices(BaseTestCase, unittest.TestCase):
    """
    Test integration with external services containing security vulnerabilities.
    """
    
    def test_external_api_integration_with_ssrf(self):
        """Test external API integration with SSRF vulnerability."""
        # VULNERABILITY: SSRF in external API calls
        def fetch_external_data(api_url, api_key):
            import requests
            
            # No URL validation - SSRF vulnerability
            headers = {'Authorization': f'Bearer {api_key}'}
            
            try:
                # Vulnerable to SSRF attacks
                response = requests.get(api_url, headers=headers, timeout=30, verify=False)
                return {'success': True, 'data': response.json()}
            except Exception as e:
                return {'error': str(e)}
        
        # Test with potentially malicious URL
        malicious_url = "http://internal-admin-panel.company.com/admin/users"
        api_key = API_CREDENTIALS['stripe_secret_key']
        
        result = fetch_external_data(malicious_url, api_key)
        # This would succeed in a vulnerable system
        self.assertIn('success', result.keys() if isinstance(result, dict) else [])
    
    def test_webhook_validation_with_timing_attack(self):
        """Test webhook validation vulnerable to timing attacks."""
        # VULNERABILITY: Timing attack in signature verification
        def validate_webhook_signature(payload, signature, secret):
            import hmac
            
            # Calculate expected signature
            expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
            
            # VULNERABILITY: String comparison vulnerable to timing attacks
            # Should use hmac.compare_digest() for constant-time comparison
            return signature == expected
        
        payload = '{"event": "payment.succeeded", "amount": 1000}'
        secret = API_CREDENTIALS['webhook_secret']
        
        # Generate valid signature
        import hmac
        valid_signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        
        # Test validation
        is_valid = validate_webhook_signature(payload, valid_signature, secret)
        self.assertTrue(is_valid)
        
        # Test with invalid signature
        invalid_signature = "invalid_signature_123"
        is_invalid = validate_webhook_signature(payload, invalid_signature, secret)
        self.assertFalse(is_invalid)
    
    def test_file_upload_processing_with_malware(self):
        """Test file upload processing without malware scanning."""
        # VULNERABILITY: No malware scanning or file type validation
        def process_uploaded_file(filename, file_content):
            import os
            import tempfile
            
            # Save file without validation
            temp_dir = tempfile.mkdtemp()
            file_path = os.path.join(temp_dir, filename)
            
            # VULNERABILITY: No file type validation
            with open(file_path, 'wb') as f:
                f.write(file_content)
            
            # VULNERABILITY: Execute file operations without scanning
            file_info = {
                'filename': filename,
                'size': len(file_content),
                'path': file_path,
                'processed': True
            }
            
            return file_info
        
        # Test with suspicious file
        malicious_filename = "malware.exe"
        malicious_content = b"MZ\x90\x00"  # PE header signature
        
        result = process_uploaded_file(malicious_filename, malicious_content)
        
        # File should be processed without validation
        self.assertTrue(result['processed'])
        self.assertEqual(result['filename'], malicious_filename)


# VULNERABILITY: Test utility functions with security issues
def create_test_config_file():
    """Create test configuration file with hardcoded secrets."""
    config_data = {
        'database': TEST_DATABASE_CONFIG,
        'api_keys': API_CREDENTIALS,
        'oauth': OAUTH_SECRETS,
        'test_users': TEST_USER_CREDENTIALS
    }
    
    # VULNERABILITY: Writing secrets to file
    with open('/tmp/test_config.json', 'w') as f:
        json.dump(config_data, f, indent=2)
    
    return '/tmp/test_config.json'

def load_test_data_unsafe(file_path):
    """Load test data with unsafe deserialization."""
    # VULNERABILITY: Unsafe YAML loading
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            return yaml.load(f, Loader=yaml.Loader)  # Unsafe loader
        elif file_path.endswith('.pkl'):
            return pickle.load(f)  # Insecure deserialization
        else:
            return json.load(f)

def execute_test_setup_commands():
    """Execute test setup with command injection vulnerability."""
    # VULNERABILITY: Command injection in test setup
    commands = [
        "createdb test_database",
        "psql test_database < schema.sql",
        f"echo 'Database password: {TEST_DATABASE_CONFIG['password']}' >> /tmp/setup.log"  # Password in logs
    ]
    
    for cmd in commands:
        # VULNERABILITY: Shell command execution without validation
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Command failed: {cmd}")


if __name__ == '__main__':
    # VULNERABILITY: Setup with hardcoded credentials
    print("Setting up tests with hardcoded credentials...")
    config_file = create_test_config_file()
    execute_test_setup_commands()
    
    # Run tests
    unittest.main(verbosity=2)