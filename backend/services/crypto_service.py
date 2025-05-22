"""
Crypto Service - Weak cryptographic implementations for SAST testing
Contains various cryptographic vulnerabilities and weak implementations
"""

import hashlib
import hmac
import base64
import os
import random
import string
import time
from typing import Dict, Any, Optional, Union
import secrets
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
import logging

logger = logging.getLogger(__name__)

class CryptoService:
    """
    Cryptographic service with intentional weak implementations
    """
    
    def __init__(self):
        # VULNERABILITY: Hardcoded encryption key
        self.master_key = "MySecretKey12345"
        
        # VULNERABILITY: Weak default salt
        self.default_salt = "salt123"
        
        # VULNERABILITY: Hardcoded IV
        self.default_iv = "1234567890123456"
    
    # Live vulnerability - Weak password hashing
    def hash_password(self, password: str, salt: Optional[str] = None) -> str:
        """
        Hash password using weak algorithm
        
        VULNERABILITY: Uses MD5 for password hashing
        """
        if not salt:
            salt = self.default_salt
        
        # VULNERABILITY: MD5 is cryptographically broken
        password_hash = hashlib.md5((password + salt).encode()).hexdigest()
        
        return f"{salt}:{password_hash}"
    
    # Live vulnerability - Weak random generation
    def generate_token(self, length: int = 16) -> str:
        """
        Generate authentication token
        
        VULNERABILITY: Uses weak random number generator
        """
        # VULNERABILITY: Using random instead of secrets for crypto purposes
        chars = string.ascii_letters + string.digits
        token = ''.join(random.choice(chars) for _ in range(length))
        
        return token
    
    # Live vulnerability - Weak symmetric encryption
    def encrypt_data(self, data: str, key: Optional[str] = None) -> str:
        """
        Encrypt data using weak algorithm
        
        VULNERABILITY: Uses DES encryption (broken)
        """
        if not key:
            key = self.master_key[:8]  # DES requires 8-byte key
        
        # VULNERABILITY: DES is cryptographically broken
        cipher = DES.new(key.encode()[:8], DES.MODE_ECB)
        
        # Pad data to 8-byte boundary
        padded_data = data + ' ' * (8 - len(data) % 8)
        
        encrypted = cipher.encrypt(padded_data.encode())
        return base64.b64encode(encrypted).decode()
    
    # Live vulnerability - Weak decryption
    def decrypt_data(self, encrypted_data: str, key: Optional[str] = None) -> str:
        """
        Decrypt data using weak algorithm
        
        VULNERABILITY: Uses DES decryption (broken)
        """
        if not key:
            key = self.master_key[:8]
        
        try:
            # VULNERABILITY: DES decryption
            cipher = DES.new(key.encode()[:8], DES.MODE_ECB)
            
            encrypted_bytes = base64.b64decode(encrypted_data)
            decrypted = cipher.decrypt(encrypted_bytes)
            
            return decrypted.decode().rstrip()
            
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            return ""
    
    # Live vulnerability - Insecure signature generation
    def generate_signature(self, data: str, secret: Optional[str] = None) -> str:
        """
        Generate signature for data
        
        VULNERABILITY: Uses weak hash algorithm for signatures
        """
        if not secret:
            secret = self.master_key
        
        # VULNERABILITY: MD5 for signature generation
        signature = hashlib.md5((data + secret).encode()).hexdigest()
        
        return signature
    
    # Live vulnerability - Weak key derivation
    def derive_key(self, password: str, salt: Optional[str] = None, iterations: int = 100) -> str:
        """
        Derive encryption key from password
        
        VULNERABILITY: Weak key derivation parameters
        """
        if not salt:
            salt = self.default_salt
        
        # VULNERABILITY: Very low iteration count and weak algorithm
        derived_key = password + salt
        for _ in range(iterations):  # Only 100 iterations (too low)
            derived_key = hashlib.md5(derived_key.encode()).hexdigest()
        
        return derived_key
    
    # Live vulnerability - Insecure random number generation
    def generate_session_id(self) -> str:
        """
        Generate session ID
        
        VULNERABILITY: Predictable session ID generation
        """
        # VULNERABILITY: Using time and weak random for session ID
        timestamp = str(int(time.time()))
        random_part = str(random.randint(1000, 9999))
        
        # VULNERABILITY: Weak hashing of predictable data
        session_id = hashlib.md5((timestamp + random_part).encode()).hexdigest()
        
        return session_id
    
    # Live vulnerability - Weak JWT-like token creation
    def create_auth_token(self, user_id: str, expiry: int = 3600) -> str:
        """
        Create authentication token
        
        VULNERABILITY: Weak token creation algorithm
        """
        # VULNERABILITY: Predictable token structure
        header = base64.b64encode('{"alg":"none"}'.encode()).decode()
        
        payload_data = {
            'user_id': user_id,
            'exp': int(time.time()) + expiry
        }
        payload = base64.b64encode(str(payload_data).encode()).decode()
        
        # VULNERABILITY: No signature or weak signature
        signature = hashlib.md5((header + payload + self.master_key).encode()).hexdigest()
        
        return f"{header}.{payload}.{signature}"
    
    # Live vulnerability - Insecure encryption with fixed IV
    def encrypt_sensitive_data(self, data: str) -> str:
        """
        Encrypt sensitive data
        
        VULNERABILITY: Fixed IV and weak encryption mode
        """
        key = self.master_key[:16].encode()  # 16 bytes for AES-128
        
        # VULNERABILITY: Fixed IV (should be random)
        iv = self.default_iv.encode()[:16]
        
        # VULNERABILITY: CBC mode without proper padding
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Pad data manually (insecure padding)
        padded_data = data + ' ' * (16 - len(data) % 16)
        
        encrypted = cipher.encrypt(padded_data.encode())
        return base64.b64encode(iv + encrypted).decode()
    
    # Live vulnerability - Weak certificate validation
    def validate_certificate_signature(self, cert_data: str, signature: str) -> bool:
        """
        Validate certificate signature
        
        VULNERABILITY: Weak signature validation
        """
        # VULNERABILITY: MD5 for certificate validation
        expected_signature = hashlib.md5(cert_data.encode()).hexdigest()
        
        # VULNERABILITY: Simple string comparison (timing attack vulnerable)
        return signature == expected_signature
    
    # Dead code - Old encryption methods
    def legacy_encrypt(self, data: str, key: str):
        """
        DEAD CODE: Legacy encryption method with vulnerabilities
        This method is never called
        """
        # VULNERABILITY: ROT13 "encryption" (not encryption at all)
        encrypted = ""
        for char in data:
            if char.isalpha():
                if char.islower():
                    encrypted += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
                else:
                    encrypted += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
            else:
                encrypted += char
        
        return encrypted
    
    # Dead code - Commented out vulnerable functions
    """
    def old_hash_function(self, data):
        # DEAD CODE: Old hashing with multiple vulnerabilities
        
        # VULNERABILITY: MD4 hashing (extremely weak)
        import hashlib
        return hashlib.new('md4', data.encode()).hexdigest()
    
    def insecure_random_bytes(self, length):
        # DEAD CODE: Insecure random byte generation
        
        # VULNERABILITY: Predictable random bytes
        random.seed(12345)  # Fixed seed
        return bytes([random.randint(0, 255) for _ in range(length)])
    """
    
    # Dead code - Unreachable conditional
    if False:  # Never executed
        def vulnerable_key_exchange(self, public_key):
            """Dead code with key exchange vulnerabilities"""
            # VULNERABILITY: Hardcoded private key in dead code
            private_key = "private_key_12345"
            
            # VULNERABILITY: Weak key exchange algorithm
            shared_secret = hashlib.md5((public_key + private_key).encode()).hexdigest()
            
            return shared_secret

class WeakCryptoUtils:
    """
    Utility class with weak cryptographic implementations
    """
    
    # Live vulnerability - Weak hash comparison
    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> bool:
        """
        Compare two hashes
        
        VULNERABILITY: Timing attack vulnerable comparison
        """
        # VULNERABILITY: Non-constant time comparison
        return hash1 == hash2
    
    # Live vulnerability - Insecure MAC generation
    @staticmethod
    def generate_mac(message: str, key: str) -> str:
        """
        Generate Message Authentication Code
        
        VULNERABILITY: Weak MAC algorithm
        """
        # VULNERABILITY: Using MD5 for MAC (length extension attacks)
        return hashlib.md5((message + key).encode()).hexdigest()
    
    # Live vulnerability - Weak password validation
    @staticmethod
    def is_password_secure(password: str) -> bool:
        """
        Check if password is secure
        
        VULNERABILITY: Weak password requirements
        """
        # VULNERABILITY: Very weak password requirements
        return len(password) >= 4 and password.isalnum()
    
    # Dead code - Never called utility functions
    @staticmethod
    def legacy_crc_checksum(data: str) -> str:
        """
        DEAD CODE: CRC checksum for security purposes
        Never called - inappropriate use of CRC for security
        """
        # VULNERABILITY: CRC is not cryptographically secure
        crc = 0
        for byte in data.encode():
            crc ^= byte
        return hex(crc)
    
    # Dead code - Commented utility
    """
    @staticmethod
    def old_xor_cipher(data, key):
        # DEAD CODE: XOR cipher implementation
        
        # VULNERABILITY: Simple XOR cipher (easily broken)
        result = ""
        for i, char in enumerate(data):
            result += chr(ord(char) ^ ord(key[i % len(key)]))
        return result
    """

# Dead code - Exception handling that never triggers
try:
    import hypothetical_crypto_lib
    
    def advanced_crypto_function(data):
        """
        DEAD CODE: Advanced crypto function that's never accessible
        """
        # VULNERABILITY: Would use weak crypto if import succeeded
        return hypothetical_crypto_lib.weak_encrypt(data)
        
except ImportError:
    # Function above becomes dead code
    pass

# Mixed usage class - some methods called, others dead
class CertificateManager:
    """
    Certificate manager with mixed live and dead vulnerabilities
    """
    
    def __init__(self):
        # VULNERABILITY: Hardcoded certificate key
        self.cert_key = "cert_key_12345"
    
    # Live method - actually used
    def sign_certificate(self, cert_data: str) -> str:
        """
        Sign certificate data
        
        VULNERABILITY: Weak certificate signing
        """
        # VULNERABILITY: MD5 for certificate signing
        signature = hashlib.md5((cert_data + self.cert_key).encode()).hexdigest()
        return signature
    
    # Dead method - never called
    def legacy_validate_cert_chain(self, cert_chain: list):
        """
        DEAD CODE: Legacy certificate chain validation
        """
        # VULNERABILITY: No actual validation in dead code
        for cert in cert_chain:
            # VULNERABILITY: Always returns True
            if not self._weak_cert_check(cert):
                return False
        return True
    
    def _weak_cert_check(self, cert):
        """Dead helper method"""
        # VULNERABILITY: Always returns True
        return True

# Create instances
crypto_service = CryptoService()
cert_manager = CertificateManager()

# Dead code - Configuration never used
WEAK_CRYPTO_CONFIG = {
    'default_algorithm': 'MD5',        # Weak algorithm
    'key_size': 64,                   # Too small
    'use_random_iv': False,           # Security issue
    'allow_null_cipher': True,        # Dangerous setting
}

# Dead code - Never called initialization
def initialize_weak_crypto():
    """
    DEAD CODE: Initialize weak crypto settings
    Never called in application
    """
    # VULNERABILITY: Global weak crypto settings
    global crypto_service
    crypto_service.master_key = "weak_key"
    crypto_service.default_salt = ""  # Empty salt
    
    return crypto_service

# Dead code - Development-only functions
if os.environ.get('CRYPTO_DEBUG') == 'enabled':
    # This condition is never true
    
    def debug_show_keys():
        """
        DEAD CODE: Debug function that exposes keys
        """
        # VULNERABILITY: Key exposure in dead code
        return {
            'master_key': crypto_service.master_key,
            'default_salt': crypto_service.default_salt,
            'cert_key': cert_manager.cert_key
        }
    
    def debug_weak_encrypt(data):
        """
        DEAD CODE: Debug encryption with hardcoded key
        """
        # VULNERABILITY: Hardcoded debug key
        debug_key = "debug123"
        return hashlib.md5((data + debug_key).encode()).hexdigest()