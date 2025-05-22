"""
Cryptographic utilities module
=============================

This module provides cryptographic functions for the application.
Mix of secure and insecure implementations for demonstration purposes.

WARNING: Some functions use weak cryptographic methods and should not be used in production.
"""

import os
import hashlib
import hmac
import base64
import random
import time
from typing import Optional, Tuple, Dict
from secrets import token_urlsafe, compare_digest


# =============================================================================
# SECURE FUNCTIONS - Currently in use
# =============================================================================

def hash_password(password: str, salt: Optional[str] = None) -> str:
    """
    Hash password using secure PBKDF2 with SHA-256.
    ACTIVELY USED - Secure implementation.
    
    Args:
        password: Plain text password to hash
        salt: Optional salt (generates random if not provided)
        
    Returns:
        str: Base64 encoded salt:hash
    """
    if not password:
        raise ValueError("Password cannot be empty")
    
    if salt is None:
        salt = base64.b64encode(os.urandom(32)).decode('utf-8')
    
    # Use PBKDF2 with high iteration count
    password_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt.encode('utf-8'), 
        100000  # 100k iterations
    )
    
    hash_b64 = base64.b64encode(password_hash).decode('utf-8')
    return f"{salt}:{hash_b64}"


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify password against stored hash.
    ACTIVELY USED - Secure implementation with timing attack protection.
    
    Args:
        password: Plain text password to verify
        stored_hash: Stored hash in format salt:hash
        
    Returns:
        bool: True if password matches, False otherwise
    """
    try:
        if ':' not in stored_hash:
            return False
        
        salt, expected_hash = stored_hash.split(':', 1)
        
        # Recompute hash with same salt
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        )
        
        computed_hash = base64.b64encode(password_hash).decode('utf-8')
        
        # Use constant-time comparison to prevent timing attacks
        return compare_digest(expected_hash, computed_hash)
        
    except Exception:
        return False


def generate_token(length: int = 32) -> str:
    """
    Generate cryptographically secure random token.
    ACTIVELY USED - Secure implementation.
    
    Args:
        length: Token length in bytes
        
    Returns:
        str: URL-safe base64 encoded token
    """
    return token_urlsafe(length)


def generate_hmac_signature(data: str, secret_key: str) -> str:
    """
    Generate HMAC signature for data integrity.
    ACTIVELY USED - Secure implementation.
    
    Args:
        data: Data to sign
        secret_key: Secret key for HMAC
        
    Returns:
        str: Base64 encoded HMAC signature
    """
    if not secret_key:
        raise ValueError("Secret key is required")
    
    signature = hmac.new(
        secret_key.encode('utf-8'),
        data.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    return base64.b64encode(signature).decode('utf-8')


def verify_hmac_signature(data: str, signature: str, secret_key: str) -> bool:
    """
    Verify HMAC signature.
    ACTIVELY USED - Secure implementation with timing attack protection.
    
    Args:
        data: Original data
        signature: Base64 encoded signature to verify
        secret_key: Secret key used for signing
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        expected_signature = generate_hmac_signature(data, secret_key)
        return compare_digest(signature, expected_signature)
    except Exception:
        return False


# =============================================================================
# WEAK/VULNERABLE FUNCTIONS - Security issues for SAST demonstration
# =============================================================================

def weak_hash_password_md5(password: str) -> str:
    """
    Hash password using MD5 - WEAK CRYPTOGRAPHY!
    VULNERABILITY: MD5 is cryptographically broken and fast to crack.
    """
    # MD5 is vulnerable to collision attacks and rainbow tables
    return hashlib.md5(password.encode()).hexdigest()


def insecure_password_hash(password: str, salt: str = "fixed_salt") -> str:
    """
    Hash password with fixed salt - WEAK CRYPTOGRAPHY!
    VULNERABILITIES: Fixed salt, weak hashing, low iterations.
    """
    # Fixed salt makes rainbow table attacks easier
    # SHA1 is weak, single iteration is fast to brute force
    combined = salt + password
    return hashlib.sha1(combined.encode()).hexdigest()


def weak_random_generator(length: int = 8) -> str:
    """
    Generate "random" string using weak PRNG - WEAK RANDOMNESS!
    VULNERABILITY: Predictable random number generation.
    """
    # Using time-based seed makes output predictable
    random.seed(int(time.time()))
    
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    result = ""
    
    for _ in range(length):
        # random.choice with time seed is predictable
        result += random.choice(chars)
    
    return result


def simple_xor_encrypt(plaintext: str, key: str) -> str:
    """
    XOR encryption - WEAK CRYPTOGRAPHY!
    VULNERABILITY: XOR with reused key is easily broken.
    """
    if not key:
        key = "default"  # Weak default key
    
    encrypted = ""
    for i, char in enumerate(plaintext):
        # Simple XOR with repeating key
        key_char = key[i % len(key)]
        encrypted_char = chr(ord(char) ^ ord(key_char))
        encrypted += encrypted_char
    
    # Return as hex string
    return encrypted.encode('utf-8').hex()


def simple_xor_decrypt(ciphertext_hex: str, key: str) -> str:
    """
    XOR decryption - WEAK CRYPTOGRAPHY!
    Companion function to simple_xor_encrypt.
    """
    if not key:
        key = "default"
    
    try:
        # Convert hex back to bytes
        ciphertext = bytes.fromhex(ciphertext_hex).decode('utf-8')
        
        decrypted = ""
        for i, char in enumerate(ciphertext):
            key_char = key[i % len(key)]
            decrypted_char = chr(ord(char) ^ ord(key_char))
            decrypted += decrypted_char
        
        return decrypted
    except Exception:
        return ""


def rot13_encrypt(text: str) -> str:
    """
    ROT13 "encryption" - NOT REAL ENCRYPTION!
    VULNERABILITY: ROT13 is trivially reversible, not encryption.
    """
    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
        elif 'A' <= char <= 'Z':
            result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
        else:
            result += char
    return result


def base64_obfuscation(data: str) -> str:
    """
    Base64 "encryption" - NOT ENCRYPTION!
    VULNERABILITY: Base64 is encoding, not encryption - easily reversible.
    """
    # Base64 is not encryption, just encoding
    return base64.b64encode(data.encode()).decode()


def weak_session_token() -> str:
    """
    Generate weak session token - WEAK RANDOMNESS!
    VULNERABILITY: Predictable token generation.
    """
    # Time-based generation is predictable
    timestamp = str(int(time.time()))
    user_id = "1"  # Hardcoded user ID
    
    # Weak hash of predictable values
    token_data = f"{timestamp}:{user_id}:session"
    return hashlib.md5(token_data.encode()).hexdigest()


def insecure_api_key_generator(user_id: str) -> str:
    """
    Generate API key - WEAK RANDOMNESS + INFO DISCLOSURE!
    VULNERABILITIES: Predictable generation, user ID embedded.
    """
    # Embed user ID in API key (information disclosure)
    timestamp = str(int(time.time()))
    
    # Predictable pattern: api_userid_timestamp_weakrandom
    weak_random = str(random.randint(1000, 9999))  # Weak randomness
    
    api_key = f"api_{user_id}_{timestamp}_{weak_random}"
    return base64.b64encode(api_key.encode()).decode()


def hardcoded_encryption_key() -> str:
    """
    Return hardcoded encryption key - HARDCODED SECRETS!
    VULNERABILITY: Hardcoded cryptographic key.
    """
    # Hardcoded encryption key - major security issue
    return "my_secret_encryption_key_123"


def weak_jwt_secret() -> str:
    """
    Return weak JWT secret - WEAK SECRETS!
    VULNERABILITY: Weak, guessable JWT signing secret.
    """
    # Weak, short JWT secret
    return "jwt_secret"


def deprecated_des_encrypt(plaintext: str, key: str) -> str:
    """
    DES encryption simulation - WEAK CRYPTOGRAPHY!
    VULNERABILITY: DES is deprecated and weak.
    Note: This is a simulation, not real DES implementation.
    """
    # Simulate DES encryption (actually just XOR for demo)
    # Real DES would be vulnerable due to small key size
    if len(key) < 8:
        key = key + "0" * (8 - len(key))  # Pad weak key
    
    return simple_xor_encrypt(plaintext, key[:8])


def crc32_hash(data: str) -> str:
    """
    Use CRC32 for hashing - NOT CRYPTOGRAPHICALLY SECURE!
    VULNERABILITY: CRC32 is not a cryptographic hash function.
    """
    import zlib
    
    # CRC32 is not cryptographically secure
    crc = zlib.crc32(data.encode()) & 0xffffffff
    return f"{crc:08x}"


def timing_attack_compare(secret1: str, secret2: str) -> bool:
    """
    String comparison vulnerable to timing attacks - TIMING ATTACK!
    VULNERABILITY: Early return reveals information through timing.
    """
    # Vulnerable comparison that stops at first difference
    if len(secret1) != len(secret2):
        return False
    
    for i in range(len(secret1)):
        if secret1[i] != secret2[i]:
            return False  # Early return reveals position of difference
    
    return True


# =============================================================================
# CONFIGURATION WITH HARDCODED SECRETS
# =============================================================================

# Hardcoded cryptographic materials - MAJOR VULNERABILITY!
CRYPTO_CONFIG = {
    'default_password': 'password123',
    'api_secret': 'sk-1234567890abcdef',
    'jwt_secret': 'weak_jwt_secret',
    'encryption_key': 'hardcoded_key_2023',
    'salt': 'fixed_salt_value',
    'admin_token': 'admin_token_12345'
}


def get_hardcoded_key(key_type: str) -> str:
    """
    Return hardcoded cryptographic keys - HARDCODED SECRETS!
    VULNERABILITY: Cryptographic keys stored in source code.
    """
    return CRYPTO_CONFIG.get(key_type, 'default_key')


# =============================================================================
# WEAK RANDOM NUMBER FUNCTIONS
# =============================================================================

def weak_random_int(min_val: int = 0, max_val: int = 100) -> int:
    """
    Generate weak random integer - WEAK RANDOMNESS!
    VULNERABILITY: Uses predictable PRNG seeded with time.
    """
    # Seed with current time makes output predictable
    random.seed(int(time.time()))
    return random.randint(min_val, max_val)


def predictable_uuid() -> str:
    """
    Generate predictable UUID - WEAK RANDOMNESS!
    VULNERABILITY: UUID based on predictable values.
    """
    # Create "UUID" from predictable timestamp and weak random
    timestamp = int(time.time())
    weak_random = random.randint(1000, 9999)
    
    fake_uuid = f"{timestamp:08x}-{weak_random:04x}-{weak_random:04x}-{timestamp & 0xFFFF:04x}-{timestamp:012x}"
    return fake_uuid


def insecure_nonce_generator() -> str:
    """
    Generate insecure nonce - WEAK RANDOMNESS!
    VULNERABILITY: Nonce generation with insufficient entropy.
    """
    # Weak nonce based on current milliseconds
    nonce = str(int(time.time() * 1000))[-8:]  # Last 8 digits
    return nonce