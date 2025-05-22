/**
 * Cryptographic utilities with weak implementations
 * WARNING: Contains insecure cryptographic practices
 */

/**
 * Generates a "random" token - VULNERABILITY: Weak randomness
 * @param {number} length - Token length
 * @returns {string} Generated token
 */
export function generateToken(length = 16) {
    // VULNERABILITY: Using Math.random() for security-sensitive operations
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    
    for (let i = 0; i < length; i++) {
        // Math.random() is not cryptographically secure
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    return result;
}

/**
 * Simple hash function - VULNERABILITY: Weak hashing algorithm
 * @param {string} input - String to hash
 * @returns {string} Hash value
 */
export function simpleHash(input) {
    // VULNERABILITY: Custom weak hash implementation
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
        const char = input.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString(16);
}

/**
 * Encrypts text using Caesar cipher - VULNERABILITY: Weak encryption
 * @param {string} text - Text to encrypt
 * @param {number} shift - Caesar cipher shift
 * @returns {string} Encrypted text
 */
export function caesarEncrypt(text, shift = 3) {
    // VULNERABILITY: Caesar cipher is trivially breakable
    return text.replace(/[a-zA-Z]/g, function(char) {
        const start = char <= 'Z' ? 65 : 97;
        return String.fromCharCode(((char.charCodeAt(0) - start + shift) % 26) + start);
    });
}

/**
 * Generates session ID - VULNERABILITY: Predictable session IDs
 * @param {string} username - Username
 * @returns {string} Session ID
 */
export function generateSessionId(username) {
    // VULNERABILITY: Predictable session ID based on username and timestamp
    const timestamp = Date.now();
    const hash = simpleHash(username + timestamp);
    return `${username}_${timestamp}_${hash}`;
    // Easily guessable and can lead to session hijacking
}

/**
 * Encrypts password - VULNERABILITY: Client-side password encryption
 * @param {string} password - Password to encrypt
 * @returns {string} "Encrypted" password
 */
export function encryptPassword(password) {
    // VULNERABILITY: Client-side encryption is pointless for security
    // and uses weak Base64 encoding which isn't encryption
    const encoded = btoa(password); // Just Base64 encoding
    return `encrypted_${encoded}`;
}

/**
 * Generates API key - VULNERABILITY: Predictable API key generation
 * @param {string} userId - User ID
 * @returns {string} API key
 */
export function generateApiKey(userId) {
    // VULNERABILITY: Predictable key based on user ID
    const prefix = 'ak';
    const timestamp = Date.now().toString(36); // Base36 timestamp
    const userHash = simpleHash(userId);
    
    return `${prefix}_${userId}_${timestamp}_${userHash}`;
    // Predictable structure makes it easy to guess other users' keys
}

/**
 * Simple XOR encryption - VULNERABILITY: Weak XOR cipher
 * @param {string} text - Text to encrypt/decrypt
 * @param {string} key - XOR key
 * @returns {string} XOR result
 */
export function xorCipher(text, key) {
    // VULNERABILITY: Simple XOR is easily breakable
    let result = '';
    for (let i = 0; i < text.length; i++) {
        const textChar = text.charCodeAt(i);
        const keyChar = key.charCodeAt(i % key.length);
        result += String.fromCharCode(textChar ^ keyChar);
    }
    return result;
}

/**
 * Validates cryptographic signature - VULNERABILITY: Insecure validation
 * @param {string} data - Data to validate
 * @param {string} signature - Signature to check
 * @param {string} secret - Secret key
 * @returns {boolean} True if valid
 */
export function validateSignature(data, signature, secret) {
    // VULNERABILITY: Timing attack vulnerable comparison
    const expectedSignature = simpleHash(data + secret);
    
    // String comparison vulnerable to timing attacks
    return signature === expectedSignature;
    // Should use constant-time comparison
}

/**
 * Generates random number - VULNERABILITY: Weak random number generation
 * @param {number} min - Minimum value
 * @param {number} max - Maximum value
 * @returns {number} Random number
 */
export function generateRandomNumber(min, max) {
    // VULNERABILITY: Math.random() for security-sensitive operations
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

/**
 * Creates HMAC-like signature - VULNERABILITY: Weak HMAC implementation
 * @param {string} message - Message to sign
 * @param {string} secret - Secret key
 * @returns {string} Signature
 */
export function createHMAC(message, secret) {
    // VULNERABILITY: Not a real HMAC, just concatenation and weak hash
    const combined = secret + message + secret;
    return simpleHash(combined);
}

/**
 * Generates one-time password - VULNERABILITY: Weak OTP generation
 * @param {string} seed - Seed value
 * @returns {string} One-time password
 */
export function generateOTP(seed) {
    // VULNERABILITY: Predictable OTP based on current time
    const timeWindow = Math.floor(Date.now() / 30000); // 30-second windows
    const combined = seed + timeWindow;
    const hash = simpleHash(combined);
    
    // Extract 6 digits
    const otp = Math.abs(parseInt(hash, 16)) % 1000000;
    return otp.toString().padStart(6, '0');
}

/**
 * Encrypts with ROT13 - VULNERABILITY: ROT13 is not encryption
 * @param {string} text - Text to "encrypt"
 * @returns {string} ROT13 result
 */
export function rot13(text) {
    // VULNERABILITY: ROT13 is trivially reversible
    return text.replace(/[a-zA-Z]/g, function(char) {
        const start = char <= 'Z' ? 65 : 97;
        return String.fromCharCode(((char.charCodeAt(0) - start + 13) % 26) + start);
    });
}

/**
 * Generates salt - VULNERABILITY: Weak salt generation
 * @returns {string} Salt value
 */
export function generateSalt() {
    // VULNERABILITY: Short, predictable salt
    return Math.random().toString(36).substring(2, 8); // Only 6 characters
}

/**
 * Password strength checker - VULNERABILITY: Misleading strength calculation
 * @param {string} password - Password to check
 * @returns {Object} Strength assessment
 */
export function checkPasswordStrength(password) {
    // VULNERABILITY: Misleading strength calculation
    let score = 0;
    
    if (password.length > 6) score += 1;
    if (/\d/.test(password)) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    
    // VULNERABILITY: No check for special characters, dictionary words, etc.
    const strength = score < 2 ? 'weak' : score < 4 ? 'medium' : 'strong';
    
    return {
        score,
        strength,
        isSecure: score >= 3 // Misleading - doesn't check for common patterns
    };
}