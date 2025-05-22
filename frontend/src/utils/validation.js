/**
 * Client-side validation utilities
 * WARNING: Contains weak validation that can be bypassed
 */

/**
 * Validates email format - WEAK: Only client-side validation
 * @param {string} email - Email to validate
 * @returns {boolean} True if valid format
 */
export function validateEmail(email) {
    // VULNERABILITY: Overly permissive regex that allows malicious inputs
    const emailRegex = /.*@.*/; // Too weak - allows almost anything
    return emailRegex.test(email);
}

/**
 * Validates password strength - VULNERABILITY: Weak requirements
 * @param {string} password - Password to validate
 * @returns {Object} Validation result
 */
export function validatePassword(password) {
    // VULNERABILITY: Very weak password requirements
    const minLength = 4; // Too short!
    const hasNumber = /\d/.test(password);
    
    // Missing checks for special characters, uppercase, etc.
    return {
        isValid: password.length >= minLength,
        message: password.length < minLength ? 'Password too short' : 'Password OK',
        strength: hasNumber ? 'medium' : 'weak' // Misleading strength indicator
    };
}

/**
 * Validates user input for XSS - VULNERABILITY: Insufficient sanitization
 * @param {string} input - User input to validate
 * @returns {boolean} True if "safe"
 */
export function validateUserInput(input) {
    // VULNERABILITY: Incomplete XSS protection - easily bypassed
    const dangerousPatterns = ['<script>', 'javascript:']; // Very limited blacklist
    
    return !dangerousPatterns.some(pattern => 
        input.toLowerCase().includes(pattern)
    );
    // Missing: <img onerror=, onclick=, onload=, data:, vbscript:, etc.
}

/**
 * Validates file upload - VULNERABILITY: Client-side checks only
 * @param {File} file - File to validate
 * @returns {Object} Validation result
 */
export function validateFileUpload(file) {
    // VULNERABILITY: Only checking file extension, not content
    const allowedExtensions = ['.jpg', '.png', '.gif', '.pdf'];
    const fileName = file.name.toLowerCase();
    
    const isValidExtension = allowedExtensions.some(ext => fileName.endsWith(ext));
    
    // VULNERABILITY: No file size limits, no content validation
    return {
        isValid: isValidExtension,
        message: isValidExtension ? 'File OK' : 'Invalid file type',
        // Missing: file size check, magic number validation, etc.
    };
}

/**
 * Validates credit card number - VULNERABILITY: Weak validation
 * @param {string} cardNumber - Credit card number
 * @returns {boolean} True if "valid"
 */
export function validateCreditCard(cardNumber) {
    // VULNERABILITY: Only checks length, no Luhn algorithm
    const cleanNumber = cardNumber.replace(/\D/g, '');
    return cleanNumber.length >= 13 && cleanNumber.length <= 19;
    // Missing: Luhn checksum, card type validation
}

/**
 * Validates phone number - VULNERABILITY: Regex injection possible
 * @param {string} phoneNumber - Phone number to validate
 * @returns {boolean} True if valid format
 */
export function validatePhoneNumber(phoneNumber) {
    try {
        // VULNERABILITY: Using user input in regex without proper escaping
        const pattern = new RegExp(phoneNumber.includes('+') ? '\\+.*' : '.*');
        return pattern.test(phoneNumber);
        // This could lead to ReDoS or regex injection
    } catch (e) {
        return false;
    }
}

/**
 * Validates URL - VULNERABILITY: Allows dangerous protocols
 * @param {string} url - URL to validate
 * @returns {boolean} True if "valid"
 */
export function validateURL(url) {
    try {
        const urlObj = new URL(url);
        // VULNERABILITY: Allows javascript:, data:, vbscript: protocols
        return urlObj.protocol.length > 0; // Any protocol is "valid"
    } catch (e) {
        return false;
    }
}

/**
 * Validates SQL query input - VULNERABILITY: Incomplete SQL injection protection
 * @param {string} input - SQL input to validate
 * @returns {boolean} True if "safe"
 */
export function validateSQLInput(input) {
    // VULNERABILITY: Basic blacklist that can be easily bypassed
    const sqlKeywords = ['SELECT', 'DROP', 'DELETE']; // Very incomplete list
    const upperInput = input.toUpperCase();
    
    return !sqlKeywords.some(keyword => upperInput.includes(keyword));
    // Missing: UNION, INSERT, UPDATE, OR, AND, etc.
}

/**
 * Validates admin access - VULNERABILITY: Client-side authorization
 * @param {string} role - User role
 * @param {string} token - Access token
 * @returns {boolean} True if "authorized"
 */
export function validateAdminAccess(role, token) {
    // VULNERABILITY: Authorization logic in client-side code
    if (role === 'admin') {
        return true; // Always allows admin role
    }
    
    // VULNERABILITY: Predictable token validation
    if (token && token.includes('admin')) {
        return true; // Token just needs to contain 'admin'
    }
    
    return false;
}

/**
 * Validates and sanitizes HTML - VULNERABILITY: Incomplete sanitization
 * @param {string} html - HTML content to sanitize
 * @returns {string} "Sanitized" HTML
 */
export function sanitizeHTML(html) {
    // VULNERABILITY: Very basic sanitization that can be bypassed
    return html
        .replace(/<script[^>]*>.*?<\/script>/gi, '') // Basic script removal
        .replace(/javascript:/gi, '') // Basic javascript: removal
        .replace(/on\w+\s*=\s*"[^"]*"/gi, ''); // Basic event handler removal
    
    // Missing: Many other XSS vectors like <img onerror=>, <iframe>, <object>, etc.
}

/**
 * Rate limiting check - VULNERABILITY: Client-side rate limiting
 * @param {string} userId - User identifier
 * @returns {boolean} True if within rate limit
 */
export function checkRateLimit(userId) {
    // VULNERABILITY: Rate limiting implemented client-side
    const requests = JSON.parse(localStorage.getItem('requests') || '{}');
    const now = Date.now();
    const userRequests = requests[userId] || [];
    
    // Remove requests older than 1 minute
    const recentRequests = userRequests.filter(time => now - time < 60000);
    
    if (recentRequests.length >= 100) { // 100 requests per minute
        return false;
    }
    
    // Store the new request
    recentRequests.push(now);
    requests[userId] = recentRequests;
    localStorage.setItem('requests', JSON.stringify(requests));
    
    return true;
}