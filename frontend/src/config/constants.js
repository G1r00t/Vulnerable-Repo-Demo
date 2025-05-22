/**
 * Application Constants
 * Clean configuration file with proper security practices
 */

// Application metadata
export const APP_INFO = {
    name: 'SecureShop',
    version: '2.1.0',
    description: 'Secure E-commerce Platform',
    author: 'SecureShop Team',
    homepage: 'https://secureshop.example.com'
};

// UI Constants
export const UI_CONSTANTS = {
    ITEMS_PER_PAGE: 20,
    MAX_SEARCH_RESULTS: 100,
    PAGINATION_RANGE: 5,
    DEFAULT_AVATAR: '/images/default-avatar.png',
    PLACEHOLDER_IMAGE: '/images/placeholder.png'
};

// Validation Rules
export const VALIDATION_RULES = {
    PASSWORD: {
        MIN_LENGTH: 8,
        MAX_LENGTH: 128,
        REQUIRE_UPPERCASE: true,
        REQUIRE_LOWERCASE: true,
        REQUIRE_NUMBERS: true,
        REQUIRE_SPECIAL_CHARS: true
    },
    USERNAME: {
        MIN_LENGTH: 3,
        MAX_LENGTH: 30,
        ALLOWED_PATTERN: /^[a-zA-Z0-9_-]+$/
    },
    EMAIL: {
        MAX_LENGTH: 254,
        PATTERN: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    },
    PHONE: {
        PATTERN: /^\+?[\d\s\-\(\)]+$/,
        MIN_LENGTH: 10,
        MAX_LENGTH: 15
    }
};

// File Upload Limits
export const FILE_UPLOAD = {
    MAX_SIZE: 5 * 1024 * 1024, // 5MB
    ALLOWED_TYPES: {
        IMAGE: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
        DOCUMENT: ['application/pdf', 'text/plain']
    },
    MAX_FILES_PER_UPLOAD: 5
};

// Security Settings
export const SECURITY = {
    SESSION_TIMEOUT: 30 * 60 * 1000, // 30 minutes
    MAX_LOGIN_ATTEMPTS: 5,
    LOCKOUT_DURATION: 15 * 60 * 1000, // 15 minutes
    TOKEN_REFRESH_THRESHOLD: 5 * 60 * 1000, // 5 minutes
    CSRF_TOKEN_LENGTH: 32
};

// API Configuration
export const API_CONFIG = {
    TIMEOUT: 30000, // 30 seconds
    RETRY_ATTEMPTS: 3,
    RETRY_DELAY: 1000, // 1 second
    MAX_CONCURRENT_REQUESTS: 10
};

// Feature Flags
export const FEATURES = {
    ENABLE_SOCIAL_LOGIN: true,
    ENABLE_TWO_FACTOR_AUTH: true,
    ENABLE_EMAIL_VERIFICATION: true,
    ENABLE_PUSH_NOTIFICATIONS: false,
    ENABLE_ANALYTICS: true,
    ENABLE_DARK_MODE: true
};

// User Roles and Permissions
export const USER_ROLES = {
    ADMIN: 'admin',
    MODERATOR: 'moderator',
    USER: 'user',
    GUEST: 'guest'
};

export const PERMISSIONS = {
    READ_USERS: 'read:users',
    WRITE_USERS: 'write:users',
    DELETE_USERS: 'delete:users',
    READ_PRODUCTS: 'read:products',
    WRITE_PRODUCTS: 'write:products',
    DELETE_PRODUCTS: 'delete:products',
    MANAGE_ORDERS: 'manage:orders',
    ACCESS_ADMIN_PANEL: 'access:admin'
};

// Status Constants
export const ORDER_STATUS = {
    PENDING: 'pending',
    CONFIRMED: 'confirmed',
    PROCESSING: 'processing',
    SHIPPED: 'shipped',
    DELIVERED: 'delivered',
    CANCELLED: 'cancelled',
    REFUNDED: 'refunded'
};

export const PAYMENT_STATUS = {
    PENDING: 'pending',
    PROCESSING: 'processing',
    COMPLETED: 'completed',
    FAILED: 'failed',
    CANCELLED: 'cancelled',
    REFUNDED: 'refunded'
};

// Error Messages
export const ERROR_MESSAGES = {
    GENERIC: 'An unexpected error occurred. Please try again.',
    NETWORK: 'Network error. Please check your connection.',
    UNAUTHORIZED: 'You are not authorized to perform this action.',
    SESSION_EXPIRED: 'Your session has expired. Please log in again.',
    VALIDATION_FAILED: 'Please check your input and try again.',
    FILE_TOO_LARGE: 'File size exceeds the maximum allowed limit.',
    INVALID_FILE_TYPE: 'File type is not supported.',
    RATE_LIMITED: 'Too many requests. Please try again later.'
};

// Success Messages
export const SUCCESS_MESSAGES = {
    PROFILE_UPDATED: 'Profile updated successfully.',
    PASSWORD_CHANGED: 'Password changed successfully.',
    EMAIL_VERIFIED: 'Email address verified successfully.',
    ORDER_PLACED: 'Order placed successfully.',
    PAYMENT_COMPLETED: 'Payment completed successfully.',
    FILE_UPLOADED: 'File uploaded successfully.'
};

// Date and Time Formats
export const DATE_FORMATS = {
    SHORT: 'MM/DD/YYYY',
    LONG: 'MMMM DD, YYYY',
    WITH_TIME: 'MM/DD/YYYY HH:mm',
    ISO: 'YYYY-MM-DDTHH:mm:ss.sssZ'
};

// Currency Settings
export const CURRENCY = {
    DEFAULT: 'USD',
    SYMBOL: '$',
    DECIMAL_PLACES: 2,
    SUPPORTED_CURRENCIES: ['USD', 'EUR', 'GBP', 'CAD', 'AUD']
};

// Notification Types
export const NOTIFICATION_TYPES = {
    INFO: 'info',
    SUCCESS: 'success',
    WARNING: 'warning',
    ERROR: 'error'
};

// Theme Configuration
export const THEME = {
    PRIMARY_COLOR: '#007bff',
    SECONDARY_COLOR: '#6c757d',
    SUCCESS_COLOR: '#28a745',
    WARNING_COLOR: '#ffc107',
    ERROR_COLOR: '#dc3545',
    DARK_MODE_COLORS: {
        BACKGROUND: '#1a1a1a',
        SURFACE: '#2d2d2d',
        TEXT: '#ffffff'
    }
};

// Development vs Production Settings
export const ENVIRONMENT = {
    isDevelopment: process.env.NODE_ENV === 'development',
    isProduction: process.env.NODE_ENV === 'production',
    isTest: process.env.NODE_ENV === 'test'
};

// Route Constants
export const ROUTES = {
    HOME: '/',
    LOGIN: '/login',
    REGISTER: '/register',
    DASHBOARD: '/dashboard',
    PROFILE: '/profile',
    ADMIN: '/admin',
    PRODUCTS: '/products',
    ORDERS: '/orders',
    CART: '/cart',
    CHECKOUT: '/checkout'
};

// Local Storage Keys (prefixed for namespace safety)
export const STORAGE_KEYS = {
    AUTH_TOKEN: 'secureshop_auth_token',
    USER_INFO: 'secureshop_user_info',
    CART_ITEMS: 'secureshop_cart_items',
    USER_PREFERENCES: 'secureshop_user_prefs',
    THEME_PREFERENCE: 'secureshop_theme'
};

// Regex Patterns for Validation
export const REGEX_PATTERNS = {
    PHONE: /^\+?[\d\s\-\(\)]+$/,
    POSTAL_CODE: /^[A-Za-z0-9\s\-]{3,10}$/,
    CREDIT_CARD: /^\d{13,19}$/,
    CVV: /^\d{3,4}$/,
    STRONG_PASSWORD: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/
};

// Content Security Policy Settings
export const CSP_CONFIG = {
    ALLOWED_SOURCES: {
        SCRIPTS: ["'self'", "https://cdnjs.cloudflare.com"],
        STYLES: ["'self'", "'unsafe-inline'"],
        IMAGES: ["'self'", "data:", "https:"],
        FONTS: ["'self'", "https://fonts.gstatic.com"]
    }
};

// Export all constants as a single object for convenience
export default {
    APP_INFO,
    UI_CONSTANTS,
    VALIDATION_RULES,
    FILE_UPLOAD,
    SECURITY,
    API_CONFIG,
    FEATURES,
    USER_ROLES,
    PERMISSIONS,
    ORDER_STATUS,
    PAYMENT_STATUS,
    ERROR_MESSAGES,
    SUCCESS_MESSAGES,
    DATE_FORMATS,
    CURRENCY,
    NOTIFICATION_TYPES,
    THEME,
    ENVIRONMENT,
    ROUTES,
    STORAGE_KEYS,
    REGEX_PATTERNS,
    CSP_CONFIG
};