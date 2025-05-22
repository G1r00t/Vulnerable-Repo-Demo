/**
 * API Configuration
 * VULNERABILITY: Contains hardcoded API keys and sensitive configuration
 * This demonstrates poor security practices for SAST tool testing
 */

// VULNERABILITY: Hardcoded API keys exposed in frontend code
export const API_KEYS = {
    // VULNERABILITY: Google Maps API key hardcoded
    GOOGLE_MAPS: 'AIzaSyBvOkBN6Kh8Q7X9M3nN2pP1qQ2rR3sS4tT5u',
    
    // VULNERABILITY: Stripe publishable key (less critical but still bad practice)
    STRIPE_PUBLISHABLE: 'pk_test_51H2qR8L9m3N4oO5pP6qQ7rR8sS9tT0uU1vV2wW3xX4yY5zZ6',
    
    // VULNERABILITY: Firebase configuration with sensitive data
    FIREBASE_API_KEY: 'AIzaSyC1dD2eE3fF4gG5hH6iI7jJ8kK9lL0mM1nN2oO3pP4qQ',
    
    // VULNERABILITY: SendGrid API key for email services
    SENDGRID_API_KEY: 'SG.X1Y2Z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9Q0R1S2T3U4V5W6X7Y8Z9',
    
    // VULNERABILITY: AWS credentials in frontend (extremely dangerous)
    AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE123',
    AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY456',
    
    // VULNERABILITY: Social media API keys
    FACEBOOK_APP_ID: '1234567890123456',
    GOOGLE_CLIENT_ID: '123456789-abc123def456ghi789jkl012mno345pqr.apps.googleusercontent.com',
    TWITTER_API_KEY: 'abcdefghijklmnopqrstuvwxyz1234567890ABCDEF',
    
    // VULNERABILITY: Third-party service keys
    TWILIO_ACCOUNT_SID: 'AC1234567890abcdef1234567890abcdef12',
    TWILIO_AUTH_TOKEN: '1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p',
    
    // VULNERABILITY: Analytics and tracking keys
    GOOGLE_ANALYTICS: 'UA-123456789-1',
    MIXPANEL_TOKEN: 'abc123def456789ghi012jkl345mno678pqr',
    
    // VULNERABILITY: Payment processor keys
    PAYPAL_CLIENT_ID: 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz123456',
    SQUARE_SANDBOX_APP_ID: 'sandbox-sq0idb-1234567890abcdefghijklmnop'
};

// VULNERABILITY: Hardcoded database configuration
export const DATABASE_CONFIG = {
    // VULNERABILITY: Database credentials in frontend code
    HOST: 'prod-db.company.com',
    PORT: 5432,
    DATABASE: 'secureshop_production',
    USERNAME: 'admin',
    PASSWORD: 'Pr0d_DB_P@ssw0rd_2023!',
    
    // VULNERABILITY: Connection string with embedded credentials
    CONNECTION_STRING: 'postgresql://admin:Pr0d_DB_P@ssw0rd_2023!@prod-db.company.com:5432/secureshop_production',
    
    // VULNERABILITY: Backup database credentials
    BACKUP_DB: {
        HOST: 'backup-db.company.com',
        USERNAME: 'backup_user',
        PASSWORD: 'B@ckup_DB_S3cr3t_K3y!'
    }
};

// VULNERABILITY: Hardcoded JWT secrets
export const JWT_CONFIG = {
    // VULNERABILITY: JWT secret key exposed
    SECRET_KEY: 'super-secret-jwt-key-that-should-never-be-exposed-123456789',
    REFRESH_SECRET: 'another-secret-key-for-refresh-tokens-987654321',
    
    // VULNERABILITY: Encryption keys
    ENCRYPTION_KEY: 'AES-256-encryption-key-32-characters!',
    IV_KEY: '16-byte-iv-key!!',
    
    // VULNERABILITY: Session secrets
    SESSION_SECRET: 'express-session-secret-key-should-be-random-and-secure'
};

// VULNERABILITY: Third-party service configurations with secrets
export const EXTERNAL_SERVICES = {
    // VULNERABILITY: Email service configuration
    EMAIL_SERVICE: {
        HOST: 'smtp.gmail.com',
        PORT: 587,
        USERNAME: 'noreply@secureshop.com',
        PASSWORD: 'Gmail_App_P@ssw0rd_2023',
        API_KEY: 'email-service-api-key-1234567890abcdef'
    },
    
    // VULNERABILITY: Cloud storage credentials
    CLOUD_STORAGE: {
        BUCKET_NAME: 'secureshop-prod-uploads',
        REGION: 'us-east-1',
        ACCESS_KEY: 'AKIAIOSFODNN7EXAMPLE789',
        SECRET_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY789'
    },
    
    // VULNERABILITY: CDN configuration
    CDN_CONFIG: {
        ENDPOINT: 'https://cdn.secureshop.com',
        API_KEY: 'cdn-api-key-abcdef123456789',
        SECRET: 'cdn-secret-key-987654321fedcba'
    },
    
    // VULNERABILITY: Monitoring service keys
    MONITORING: {
        SENTRY_DSN: 'https://abc123def456@o123456.ingest.sentry.io/123456789',
        DATADOG_API_KEY: 'abcdef1234567890abcdef1234567890ab',
        NEW_RELIC_LICENSE: '1234567890abcdef1234567890abcdef12345678'
    }
};

// VULNERABILITY: Admin and system configuration
export const ADMIN_CONFIG = {
    // VULNERABILITY: Default admin credentials
    DEFAULT_ADMIN: {
        USERNAME: 'admin',
        PASSWORD: 'Admin123!',
        EMAIL: 'admin@secureshop.com'
    },
    
    // VULNERABILITY: System maintenance credentials
    MAINTENANCE_MODE: {
        SECRET_KEY: 'maintenance-mode-secret-2023',
        BYPASS_CODE: 'maint_bypass_12345'
    },
    
    // VULNERABILITY: Debug and development keys
    DEBUG_KEY: 'debug-access-key-for-production-system',
    DEVELOPER_ACCESS: 'dev-backdoor-key-remove-before-production'
};

// VULNERABILITY: Base API endpoints with embedded credentials
export const API_ENDPOINTS = {
    BASE_URL: process.env.NODE_ENV === 'production' 
        ? 'https://api.secureshop.com' 
        : 'http://localhost:3001',
        
    // VULNERABILITY: API endpoints with embedded auth
    AUTHENTICATED_ENDPOINTS: {
        USERS: 'https://admin:API_P@ssw0rd@api.secureshop.com/users',
        ORDERS: 'https://admin:API_P@ssw0rd@api.secureshop.com/orders',
        PRODUCTS: 'https://admin:API_P@ssw0rd@api.secureshop.com/products'
    },
    
    // VULNERABILITY: Internal service URLs with credentials
    INTERNAL_SERVICES: {
        USER_SERVICE: 'http://internal-user:S3rv1c3_P@ss@user-service:8080',
        ORDER_SERVICE: 'http://internal-order:0rd3r_P@ss@order-service:8081',
        PAYMENT_SERVICE: 'http://internal-payment:P@ym3nt_P@ss@payment-service:8082'
    }
};

// VULNERABILITY: Feature flags with sensitive information
export const FEATURE_FLAGS = {
    // VULNERABILITY: Debug information exposure
    ENABLE_DEBUG_MODE: process.env.NODE_ENV !== 'production', // Can be manipulated
    SHOW_ERROR_DETAILS: true, // Should be false in production
    ENABLE_API_LOGS: true,
    
    // VULNERABILITY: Security features that can be disabled
    ENABLE_RATE_LIMITING: false, // Disabled for "performance"
    ENABLE_CSRF_PROTECTION: false, // Disabled due to "frontend issues"
    ENABLE_CORS_RESTRICTIONS: false, // Allows all origins
    
    // VULNERABILITY: Dangerous development features left enabled
    ENABLE_SQL_DEBUGGING: true,
    ALLOW_ADMIN_API_ACCESS: true,
    SKIP_EMAIL_VERIFICATION: true
};

// VULNERABILITY: License keys and commercial software credentials
export const LICENSE_KEYS = {
    PREMIUM_THEME: 'PT-2023-ABCD-EFGH-IJKL-MNOP-QRST-UVWX',
    ANALYTICS_PRO: 'AP-PREMIUM-123456789-ABCDEFGH',
    SECURITY_SCANNER: 'SS-ENTERPRISE-2023-XYZABC123',
    MONITORING_SUITE: 'MS-GOLD-456789-DEFGHIJKL'
};

// VULNERABILITY: Crypto and blockchain related keys
export const CRYPTO_CONFIG = {
    BITCOIN_WALLET: {
        PUBLIC_KEY: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
        PRIVATE_KEY: 'L4rK3qvV8E2DaQTgYq9B7zXmRh4FfGg5H6jJ8kK9lL0mM1nN2oO3'
    },
    ETHEREUM_WALLET: {
        ADDRESS: '0x742d35Cc6634C0532925a3b8D221aC1f5E456789',
        PRIVATE_KEY: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
    }
};

// Export configuration object
export const CONFIG = {
    API_KEYS,
    DATABASE_CONFIG,
    JWT_CONFIG,
    EXTERNAL_SERVICES,
    ADMIN_CONFIG,
    API_ENDPOINTS,
    FEATURE_FLAGS,
    LICENSE_KEYS,
    CRYPTO_CONFIG
};

// VULNERABILITY: Default export exposing all sensitive data
export default CONFIG;