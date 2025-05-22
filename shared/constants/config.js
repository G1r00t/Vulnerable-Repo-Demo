// Mixed configuration file with some clean practices and some vulnerabilities
const path = require('path');
const fs = require('fs');

// Clean environment detection
const isDevelopment = process.env.NODE_ENV === 'development';
const isProduction = process.env.NODE_ENV === 'production';
const isTest = process.env.NODE_ENV === 'test';

// Clean configuration structure
const config = {
    app: {
        name: 'AI-SAST Demo App',
        version: process.env.APP_VERSION || '1.0.0',
        port: process.env.PORT || 3000,
        host: process.env.HOST || 'localhost'
    },
    
    // Clean environment-specific settings
    environment: {
        isDevelopment,
        isProduction,
        isTest,
        logLevel: process.env.LOG_LEVEL || (isDevelopment ? 'debug' : 'info')
    },
    
    // Clean CORS configuration
    cors: {
        origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : ['http://localhost:3000'],
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
    },
    
    // Clean rate limiting
    rateLimit: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000, // 15 minutes
        max: parseInt(process.env.RATE_LIMIT_MAX) || 100, // limit each IP to 100 requests per windowMs
        standardHeaders: true,
        legacyHeaders: false
    },
    
    // Database configuration - VULNERABILITY: Fallback hardcoded credentials
    database: {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT) || 5432,
        name: process.env.DB_NAME || 'demo_app',
        username: process.env.DB_USERNAME || 'postgres', // Weak fallback
        password: process.env.DB_PASSWORD || 'password123', // VULNERABILITY: Hardcoded password
        ssl: process.env.DB_SSL === 'true',
        pool: {
            min: 2,
            max: 10,
            acquire: 30000,
            idle: 10000
        }
    },
    
    // JWT configuration with mixed security
    jwt: {
        secret: process.env.JWT_SECRET || 'default-jwt-secret-change-in-production', // VULNERABILITY: Weak default
        algorithm: 'HS256',
        expiresIn: process.env.JWT_EXPIRES_IN || '24h',
        issuer: 'ai-sast-demo',
        audience: 'ai-sast-demo-users'
    },
    
    // Redis configuration - VULNERABILITY: Some hardcoded values
    redis: {
        host: process.env.REDIS_HOST || 'localhost',
        port: parseInt(process.env.REDIS_PORT) || 6379,
        password: process.env.REDIS_PASSWORD || 'redis123', // VULNERABILITY: Hardcoded fallback
        db: parseInt(process.env.REDIS_DB) || 0,
        keyPrefix: 'demo_app:',
        retryDelayOnFailover: 100,
        maxRetriesPerRequest: 3
    },
    
    // Clean file upload configuration
    upload: {
        maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024, // 10MB
        allowedMimeTypes: [
            'image/jpeg',
            'image/png',
            'image/gif',
            'application/pdf',
            'text/plain'
        ],
        uploadDir: process.env.UPLOAD_DIR || path.join(__dirname, '../../uploads'),
        tempDir: process.env.TEMP_DIR || path.join(__dirname, '../../temp')
    },
    
    // Email configuration with some vulnerabilities
    email: {
        service: process.env.EMAIL_SERVICE || 'smtp',
        smtp: {
            host: process.env.SMTP_HOST || 'localhost',
            port: parseInt(process.env.SMTP_PORT) || 587,
            secure: process.env.SMTP_SECURE === 'true',
            auth: {
                user: process.env.SMTP_USER || 'admin@example.com', // Weak fallback
                pass: process.env.SMTP_PASS || 'EmailPass123!' // VULNERABILITY: Hardcoded password
            }
        },
        sendgrid: {
            apiKey: process.env.SENDGRID_API_KEY || 'SG.hardcoded-api-key-here' // VULNERABILITY: Hardcoded API key
        },
        from: process.env.EMAIL_FROM || 'noreply@example.com',
        replyTo: process.env.EMAIL_REPLY_TO || 'support@example.com'
    },
    
    // External API configurations - VULNERABILITIES: Multiple hardcoded keys
    externalApis: {
        stripe: {
            publishableKey: process.env.STRIPE_PUBLISHABLE_KEY || 'pk_test_hardcoded_stripe_key',
            secretKey: process.env.STRIPE_SECRET_KEY || 'sk_test_hardcoded_stripe_secret' // VULNERABILITY
        },
        aws: {
            accessKeyId: process.env.AWS_ACCESS_KEY_ID || 'AKIAIOSFODNN7EXAMPLE', // VULNERABILITY
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', // VULNERABILITY
            region: process.env.AWS_REGION || 'us-west-2',
            s3Bucket: process.env.S3_BUCKET || 'demo-app-uploads'
        },
        google: {
            clientId: process.env.GOOGLE_CLIENT_ID || '123456789-example.apps.googleusercontent.com',
            clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'GOCSPX-hardcoded-google-secret' // VULNERABILITY
        }
    },
    
    // Security configuration - mixed good and bad practices
    security: {
        // Clean password requirements
        password: {
            minLength: 8,
            requireUppercase: true,
            requireLowercase: true,
            requireNumbers: true,
            requireSpecialChars: true
        },
        
        // Session configuration with vulnerabilities
        session: {
            secret: process.env.SESSION_SECRET || 'session-secret-123', // VULNERABILITY: Weak default
            name: 'sessionId',
            resave: false,
            saveUninitialized: false,
            cookie: {
                secure: isProduction,
                httpOnly: true,
                maxAge: 24 * 60 * 60 * 1000 // 24 hours
            }
        },
        
        // Clean CSRF configuration
        csrf: {
            enabled: !isTest,
            cookieName: '_csrf',
            headerName: 'x-csrf-token'
        },
        
        // Encryption keys - VULNERABILITY: Hardcoded fallbacks
        encryption: {
            algorithm: 'aes-256-gcm',
            key: process.env.ENCRYPTION_KEY || '12345678901234567890123456789012', // VULNERABILITY: Weak key
            iv: process.env.ENCRYPTION_IV || '123456789012' // VULNERABILITY: Hardcoded IV
        }
    },
    
    // Clean logging configuration
    logging: {
        level: process.env.LOG_LEVEL || 'info',
        format: process.env.LOG_FORMAT || 'json',
        file: {
            enabled: process.env.LOG_TO_FILE === 'true',
            filename: process.env.LOG_FILE || 'app.log',
            maxSize: '10m',
            maxFiles: 5
        },
        console: {
            enabled: true,
            colorize: isDevelopment
        }
    }
};

// VULNERABILITY: Insecure configuration loading function
function loadSecretConfig() {
    try {
        // This attempts to load a config file with secrets - path traversal risk
        const secretPath = process.env.SECRET_CONFIG_PATH || '../secrets/config.json';
        const secretConfig = JSON.parse(fs.readFileSync(secretPath, 'utf8')); // Path traversal vulnerability
        
        // Merge secrets into main config - no validation
        Object.assign(config, secretConfig);
        
        console.log('Loaded secret configuration from:', secretPath); // Information disclosure
    } catch (error) {
        console.log('No secret config file found, using defaults');
        
        // VULNERABILITY: Logging sensitive defaults
        console.log('Using hardcoded database password:', config.database.password);
        console.log('Using hardcoded JWT secret:', config.jwt.secret);
    }
}

// Clean validation function
function validateConfig() {
    const required = [
        'app.name',
        'app.port',
        'database.host',
        'database.name'
    ];
    
    const missing = required.filter(key => {
        const value = key.split('.').reduce((obj, prop) => obj && obj[prop], config);
        return !value;
    });
    
    if (missing.length > 0) {
        throw new Error(`Missing required configuration: ${missing.join(', ')}`);
    }
}

// Initialize configuration
if (isProduction) {
    loadSecretConfig(); // Only load secrets in production
}

validateConfig();

// Clean helper functions
const configHelpers = {
    isDevelopment: () => isDevelopment,
    isProduction: () => isProduction,
    isTest: () => isTest,
    
    getDatabaseUrl: () => {
        const { host, port, name, username, password } = config.database;
        return `postgresql://${username}:${password}@${host}:${port}/${name}`;
    },
    
    getRedisUrl: () => {
        const { host, port, password } = config.redis;
        return password ? `redis://:${password}@${host}:${port}` : `redis://${host}:${port}`;
    },
    
    // VULNERABILITY: Function that exposes sensitive config
    getAllSecrets: () => {
        return {
            jwtSecret: config.jwt.secret,
            dbPassword: config.database.password,
            redisPassword: config.redis.password,
            encryptionKey: config.security.encryption.key,
            stripeSecret: config.externalApis.stripe.secretKey,
            awsSecretKey: config.externalApis.aws.secretAccessKey
        };
    }
};

// Export configuration
module.exports = {
    ...config,
    helpers: configHelpers
};

// VULNERABILITY: Debug code left in production
if (process.env.DEBUG_CONFIG === 'true') {
    console.log('=== FULL CONFIGURATION DEBUG ===');
    console.log(JSON.stringify(config, null, 2)); // Logs all secrets in debug mode
    console.log('=== END CONFIGURATION DEBUG ===');
}