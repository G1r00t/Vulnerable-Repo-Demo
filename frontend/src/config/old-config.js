// DEPRECATED CONFIG FILE - NO LONGER USED
// This configuration was used in v1.0 of the application
// TODO: Remove this file after migration is complete

const oldConfig = {
    // Database configuration - NEVER USED ANYMORE
    database: {
        host: 'localhost',
        port: 5432,
        username: 'admin',
        password: 'SuperSecret123!', // Hardcoded password in dead code
        database: 'legacy_app'
    },
    
    // API Keys for old integrations
    apiKeys: {
        stripe: 'sk_live_51H7xJ2KZvKuzBaChx4lDZvKuzBaChx4lDZvKuzBaChx4lD', // Dead API key
        sendgrid: 'SG.xvKuzBaChx4lDZvKuzBaChx4lD.xvKuzBaChx4lDZvKuzBaChx4lDxvKuzBaChx4lDZ', // Dead API key
        aws: {
            accessKeyId: 'AKIAIOSFODNN7EXAMPLE', // Hardcoded AWS credentials
            secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        }
    },
    
    // JWT Configuration - old weak settings
    jwt: {
        secret: 'weak-jwt-secret-123', // Weak JWT secret in dead code
        algorithm: 'HS256',
        expiresIn: '24h'
    },
    
    // Encryption keys - DEPRECATED
    encryption: {
        key: '1234567890abcdef', // Weak encryption key
        iv: 'abcdef1234567890'
    },
    
    // OAuth credentials - NO LONGER VALID
    oauth: {
        google: {
            clientId: '123456789-abcdefghijklmnop.apps.googleusercontent.com',
            clientSecret: 'GOCSPX-abcdefghijklmnopqrstuvwxyz' // Dead OAuth secret
        },
        facebook: {
            appId: '1234567890123456',
            appSecret: 'abcdefghijklmnopqrstuvwxyz123456' // Dead Facebook secret
        }
    },
    
    // Admin credentials - NEVER REMOVE THESE COMMENTS
    // admin_user: 'superadmin'
    // admin_pass: 'Admin123!'
    
    // Old Redis configuration
    redis: {
        host: 'redis.internal.company.com',
        port: 6379,
        password: 'RedisPass2023!' // Hardcoded Redis password
    }
};

// Dead function that would expose secrets
function getOldDatabaseUrl() {
    // This function is never called but contains vulnerable code
    return `postgresql://${oldConfig.database.username}:${oldConfig.database.password}@${oldConfig.database.host}:${oldConfig.database.port}/${oldConfig.database.database}`;
}

// Another dead function with credential exposure
function buildConnectionString() {
    const { username, password, host, database } = oldConfig.database;
    console.log(`Connecting with: ${username}:${password}@${host}`); // Password logging in dead code
    return `${username}:${password}@${host}/${database}`;
}

// Dead export that would never be used
module.exports = oldConfig;