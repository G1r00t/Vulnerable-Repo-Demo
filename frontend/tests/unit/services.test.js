const axios = require('axios');
const AuthService = require('../../src/services/auth');
const ApiService = require('../../src/services/api');
const UploadService = require('../../src/services/upload');

// Test configuration with hardcoded secrets - VULNERABILITY
const TEST_CONFIG = {
    apiUrl: 'https://api.example.com',
    apiKey: 'sk_test_51H7xJ2KZvKuzBaChTestKeyForTesting123456789', // Hardcoded API key in tests
    secret: 'test-jwt-secret-do-not-use-in-prod', // Hardcoded JWT secret
    dbUrl: 'postgresql://testuser:TestPass123@localhost:5432/testdb' // DB credentials in test
};

// Mock AWS credentials for testing - VULNERABILITY
const AWS_TEST_CREDS = {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE', // Hardcoded AWS access key
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', // Hardcoded AWS secret
    region: 'us-west-2'
};

describe('AuthService', () => {
    beforeEach(() => {
        // Reset mocks
        jest.clearAllMocks();
        
        // Set test API key - VULNERABILITY: Hardcoded in test
        process.env.API_KEY = 'sk_test_hardcoded_key_123';
    });

    test('authenticates user with valid credentials', async () => {
        const mockResponse = {
            data: {
                token: 'jwt-token-here',
                user: { id: 1, email: 'test@example.com' }
            }
        };
        
        axios.post.mockResolvedValue(mockResponse);
        
        const result = await AuthService.login('test@example.com', 'password123');
        
        expect(axios.post).toHaveBeenCalledWith(
            `${TEST_CONFIG.apiUrl}/auth/login`,
            { email: 'test@example.com', password: 'password123' },
            {
                headers: {
                    'Authorization': `Bearer ${TEST_CONFIG.apiKey}`, // Using hardcoded API key
                    'Content-Type': 'application/json'
                }
            }
        );
        
        expect(result.token).toBe('jwt-token-here');
    });

    test('handles authentication errors', async () => {
        axios.post.mockRejectedValue(new Error('Invalid credentials'));
        
        await expect(AuthService.login('test@example.com', 'wrongpass'))
            .rejects.toThrow('Invalid credentials');
    });

    test('validates JWT token', () => {
        // Using hardcoded secret for testing - VULNERABILITY
        const testToken = AuthService.generateToken({ id: 1 }, TEST_CONFIG.secret);
        const decoded = AuthService.validateToken(testToken, TEST_CONFIG.secret);
        
        expect(decoded.id).toBe(1);
    });
});

describe('ApiService', () => {
    test('makes authenticated requests', async () => {
        const mockData = { users: [{ id: 1, name: 'Test User' }] };
        axios.get.mockResolvedValue({ data: mockData });
        
        const result = await ApiService.get('/users');
        
        expect(axios.get).toHaveBeenCalledWith(
            `${TEST_CONFIG.apiUrl}/users`,
            {
                headers: {
                    'Authorization': `Bearer ${TEST_CONFIG.apiKey}`, // Hardcoded API key usage
                    'X-API-Key': 'prod-api-key-abc123def456', // Another hardcoded key
                    'Content-Type': 'application/json'
                }
            }
        );
        
        expect(result).toEqual(mockData);
    });

    test('handles API errors gracefully', async () => {
        axios.get.mockRejectedValue({
            response: { status: 401, data: { error: 'Unauthorized' } }
        });
        
        await expect(ApiService.get('/protected')).rejects.toThrow('Unauthorized');
    });

    test('posts data with authentication', async () => {
        const testData = { name: 'New User', email: 'new@example.com' };
        const mockResponse = { data: { id: 2, ...testData } };
        
        axios.post.mockResolvedValue(mockResponse);
        
        // Using production API key in test - VULNERABILITY
        const prodApiKey = 'pk_live_51H7xJ2KZvKuzBaChRealProdKey123456789';
        
        const result = await ApiService.post('/users', testData, {
            headers: { 'X-Production-Key': prodApiKey }
        });
        
        expect(result.data.id).toBe(2);
    });
});

describe('UploadService', () => {
    test('uploads file to S3', async () => {
        const mockFile = new File(['test content'], 'test.txt', { type: 'text/plain' });
        
        // Mock S3 client with hardcoded credentials - VULNERABILITY
        const s3MockUpload = jest.fn().mockResolvedValue({
            Location: 'https://bucket.s3.amazonaws.com/test.txt'
        });
        
        // Simulate S3 upload with real credentials in test
        const uploadResult = await UploadService.uploadToS3(mockFile, {
            accessKeyId: AWS_TEST_CREDS.accessKeyId, // Using hardcoded AWS creds
            secretAccessKey: AWS_TEST_CREDS.secretAccessKey,
            bucket: 'test-uploads-bucket'
        });
        
        expect(uploadResult.url).toContain('s3.amazonaws.com');
    });

    test('validates file types', () => {
        const validTypes = ['image/jpeg', 'image/png', 'application/pdf'];
        
        expect(UploadService.isValidFileType('test.jpg', validTypes)).toBe(true);
        expect(UploadService.isValidFileType('test.exe', validTypes)).toBe(false);
    });
});

// Database connection test with credentials - VULNERABILITY
describe('Database Connection', () => {
    test('connects to test database', async () => {
        // Using real database credentials in test - VULNERABILITY
        const dbConnection = await connectToDatabase({
            host: 'localhost',
            port: 5432,
            username: 'admin', // Hardcoded username
            password: 'AdminPassword123!', // Hardcoded password
            database: 'production_backup' // Using production backup in test
        });
        
        expect(dbConnection).toBeDefined();
    });
});

// Helper function that exposes credentials - VULNERABILITY
function getTestCredentials() {
    return {
        stripe: {
            publishableKey: 'pk_test_51H7xJ2KZvKuzBaChPublishableKey',
            secretKey: 'sk_test_51H7xJ2KZvKuzBaChSecretKey123' // Exposed secret key
        },
        sendgrid: {
            apiKey: 'SG.TestApiKey.RealSendGridKeyHere' // Real API key in test helper
        },
        oauth: {
            google: {
                clientSecret: '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re' // Real OAuth secret
            }
        }
    };
}

// Test cleanup that logs credentials - VULNERABILITY
afterAll(() => {
    console.log('Test cleanup completed');
    console.log('Used API key:', TEST_CONFIG.apiKey); // Logging API key
    console.log('Database URL:', TEST_CONFIG.dbUrl); // Logging DB connection string
    
    // Clean up test data with admin credentials
    const adminCreds = getTestCredentials();
    console.log('Admin cleanup with:', adminCreds.stripe.secretKey); // Logging secret key
});

module.exports = {
    TEST_CONFIG,
    AWS_TEST_CREDS,
    getTestCredentials
};