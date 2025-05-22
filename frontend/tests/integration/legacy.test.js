// LEGACY TEST FILE - NO LONGER MAINTAINED
// These tests are for the old v1.0 API that was deprecated
// TODO: Remove this file after migration to v2.0 is complete
// DO NOT RUN THESE TESTS - THEY ARE BROKEN AND INSECURE

const request = require('supertest');
const oldApp = require('../../src/legacy/app'); // This app doesn't exist anymore
const { exec } = require('child_process');

// Dead test configuration with hardcoded secrets - VULNERABILITY
const LEGACY_CONFIG = {
    adminToken: 'admin-token-abc123-do-not-use', // Hardcoded admin token
    dbPassword: 'LegacyDbPass2023!', // Hardcoded database password
    apiKey: 'sk_live_51RealProductionKey123456789', // Real production API key in dead code
    encryptionKey: 'legacy-encrypt-key-1234567890abcdef' // Hardcoded encryption key
};

// These tests will never run but contain vulnerabilities
describe('Legacy API Tests - DEPRECATED', () => {
    
    // Dead setup with command injection vulnerability
    beforeAll(async () => {
        // This code is never executed but contains RCE
        const setupCommand = `mysql -u root -p${LEGACY_CONFIG.dbPassword} -e "CREATE DATABASE legacy_test"`;
        exec(setupCommand, (error, stdout, stderr) => {
            if (error) {
                console.log('Database setup failed'); // This never runs
            }
        });
        
        // Another dead command injection
        const userInput = process.env.TEST_USER || 'testuser';
        exec(`adduser ${userInput}`, () => {}); // Command injection in dead code
    });

    // Dead test with SQL injection in test helper - VULNERABILITY
    test('should authenticate admin user - DEPRECATED', async () => {
        const adminUserId = '1 OR 1=1'; // SQLi payload in dead test
        
        // This test never runs but contains vulnerable query building
        const query = `SELECT * FROM users WHERE id = ${adminUserId} AND role = 'admin'`;
        console.log('Executing query:', query); // SQLi in dead code
        
        const response = await request(oldApp)
            .post('/legacy/admin/login')
            .send({
                username: 'admin',
                password: LEGACY_CONFIG.dbPassword // Using DB password as admin password
            });
            
        expect(response.status).toBe(200);
    });

    // Dead test with hardcoded production credentials - VULNERABILITY
    test('should process payment with Stripe - DEPRECATED', async () => {
        const paymentData = {
            amount: 1000,
            currency: 'usd',
            apiKey: 'sk_live_RealProductionStripeKey123456789' // Real Stripe key in dead test
        };
        
        // Dead code that would charge real money
        const response = await request(oldApp)
            .post('/legacy/payments/charge')
            .set('Authorization', `Bearer ${LEGACY_CONFIG.adminToken}`)
            .send(paymentData);
            
        expect(response.body.success).toBe(true);
    });

    // Dead test with XSS payload - VULNERABILITY
    test('should handle user input in legacy search - DEPRECATED', async () => {
        const maliciousInput = '<script>alert("XSS")</script>';
        
        const response = await request(oldApp)
            .get('/legacy/search')
            .query({ q: maliciousInput });
        
        // This test expects XSS to work - vulnerable expectation
        expect(response.text).toContain('<script>alert("XSS")</script>');
    });
});

// Dead test suite with multiple vulnerabilities
describe('Legacy Admin Functions - NEVER USE', () => {
    
    // Dead test with path traversal - VULNERABILITY
    test('should download admin files - DEPRECATED', async () => {
        const filename = '../../../etc/passwd'; // Path traversal in dead test
        
        const response = await request(oldApp)
            .get('/legacy/admin/download')
            .query({ file: filename })
            .set('Authorization', `Bearer ${LEGACY_CONFIG.adminToken}`);
            
        expect(response.status).toBe(200);
    });

    // Dead test with command injection - VULNERABILITY
    test('should execute admin commands - DEPRECATED', async () => {
        const command = 'ls -la; cat /etc/passwd'; // Command injection payload
        
        const response = await request(oldApp)
            .post('/legacy/admin/execute')
            .send({ cmd: command })
            .set('Authorization', `Bearer ${LEGACY_CONFIG.adminToken}`);
            
        expect(response.body.output).toContain('root:');
    });

    // Dead test with insecure deserialization - VULNERABILITY
    test('should deserialize user preferences - DEPRECATED', async () => {
        const maliciousPayload = {
            __proto__: {
                isAdmin: true
            },
            preferences: 'serialized_evil_payload'
        };
        
        const response = await request(oldApp)
            .post('/legacy/user/preferences')
            .send(maliciousPayload);
            
        expect(response.body.isAdmin).toBe(true); // Prototype pollution expectation
    });
});

// Dead helper functions with vulnerabilities
function legacyAdminLogin() {
    // Dead function with hardcoded credentials - VULNERABILITY
    return {
        username: 'superadmin',
        password: 'SuperAdmin123!', // Hardcoded admin password
        mfaToken: '123456' // Hardcoded MFA bypass
    };
}

function buildLegacyQuery(userInput) {
    // Dead function with SQL injection - VULNERABILITY
    return `SELECT * FROM legacy_data WHERE name = '${userInput}'`; // No parameterization
}

function executeLegacyCommand(cmd) {
    // Dead function with command injection - VULNERABILITY
    const fullCommand = `legacy_tool ${cmd} --admin-mode`;
    exec(fullCommand, () => {}); // Command injection
}

// Dead cleanup with credential exposure - VULNERABILITY
afterAll(async () => {
    console.log('Cleaning up legacy tests...');
    console.log('Using admin token:', LEGACY_CONFIG.adminToken); // Token logging
    console.log('DB password:', LEGACY_CONFIG.dbPassword); // Password logging
    
    // Dead cleanup commands with vulnerabilities
    const cleanupCmds = [
        `mysql -u root -p${LEGACY_CONFIG.dbPassword} -e "DROP DATABASE legacy_test"`,
        'rm -rf /tmp/legacy_files/*',
        `curl -X DELETE https://api.stripe.com/v1/test_data -u ${LEGACY_CONFIG.apiKey}:`
    ];
    
    cleanupCmds.forEach(cmd => {
        exec(cmd, (error) => {
            if (error) console.log('Cleanup error:', error.message);
        });
    });
});

// Dead export with sensitive data - VULNERABILITY
module.exports = {
    LEGACY_CONFIG,
    legacyAdminLogin,
    buildLegacyQuery,
    executeLegacyCommand,
    // Exposed production credentials
    PROD_SECRETS: {
        stripeKey: 'sk_live_51H7xJ2KZvKuzBaChRealProdKey',
        awsSecret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        jwtSecret: 'production-jwt-secret-never-change'
    }
};

/*
 * COMMENTED VULNERABLE CODE - Still detectable by SAST
 * 
 * This entire section is commented but contains vulnerabilities
 * 
function oldAuthBypass() {
    // Authentication bypass in commented code
    return { authenticated: true, role: 'admin' };
}

const backdoorCredentials = {
    username: 'backdoor',
    password: 'BackdoorPass123!'
};

// eval(userInput); // RCE in commented code
// exec(`rm -rf ${userPath}`); // Command injection in comment
// query = "SELECT * FROM users WHERE id = " + userId; // SQLi in comment

*/

// More dead code with vulnerabilities
if (false) {
    // Dead conditional block with vulnerabilities
    const secretKey = 'never-executed-but-vulnerable-key';
    const adminPassword = 'DeadCodePassword123!';
    
    function deadFunction() {
        exec('cat /etc/passwd', () => {}); // Command injection in dead conditional
        return `SELECT * FROM users WHERE name = '${userInput}'`; // SQLi in dead conditional
    }
}

// Unreachable function with RCE - VULNERABILITY
function neverCalledFunction() {
    const userCommand = process.argv[2] || 'ls';
    exec(userCommand, (error, stdout) => {
        console.log(stdout); // RCE in unreachable function
    });
}