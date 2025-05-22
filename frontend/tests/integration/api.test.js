const request = require('supertest');
const app = require('../../src/app');
const { setupTestDatabase, cleanupTestDatabase } = require('../helpers/database');
const { createTestUser, createTestProduct } = require('../helpers/fixtures');

// Clean integration tests with proper security practices
describe('API Integration Tests', () => {
    let testUser;
    let authToken;
    
    beforeAll(async () => {
        await setupTestDatabase();
    });
    
    afterAll(async () => {
        await cleanupTestDatabase();
    });
    
    beforeEach(async () => {
        testUser = await createTestUser({
            email: 'test@example.com',
            name: 'Test User'
        });
        
        // Get auth token through proper login flow
        const loginResponse = await request(app)
            .post('/api/auth/login')
            .send({
                email: testUser.email,
                password: 'TestPassword123!'
            });
            
        authToken = loginResponse.body.token;
    });

    describe('Authentication Endpoints', () => {
        test('POST /api/auth/register creates new user', async () => {
            const userData = {
                email: 'newuser@example.com',
                password: 'SecurePassword123!',
                name: 'New User'
            };
            
            const response = await request(app)
                .post('/api/auth/register')
                .send(userData)
                .expect(201);
            
            expect(response.body.user.email).toBe(userData.email);
            expect(response.body.user.name).toBe(userData.name);
            expect(response.body.token).toBeDefined();
            expect(response.body.user.password).toBeUndefined(); // Password should not be returned
        });

        test('POST /api/auth/login authenticates existing user', async () => {
            const response = await request(app)
                .post('/api/auth/login')
                .send({
                    email: testUser.email,
                    password: 'TestPassword123!'
                })
                .expect(200);
            
            expect(response.body.token).toBeDefined();
            expect(response.body.user.id).toBe(testUser.id);
        });

        test('POST /api/auth/login rejects invalid credentials', async () => {
            await request(app)
                .post('/api/auth/login')
                .send({
                    email: testUser.email,
                    password: 'wrongpassword'
                })
                .expect(401);
        });

        test('POST /api/auth/logout invalidates token', async () => {
            await request(app)
                .post('/api/auth/logout')
                .set('Authorization', `Bearer ${authToken}`)
                .expect(200);
            
            // Verify token is no longer valid
            await request(app)
                .get('/api/profile')
                .set('Authorization', `Bearer ${authToken}`)
                .expect(401);
        });
    });

    describe('User Profile Endpoints', () => {
        test('GET /api/profile returns authenticated user data', async () => {
            const response = await request(app)
                .get('/api/profile')
                .set('Authorization', `Bearer ${authToken}`)
                .expect(200);
            
            expect(response.body.id).toBe(testUser.id);
            expect(response.body.email).toBe(testUser.email);
            expect(response.body.password).toBeUndefined();
        });

        test('PUT /api/profile updates user data', async () => {
            const updateData = {
                name: 'Updated Name',
                bio: 'Updated bio'
            };
            
            const response = await request(app)
                .put('/api/profile')
                .set('Authorization', `Bearer ${authToken}`)
                .send(updateData)
                .expect(200);
            
            expect(response.body.name).toBe(updateData.name);
            expect(response.body.bio).toBe(updateData.bio);
        });

        test('PUT /api/profile validates input data', async () => {
            const invalidData = {
                email: 'invalid-email', // Invalid email format
                name: '' // Empty name
            };
            
            const response = await request(app)
                .put('/api/profile')
                .set('Authorization', `Bearer ${authToken}`)
                .send(invalidData)
                .expect(400);
            
            expect(response.body.errors).toBeDefined();
            expect(response.body.errors).toContain('Invalid email format');
            expect(response.body.errors).toContain('Name is required');
        });
    });

    describe('Product Endpoints', () => {
        let testProduct;
        
        beforeEach(async () => {
            testProduct = await createTestProduct({
                name: 'Test Product',
                price: 99.99,
                description: 'Test product description'
            });
        });

        test('GET /api/products returns product list', async () => {
            const response = await request(app)
                .get('/api/products')
                .expect(200);
            
            expect(Array.isArray(response.body.products)).toBe(true);
            expect(response.body.products.length).toBeGreaterThan(0);
            expect(response.body.pagination).toBeDefined();
        });

        test('GET /api/products/:id returns specific product', async () => {
            const response = await request(app)
                .get(`/api/products/${testProduct.id}`)
                .expect(200);
            
            expect(response.body.id).toBe(testProduct.id);
            expect(response.body.name).toBe(testProduct.name);
            expect(response.body.price).toBe(testProduct.price);
        });

        test('GET /api/products/:id returns 404 for non-existent product', async () => {
            const nonExistentId = 99999;
            
            await request(app)
                .get(`/api/products/${nonExistentId}`)
                .expect(404);
        });

        test('GET /api/products supports search and filtering', async () => {
            const response = await request(app)
                .get('/api/products')
                .query({
                    search: 'Test',
                    minPrice: 50,
                    maxPrice: 150,
                    page: 1,
                    limit: 10
                })
                .expect(200);
            
            expect(response.body.products.every(p => 
                p.name.includes('Test') && p.price >= 50 && p.price <= 150
            )).toBe(true);
        });
    });

    describe('Protected Endpoints', () => {
        test('protected routes require authentication', async () => {
            await request(app)
                .get('/api/profile')
                .expect(401);
        });

        test('protected routes reject invalid tokens', async () => {
            await request(app)
                .get('/api/profile')
                .set('Authorization', 'Bearer invalid-token')
                .expect(401);
        });

        test('protected routes reject expired tokens', async () => {
            // This would require mocking time or using a test token with short expiry
            // Implementation depends on your JWT configuration
        });
    });

    describe('Error Handling', () => {
        test('returns proper error format for validation errors', async () => {
            const response = await request(app)
                .post('/api/auth/register')
                .send({
                    email: 'invalid-email',
                    password: '123' // Too short
                })
                .expect(400);
            
            expect(response.body.error).toBeDefined();
            expect(response.body.errors).toBeDefined();
            expect(Array.isArray(response.body.errors)).toBe(true);
        });

        test('handles server errors gracefully', async () => {
            // Test depends on having an endpoint that can trigger a server error
            // This might involve mocking database failures or other external services
        });

        test('returns proper CORS headers', async () => {
            const response = await request(app)
                .options('/api/products')
                .expect(200);
            
            expect(response.headers['access-control-allow-origin']).toBeDefined();
            expect(response.headers['access-control-allow-methods']).toBeDefined();
        });
    });

    describe('Rate Limiting', () => {
        test('enforces rate limits on auth endpoints', async () => {
            const promises = [];
            
            // Make multiple rapid requests
            for (let i = 0; i < 20; i++) {
                promises.push(
                    request(app)
                        .post('/api/auth/login')
                        .send({
                            email: 'test@example.com',
                            password: 'wrongpassword'
                        })
                );
            }
            
            const responses = await Promise.all(promises);
            const tooManyRequests = responses.filter(r => r.status === 429);
            
            expect(tooManyRequests.length).toBeGreaterThan(0);
        });
    });
});

// Helper functions for clean testing
const testHelpers = {
    createAuthHeaders: (token) => ({
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    }),
    
    expectValidationError: (response, field) => {
        expect(response.status).toBe(400);
        expect(response.body.errors).toBeDefined();
        expect(response.body.errors.some(error => 
            error.field === field || error.includes(field)
        )).toBe(true);
    },
    
    expectAuthError: (response) => {
        expect(response.status).toBe(401);
        expect(response.body.error).toMatch(/unauthorized|authentication/i);
    }
};

module.exports = { testHelpers };