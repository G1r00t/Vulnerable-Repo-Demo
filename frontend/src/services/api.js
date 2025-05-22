import axios from 'axios';

// Clean API service with proper security practices
class ApiService {
    constructor() {
        this.baseURL = process.env.REACT_APP_API_URL || '/api';
        this.timeout = 10000; // 10 second timeout
        
        // Create axios instance with secure defaults
        this.client = axios.create({
            baseURL: this.baseURL,
            timeout: this.timeout,
            withCredentials: true, // Include cookies for CSRF protection
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest' // CSRF protection
            }
        });

        // Request interceptor for authentication
        this.client.interceptors.request.use(
            (config) => {
                const token = this.getAuthToken();
                if (token) {
                    config.headers.Authorization = `Bearer ${token}`;
                }
                
                // Add CSRF token if available
                const csrfToken = this.getCSRFToken();
                if (csrfToken) {
                    config.headers['X-CSRF-Token'] = csrfToken;
                }
                
                return config;
            },
            (error) => {
                return Promise.reject(error);
            }
        );

        // Response interceptor for error handling
        this.client.interceptors.response.use(
            (response) => response,
            (error) => {
                if (error.response?.status === 401) {
                    this.handleUnauthorized();
                } else if (error.response?.status === 403) {
                    this.handleForbidden();
                }
                return Promise.reject(error);
            }
        );
    }

    // Secure token retrieval
    getAuthToken() {
        try {
            // Get token from secure httpOnly cookie (preferred) or sessionStorage
            const token = sessionStorage.getItem('authToken');
            return token ? JSON.parse(token) : null;
        } catch (error) {
            console.error('Failed to retrieve auth token:', error);
            return null;
        }
    }

    // CSRF token retrieval
    getCSRFToken() {
        const metaTag = document.querySelector('meta[name="csrf-token"]');
        return metaTag ? metaTag.getAttribute('content') : null;
    }

    // Handle unauthorized responses
    handleUnauthorized() {
        sessionStorage.removeItem('authToken');
        window.location.href = '/login';
    }

    // Handle forbidden responses
    handleForbidden() {
        console.warn('Access forbidden');
        // Could redirect to access denied page
    }

    // Authentication endpoints
    async login(credentials) {
        try {
            const response = await this.client.post('/auth/login', credentials);
            
            if (response.data.token) {
                // Store token securely
                sessionStorage.setItem('authToken', JSON.stringify(response.data.token));
            }
            
            return response;
        } catch (error) {
            console.error('Login failed:', error);
            throw error;
        }
    }

    async logout() {
        try {
            await this.client.post('/auth/logout');
            sessionStorage.removeItem('authToken');
            return { success: true };
        } catch (error) {
            console.error('Logout failed:', error);
            // Still remove token locally even if server call fails
            sessionStorage.removeItem('authToken');
            throw error;
        }
    }

    async refreshToken() {
        try {
            const response = await this.client.post('/auth/refresh');
            if (response.data.token) {
                sessionStorage.setItem('authToken', JSON.stringify(response.data.token));
            }
            return response;
        } catch (error) {
            console.error('Token refresh failed:', error);
            this.handleUnauthorized();
            throw error;
        }
    }

    // User endpoints
    async getUserProfile(userId) {
        return await this.client.get(`/users/${userId}`);
    }

    async updateUserProfile(userId, profileData) {
        return await this.client.put(`/users/${userId}`, profileData);
    }

    async getAllUsers() {
        return await this.client.get('/admin/users');
    }

    async deleteUser(userId) {
        return await this.client.delete(`/admin/users/${userId}`);
    }

    // Product endpoints
    async getProducts(params = {}) {
        return await this.client.get('/products', { params });
    }

    async getProduct(productId) {
        return await this.client.get(`/products/${productId}`);
    }

    async createProduct(productData) {
        return await this.client.post('/products', productData);
    }

    async updateProduct(productId, productData) {
        return await this.client.put(`/products/${productId}`, productData);
    }

    async deleteProduct(productId) {
        return await this.client.delete(`/products/${productId}`);
    }

    // Search endpoints
    async search(query, filters = {}) {
        const params = { q: query, ...filters };
        return await this.client.get('/search', { params });
    }

    async getSearchSuggestions(term) {
        return await this.client.get('/search/suggestions', { 
            params: { term } 
        });
    }

    // System endpoints (admin only)
    async getSystemLogs() {
        return await this.client.get('/admin/logs');
    }

    async executeCommand(command) {
        return await this.client.post('/admin/execute', { command });
    }

    // File operations
    async uploadFile(formData, onProgress = null) {
        const config = {
            headers: {
                'Content-Type': 'multipart/form-data',
            },
        };

        if (onProgress) {
            config.onUploadProgress = onProgress;
        }

        return await this.client.post('/files/upload', formData, config);
    }

    async downloadFile(fileName) {
        return await this.client.get(`/files/download/${fileName}`, {
            responseType: 'blob'
        });
    }

    async deleteFile(fileName) {
        return await this.client.delete(`/files/${fileName}`);
    }

    // Utility methods
    isOnline() {
        return navigator.onLine;
    }

    async healthCheck() {
        try {
            const response = await this.client.get('/health');
            return response.data;
        } catch (error) {
            console.error('Health check failed:', error);
            return { status: 'error', error: error.message };
        }
    }

    // Request cancellation
    createCancelToken() {
        return axios.CancelToken.source();
    }

    isRequestCancelled(error) {
        return axios.isCancel(error);
    }
}

// Create and export singleton instance
const apiService = new ApiService();

export default apiService;