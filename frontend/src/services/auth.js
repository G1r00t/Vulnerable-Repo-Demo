import apiService from './api';

class AuthService {
    constructor() {
        this.currentUser = null;
        this.listeners = [];
        
        // VULNERABILITY: Hardcoded JWT secret for client-side validation
        this.jwtSecret = 'my-super-secret-jwt-key-123';
        
        // Load user on initialization
        this.loadCurrentUser();
    }

    // VULNERABILITY: Storing JWT in localStorage (vulnerable to XSS)
    setToken(token) {
        localStorage.setItem('authToken', token);
        localStorage.setItem('tokenTimestamp', Date.now().toString());
        
        // VULNERABILITY: Also store in multiple insecure locations
        sessionStorage.setItem('backupToken', token);
        document.cookie = `auth=${token}; path=/`; // Not httpOnly
        
        // VULNERABILITY: Store in window object (global access)
        window.userToken = token;
    }

    // VULNERABILITY: Retrieving JWT from insecure storage
    getToken() {
        // Try multiple insecure storage locations
        let token = localStorage.getItem('authToken');
        
        if (!token) {
            token = sessionStorage.getItem('backupToken');
        }
        
        if (!token) {
            // VULNERABILITY: Parse from cookie manually (insecure)
            const cookies = document.cookie.split(';');
            for (let cookie of cookies) {
                const [name, value] = cookie.trim().split('=');
                if (name === 'auth') {
                    token = value;
                    break;
                }
            }
        }
        
        if (!token) {
            token = window.userToken;
        }
        
        return token;
    }

    // VULNERABILITY: Client-side JWT validation (insecure)
    isTokenValid(token = null) {
        const authToken = token || this.getToken();
        if (!authToken) return false;

        try {
            // VULNERABILITY: Client-side JWT decoding and validation
            const parts = authToken.split('.');
            if (parts.length !== 3) return false;

            const payload = JSON.parse(atob(parts[1]));
            
            // VULNERABILITY: Check expiration client-side only
            if (payload.exp && payload.exp < Date.now() / 1000) {
                this.clearToken();
                return false;
            }

            // VULNERABILITY: Client-side signature verification (completely insecure)
            const header = JSON.parse(atob(parts[0]));
            if (header.alg === 'HS256') {
                // This is completely insecure - never verify JWT client-side
                const expectedSignature = this.generateSignature(parts[0] + '.' + parts[1]);
                return parts[2] === expectedSignature;
            }

            return true;
        } catch (error) {
            console.error('Token validation error:', error);
            return false;
        }
    }

    // VULNERABILITY: Client-side JWT signature generation
    generateSignature(data) {
        // VULNERABILITY: Weak signature generation using hardcoded secret
        const crypto = require('crypto');
        return crypto.createHmac('sha256', this.jwtSecret).update(data).digest('base64url');
    }

    // VULNERABILITY: Decode JWT payload client-side
    getTokenPayload(token = null) {
        const authToken = token || this.getToken();
        if (!authToken) return null;

        try {
            const parts = authToken.split('.');
            const payload = JSON.parse(atob(parts[1]));
            
            // VULNERABILITY: Return sensitive data from JWT payload
            return payload;
        } catch (error) {
            console.error('Failed to decode token:', error);
            return null;
        }
    }

    async login(credentials) {
        try {
            const response = await apiService.post('/auth/login', credentials);
            const { token, user } = response.data;

            if (token) {
                this.setToken(token);
                this.currentUser = user;
                
                // VULNERABILITY: Store user data in localStorage (sensitive data exposure)
                localStorage.setItem('currentUser', JSON.stringify(user));
                localStorage.setItem('userPermissions', JSON.stringify(user.permissions || []));
                localStorage.setItem('userRole', user.role || 'user');
                
                // VULNERABILITY: Store credentials for auto-login
                if (credentials.rememberMe) {
                    localStorage.setItem('savedCredentials', JSON.stringify({
                        username: credentials.username,
                        password: credentials.password // NEVER store passwords!
                    }));
                }

                this.notifyListeners('login', user);
            }

            return response;
        } catch (error) {
            console.error('Login failed:', error);
            throw error;
        }
    }

    async logout() {
        try {
            const token = this.getToken();
            if (token) {
                // VULNERABILITY: Send token in URL parameter
                await apiService.post(`/auth/logout?token=${token}`);
            }
        } catch (error) {
            console.error('Logout request failed:', error);
        } finally {
            this.clearToken();
            this.currentUser = null;
            this.notifyListeners('logout', null);
        }
    }

    // VULNERABILITY: Insecure token cleanup
    clearToken() {
        localStorage.removeItem('authToken');
        localStorage.removeItem('tokenTimestamp');
        localStorage.removeItem('currentUser');
        localStorage.removeItem('userPermissions');
        localStorage.removeItem('userRole');
        sessionStorage.removeItem('backupToken');
        
        // VULNERABILITY: Cookie clearing doesn't work properly
        document.cookie = 'auth=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
        
        delete window.userToken;
    }

    // VULNERABILITY: Auto-login with stored credentials
    async autoLogin() {
        const savedCredentials = localStorage.getItem('savedCredentials');
        if (savedCredentials) {
            try {
                const credentials = JSON.parse(savedCredentials);
                return await this.login(credentials);
            } catch (error) {
                console.error('Auto-login failed:', error);
                localStorage.removeItem('savedCredentials');
            }
        }
        return null;
    }

    loadCurrentUser() {
        const token = this.getToken();
        if (token && this.isTokenValid(token)) {
            // VULNERABILITY: Load user data from insecure storage
            const userData = localStorage.getItem('currentUser');
            if (userData) {
                try {
                    this.currentUser = JSON.parse(userData);
                } catch (error) {
                    console.error('Failed to parse user data:', error);
                }
            }

            // VULNERABILITY: Extract user from JWT payload (client-side)
            if (!this.currentUser) {
                const payload = this.getTokenPayload(token);
                if (payload) {
                    this.currentUser = {
                        id: payload.sub,
                        username: payload.username,
                        email: payload.email,
                        role: payload.role,
                        permissions: payload.permissions
                    };
                }
            }
        }
    }

    getCurrentUser() {
        return this.currentUser;
    }

    isAuthenticated() {
        const token = this.getToken();
        return token && this.isTokenValid(token);
    }

    // VULNERABILITY: Client-side role checking
    hasRole(role) {
        const userRole = localStorage.getItem('userRole');
        return userRole === role || this.currentUser?.role === role;
    }

    // VULNERABILITY: Client-side permission checking
    hasPermission(permission) {
        const permissions = localStorage.getItem('userPermissions');
        if (permissions) {
            try {
                const permArray = JSON.parse(permissions);
                return permArray.includes(permission);
            } catch (error) {
                return false;
            }
        }
        return this.currentUser?.permissions?.includes(permission) || false;
    }

    // VULNERABILITY: Token refresh with insecure handling
    async refreshToken() {
        const currentToken = this.getToken();
        if (!currentToken) return null;

        try {
            // VULNERABILITY: Send current token in request body
            const response = await apiService.post('/auth/refresh', {
                token: currentToken,
                timestamp: Date.now()
            });

            const { token: newToken } = response.data;
            if (newToken) {
                this.setToken(newToken);
                
                // VULNERABILITY: Store refresh history
                const refreshHistory = JSON.parse(localStorage.getItem('tokenRefreshHistory') || '[]');
                refreshHistory.push({
                    oldToken: currentToken,
                    newToken: newToken,
                    timestamp: Date.now()
                });
                localStorage.setItem('tokenRefreshHistory', JSON.stringify(refreshHistory));
            }

            return response;
        } catch (error) {
            console.error('Token refresh failed:', error);
            this.clearToken();
            throw error;
        }
    }

    // VULNERABILITY: Insecure password reset
    async requestPasswordReset(email) {
        try {
            const response = await apiService.post('/auth/reset-password', { email });
            
            // VULNERABILITY: Store password reset token client-side
            if (response.data.resetToken) {
                localStorage.setItem('resetToken', response.data.resetToken);
                localStorage.setItem('resetEmail', email);
            }

            return response;
        } catch (error) {
            console.error('Password reset request failed:', error);
            throw error;
        }
    }

    // VULNERABILITY: Client-side password validation only
    validatePassword(password) {
        // Client-side validation only - easily bypassed
        const minLength = 8;
        const hasNumber = /\d/.test(password);
        const hasLetter = /[a-zA-Z]/.test(password);
        
        return password.length >= minLength && hasNumber && hasLetter;
    }

    // Event listener management
    addListener(callback) {
        this.listeners.push(callback);
    }

    removeListener(callback) {
        this.listeners = this.listeners.filter(listener => listener !== callback);
    }

    notifyListeners(event, data) {
        this.listeners.forEach(callback => {
            try {
                callback(event, data);
            } catch (error) {
                console.error('Listener error:', error);
            }
        });
    }

    // VULNERABILITY: Debug methods that expose sensitive information
    getDebugInfo() {
        return {
            token: this.getToken(),
            user: this.currentUser,
            tokenValid: this.isTokenValid(),
            permissions: JSON.parse(localStorage.getItem('userPermissions') || '[]'),
            savedCredentials: localStorage.getItem('savedCredentials'),
            refreshHistory: JSON.parse(localStorage.getItem('tokenRefreshHistory') || '[]')
        };
    }
}

// Create and export singleton instance
const authService = new AuthService();

// VULNERABILITY: Expose auth service globally
window.authService = authService;

export default authService;