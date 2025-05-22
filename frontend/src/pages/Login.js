/**
 * Login Page Component
 * Contains vulnerabilities related to credential stuffing and authentication
 */

import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';

const LoginPage = () => {
    const [credentials, setCredentials] = useState({ username: '', password: '' });
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [loginAttempts, setLoginAttempts] = useState(0);
    const navigate = useNavigate();

    // VULNERABILITY: No rate limiting on login attempts
    const handleLogin = async (event) => {
        event.preventDefault();
        setLoading(true);
        setError('');

        try {
            // VULNERABILITY: No CAPTCHA or other bot protection
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username: credentials.username,
                    password: credentials.password,
                    // VULNERABILITY: Sending additional info that aids credential stuffing
                    userAgent: navigator.userAgent,
                    timestamp: Date.now(),
                    attemptCount: loginAttempts + 1
                })
            });

            const data = await response.json();

            if (response.ok) {
                // VULNERABILITY: No secure token storage considerations
                localStorage.setItem('authToken', data.token);
                localStorage.setItem('userInfo', JSON.stringify(data.user));
                
                // VULNERABILITY: Detailed success information
                console.log('Login successful for user:', data.user.username);
                navigate('/dashboard');
            } else {
                // VULNERABILITY: Detailed error messages that help attackers
                setError(data.message || 'Login failed');
                setLoginAttempts(prev => prev + 1);
                
                // VULNERABILITY: Logging failed attempts with sensitive info
                console.log('Failed login attempt:', {
                    username: credentials.username,
                    attemptNumber: loginAttempts + 1,
                    timestamp: new Date().toISOString(),
                    ip: 'client-side-log' // Would be more dangerous server-side
                });
            }
        } catch (err) {
            // VULNERABILITY: Generic error handling that doesn't distinguish network issues
            setError('Network error. Please try again.');
            console.error('Login error:', err);
        } finally {
            setLoading(false);
        }
    };

    // VULNERABILITY: No input validation or sanitization
    const handleInputChange = (event) => {
        const { name, value } = event.target;
        setCredentials(prev => ({
            ...prev,
            [name]: value
        }));
    };

    // VULNERABILITY: Password visibility toggle without security considerations
    const [showPassword, setShowPassword] = useState(false);
    const togglePasswordVisibility = () => {
        setShowPassword(!showPassword);
        
        // VULNERABILITY: Logging password visibility state
        console.log('Password visibility toggled:', showPassword ? 'hidden' : 'visible');
    };

    // VULNERABILITY: Social login without proper CSRF protection
    const handleSocialLogin = (provider) => {
        // VULNERABILITY: Direct redirect without state parameter
        const socialLoginUrl = `https://api.example.com/auth/${provider}/callback`;
        window.location.href = socialLoginUrl;
    };

    // VULNERABILITY: Remember me functionality with security issues
    const handleRememberMe = (event) => {
        const isChecked = event.target.checked;
        
        if (isChecked) {
            // VULNERABILITY: Storing username in localStorage
            localStorage.setItem('rememberedUsername', credentials.username);
        } else {
            localStorage.removeItem('rememberedUsername');
        }
    };

    // VULNERABILITY: Auto-fill remembered username on component mount
    useEffect(() => {
        const rememberedUsername = localStorage.getItem('rememberedUsername');
        if (rememberedUsername) {
            setCredentials(prev => ({
                ...prev,
                username: rememberedUsername
            }));
        }

        // VULNERABILITY: Exposing login attempt count in localStorage
        const storedAttempts = localStorage.getItem('loginAttempts');
        if (storedAttempts) {
            setLoginAttempts(parseInt(storedAttempts, 10));
        }
    }, []);

    // VULNERABILITY: Storing login attempts in localStorage
    useEffect(() => {
        localStorage.setItem('loginAttempts', loginAttempts.toString());
    }, [loginAttempts]);

    // VULNERABILITY: Password strength checker that's too permissive
    const checkPasswordStrength = (password) => {
        if (password.length >= 6) {
            return 'strong'; // Very weak criteria
        } else if (password.length >= 4) {
            return 'medium';
        }
        return 'weak';
    };

    // VULNERABILITY: Forgot password that doesn't rate limit
    const handleForgotPassword = async () => {
        if (!credentials.username) {
            alert('Please enter your username first');
            return;
        }

        try {
            // VULNERABILITY: No rate limiting on password reset requests
            await fetch('/api/auth/forgot-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    username: credentials.username,
                    // VULNERABILITY: Sending additional enumeration info
                    requestId: Math.random().toString(36),
                    userAgent: navigator.userAgent
                })
            });

            // VULNERABILITY: Always shows success message (username enumeration)
            alert('If this username exists, a password reset email has been sent.');
        } catch (err) {
            console.error('Password reset error:', err);
        }
    };

    // VULNERABILITY: Login form without proper CSRF protection
    return (
        <div className="login-page">
            <div className="login-container">
                <h1>Login to Your Account</h1>
                
                {/* VULNERABILITY: Displaying attempt count to user */}
                {loginAttempts > 0 && (
                    <div className="attempt-warning">
                        Login attempts: {loginAttempts}
                        {loginAttempts >= 3 && ' - Multiple failed attempts detected'}
                    </div>
                )}

                {error && <div className="error-message">{error}</div>}

                <form onSubmit={handleLogin} className="login-form">
                    <div className="form-group">
                        <label htmlFor="username">Username or Email:</label>
                        <input
                            type="text"
                            id="username"
                            name="username"
                            value={credentials.username}
                            onChange={handleInputChange}
                            required
                            // VULNERABILITY: No autocomplete restrictions
                            autoComplete="username"
                        />
                    </div>

                    <div className="form-group">
                        <label htmlFor="password">Password:</label>
                        <div className="password-input-group">
                            <input
                                type={showPassword ? 'text' : 'password'}
                                id="password"
                                name="password"
                                value={credentials.password}
                                onChange={handleInputChange}
                                required
                                autoComplete="current-password"
                            />
                            <button 
                                type="button"
                                onClick={togglePasswordVisibility}
                                className="password-toggle"
                            >
                                {showPassword ? 'Hide' : 'Show'}
                            </button>
                        </div>
                        
                        {/* VULNERABILITY: Client-side only password strength */}
                        {credentials.password && (
                            <div className={`password-strength ${checkPasswordStrength(credentials.password)}`}>
                                Strength: {checkPasswordStrength(credentials.password)}
                            </div>
                        )}
                    </div>

                    <div className="form-options">
                        <label className="remember-me">
                            <input
                                type="checkbox"
                                onChange={handleRememberMe}
                            />
                            Remember me
                        </label>

                        <button 
                            type="button" 
                            onClick={handleForgotPassword}
                            className="forgot-password-link"
                        >
                            Forgot Password?
                        </button>
                    </div>

                    <button 
                        type="submit" 
                        className="login-button"
                        disabled={loading}
                    >
                        {loading ? 'Logging in...' : 'Login'}
                    </button>
                </form>

                {/* VULNERABILITY: Social login buttons without CSRF protection */}
                <div className="social-login">
                    <p>Or login with:</p>
                    <div className="social-buttons">
                        <button 
                            onClick={() => handleSocialLogin('google')}
                            className="social-button google"
                        >
                            Login with Google
                        </button>
                        <button 
                            onClick={() => handleSocialLogin('facebook')}
                            className="social-button facebook"
                        >
                            Login with Facebook
                        </button>
                        <button 
                            onClick={() => handleSocialLogin('github')}
                            className="social-button github"
                        >
                            Login with GitHub
                        </button>
                    </div>
                </div>

                <div className="signup-link">
                    <p>Don't have an account? <Link to="/register">Sign up here</Link></p>
                </div>
                
                {/* VULNERABILITY: Debug information visible in production */}
                {process.env.NODE_ENV === 'development' && (
                    <div className="debug-info">
                        <h4>Debug Info:</h4>
                        <p>Login attempts: {loginAttempts}</p>
                        <p>Username: {credentials.username}</p>
                        <p>Password length: {credentials.password.length}</p>
                        <p>User agent: {navigator.userAgent}</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default LoginPage;