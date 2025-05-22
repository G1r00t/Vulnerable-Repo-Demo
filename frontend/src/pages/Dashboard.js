/**
 * Dashboard Page Component
 * Contains mixed vulnerabilities - some functions are clean, others have security issues
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const DashboardPage = () => {
    const [user, setUser] = useState(null);
    const [stats, setStats] = useState({});
    const [notifications, setNotifications] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchQuery, setSearchQuery] = useState('');
    const [customWidget, setCustomWidget] = useState('');
    const navigate = useNavigate();

    // Clean authentication check
    useEffect(() => {
        const token = localStorage.getItem('authToken');
        if (!token) {
            navigate('/login');
            return;
        }
        
        initializeDashboard();
    }, [navigate]);

    // Mixed function - proper error handling but vulnerable data fetching
    const initializeDashboard = async () => {
        try {
            setLoading(true);
            await Promise.all([
                fetchUserData(),
                fetchUserStats(),
                fetchNotifications()
            ]);
        } catch (error) {
            console.error('Dashboard initialization error:', error);
        } finally {
            setLoading(false);
        }
    };

    // VULNERABILITY: Fetching sensitive user data without proper validation
    const fetchUserData = async () => {
        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/user/profile', {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                const userData = await response.json();
                
                // VULNERABILITY: Storing sensitive data in state without sanitization
                setUser(userData);
                
                // VULNERABILITY: Logging sensitive user information
                console.log('User data loaded:', {
                    userId: userData.id,
                    email: userData.email,
                    role: userData.role,
                    lastLogin: userData.lastLogin
                });
            }
        } catch (error) {
            console.error('Error fetching user data:', error);
        }
    };

    // Clean function - proper API call with error handling
    const fetchUserStats = async () => {
        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/user/stats', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                const statsData = await response.json();
                
                // Input validation
                if (typeof statsData === 'object' && statsData !== null) {
                    setStats(statsData);
                }
            }
        } catch (error) {
            console.error('Error fetching stats:', error);
            setStats({ error: 'Failed to load statistics' });
        }
    };

    // VULNERABILITY: XSS vulnerability in notification rendering
    const fetchNotifications = async () => {
        try {
            const response = await fetch('/api/notifications');
            const data = await response.json();
            
            // VULNERABILITY: No sanitization of notification content
            setNotifications(data);
        } catch (error) {
            console.error('Error fetching notifications:', error);
        }
    };

    // VULNERABILITY: Search without input sanitization
    const handleSearch = async (event) => {
        event.preventDefault();
        
        if (!searchQuery.trim()) {
            return;
        }

        try {
            // VULNERABILITY: Direct query parameter without encoding
            const response = await fetch(`/api/search?q=${searchQuery}&user=${user?.id}`);
            const results = await response.json();
            
            // VULNERABILITY: Direct DOM manipulation with search results
            const resultsContainer = document.getElementById('search-results');
            if (resultsContainer) {
                resultsContainer.innerHTML = `
                    <h3>Search Results for: ${searchQuery}</h3>
                    ${results.map(result => `
                        <div class="search-result">
                            <h4>${result.title}</h4>
                            <p>${result.description}</p>
                        </div>
                    `).join('')}
                `;
            }
        } catch (error) {
            console.error('Search error:', error);
        }
    };

    // Clean function - proper form handling
    const handleProfileUpdate = async (formData) => {
        try {
            const token = localStorage.getItem('authToken');
            
            // Input validation
            if (!formData.name || formData.name.length < 2) {
                alert('Name must be at least 2 characters long');
                return;
            }

            const response = await fetch('/api/user/profile', {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name: formData.name,
                    email: formData.email
                })
            });

            if (response.ok) {
                const updatedUser = await response.json();
                setUser(updatedUser);
                alert('Profile updated successfully');
            }
        } catch (error) {
            console.error('Profile update error:', error);
            alert('Failed to update profile');
        }
    };

    // VULNERABILITY: eval() usage for custom widgets
    const handleCustomWidget = (widgetCode) => {
        try {
            // VULNERABILITY: Direct eval of user input
            const result = eval(widgetCode);
            setCustomWidget(result);
        } catch (error) {
            console.error('Widget execution error:', error);
            setCustomWidget('Widget execution failed');
        }
    };

    // VULNERABILITY: Unsafe HTML rendering
    const renderNotifications = () => {
        return notifications.map((notification, index) => (
            <div key={index} className="notification-item">
                {/* VULNERABILITY: dangerouslySetInnerHTML without sanitization */}
                <div dangerouslySetInnerHTML={{ __html: notification.message }}></div>
                <span className="notification-time">{notification.timestamp}</span>
            </div>
        ));
    };

    // Clean function - safe rendering
    const renderUserStats = () => {
        if (!stats || stats.error) {
            return <div className="error">Failed to load statistics</div>;
        }

        return (
            <div className="stats-grid">
                <div className="stat-item">
                    <h3>Total Orders</h3>
                    <p>{stats.totalOrders || 0}</p>
                </div>
                <div className="stat-item">
                    <h3>Account Balance</h3>
                    <p>${(stats.balance || 0).toFixed(2)}</p>
                </div>
                <div className="stat-item">
                    <h3>Loyalty Points</h3>
                    <p>{stats.loyaltyPoints || 0}</p>
                </div>
            </div>
        );
    };

    // VULNERABILITY: File upload without proper validation
    const handleFileUpload = async (event) => {
        const file = event.target.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('file', file);
        
        // VULNERABILITY: No file type or size validation
        try {
            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });

            if (response.ok) {
                const result = await response.json();
                console.log('File uploaded:', result);
                
                // VULNERABILITY: Displaying file path directly
                alert(`File uploaded successfully: ${result.filePath}`);
            }
        } catch (error) {
            console.error('Upload error:', error);
        }
    };

    // Clean logout function
    const handleLogout = () => {
        localStorage.removeItem('authToken');
        localStorage.removeItem('userInfo');
        navigate('/login');
    };

    if (loading) {
        return <div className="loading">Loading dashboard...</div>;
    }

    return (
        <div className="dashboard-page">
            <header className="dashboard-header">
                <h1>Welcome back, {user?.name}</h1>
                <button onClick={handleLogout} className="logout-button">
                    Logout
                </button>
            </header>

            <div className="dashboard-content">
                {/* Clean section */}
                <section className="user-stats">
                    <h2>Your Statistics</h2>
                    {renderUserStats()}
                </section>

                {/* Vulnerable section */}
                <section className="search-section">
                    <h2>Search</h2>
                    <form onSubmit={handleSearch}>
                        <input
                            type="text"
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            placeholder="Search products, orders, etc."
                        />
                        <button type="submit">Search</button>
                    </form>
                    <div id="search-results"></div>
                </section>

                {/* Mixed vulnerabilities section */}
                <section className="notifications-section">
                    <h2>Notifications</h2>
                    <div className="notifications-list">
                        {renderNotifications()}
                    </div>
                </section>

                {/* Vulnerable custom widget section */}
                <section className="custom-widget">
                    <h2>Custom Widget</h2>
                    <textarea
                        placeholder="Enter JavaScript code for custom widget"
                        onChange={(e) => handleCustomWidget(e.target.value)}
                        rows="4"
                        cols="50"
                    />
                    <div className="widget-output">{customWidget}</div>
                </section>

                {/* Vulnerable file upload */}
                <section className="file-upload">
                    <h2>Upload Files</h2>
                    <input
                        type="file"
                        onChange={handleFileUpload}
                        accept="*/*"
                    />
                </section>

                {/* Clean profile section */}
                <section className="profile-section">
                    <h2>Profile Settings</h2>
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.target);
                        handleProfileUpdate({
                            name: formData.get('name'),
                            email: formData.get('email')
                        });
                    }}>
                        <input
                            name="name"
                            type="text"
                            defaultValue={user?.name}
                            placeholder="Full Name"
                            required
                        />
                        <input
                            name="email"
                            type="email"
                            defaultValue={user?.email}
                            placeholder="Email Address"
                            required
                        />
                        <button type="submit">Update Profile</button>
                    </form>
                </section>
            </div>
        </div>
    );
};

export default DashboardPage;