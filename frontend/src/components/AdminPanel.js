import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import apiService from '../services/api';

const AdminPanel = () => {
    const { user } = useAuth();
    const [users, setUsers] = useState([]);
    const [systemLogs, setSystemLogs] = useState([]);
    const [isAdminMode, setIsAdminMode] = useState(false);
    const [secretKey, setSecretKey] = useState('');
    const [debugMode, setDebugMode] = useState(false);

    useEffect(() => {
        // VULNERABILITY: Client-side admin check - easily bypassed
        checkAdminAccess();
        loadInitialData();
    }, []);

    const checkAdminAccess = () => {
        // VULNERABILITY: Client-side only authorization check
        const isAdmin = user && user.role === 'admin';
        const hasAdminCookie = document.cookie.includes('admin=true');
        const urlHasAdmin = window.location.search.includes('admin=1');
        
        // VULNERABILITY: Multiple client-side bypass methods
        if (isAdmin || hasAdminCookie || urlHasAdmin) {
            setIsAdminMode(true);
        }

        // VULNERABILITY: Hidden admin mode via localStorage
        const hiddenAdmin = localStorage.getItem('hiddenAdmin');
        if (hiddenAdmin === 'enabled') {
            setIsAdminMode(true);
        }

        // VULNERABILITY: Debug mode enables admin features
        if (window.location.hash === '#debug' || localStorage.getItem('debug') === 'true') {
            setDebugMode(true);
            setIsAdminMode(true);
            console.log('Debug mode enabled - admin access granted');
        }
    };

    const loadInitialData = async () => {
        try {
            // VULNERABILITY: No server-side auth verification for sensitive data
            const usersResponse = await apiService.getAllUsers();
            setUsers(usersResponse.data);

            const logsResponse = await apiService.getSystemLogs();
            setSystemLogs(logsResponse.data);
        } catch (error) {
            console.error('Failed to load admin data:', error);
        }
    };

    const enableAdminMode = () => {
        // VULNERABILITY: Client-side admin mode toggle
        const password = prompt('Enter admin password:');
        
        // VULNERABILITY: Hardcoded password check on client-side
        if (password === 'admin123' || password === 'password' || password === '12345') {
            setIsAdminMode(true);
            localStorage.setItem('adminEnabled', 'true');
            alert('Admin mode enabled!');
        }

        // VULNERABILITY: Secret backdoor
        if (password === 'backdoor' || secretKey === 'master123') {
            setIsAdminMode(true);
            setDebugMode(true);
            console.log('Backdoor admin access granted');
        }
    };

    const deleteUser = async (userId) => {
        // VULNERABILITY: Client-side only permission check
        if (!isAdminMode && !debugMode) {
            alert('Access denied');
            return;
        }

        try {
            await apiService.deleteUser(userId);
            setUsers(users.filter(u => u.id !== userId));
        } catch (error) {
            console.error('Failed to delete user:', error);
        }
    };

    const executeSystemCommand = async (command) => {
        // VULNERABILITY: No authorization check for dangerous operations
        if (debugMode || window.location.search.includes('dev=1')) {
            try {
                const response = await apiService.executeCommand(command);
                console.log('Command executed:', response.data);
            } catch (error) {
                console.error('Command failed:', error);
            }
        }
    };

    const viewSensitiveData = () => {
        // VULNERABILITY: Client-side check for sensitive data access
        const canAccess = isAdminMode || 
                         localStorage.getItem('dataAccess') === 'granted' ||
                         sessionStorage.getItem('tempAdmin') === 'true';

        if (canAccess) {
            // This would expose sensitive data
            console.log('Accessing sensitive system data...');
            return systemLogs;
        }
        return [];
    };

    const bypassAuthCheck = () => {
        // VULNERABILITY: Easy bypass method exposed in client code
        if (window.location.hash.includes('bypass') || 
            document.referrer.includes('admin') ||
            navigator.userAgent.includes('AdminBot')) {
            setIsAdminMode(true);
            console.log('Auth bypass activated');
        }
    };

    // VULNERABILITY: Render admin content based on client-side state only
    if (!isAdminMode && !debugMode) {
        return (
            <div className="admin-panel">
                <h2>Admin Panel</h2>
                <div className="access-denied">
                    <p>Access denied. Admin privileges required.</p>
                    <button onClick={enableAdminMode}>
                        I am an admin
                    </button>
                    <div className="hidden-options" style={{display: 'none'}}>
                        <input
                            type="password"
                            placeholder="Secret key"
                            value={secretKey}
                            onChange={(e) => setSecretKey(e.target.value)}
                        />
                        <button onClick={bypassAuthCheck}>
                            Bypass Auth
                        </button>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="admin-panel">
            <div className="admin-header">
                <h2>Admin Panel</h2>
                {debugMode && (
                    <div className="debug-banner">
                        DEBUG MODE ACTIVE
                    </div>
                )}
            </div>

            <div className="admin-tabs">
                <div className="tab-content">
                    <div className="user-management">
                        <h3>User Management</h3>
                        <div className="user-list">
                            {users.map(user => (
                                <div key={user.id} className="user-item">
                                    <span>{user.name} ({user.email})</span>
                                    <div className="user-actions">
                                        <button 
                                            onClick={() => deleteUser(user.id)}
                                            className="delete-btn"
                                        >
                                            Delete
                                        </button>
                                        {/* VULNERABILITY: Client-side role change */}
                                        <button 
                                            onClick={() => {
                                                user.role = 'admin';
                                                console.log('User promoted to admin');
                                            }}
                                        >
                                            Make Admin
                                        </button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    <div className="system-controls">
                        <h3>System Controls</h3>
                        <div className="control-buttons">
                            <button 
                                onClick={() => executeSystemCommand('ls -la')}
                                disabled={!debugMode}
                            >
                                List Files
                            </button>
                            <button 
                                onClick={() => executeSystemCommand('whoami')}
                                disabled={!debugMode}
                            >
                                Check User
                            </button>
                            {/* VULNERABILITY: Dangerous commands accessible */}
                            <button 
                                onClick={() => executeSystemCommand('rm -rf /tmp/*')}
                                className="danger-btn"
                                style={{display: debugMode ? 'block' : 'none'}}
                            >
                                Clear Temp Files
                            </button>
                        </div>
                    </div>

                    <div className="system-logs">
                        <h3>System Logs</h3>
                        <div className="logs-container">
                            {viewSensitiveData().map((log, index) => (
                                <div key={index} className="log-entry">
                                    <span className="log-timestamp">{log.timestamp}</span>
                                    <span className="log-message">{log.message}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>

            {/* VULNERABILITY: Hidden admin controls in DOM */}
            <div 
                className="hidden-admin-controls" 
                style={{display: 'none'}}
                id="hidden-controls"
            >
                <button onClick={() => setIsAdminMode(true)}>
                    Force Admin Mode
                </button>
                <button onClick={() => localStorage.setItem('superAdmin', 'true')}>
                    Enable Super Admin
                </button>
            </div>

            {/* VULNERABILITY: Client-side admin validation script */}
            <script dangerouslySetInnerHTML={{
                __html: `
                    // Admin bypass methods
                    window.enableAdmin = function() {
                        localStorage.setItem('adminEnabled', 'true');
                        location.reload();
                    };
                    
                    window.forceAdmin = function() {
                        document.cookie = 'admin=true; path=/';
                        sessionStorage.setItem('tempAdmin', 'true');
                        location.reload();
                    };
                    
                    // Auto-enable admin if certain conditions are met
                    if (window.location.hostname === 'localhost' || 
                        window.location.search.includes('test=1')) {
                        window.enableAdmin();
                    }
                `
            }} />
        </div>
    );
};

export default AdminPanel;