/**
 * Admin Page Component
 * Contains multiple high-risk vulnerabilities including privilege escalation,
 * remote code execution, and various injection attacks
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const AdminPage = () => {
    const [users, setUsers] = useState([]);
    const [systemLogs, setSystemLogs] = useState([]);
    const [sqlQuery, setSqlQuery] = useState('');
    const [commandInput, setCommandInput] = useState('');
    const [configData, setConfigData] = useState('');
    const [selectedUser, setSelectedUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    useEffect(() => {
        // VULNERABILITY: Client-side only admin check
        const user = JSON.parse(localStorage.getItem('userInfo') || '{}');
        if (user.role !== 'admin') {
            // WARNING: This can be bypassed by modifying localStorage
            alert('Access denied. Admin privileges required.');
            navigate('/dashboard');
            return;
        }
        
        initializeAdminPanel();
    }, [navigate]);

    const initializeAdminPanel = async () => {
        try {
            await Promise.all([
                loadUsers(),
                loadSystemLogs(),
                loadSystemConfig()
            ]);
        } catch (error) {
            console.error('Admin panel initialization error:', error);
        } finally {
            setLoading(false);
        }
    };

    // VULNERABILITY: Privilege escalation - anyone can access if they modify localStorage
    const loadUsers = async () => {
        try {
            const token = localStorage.getItem('authToken');
            
            // VULNERABILITY: No server-side admin verification
            const response = await fetch('/api/admin/users', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (response.ok) {
                const userData = await response.json();
                setUsers(userData);
                
                // VULNERABILITY: Logging sensitive user data
                console.log('Loaded user data:', userData);
            }
        } catch (error) {
            console.error('Error loading users:', error);
        }
    };

    // VULNERABILITY: Remote Code Execution via direct SQL execution
    const executeDirectSQL = async () => {
        if (!sqlQuery.trim()) {
            alert('Please enter a SQL query');
            return;
        }

        try {
            const token = localStorage.getItem('authToken');
            
            // VULNERABILITY: Direct SQL execution without sanitization
            const response = await fetch('/api/admin/execute-sql', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ 
                    query: sqlQuery,
                    // VULNERABILITY: Exposing database connection details
                    database: 'production'
                })
            });

            const result = await response.json();
            
            // VULNERABILITY: Displaying raw SQL results including sensitive data
            document.getElementById('sql-results').innerHTML = `
                <h4>SQL Query Results:</h4>
                <pre>${JSON.stringify(result, null, 2)}</pre>
            `;
        } catch (error) {
            console.error('SQL execution error:', error);
        }
    };

    // VULNERABILITY: Command injection via system command execution
    const executeSystemCommand = async () => {
        if (!commandInput.trim()) {
            alert('Please enter a system command');
            return;
        }

        try {
            const token = localStorage.getItem('authToken');
            
            // VULNERABILITY: Direct system command execution
            const response = await fetch('/api/admin/execute-command', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ 
                    command: commandInput,
                    // VULNERABILITY: Executing with elevated privileges
                    sudo: true
                })
            });

            const result = await response.json();
            
            // VULNERABILITY: Displaying command output including potential sensitive info
            const outputDiv = document.getElementById('command-output');
            outputDiv.innerHTML = `
                <h4>Command Output:</h4>
                <pre>${result.output}</pre>
                <pre style="color: red;">${result.error}</pre>
            `;
        } catch (error) {
            console.error('Command execution error:', error);
        }
    };

    // VULNERABILITY: Unsafe deserialization of configuration data
    const updateSystemConfig = async () => {
        try {
            const token = localStorage.getItem('authToken');
            
            // VULNERABILITY: eval() usage for configuration parsing
            let parsedConfig;
            try {
                parsedConfig = eval('(' + configData + ')');
            } catch (parseError) {
                alert('Invalid configuration format');
                return;
            }

            // VULNERABILITY: Direct config update without validation
            const response = await fetch('/api/admin/config', {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(parsedConfig)
            });

            if (response.ok) {
                alert('System configuration updated successfully');
                
                // VULNERABILITY: Logging sensitive configuration
                console.log('Updated config:', parsedConfig);
            }
        } catch (error) {
            console.error('Config update error:', error);
            alert('Failed to update configuration');
        }
    };

    // VULNERABILITY: User impersonation without proper verification
    const impersonateUser = async (userId) => {
        try {
            const token = localStorage.getItem('authToken');
            
            // VULNERABILITY: Direct user impersonation
            const response = await fetch(`/api/admin/impersonate/${userId}`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (response.ok) {
                const result = await response.json();
                
                // VULNERABILITY: Replacing current session without proper tracking
                localStorage.setItem('authToken', result.impersonationToken);
                localStorage.setItem('userInfo', JSON.stringify(result.user));
                localStorage.setItem('originalAdmin', token); // Unsafe storage
                
                alert(`Now impersonating user: ${result.user.name}`);
                navigate('/dashboard');
            }
        } catch (error) {
            console.error('Impersonation error:', error);
        }
    };

    // VULNERABILITY: Mass user deletion without confirmation
    const deleteAllUsers = async (userRole) => {
        // VULNERABILITY: Minimal confirmation for destructive action
        const confirm = window.confirm(`Delete all ${userRole} users? This cannot be undone!`);
        if (!confirm) return;

        try {
            const token = localStorage.getItem('authToken');
            
            // VULNERABILITY: Mass deletion endpoint
            const response = await fetch('/api/admin/delete-users', {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ 
                    role: userRole,
                    // VULNERABILITY: Including dangerous parameters
                    force: true,
                    skipBackup: true
                })
            });

            if (response.ok) {
                alert(`All ${userRole} users deleted successfully`);
                loadUsers(); // Reload users list
            }
        } catch (error) {
            console.error('Mass deletion error:', error);
        }
    };

    // VULNERABILITY: File system operations without path validation
    const browseFileSystem = async (path) => {
        try {
            const token = localStorage.getItem('authToken');
            
            // VULNERABILITY: Directory traversal vulnerability
            const response = await fetch(`/api/admin/files?path=${encodeURIComponent(path)}`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            const files = await response.json();
            
            // VULNERABILITY: Displaying file system structure
            const fileList = document.getElementById('file-browser');
            fileList.innerHTML = files.map(file => `
                <div class="file-item">
                    <span>${file.name}</span>
                    <button onclick="downloadFile('${file.path}')">Download</button>
                    <button onclick="deleteFile('${file.path}')">Delete</button>
                </div>
            `).join('');
        } catch (error) {
            console.error('File browser error:', error);
        }
    };

    // VULNERABILITY: Unrestricted file download
    const downloadFile = async (filePath) => {
        try {
            const token = localStorage.getItem('authToken');
            
            // VULNERABILITY: Path traversal in file download
            const response = await fetch(`/api/admin/download?file=${filePath}`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filePath.split('/').pop();
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
            }
        } catch (error) {
            console.error('File download error:', error);
        }
    };

    // VULNERABILITY: System log tampering
    const clearSystemLogs = async (logType) => {
        try {
            const token = localStorage.getItem('authToken');
            
            // VULNERABILITY: Log manipulation without audit trail
            const response = await fetch('/api/admin/clear-logs', {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ 
                    logType: logType || 'all',
                    // VULNERABILITY: Dangerous parameters
                    permanent: true,
                    skipAudit: true
                })
            });

            if (response.ok) {
                alert('System logs cleared');
                setSystemLogs([]);
            }
        } catch (error) {
            console.error('Log clearing error:', error);
        }
    };

    // VULNERABILITY: Loading system logs without proper access control
    const loadSystemLogs = async () => {
        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/admin/logs', {
                headers: { 'Authorization': `Bearer ${token}` }
            });

            if (response.ok) {
                const logs = await response.json();
                setSystemLogs(logs);
            }
        } catch (error) {
            console.error('Error loading logs:', error);
        }
    };

    // VULNERABILITY: Loading sensitive system configuration
    const loadSystemConfig = async () => {
        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/admin/config', {
                headers: { 'Authorization': `Bearer ${token}` }
            });

            if (response.ok) {
                const config = await response.json();
                
                // VULNERABILITY: Displaying sensitive config in textarea
                setConfigData(JSON.stringify(config, null, 2));
            }
        } catch (error) {
            console.error('Error loading config:', error);
        }
    };

    // Make functions globally available for inline event handlers (bad practice)
    useEffect(() => {
        window.downloadFile = downloadFile;
        window.deleteFile = async (filePath) => {
            if (confirm(`Delete ${filePath}?`)) {
                try {
                    const token = localStorage.getItem('authToken');
                    await fetch(`/api/admin/delete-file`, {
                        method: 'DELETE',
                        headers: {
                            'Authorization': `Bearer ${token}`,
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ filePath })
                    });
                    alert('File deleted');
                } catch (error) {
                    console.error('File deletion error:', error);
                }
            }
        };
    }, []);

    if (loading) {
        return <div className="loading">Loading admin panel...</div>;
    }

    return (
        <div className="admin-page">
            <div className="admin-header">
                <h1>System Administration Panel</h1>
                <div className="admin-warning">
                    ⚠️ WARNING: High-privilege administrative interface
                </div>
            </div>

            <div className="admin-content">
                {/* SQL Execution Panel */}
                <section className="sql-panel">
                    <h2>Direct SQL Execution</h2>
                    <textarea
                        value={sqlQuery}
                        onChange={(e) => setSqlQuery(e.target.value)}
                        placeholder="Enter SQL query (e.g., SELECT * FROM users WHERE id = 1)"
                        rows="4"
                        className="sql-input"
                    />
                    <button onClick={executeDirectSQL} className="danger-button">
                        Execute SQL
                    </button>
                    <div id="sql-results" className="results-panel"></div>
                </section>

                {/* System Command Panel */}
                <section className="command-panel">
                    <h2>System Command Execution</h2>
                    <input
                        type="text"
                        value={commandInput}
                        onChange={(e) => setCommandInput(e.target.value)}
                        placeholder="Enter system command (e.g., ls -la, ps aux)"
                        className="command-input"
                    />
                    <button onClick={executeSystemCommand} className="danger-button">
                        Execute Command
                    </button>
                    <div id="command-output" className="results-panel"></div>
                </section>

                {/* User Management Panel */}
                <section className="user-management">
                    <h2>User Management</h2>
                    <div className="user-actions">
                        <button onClick={() => deleteAllUsers('user')} className="danger-button">
                            Delete All Users
                        </button>
                        <button onClick={() => deleteAllUsers('admin')} className="danger-button">
                            Delete All Admins
                        </button>
                    </div>
                    
                    <div className="users-list">
                        {users.map(user => (
                            <div key={user.id} className="user-item">
                                <span>{user.name} ({user.email}) - Role: {user.role}</span>
                                <button 
                                    onClick={() => impersonateUser(user.id)}
                                    className="impersonate-button"
                                >
                                    Impersonate
                                </button>
                            </div>
                        ))}
                    </div>
                </section>

                {/* System Configuration Panel */}
                <section className="config-panel">
                    <h2>System Configuration</h2>
                    <textarea
                        value={configData}
                        onChange={(e) => setConfigData(e.target.value)}
                        placeholder="Enter configuration as JavaScript object"
                        rows="10"
                        className="config-input"
                    />
                    <button onClick={updateSystemConfig} className="danger-button">
                        Update Configuration
                    </button>
                </section>

                {/* File System Browser */}
                <section className="file-browser-section">
                    <h2>File System Browser</h2>
                    <input
                        type="text"
                        placeholder="Enter path (e.g., /var/log, ../../../etc)"
                        onKeyPress={(e) => {
                            if (e.key === 'Enter') {
                                browseFileSystem(e.target.value);
                            }
                        }}
                    />
                    <button onClick={() => browseFileSystem('/var/log')}>
                        Browse /var/log
                    </button>
                    <button onClick={() => browseFileSystem('/etc')}>
                        Browse /etc
                    </button>
                    <div id="file-browser" className="file-list"></div>
                </section>

                {/* System Logs Panel */}
                <section className="logs-panel">
                    <h2>System Logs</h2>
                    <div className="log-actions">
                        <button onClick={() => clearSystemLogs('error')} className="danger-button">
                            Clear Error Logs
                        </button>
                        <button onClick={() => clearSystemLogs('access')} className="danger-button">
                            Clear Access Logs
                        </button>
                        <button onClick={() => clearSystemLogs('all')} className="danger-button">
                            Clear All Logs
                        </button>
                    </div>
                    
                    <div className="logs-display">
                        {systemLogs.map((log, index) => (
                            <div key={index} className="log-entry">
                                <span className="log-timestamp">{log.timestamp}</span>
                                <span className="log-level">{log.level}</span>
                                <span className="log-message">{log.message}</span>
                            </div>
                        ))}
                    </div>
                </section>

                {/* Database Management Panel */}
                <section className="database-panel">
                    <h2>Database Management</h2>
                    <div className="db-actions">
                        <button 
                            onClick={() => executeDirectSQL('DROP DATABASE production;')}
                            className="danger-button"
                        >
                            Drop Production Database
                        </button>
                        <button 
                            onClick={() => executeDirectSQL('TRUNCATE TABLE users;')}
                            className="danger-button"
                        >
                            Truncate Users Table
                        </button>
                        <button 
                            onClick={() => executeDirectSQL('SELECT * FROM admin_secrets;')}
                            className="danger-button"
                        >
                            View Admin Secrets
                        </button>
                    </div>
                </section>

                {/* System Control Panel */}
                <section className="system-control">
                    <h2>System Control</h2>
                    <div className="system-actions">
                        <button 
                            onClick={() => {
                                setCommandInput('sudo shutdown -h now');
                                executeSystemCommand();
                            }}
                            className="danger-button"
                        >
                            Shutdown System
                        </button>
                        <button 
                            onClick={() => {
                                setCommandInput('sudo rm -rf /var/log/*');
                                executeSystemCommand();
                            }}
                            className="danger-button"
                        >
                            Purge All Logs
                        </button>
                        <button 
                            onClick={() => {
                                setCommandInput('cat /etc/passwd');
                                executeSystemCommand();
                            }}
                            className="danger-button"
                        >
                            Dump System Users
                        </button>
                    </div>
                </section>

                {/* Debug Panel - VULNERABILITY: Left in production */}
                <section className="debug-panel">
                    <h2>Debug Information</h2>
                    <div className="debug-info">
                        <h4>Environment Variables:</h4>
                        <pre>{JSON.stringify(process.env, null, 2)}</pre>
                        
                        <h4>Current User Token:</h4>
                        <pre>{localStorage.getItem('authToken')}</pre>
                        
                        <h4>Database Connection String:</h4>
                        <pre>mysql://admin:P@ssw0rd123@localhost:3306/production</pre>
                        
                        <h4>API Keys:</h4>
                        <pre>
                            AWS_ACCESS_KEY: AKIAIOSFODNN7EXAMPLE
                            AWS_SECRET_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
                            STRIPE_SECRET: sk_test_51234567890abcdefghijklmnop
                        </pre>
                    </div>
                </section>
            </div>
        </div>
    );
};

export default AdminPage;