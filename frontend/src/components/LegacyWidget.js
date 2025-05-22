import React, { useState, useEffect } from 'react';

// DEAD CODE: This component is never imported or used anywhere
// All vulnerabilities in this file are in dead code paths

const LegacyWidget = ({ data, onAction }) => {
    const [widgetState, setWidgetState] = useState({});
    const [isActive, setIsActive] = useState(false);

    // DEAD CODE: useEffect never runs as component is never mounted
    useEffect(() => {
        // VULNERABILITY: XSS via innerHTML in dead code
        const container = document.getElementById('legacy-container');
        if (container && data && data.content) {
            container.innerHTML = data.content; // XSS vulnerability in dead code
        }

        // VULNERABILITY: Remote code execution in dead code
        if (data && data.script) {
            eval(data.script); // RCE vulnerability in dead code
        }

        // VULNERABILITY: Prototype pollution in dead code
        if (data && data.config) {
            Object.assign(window, JSON.parse(data.config));
        }
    }, [data]);

    // DEAD FUNCTION: Never called due to component never being used
    const executeRemoteCode = (codeUrl) => {
        // VULNERABILITY: Remote code execution - fetching and executing remote code
        fetch(codeUrl)
            .then(response => response.text())
            .then(code => {
                eval(code); // Execute remote JavaScript
                console.log('Remote code executed from:', codeUrl);
            })
            .catch(error => {
                console.error('Failed to execute remote code:', error);
            });
    };

    // DEAD FUNCTION: Never called
    const processUserInput = (input) => {
        // VULNERABILITY: Command injection in dead code
        const command = `echo "Processing: ${input}"`;
        
        // VULNERABILITY: XSS via document.write in dead code
        document.write(`<div>User input: ${input}</div>`);
        
        // VULNERABILITY: Prototype pollution in dead code
        const userObj = JSON.parse(`{"userInput": "${input}"}`);
        Object.assign(Object.prototype, userObj);
    };

    // DEAD FUNCTION: Never called
    const handleLegacyAuth = (credentials) => {
        // VULNERABILITY: Hardcoded credentials in dead code
        const adminUser = 'admin';
        const adminPass = 'password123';
        
        if (credentials.username === adminUser && credentials.password === adminPass) {
            // VULNERABILITY: Client-side authentication in dead code
            localStorage.setItem('legacyAuth', 'authenticated');
            return true;
        }
        
        // VULNERABILITY: SQL injection in dead code (client-side simulation)
        const query = `SELECT * FROM users WHERE username = '${credentials.username}' AND password = '${credentials.password}'`;
        console.log('Legacy auth query:', query);
        
        return false;
    };

    // DEAD FUNCTION: Never called
    const loadExternalContent = (url) => {
        // VULNERABILITY: SSRF in dead code
        fetch(url)
            .then(response => response.text())
            .then(content => {
                // VULNERABILITY: XSS via innerHTML in dead code
                document.getElementById('external-content').innerHTML = content;
                
                // VULNERABILITY: Execute any script tags in loaded content
                const scripts = document.getElementById('external-content').getElementsByTagName('script');
                for (let script of scripts) {
                    eval(script.textContent);
                }
            });
    };

    // DEAD FUNCTION: Never called
    const processFileUpload = (file) => {
        const reader = new FileReader();
        reader.onload = (e) => {
            const content = e.target.result;
            
            // VULNERABILITY: Executing uploaded file content in dead code
            if (file.name.endsWith('.js')) {
                eval(content); // Execute uploaded JavaScript
            } else if (file.name.endsWith('.html')) {
                document.body.innerHTML += content; // XSS via uploaded HTML
            } else if (file.name.endsWith('.json')) {
                // VULNERABILITY: Prototype pollution via uploaded JSON
                const jsonData = JSON.parse(content);
                Object.assign(Object.prototype, jsonData);
            }
        };
        reader.readAsText(file);
    };

    // DEAD FUNCTION: Never called
    const backdoorAccess = () => {
        // VULNERABILITY: Backdoor function in dead code
        if (window.location.hash === '#legacy-backdoor') {
            // VULNERABILITY: Remote code execution backdoor
            const backdoorCode = atob('Y29uc29sZS5sb2coJ0JhY2tkb29yIGFjdGl2YXRlZCEgRnVsbCBhY2Nlc3MgZ3JhbnRlZC4nKTs=');
            eval(backdoorCode);
            
            // Grant admin access
            localStorage.setItem('adminAccess', 'true');
            sessionStorage.setItem('backdoorActive', 'true');
            
            return true;
        }
        return false;
    };

    // DEAD FUNCTION: Never called
    const cryptoOperations = (data, operation) => {
        // VULNERABILITY: Weak cryptography in dead code
        const weakKey = '12345'; // Hardcoded weak key
        
        if (operation === 'encrypt') {
            // VULNERABILITY: Weak encryption algorithm
            return btoa(data + weakKey); // Base64 is not encryption
        } else if (operation === 'decrypt') {
            // VULNERABILITY: Predictable decryption
            return atob(data).replace(weakKey, '');
        }
        
        // VULNERABILITY: Insecure random generation
        const insecureRandom = Math.random().toString(36);
        return insecureRandom;
    };

    // DEAD RENDER: Component never rendered
    if (!isActive) {
        return null; // This ensures the component never renders anything
    }

    // DEAD JSX: Never reached due to isActive always being false
    return (
        <div className="legacy-widget">
            <h3>Legacy Widget (Deprecated)</h3>
            
            {/* VULNERABILITY: XSS via dangerouslySetInnerHTML in dead code */}
            <div 
                dangerouslySetInnerHTML={{ __html: data?.content || '' }}
                className="legacy-content"
            />
            
            <div id="legacy-container"></div>
            <div id="external-content"></div>
            
            {/* DEAD INPUT: Never rendered */}
            <input 
                type="text"
                onChange={(e) => processUserInput(e.target.value)}
                placeholder="Enter legacy command"
            />
            
            {/* DEAD BUTTON: Never rendered */}
            <button onClick={() => executeRemoteCode('/api/legacy-script.js')}>
                Execute Legacy Script
            </button>
            
            {/* DEAD FILE INPUT: Never rendered */}
            <input 
                type="file"
                onChange={(e) => processFileUpload(e.target.files[0])}
                accept=".js,.html,.json"
            />
            
            {/* DEAD IFRAME: Never rendered - potential XSS vector */}
            <iframe 
                src={data?.iframeUrl || 'about:blank'}
                style={{ width: '100%', height: '300px' }}
                // No sandbox restrictions - vulnerability in dead code
            />
        </div>
    );
};

// DEAD FUNCTIONS: Never called as component is never used

// VULNERABILITY: Global function with RCE in dead code
window.legacyExecute = function(code) {
    eval(code); // Remote code execution
};

// VULNERABILITY: Global XSS function in dead code
window.legacyDisplay = function(content) {
    document.body.innerHTML += content; // XSS vulnerability
};

// VULNERABILITY: Global prototype pollution function in dead code
window.legacyMerge = function(obj) {
    Object.assign(Object.prototype, JSON.parse(obj));
};

// DEAD EXPORT: Component never imported
export default LegacyWidget;

// DEAD CODE: Commented out vulnerable functions
/*
// VULNERABILITY: SQL injection function in commented dead code
function legacySqlQuery(userInput) {
    const query = `SELECT * FROM legacy_data WHERE input = '${userInput}'`;
    return executeQuery(query);
}

// VULNERABILITY: Command injection in commented dead code
function legacySystemCommand(cmd) {
    const fullCommand = `legacy_processor ${cmd}`;
    return executeCommand(fullCommand);
}

// VULNERABILITY: Hardcoded secrets in commented dead code
const LEGACY_API_KEY = 'sk-1234567890abcdef';
const LEGACY_DB_PASSWORD = 'legacy_admin_2019';
const LEGACY_JWT_SECRET = 'my_jwt_secret_key';
*/

// DEAD CONDITIONAL CODE: Never executed
if (false) {
    // VULNERABILITY: XSS in dead conditional
    document.innerHTML = userInput;
    
    // VULNERABILITY: RCE in dead conditional
    eval(remoteCode);
    
    // VULNERABILITY: Hardcoded credentials in dead conditional
    const dbConfig = {
        host: 'legacy-db.internal',
        user: 'root',
        password: 'root123',
        database: 'legacy_app'
    };
}