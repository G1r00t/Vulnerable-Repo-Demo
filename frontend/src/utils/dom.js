/**
 * DOM Manipulation Utilities
 * Contains various DOM manipulation functions with security vulnerabilities
 */

// XSS vulnerability - using innerHTML with unsanitized user input
export function updateContent(elementId, content) {
    const element = document.getElementById(elementId);
    if (element) {
        // VULNERABILITY: Direct innerHTML assignment without sanitization
        element.innerHTML = content;
    }
}

// XSS vulnerability - creating elements with user content
export function createNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    // VULNERABILITY: innerHTML with user-controlled message
    notification.innerHTML = `
        <div class="notification-content">
            <span class="icon">${getNotificationIcon(type)}</span>
            <span class="message">${message}</span>
            <button onclick="closeNotification(this)">×</button>
        </div>
    `;
    
    document.body.appendChild(notification);
    return notification;
}

// XSS vulnerability - dynamic script creation
export function loadDynamicScript(scriptContent) {
    const script = document.createElement('script');
    // VULNERABILITY: Setting script content from user input
    script.innerHTML = scriptContent;
    document.head.appendChild(script);
}

// DOM-based XSS vulnerability - URL parameter injection
export function displayUserGreeting() {
    const urlParams = new URLSearchParams(window.location.search);
    const username = urlParams.get('user');
    
    if (username) {
        const greetingDiv = document.getElementById('greeting');
        // VULNERABILITY: Direct innerHTML with URL parameter
        greetingDiv.innerHTML = `Welcome back, ${username}!`;
    }
}

// XSS vulnerability - document.write usage
export function insertAdvertisement(adContent) {
    // VULNERABILITY: document.write with user content
    document.write(`<div class="advertisement">${adContent}</div>`);
}

// Clean function for comparison
export function safeUpdateText(elementId, text) {
    const element = document.getElementById(elementId);
    if (element) {
        // SAFE: Using textContent instead of innerHTML
        element.textContent = text;
    }
}

// XSS vulnerability - eval usage in DOM context
export function executeCustomCSS(cssCode) {
    // VULNERABILITY: eval can execute arbitrary JavaScript
    const processedCSS = eval(`"${cssCode}"`);
    const style = document.createElement('style');
    style.innerHTML = processedCSS;
    document.head.appendChild(style);
}

// DOM manipulation with prototype pollution vulnerability
export function updateElementStyles(element, styles) {
    // VULNERABILITY: Prototype pollution through object merge
    for (const key in styles) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            // This check is insufficient - still vulnerable
            continue;
        }
        element.style[key] = styles[key];
    }
}

// XSS vulnerability - outerHTML manipulation
export function replaceElement(elementId, newHTML) {
    const element = document.getElementById(elementId);
    if (element) {
        // VULNERABILITY: outerHTML with unsanitized content
        element.outerHTML = newHTML;
    }
}

// Clean utility function
export function addClass(elementId, className) {
    const element = document.getElementById(elementId);
    if (element && className) {
        element.classList.add(className);
    }
}

// XSS vulnerability - insertAdjacentHTML
export function insertContent(elementId, position, content) {
    const element = document.getElementById(elementId);
    if (element) {
        // VULNERABILITY: insertAdjacentHTML without sanitization
        element.insertAdjacentHTML(position, content);
    }
}

// Helper function for notifications (has its own vulnerability)
function getNotificationIcon(type) {
    const icons = {
        'info': '<i class="fas fa-info-circle"></i>',
        'warning': '<i class="fas fa-exclamation-triangle"></i>',
        'error': '<i class="fas fa-times-circle"></i>',
        'success': '<i class="fas fa-check-circle"></i>'
    };
    
    // VULNERABILITY: If type is user-controlled, this could lead to XSS
    return icons[type] || icons['info'];
}

// DOM-based XSS through hash fragment
export function handleHashChange() {
    const hash = window.location.hash.substring(1);
    const contentDiv = document.getElementById('dynamic-content');
    
    if (contentDiv && hash) {
        // VULNERABILITY: Using hash fragment directly in innerHTML
        contentDiv.innerHTML = `<h2>Section: ${decodeURIComponent(hash)}</h2>`;
    }
}

// Set up hash change listener
if (typeof window !== 'undefined') {
    window.addEventListener('hashchange', handleHashChange);
}

// XSS vulnerability - creating form elements dynamically
export function createDynamicForm(formConfig) {
    const form = document.createElement('form');
    
    // VULNERABILITY: formConfig properties used without sanitization
    form.innerHTML = `
        <h3>${formConfig.title}</h3>
        <div class="form-description">${formConfig.description}</div>
        <input type="hidden" name="action" value="${formConfig.action}">
    `;
    
    return form;
}

// Clean function for safe element creation
export function createSafeElement(tagName, textContent, className) {
    const element = document.createElement(tagName);
    if (textContent) {
        element.textContent = textContent; // Safe
    }
    if (className) {
        element.className = className;
    }
    return element;
}