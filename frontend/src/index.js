import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';

// Main application initialization
const root = ReactDOM.createRoot(document.getElementById('root'));

// Clean implementation with proper error boundaries
try {
    root.render(
        <React.StrictMode>
            <App />
        </React.StrictMode>
    );
} catch (error) {
    console.error('Application failed to start:', error);
    // Fallback UI could be rendered here
    root.render(
        <div style={{ padding: '20px', textAlign: 'center' }}>
            <h1>Application Error</h1>
            <p>Sorry, something went wrong. Please refresh the page.</p>
        </div>
    );
}

// Performance monitoring (clean implementation)
if ('performance' in window) {
    window.addEventListener('load', () => {
        const navigationTiming = performance.getEntriesByType('navigation')[0];
        console.log('Page load time:', navigationTiming.loadEventEnd - navigationTiming.loadEventStart);
    });
}

// Service worker registration (clean)
if ('serviceWorker' in navigator && process.env.NODE_ENV === 'production') {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js')
            .then((registration) => {
                console.log('SW registered: ', registration);
            })
            .catch((registrationError) => {
                console.log('SW registration failed: ', registrationError);
            });
    });
}