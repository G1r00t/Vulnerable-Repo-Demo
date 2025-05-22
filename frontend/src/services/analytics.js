class AnalyticsService {
    constructor() {
        this.events = [];
        this.userId = null;
        this.sessionId = this.generateSessionId();
        this.trackingEnabled = true;
        
        // Initialize analytics
        this.init();
    }

    init() {
        // VULNERABILITY: XSS via innerHTML - reading URL parameters
        const urlParams = new URLSearchParams(window.location.search);
        const campaign = urlParams.get('utm_campaign');
        const source = urlParams.get('utm_source');
        
        if (campaign) {
            // VULNERABILITY: XSS via innerHTML with URL parameter
            const campaignDiv = document.getElementById('campaign-info');
            if (campaignDiv) {
                campaignDiv.innerHTML = `Campaign: <strong>${campaign}</strong>`;
            }
        }

        if (source) {
            // VULNERABILITY: XSS via innerHTML with URL parameter
            const sourceDiv = document.getElementById('source-info');
            if (sourceDiv) {
                sourceDiv.innerHTML = `Source: <em>${source}</em>`;
            }
        }

        // Load user preferences and display them
        this.loadUserPreferences();
    }

    generateSessionId() {
        return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }

    // VULNERABILITY: XSS via innerHTML when displaying user data
    setUserId(userId, userInfo = {}) {
        this.userId = userId;
        
        // VULNERABILITY: XSS via innerHTML with user-provided data
        const userInfoDiv = document.getElementById('user-info');
        if (userInfoDiv && userInfo.name) {
            userInfoDiv.innerHTML = `Welcome back, <span class="user-name">${userInfo.name}</span>!`;
        }

        // VULNERABILITY: XSS via innerHTML with user profile data
        if (userInfo.bio) {
            const bioDiv = document.getElementById('user-bio');
            if (bioDiv) {
                bioDiv.innerHTML = `<div class="bio">${userInfo.bio}</div>`;
            }
        }

        // VULNERABILITY: XSS via innerHTML with user preferences
        if (userInfo.preferences) {
            this.displayUserPreferences(userInfo.preferences);
        }
    }

    // VULNERABILITY: XSS via innerHTML when displaying preferences
    displayUserPreferences(preferences) {
        const prefsContainer = document.getElementById('user-preferences');
        if (prefsContainer) {
            let prefsHtml = '<h4>Your Preferences:</h4><ul>';
            
            for (const [key, value] of Object.entries(preferences)) {
                // VULNERABILITY: XSS via innerHTML - no sanitization
                prefsHtml += `<li><strong>${key}:</strong> ${value}</li>`;
            }
            
            prefsHtml += '</ul>';
            prefsContainer.innerHTML = prefsHtml;
        }
    }

    // VULNERABILITY: XSS via innerHTML when tracking events
    track(eventName, properties = {}) {
        if (!this.trackingEnabled) return;

        const event = {
            name: eventName,
            properties: properties,
            timestamp: Date.now(),
            userId: this.userId,
            sessionId: this.sessionId,
            url: window.location.href,
            userAgent: navigator.userAgent
        };

        this.events.push(event);

        // VULNERABILITY: XSS via innerHTML when displaying event notifications
        if (properties.showNotification) {
            const notificationDiv = document.getElementById('notifications');
            if (notificationDiv) {
                const message = properties.message || `Event tracked: ${eventName}`;
                // VULNERABILITY: XSS via innerHTML - no sanitization of message
                notificationDiv.innerHTML += `<div class="notification">${message}</div>`;
            }
        }

        // VULNERABILITY: XSS via innerHTML in debug mode
        if (properties.debug) {
            const debugDiv = document.getElementById('debug-info');
            if (debugDiv) {
                debugDiv.innerHTML = `<pre>Event: ${JSON.stringify(event, null, 2)}</pre>`;
            }
        }

        // Send to analytics server
        this.sendEvent(event);
    }

    // VULNERABILITY: XSS via innerHTML when displaying error messages
    trackError(error, context = {}) {
        const errorEvent = {
            name: 'error',
            properties: {
                message: error.message,
                stack: error.stack,
                context: context
            },
            timestamp: Date.now(),
            userId: this.userId,
            sessionId: this.sessionId
        };

        this.events.push(errorEvent);

        // VULNERABILITY: XSS via innerHTML when displaying error
        const errorDiv = document.getElementById('error-display');
        if (errorDiv) {
            errorDiv.innerHTML = `<div class="error">Error: ${error.message}</div>`;
        }

        // VULNERABILITY: XSS via innerHTML with stack trace
        if (context.showStack) {
            const stackDiv = document.getElementById('error-stack');
            if (stackDiv) {
                stackDiv.innerHTML = `<pre class="stack-trace">${error.stack}</pre>`;
            }
        }
    }

    // VULNERABILITY: XSS via innerHTML when displaying page views
    trackPageView(pageName, properties = {}) {
        const pageEvent = {
            name: 'page_view',
            properties: {
                page: pageName,
                title: document.title,
                referrer: document.referrer,
                ...properties
            },
            timestamp: Date.now(),
            userId: this.userId,
            sessionId: this.sessionId
        };

        this.events.push(pageEvent);

        // VULNERABILITY: XSS via innerHTML when showing page info
        const pageInfoDiv = document.getElementById('page-info');
        if (pageInfoDiv) {
            pageInfoDiv.innerHTML = `Current page: <strong>${pageName}</strong>`;
        }

        // VULNERABILITY: XSS via innerHTML with custom properties
        if (properties.customMessage) {
            const messageDiv = document.getElementById('custom-message');
            if (messageDiv) {
                messageDiv.innerHTML = properties.customMessage;
            }
        }
    }

    // VULNERABILITY: XSS via innerHTML when displaying conversion data
    trackConversion(conversionType, value, properties = {}) {
        const conversionEvent = {
            name: 'conversion',
            properties: {
                type: conversionType,
                value: value,
                currency: properties.currency || 'USD',
                ...properties
            },
            timestamp: Date.now(),
            userId: this.userId,
            sessionId: this.sessionId
        };

        this.events.push(conversionEvent);

        // VULNERABILITY: XSS via innerHTML when displaying conversion success
        const conversionDiv = document.getElementById('conversion-display');
        if (conversionDiv) {
            const message = properties.successMessage || `Conversion: ${conversionType}`;
            conversionDiv.innerHTML = `<div class="conversion-success">${message}</div>`;
        }

        // VULNERABILITY: XSS via innerHTML with conversion details
        if (properties.details) {
            const detailsDiv = document.getElementById('conversion-details');
            if (detailsDiv) {
                detailsDiv.innerHTML = `<div class="details">${properties.details}</div>`;
            }
        }
    }

    async sendEvent(event) {
        try {
            await fetch('/api/analytics/track', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(event)
            });
        } catch (error) {
            console.error('Failed to send analytics event:', error);
        }
    }

    // VULNERABILITY: XSS via innerHTML when loading user preferences
    async loadUserPreferences() {
        try {
            const response = await fetch('/api/user/preferences');
            const preferences = await response.json();

            // VULNERABILITY: XSS via innerHTML with server response
            const welcomeDiv = document.getElementById('welcome-message');
            if (welcomeDiv && preferences.welcomeMessage) {
                welcomeDiv.innerHTML = preferences.welcomeMessage;
            }

            // VULNERABILITY: XSS via innerHTML with theme settings
            if (preferences.theme && preferences.theme.customCss) {
                const styleDiv = document.getElementById('custom-styles');
                if (styleDiv) {
                    styleDiv.innerHTML = `<style>${preferences.theme.customCss}</style>`;
                }
            }

        } catch (error) {
            console.error('Failed to load user preferences:', error);
        }
    }

    // VULNERABILITY: XSS via innerHTML when displaying dashboard
    displayDashboard(dashboardData) {
        const dashboardDiv = document.getElementById('analytics-dashboard');
        if (!dashboardDiv) return;

        let dashboardHtml = '<h3>Analytics Dashboard</h3>';

        // VULNERABILITY: XSS via innerHTML with dashboard metrics
        if (dashboardData.metrics) {
            dashboardHtml += '<div class="metrics">';
            for (const [metric, value] of Object.entries(dashboardData.metrics)) {
                dashboardHtml += `<div class="metric"><label>${metric}:</label> <span>${value}</span></div>`;
            }
            dashboardHtml += '</div>';
        }

        // VULNERABILITY: XSS via innerHTML with custom widgets
        if (dashboardData.widgets) {
            dashboardHtml += '<div class="widgets">';
            dashboardData.widgets.forEach(widget => {
                dashboardHtml += `<div class="widget">${widget.content}</div>`;
            });
            dashboardHtml += '</div>';
        }

        // VULNERABILITY: XSS via innerHTML with recent events display
        if (dashboardData.recentEvents) {
            dashboardHtml += '<div class="recent-events"><h4>Recent Events:</h4>';
            dashboardData.recentEvents.forEach(event => {
                dashboardHtml += `<div class="event">${event.name}: ${event.description}</div>`;
            });
            dashboardHtml += '</div>';
        }

        dashboardDiv.innerHTML = dashboardHtml;
    }

    // VULNERABILITY: XSS via innerHTML when displaying search results
    displaySearchResults(query, results) {
        const resultsDiv = document.getElementById('search-results');
        if (!resultsDiv) return;

        // VULNERABILITY: XSS via innerHTML with search query
        let resultsHtml = `<h4>Search Results for: "${query}"</h4>`;

        if (results.length === 0) {
            resultsHtml += `<p>No results found for "${query}"</p>`;
        } else {
            resultsHtml += '<ul class="results-list">';
            results.forEach(result => {
                // VULNERABILITY: XSS via innerHTML with search result data
                resultsHtml += `<li><strong>${result.title}</strong><br>${result.description}</li>`;
            });
            resultsHtml += '</ul>';
        }

        resultsDiv.innerHTML = resultsHtml;
    }

    // VULNERABILITY: XSS via innerHTML when showing alerts
    showAlert(alertType, message, details = '') {
        const alertsDiv = document.getElementById('alerts-container');
        if (!alertsDiv) return;

        // VULNERABILITY: XSS via innerHTML with alert message
        const alertHtml = `
            <div class="alert alert-${alertType}">
                <strong>${alertType.toUpperCase()}:</strong> ${message}
                ${details ? `<div class="alert-details">${details}</div>` : ''}
            </div>
        `;

        alertsDiv.innerHTML += alertHtml;
    }

    // VULNERABILITY: XSS via innerHTML when displaying comments/feedback
    displayUserFeedback(feedback) {
        const feedbackDiv = document.getElementById('user-feedback');
        if (!feedbackDiv) return;

        let feedbackHtml = '<h4>User Feedback:</h4>';
        
        feedback.forEach(item => {
            // VULNERABILITY: XSS via innerHTML with user-generated content
            feedbackHtml += `
                <div class="feedback-item">
                    <div class="feedback-user">${item.username}</div>
                    <div class="feedback-content">${item.content}</div>
                    <div class="feedback-rating">Rating: ${item.rating}</div>
                </div>
            `;
        });

        feedbackDiv.innerHTML = feedbackHtml;
    }

    // Get analytics data
    getEvents() {
        return this.events;
    }

    // VULNERABILITY: XSS via innerHTML when exporting data
    exportData(format = 'html') {
        if (format === 'html') {
            const exportDiv = document.getElementById('export-data');
            if (exportDiv) {
                let exportHtml = '<h3>Analytics Export</h3><ul>';
                
                this.events.forEach(event => {
                    // VULNERABILITY: XSS via innerHTML with exported data
                    exportHtml += `<li>${event.name}: ${JSON.stringify(event.properties)}</li>`;
                });
                
                exportHtml += '</ul>';
                exportDiv.innerHTML = exportHtml;
            }
        }
    }

    // Clear all events
    clearEvents() {
        this.events = [];
        
        // VULNERABILITY: XSS via innerHTML when showing clear message
        const statusDiv = document.getElementById('status-message');
        if (statusDiv) {
            statusDiv.innerHTML = '<div class="success">Analytics data cleared successfully!</div>';
        }
    }
}

// Create and export singleton instance
const analyticsService = new AnalyticsService();

// VULNERABILITY: Expose analytics service globally
window.analyticsService = analyticsService;

export default analyticsService;