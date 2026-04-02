/**
 * Session Management and Activity Tracking
 * Handles session refresh, timeout warnings, and user activity tracking
 */

class SessionManager {
    constructor(options = {}) {
        this.sessionTimeoutMinutes = options.sessionTimeoutMinutes || 1; // Default 1 minute for demo
        this.refreshIntervalSeconds = options.refreshIntervalSeconds || 30; // Refresh every 30 seconds
        this.warningBeforeTimeoutSeconds = options.warningBeforeTimeoutSeconds || 30; // Warn 30 seconds before timeout
        this.activityLogEnabled = options.activityLogEnabled || true;
        
        this.lastActivityTime = Date.now();
        this.isSessionActive = true;
        this.warningShown = false;
        this.activityLog = [];
        
        this.init();
    }

    /**
     * Initialize session manager
     */
    init() {
        console.log('🔐 Session Manager initialized');
        
        // Setup activity listeners
        this.setupActivityListeners();
        
        // Start periodic session refresh
        this.startSessionRefresh();
        
        // Setup unload handler
        this.setupUnloadHandler();
        
        // Initial activity log
        this.logActivity('Session Started', 'session');
    }

    /**
     * Setup listeners for user activities
     */
    setupActivityListeners() {
        // Mouse movement
        document.addEventListener('mousemove', () => this.onUserActivity('Mouse Movement'));
        
        // Click events
        document.addEventListener('click', (e) => {
            const target = e.target;
            const elementInfo = target.id ? `#${target.id}` : target.className ? `.${target.className.split(' ')[0]}` : target.tagName;
            this.onUserActivity(`Click on ${elementInfo}`);
        });
        
        // Keyboard events
        document.addEventListener('keydown', () => this.onUserActivity('Keyboard Input'));
        
        // Form submission
        document.addEventListener('submit', (e) => {
            this.onUserActivity(`Form Submitted: ${e.target.id || 'Unknown'}`);
        });
        
        // Page visibility change
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.logActivity('Page Hidden', 'visibility');
            } else {
                this.logActivity('Page Visible', 'visibility');
                this.refreshSession(); // Refresh immediately when returning to page
            }
        });
        
        // Window focus
        window.addEventListener('focus', () => this.onUserActivity('Window Focused'));
        window.addEventListener('blur', () => this.logActivity('Window Blurred', 'blur'));
    }

    /**
     * Handle user activity
     */
    onUserActivity(activityName) {
        const now = Date.now();
        const timeSinceLastActivity = (now - this.lastActivityTime) / 1000;
        
        // Only log activity if at least 5 seconds have passed since last activity
        if (timeSinceLastActivity >= 5) {
            this.logActivity(activityName, 'user');
            this.lastActivityTime = now;
            
            // Reset warning if user becomes active again
            if (!this.isSessionActive) {
                this.warningShown = false;
                this.isSessionActive = true;
                this.hideSessionWarning();
                this.logActivity('Session Reactivated', 'session');
            }
        }
    }

    /**
     * Log activity to array and storage
     */
    logActivity(activityName, category = 'user') {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = {
            time: timestamp,
            activity: activityName,
            category: category,
            timestamp: Date.now()
        };
        
        this.activityLog.push(logEntry);
        
        // Keep only last 50 activities in memory
        if (this.activityLog.length > 50) {
            this.activityLog.shift();
        }
        
        if (this.activityLogEnabled) {
            console.log(`📊 [${timestamp}] Activity: ${activityName} (${category})`);
        }
        
        // Store in sessionStorage for tracking
        try {
            sessionStorage.setItem('activityLog', JSON.stringify(this.activityLog));
        } catch (e) {
            console.warn('Could not store activity log in sessionStorage');
        }
    }

    /**
     * Start periodic session refresh
     */
    startSessionRefresh() {
        setInterval(async () => {
            if (this.isSessionActive) {
                await this.refreshSession();
            }
        }, this.refreshIntervalSeconds * 1000);
        
        // Also check for timeout warning
        setInterval(() => {
            this.checkSessionTimeout();
        }, 5000); // Check every 5 seconds
    }

    /**
     * Refresh session by calling the API
     */
    async refreshSession() {
        try {
            const response = await fetch('/api/refresh-session', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                const data = await response.json();
                if (data.success) {
                    console.log('✅ Session refreshed successfully');
                    this.logActivity('Session Refreshed', 'session');
                    this.warningShown = false; // Clear warning flag
                    this.hideSessionWarning();
                    return true;
                }
            } else if (response.status === 401) {
                console.warn('⚠️ Session expired - unauthorized');
                this.handleSessionExpired();
                return false;
            }
        } catch (error) {
            console.error('❌ Error refreshing session:', error);
        }
        return false;
    }

    /**
     * Check if session is about to timeout
     */
    checkSessionTimeout() {
        try {
            fetch('/api/session-status', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success && data.is_active) {
                    const remainingSeconds = data.remaining_time_seconds;
                    
                    // Show warning if less than warning threshold
                    if (remainingSeconds < this.warningBeforeTimeoutSeconds && !this.warningShown) {
                        this.showSessionWarning(remainingSeconds);
                        this.warningShown = true;
                        this.logActivity(`Session timeout in ${remainingSeconds}s`, 'warning');
                    }
                    
                    // Hide warning if session is refreshed
                    if (remainingSeconds > this.warningBeforeTimeoutSeconds + 10) {
                        if (this.warningShown) {
                            this.hideSessionWarning();
                            this.warningShown = false;
                        }
                    }
                } else if (!data.is_active) {
                    this.handleSessionExpired();
                }
            })
            .catch(error => console.error('Error checking session status:', error));
        } catch (error) {
            console.error('Error in checkSessionTimeout:', error);
        }
    }

    /**
     * Show session timeout warning
     */
    showSessionWarning(remainingSeconds) {
        // Check if warning already exists
        let warningEl = document.getElementById('sessionTimeoutWarning');
        if (!warningEl) {
            warningEl = document.createElement('div');
            warningEl.id = 'sessionTimeoutWarning';
            warningEl.className = 'session-timeout-warning';
            warningEl.innerHTML = `
                <div class="warning-content">
                    <span class="warning-icon">⏰</span>
                    <span class="warning-text">Your session will expire in <strong id="remainingTime">${remainingSeconds}</strong> seconds</span>
                    <button class="stay-logged-in-btn" onclick="sessionManager.refreshSession()">Stay Logged In</button>
                </div>
            `;
            document.body.appendChild(warningEl);
            
            // Add CSS if not already present
            this.injectWarningStyles();
        }
        
        // Update remaining time
        const remainingTimeEl = document.getElementById('remainingTime');
        if (remainingTimeEl) {
            remainingTimeEl.textContent = Math.ceil(remainingSeconds);
        }
    }

    /**
     * Hide session timeout warning
     */
    hideSessionWarning() {
        const warningEl = document.getElementById('sessionTimeoutWarning');
        if (warningEl) {
            warningEl.style.display = 'none';
        }
    }

    /**
     * Handle session expiration
     */
    handleSessionExpired() {
        console.log('❌ Session has expired');
        this.logActivity('Session Expired', 'session');
        
        // Show expiration message
        const msgEl = document.createElement('div');
        msgEl.className = 'session-expired-message';
        msgEl.innerHTML = `
            <div class="expired-content">
                <span class="expired-icon">🔐</span>
                <span class="expired-text">Your session has expired. Please login again.</span>
                <button onclick="window.location.href='/login'">Login Again</button>
            </div>
        `;
        document.body.appendChild(msgEl);
        this.injectExpiredStyles();
        
        // Redirect after 3 seconds
        setTimeout(() => {
            window.location.href = '/login';
        }, 3000);
    }

    /**
     * Inject warning styles
     */
    injectWarningStyles() {
        if (document.getElementById('sessionWarningStyles')) return;
        
        const style = document.createElement('style');
        style.id = 'sessionWarningStyles';
        style.textContent = `
            .session-timeout-warning {
                position: fixed;
                top: 20px;
                right: 20px;
                background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
                color: white;
                padding: 15px 20px;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
                z-index: 10000;
                animation: slideIn 0.5s ease-out;
            }
            
            @keyframes slideIn {
                from {
                    transform: translateX(400px);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
            
            .warning-content {
                display: flex;
                align-items: center;
                gap: 12px;
                font-size: 14px;
            }
            
            .warning-icon {
                font-size: 20px;
            }
            
            .warning-text {
                flex: 1;
            }
            
            .stay-logged-in-btn {
                background: white;
                color: #d97706;
                border: none;
                padding: 6px 16px;
                border-radius: 4px;
                cursor: pointer;
                font-weight: 600;
                transition: transform 0.2s ease;
            }
            
            .stay-logged-in-btn:hover {
                transform: scale(1.05);
            }
        `;
        document.head.appendChild(style);
    }

    /**
     * Inject expired session styles
     */
    injectExpiredStyles() {
        if (document.getElementById('sessionExpiredStyles')) return;
        
        const style = document.createElement('style');
        style.id = 'sessionExpiredStyles';
        style.textContent = `
            .session-expired-message {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.5);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 10001;
            }
            
            .expired-content {
                background: white;
                padding: 30px;
                border-radius: 10px;
                text-align: center;
                box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 15px;
            }
            
            .expired-icon {
                font-size: 48px;
            }
            
            .expired-text {
                font-size: 18px;
                font-weight: 600;
                color: #333;
            }
            
            .expired-content button {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                padding: 10px 30px;
                border-radius: 5px;
                cursor: pointer;
                font-weight: 600;
                transition: transform 0.2s ease;
            }
            
            .expired-content button:hover {
                transform: scale(1.05);
            }
        `;
        document.head.appendChild(style);
    }

    /**
     * Setup unload handler to log session end
     */
    setupUnloadHandler() {
        window.addEventListener('beforeunload', () => {
            this.logActivity('Session Ended (Page Unload)', 'session');
        });
    }

    /**
     * Get activity log
     */
    getActivityLog() {
        return this.activityLog;
    }

    /**
     * Export activity log to JSON
     */
    exportActivityLog() {
        const dataStr = JSON.stringify(this.activityLog, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `activity-log-${Date.now()}.json`;
        link.click();
        URL.revokeObjectURL(url);
    }

    /**
     * Clear activity log
     */
    clearActivityLog() {
        this.activityLog = [];
        sessionStorage.removeItem('activityLog');
        console.log('Activity log cleared');
    }
}

// Create global instance
let sessionManager;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    // Only initialize if user is logged in (check for session)
    fetch('/api/session-status')
        .then(response => response.json())
        .then(data => {
            if (data.success && data.is_active) {
                sessionManager = new SessionManager({
                    sessionTimeoutMinutes: data.session_timeout_minutes || 1,
                    refreshIntervalSeconds: 30,
                    warningBeforeTimeoutSeconds: 30,
                    activityLogEnabled: true
                });
                
                // Make sessionManager global for button clicks
                window.sessionManager = sessionManager;
                console.log('✅ Session Manager ready');
            }
        })
        .catch(error => {
            console.log('No active session - Session Manager not initialized');
        });
});
