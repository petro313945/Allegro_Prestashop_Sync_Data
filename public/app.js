// State management
let currentOffers = [];
let allLoadedOffers = []; // Store all loaded offers for filtering
let importedOffers = [];
let currentOffset = 0; // Kept for display purposes
let currentLimit = 30; // Default products per page
let totalCount = 0; // Current page product count
let totalProductsSeen = 0; // Total products seen across all pages in current category
let isOAuthConnected = false; // Track OAuth connection status
let allCategories = [];
let categoriesWithProducts = []; // Categories that have products
let categoryNameCache = {}; // Cache for category names by ID
let selectedCategoryId = null; // null means "All Categories"
let currentNextPage = null; // For cursor-based pagination
let pageHistory = []; // Track page history for going back
let currentPhrase = ''; // Track current search phrase
let currentPageNumber = 1; // Track current page number
let currentStatusFilter = 'ALL'; // ALL | ACTIVE | ENDED

// Category tree state (Allegro hierarchy)
let categoryTreePath = []; // Array of { id, name } from root to current parent
let categoryTreeCache = {}; // Cache of categories per parent: { [parentIdOrRoot]: categories[] }
let categoryTreeInitialized = false; // Avoid reloading root tree unnecessarily
let categoryTreeWithProducts = {}; // Tree structure with only categories that have products: { [categoryId]: { id, name, count, children: {}, parent: id } }
let categoryProductCounts = {}; // Map of category ID to product count: { [categoryId]: count }
let totalOffersCountFromAPI = null; // Total count from Allegro API (for accurate "All Categories" display)

// PrestaShop state
let prestashopConfigured = false;
let prestashopAuthorized = false; // Track if PrestaShop connection is successfully tested/authorized

// API Base URL
const API_BASE = '';

// Authentication state
let authToken = null;
let currentUser = null;
let sessionExpiredMessageShown = false; // Flag to prevent showing multiple session expired messages

// Auth token management
function getAuthToken() {
    if (!authToken) {
        authToken = localStorage.getItem('auth_token');
    }
    return authToken;
}

function setAuthToken(token) {
    authToken = token;
    if (token) {
        localStorage.setItem('auth_token', token);
    } else {
        localStorage.removeItem('auth_token');
    }
}

// Helper function to clear all cookies
function clearAllCookies() {
    // Get all cookies
    const cookies = document.cookie.split(';');
    
    // Clear each cookie by setting it to expire in the past
    cookies.forEach(cookie => {
        const eqPos = cookie.indexOf('=');
        const name = eqPos > -1 ? cookie.substr(0, eqPos).trim() : cookie.trim();
        
        // Clear cookie for current path
        document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/`;
        
        // Clear cookie for root path
        document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;domain=${window.location.hostname}`;
        
        // Clear cookie without domain (for localhost)
        document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;domain=`;
    });
}

// Helper function to clear all localStorage items
function clearAllLocalStorage() {
    try {
        localStorage.clear();
    } catch (error) {
        console.error('Error clearing localStorage:', error);
    }
}

// Helper function to clear all sessionStorage items
function clearAllSessionStorage() {
    try {
        sessionStorage.clear();
    } catch (error) {
        console.error('Error clearing sessionStorage:', error);
    }
}

function clearAuth() {
    authToken = null;
    currentUser = null;
    
    // Clear all browser storage: localStorage, sessionStorage, and cookies
    clearAllLocalStorage();
    clearAllSessionStorage();
    clearAllCookies();
    
    // Reset session expired message flag when clearing auth
    sessionExpiredMessageShown = false;
}

// API fetch wrapper (no authentication required for Allegro/Prestashop operations)
async function apiFetch(url, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };

    const response = await fetch(url, {
        ...options,
        headers
    });

    return response;
}

// Authenticated fetch wrapper with automatic session refresh
// Session is automatically refreshed on every API call to prevent expiration during active use
async function authFetch(url, options = {}) {
    const token = getAuthToken();
    if (!token) {
        throw new Error('Not authenticated');
    }

    const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
        ...options.headers
    };

    // Make the request - the authMiddleware will automatically refresh the session
    // by updating lastActivity in validateSession()
    const response = await fetch(url, {
        ...options,
        headers
    });

    // If unauthorized, clear token and show login
    if (response.status === 401) {
        clearAuth();
        // Show user-friendly message about token expiration only once
        if (!sessionExpiredMessageShown) {
            showToast('Your session has expired. Please log in again to continue.', 'error', 8000);
            sessionExpiredMessageShown = true;
        }
        showLoginScreen();
        throw new Error('Session expired. Please log in again.');
    }

    return response;
}

// Update user display with username (without domain), icon, and role
function updateUserDisplay(user) {
    const userDisplayEl = document.getElementById('userDisplay');
    
    if (userDisplayEl && user && user.email && user.role) {
        // Extract username from email (remove @domain.com)
        const username = user.email.split('@')[0];
        // Capitalize first letter of username
        const displayName = username.charAt(0).toUpperCase() + username.slice(1);
        // Capitalize first letter of role
        const roleText = user.role.charAt(0).toUpperCase() + user.role.slice(1);
        // Format as "admin: Me" or "user: Me"
        userDisplayEl.textContent = `${roleText}: ${displayName}`;
        userDisplayEl.className = `user-status-badge ${user.role}`;
    }
}

// Login function
async function login(email, password) {
    try {
        const response = await fetch(`${API_BASE}/api/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Login failed');
        }

        setAuthToken(data.token);
        currentUser = data.user;
        
        // Reset session expired message flag on successful login
        sessionExpiredMessageShown = false;
        
        // Update user email display
        updateUserDisplay(data.user);
        
        // Load credentials from database in background (non-blocking for faster login)
        // Use Promise.allSettled() so one failure doesn't block the other
        Promise.allSettled([
            loadCredentialsFromAPI(),
            loadPrestashopConfigFromAPI()
        ]).then(results => {
            results.forEach((result, index) => {
                if (result.status === 'rejected') {
                    const apiName = index === 0 ? 'loadCredentialsFromAPI' : 'loadPrestashopConfigFromAPI';
                    console.error(`Error loading ${apiName} in background:`, result.reason);
                }
            });
        });
        
        return data;
    } catch (error) {
        throw error;
    }
}

// Logout function
async function logout() {
    // Capture user info before clearing auth
    const user = currentUser;
    const token = getAuthToken();
    
    // Show login screen immediately for fast logout
    clearAuth();
    showLoginScreen();
    
    // Show logout info toast
    if (user && user.email) {
        const logoutTime = new Date().toLocaleString();
        showToast(`${user.email} logged out at ${logoutTime}`, 'info', 5000);
    }
    
    // Do logout API call in background (non-blocking)
    if (token) {
        authFetch(`${API_BASE}/api/logout`, {
            method: 'POST'
        }).catch(error => {
            // Silently handle errors - user is already logged out on client side
            console.error('Logout API error (non-critical):', error);
        });
    }
}

// Show/hide login screen
function showLoginScreen() {
    document.getElementById('loginScreen').style.display = 'flex';
    document.getElementById('mainApp').style.display = 'none';
    // Reset logout listener flag when showing login screen
    isLogoutListenerAttached = false;
    isLogoutInProgress = false;
}

// Check if user is logged in on page load
// Validates session with server to update lastActivity timestamp
async function checkAuth() {
    const token = getAuthToken();
    if (!token) {
        showLoginScreen();
        return false;
    }

    try {
        // Validate session with server - this updates the session's lastActivity
        const response = await authFetch(`${API_BASE}/api/auth/validate`);
        const data = await response.json();
        
        if (data.success && data.user) {
            // Update current user from server response
            currentUser = data.user;
            
            // Update user display
            updateUserDisplay(currentUser);
            showMainInterface();
            
            // Load credentials from database in parallel for faster loading
            // Use Promise.allSettled() so one failure doesn't block the other
            const credentialResults = await Promise.allSettled([
                loadCredentialsFromAPI(),
                loadPrestashopConfigFromAPI()
            ]);
            
            // Log any failures but don't block the UI
            credentialResults.forEach((result, index) => {
                if (result.status === 'rejected') {
                    const apiName = index === 0 ? 'loadCredentialsFromAPI' : 'loadPrestashopConfigFromAPI';
                    console.error(`Error loading ${apiName}:`, result.reason);
                }
            });
            
            // Show message that user is already logged in
            if (currentUser && currentUser.email) {
                const now = new Date();
                const dateStr = now.toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric' });
                const timeStr = now.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                showToast(`${currentUser.email} already logged in at ${dateStr}, ${timeStr}`, 'info', 4000);
            }
            
            return true;
        } else {
            // Session validation failed
            clearAuth();
            showLoginScreen();
            return false;
        }
    } catch (error) {
        // Session expired or invalid - authFetch already handles 401 and shows login
        if (error.message !== 'Session expired. Please log in again.') {
            console.error('Error validating session:', error);
        }
        return false;
    }
}

// Initialize app
document.addEventListener('DOMContentLoaded', async () => {
    // Setup login form handler
    const loginForm = document.getElementById('loginForm');
    const loginEmail = document.getElementById('loginEmail');
    const loginPassword = document.getElementById('loginPassword');
    const loginErrorMessage = document.getElementById('loginErrorMessage');
    const loginSubmitBtn = document.getElementById('loginSubmitBtn');

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        loginErrorMessage.style.display = 'none';
        loginSubmitBtn.disabled = true;
        loginSubmitBtn.textContent = 'Logging in...';

        try {
            const loginResult = await login(loginEmail.value.trim(), loginPassword.value);
            // Show main interface immediately after successful login
            showMainInterface();
            // Notify user with who logged in and when
            const userEmail = loginResult?.user?.email || loginEmail.value.trim();
            const loginTime = new Date().toLocaleString();
            showToast(`${userEmail} logged in at ${loginTime}`, 'success', 5000);
            
            // Initialize app components in background (non-blocking for faster login)
            setupEventListeners();
            updateUIState(false);
            updateButtonStates();
            if (typeof updateSyncCategoryButtonState === 'function') {
                updateSyncCategoryButtonState();
            }
            
            // Load data in background (non-blocking)
            // Use Promise.allSettled() so one failure doesn't block others
            Promise.allSettled([
                loadImportedOffers(),
                loadPrestashopConfig(),
                checkPrestashopStatus(),
                loadSavedCredentials()
            ]).then(results => {
                results.forEach((result, index) => {
                    if (result.status === 'rejected') {
                        const apiNames = ['loadImportedOffers', 'loadPrestashopConfig', 'checkPrestashopStatus', 'loadSavedCredentials'];
                        console.error(`Error initializing ${apiNames[index]}:`, result.reason);
                    }
                });
            });
        } catch (error) {
            loginErrorMessage.textContent = error.message || 'Login failed. Please try again.';
            loginErrorMessage.style.display = 'block';
        } finally {
            loginSubmitBtn.disabled = false;
            loginSubmitBtn.textContent = 'Log In';
            loginPassword.value = '';
        }
    });

    // Check if already logged in
    const isAuthenticated = await checkAuth();
    if (!isAuthenticated) {
        return; // Stop here, wait for login
    }

    // User is authenticated, continue with app initialization
    setupEventListeners();
    loadImportedOffers();
    loadPrestashopConfig();
    checkPrestashopStatus();
    
    // Load saved credentials and restore authentication state
    await loadSavedCredentials();
    
    // Initially disable all actions until authenticated
    updateUIState(false);
    // Update button states on initialization
    updateButtonStates();
    // Update sync category button state
    if (typeof updateSyncCategoryButtonState === 'function') {
        updateSyncCategoryButtonState();
    }

    // Data will be loaded fresh from Allegro API when user clicks "Load My Offers"
});

// Automatically load offers when everything is already configured
async function autoLoadOffersIfReady() {
    const loadOffersBtn = document.getElementById('loadOffersBtn');
    if (!loadOffersBtn) return;

    // Require Allegro auth + OAuth + PrestaShop authorization
    if (!checkAuthentication() || !isOAuthConnected || !prestashopAuthorized) {
        return;
    }

    // If offers are already loaded, don't reload
    if (allLoadedOffers && allLoadedOffers.length > 0) {
        return;
    }

    // Fixed page size: always 30 offers per page
    const limit = 30;
    currentLimit = limit;
    currentOffset = 0;
    currentPageNumber = 1;
    totalProductsSeen = 0;
    allLoadedOffers = [];

    // Ensure categories are loaded (short and in background)
    if (allCategories.length === 0) {
        try {
            await loadCategoriesFromOffers();
        } catch (error) {
            console.warn('Auto categories load failed, continuing with offers:', error);
        }
    }

    // Start loading offers (progressive rendering handled inside)
    fetchAllOffers();
}

// Load credentials from API (database)
async function loadCredentialsFromAPI() {
    try {
        const response = await authFetch(`${API_BASE}/api/credentials`);
        
        if (!response.ok) {
            if (response.status === 401) {
                return; // Not authenticated, will be handled by authFetch
            }
            return;
        }
        
        const data = await response.json();
        
        if (data.success && data.credentials && data.credentials.clientId) {
            // Restore credentials to input fields (only clientId, secret is masked for security)
            const clientIdInput = document.getElementById('clientId');
            if (clientIdInput) {
                clientIdInput.value = data.credentials.clientId;
            }
            
            // If client secret exists in DB (indicated by '***' or non-null value), show indicator
            const clientSecretInput = document.getElementById('clientSecret');
            if (clientSecretInput && data.credentials.clientSecret) {
                // Set placeholder to indicate secret is saved but masked
                clientSecretInput.placeholder = 'Client Secret is saved (hidden for security)';
                clientSecretInput.value = ''; // Keep field empty for security
                // Add a visual indicator class
                clientSecretInput.classList.add('secret-saved');
            }
            
            // Update auth status immediately if credentials are present (even before test)
            const authStatusEl = document.getElementById('authStatus');
            if (authStatusEl && data.credentials.clientSecret) {
                authStatusEl.textContent = 'API Credentials: Configured';
                authStatusEl.className = 'quick-status-badge success';
                authStatusEl.title = 'Allegro API credentials (Client ID/Secret) are saved';
            }
            
            // Show disconnect button if credentials are present
            const clearBtn = document.getElementById('clearCredentialsBtn');
            if (clearBtn && data.credentials.clientSecret) {
                clearBtn.style.display = 'block';
            }
            
            // Update config status indicators immediately
            updateConfigStatuses();
            
            // Check if credentials are still valid by testing authentication
            const authResponse = await authFetch(`${API_BASE}/api/test-auth`).catch(() => null);
            if (authResponse && authResponse.ok) {
                const authData = await authResponse.json();
                
                if (authData.success) {
                    // Credentials are valid - update authentication state
                    if (authStatusEl) {
                        authStatusEl.textContent = 'API Credentials: Configured';
                        authStatusEl.className = 'quick-status-badge success';
                        authStatusEl.title = 'Allegro API credentials (Client ID/Secret) are saved and working';
                    }
                    
                    // Update config status indicators and button states
                    updateConfigStatuses();
                    
                    // Check OAuth status (this will also try to refresh expired tokens)
                    await checkOAuthStatus();
                    
                    // Update UI state
                    updateUIState(true);
                }
            } else {
                // Even if test fails, credentials are still configured
                // Check OAuth status anyway
                await checkOAuthStatus();
                updateUIState(true);
            }
        }
    } catch (error) {
        // Silently fail - credentials may not be configured yet
        console.log('No credentials found in database or error loading:', error.message);
    }
}

// Legacy function name for backward compatibility
async function loadSavedCredentials() {
    return loadCredentialsFromAPI();
}

// Update config status indicators
function updateConfigStatuses() {
    // Check if Allegro credentials are actually saved by checking the input fields
    const clientIdInput = document.getElementById('clientId');
    const clientSecretInput = document.getElementById('clientSecret');
    const hasAllegroCredentials = clientIdInput && clientIdInput.value.trim() && 
                                  (clientSecretInput && (clientSecretInput.value.trim() || clientSecretInput.classList.contains('secret-saved')));
    const isAllegroAuthenticated = checkAuthentication();
    
    // Update Allegro status
    const allegroStatus = document.getElementById('allegroConfigStatus');
    if (allegroStatus) {
        if (hasAllegroCredentials || isAllegroAuthenticated) {
            allegroStatus.textContent = 'Connected';
            allegroStatus.className = 'config-status success';
        } else {
            allegroStatus.textContent = 'Not Configured';
            allegroStatus.className = 'config-status error';
        }
    }
    
    // Update Allegro quick status
    const allegroQuickStatus = document.getElementById('allegroQuickStatus');
    if (allegroQuickStatus) {
        if (hasAllegroCredentials || isAllegroAuthenticated) {
            allegroQuickStatus.textContent = 'Allegro: Connected';
            allegroQuickStatus.className = 'quick-status-badge success';
        } else {
            allegroQuickStatus.textContent = 'Allegro: Not Configured';
            allegroQuickStatus.className = 'quick-status-badge error';
        }
    }
    
    // Check if PrestaShop credentials are actually saved by checking the input fields
    const prestashopUrlInput = document.getElementById('prestashopUrl');
    const prestashopApiKeyInput = document.getElementById('prestashopApiKey');
    const hasPrestashopCredentials = prestashopUrlInput && prestashopUrlInput.value.trim() && 
                                     prestashopApiKeyInput && (prestashopApiKeyInput.value.trim() || prestashopApiKeyInput.classList.contains('secret-saved'));
    
    // Update PrestaShop status - show "Connected" if credentials are saved, "Configured" if saved but not tested
    const prestashopStatusEl = document.getElementById('prestashopConfigStatus');
    if (prestashopStatusEl) {
        if (prestashopConfigured && prestashopAuthorized) {
            prestashopStatusEl.textContent = 'Connected';
            prestashopStatusEl.className = 'config-status success';
        } else if (hasPrestashopCredentials || prestashopConfigured) {
            prestashopStatusEl.textContent = 'Configured';
            prestashopStatusEl.className = 'config-status success';
        } else {
            prestashopStatusEl.textContent = 'Not Configured';
            prestashopStatusEl.className = 'config-status error';
        }
    }
    
    // Update PrestaShop quick status
    const prestashopQuickStatus = document.getElementById('prestashopQuickStatus');
    if (prestashopQuickStatus) {
        if (prestashopConfigured && prestashopAuthorized) {
            prestashopQuickStatus.textContent = 'PrestaShop: Connected';
            prestashopQuickStatus.className = 'quick-status-badge success';
        } else if (hasPrestashopCredentials || prestashopConfigured) {
            prestashopQuickStatus.textContent = 'PrestaShop: Configured';
            prestashopQuickStatus.className = 'quick-status-badge success';
        } else {
            prestashopQuickStatus.textContent = 'PrestaShop: Not Configured';
            prestashopQuickStatus.className = 'quick-status-badge error';
        }
    }
    
    // Update PrestaShop header status
    const prestashopHeaderStatus = document.getElementById('prestashopHeaderStatus');
    if (prestashopHeaderStatus) {
        if (prestashopConfigured && prestashopAuthorized) {
            prestashopHeaderStatus.textContent = 'Connected';
            prestashopHeaderStatus.className = 'status-value success';
        } else if (hasPrestashopCredentials || prestashopConfigured) {
            prestashopHeaderStatus.textContent = 'Configured';
            prestashopHeaderStatus.className = 'status-value success';
        } else {
            prestashopHeaderStatus.textContent = 'Not Connected';
            prestashopHeaderStatus.className = 'status-value error';
        }
    }
    
    // Update button states
    updateButtonStates();
}

// Update button states based on authentication/configuration status
function updateButtonStates() {
    // Update Allegro API Configuration button and inputs
    const allegroConnectBtn = document.getElementById('saveCredentialsBtn');
    const clientIdInput = document.getElementById('clientId');
    const clientSecretInput = document.getElementById('clientSecret');
    
    // Update Allegro disconnect and authorize buttons
    const clearBtn = document.getElementById('clearCredentialsBtn');
    const authorizeBtn = document.getElementById('authorizeAccountBtn');
    
    if (allegroConnectBtn) {
        if (checkAuthentication()) {
            // Connected state: grey, disabled, shows "Connected"
            allegroConnectBtn.textContent = 'Connected';
            allegroConnectBtn.className = 'btn btn-connected';
            allegroConnectBtn.disabled = true;
            
            // Show disconnect and authorize buttons
            if (clearBtn) {
                clearBtn.style.display = 'block';
            }
            if (authorizeBtn) {
                // Show button only when OAuth is not connected
                if (isOAuthConnected) {
                    authorizeBtn.style.display = 'none';
                } else {
                    authorizeBtn.style.display = 'block';
                    authorizeBtn.textContent = 'Authorize Account';
                    authorizeBtn.title = 'Click to authorize your Allegro account via OAuth';
                }
            }
            
            // Make inputs readonly
            if (clientIdInput) {
                clientIdInput.readOnly = true;
            }
            if (clientSecretInput) {
                clientSecretInput.readOnly = true;
            }
        } else {
            // Not connected: blue, enabled, shows "Connect"
            allegroConnectBtn.textContent = 'Connect';
            allegroConnectBtn.className = 'btn btn-primary';
            allegroConnectBtn.disabled = false;
            
            // Hide disconnect and authorize buttons
            if (clearBtn) {
                clearBtn.style.display = 'none';
            }
            if (authorizeBtn) {
                authorizeBtn.style.display = 'none';
            }
            
            // Make inputs editable
            if (clientIdInput) {
                clientIdInput.readOnly = false;
            }
            if (clientSecretInput) {
                clientSecretInput.readOnly = false;
            }
        }
    }
    
    // Update PrestaShop Configuration button and inputs
    const prestashopConnectBtn = document.getElementById('testPrestashopBtn');
    const prestashopDisconnectBtn = document.getElementById('clearPrestashopBtn');
    const prestashopUrlInput = document.getElementById('prestashopUrl');
    const prestashopApiKeyInput = document.getElementById('prestashopApiKey');
    
    if (prestashopConnectBtn) {
        if (prestashopConfigured && prestashopAuthorized) {
            // Connected state: grey, disabled, shows "Connected"
            prestashopConnectBtn.textContent = 'Connected';
            prestashopConnectBtn.className = 'btn btn-connected';
            prestashopConnectBtn.disabled = true;
            
            // Show disconnect button
            if (prestashopDisconnectBtn) {
                prestashopDisconnectBtn.style.display = 'block';
            }
            
            // Make inputs readonly
            if (prestashopUrlInput) {
                prestashopUrlInput.readOnly = true;
            }
            if (prestashopApiKeyInput) {
                prestashopApiKeyInput.readOnly = true;
            }

            // Update CSV export buttons based on current data
            if (typeof updateCsvExportButtonsState === 'function') {
                updateCsvExportButtonsState();
            }
            // Update sync category button state
            if (typeof updateSyncCategoryButtonState === 'function') {
                updateSyncCategoryButtonState();
            }
        } else {
            // Ensure CSV export buttons are disabled when PrestaShop is not configured
            if (typeof updateCsvExportButtonsState === 'function') {
                updateCsvExportButtonsState();
            }
            // Update sync category button state
            if (typeof updateSyncCategoryButtonState === 'function') {
                updateSyncCategoryButtonState();
            }
            // Not connected: blue, enabled, shows "Connect"
            prestashopConnectBtn.textContent = 'Connect';
            prestashopConnectBtn.className = 'btn btn-primary';
            prestashopConnectBtn.disabled = false;
            
            // Hide disconnect button
            if (prestashopDisconnectBtn) {
                prestashopDisconnectBtn.style.display = 'none';
            }
            
            // Make inputs editable
            if (prestashopUrlInput) {
                prestashopUrlInput.readOnly = false;
            }
            if (prestashopApiKeyInput) {
                prestashopApiKeyInput.readOnly = false;
            }
        }
    }
}

// Update sync category button state based on categories and PrestaShop configuration
function updateSyncCategoryButtonState() {
    const triggerCategorySyncBtn = document.getElementById('triggerCategorySyncBtn');
    
    // Enable button only if categories are loaded and PrestaShop is configured and authorized
    const hasCategories = allCategories && allCategories.length > 0;
    const canSync = hasCategories && prestashopConfigured && prestashopAuthorized;
    
    // Update Sync Now button (triggerCategorySyncBtn)
    if (triggerCategorySyncBtn) {
        triggerCategorySyncBtn.disabled = !canSync;
        
        if (!hasCategories) {
            triggerCategorySyncBtn.title = 'Load categories first';
        } else if (!prestashopConfigured || !prestashopAuthorized) {
            triggerCategorySyncBtn.title = 'PrestaShop must be configured and authorized';
        } else {
            triggerCategorySyncBtn.title = '';
        }
    }
}

// Update CSV export buttons state based on configuration and data availability
function updateCsvExportButtonsState() {
    const exportCategoriesCsvBtn = document.getElementById('exportCategoriesCsvBtn');
    const exportProductsCsvBtn = document.getElementById('exportProductsCsvBtn');

    const canUsePrestashop = prestashopConfigured && prestashopAuthorized;

    // Categories CSV: require configured PrestaShop and at least one category
    if (exportCategoriesCsvBtn) {
        const hasCategories =
            (Array.isArray(allCategories) && allCategories.length > 0) ||
            (Array.isArray(categoriesWithProducts) && categoriesWithProducts.length > 0);
        exportCategoriesCsvBtn.disabled = !canUsePrestashop || !hasCategories;
    }

    // Products CSV: require configured PrestaShop and at least one imported product
    if (exportProductsCsvBtn) {
        const hasImportedProducts = Array.isArray(importedOffers) && importedOffers.length > 0;
        exportProductsCsvBtn.disabled = !canUsePrestashop || !hasImportedProducts;
    }
}

// Store logout handler reference to allow removal
let logoutHandler = null;
// Flag to prevent multiple confirm dialogs
let isLogoutInProgress = false;
// Track if listener is already attached to prevent duplicates
let isLogoutListenerAttached = false;

// Setup event listeners
function setupEventListeners() {
    // Logout button - ensure listener is only attached once
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn && !isLogoutListenerAttached) {
        // Set flag immediately to prevent race conditions
        isLogoutListenerAttached = true;
        
        // Create handler function with flag check to prevent multiple confirm dialogs
        logoutHandler = async () => {
            // Prevent multiple confirm dialogs
            if (isLogoutInProgress) {
                return;
            }
            
            if (confirm('Are you sure you want to log out?')) {
                isLogoutInProgress = true;
                try {
                    await logout();
                } finally {
                    // Reset flag after logout completes (or fails)
                    setTimeout(() => {
                        isLogoutInProgress = false;
                    }, 1000);
                }
            }
        };
        // Add the listener only once
        logoutBtn.addEventListener('click', logoutHandler);
    }

    // Update user email display
    if (currentUser) {
        updateUserDisplay(currentUser);
    }
    document.getElementById('saveCredentialsBtn').addEventListener('click', saveCredentials);
    const clearBtn = document.getElementById('clearCredentialsBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', clearCredentials);
    }
    
    // Sync timer control buttons
    const startSyncBtn = document.getElementById('startSyncBtn');
    if (startSyncBtn) {
        startSyncBtn.addEventListener('click', startSyncTimerControl);
    }
    const stopSyncBtn = document.getElementById('stopSyncBtn');
    if (stopSyncBtn) {
        stopSyncBtn.addEventListener('click', stopSyncTimerControl);
    }
    const triggerSyncBtn = document.getElementById('triggerSyncBtn');
    if (triggerSyncBtn) {
        triggerSyncBtn.addEventListener('click', triggerSyncNow);
    }
    
    // X Rate input field with validation
    const xRateInput = document.getElementById('xRateInput');
    if (xRateInput) {
        xRateInput.addEventListener('input', (e) => {
            const value = parseFloat(e.target.value);
            // Validate range 0-500
            if (isNaN(value) || value < 0 || value > 500) {
                e.target.setCustomValidity('Value must be between 0 and 500');
            } else {
                e.target.setCustomValidity('');
            }
            userChangedSlider = true; // Mark that user manually changed it
        });
        
        xRateInput.addEventListener('blur', (e) => {
            const value = parseFloat(e.target.value);
            // Clamp value to valid range on blur
            if (isNaN(value) || value < 0) {
                e.target.value = 0;
            } else if (value > 500) {
                e.target.value = 500;
            }
        });
    }
    
    // Category sync timer control buttons
    const startCategorySyncBtn = document.getElementById('startCategorySyncBtn');
    if (startCategorySyncBtn) {
        startCategorySyncBtn.addEventListener('click', startCategorySyncTimerControl);
    }
    const stopCategorySyncBtn = document.getElementById('stopCategorySyncBtn');
    if (stopCategorySyncBtn) {
        stopCategorySyncBtn.addEventListener('click', stopCategorySyncTimerControl);
    }
    // Note: triggerCategorySyncBtn event listener is set up later in the file (around line 912)
    // We'll update it there to also call updateCategorySyncStatusFromServer
    
    const authorizeAccountBtn = document.getElementById('authorizeAccountBtn');
    if (authorizeAccountBtn) {
        authorizeAccountBtn.addEventListener('click', authorizeAccount);
    }
    const testAuthBtn = document.getElementById('testAuthBtn');
    if (testAuthBtn) {
        testAuthBtn.addEventListener('click', testAuthentication);
    }
    document.getElementById('clearBtn').addEventListener('click', clearSearch);

    // Select/Deselect all offers on current page
    const selectAllOffersBtn = document.getElementById('selectAllOffersBtn');
    if (selectAllOffersBtn) {
        selectAllOffersBtn.addEventListener('click', selectAllOffersOnPage);
    }
    
    // Listen for OAuth success message from popup
    window.addEventListener('message', function(event) {
        if (event.data && event.data.type === 'oauth_success') {
            checkOAuthStatus();
        }
    });
    
    // Add event listener for load offers button
    const loadOffersBtn = document.getElementById('loadOffersBtn');
    if (loadOffersBtn) {
        loadOffersBtn.addEventListener('click', async () => {
            // Show confirmation alert
            if (!confirm('Are you sure you want to load offers from Allegro?')) {
                return;
            }
            
            // Fixed page size: always 30 offers per page
            const limit = 30;
            currentLimit = limit;
            currentOffset = 0;
            currentPageNumber = 1;
            totalProductsSeen = 0;
            allLoadedOffers = []; // Clear previous offers
            
            // Load categories from offers first if not already loaded (required for proper functionality)
            if (allCategories.length === 0) {
                try {
                    await loadCategoriesFromOffers();
                } catch (error) {
                    // If categories fail to load, still proceed with loading offers
                    console.warn('Categories failed to load, but continuing with offers:', error);
                }
            }
            
            fetchAllOffers(); // Fetch all offers
        });
    }
    
    // Status filter (All / Active / Ended)
    const statusFilterSelect = document.getElementById('statusFilter');
    if (statusFilterSelect) {
        statusFilterSelect.addEventListener('change', () => {
            currentStatusFilter = statusFilterSelect.value || 'ALL';
            // Reset pagination when status filter changes
            currentOffset = 0;
            currentPageNumber = 1;
            pageHistory = [];
            totalProductsSeen = 0;
            displayOffersPage();
        });
    }

    // Offer search bar (client-side filtering by offer name / id / external id)
    const offerSearchInput = document.getElementById('offerSearchInput');
    if (offerSearchInput) {
        offerSearchInput.addEventListener('input', () => {
            // Store lowercase phrase for easier comparisons
            currentPhrase = (offerSearchInput.value || '').trim().toLowerCase();

            // Reset pagination when search changes
            currentOffset = 0;
            currentPageNumber = 1;
            pageHistory = [];
            totalProductsSeen = 0;

            // Re-render current offers (search is applied in getOffersFilteredByStatus)
            displayOffersPage();
        });
    }
    
    // Product count is fixed (30 per page), so no selector or change handler needed
    document.getElementById('importSelectedBtn').addEventListener('click', importSelected);
    document.getElementById('prevBtn').addEventListener('click', () => changePage(-1));
    document.getElementById('nextBtn').addEventListener('click', () => changePage(1));
    
    // Page jump functionality
    const pageJumpBtn = document.getElementById('pageJumpBtn');
    const pageJumpInput = document.getElementById('pageJumpInput');
    if (pageJumpBtn && pageJumpInput) {
        pageJumpBtn.addEventListener('click', jumpToPage);
        pageJumpInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                jumpToPage();
            }
        });
    }
    
    document.getElementById('clearImportedBtn').addEventListener('click', clearImportedProducts);
    document.getElementById('exportToPrestashopBtn').addEventListener('click', exportToPrestashop);
    
    // Sync Now button (triggerCategorySyncBtn) event listener
    const triggerCategorySyncBtn = document.getElementById('triggerCategorySyncBtn');
    if (triggerCategorySyncBtn) {
        triggerCategorySyncBtn.addEventListener('click', async () => {
            if (triggerCategorySyncBtn.disabled) return;
            
            // Call triggerCategorySyncNow with showConfirmation=true for manual sync
            await triggerCategorySyncNow(true);
        });
    }
    
    // PrestaShop event listeners
    const testPrestashopBtn = document.getElementById('testPrestashopBtn');
    if (testPrestashopBtn) {
        testPrestashopBtn.addEventListener('click', testPrestashopConnection);
    }
    const clearPrestashopBtn = document.getElementById('clearPrestashopBtn');
    if (clearPrestashopBtn) {
        clearPrestashopBtn.addEventListener('click', clearPrestashopConfig);
    }
    const loadPrestashopCategoriesBtn = document.getElementById('loadPrestashopCategoriesBtn');
    if (loadPrestashopCategoriesBtn) {
        loadPrestashopCategoriesBtn.addEventListener('click', loadPrestashopCategories);
    }
    
    // CSV Export event listeners
    const exportCategoriesCsvBtn = document.getElementById('exportCategoriesCsvBtn');
    if (exportCategoriesCsvBtn) {
        exportCategoriesCsvBtn.addEventListener('click', exportCategoriesCsv);
    }
    const exportProductsCsvBtn = document.getElementById('exportProductsCsvBtn');
    if (exportProductsCsvBtn) {
        exportProductsCsvBtn.addEventListener('click', exportProductsCsv);
    }
    
    // Load PrestaShop config on startup
    loadPrestashopConfig();
    checkPrestashopStatus();
    
    // Setup collapsible config panel
    setupConfigPanelToggle();
    
    // Setup tab navigation
    setupTabNavigation();
    
    // Setup user management (only for admins)
    setupUserManagement();
    
    // Initialize dashboard stats
    updateDashboardStats();
}

// Toast notification system
function showToast(message, type = 'info', duration = 5000) {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: '✓',
        error: '✕',
        info: 'ℹ'
    };
    
    // Check if message contains HTML (like <br> tags)
    const isHTML = /<[^>]+>/.test(message);
    
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <span class="toast-message">${isHTML ? message : escapeHtml(message)}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">×</button>
    `;
    
    container.appendChild(toast);
    
    // Auto remove after duration
    setTimeout(() => {
        toast.classList.add('hiding');
        setTimeout(() => {
            if (toast.parentElement) {
                toast.remove();
            }
        }, 300);
    }, duration);
}

// Show message in a message element (for credentials forms)
function showMessage(elementId, message, type = 'info') {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    element.textContent = message;
    element.className = `message ${type}`;
    element.style.display = 'block';
    
    // Auto-hide after 5 seconds for success messages
    if (type === 'success') {
        setTimeout(() => {
            element.style.display = 'none';
        }, 5000);
    }
}

// Save credentials and authenticate immediately
async function saveCredentials() {
    const clientId = document.getElementById('clientId').value.trim();
    const clientSecret = document.getElementById('clientSecret').value.trim();
    const connectBtn = document.getElementById('saveCredentialsBtn');
    
    if (!clientId || !clientSecret) {
        showToast('Please enter both Client ID and Client Secret', 'error');
        return;
    }
    
    // Check if user is logged in
    const token = getAuthToken();
    if (!token) {
        showToast('Please log in to configure Allegro.', 'error', 8000);
        showLoginScreen();
        return;
    }
    
    // Note: Session is automatically refreshed on every API call via authMiddleware
    // The validateSession() function updates lastActivity, preventing expiration during active use
    
    // Disable button during authentication
    connectBtn.disabled = true;
    connectBtn.textContent = 'Connecting...';
    
    try {
        // Step 1: Send credentials to backend (now requires authentication)
        const credentialsResponse = await authFetch(`${API_BASE}/api/credentials`, {
            method: 'POST',
            body: JSON.stringify({
                clientId: clientId,
                clientSecret: clientSecret
            })
        });
        
        // Check for 401 status before parsing JSON
        if (!credentialsResponse.ok && credentialsResponse.status === 401) {
            const errorData = await credentialsResponse.json().catch(() => ({}));
            throw new Error(errorData.error || 'Authentication required. Please log in again to configure Allegro.');
        }
        
        const credentialsData = await credentialsResponse.json();
        
        if (!credentialsData.success) {
            throw new Error(credentialsData.error || 'Failed to save credentials');
        }
        
        // Step 2: Test authentication immediately (requires auth token)
        const authResponse = await authFetch(`${API_BASE}/api/test-auth`);
        
        // Check for 401 status before parsing JSON
        if (!authResponse.ok && authResponse.status === 401) {
            const errorData = await authResponse.json().catch(() => ({}));
            throw new Error(errorData.error || 'Authentication required. Please log in again to test Allegro credentials.');
        }
        
        const authData = await authResponse.json();
        
        if (authData.success) {
            // Authentication successful - show detail interface
            // Credentials are now stored in database, no need for localStorage
            
            // Clear client secret field for security (value is saved in DB)
            const clientSecretInput = document.getElementById('clientSecret');
            if (clientSecretInput) {
                clientSecretInput.value = '';
                clientSecretInput.placeholder = 'Client Secret is saved (hidden for security)';
                clientSecretInput.classList.add('secret-saved');
            }
            
            showToast('Allegro API credentials saved and verified successfully. You can now authorize your account.', 'success');
            
            // Show main content
            showMainInterface();
            
            const authStatusEl = document.getElementById('authStatus');
            if (authStatusEl) {
                authStatusEl.textContent = 'API Credentials: Configured';
                authStatusEl.className = 'quick-status-badge success';
                authStatusEl.title = 'Allegro API credentials (Client ID/Secret) are saved and working';
            }
            
            // Show disconnect button in Allegro API Configuration section
            const clearBtn = document.getElementById('clearCredentialsBtn');
            if (clearBtn) {
                clearBtn.style.display = 'block';
            }
            
            // Update config status indicators and button states
            updateConfigStatuses();
            
            // Update UI state
            updateUIState(true);
            
            // Check API status
            await checkApiStatus();
            
            // Check OAuth status
            await checkOAuthStatus();
            
            // Categories will be loaded automatically after OAuth authorization
        } else {
            // Authentication failed - stay on first interface
            throw new Error(authData.error || 'Authentication failed. Please check your credentials.');
        }
    } catch (error) {
        // Show user-friendly error message
        let errorMessage = 'Failed to save credentials. ';
        
        // Check if it's an authentication error
        if (error.message && (error.message.includes('Session expired') || error.message.includes('Not authenticated') || error.message.includes('Authentication required'))) {
            errorMessage = 'Your session has expired. Please log in again to configure Allegro.';
            showLoginScreen();
        } else if (error.message && !error.message.includes('status code')) {
            errorMessage = error.message;
        } else {
            errorMessage += 'Please check your Client ID and Client Secret, and make sure you are logged in.';
        }
        
        showToast(errorMessage, 'error', 8000);
        hideMainInterface();
        updateUIState(false);
    } finally {
        // Update button state based on authentication status
        updateButtonStates();
    }
}

async function sendCredentialsToBackend(clientId, clientSecret) {
    try {
        const response = await authFetch(`${API_BASE}/api/credentials`, {
            method: 'POST',
            body: JSON.stringify({
                clientId: clientId,
                clientSecret: clientSecret
            })
        });
        
        // Check for 401 status before parsing JSON
        if (!response.ok && response.status === 401) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Authentication required. Please log in again.');
        }
        
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.error || 'Failed to save credentials');
        }
        
        return true;
    } catch (error) {
        throw error;
    }
}

// Show main interface
function showMainInterface() {
    const loginScreen = document.getElementById('loginScreen');
    const mainApp = document.getElementById('mainApp');
    if (loginScreen) {
        loginScreen.style.display = 'none';
    }
    if (mainApp) {
        mainApp.style.display = 'flex';
    }
}

// Hide main interface
function hideMainInterface() {
    // Always show main interface now - no modal
    // Keep function for compatibility
}

// Clear credentials
async function clearCredentials() {
    document.getElementById('clientId').value = '';
    const clientSecretInput = document.getElementById('clientSecret');
    if (clientSecretInput) {
        clientSecretInput.value = '';
        clientSecretInput.placeholder = 'Enter Allegro Client Secret';
        clientSecretInput.classList.remove('secret-saved');
    }
    // Credentials are stored in database, no need to clear localStorage
    
    const messageEl = document.getElementById('credentialsMessage');
    if (messageEl) {
        messageEl.style.display = 'none';
    }
    
    // Disconnect Allegro credentials (delete from database)
    try {
        const credentialsResponse = await authFetch(`${API_BASE}/api/credentials/disconnect`, {
            method: 'POST'
        });
        
        // Check for 401 status before parsing JSON
        if (!credentialsResponse.ok && credentialsResponse.status === 401) {
            // Session expired, will be handled by authFetch
            return;
        }
        
        const credentialsData = await credentialsResponse.json();
        if (credentialsData.success) {
            showToast('Allegro credentials disconnected successfully', 'success');
        } else {
            showToast('Error disconnecting Allegro credentials: ' + (credentialsData.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        console.error('Error disconnecting Allegro credentials:', error);
        showToast('Error disconnecting Allegro credentials: ' + error.message, 'error');
    }
    
    // Disconnect OAuth (clear tokens)
    try {
        const oauthResponse = await authFetch(`${API_BASE}/api/oauth/disconnect`, {
            method: 'POST'
        });
        
        // Check for 401 status before parsing JSON
        if (!oauthResponse.ok && oauthResponse.status === 401) {
            // Session expired, will be handled by authFetch
            return;
        }
        
        const oauthData = await oauthResponse.json();
        if (oauthData.success) {
            showToast('Allegro OAuth disconnected successfully', 'success');
        } else {
            showToast('Error disconnecting OAuth: ' + (oauthData.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        console.error('Error disconnecting OAuth:', error);
        showToast('Error disconnecting OAuth: ' + error.message, 'error');
    }
    
    updateUIState(false);
    
    // Hide main interface
    hideMainInterface();
    
    // Clear auth status
    const authStatusEl = document.getElementById('authStatus');
    const oauthStatusEl = document.getElementById('oauthStatus');
    if (authStatusEl) {
        authStatusEl.textContent = 'API Credentials: Pending';
        authStatusEl.className = 'quick-status-badge error';
        authStatusEl.title = 'Enter and save your Allegro Client ID and Client Secret';
    }
    if (oauthStatusEl) {
        oauthStatusEl.textContent = 'OAuth: Not Connected';
        oauthStatusEl.className = 'quick-status-badge error';
        oauthStatusEl.title = 'Click "Authorize Account" button to connect your Allegro account via OAuth';
    }
    isOAuthConnected = false;
    updateUIState(false);
    
    // Hide OAuth info
    const oauthInfoEl = document.getElementById('oauthInfo');
    if (oauthInfoEl) {
        oauthInfoEl.style.display = 'none';
    }
    
    // Update config status indicators to show "Not Configured" and update button states
    updateConfigStatuses();
    
    // Hide disconnect button and authorize button in Allegro API Configuration section
    const clearBtn = document.getElementById('clearCredentialsBtn');
    const authorizeBtn = document.getElementById('authorizeAccountBtn');
    if (clearBtn) {
        clearBtn.style.display = 'none';
    }
    if (authorizeBtn) {
        authorizeBtn.style.display = 'none';
    }
    
    // Check OAuth status to update UI
    await checkOAuthStatus();
    
}

// Clear PrestaShop configuration
async function clearPrestashopConfig() {
    // Clear input fields
    document.getElementById('prestashopUrl').value = '';
    const apiKeyInput = document.getElementById('prestashopApiKey');
    if (apiKeyInput) {
        apiKeyInput.value = '';
        apiKeyInput.placeholder = 'Enter PrestaShop API Key';
        apiKeyInput.classList.remove('secret-saved');
    }
    
    // Remove from localStorage
    // PrestaShop config is stored in database, no need to remove from localStorage
    
    // Clear message
    const messageEl = document.getElementById('prestashopMessage');
    if (messageEl) {
        messageEl.style.display = 'none';
    }
    
    // Reset configuration state
    prestashopConfigured = false;
    prestashopAuthorized = false;
    
    // Hide saved configuration info
    hidePrestashopSavedConfigDisplay();
    
    // Clear backend configuration and all JSON files (prestashop.json, credentials.json, tokens.json)
    try {
        const response = await authFetch(`${API_BASE}/api/prestashop/disconnect`, {
            method: 'POST'
        });
        
        // Check for 401 status before parsing JSON
        if (!response.ok && response.status === 401) {
            // Session expired, will be handled by authFetch
            return;
        }
        
        const data = await response.json();
        if (data.success) {
            showToast('PrestaShop disconnected successfully', 'success');
        } else {
            showToast('Error disconnecting PrestaShop: ' + (data.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        console.error('Error clearing PrestaShop configuration:', error);
        showToast('Error clearing configuration: ' + error.message, 'error');
    }
    
    // Update config status indicators and button states
    updateConfigStatuses();
    
    // Update UI state (only affects PrestaShop-related features)
    updateUIState(false);
    updateButtonStates();
    
    // Update sync category button state
    if (typeof updateSyncCategoryButtonState === 'function') {
        updateSyncCategoryButtonState();
    }
    
    // Hide main interface since credentials are cleared
    hideMainInterface();
}

// Check if user is authenticated
function checkAuthentication() {
    const authStatusEl = document.getElementById('authStatus');
    return authStatusEl && authStatusEl.className.includes('success') && authStatusEl.textContent.includes('API Credentials: Configured');
}

// Validate authentication before allowing actions
function validateAuth() {
    if (!checkAuthentication()) {
        const errorEl = document.getElementById('errorMessage');
        if (errorEl) {
            const errorContentEl = errorEl.querySelector('.error-message-content');
            if (errorContentEl) {
                errorContentEl.textContent = 'Authentication required. Please test connection first.';
            } else {
                errorEl.innerHTML = `<div class="error-message-content">Authentication required. Please test connection first.</div><button class="error-message-close" onclick="closeErrorMessage()" title="Close">×</button>`;
            }
            errorEl.style.display = 'flex';
            setTimeout(() => {
                closeErrorMessage();
            }, 5000);
        }
        return false;
    }
    return true;
}

// Update UI state based on credentials and authentication
function updateUIState(configured) {
    const importSelectedBtn = document.getElementById('importSelectedBtn');
    const selectedCategorySelect = document.getElementById('selectedCategory');
    
    // Disable all actions and inputs if not authenticated
    const authenticated = checkAuthentication();
    const authRequiredMessage = document.getElementById('authRequiredMessage');
    
    if (authRequiredMessage) {
        authRequiredMessage.style.display = authenticated ? 'none' : 'block';
    }
    
    const loadCategoriesBtn = document.getElementById('loadCategoriesBtn');
    const loadOffersBtn = document.getElementById('loadOffersBtn');
    
    if (selectedCategorySelect) {
        selectedCategorySelect.disabled = !authenticated;
    }
    
    // Disable Allegro Categories and Load Offers until PrestaShop is authorized
    if (loadOffersBtn) {
        // Disable Load Offers until OAuth is connected (Authorize Account)
        loadOffersBtn.disabled = !authenticated || !isOAuthConnected || !prestashopAuthorized;
        if (!isOAuthConnected && authenticated) {
            loadOffersBtn.title = 'Account authorization required. Please click "Authorize Account" first.';
        } else if (!prestashopAuthorized && authenticated) {
            loadOffersBtn.title = 'PrestaShop authorization required';
        } else if (!authenticated) {
            loadOffersBtn.title = 'Authentication required';
        } else {
            loadOffersBtn.title = '';
        }
    }
    
    if (importSelectedBtn) {
        const selectedCheckboxes = document.querySelectorAll('.offer-checkbox:checked');
        importSelectedBtn.disabled = !authenticated || selectedCheckboxes.length === 0;
        if (!authenticated) {
            importSelectedBtn.title = 'Authentication required';
        } else {
            importSelectedBtn.title = '';
        }
    }
    
    // Update sync category button state
    if (typeof updateSyncCategoryButtonState === 'function') {
        updateSyncCategoryButtonState();
    }
}

async function checkApiStatus() {
    try {
        const response = await authFetch(`${API_BASE}/api/health`);
        const data = await response.json();
        // Status is now shown in Allegro API Configuration panel
        updateConfigStatuses();
    } catch (error) {
        // Status is now shown in Allegro API Configuration panel
        updateConfigStatuses();
    }
}

// Check OAuth connection status
async function checkOAuthStatus() {
    try {
        const response = await authFetch(`${API_BASE}/api/oauth/status`);
        
        // Check for 401 status before parsing JSON
        if (!response.ok && response.status === 401) {
            // Session expired, will be handled by authFetch
            return;
        }
        
        const data = await response.json();
        
        const oauthStatusEl = document.getElementById('oauthStatus');
        const authorizeBtn = document.getElementById('authorizeAccountBtn');
        const oauthInfoEl = document.getElementById('oauthInfo');
        
        isOAuthConnected = data.connected || false;
        
        if (oauthStatusEl) {
            if (isOAuthConnected) {
                oauthStatusEl.textContent = 'OAuth: Connected';
                oauthStatusEl.className = 'quick-status-badge success';
                oauthStatusEl.title = 'Your Allegro account is connected via OAuth. The app can access your offers and products.';
            } else {
                oauthStatusEl.textContent = 'OAuth: Not Connected';
                oauthStatusEl.className = 'quick-status-badge error';
                oauthStatusEl.title = 'Click "Authorize Account" button below to connect your Allegro account via OAuth. This allows the app to access your offers and products.';
            }
        }
        
        // Display OAuth info if available
        if (oauthInfoEl) {
            if (isOAuthConnected && data.userId) {
                const expiresAt = data.expiresAt ? new Date(data.expiresAt) : null;
                const expiresText = expiresAt ? ` (expires: ${expiresAt.toLocaleString()})` : '';
                oauthInfoEl.innerHTML = `
                    <div style="margin-top: 10px; padding: 10px; background: #f5f5f5; border-radius: 4px; font-size: 12px;">
                        <strong>OAuth Info:</strong><br>
                        User ID: ${data.userId || 'N/A'}${expiresText}
                    </div>
                `;
                oauthInfoEl.style.display = 'block';
            } else {
                oauthInfoEl.style.display = 'none';
            }
        }
        
        // Show/hide authorize button based on authentication and OAuth status
        // Hide button when OAuth is connected, show only when disconnected
        if (authorizeBtn) {
            if (checkAuthentication()) {
                if (isOAuthConnected) {
                    // Hide button when OAuth is connected
                    authorizeBtn.style.display = 'none';
                } else {
                    // Show button with "Authorize Account" text when OAuth is not connected
                    authorizeBtn.style.display = 'block';
                    authorizeBtn.textContent = 'Authorize Account';
                    authorizeBtn.title = 'Click to authorize your Allegro account via OAuth';
                }
            } else {
                authorizeBtn.style.display = 'none';
            }
        }
        
        // Update UI state to refresh Load Offers button and other controls
        updateUIState(true);

        // When OAuth is connected, categories will be loaded by loadCategoriesFromOffers()
        // Don't load from cache here to avoid displaying stale data
        // Categories should only be displayed after fresh data is fetched

        // If everything is configured on this device, auto-load offers after refresh
        await autoLoadOffersIfReady();
    } catch (error) {
        console.error('Error checking OAuth status:', error);
        const oauthStatusEl = document.getElementById('oauthStatus');
        if (oauthStatusEl) {
            oauthStatusEl.textContent = 'OAuth: Error';
            oauthStatusEl.className = 'quick-status-badge error';
            oauthStatusEl.title = 'Error checking OAuth connection status';
        }
        const oauthInfoEl = document.getElementById('oauthInfo');
        if (oauthInfoEl) {
            oauthInfoEl.style.display = 'none';
        }
        // Update UI state even on error
        updateUIState(true);
    }
}

// Authorize account (OAuth flow)
async function authorizeAccount() {
    if (!checkAuthentication()) {
        showToast('Please enter and save your Client ID and Client Secret first, then click "Authorize Account"', 'error', 8000);
        return;
    }
    
    try {
        // Get OAuth authorization URL from backend (now requires authentication)
        const response = await authFetch(`${API_BASE}/api/oauth/authorize`);
        
        // Check for 401 status before parsing JSON
        if (!response.ok && response.status === 401) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Authentication required. Please log in again to connect your Allegro account.');
        }
        
        const data = await response.json();
        
        if (!data.success || !data.authUrl) {
            throw new Error(data.error || 'Failed to get authorization URL');
        }
        
        // Open OAuth authorization in a popup window using the URL from backend
        const width = 600;
        const height = 700;
        const left = (window.screen.width - width) / 2;
        const top = (window.screen.height - height) / 2;
        
        const popup = window.open(
            data.authUrl,
            'Allegro Authorization',
            `width=${width},height=${height},left=${left},top=${top},toolbar=no,menubar=no,scrollbars=yes,resizable=yes`
        );
        
        // Check if popup was blocked
        if (!popup) {
            showToast('Popup blocked. Please allow popups for this site and try again.', 'error');
            return;
        }
        
        // Poll for popup closure or check status periodically
        const checkInterval = setInterval(async () => {
            if (popup.closed) {
                clearInterval(checkInterval);
                // Check OAuth status after popup closes
                await checkOAuthStatus();
                // If connected, load categories from offers and refresh offers
                if (isOAuthConnected) {
                    showToast('Allegro account connected successfully! You can now sync offers and import products.', 'success');
                    // Load categories from user's offers (only categories with products)
                    await loadCategoriesFromOffers();
                    // Load full Allegro category tree for sidebar navigation
                    await loadCategoryTreeRoot(true);
                    // Refresh offers if already loaded
                    if (currentOffers.length > 0 || currentPageNumber > 1) {
                        await fetchOffers(currentOffset, currentLimit);
                    }
                    // Update UI state to enable Load Offers button
                    updateUIState(true);
                }
            }
        }, 500);
    } catch (error) {
        console.error('Error starting OAuth flow:', error);
        showToast('Failed to start authorization: ' + error.message, 'error');
    }
}

// Test authentication (kept for backward compatibility, but not used in main flow)
async function testAuthentication() {
    const authStatusEl = document.getElementById('authStatus');
    if (authStatusEl) {
        authStatusEl.textContent = 'API Credentials: Testing';
        authStatusEl.className = 'quick-status-badge pending';
        authStatusEl.title = 'Testing Allegro API credentials...';
    }
    
    const clientId = document.getElementById('clientId').value.trim();
    const clientSecret = document.getElementById('clientSecret').value.trim();
    
    if (!clientId || !clientSecret) {
        if (authStatusEl) {
            authStatusEl.textContent = 'API Credentials: Required';
            authStatusEl.className = 'quick-status-badge error';
            authStatusEl.title = 'Please enter your Allegro Client ID and Client Secret';
        }
        showToast('Credentials required', 'error');
        return;
    }
    
    // Ensure credentials are sent to backend
    try {
        await sendCredentialsToBackend(clientId, clientSecret);
    } catch (error) {
        if (authStatusEl) {
            authStatusEl.textContent = 'Allegro Auth: Error';
            authStatusEl.className = 'quick-status-badge error';
        }
        showToast('Failed to save credentials', 'error');
        return;
    }
    
    try {
        const response = await authFetch(`${API_BASE}/api/test-auth`);
        
        // Check for 401 status before parsing JSON
        if (!response.ok && response.status === 401) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Authentication required. Please log in again to test Allegro credentials.');
        }
        
        const data = await response.json();
        
        if (data.success) {
            if (authStatusEl) {
                authStatusEl.textContent = 'API Credentials: Configured';
                authStatusEl.className = 'quick-status-badge success';
                authStatusEl.title = 'Allegro API credentials are saved and working';
            }
            updateUIState(true);
            showToast('Allegro API credentials verified successfully. Ready to connect your account.', 'success');
            // Categories will be loaded automatically after OAuth authorization
        } else {
            if (authStatusEl) {
                authStatusEl.textContent = 'API Credentials: Failed';
                authStatusEl.className = 'quick-status-badge error';
                authStatusEl.title = 'API credentials test failed. Please check your Client ID and Client Secret';
            }
            updateUIState(false);
            showToast('Authentication failed. Please check your credentials.', 'error');
        }
    } catch (error) {
        if (authStatusEl) {
            authStatusEl.textContent = 'API Credentials: Error';
            authStatusEl.className = 'quick-status-badge error';
            authStatusEl.title = 'Error testing API credentials';
        }
        updateUIState(false);
        // Show user-friendly error message
        let errorMessage = 'Authentication failed. Please check your credentials.';
        if (error.message && !error.message.includes('status code')) {
            errorMessage = error.message;
        }
        showToast(errorMessage, 'error');
    }
}
// Handle product count change
async function handleProductCountChange() {
    return;
}

// Fetch all offers from API (loads all pages)
async function fetchAllOffers() {
    // Validate authentication status (credentials are configured if auth status shows "Configured")
    // Don't check input field value since secret is masked for security when loaded from DB
    if (!checkAuthentication()) {
        const errorEl = document.getElementById('errorMessage');
        if (errorEl) {
            const errorContentEl = errorEl.querySelector('.error-message-content');
            if (errorContentEl) {
                errorContentEl.textContent = 'Authentication required. Please configure your Client ID and Client Secret first.';
            } else {
                errorEl.innerHTML = `<div class="error-message-content">Authentication required. Please configure your Client ID and Client Secret first.</div><button class="error-message-close" onclick="closeErrorMessage()" title="Close">×</button>`;
            }
            errorEl.style.display = 'flex';
        }
        return;
    }
    
    // Check OAuth connection
    if (!isOAuthConnected) {
        const errorEl = document.getElementById('errorMessage');
        if (errorEl) {
            const errorContentEl = errorEl.querySelector('.error-message-content');
            if (errorContentEl) {
                errorContentEl.innerHTML = '<strong>OAuth Authorization Required</strong><br><br>Please click "Authorize Account" to connect your Allegro account. This is required to access your offers.';
            } else {
                errorEl.innerHTML = `<div class="error-message-content"><strong>OAuth Authorization Required</strong><br><br>Please click "Authorize Account" to connect your Allegro account. This is required to access your offers.</div><button class="error-message-close" onclick="closeErrorMessage()" title="Close">×</button>`;
            }
            errorEl.style.display = 'flex';
        }
        return;
    }
    
    const loadingEl = document.getElementById('loadingIndicator');
    const errorEl = document.getElementById('errorMessage');
    const offersListEl = document.getElementById('offersList');
    
    loadingEl.style.display = 'block';
    errorEl.style.display = 'none';
    offersListEl.innerHTML = '<div style="text-align: center; padding: 40px; color: #1a73e8;">Loading offers...</div>';
    
    try {
        let allOffers = [];
        let offset = 0;
        // Use moderate page size so first screen appears faster
        const limit = 200;
        let hasMore = true;
        let totalCountFromAPI = null;
        
        // Fetch all pages
        while (hasMore) {
            const params = new URLSearchParams();
            params.append('offset', offset);
            params.append('limit', limit);
            
            // Use authenticated fetch because /api/offers is protected by JWT authMiddleware
            const response = await authFetch(`${API_BASE}/api/offers?${params}`);
            
            // Check for 401 status before parsing JSON
            if (!response.ok && response.status === 401) {
                const errorData = await response.json().catch(() => ({}));
                const errorMsg = errorData.error || 'Invalid credentials. Please check your Client ID and Client Secret.';
                throw new Error(errorMsg);
            }
            
            // Check for 403 status (OAuth required)
            if (!response.ok && response.status === 403) {
                const errorData = await response.json().catch(() => ({}));
                if (errorData.requiresUserOAuth) {
                    throw new Error('OAuth authorization required. Please click "Authorize Account" to connect your Allegro account.');
                }
                const errorMsg = errorData.error || 'Access denied. Please authorize your account.';
                throw new Error(errorMsg);
            }
            
            const result = await response.json();
            
            if (result.success) {
                const offers = result.data.offers || [];
                allOffers = allOffers.concat(offers);
                
                // Get total count from first response
                if (totalCountFromAPI === null) {
                    totalCountFromAPI = result.data.totalCount || result.data.count || 0;
                }

                // After the first successful page, immediately show offers to the user
                // so the UI becomes responsive without waiting for all pages.
                if (offset === 0) {
                    // Store currently loaded offers
                    allLoadedOffers = allOffers;
                    totalCount = totalCountFromAPI || allOffers.length;

                    // By default, show all offers on first load (status and category filters
                    // are applied in displayOffersPage / category handlers)
                    currentOffers = allLoadedOffers;

                    // Reset pagination for the first visible page
                    currentOffset = 0;
                    currentPageNumber = 1;
                    pageHistory = [];
                    totalProductsSeen = 0;

                    // Render first page immediately
                    displayOffersPage();
                    updateImportButtons();
                }
                
                // Check if there are more offers to fetch
                if (offers.length < limit || (totalCountFromAPI > 0 && allOffers.length >= totalCountFromAPI)) {
                    hasMore = false;
                } else {
                    offset += limit;
                }
            } else {
                // Check if this is the OAuth requirement error
                if (result.requiresUserOAuth) {
                    // Show user-friendly message with action button
                    const errorContentEl = errorEl.querySelector('.error-message-content');
                    let errorMsg = result.error || 'User OAuth authentication required.';
                    if (result.instructions && Array.isArray(result.instructions) && result.instructions.length > 0) {
                        errorMsg += ' ' + result.instructions[0];
                    }
                    
                    if (errorContentEl) {
                        errorContentEl.innerHTML = `
                            <strong>Authorization Required</strong><br><br>
                            ${escapeHtml(errorMsg)}<br><br>
                            <button id="authorizeFromErrorBtn" class="btn btn-primary" style="margin-top: 10px;">Authorize Account</button>
                        `;
                        
                        // Add event listener to authorize button
                        setTimeout(() => {
                            const authorizeFromErrorBtn = document.getElementById('authorizeFromErrorBtn');
                            if (authorizeFromErrorBtn) {
                                authorizeFromErrorBtn.addEventListener('click', authorizeAccount);
                            }
                        }, 100);
                    } else {
                        errorEl.innerHTML = `
                            <div class="error-message-content">
                                <strong>Authorization Required</strong><br><br>
                                ${escapeHtml(errorMsg)}<br><br>
                                <button id="authorizeFromErrorBtn" class="btn btn-primary" style="margin-top: 10px;">Authorize Account</button>
                            </div>
                            <button class="error-message-close" onclick="closeErrorMessage()" title="Close">×</button>
                        `;
                        setTimeout(() => {
                            const authorizeFromErrorBtn = document.getElementById('authorizeFromErrorBtn');
                            if (authorizeFromErrorBtn) {
                                authorizeFromErrorBtn.addEventListener('click', authorizeAccount);
                            }
                        }, 100);
                    }
                    errorEl.style.display = 'flex';
                    return; // Don't throw error, just show the message
                }
                
                // Show the actual error message from the API
                const errorMsg = result.error || result.error?.message || 'Failed to fetch offers';
                throw new Error(errorMsg);
            }
        }
        
        // Store all loaded offers (including any loaded after the first page)
        allLoadedOffers = allOffers;
        totalCount = totalCountFromAPI || allOffers.length;
        
        // Always refresh currentOffers when the full dataset has been loaded so that
        // search & status filters work on ALL products, not just the first loaded page.
        // Keep the currently selected category in mind.
        if (allOffers.length > 0) {
            if (selectedCategoryId !== null) {
                currentOffers = allOffers.filter(offer => {
                    let offerCategoryId = null;
                    if (offer.category) {
                        if (typeof offer.category === 'string') {
                            offerCategoryId = offer.category;
                        } else if (offer.category.id) {
                            offerCategoryId = offer.category.id;
                        }
                    }
                    return offerCategoryId && String(offerCategoryId) === String(selectedCategoryId);
                });
            } else {
                currentOffers = allOffers;
            }
            
            // If we're still on the first page (typical during initial load),
            // ensure pagination state is consistent with the refreshed offers list.
            if (currentPageNumber === 1) {
                currentOffset = 0;
                pageHistory = [];
                totalProductsSeen = 0;
            }
        }
    } catch (error) {
        // Show detailed error message
        let errorMsg = error.message || 'Request failed';
        
        // If it's a network error, provide more context
        if (error.message === 'Failed to fetch' || error.message === 'NetworkError') {
            errorMsg = 'Network error: Could not connect to server. Please check your connection.';
        }
        
        // Format error message for display (preserve line breaks and make links clickable)
        let formattedMsg = errorMsg.split('\n').join('<br>');
        // Make URLs clickable
        formattedMsg = formattedMsg.replace(/(https?:\/\/[^\s]+)/g, '<a href="$1" target="_blank" rel="noopener noreferrer">$1</a>');
        
        // Update error message content in the content div
        const errorContentEl = errorEl.querySelector('.error-message-content');
        if (errorContentEl) {
            errorContentEl.innerHTML = `<strong>Failed to fetch offers:</strong><br><br>${formattedMsg}`;
        } else {
            // Fallback if structure is not updated
            errorEl.innerHTML = `<div class="error-message-content"><strong>Failed to fetch offers:</strong><br><br>${formattedMsg}</div><button class="error-message-close" onclick="closeErrorMessage()" title="Close">×</button>`;
        }
        errorEl.style.display = 'flex';
        
        // Show toast notification as well
        showToast('Unable to load your offers. Please check the error message below.', 'error', 8000);
    } finally {
        loadingEl.style.display = 'none';
    }
}

// Fetch offers from API (for pagination - single page)
// Note: Uses /sale/offers endpoint which returns only the authenticated user's own offers
// This endpoint uses offset-based pagination and doesn't require phrase or category
async function fetchOffers(offset = 0, limit = 20) {
    // If we have all offers loaded, just paginate through them
    if (allLoadedOffers.length > 0) {
        currentOffset = offset;
        currentPageNumber = Math.floor(offset / limit) + 1;
        displayOffersPage();
        return;
    }
    
    // Otherwise, fetch from API (shouldn't happen if Load My Offers was clicked)
    // This is kept for backward compatibility
    
    // Validate authentication status (credentials are configured if auth status shows "Configured")
    // Don't check input field value since secret is masked for security when loaded from DB
    if (!checkAuthentication()) {
        const errorEl = document.getElementById('errorMessage');
        if (errorEl) {
            const errorContentEl = errorEl.querySelector('.error-message-content');
            if (errorContentEl) {
                errorContentEl.textContent = 'Authentication required. Please configure your Client ID and Client Secret first.';
            } else {
                errorEl.innerHTML = `<div class="error-message-content">Authentication required. Please configure your Client ID and Client Secret first.</div><button class="error-message-close" onclick="closeErrorMessage()" title="Close">×</button>`;
            }
            errorEl.style.display = 'flex';
        }
        return;
    }
    
    // Check OAuth connection
    if (!isOAuthConnected) {
        const errorEl = document.getElementById('errorMessage');
        if (errorEl) {
            const errorContentEl = errorEl.querySelector('.error-message-content');
            if (errorContentEl) {
                errorContentEl.innerHTML = '<strong>OAuth Authorization Required</strong><br><br>Please click "Authorize Account" to connect your Allegro account. This is required to access your offers.';
            } else {
                errorEl.innerHTML = `<div class="error-message-content"><strong>OAuth Authorization Required</strong><br><br>Please click "Authorize Account" to connect your Allegro account. This is required to access your offers.</div><button class="error-message-close" onclick="closeErrorMessage()" title="Close">×</button>`;
            }
            errorEl.style.display = 'flex';
        }
        return;
    }
    
    const loadingEl = document.getElementById('loadingIndicator');
    const errorEl = document.getElementById('errorMessage');
    const offersListEl = document.getElementById('offersList');
    
    loadingEl.style.display = 'block';
    errorEl.style.display = 'none';
    offersListEl.innerHTML = '';
    
    try {
        const params = new URLSearchParams();
        
        // /sale/offers uses offset-based pagination
        params.append('offset', offset);
        params.append('limit', limit);
        
        // Use authenticated fetch because /api/offers is protected by JWT authMiddleware
        const response = await authFetch(`${API_BASE}/api/offers?${params}`);
        
        // Check for 401 status before parsing JSON
        if (!response.ok && response.status === 401) {
            const errorData = await response.json().catch(() => ({}));
            const errorMsg = errorData.error || 'Invalid credentials. Please check your Client ID and Client Secret.';
            throw new Error(errorMsg);
        }
        
        // Check for 403 status (OAuth required)
        if (!response.ok && response.status === 403) {
            const errorData = await response.json().catch(() => ({}));
            if (errorData.requiresUserOAuth) {
                throw new Error('OAuth authorization required. Please click "Authorize Account" to connect your Allegro account.');
            }
            const errorMsg = errorData.error || 'Access denied. Please authorize your account.';
            throw new Error(errorMsg);
        }
        
        const result = await response.json();
        
        if (result.success) {
            const pageOffers = result.data.offers || [];
            // Use totalCount from API if available, otherwise use count or current offers length
            totalCount = result.data.totalCount || result.data.count || 0;
            
            // Update current offset for pagination
            currentOffset = offset;
            currentLimit = limit;
            
            // Calculate total products seen (use totalCount if available, otherwise calculate)
            if (result.data.totalCount) {
                totalProductsSeen = Math.min(offset + pageOffers.length, result.data.totalCount);
            } else {
                totalProductsSeen = offset + pageOffers.length;
            }
            
            // If this is the first page, store all offers
            if (offset === 0) {
                allLoadedOffers = pageOffers;
            } else {
                // For subsequent pages, append to allLoadedOffers if not already there
                pageOffers.forEach(offer => {
                    if (!allLoadedOffers.find(o => o.id === offer.id)) {
                        allLoadedOffers.push(offer);
                    }
                });
            }
            
            // Apply category filter
            if (selectedCategoryId !== null) {
                currentOffers = allLoadedOffers.filter(offer => {
                    let offerCategoryId = null;
                    if (offer.category) {
                        if (typeof offer.category === 'string') {
                            offerCategoryId = offer.category;
                        } else if (offer.category.id) {
                            offerCategoryId = offer.category.id;
                        }
                    }
                    return offerCategoryId && String(offerCategoryId) === String(selectedCategoryId);
                });
            } else {
                currentOffers = allLoadedOffers;
            }
            
            // Display current page
            displayOffersPage();
            updateImportButtons();
        } else {
            // Check if this is the OAuth requirement error
            if (result.requiresUserOAuth) {
                // Show user-friendly message with action button
                const errorContentEl = errorEl.querySelector('.error-message-content');
                let errorMsg = result.error || 'User OAuth authentication required.';
                if (result.instructions && Array.isArray(result.instructions) && result.instructions.length > 0) {
                    errorMsg += ' ' + result.instructions[0];
                }
                
                if (errorContentEl) {
                    errorContentEl.innerHTML = `
                        <strong>Authorization Required</strong><br><br>
                        ${escapeHtml(errorMsg)}<br><br>
                        <button id="authorizeFromErrorBtn" class="btn btn-primary" style="margin-top: 10px;">Authorize Account</button>
                    `;
                    
                    // Add event listener to authorize button
                    setTimeout(() => {
                        const authorizeFromErrorBtn = document.getElementById('authorizeFromErrorBtn');
                        if (authorizeFromErrorBtn) {
                            authorizeFromErrorBtn.addEventListener('click', authorizeAccount);
                        }
                    }, 100);
                } else {
                    errorEl.innerHTML = `
                        <div class="error-message-content">
                            <strong>Authorization Required</strong><br><br>
                            ${escapeHtml(errorMsg)}<br><br>
                            <button id="authorizeFromErrorBtn" class="btn btn-primary" style="margin-top: 10px;">Authorize Account</button>
                        </div>
                        <button class="error-message-close" onclick="closeErrorMessage()" title="Close">×</button>
                    `;
                    setTimeout(() => {
                        const authorizeFromErrorBtn = document.getElementById('authorizeFromErrorBtn');
                        if (authorizeFromErrorBtn) {
                            authorizeFromErrorBtn.addEventListener('click', authorizeAccount);
                        }
                    }, 100);
                }
                errorEl.style.display = 'flex';
                return; // Don't throw error, just show the message
            }
            
            // Show the actual error message from the API
            const errorMsg = result.error || result.error?.message || 'Failed to fetch offers';
            throw new Error(errorMsg);
        }
    } catch (error) {
        // Show detailed error message
        let errorMsg = error.message || 'Request failed';
        
        // If it's a network error, provide more context
        if (error.message === 'Failed to fetch' || error.message === 'NetworkError') {
            errorMsg = 'Network error: Could not connect to server. Please check your connection.';
        }
        
        // Format error message for display (preserve line breaks and make links clickable)
        let formattedMsg = errorMsg.split('\n').join('<br>');
        // Make URLs clickable
        formattedMsg = formattedMsg.replace(/(https?:\/\/[^\s]+)/g, '<a href="$1" target="_blank" rel="noopener noreferrer">$1</a>');
        
        // Update error message content in the content div
        const errorContentEl = errorEl.querySelector('.error-message-content');
        if (errorContentEl) {
            errorContentEl.innerHTML = `<strong>Failed to fetch offers:</strong><br><br>${formattedMsg}`;
        } else {
            // Fallback if structure is not updated
            errorEl.innerHTML = `<div class="error-message-content"><strong>Failed to fetch offers:</strong><br><br>${formattedMsg}</div><button class="error-message-close" onclick="closeErrorMessage()" title="Close">×</button>`;
        }
        errorEl.style.display = 'flex';
        
        // Show toast notification as well
        showToast('Unable to load your offers. Please check the error message below.', 'error', 8000);
    } finally {
        loadingEl.style.display = 'none';
    }
}

// Display offers (for backward compatibility)
async function displayOffers(offers) {
    // Store all offers
    allLoadedOffers = offers;
    
    // Apply category filter if selected
    let filteredOffers = offers;
    if (selectedCategoryId !== null) {
        filteredOffers = offers.filter(offer => {
            let offerCategoryId = null;
            if (offer.category) {
                if (typeof offer.category === 'string') {
                    offerCategoryId = offer.category;
                } else if (offer.category.id) {
                    offerCategoryId = offer.category.id;
                }
            }
            return offerCategoryId && String(offerCategoryId) === String(selectedCategoryId);
        });
    }
    
    currentOffers = filteredOffers;
    totalCount = filteredOffers.length;
    
    // Reset pagination
    currentOffset = 0;
    currentPageNumber = 1;
    pageHistory = [];
    totalProductsSeen = 0;
    
    // Display first page
    displayOffersPage();
}

// Get offers filtered by current search phrase and status (ALL / ACTIVE / ENDED)
function getOffersFilteredByStatus() {
    let offers = currentOffers || [];

    // Apply client-side search by name / title / id / external id
    if (currentPhrase && typeof currentPhrase === 'string' && currentPhrase.trim() !== '') {
        const phrase = currentPhrase.trim().toLowerCase();
        offers = offers.filter(offer => {
            const name = (offer.name || offer.title || offer.product?.name || '').toLowerCase();
            const id = (offer.id || '').toString().toLowerCase();
            const externalId = (offer.external?.id || '').toString().toLowerCase();
            return (
                (name && name.includes(phrase)) ||
                (id && id.includes(phrase)) ||
                (externalId && externalId.includes(phrase))
            );
        });
    }

    // Apply status filter
    if (!currentStatusFilter || currentStatusFilter === 'ALL') {
        return offers;
    }
    
    return offers.filter(offer => {
        const status = offer?.publication?.status || null;
        if (!status) {
            // If there is no status, hide it when a specific filter is applied
            return false;
        }
        if (currentStatusFilter === 'ACTIVE') {
            return status === 'ACTIVE';
        }
        if (currentStatusFilter === 'ENDED') {
            return status === 'ENDED';
        }
        return true;
    });
}

// Display current page of offers
// Initialize automatic image rotation for products with multiple images
function initializeImageRotation() {
    // Clear any existing intervals
    if (window.imageRotationIntervals) {
        window.imageRotationIntervals.forEach(interval => clearInterval(interval));
        window.imageRotationIntervals = [];
    } else {
        window.imageRotationIntervals = [];
    }
    
    // Find all product cards with multiple images
    document.querySelectorAll('.offer-card[data-image-urls]').forEach(card => {
        const imageUrlsJson = card.getAttribute('data-image-urls');
        if (!imageUrlsJson) return;
        
        try {
            const imageUrls = JSON.parse(imageUrlsJson);
            if (imageUrls && Array.isArray(imageUrls) && imageUrls.length > 1) {
                const imgElement = card.querySelector('.offer-image');
                if (imgElement) {
                    // Start rotation for this product
                    startImageRotation(card, imageUrls, imgElement);
                }
            }
        } catch (e) {
            console.error('Error parsing image URLs:', e);
        }
    });
}

// Start image rotation for a specific product card
function startImageRotation(card, imageUrls, imgElement) {
    // Initialize imageRotationIntervals if it doesn't exist
    if (!window.imageRotationIntervals) {
        window.imageRotationIntervals = [];
    }
    
    // Clear any existing rotation for this card
    if (card.dataset.rotationInterval) {
        clearInterval(parseInt(card.dataset.rotationInterval));
    }
    
    let currentIndex = 0;
    
    // Function to rotate to next image
    const rotateImage = () => {
        if (!card.isConnected || !document.contains(card)) {
            if (card.dataset.rotationInterval) {
                clearInterval(parseInt(card.dataset.rotationInterval));
                delete card.dataset.rotationInterval;
            }
            return;
        }
        
        // Check if imgElement still exists
        const currentImg = card.querySelector('.offer-image') || card.querySelector('.imported-item-img');
        if (!currentImg) {
            if (card.dataset.rotationInterval) {
                clearInterval(parseInt(card.dataset.rotationInterval));
                delete card.dataset.rotationInterval;
            }
            return;
        }
        
        currentIndex = (currentIndex + 1) % imageUrls.length;
        const nextImageUrl = imageUrls[currentIndex];
        
        if (nextImageUrl && currentImg) {
            // Add fade effect
            currentImg.style.opacity = '0';
            
            setTimeout(() => {
                if (currentImg && card.isConnected) {
                    currentImg.src = nextImageUrl;
                    currentImg.setAttribute('data-current-image-index', currentIndex);
                    currentImg.style.opacity = '1';
                }
            }, 200); // Half of transition duration
        }
    };
    
    // Start rotation - change image every 3 seconds
    const interval = setInterval(rotateImage, 3000);
    window.imageRotationIntervals.push(interval);
    
    // Store interval reference on card for cleanup
    card.dataset.rotationInterval = interval.toString();
}

// Manual image navigation function
function navigateImage(event, productId, direction) {
    // Stop event propagation to prevent card click
    if (event) {
        event.stopPropagation();
    }
    
    // Find the card by product ID
    const card = document.querySelector(`[data-product-id="${productId}"], [data-offer-id="${productId}"]`);
    if (!card) return;
    
    // Get image URLs from card data attribute
    const imageUrlsJson = card.getAttribute('data-image-urls');
    if (!imageUrlsJson) return;
    
    try {
        const imageUrls = JSON.parse(imageUrlsJson);
        if (!imageUrls || imageUrls.length === 0) return;
        
        // Find the image element
        const imgElement = card.querySelector('.offer-image') || card.querySelector('.imported-item-img');
        if (!imgElement) return;
        
        // Get current index
        let currentIndex = parseInt(imgElement.getAttribute('data-current-image-index') || '0', 10);
        
        // Calculate new index
        if (direction === 'next') {
            currentIndex = (currentIndex + 1) % imageUrls.length;
        } else if (direction === 'prev') {
            currentIndex = (currentIndex - 1 + imageUrls.length) % imageUrls.length;
        }
        
        // Update image with fade effect
        imgElement.style.opacity = '0';
        
        setTimeout(() => {
            if (imgElement && card.isConnected) {
                imgElement.src = imageUrls[currentIndex];
                imgElement.setAttribute('data-current-image-index', currentIndex);
                imgElement.style.opacity = '1';
                
                // Reset auto-rotation timer (pause for 5 seconds after manual navigation)
                if (card.dataset.rotationInterval) {
                    clearInterval(parseInt(card.dataset.rotationInterval));
                    delete card.dataset.rotationInterval;
                    
                    // Restart rotation after 5 seconds
                    setTimeout(() => {
                        if (card.isConnected) {
                            const img = card.querySelector('.offer-image') || card.querySelector('.imported-item-img');
                            if (img) {
                                startImageRotation(card, imageUrls, img);
                            }
                        }
                    }, 5000);
                }
            }
        }, 200);
    } catch (e) {
        console.error('Error navigating image:', e);
    }
}

async function displayOffersPage() {
    const offersListEl = document.getElementById('offersList');
    
    // Apply status filter to all currently loaded offers
    const filteredOffers = getOffersFilteredByStatus();
    
    // Get offers for current page from filtered list
    const startIndex = currentOffset;
    const endIndex = Math.min(startIndex + currentLimit, filteredOffers.length);
    const pageOffers = filteredOffers.slice(startIndex, endIndex);
    
    // Update dashboard stats
    updateDashboardStats();
    
    if (pageOffers.length === 0) {
        if (selectedCategoryId !== null) {
            offersListEl.innerHTML = '<p style="text-align: center; padding: 40px; color: #1a73e8;">No product offers found in this category. Try selecting a different category or click "Load My Offers" to load products.</p>';
        } else {
            offersListEl.innerHTML = '<p style="text-align: center; padding: 40px; color: #1a73e8;">No product offers found. Click "Load My Offers" to load products.</p>';
        }
        updatePagination();
        return;
    }
    
    // Render cards first
    offersListEl.innerHTML = pageOffers.map(offer => createOfferCard(offer)).join('');
    
    // Add checkbox listeners
    document.querySelectorAll('.offer-checkbox').forEach(checkbox => {
        checkbox.addEventListener('change', updateImportButtons);
    });
    
    // Sync selected state for any pre-checked checkboxes
    updateImportButtons();
    updateSelectAllButtonState();
    
    // Make clicking on the product card toggle its checkbox (if present)
    document.querySelectorAll('.offer-card').forEach(card => {
        card.addEventListener('click', (event) => {
            // Don't handle clicks directly on checkboxes or other interactive controls
            if (event.target.closest('.offer-checkbox') || event.target.closest('button') || event.target.closest('a')) {
                return;
            }
            
            const checkbox = card.querySelector('.offer-checkbox');
            if (!checkbox) {
                return;
            }
            
            checkbox.checked = !checkbox.checked;
            // Update selected class immediately
            if (checkbox.checked) {
                card.classList.add('selected');
            } else {
                card.classList.remove('selected');
            }
            updateImportButtons();
        });
    });
    
    // Fetch full product details for products without images
    // This is done asynchronously to not block the UI
    // Fetch product details for all products to get descriptions and additional images
    // Limit to current page to avoid too many API calls
    const productsToFetch = pageOffers.slice(0, 30); // Fetch details for up to 30 products per page
    if (productsToFetch.length > 0) {
        console.log(`Fetching details for ${productsToFetch.length} products to get descriptions...`);
        // Fetch details in parallel (but limit concurrency to avoid overwhelming the API)
        // Use Promise.allSettled() so one failure doesn't block others
        const batchSize = 5;
        for (let i = 0; i < productsToFetch.length; i += batchSize) {
            const batch = productsToFetch.slice(i, i + batchSize);
            const results = await Promise.allSettled(batch.map(product => fetchProductDetails(product.id)));
            
            // Log any failures but continue processing
            results.forEach((result, index) => {
                if (result.status === 'rejected') {
                    console.error(`Failed to fetch details for product ${batch[index].id}:`, result.reason);
                }
            });
        }
    }
    
    // Initialize automatic image rotation for products with multiple images
    initializeImageRotation();
    
    updatePagination();
}

// Fetch full offer details including images and descriptions
// Only fetches details for offers that belong to the authenticated user
async function fetchProductDetails(offerId) {
    try {
        // Verify this offer is in the user's offers list before fetching
        // This prevents trying to fetch details for offers that don't belong to the user
        const isUserOffer = allLoadedOffers.some(offer => offer.id === offerId || offer.id?.toString() === offerId?.toString());
        if (!isUserOffer) {
            console.log(`Skipping offer ${offerId} - not found in user's offers list`);
            return;
        }
        
        // Use /api/products/{offerId} which uses /sale/product-offers/{offerId}
        // This endpoint only works for the user's own offers
        const response = await authFetch(`${API_BASE}/api/products/${offerId}`);
        let product = null;
        
        if (response.ok) {
            const result = await response.json();
            if (result.success && result.data) {
                product = result.data;
            }
        } else if (response.status === 403) {
            // Access denied - this offer doesn't belong to the user
            // Silently skip it (this is expected for offers not owned by the user)
            console.log(`Skipping offer ${offerId} - access denied (not your offer)`);
            return;
        } else {
            // For other errors, try the offers endpoint as fallback (only if it's a user offer)
            if (isUserOffer) {
                // Use authenticated fetch because /api/offers is protected by JWT authMiddleware
                const offerResponse = await authFetch(`${API_BASE}/api/offers/${offerId}`);
                if (offerResponse.ok) {
                    const offerResult = await offerResponse.json();
                    if (offerResult.success && offerResult.data) {
                        product = offerResult.data;
                    }
                }
            }
        }
        
        if (product) {
            const card = document.querySelector(`[data-product-id="${offerId}"]`);
            if (!card) return;
            
            // Extract description from offer/product details
            // New format: description.sections[].items[] where items can be TEXT (with content) or IMAGE (with url)
            let productDescription = '';
            let descriptionHtml = '';
            
            // Check for new format: description.sections[].items[]
            if (product.description && product.description.sections && Array.isArray(product.description.sections)) {
                // Process all sections and their items
                product.description.sections.forEach(section => {
                    if (section.items && Array.isArray(section.items)) {
                        section.items.forEach(item => {
                            if (item.type === 'TEXT' && item.content) {
                                // TEXT items contain HTML content
                                descriptionHtml += item.content;
                            } else if (item.type === 'IMAGE' && item.url) {
                                // IMAGE items in description - can be included as <img> tags
                                descriptionHtml += `<img src="${escapeHtml(item.url)}" alt="Product image" style="max-width: 100%; height: auto; margin: 10px 0;">`;
                            }
                        });
                    }
                });
                if (descriptionHtml) {
                    productDescription = descriptionHtml;
                }
            } else if (product.description && typeof product.description === 'string') {
                productDescription = product.description;
            } else if (product.descriptionHtml) {
                productDescription = product.descriptionHtml;
            } else if (product.product?.description) {
                productDescription = product.product.description;
            } else if (product.product?.descriptionHtml) {
                productDescription = product.product.descriptionHtml;
            } else if (product.details?.description) {
                productDescription = product.details.description;
            } else if (product.publication?.description) {
                productDescription = product.publication.description;
            } else if (product.sellingMode?.description) {
                productDescription = product.sellingMode.description;
            } else if (product.sections && Array.isArray(product.sections)) {
                // Some Allegro endpoints return description in sections array
                const descriptionSection = product.sections.find(s => 
                    s.type === 'DESCRIPTION' || 
                    s.type === 'TEXT' || 
                    s.type === 'description' ||
                    s.type === 'text'
                );
                if (descriptionSection) {
                    if (descriptionSection.items && Array.isArray(descriptionSection.items)) {
                        productDescription = descriptionSection.items
                            .map(item => item.content || item.text || item.html || '')
                            .filter(text => text.trim().length > 0)
                            .join('\n');
                    } else if (descriptionSection.content) {
                        productDescription = descriptionSection.content;
                    } else if (descriptionSection.text) {
                        productDescription = descriptionSection.text;
                    } else if (descriptionSection.html) {
                        productDescription = descriptionSection.html;
                    }
                }
            }
            
            // Update description in card if we found one and card doesn't already have it
            // Only process if we have a non-empty description
            if (productDescription) {
                // Helper function to strip HTML tags and get plain text preview
                function stripHtml(html) {
                    if (!html) return '';
                    if (typeof document !== 'undefined') {
                        try {
                            const tmp = document.createElement('DIV');
                            tmp.innerHTML = html;
                            return tmp.textContent || tmp.innerText || '';
                        } catch (e) {
                            // Fallback to regex if DOM method fails
                        }
                    }
                    return html.replace(/<[^>]*>/g, '').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').trim();
                }
                
                const fullTextDescription = stripHtml(productDescription).trim();
                const hasValidDescription = fullTextDescription.length > 0;
                
                if (hasValidDescription) { 
                    let existingDescription = card.querySelector('.offer-description');
                    const isHtmlDescription = productDescription.includes('<');
                    const descriptionPreview = fullTextDescription.substring(0, 30);
                    const hasMoreDescription = fullTextDescription.length > 30;
                    
                    if (!existingDescription) {
                        // Insert description at the end of the card to span full width
                        // Find the offer-content section and insert description after the entire card content
                        const offerContent = card.querySelector('.offer-content');
                        if (offerContent && offerContent.parentNode) {
                            const descriptionHtml = `
                                <div class="offer-description offer-description-full-width" data-product-id="${offerId}">
                                    <div class="offer-description-header">
                                        <strong>Description:</strong>
                                        ${hasMoreDescription ? `<button class="description-toggle-btn" onclick="toggleDescription('${offerId}')" data-expanded="false" title="Show more"><span class="toggle-icon">▼</span></button>` : ''}
                                    </div>
                                    ${hasMoreDescription ? `
                                        <div class="offer-description-preview">${escapeHtml(descriptionPreview)}...</div>
                                        <div class="offer-description-full" style="display: none;">
                                            ${isHtmlDescription ? productDescription : escapeHtml(productDescription)}
                                        </div>
                                    ` : `
                                        <div class="offer-description-preview ${isHtmlDescription ? 'offer-description-html' : ''}">
                                            ${isHtmlDescription ? productDescription : escapeHtml(productDescription)}
                                        </div>
                                    `}
                                </div>
                            `;
                            // Insert after the offer-content div, so it spans full card width
                            offerContent.insertAdjacentHTML('afterend', descriptionHtml);
                        }
                    } else {
                        // Update existing description with full HTML if we have it
                        const previewEl = existingDescription.querySelector('.offer-description-preview');
                        const fullEl = existingDescription.querySelector('.offer-description-full');
                        const toggleBtn = existingDescription.querySelector('.description-toggle-btn');
                        
                        if (previewEl && !fullEl) {
                            // No "full" version exists - update preview with full content
                            previewEl.className = `offer-description-preview ${isHtmlDescription ? 'offer-description-html' : ''}`;
                            previewEl.innerHTML = isHtmlDescription ? productDescription : escapeHtml(productDescription);
                        } else if (fullEl) {
                            // Update full description
                            fullEl.innerHTML = isHtmlDescription ? productDescription : escapeHtml(productDescription);
                            // Update preview if it exists
                            if (previewEl) {
                                previewEl.textContent = descriptionPreview + (hasMoreDescription ? '...' : '');
                            }
                        }
                    }
                }
            }
            
            // Extract ALL images from the product response
            // New format: images[] is an array of image URLs
            let imageUrls = [];
            let imageUrl = '';
            
            // Check images array first (new format from /sale/product-offers endpoint)
            if (product.images && Array.isArray(product.images)) {
                product.images.forEach(img => {
                    let imgUrl = '';
                    if (typeof img === 'string' && img.startsWith('http')) {
                        // Direct URL string
                        imgUrl = img;
                    } else if (typeof img === 'object' && img !== null) {
                        // Object with url property
                        imgUrl = img.url || img.uri || img.path || img.src || img.link || '';
                    }
                    if (imgUrl && !imageUrls.includes(imgUrl)) {
                        imageUrls.push(imgUrl);
                    }
                });
            }
            
            // Check primaryImage (fallback for older format)
            if (product.primaryImage && product.primaryImage.url) {
                const primaryUrl = product.primaryImage.url;
                if (!imageUrls.includes(primaryUrl)) {
                    imageUrls.unshift(primaryUrl); // Add to beginning
                }
            }
            
            // Set first image as main image
            if (imageUrls.length > 0) {
                imageUrl = imageUrls[0];
            }
            
            // Use all images (no limit for product-offers endpoint)
            const totalImageCount = imageUrls.length;
            
            // Update the card if we found an image
            if (imageUrl) {
                const imageWrapper = card.querySelector('.offer-image-wrapper');
                if (imageWrapper) {
                    // Store ALL image URLs in card data attribute for rotation
                    const imageUrlsJson = JSON.stringify(imageUrls);
                    card.setAttribute('data-image-urls', imageUrlsJson);
                    const productIdForImage = product.id || offerId || card.getAttribute('data-product-id');
                    
                    imageWrapper.innerHTML = `
                        <img src="${imageUrl}" alt="${escapeHtml(product.name || 'Product')}" class="offer-image ${totalImageCount > 1 ? 'offer-image-clickable' : ''}" 
                             loading="lazy"
                             data-current-image-index="0"
                             ${totalImageCount > 1 ? `onclick="navigateImage(event, '${productIdForImage}', 'next')" title="Click to see next image"` : ''}
                             onerror="this.onerror=null; this.style.display='none'; if(this.nextElementSibling) this.nextElementSibling.style.display='flex';">
                        ${totalImageCount > 0 ? `
                            <div class="offer-image-count-badge" title="${totalImageCount} image${totalImageCount > 1 ? 's' : ''} available from Allegro${totalImageCount > 1 ? ' - Click image to navigate' : ''}">
                                <span class="offer-image-count-icon">📷</span>
                                <span class="offer-image-count-number">${totalImageCount}</span>
                            </div>
                        ` : ''}
                        ${totalImageCount > 1 ? `
                            <button class="offer-image-nav-btn offer-image-nav-prev" onclick="navigateImage(event, '${productIdForImage}', 'prev')" title="Previous image">‹</button>
                            <button class="offer-image-nav-btn offer-image-nav-next" onclick="navigateImage(event, '${productIdForImage}', 'next')" title="Next image">›</button>
                        ` : ''}
                        <div class="offer-image-placeholder" style="display: none;">
                            <span>No Image</span>
                        </div>
                    `;
                    
                    // Initialize rotation if multiple images
                    if (totalImageCount > 1) {
                        const imgElement = imageWrapper.querySelector('.offer-image');
                        if (imgElement) {
                            startImageRotation(card, imageUrls, imgElement);
                        }
                    }
                }
            }
            
            // IMPORTANT: Update the offer in importedOffers array with full product data
            // This ensures that when exporting, we have the complete description and images
            const importedOfferIndex = importedOffers.findIndex(imp => imp.id === offerId || imp.id?.toString() === offerId?.toString());
            if (importedOfferIndex !== -1) {
                // Merge the full product data into the imported offer
                // Preserve existing fields but update with full product details
                const existingOffer = importedOffers[importedOfferIndex];
                importedOffers[importedOfferIndex] = {
                    ...existingOffer,
                    ...product,
                    // Ensure description structure is preserved
                    description: product.description || existingOffer.description,
                    // Ensure all images are included
                    images: product.images || existingOffer.images,
                    primaryImage: product.primaryImage || existingOffer.primaryImage,
                    // Store the full product object if available
                    product: product.product || product
                };
                // Save updated imported offers
                saveImportedOffers();
                console.log(`Updated imported offer ${offerId} with full product details (description and images)`);
            }
        }

        // Data is always loaded fresh from Allegro API, no localStorage caching
    } catch (error) {
        console.error(`Error fetching product details for ${offerId}:`, error);
    }
}

// Create offer card HTML (for products from /sale/products endpoint)
function createOfferCard(product) {
    // Count ALL available images from Allegro (same logic as backend)
    // According to Allegro API docs, images are in an array with url field: [{url: "..."}, {url: "..."}]
    let imageUrls = [];
    let mainImage = '';
    
    // Method 1: Check images array first (this is the primary source for multiple images)
    if (product.images && Array.isArray(product.images) && product.images.length > 0) {
        product.images.forEach(img => {
            let imgUrl = '';
            if (typeof img === 'object' && img !== null) {
                // Allegro API format: {url: "https://..."}
                imgUrl = img.url || img.uri || img.path || img.src || img.link || '';
            } else if (typeof img === 'string' && img.startsWith('http')) {
                imgUrl = img;
            }
            if (imgUrl && imgUrl.length > 0 && !imageUrls.includes(imgUrl)) {
                imageUrls.push(imgUrl);
            }
        });
        // Set mainImage to first image if available
        if (imageUrls.length > 0) {
            mainImage = imageUrls[0];
        }
    }
    
    // Method 2: Add primary image if it exists and isn't already in the array
    // Note: primaryImage.url might be the same as images[0].url, so we check for duplicates
    if (product.primaryImage && product.primaryImage.url) {
        const primaryImageUrl = product.primaryImage.url;
        if (!imageUrls.includes(primaryImageUrl)) {
            // Add primary image at the beginning if it's not already in the array
            imageUrls.unshift(primaryImageUrl);
            if (!mainImage) {
                mainImage = primaryImageUrl;
            }
        } else if (!mainImage) {
            // Use primary image as main if it's already in array but mainImage not set
            mainImage = primaryImageUrl;
        }
    }
    
    // Method 3: Check alternative image locations (fallback)
    const altImageFields = ['image', 'imageUrl', 'photo', 'thumbnail'];
    for (const field of altImageFields) {
        if (product[field] && typeof product[field] === 'string' && product[field].startsWith('http')) {
            if (!imageUrls.includes(product[field])) {
                imageUrls.push(product[field]);
            }
            if (!mainImage) {
                mainImage = product[field];
            }
        }
    }
    
    // Method 4: Check if images are in a nested structure (e.g. product.media.images)
    if (product.media && product.media.images && Array.isArray(product.media.images)) {
        product.media.images.forEach(img => {
            let imgUrl = '';
            if (typeof img === 'object' && img !== null) {
                imgUrl = img.url || img.uri || img.path || img.src || '';
            } else if (typeof img === 'string' && img.startsWith('http')) {
                imgUrl = img;
            }
            if (imgUrl && imgUrl.length > 0 && !imageUrls.includes(imgUrl)) {
                imageUrls.push(imgUrl);
            }
        });
        if (!mainImage && imageUrls.length > 0) {
            mainImage = imageUrls[0];
        }
    }
    
    // Count total images (limit to 5 as per backend logic)
    const totalImageCount = Math.min(imageUrls.length, 5);

    // Extract badges from product data
    const badges = [];
    
    // Check for SMART badge (common Allegro badge)
    if (product.promotions?.smart || product.smart || product.badges?.smart) {
        badges.push('SMART');
    }
    
    // Check for SUPER PRICE badge
    if (product.promotions?.superPrice || product.superPrice || product.badges?.superPrice) {
        badges.push('SUPER PRICE');
    }
    
    // Check for lowest price guarantee
    if (product.promotions?.lowestPrice || product.lowestPrice || product.badges?.lowestPrice) {
        badges.push('LOWEST PRICE');
    }
    
    // Add publication status as badge
    if (product.publication?.status) {
        const status = product.publication.status;
        if (status === 'ACTIVE') {
            badges.push('ACTIVE');
        } else if (status === 'INACTIVE') {
            badges.push('INACTIVE');
        } else if (status === 'ENDED') {
            badges.push('ENDED');
        }
    }

    // Determine status badge (ACTIVE / ENDED / INACTIVE)
    let statusBadge = '';
    if (Array.isArray(badges) && badges.length > 0) {
        if (badges.includes('ACTIVE')) {
            statusBadge = 'ACTIVE';
        } else if (badges.includes('ENDED')) {
            statusBadge = 'ENDED';
        } else if (badges.includes('INACTIVE')) {
            statusBadge = 'INACTIVE';
        }
    }
    
    // Product ID
    const productId = product.id || 'N/A';
    
    // Category ID and Name
    // Check multiple possible category structures
    let categoryId = 'N/A';
    let categoryIdFound = false;
    
    if (product.category) {
        if (typeof product.category === 'string') {
            categoryId = product.category;
            categoryIdFound = true;
        } else if (product.category.id) {
            categoryId = product.category.id;
            categoryIdFound = true;
        }
    }
    
    // Also check product.category if category is not at root level
    if (!categoryIdFound && product.product?.category) {
        if (typeof product.product.category === 'string') {
            categoryId = product.product.category;
            categoryIdFound = true;
        } else if (product.product.category.id) {
            categoryId = product.product.category.id;
            categoryIdFound = true;
        }
    }
    
    // Get category name - check multiple sources
    let categoryName = 'N/A';
    
    // First, check if category name is directly available in product.category
    if (product.category?.name) {
        categoryName = product.category.name;
    }
    // Second, check cache
    else if (categoryId !== 'N/A' && categoryNameCache[categoryId]) {
        categoryName = categoryNameCache[categoryId];
    }
    // Third, try to find category name from allCategories array
    else if (categoryId !== 'N/A' && allCategories && allCategories.length > 0) {
        // Try exact match first
        let category = allCategories.find(cat => {
            const catId = cat.id;
            const prodCatId = categoryId;
            return catId === prodCatId || 
                   String(catId) === String(prodCatId) ||
                   catId === String(prodCatId) ||
                   String(catId) === prodCatId;
        });
        
        if (category && category.name) {
            categoryName = category.name;
            // Cache it
            categoryNameCache[categoryId] = categoryName;
        } else {
            // Try to fetch category name from API asynchronously
            fetchCategoryName(categoryId).then(name => {
                if (name && name !== 'N/A') {
                    categoryNameCache[categoryId] = name;
                    // Update the card if it's still visible
                    const card = document.querySelector(`[data-product-id="${offerId}"]`);
                    if (card) {
                        const categoryEl = card.querySelector('.offer-category');
                        if (categoryEl) {
                            categoryEl.textContent = `CATEGORY: ${name}`;
                        }
                    }
                }
            }).catch(err => {
                console.log(`Failed to fetch category name for ID ${categoryId}:`, err);
            });
        }
    }
    
    // Fallback: if category name still not found and we have a selected category, use that
    if (categoryName === 'N/A' && selectedCategoryId && allCategories && allCategories.length > 0) {
        const selectedCategory = allCategories.find(cat => {
            const catId = cat.id;
            const selCatId = selectedCategoryId;
            return catId === selCatId || 
                   String(catId) === String(selCatId) ||
                   catId === String(selCatId) ||
                   String(catId) === selCatId;
        });
        if (selectedCategory && selectedCategory.name) {
            categoryName = selectedCategory.name;
            categoryNameCache[categoryId] = categoryName;
        }
    }
    
    // Product name
    const productName = product.name || 'Untitled Product';
    
    // Extract real data from product object
    // Check for pricing information (products may not have prices directly)
    let currentPrice = null;
    let originalPrice = null;
    let discountPercent = 0;
    let hasDiscount = false;
    
    // Check various possible price fields
    if (product.price) {
        currentPrice = product.price.amount || product.price.value || product.price;
        if (product.price.originalAmount || product.price.originalValue) {
            originalPrice = product.price.originalAmount || product.price.originalValue;
            hasDiscount = true;
            if (originalPrice && currentPrice) {
                discountPercent = Math.round(((originalPrice - currentPrice) / originalPrice) * 100);
            }
        }
    } else if (product.sellingMode?.price) {
        currentPrice = product.sellingMode.price.amount || product.sellingMode.price.value;
        if (product.sellingMode.price.originalAmount || product.sellingMode.price.originalValue) {
            originalPrice = product.sellingMode.price.originalAmount || product.sellingMode.price.originalValue;
            hasDiscount = true;
            if (originalPrice && currentPrice) {
                discountPercent = Math.round(((originalPrice - currentPrice) / originalPrice) * 100);
            }
        }
    }
    
    // Format prices if available
    const formattedCurrentPrice = currentPrice ? parseFloat(currentPrice).toFixed(2) : null;
    const formattedOriginalPrice = originalPrice ? parseFloat(originalPrice).toFixed(2) : null;
    
    // Extract delivery information
    let deliveryInfo = null;
    if (product.delivery) {
        if (product.delivery.shippingRates) {
            const shippingRate = product.delivery.shippingRates;
            if (typeof shippingRate === 'object' && shippingRate !== null) {
                // shippingRates might be an object with id, not an array
                if (shippingRate.time) {
                    deliveryInfo = shippingRate.time;
                }
            } else if (Array.isArray(product.delivery.shippingRates) && product.delivery.shippingRates.length > 0) {
                const firstRate = product.delivery.shippingRates[0];
                if (firstRate?.time) {
                    deliveryInfo = firstRate.time;
                }
            }
        }
        if (!deliveryInfo && product.delivery.time) {
            deliveryInfo = product.delivery.time;
        }
    }
    
    // Extract payment information
    let paymentInfo = null;
    if (product.payment) {
        if (product.payment.payLater) {
            paymentInfo = 'pay later with PAY';
        } else if (product.payment.methods) {
            const hasPayLater = product.payment.methods.some(m => m === 'PAY_LATER' || m === 'pay_later');
            if (hasPayLater) {
                paymentInfo = 'pay later with PAY';
            }
        }
    }
    
    // Extract stock information
    let stockInfo = null;
    let stockAvailable = null;
    let stockSold = null;
    if (product.stock) {
        stockAvailable = typeof product.stock.available === 'number' ? product.stock.available : (product.stock.available || 0);
        stockSold = typeof product.stock.sold === 'number' ? product.stock.sold : (product.stock.sold || 0);
        if (stockAvailable > 0 || stockSold > 0) {
            stockInfo = {
                available: stockAvailable,
                sold: stockSold
            };
        } 
    }
    
    // Extract stats information (watchers & visits)
    let statsInfo = null;
    let watchersCount = null;
    let visitsCount = null;
    if (product.stats) {
        const watchers = product.stats.watchersCount;
        const visits = product.stats.visitsCount;
        watchersCount = typeof watchers === 'number' ? watchers : (watchers || 0);
        visitsCount = typeof visits === 'number' ? visits : (visits || 0);
        const statsParts = [];
        if (watchersCount > 0) {
            statsParts.push(`${watchersCount} watcher${watchersCount !== 1 ? 's' : ''}`);
        }
        if (visitsCount > 0) {
            statsParts.push(`${visitsCount} visit${visitsCount !== 1 ? 's' : ''}`);
        }
        if (statsParts.length > 0) {
            statsInfo = statsParts.join(', ');
        }
    }
    
    // Store image URLs in JSON format for rotation (limit to 5)
    const imageUrlsJson = JSON.stringify(imageUrls.slice(0, 5));
    
    // Extract description from product
    // Check multiple possible locations where Allegro API might store descriptions
    let productDescription = '';
    if (product.description) {
        productDescription = product.description;
    } else if (product.descriptionHtml) {
        productDescription = product.descriptionHtml;
    } else if (product.product?.description) {
        productDescription = product.product.description;
    } else if (product.product?.descriptionHtml) {
        productDescription = product.product.descriptionHtml;
    } else if (product.details?.description) {
        productDescription = product.details.description;
    } else if (product.publication?.description) {
        productDescription = product.publication.description;
    } else if (product.sellingMode?.description) {
        productDescription = product.sellingMode.description;
    } else if (product.sections && Array.isArray(product.sections)) {
        // Some Allegro endpoints return description in sections array
        const descriptionSection = product.sections.find(s => 
            s.type === 'DESCRIPTION' || 
            s.type === 'TEXT' || 
            s.type === 'description' ||
            s.type === 'text'
        );
        if (descriptionSection) {
            if (descriptionSection.items && Array.isArray(descriptionSection.items)) {
                productDescription = descriptionSection.items
                    .map(item => item.content || item.text || item.html || '')
                    .filter(text => text.trim().length > 0)
                    .join('\n');
            } else if (descriptionSection.content) {
                productDescription = descriptionSection.content;
            } else if (descriptionSection.text) {
                productDescription = descriptionSection.text;
            } else if (descriptionSection.html) {
                productDescription = descriptionSection.html;
            }
        }
    }
    
    // Helper function to strip HTML tags and get plain text preview
    function stripHtml(html) {
        if (!html) return '';
        // Use DOM method if available (more reliable)
        if (typeof document !== 'undefined') {
            try {
                const tmp = document.createElement('DIV');
                tmp.innerHTML = html;
                return tmp.textContent || tmp.innerText || '';
            } catch (e) {
                // Fallback to regex if DOM method fails
            }
        }
        // Fallback: simple regex to remove HTML tags
        return html.replace(/<[^>]*>/g, '').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').trim();
    }
    
    // Get a preview of the description (first 30 characters)
    // Only process if we have a non-empty description
    const fullTextDescription = productDescription ? stripHtml(productDescription).trim() : '';
    const hasValidDescription = fullTextDescription.length > 0;
    const descriptionPreview = hasValidDescription ? fullTextDescription.substring(0, 30) : '';
    const hasMoreDescription = fullTextDescription.length > 30;
    const isHtmlDescription = productDescription && productDescription.includes('<');
    
    return `
        <div class="offer-card" data-product-id="${productId}" data-image-urls='${imageUrlsJson}'>
            <div class="offer-left-column">
                ${statusBadge ? `
                    <div class="offer-status-badge ${
                        statusBadge === 'ACTIVE' ? 'offer-status-active' : 
                        (statusBadge === 'ENDED' ? 'offer-status-ended' : 'offer-status-inactive')
                    }">
                        ${statusBadge}
                    </div>
                ` : ''}
                <div class="offer-image-wrapper">
                    ${mainImage ? `
                        <img src="${mainImage}" alt="${escapeHtml(productName)}" class="offer-image ${totalImageCount > 1 ? 'offer-image-clickable' : ''}" 
                             loading="lazy"
                             data-current-image-index="0"
                             ${totalImageCount > 1 ? `onclick="navigateImage(event, '${productId}', 'next')" title="Click to see next image"` : ''}
                             onerror="this.onerror=null; this.style.display='none'; if(this.nextElementSibling) this.nextElementSibling.style.display='flex';">
                        ${totalImageCount > 0 ? `
                            <div class="offer-image-count-badge" title="${totalImageCount} image${totalImageCount > 1 ? 's' : ''} available from Allegro${totalImageCount > 1 ? ' - Click image to navigate' : ''}">
                                <span class="offer-image-count-icon">📷</span>
                                <span class="offer-image-count-number">${totalImageCount}</span>
                            </div>
                        ` : ''}
                        ${totalImageCount > 1 ? `
                            <button class="offer-image-nav-btn offer-image-nav-prev" onclick="navigateImage(event, '${productId}', 'prev')" title="Previous image">‹</button>
                            <button class="offer-image-nav-btn offer-image-nav-next" onclick="navigateImage(event, '${productId}', 'next')" title="Next image">›</button>
                        ` : ''}
                        <div class="offer-image-placeholder" style="display: none;">
                            <span>No Image</span>
                        </div>
                    ` : `
                        <div class="offer-image-placeholder">
                            <span>No Image</span>
                        </div>
                    `}
                </div>
                ${(watchersCount > 0 || visitsCount > 0 || stockInfo) ? `
                    <div class="offer-metrics offer-metrics-left">
                        ${watchersCount > 0 ? `
                            <div class="metric metric-watchers" title="People watching this offer">
                                <span class="metric-icon metric-icon-watchers">★</span>
                                <span class="metric-value">${watchersCount}</span>
                            </div>
                        ` : ''}
                        ${visitsCount > 0 ? `
                            <div class="metric metric-visits" title="Listing visits">
                                <span class="metric-icon metric-icon-visits">👁</span>
                                <span class="metric-value">${visitsCount}</span>
                            </div>
                        ` : ''}
                        ${stockInfo ? `
                            <div class="metric metric-stock" title="Current stock">
                                <span class="metric-icon metric-icon-stock">📦</span>
                                <span class="metric-value">${stockInfo.available}</span>
                                ${stockInfo.sold > 0 ? `<span class="metric-sub">(${stockInfo.sold} sold)</span>` : ''}
                            </div>
                        ` : ''}
                    </div>
                ` : ''}
            </div>
            <div class="offer-content">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 4px;">
                    <div style="flex: 1; display: flex; flex-wrap: wrap; gap: 4px; align-items: center;">
                        ${badges.length > 0 ? badges.map(badge => {
                            if (badge === 'SMART') {
                                return `<span class="offer-badge badge-smart">${badge}</span>`;
                            } else if (badge === 'SUPER PRICE') {
                                return `<span class="offer-badge badge-super-price">${badge}</span>`;
                            } else if (badge === 'LOWEST PRICE') {
                                return `<span class="badge-lowest-price">Lowest price guarantee</span>`;
                            }
                            return '';
                        }).join('') : '<span class="no-data-text">none yet</span>'}
                    </div>
                    <div style="display: flex; flex-direction: column; align-items: flex-end; gap: 2px;">
                        ${formattedCurrentPrice ? `
                            ${hasDiscount && formattedOriginalPrice ? `
                                <div class="price-row" style="justify-content: flex-end; margin-bottom: 2px;">
                                    <span class="discount-badge">-${discountPercent}%</span>
                                    <span class="original-price">${formattedOriginalPrice} PLN</span>
                                </div>
                                <div class="price-info" style="justify-content: flex-end; margin-bottom: 2px;">
                                    <span class="price-info-icon" title="30-day price history">i</span>
                                    <span>30-day price</span>
                                </div>
                            ` : ''}
                            <div class="price-row" style="justify-content: flex-end;">
                                <span class="current-price">${formattedCurrentPrice}</span>
                                <span class="price-currency">PLN</span>
                                ${badges.includes('SMART') ? `<span class="offer-badge badge-smart" style="margin-left: 4px;">SMART</span>` : ''}
                            </div>
                        ` : `
                            <div class="price-row" style="justify-content: flex-end;">
                                <input type="checkbox" class="offer-checkbox" data-product-id="${productId}" style="margin-right: 4px;">
                                <span class="price-note">See offers for price</span>
                            </div>
                        `}
                    </div>
                </div>
                
                <div class="offer-header">
                    <h3 class="offer-title">${escapeHtml(productName)}</h3>
                    ${!formattedCurrentPrice ? '' : `<input type="checkbox" class="offer-checkbox" data-product-id="${productId}">`}
                </div>
                
                <div class="offer-details">
                    ${paymentInfo ? `
                        <div class="payment-info">
                            <span>pay later with</span>
                            <span class="pay-badge">PAY</span>
                        </div>
                    ` : ''}
                    ${deliveryInfo ? `
                        <div class="delivery-info">
                            <span>${deliveryInfo}</span>
                            <span class="delivery-info-icon" title="Delivery details">i</span>
                        </div>
                    ` : ''}
                    ${!paymentInfo && !deliveryInfo && !stockInfo && !statsInfo ? '<div class="no-data-text">none yet</div>' : ''}
                </div>
                
                <div class="offer-info">
                    <div class="offer-info-row">
                        <span class="info-label">Product ID:</span>
                        <span class="info-value product-id">${productId.substring(0, 8)}...</span>
                    </div>
                    <div class="offer-info-row">
                        <span class="info-label">Category:</span>
                        <span class="info-value category-id">${escapeHtml(categoryName)}</span>
                    </div>
                </div>
            </div>
            ${hasValidDescription ? `
                <div class="offer-description offer-description-full-width" data-product-id="${productId}">
                    <div class="offer-description-header">
                        <strong>Description:</strong>
                        ${hasMoreDescription ? `<button class="description-toggle-btn" onclick="toggleDescription('${productId}')" data-expanded="false" title="Show more"><span class="toggle-icon">▼</span></button>` : ''}
                    </div>
                    <div class="offer-description-preview">${escapeHtml(descriptionPreview)}${hasMoreDescription ? '...' : ''}</div>
                    ${hasMoreDescription ? `
                        <div class="offer-description-full" style="display: none;">
                            ${isHtmlDescription ? productDescription : escapeHtml(productDescription)}
                        </div>
                    ` : ''}
                </div>
            ` : ''}
        </div>
    `;
}

// Toggle description visibility
function toggleDescription(productId) {
    const descriptionEl = document.querySelector(`.offer-description[data-product-id="${productId}"]`);
    if (!descriptionEl) return;
    
    const previewEl = descriptionEl.querySelector('.offer-description-preview');
    const fullEl = descriptionEl.querySelector('.offer-description-full');
    const toggleBtn = descriptionEl.querySelector('.description-toggle-btn');
    
    if (!fullEl || !toggleBtn) return;
    
    const isExpanded = toggleBtn.dataset.expanded === 'true';
    
    if (isExpanded) {
        previewEl.style.display = 'block';
        fullEl.style.display = 'none';
        toggleBtn.innerHTML = '<span class="toggle-icon">▼</span>';
        toggleBtn.title = 'Show more';
        toggleBtn.dataset.expanded = 'false';
    } else {
        previewEl.style.display = 'none';
        fullEl.style.display = 'block';
        toggleBtn.innerHTML = '<span class="toggle-icon">▲</span>';
        toggleBtn.title = 'Show less';
        toggleBtn.dataset.expanded = 'true';
    }
}

// Update pagination
function updatePagination() {
    const paginationEl = document.getElementById('pagination');
    const pageInfoEl = document.getElementById('pageInfo');
    const totalCountInfoEl = document.getElementById('totalCountInfo');
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const pageJumpInput = document.getElementById('pageJumpInput');
    
    // Work with status-filtered offers for pagination
    const filteredOffers = getOffersFilteredByStatus();
    
    if (filteredOffers.length === 0 && currentPageNumber === 1) {
        paginationEl.style.display = 'none';
        return;
    }
    
    paginationEl.style.display = 'flex';
    
    // Calculate max page number based on filtered offers
    let maxPage = 1;
    if (filteredOffers.length > 0 && currentLimit > 0) {
        maxPage = Math.ceil(filteredOffers.length / currentLimit);
    }
    
    // Update page jump input
    if (pageJumpInput) {
        pageJumpInput.value = currentPageNumber;
        pageJumpInput.max = maxPage;
        pageJumpInput.min = 1;
    }
    
    // Calculate current page offers count
    const startIndex = currentOffset;
    const endIndex = Math.min(startIndex + currentLimit, filteredOffers.length);
    const pageOffersCount = endIndex - startIndex;
    
    // Check if there are more pages
    const hasMorePages = currentOffset + currentLimit < filteredOffers.length;
    
    let pageInfoText = `Page ${currentPageNumber}`;
    if (maxPage > 1) {
        pageInfoText += ` of ${maxPage}`;
    }
    
    if (pageOffersCount > 0) {
        pageInfoText += ` (${pageOffersCount} offer${pageOffersCount !== 1 ? 's' : ''} on this page)`;
    }
    
    pageInfoEl.textContent = pageInfoText;
    
    // Show total count info
    if (totalCountInfoEl) {
        totalCountInfoEl.textContent = `Total: ${filteredOffers.length} offer${filteredOffers.length !== 1 ? 's' : ''}`;
    }
    
    // Prev button: enabled if not on first page
    prevBtn.disabled = currentPageNumber === 1;
    
    // Next button: enabled if there are more pages
    nextBtn.disabled = !hasMorePages;
}

// Change page (offset-based pagination)
async function changePage(direction) {
    if (direction === 1) {
        // Next page: increment offset
        // Save current page to history for going back
        pageHistory.push({
            offset: currentOffset,
            pageNumber: currentPageNumber
        });
        
        // Increment page number and offset
        currentPageNumber++;
        currentOffset += currentLimit;
        
        // Display the page (no need to fetch if we have all offers loaded)
        displayOffersPage();
    } else if (direction === -1) {
        // Previous page: go back in history
        if (pageHistory.length === 0 || currentPageNumber === 1) {
            // Reset to first page
            pageHistory = [];
            currentOffset = 0;
            currentPageNumber = 1;
            totalProductsSeen = 0;
            displayOffersPage();
        } else {
            // Go back to previous page from history
            const previousPage = pageHistory.pop();
            currentOffset = previousPage.offset;
            currentPageNumber = previousPage.pageNumber;
            totalProductsSeen = currentOffset;
            displayOffersPage();
        }
    }
}

// Jump to specific page
async function jumpToPage() {
    const pageJumpInput = document.getElementById('pageJumpInput');
    if (!pageJumpInput) return;
    
    const targetPage = parseInt(pageJumpInput.value, 10);
    if (isNaN(targetPage) || targetPage < 1) {
        showToast('Please enter a valid page number', 'error');
        return;
    }
    
    // Calculate max page based on filtered (status) offers
    const filteredOffers = getOffersFilteredByStatus();
    let maxPage = 1;
    if (filteredOffers.length > 0 && currentLimit > 0) {
        maxPage = Math.ceil(filteredOffers.length / currentLimit);
    }
    
    if (targetPage > maxPage) {
        showToast(`Page ${targetPage} does not exist. Maximum page is ${maxPage}.`, 'error');
        pageJumpInput.value = currentPageNumber;
        return;
    }
    
    // Calculate offset for target page
    const targetOffset = (targetPage - 1) * currentLimit;
    
    // Clear history and set new values
    pageHistory = [];
    currentPageNumber = targetPage;
    currentOffset = targetOffset;
    totalProductsSeen = targetOffset;
    
    // Display the page (no need to fetch if we have all offers loaded)
    displayOffersPage();
}

// Update import buttons state
function updateImportButtons() {
    const selectedCheckboxes = document.querySelectorAll('.offer-checkbox:checked');
    const importSelectedBtn = document.getElementById('importSelectedBtn');
    const authenticated = checkAuthentication();
    
    // Update selected class on all offer cards based on checkbox state
    document.querySelectorAll('.offer-card').forEach(card => {
        const checkbox = card.querySelector('.offer-checkbox');
        if (checkbox) {
            if (checkbox.checked) {
                card.classList.add('selected');
            } else {
                card.classList.remove('selected');
            }
        }
    });
    
    if (importSelectedBtn) {
        importSelectedBtn.disabled = !authenticated || selectedCheckboxes.length === 0;
    }

    // Keep Select All / Deselect All button label in sync with current state
    updateSelectAllButtonState();
}

// Update Select All button visibility based on current page checkboxes
function updateSelectAllButtonState() {
    const selectAllBtn = document.getElementById('selectAllOffersBtn');
    if (!selectAllBtn) return;

    const checkboxes = document.querySelectorAll('#offersList .offer-checkbox');
    if (checkboxes.length === 0) {
        selectAllBtn.style.display = 'none';
        return;
    }

    selectAllBtn.style.display = 'inline-block';
    selectAllBtn.textContent = 'Select All';
    selectAllBtn.title = 'Select all offers on this page';
}

// Select all offers on the current page
function selectAllOffersOnPage() {
    const checkboxes = document.querySelectorAll('#offersList .offer-checkbox');
    if (checkboxes.length === 0) {
        return;
    }

    checkboxes.forEach(cb => {
        cb.checked = true;
    });

    // Update card styles, import button state and keep Select All state in sync
    updateImportButtons();
}

// Import selected offers
function importSelected() {
    // Validate authentication
    if (!validateAuth()) {
        return;
    }
    
    const selectedCheckboxes = document.querySelectorAll('.offer-checkbox:checked');
    // Support both data-offer-id and data-product-id for compatibility
    const selectedIds = Array.from(selectedCheckboxes).map(cb => 
        cb.dataset.productId || cb.dataset.offerId
    );
    
    const offersToImport = currentOffers.filter(offer => selectedIds.includes(offer.id));
    importOffers(offersToImport);
    
    // Unselect all checkboxes after import
    selectedCheckboxes.forEach(checkbox => {
        checkbox.checked = false;
    });
    
    // Update UI state to reflect unselected checkboxes
    updateImportButtons();
}

// Import offers
function importOffers(offers) {
    offers.forEach(offer => {
        if (!importedOffers.find(imp => imp.id === offer.id)) {
            importedOffers.push(offer);
        }
    });
    
    saveImportedOffers();
    displayImportedOffers();
}

// Display imported offers
function displayImportedOffers() {
    const importedListEl = document.getElementById('importedList');
    const clearImportedBtn = document.getElementById('clearImportedBtn');
    const exportToPrestashopBtn = document.getElementById('exportToPrestashopBtn');
    
    // Update tab badge
    const tabImportedCount = document.getElementById('tabImportedCount');
    if (tabImportedCount) {
        tabImportedCount.textContent = importedOffers.length;
    }
    
    // Update dashboard stats
    updateDashboardStats();
    
    // Enable/disable buttons based on imported products count
    if (clearImportedBtn) {
        clearImportedBtn.disabled = importedOffers.length === 0;
    }
    
    // Update export button state (checks both imported offers and PrestaShop config)
    updateExportButtonState();
    // Also update CSV export buttons which depend on imported products
    updateCsvExportButtonsState();
    
    if (importedOffers.length === 0) {
        importedListEl.innerHTML = '<p style="text-align: center; padding: 20px; color: #1a73e8;">No products imported yet</p>';
        return;
    }
    
    importedListEl.innerHTML = importedOffers.map(offer => {
        // Count ALL available images from Allegro (same logic as backend and createOfferCard)
        // According to Allegro API docs, images are in an array with url field: [{url: "..."}, {url: "..."}]
        let imageUrls = [];
        let mainImage = '';
        
        // Method 1: Check images array first (this is the primary source for multiple images)
        if (offer.images && Array.isArray(offer.images) && offer.images.length > 0) {
            offer.images.forEach(img => {
                let imgUrl = '';
                if (typeof img === 'object' && img !== null) {
                    // Allegro API format: {url: "https://..."}
                    imgUrl = img.url || img.uri || img.path || img.src || img.link || '';
                } else if (typeof img === 'string' && img.startsWith('http')) {
                    imgUrl = img;
                }
                if (imgUrl && imgUrl.length > 0 && !imageUrls.includes(imgUrl)) {
                    imageUrls.push(imgUrl);
                }
            });
            // Set mainImage to first image if available
            if (imageUrls.length > 0) {
                mainImage = imageUrls[0];
            }
        }
        
        // Method 2: Add primary image if it exists and isn't already in the array
        if (offer.primaryImage && offer.primaryImage.url) {
            const primaryImageUrl = offer.primaryImage.url;
            if (!imageUrls.includes(primaryImageUrl)) {
                imageUrls.unshift(primaryImageUrl);
                if (!mainImage) {
                    mainImage = primaryImageUrl;
                }
            } else if (!mainImage) {
                mainImage = primaryImageUrl;
            }
        }
        
        // Method 3: Check alternative image locations (fallback)
        const altImageFields = ['image', 'imageUrl', 'photo', 'thumbnail'];
        for (const field of altImageFields) {
            if (offer[field] && typeof offer[field] === 'string' && offer[field].startsWith('http')) {
                if (!imageUrls.includes(offer[field])) {
                    imageUrls.push(offer[field]);
                }
                if (!mainImage) {
                    mainImage = offer[field];
                }
            }
        }
        
        // Method 4: Check if images are in a nested structure (e.g. offer.media.images)
        if (offer.media && offer.media.images && Array.isArray(offer.media.images)) {
            offer.media.images.forEach(img => {
                let imgUrl = '';
                if (typeof img === 'object' && img !== null) {
                    imgUrl = img.url || img.uri || img.path || img.src || '';
                } else if (typeof img === 'string' && img.startsWith('http')) {
                    imgUrl = img;
                }
                if (imgUrl && imgUrl.length > 0 && !imageUrls.includes(imgUrl)) {
                    imageUrls.push(imgUrl);
                }
            });
            if (!mainImage && imageUrls.length > 0) {
                mainImage = imageUrls[0];
            }
        }
        
        // Count total images (limit to 5 as per backend logic)
        const totalImageCount = Math.min(imageUrls.length, 5);
        
        // Store image URLs in JSON format for rotation (limit to 5)
        const imageUrlsJson = JSON.stringify(imageUrls.slice(0, 5));
        
        const productName = offer.name || 'Untitled Product';
        // Truncate product name to keep it short
        const shortName = productName.length > 50 ? productName.substring(0, 47) + '...' : productName;
        // Shorten product ID for display
        const shortId = offer.id.length > 12 ? offer.id.substring(0, 8) + '...' : offer.id;
        
        return `
        <div class="imported-item" data-offer-id="${offer.id}" data-image-urls='${imageUrlsJson}'>
            <div class="imported-item-image">
                    ${mainImage ? `
                        <img src="${mainImage}" alt="${escapeHtml(productName)}" class="imported-item-img ${totalImageCount > 1 ? 'offer-image-clickable' : ''}" 
                             loading="lazy"
                             data-current-image-index="0"
                             ${totalImageCount > 1 ? `onclick="navigateImage(event, '${offer.id}', 'next')" title="Click to see next image"` : ''}
                             onerror="this.onerror=null; this.style.display='none'; if(this.nextElementSibling) this.nextElementSibling.style.display='flex';">
                    ${totalImageCount > 1 ? `
                        <button class="offer-image-nav-btn offer-image-nav-prev" onclick="navigateImage(event, '${offer.id}', 'prev')" title="Previous image">‹</button>
                        <button class="offer-image-nav-btn offer-image-nav-next" onclick="navigateImage(event, '${offer.id}', 'next')" title="Next image">›</button>
                    ` : ''}
                    <div class="imported-item-image-placeholder" style="display: none;">
                        <span>No Image</span>
                    </div>
                ` : `
                    <div class="imported-item-image-placeholder">
                        <span>No Image</span>
                    </div>
                `}
            </div>
            <div class="imported-item-content">
                <div class="imported-item-title">${escapeHtml(shortName)}</div>
                <div class="imported-item-id">ID: ${shortId}</div>
            </div>
            <button class="imported-item-remove" onclick="removeImportedOffer('${offer.id}')" title="Remove product">
                <span>×</span>
            </button>
        </div>
    `;
    }).join('');
    
    // Initialize automatic image rotation for imported products with multiple images
    initializeImportedImageRotation();
}

// Initialize automatic image rotation for imported products
function initializeImportedImageRotation() {
    // Find all imported items with multiple images
    document.querySelectorAll('.imported-item[data-image-urls]').forEach(item => {
        const imageUrlsJson = item.getAttribute('data-image-urls');
        if (!imageUrlsJson) return;
        
        try {
            const imageUrls = JSON.parse(imageUrlsJson);
            if (imageUrls && Array.isArray(imageUrls) && imageUrls.length > 1) {
                const imgElement = item.querySelector('.imported-item-img');
                if (imgElement) {
                    // Start rotation for this imported product
                    startImageRotation(item, imageUrls, imgElement);
                }
            }
        } catch (e) {
            console.error('Error parsing image URLs for imported item:', e);
        }
    });
}

// Remove imported offer
function removeImportedOffer(offerId) {
    importedOffers = importedOffers.filter(offer => offer.id !== offerId);
    saveImportedOffers();
    displayImportedOffers();
    showToast('Product removed from imported list', 'success');
}

// Clear all imported products
function clearImportedProducts() {
    if (importedOffers.length === 0) {
        return;
    }
    
    importedOffers = [];
    saveImportedOffers();
    displayImportedOffers();
    showToast('All imported products cleared', 'success');
}

// Helper function to extract images from offer object
function extractImages(offer) {
    const images = [];
    
    // Method 1: Check primaryImage.url (Allegro /sale/offers API format)
    if (offer.primaryImage && offer.primaryImage.url) {
        images.push(offer.primaryImage.url);
    }
    
    // Method 2: Check images array
    if (offer.images) {
        if (Array.isArray(offer.images)) {
            offer.images.forEach(img => {
                if (typeof img === 'object' && img !== null) {
                    const url = img.url || img.uri || img.path || img.src || img.link;
                    if (url && !images.includes(url)) {
                        images.push(url);
                    }
                } else if (typeof img === 'string' && img.startsWith('http') && !images.includes(img)) {
                    images.push(img);
                }
            });
        } else if (typeof offer.images === 'string' && offer.images.startsWith('http')) {
            if (!images.includes(offer.images)) {
                images.push(offer.images);
            }
        } else if (typeof offer.images === 'object' && offer.images !== null) {
            const url = offer.images.url || offer.images.uri || offer.images.path || offer.images.src;
            if (url && !images.includes(url)) {
                images.push(url);
            }
        }
    }
    
    // Method 3: Check alternative image locations
    const altImage = offer.image || offer.imageUrl || offer.photo || offer.thumbnail;
    if (altImage && !images.includes(altImage)) {
        images.push(altImage);
    }
    
    // Method 4: Check media.images
    if (offer.media && offer.media.images && Array.isArray(offer.media.images)) {
        offer.media.images.forEach(img => {
            const url = typeof img === 'string' ? img : (img.url || img.uri || img);
            if (url && !images.includes(url)) {
                images.push(url);
            }
        });
    }
    
    return images;
}

// Helper function to extract price from offer object
function extractPrice(offer) {
    // Check various possible price fields
    if (offer.price) {
        if (typeof offer.price === 'object') {
            return offer.price.amount || offer.price.value || null;
        } else if (typeof offer.price === 'number') {
            return offer.price;
        }
    }
    
    // Check sellingMode.price (common Allegro API format)
    if (offer.sellingMode?.price) {
        return offer.sellingMode.price.amount || offer.sellingMode.price.value || null;
    }
    
    return null;
}

// Helper function to extract description from offer object
function extractDescription(offer) {
    // Check various possible description fields
    if (offer.description) {
        return offer.description;
    }
    
    if (offer.descriptionHtml) {
        return offer.descriptionHtml;
    }
    
    if (offer.product?.description) {
        return offer.product.description;
    }
    
    if (offer.product?.descriptionHtml) {
        return offer.product.descriptionHtml;
    }
    
    if (offer.details?.description) {
        return offer.details.description;
    }
    
    if (offer.publication?.description) {
        return offer.publication.description;
    }
    
    if (offer.sellingMode?.description) {
        return offer.sellingMode.description;
    }
    
    // Check sections array
    if (offer.sections && Array.isArray(offer.sections)) {
        const descriptionSection = offer.sections.find(s => 
            s.type === 'DESCRIPTION' || 
            s.type === 'TEXT' || 
            s.type === 'description' ||
            s.type === 'text'
        );
        if (descriptionSection) {
            if (descriptionSection.items && Array.isArray(descriptionSection.items)) {
                return descriptionSection.items
                    .map(item => item.content || item.text || item.html || '')
                    .filter(text => text.trim().length > 0)
                    .join('\n');
            } else if (descriptionSection.content) {
                return descriptionSection.content;
            } else if (descriptionSection.text) {
                return descriptionSection.text;
            } else if (descriptionSection.html) {
                return descriptionSection.html;
            }
        }
    }
    
    return '';
}

// PrestaShop Configuration Functions

async function savePrestashopConfig() {
    const url = document.getElementById('prestashopUrl').value.trim();
    const apiKey = document.getElementById('prestashopApiKey').value.trim();
    
    if (!url || !apiKey) {
        showToast('Please fill in all PrestaShop fields', 'error');
        return;
    }
    
    // Hide any previous messages
    const messageEl = document.getElementById('prestashopMessage');
    if (messageEl) messageEl.style.display = 'none';
    
    try {
        const response = await authFetch(`${API_BASE}/api/prestashop/configure`, {
            method: 'POST',
            body: JSON.stringify({
                baseUrl: url,
                apiKey: apiKey
            })
        });
        
        // Check for 401 status before parsing JSON
        if (!response.ok && response.status === 401) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Authentication required. Please log in again to configure PrestaShop.');
        }
        
        const data = await response.json();
        
        if (data.success) {
            // Clear API key field for security (value is saved in DB)
            const apiKeyInput = document.getElementById('prestashopApiKey');
            if (apiKeyInput) {
                apiKeyInput.value = '';
                apiKeyInput.placeholder = 'API Key is saved (hidden for security)';
                apiKeyInput.classList.add('secret-saved');
            }
            
            showToast('PrestaShop configuration saved successfully!', 'success');
            // Configuration is now stored in database, no need for localStorage
            prestashopConfigured = true;
            // Note: prestashopAuthorized will be set to true only after successful test connection
            prestashopAuthorized = false;
            
            // Show saved configuration info
            updatePrestashopSavedConfigDisplay(url);
            
            // Update config statuses and button states
            updateConfigStatuses();
            checkPrestashopStatus();
            updateExportButtonState();
            updateUIState(true); // Update UI state
        } else {
            showToast(data.error || 'Failed to save configuration', 'error', 8000);
        }
    } catch (error) {
        showToast('✗ Error: ' + error.message, 'error', 8000);
    }
}

async function testPrestashopConnection() {
    const url = document.getElementById('prestashopUrl').value.trim();
    const apiKey = document.getElementById('prestashopApiKey').value.trim();
    
    if (!url || !apiKey) {
        showToast('Please fill in URL and API key first', 'error');
        return;
    }
    
    // Hide any previous messages
    const messageEl = document.getElementById('prestashopMessage');
    if (messageEl) messageEl.style.display = 'none';
    
    // Show loading
    const testBtn = document.getElementById('testPrestashopBtn');
    const originalText = testBtn.textContent;
    testBtn.disabled = true;
    testBtn.textContent = 'Connecting...';
    
    try {
        // Save temporarily for test (now requires authentication)
        const response = await authFetch(`${API_BASE}/api/prestashop/configure`, {
            method: 'POST',
            body: JSON.stringify({
                baseUrl: url,
                apiKey: apiKey
            })
        });
        
        // Check for 401 status before parsing JSON
        if (!response.ok && response.status === 401) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Authentication required. Please log in again to configure PrestaShop.');
        }
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Failed to save configuration');
        }
        
        // Test connection (requires auth token)
        const testResponse = await authFetch(`${API_BASE}/api/prestashop/test`);
        
        // Check for 401 status before parsing JSON
        if (!testResponse.ok && testResponse.status === 401) {
            const errorData = await testResponse.json().catch(() => ({}));
            throw new Error(errorData.error || 'Authentication required. Please log in again to test PrestaShop connection.');
        }
        
        const testData = await testResponse.json();
        
        if (testData.success) {
            // Configuration is now stored in database, no need for localStorage
            // Clear API key field for security (value is saved in DB)
            const apiKeyInput = document.getElementById('prestashopApiKey');
            if (apiKeyInput) {
                apiKeyInput.value = '';
                apiKeyInput.placeholder = 'API Key is saved (hidden for security)';
                apiKeyInput.classList.add('secret-saved');
            }
            
            showToast(testData.message, 'success');
            prestashopConfigured = true;
            prestashopAuthorized = true; // Mark PrestaShop as authorized after successful test
            
            // Show saved configuration info
            updatePrestashopSavedConfigDisplay(url);
            
            // Update config statuses and button states
            updateConfigStatuses();
            checkPrestashopStatus();
            updateUIState(true); // Update UI to enable Allegro Categories and Load Offers
            updateButtonStates(); // Update all button states including sync category button
        } else {
            // Show error with line breaks if it contains \n
            const errorMsg = (testData.error || 'Connection failed').replace(/\n/g, '<br>');
            showToast(errorMsg, 'error', 10000);
        }
    } catch (error) {
        // Format error message for better readability
        let errorMsg = error.message;
        if (errorMsg.includes('\n')) {
            errorMsg = errorMsg.replace(/\n/g, '<br>• ');
            errorMsg = '• ' + errorMsg;
        }
        showToast(errorMsg, 'error', 10000);
    } finally {
        testBtn.disabled = false;
        testBtn.textContent = originalText;
    }
}

// Load PrestaShop config from API (database)
async function loadPrestashopConfigFromAPI() {
    try {
        const response = await authFetch(`${API_BASE}/api/prestashop/credentials`);
        
        if (!response.ok) {
            if (response.status === 401) {
                return; // Not authenticated, will be handled by authFetch
            }
            return;
        }
        
        const data = await response.json();
        
        if (data.success && data.credentials && data.credentials.baseUrl) {
            // Restore configuration to input fields
            document.getElementById('prestashopUrl').value = data.credentials.baseUrl || '';
            
            // If API key exists in DB (indicated by '***' or non-null value), show indicator
            const apiKeyInput = document.getElementById('prestashopApiKey');
            if (apiKeyInput && data.credentials.apiKey) {
                // Set placeholder to indicate API key is saved but masked
                apiKeyInput.placeholder = 'API Key is saved (hidden for security)';
                apiKeyInput.value = ''; // Keep field empty for security
                // Add a visual indicator class
                apiKeyInput.classList.add('secret-saved');
            }
            
            // Show saved configuration info
            updatePrestashopSavedConfigDisplay(data.credentials.baseUrl);
            
            // Mark as configured
            prestashopConfigured = true;
            
            // Update config statuses to reflect saved state immediately
            updateConfigStatuses();
        } else {
            // No saved config - leave empty so user enters their URL
            document.getElementById('prestashopUrl').value = '';
            const apiKeyInput = document.getElementById('prestashopApiKey');
            if (apiKeyInput) {
                apiKeyInput.value = '';
                apiKeyInput.placeholder = 'Enter PrestaShop API Key';
                apiKeyInput.classList.remove('secret-saved');
            }
            hidePrestashopSavedConfigDisplay();
        }
    } catch (error) {
        // Silently fail - config may not be configured yet
        console.log('No PrestaShop config found in database or error loading:', error.message);
        document.getElementById('prestashopUrl').value = '';
        const apiKeyInput = document.getElementById('prestashopApiKey');
        if (apiKeyInput) {
            apiKeyInput.value = '';
            apiKeyInput.placeholder = 'Enter PrestaShop API Key';
            apiKeyInput.classList.remove('secret-saved');
        }
        hidePrestashopSavedConfigDisplay();
    }
}

// Legacy function name for backward compatibility
function loadPrestashopConfig() {
    // This function is called during initialization, but credentials should be loaded from API
    // after login. For now, just clear the fields.
    document.getElementById('prestashopUrl').value = '';
    const apiKeyInput = document.getElementById('prestashopApiKey');
    if (apiKeyInput) {
        apiKeyInput.value = '';
        apiKeyInput.placeholder = 'Enter PrestaShop API Key';
        apiKeyInput.classList.remove('secret-saved');
    }
    hidePrestashopSavedConfigDisplay();
}

// Update saved configuration display
function updatePrestashopSavedConfigDisplay(url) {
    const savedConfigInfo = document.getElementById('prestashopSavedConfigInfo');
    if (savedConfigInfo) {
        savedConfigInfo.style.display = 'inline-block';
    }
}

// Hide saved configuration display
function hidePrestashopSavedConfigDisplay() {
    const savedConfigInfo = document.getElementById('prestashopSavedConfigInfo');
    if (savedConfigInfo) {
        savedConfigInfo.style.display = 'none';
    }
}

async function checkPrestashopStatus() {
    try {
        const response = await authFetch(`${API_BASE}/api/prestashop/status`);
        
        // Check for 401 status before parsing JSON
        if (!response.ok && response.status === 401) {
            // Session expired, will be handled by authFetch
            return;
        }
        
        const data = await response.json();
        
        prestashopConfigured = data.configured;
        
        // If PrestaShop is configured, check if connection is authorized by testing it
        // Only set authorized to true if we can successfully test the connection
        if (prestashopConfigured) {
            try {
                const testResponse = await authFetch(`${API_BASE}/api/prestashop/test`);
                if (!testResponse.ok && testResponse.status === 401) {
                    // Session expired, can't test
                    prestashopAuthorized = false;
                    return;
                }
                const testData = await testResponse.json();
                prestashopAuthorized = testData.success || false;
            } catch (error) {
                prestashopAuthorized = false;
            }
        } else {
            prestashopAuthorized = false;
        }
        
        // Show/hide saved config display based on configured status
        // Try to load config from API if authenticated
        if (prestashopConfigured && getAuthToken()) {
            try {
                const response = await authFetch(`${API_BASE}/api/prestashop/credentials`).catch(() => null);
                if (response && response.ok) {
                    const data = await response.json();
                    if (data.success && data.credentials && data.credentials.baseUrl) {
                        updatePrestashopSavedConfigDisplay(data.credentials.baseUrl);
                        // Also update API key indicator if API key exists
                        const apiKeyInput = document.getElementById('prestashopApiKey');
                        if (apiKeyInput && data.credentials.apiKey) {
                            apiKeyInput.placeholder = 'API Key is saved (hidden for security)';
                            apiKeyInput.value = ''; // Keep field empty for security
                            apiKeyInput.classList.add('secret-saved');
                        }
                    } else {
                        hidePrestashopSavedConfigDisplay();
                    }
                } else {
                    hidePrestashopSavedConfigDisplay();
                }
            } catch (error) {
                hidePrestashopSavedConfigDisplay();
            }
        } else {
            hidePrestashopSavedConfigDisplay();
        }
        
        updateConfigStatuses();
        updateExportButtonState();
        updateUIState(true); // Update UI state to reflect PrestaShop authorization status
        updateButtonStates(); // Update all button states including sync category button

        // If everything is configured on this device, auto-load offers after refresh
        await autoLoadOffersIfReady();
    } catch (error) {
        console.error('Error checking PrestaShop status:', error);
        prestashopAuthorized = false;
        updateUIState(true); // Update UI state even on error
        updateButtonStates(); // Update button states even on error
    }
}

/**
 * Sync categories to PrestaShop after loading from Allegro
 * Creates categories in PrestaShop with proper tree structure (parent-child relationships)
 * Does not create categories that already exist
 * 
 * IMPORTANT: This function syncs ALL categories from allCategories, which includes
 * categories from offers with ALL statuses (ACTIVE, INACTIVE, ENDED, ACTIVATING).
 * This ensures categories for current-user-accounts with products are synchronized,
 * regardless of the product status.
 */
async function syncCategoriesToPrestashop() {
    // Check if PrestaShop is configured and authorized
    if (!prestashopConfigured || !prestashopAuthorized) {
        console.log('PrestaShop not configured or not authorized, skipping category sync');
        return;
    }

    // Check if we have categories to sync
    if (!allCategories || allCategories.length === 0) {
        console.log('No categories to sync to PrestaShop');
        return;
    }

    console.log(`Starting sync of ${allCategories.length} categories to PrestaShop with tree structure...`);

    // Capture sync start time
    const syncStartTime = new Date().toISOString();

    // Map to store Allegro category ID -> PrestaShop category ID
    const categoryIdMap = new Map();
    
    let createdCount = 0;
    let existingCount = 0;
    let errorCount = 0;
    let skippedCount = 0;
    const skippedCategories = []; // Track skipped categories for debugging

    // Step 1: Collect all unique categories from all paths (including parents)
    const allCategoryNodes = new Map(); // Map<categoryId, {id, name, parentId, level}>
    const processedPaths = new Set();
    
    // Fetch parent paths for all categories
    for (const category of allCategories) {
        const categoryId = String(category.id);
        const pathKey = `path_${categoryId}`;
        
        if (processedPaths.has(pathKey)) {
            continue;
        }

        // Check if category has a placeholder name - we'll try to get the real name from the path
        const hasPlaceholderName = !category.name || category.name === `Category ${categoryId}` || category.name === 'N/A';
        
        try {
            // Fetch the full parent path for this category
            // This will give us the real category names even if the original category had a placeholder name
            const path = await fetchCategoryPath(categoryId);
            
            if (path && path.length > 0) {
                // Get the leaf category (last in path) - this is the actual category we're processing
                const leafCategory = path[path.length - 1];
                const leafCategoryId = String(leafCategory.id);
                
                // Use the name from the path if we had a placeholder name
                const categoryName = hasPlaceholderName ? leafCategory.name : category.name;
                
                // Validate that we have a real name now
                if (!categoryName || categoryName === `Category ${leafCategoryId}` || categoryName === 'N/A') {
                    skippedCount++;
                    skippedCategories.push({ id: categoryId, reason: 'Invalid name after path fetch', name: categoryName });
                    console.warn(`Category ${categoryId} still has invalid name after fetching path, skipping: "${categoryName}"`);
                    processedPaths.add(pathKey);
                    continue;
                }
                
                // Log successful name resolution for debugging (especially for "Modules" category)
                if (hasPlaceholderName) {
                    console.log(`✓ Resolved category name for ${categoryId}: "${categoryName}" (was placeholder)`);
                }
                
                // Add all categories in the path (including parents)
                for (let i = 0; i < path.length; i++) {
                    const pathNode = path[i];
                    const pathNodeId = String(pathNode.id);
                    
                    // Only add if not already processed
                    if (!allCategoryNodes.has(pathNodeId)) {
                        allCategoryNodes.set(pathNodeId, {
                            id: pathNodeId,
                            name: pathNode.name,
                            parentId: i > 0 ? String(path[i - 1].id) : null,
                            level: i
                        });
                    }
                }
                
                // Update the leaf category name if we had a placeholder
                if (hasPlaceholderName && allCategoryNodes.has(leafCategoryId)) {
                    allCategoryNodes.get(leafCategoryId).name = categoryName;
                }
            } else {
                // If no path found, try to use the category name we have
                // But skip if it's still a placeholder
                if (hasPlaceholderName) {
                    skippedCount++;
                    skippedCategories.push({ id: categoryId, reason: 'No path and placeholder name', name: category.name });
                    console.warn(`Category ${categoryId} has no path and placeholder name, skipping: "${category.name}"`);
                    processedPaths.add(pathKey);
                    continue;
                }
                
                // Treat as root level category with valid name
                if (!allCategoryNodes.has(categoryId)) {
                    allCategoryNodes.set(categoryId, {
                        id: categoryId,
                        name: category.name,
                        parentId: null,
                        level: 0
                    });
                }
            }
            
            processedPaths.add(pathKey);
        } catch (error) {
            console.error(`Error fetching path for category ${categoryId}:`, error);
            
            // If we have a valid name, still add the category even if path fetch fails
            if (!hasPlaceholderName && category.name) {
                if (!allCategoryNodes.has(categoryId)) {
                    allCategoryNodes.set(categoryId, {
                        id: categoryId,
                        name: category.name,
                        parentId: null,
                        level: 0
                    });
                }
            } else {
                skippedCount++;
                skippedCategories.push({ id: categoryId, reason: 'Path fetch error and invalid/placeholder name', name: category.name });
                console.warn(`Category ${categoryId} skipped due to path fetch error and invalid/placeholder name`);
            }
            
            processedPaths.add(pathKey);
        }
    }
    
    // Log summary of category collection
    console.log(`Category collection summary: ${allCategoryNodes.size} unique categories collected, ${skippedCount} skipped`);
    if (skippedCount > 0) {
        console.warn(`Skipped categories:`, skippedCategories);
    }
    
    // Check if "Modules" category is in the collected categories (for testing)
    const modulesCategory = Array.from(allCategoryNodes.values()).find(cat => 
        cat.name && cat.name.toLowerCase().includes('module')
    );
    if (modulesCategory) {
        console.log(`✓ "Modules" category found in collected categories: ID=${modulesCategory.id}, Name="${modulesCategory.name}", Level=${modulesCategory.level}`);
    } else {
        console.warn(`⚠ "Modules" category NOT found in collected categories. Check if it was skipped.`);
    }

    // Step 2: Group categories by level for proper creation order
    const categoriesByLevel = {};
    
    for (const [categoryId, categoryNode] of allCategoryNodes) {
        const level = categoryNode.level;
        if (!categoriesByLevel[level]) {
            categoriesByLevel[level] = [];
        }
        categoriesByLevel[level].push(categoryNode);
    }

    // Step 3: Create categories level by level (parents before children)
    const levels = Object.keys(categoriesByLevel).map(Number).sort((a, b) => a - b);
    
    for (const level of levels) {
        const categoriesAtLevel = categoriesByLevel[level];
        
        for (const categoryNode of categoriesAtLevel) {
            const categoryName = categoryNode.name;
            const allegroCategoryId = categoryNode.id;
            const allegroParentId = categoryNode.parentId;
            
            // Determine PrestaShop parent ID
            // Step 7: Find parent category via meta_keywords (Allegro ID)
            let prestashopParentId = 2; // Default to Home (ID: 2)
            
            if (allegroParentId && categoryIdMap.has(allegroParentId)) {
                // Use mapped PrestaShop parent ID (parent was created in previous level)
                prestashopParentId = categoryIdMap.get(allegroParentId);
            } else if (allegroParentId) {
                // Parent should be found by meta_keywords (Allegro ID) on the backend
                // We'll pass allegroParentId and let the backend find it
                // For now, use default parent - backend will find it by meta_keywords
                prestashopParentId = 2; // Backend will find parent by meta_keywords
            }

            // Check if we've already processed this category by Allegro ID in this sync session
            // This prevents duplicate API calls for the same category
            if (categoryIdMap.has(allegroCategoryId)) {
                const existingPrestashopId = categoryIdMap.get(allegroCategoryId);
                existingCount++;
                console.log(`Category "${categoryName}" (Allegro ID: ${allegroCategoryId}) already processed in this sync session (PrestaShop ID: ${existingPrestashopId}), skipping API call`);
                continue;
            }

            try {
                const response = await authFetch(`${API_BASE}/api/prestashop/categories`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        name: categoryName,
                        idParent: prestashopParentId,
                        active: 1,
                        allegroCategoryId: allegroCategoryId,
                        allegroParentId: allegroParentId
                    })
                });

                const result = await response.json();

                if (result.success && result.category && result.category.id) {
                    const prestashopCategoryId = result.category.id;
                    
                    // Store mapping: Allegro category ID -> PrestaShop category ID
                    categoryIdMap.set(allegroCategoryId, prestashopCategoryId);
                    
                    if (result.existing) {
                        existingCount++;
                        console.log(`Category "${categoryName}" (Allegro ID: ${allegroCategoryId}) already exists in PrestaShop (ID: ${prestashopCategoryId})`);
                    } else {
                        createdCount++;
                        console.log(`Created category "${categoryName}" (Allegro ID: ${allegroCategoryId}) in PrestaShop (ID: ${prestashopCategoryId})`);
                    }
                } else {
                    errorCount++;
                    console.error(`Failed to sync category "${categoryName}":`, result.error || 'Unknown error');
                }
                
                // Small delay to avoid overwhelming the API
                await new Promise(resolve => setTimeout(resolve, 100));
            } catch (error) {
                errorCount++;
                console.error(`Error syncing category "${categoryName}":`, error);
            }
        }
    }

    // Capture sync end time
    const syncEndTime = new Date().toISOString();
    const totalProcessed = createdCount + existingCount + errorCount + skippedCount;

    // Show summary
    if (createdCount > 0 || existingCount > 0 || errorCount > 0 || skippedCount > 0) {
        const message = `✓ Category sync completed: ${totalProcessed} total (${createdCount} created, ${existingCount} existed, ${errorCount} errors${skippedCount > 0 ? `, ${skippedCount} skipped` : ''})`;
        console.log(message);
        
        // Show toast notification if there were results
        if (createdCount > 0 || errorCount > 0) {
            showToast(message, errorCount > 0 ? 'warning' : 'success');
        }
    } else {
        console.log('✓ Category sync completed: No categories to sync');
    }
    
    // Save category sync statistics to database
    try {
        await authFetch(`${API_BASE}/api/category-sync/statistics`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                categoriesCreatedCount: createdCount,
                categoriesExistingCount: existingCount,
                categoriesErrorCount: errorCount,
                categoriesSkippedCount: skippedCount,
                totalCategoriesChecked: totalProcessed,
                syncStartTime: syncStartTime,
                syncEndTime: syncEndTime,
                changedInfo: [] // Could be enhanced to track individual category changes
            })
        });
    } catch (error) {
        console.error('Error saving category sync statistics:', error);
        // Don't fail the sync if statistics saving fails
    }
    
    // Final check: verify "Modules" category was synced
    const syncedModulesCategory = Array.from(categoryIdMap.entries()).find(([allegroId, prestashopId]) => {
        const node = allCategoryNodes.get(allegroId);
        return node && node.name && node.name.toLowerCase().includes('module');
    });
    if (syncedModulesCategory) {
        const [allegroId, prestashopId] = syncedModulesCategory;
        const node = allCategoryNodes.get(allegroId);
        console.log(`✓ "Modules" category successfully synced: Allegro ID=${allegroId}, PrestaShop ID=${prestashopId}, Name="${node.name}"`);
    } else {
        console.warn(`⚠ "Modules" category was NOT synced. Check skipped categories list above.`);
    }
}

function updateExportButtonState() {
    const exportBtn = document.getElementById('exportToPrestashopBtn');
    
    if (exportBtn) {
        exportBtn.disabled = importedOffers.length === 0 || !prestashopConfigured;
    }
}

// Export to PrestaShop - Actually create products
async function exportToPrestashop() {
    if (importedOffers.length === 0) {
        showToast('No products to export', 'error');
        return;
    }
    
    if (!prestashopConfigured) {
        showToast('Please configure PrestaShop first', 'error');
        return;
    }
    
    // Confirm before export
    if (!confirm(`Export ${importedOffers.length} product(s) to PrestaShop?`)) {
        return;
    }

    const exportBtn = document.getElementById('exportToPrestashopBtn');
    const clearImportedBtn = document.getElementById('clearImportedBtn');
    const importSelectedBtn = document.getElementById('importSelectedBtn');
    const progressContainer = document.getElementById('exportProgress');
    const progressBarFill = document.getElementById('exportProgressBarFill');
    const progressText = document.getElementById('exportProgressText');

    // Disable actions while export is running
    if (exportBtn) exportBtn.disabled = true;
    if (clearImportedBtn) clearImportedBtn.disabled = true;
    if (importSelectedBtn) importSelectedBtn.disabled = true;

    // Initialise and show progress UI
    if (progressContainer && progressBarFill && progressText) {
        progressContainer.style.display = 'flex';
        progressBarFill.style.width = '0%';
        progressText.textContent = `Starting export (0/${importedOffers.length})…`;
    }

    showToast('Starting export to PrestaShop...', 'info');

    let successCount = 0;
    let errorCount = 0;
    const errors = [];
    
    // Before exporting, ensure we have full product details for all offers
    // This ensures descriptions and images are available
    showToast('Fetching full product details before export...', 'info');
    for (let i = 0; i < importedOffers.length; i++) {
        const offer = importedOffers[i];
        // Check if offer has full description structure or needs fetching
        const hasFullDescription = offer.description?.sections || 
                                   (offer.description && typeof offer.description === 'string' && offer.description.length > 0) ||
                                   offer.product?.description;
        const hasImages = (offer.images && Array.isArray(offer.images) && offer.images.length > 0) ||
                          offer.primaryImage?.url;
        
        // If missing description or images, fetch full details
        if (!hasFullDescription || !hasImages) {
            try {
                await fetchProductDetails(offer.id);
                // Update offer reference after fetchProductDetails updates importedOffers
                const updatedOffer = importedOffers.find(imp => imp.id === offer.id || imp.id?.toString() === offer.id?.toString());
                if (updatedOffer) {
                    importedOffers[i] = updatedOffer;
                }
            } catch (error) {
                console.warn(`Failed to fetch full details for offer ${offer.id}, proceeding with available data:`, error);
            }
        }
    }
    
    // Export products one by one
    for (let i = 0; i < importedOffers.length; i++) {
        const offer = importedOffers[i];
        
        try {
            // Fetch category path for matching in PrestaShop
            let categoryPath = null;
            let categoryId = null;
            
            if (offer.category) {
                const allegroCategoryId = typeof offer.category === 'string' 
                    ? offer.category 
                    : offer.category.id;
                
                // Fetch the full category path from root to leaf
                try {
                    categoryPath = await fetchCategoryPath(allegroCategoryId);
                    if (categoryPath && categoryPath.length > 0) {
                        // Add the path to the offer object for the backend
                        offer.categoryPath = categoryPath;
                    }
                } catch (error) {
                    console.warn(`Failed to fetch category path for offer ${offer.id}:`, error);
                    // Continue without category path - backend will use default
                }
            }
            
            const response = await authFetch(`${API_BASE}/api/prestashop/products`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    offer: offer,
                    categoryId: categoryId,
                    categories: allCategories // Send categories list so backend can use existing category info
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                successCount++;
                showToast(`Exported ${successCount}/${importedOffers.length}: ${offer.name}`, 'success', 2000);
            } else {
                errorCount++;
                errors.push(`${offer.name}: ${data.error}`);
                console.error('Export error:', data.error);
            }
        } catch (error) {
            errorCount++;
            errors.push(`${offer.name}: ${error.message}`);
            console.error('Export error:', error);
        }
        
        // Small delay to avoid overwhelming the API
        await new Promise(resolve => setTimeout(resolve, 500));

        // Update progress bar
        if (progressBarFill && progressText) {
            const completed = i + 1;
            const percent = Math.round((completed / importedOffers.length) * 100);
            progressBarFill.style.width = `${percent}%`;
            progressText.textContent = `Exporting products… ${completed}/${importedOffers.length} (${percent}%)`;
        }
    }
    
    // Show final results
    const totalExported = successCount + errorCount;
    if (errorCount > 0) {
        const message = `✗ Product export completed: ${totalExported} total (${successCount} success, ${errorCount} errors)`;
        console.log(message);
        showToast(message, 'error', 10000);
        console.error('Export errors:', errors);
    } else {
        const message = `✓ Product export completed: ${successCount} product(s) exported successfully`;
        console.log(message);
        showToast(message, 'success', 10000);
    }

    // Hide progress UI after a short delay
    if (progressContainer) {
        setTimeout(() => {
            progressContainer.style.display = 'none';
        }, 1500);
    }

    // Re-enable buttons based on current state
    if (clearImportedBtn) {
        clearImportedBtn.disabled = importedOffers.length === 0;
    }
    // Export button state depends on imported offers and PrestaShop config
    updateExportButtonState();
    // Import selected button state is controlled by auth + selection
    if (typeof updateUIState === 'function') {
        updateUIState();
    } else if (importSelectedBtn) {
        const selectedCheckboxes = document.querySelectorAll('.offer-checkbox:checked');
        importSelectedBtn.disabled = !authenticated || selectedCheckboxes.length === 0;
    }
}

// CSV Export Functions
async function exportCategoriesCsv() {
    const btn = document.getElementById('exportCategoriesCsvBtn');
    const messageEl = document.getElementById('csvExportMessage');
    
    if (btn) btn.disabled = true;
    if (messageEl) {
        messageEl.style.display = 'block';
        messageEl.className = 'message info';
        messageEl.textContent = 'Exporting categories...';
    }
    
    try {
        const response = await authFetch(`${API_BASE}/api/export/categories.csv`);
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ error: 'Failed to export categories' }));
            throw new Error(errorData.error || 'Failed to export categories');
        }
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'categories_import.csv';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        
        if (messageEl) {
            messageEl.className = 'message success';
            messageEl.textContent = 'Categories exported successfully!';
        }
        showToast('Categories exported successfully!', 'success', 3000);
    } catch (error) {
        console.error('Export error:', error);
        if (messageEl) {
            messageEl.className = 'message error';
            messageEl.textContent = `Export failed: ${error.message}`;
        }
        showToast(`Export failed: ${error.message}`, 'error', 5000);
    } finally {
        // Recalculate button states based on latest configuration/data
        updateCsvExportButtonsState();
    }
}

async function exportProductsCsv() {
    const btn = document.getElementById('exportProductsCsvBtn');
    const messageEl = document.getElementById('csvExportMessage');
    
    if (btn) btn.disabled = true;
    if (messageEl) {
        messageEl.style.display = 'block';
        messageEl.className = 'message info';
        messageEl.textContent = 'Exporting products...';
    }
    
    try {
        const response = await authFetch(`${API_BASE}/api/export/products.csv`);
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ error: 'Failed to export products' }));
            throw new Error(errorData.error || 'Failed to export products');
        }
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'products_import.csv';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        
        if (messageEl) {
            messageEl.className = 'message success';
            messageEl.textContent = 'Products exported successfully!';
        }
        showToast('Products exported successfully!', 'success', 3000);
    } catch (error) {
        console.error('Export error:', error);
        if (messageEl) {
            messageEl.className = 'message error';
            messageEl.textContent = `Export failed: ${error.message}`;
        }
        showToast(`Export failed: ${error.message}`, 'error', 5000);
    } finally {
        // Recalculate button states based on latest configuration/data
        updateCsvExportButtonsState();
    }
}

// Save imported offers to localStorage
function saveImportedOffers() {
    localStorage.setItem('importedOffers', JSON.stringify(importedOffers));
}

// Load imported offers from localStorage
function loadImportedOffers() {
    const saved = localStorage.getItem('importedOffers');
    if (saved) {
        try {
            importedOffers = JSON.parse(saved);
            displayImportedOffers();
        } catch (e) {
            console.error('Error loading imported offers:', e);
        }
    }
}

// Clear search + selection - reset search field and unselect all products
function clearSearch() {
    // Clear search input field
    const offerSearchInput = document.getElementById('offerSearchInput');
    if (offerSearchInput) {
        offerSearchInput.value = '';
    }

    // Reset stored search phrase
    currentPhrase = '';

    // Reset pagination when clearing search
    currentOffset = 0;
    currentPageNumber = 1;
    pageHistory = [];
    totalProductsSeen = 0;

    // Uncheck any selected offer checkboxes
    document.querySelectorAll('.offer-checkbox').forEach(cb => {
        cb.checked = false;
    });

    // Re-render offers list with cleared search (if offers already loaded)
    if (typeof displayOffersPage === 'function') {
        displayOffersPage();
    }

    // After unselecting, update import buttons and Select All button state
    updateImportButtons();
}

// Load categories from user's offers (only categories that have products)
// Cache for category data to avoid redundant API calls
let categoryDataCache = {};

// Fetch category data with parent information
async function fetchCategoryData(categoryId) {
    if (categoryDataCache[categoryId]) {
        return categoryDataCache[categoryId];
    }
    
    try {
        const response = await authFetch(`${API_BASE}/api/categories/${categoryId}`);
        if (!response.ok) {
            return null;
        }
        
        const result = await response.json();
        if (result.success && result.data) {
            categoryDataCache[categoryId] = result.data;
            return result.data;
        }
    } catch (error) {
        console.log(`Error fetching category data for ${categoryId}:`, error);
    }
    
    return null;
}

// Fetch parent category path for a given category ID
async function fetchCategoryPath(categoryId) {
    const path = [];
    const visited = new Set(); // Prevent infinite loops
    
    let currentCategoryId = String(categoryId);
    
    while (currentCategoryId && !visited.has(currentCategoryId)) {
        visited.add(currentCategoryId);
        
        const category = await fetchCategoryData(currentCategoryId);
        if (!category) {
            break;
        }
        
        path.unshift({
            id: currentCategoryId,
            name: category.name || `Category ${currentCategoryId}`
        });
        
        // Check for parent category
        if (category.parent && category.parent.id) {
            currentCategoryId = String(category.parent.id);
        } else {
            break;
        }
    }
    
    return path.length > 0 ? path : null;
}

// Build category tree structure with only categories that have products
async function buildCategoryTreeWithProducts(categoriesWithCounts) {
    categoryTreeWithProducts = {};
    categoryProductCounts = {};
    categoryDataCache = {}; // Clear cache for fresh build
    categoryTreeCache = {}; // Clear category tree cache to force refresh with counts
    
    // First, store all categories with their product counts
    const categoryMap = new Map();
    categoriesWithCounts.forEach(cat => {
        const catId = String(cat.id);
        categoryProductCounts[catId] = cat.count;
        categoryMap.set(catId, {
            id: catId,
            name: cat.name,
            count: cat.count
        });
    });
    
    // Fetch parent paths for all categories and build tree
    // Process in batches to avoid overwhelming the API
    const batchSize = 10;
    const categoryIds = Array.from(categoryMap.keys());
    
    // Track leaf category counts to ensure we don't double-count
    const leafCategoryCounts = new Map();
    
    for (let i = 0; i < categoryIds.length; i += batchSize) {
        const batch = categoryIds.slice(i, i + batchSize);
        // Use Promise.allSettled() so one failure doesn't block others
        const results = await Promise.allSettled(batch.map(async (catId) => {
            const category = categoryMap.get(catId);
            const path = await fetchCategoryPath(catId);
            
            if (path && path.length > 0) {
                // Build tree structure from path
                let currentLevel = categoryTreeWithProducts;
                const leafCategoryId = String(path[path.length - 1].id);
                
                // Store the leaf category count (each leaf category should only be counted once)
                if (!leafCategoryCounts.has(leafCategoryId)) {
                    leafCategoryCounts.set(leafCategoryId, category.count);
                }
                
                for (let j = 0; j < path.length; j++) {
                    const pathNode = path[j];
                    const pathNodeId = String(pathNode.id);
                    
                    // Initialize node if it doesn't exist
                    if (!currentLevel[pathNodeId]) {
                        currentLevel[pathNodeId] = {
                            id: pathNodeId,
                            name: pathNode.name,
                            count: 0,
                            children: {},
                            parent: j > 0 ? path[j - 1].id : null
                        };
                    }
                    
                    // Ensure children object exists
                    if (!currentLevel[pathNodeId].children) {
                        currentLevel[pathNodeId].children = {};
                    }
                    
                    // Move to next level
                    currentLevel = currentLevel[pathNodeId].children;
                }
            }
        }));
        
        // Log any failures but continue processing
        results.forEach((result, index) => {
            if (result.status === 'rejected') {
                console.error(`Failed to fetch category path for ${batch[index]}:`, result.reason);
            }
        });
    }
    
    // Set category counts correctly: leaf categories get their direct product count,
    // parent categories get the sum of all products in their subtree
    function setLeafCounts(node, leafCounts) {
        // Get direct product count for this category (if it has products directly)
        const directCount = leafCounts.get(node.id) || 0;
        
        // Calculate total from all children
        let childrenTotal = 0;
        if (node.children && Object.keys(node.children).length > 0) {
            for (const childId in node.children) {
                childrenTotal += setLeafCounts(node.children[childId], leafCounts);
            }
        }
        
        // Category count = direct products + products from all descendants
        // Note: In Allegro, typically a category either has direct products OR has children,
        // but we handle both cases to be safe
        node.count = directCount + childrenTotal;
        return node.count;
    }
    
    // Set counts for all root nodes
    for (const rootId in categoryTreeWithProducts) {
        setLeafCounts(categoryTreeWithProducts[rootId], leafCategoryCounts);
    }
}

// Get children of a category from the tree structure
function getCategoryChildren(parentId, tree = categoryTreeWithProducts) {
    if (!parentId) {
        // Return root level categories
        return Object.values(tree).map(node => ({
            id: node.id,
            name: node.name,
            count: node.count,
            leaf: Object.keys(node.children).length === 0
        }));
    }
    
    // Find the category in the tree
    function findCategory(id, currentTree) {
        for (const nodeId in currentTree) {
            if (nodeId === id) {
                return currentTree[nodeId];
            }
            const found = findCategory(id, currentTree[nodeId].children);
            if (found) return found;
        }
        return null;
    }
    
    const category = findCategory(String(parentId), tree);
    if (category && category.children) {
        return Object.values(category.children).map(node => ({
            id: node.id,
            name: node.name,
            count: node.count,
            leaf: Object.keys(node.children).length === 0
        }));
    }
    
    return [];
}

// Find a category node (including its subtree) in the global category tree
function findCategoryNodeInTree(categoryId, tree = categoryTreeWithProducts) {
    const targetId = String(categoryId);

    function dfs(currentTree) {
        for (const nodeId in currentTree) {
            const node = currentTree[nodeId];
            if (nodeId === targetId) {
                return node;
            }
            if (node.children) {
                const found = dfs(node.children);
                if (found) return found;
            }
        }
        return null;
    }

    return dfs(tree);
}

// Get an array of category IDs including the selected category and all its descendants
function getCategoryAndDescendantIds(categoryId) {
    if (categoryId === null || categoryId === undefined) {
        return [];
    }

    const rootNode = findCategoryNodeInTree(categoryId);
    if (!rootNode) {
        // Fallback: just use the single category id
        return [String(categoryId)];
    }

    const ids = [];
    function collectIds(node) {
        ids.push(String(node.id));
        if (node.children) {
            for (const childId in node.children) {
                collectIds(node.children[childId]);
            }
        }
    }
    collectIds(rootNode);

    return ids;
}

async function loadCategoriesFromOffers() {
    const categoriesListEl = document.getElementById('categoriesList');
    if (!categoriesListEl) return;
    
    // Check authentication status (credentials are configured if auth status shows "Configured")
    // Don't check input field value since secret is masked for security
    if (!checkAuthentication()) {
        categoriesListEl.innerHTML = '<p style="text-align: center; padding: 20px; color: #c5221f;">Please configure your Client ID and Client Secret first.</p>';
        return;
    }
    
    // Check OAuth connection
    if (!isOAuthConnected) {
        categoriesListEl.innerHTML = '<p style="text-align: center; padding: 20px; color: #c5221f;">OAuth authorization required. Please click "Authorize Account" to connect your Allegro account.</p>';
        return;
    }
    
    // Clear old cache to ensure we display only fresh data
    categoryTreeWithProducts = {};
    categoryTreeCache = {};
    categoryTreeInitialized = false;
    allCategories = [];
    categoriesWithProducts = [];
    
    // Show a short, friendly loading message
    categoriesListEl.innerHTML = '<div style="text-align: center; padding: 20px; color: #1a73e8; font-size: 0.9em;">Loading categories from your offers...</div>';
    
    try {
        // Fetch offers with ALL statuses to ensure all categories with products are collected
        // This is critical for category synchronization - categories must be synced even if their products are not ACTIVE
        // Categories for current-user-accounts with products should be synchronized from Allegro to PrestaShop
        let allOffers = [];
        let offset = 0;
        const limit = 1000; // Maximum allowed by API
        let hasMore = true;
        let totalCountFromAPI = null; // Store API's totalCount for accurate display
        
        while (hasMore) {
            // Fetch offers with all statuses (ACTIVE, INACTIVE, ENDED, ACTIVATING) to collect all categories
            // Use authenticated fetch because /api/offers is protected by JWT authMiddleware
            // Pass statuses as comma-separated string (server handles this format)
            const response = await authFetch(`${API_BASE}/api/offers?offset=${offset}&limit=${limit}&status=ACTIVE,INACTIVE,ENDED,ACTIVATING`);
            
            if (!response.ok) {
                if (response.status === 401) {
                    const errorData = await response.json().catch(() => ({}));
                    const errorMsg = errorData.error || 'Invalid credentials. Please check your Client ID and Client Secret.';
                    throw new Error(errorMsg);
                } else if (response.status === 403) {
                    const errorData = await response.json().catch(() => ({}));
                    if (errorData.requiresUserOAuth) {
                        throw new Error('OAuth authorization required. Please click "Authorize Account" to connect your Allegro account.');
                    }
                    const errorMsg = errorData.error || 'Access denied. Please authorize your account.';
                    throw new Error(errorMsg);
                } else {
                    const errorText = await response.text();
                    console.error(`Failed to fetch offers: ${response.status} ${response.statusText}`, errorText);
                    throw new Error(`Failed to fetch offers: ${response.status} ${response.statusText}. Please check your OAuth connection and try again.`);
                }
            }
            
            const result = await response.json();
            
            if (result.success) {
                const offers = result.data.offers || [];
                allOffers = allOffers.concat(offers);
                
                // Store totalCount from API (this is the accurate count from Allegro)
                if (totalCountFromAPI === null) {
                    totalCountFromAPI = result.data.totalCount || 0;
                }
                
                // Check if there are more offers to fetch
                const totalCount = result.data.totalCount || 0;
                if (offers.length < limit || (totalCount > 0 && allOffers.length >= totalCount)) {
                    hasMore = false;
                } else {
                    offset += limit;
                }
            } else {
                // API returned an error
                const errorMsg = result.error || 'Unknown error';
                console.error('API returned error:', errorMsg);
                throw new Error(`Failed to load offers: ${errorMsg}`);
            }
        }
        
        // Filter to only active offers for accurate display counts
        const activeOffersForCount = allOffers.filter(offer => {
            return offer?.publication?.status === 'ACTIVE';
        });
        
        console.log(`Loaded ${allOffers.length} offers from Allegro (${activeOffersForCount.length} ACTIVE) for category extraction (API totalCount: ${totalCountFromAPI || 'N/A'})`);
        
        // Check if we have any offers at all
        if (allOffers.length === 0) {
            categoriesListEl.innerHTML = '<p style="text-align: center; padding: 20px; color: #666;">No offers found. Please click "Load My Offers" first to load your Allegro offers, then categories will be displayed.</p>';
            return;
        }
        
        // Store total count of ACTIVE offers for accurate "All Categories" display
        if (totalCountFromAPI !== null && totalCountFromAPI > 0) {
            // Use API count if it matches active offers, otherwise use filtered count
            totalOffersCountFromAPI = activeOffersForCount.length;
        } else {
            totalOffersCountFromAPI = activeOffersForCount.length;
        }
        
        // Extract unique categories from ALL offers (not just ACTIVE)
        // This ensures all categories with products are collected for synchronization
        // Categories for current-user-accounts with products should be synchronized from Allegro to PrestaShop
        const categoriesFromOffers = new Map();
        
        // Process ALL offers to collect categories (not just active ones)
        let offersWithCategories = 0;
        let offersWithoutCategories = 0;
        let activeOffersWithCategories = 0; // Track active offers separately for display
        
        allOffers.forEach(offer => {
            let offerCategoryId = null;
            let offerCategoryName = null;
            
            // Try multiple ways to extract category
            if (offer.category) {
                if (typeof offer.category === 'string') {
                    offerCategoryId = offer.category;
                } else if (offer.category.id) {
                    offerCategoryId = offer.category.id;
                    offerCategoryName = offer.category.name || null;
                }
            }
            
            // Also check product.category
            if (!offerCategoryId && offer.product?.category) {
                if (typeof offer.product.category === 'string') {
                    offerCategoryId = offer.product.category;
                } else if (offer.product.category.id) {
                    offerCategoryId = offer.product.category.id;
                    offerCategoryName = offer.product.category.name || null;
                }
            }
            
            if (offerCategoryId) {
                offersWithCategories++;
                // Track active offers separately for display purposes
                if (offer?.publication?.status === 'ACTIVE') {
                    activeOffersWithCategories++;
                }
                
                const catId = String(offerCategoryId);
                if (!categoriesFromOffers.has(catId)) {
                    categoriesFromOffers.set(catId, {
                        id: catId,
                        name: offerCategoryName || categoryNameCache[catId] || `Category ${catId}`,
                        count: 0, // Count will track active offers for display
                        totalCount: 0 // Track total offers (all statuses) for sync purposes
                    });
                }
                // Increment count only for active offers (for display)
                if (offer?.publication?.status === 'ACTIVE') {
                    categoriesFromOffers.get(catId).count++;
                }
                // Always increment totalCount to track that this category has products
                categoriesFromOffers.get(catId).totalCount++;
            } else {
                offersWithoutCategories++;
            }
        });
        
        console.log(`Category extraction: ${offersWithCategories} offers with categories (${activeOffersWithCategories} ACTIVE), ${offersWithoutCategories} offers without categories`);
        
        // Convert map to array and fetch category names if needed
        const categoriesArray = Array.from(categoriesFromOffers.values());
        
        console.log(`Found ${categoriesArray.length} unique categories from ${allOffers.length} total offers (${activeOffersForCount.length} ACTIVE)`);
        if (categoriesArray.length > 0) {
            const totalProductsInCategories = categoriesArray.reduce((sum, cat) => sum + (cat.count || 0), 0);
            console.log(`Total products in categories: ${totalProductsInCategories}`);
            console.log('Top categories by count:', categoriesArray
                .sort((a, b) => (b.count || 0) - (a.count || 0))
                .slice(0, 10)
                .map(c => `${c.name || c.id}: ${c.count}`)
                .join(', '));
        }
        
        // Note: Categories are only shown if they have at least one product in loaded offers
        // If a category doesn't appear, it means no offers in that category were loaded
        // Category counts reflect the number of offers loaded, which may differ from Allegro website
        
        // Fetch category names for categories without names, in parallel for speed
        // Use Promise.allSettled() so one failure doesn't block others
        const categoryNameResults = await Promise.allSettled(categoriesArray.map(async (cat) => {
            if (cat.name === `Category ${cat.id}` || !cat.name) {
                try {
                    const catName = await fetchCategoryName(cat.id);
                    if (catName && catName !== 'N/A') {
                        cat.name = catName;
                        categoryNameCache[cat.id] = catName;
                    }
                } catch (error) {
                    console.log(`Failed to fetch category name for ${cat.id}:`, error);
                }
            }
        }));
        
        // Log any failures (though individual errors are already caught above)
        categoryNameResults.forEach((result, index) => {
            if (result.status === 'rejected') {
                console.error(`Failed to process category name for ${categoriesArray[index].id}:`, result.reason);
            }
        });
        
        // Build category tree with only categories that have products
        await buildCategoryTreeWithProducts(categoriesArray);
        
        // Store categories for use with PrestaShop export/mapping and dropdowns
        allCategories = categoriesArray;
        categoriesWithProducts = categoriesArray;
        
        // Update category select dropdown in the Offers section
        updateCategorySelect();
        
        // Update dashboard stats
        updateDashboardStats();
        
        if (categoriesArray.length === 0) {
            categoriesListEl.innerHTML = '<p style="text-align: center; padding: 20px; color: #666;">No categories found in your offers. Load offers to see categories.</p>';
        } else {
            // Display the category tree in the sidebar - use forceReload=true to ensure fresh data is displayed
            // This ensures categories are only displayed after fresh data is completely fetched and processed
            await loadCategoryTreeRoot(true);
            
            // Show info message about category counts
            console.log(`✓ Categories loaded: ${categoriesArray.length} categories from ${allOffers.length} offers`);
            console.log('Note: Category counts reflect offers loaded from Allegro API. Some categories may not appear if they have no offers, or counts may differ from Allegro website if offers are filtered by status.');
        }

        // Data is always loaded fresh from Allegro API, no localStorage caching

        // Categories changed, refresh CSV export buttons state
        updateCsvExportButtonsState();

        // Enable sync button if categories are loaded and PrestaShop is configured
        updateSyncCategoryButtonState();
    } catch (error) {
        console.error('Error loading categories from offers:', error);
        let errorMessage = 'Failed to load categories. Please try again.';
        
        // Provide more specific error messages
        if (error.message) {
            if (error.message.includes('OAuth') || error.message.includes('authorize')) {
                errorMessage = error.message;
            } else if (error.message.includes('credentials') || error.message.includes('Client')) {
                errorMessage = error.message + ' Please check your credentials and try again.';
            } else {
                errorMessage = error.message;
            }
        }
        
        categoriesListEl.innerHTML = `<p style="text-align: center; padding: 20px; color: #c5221f;">${escapeHtml(errorMessage)}</p>`;
    }
}

// Legacy function - kept for backward compatibility but redirects to loadCategoriesFromOffers
async function loadCategories() {
    await loadCategoriesFromOffers();
}

// -----------------------------
// Allegro category tree (sidebar)
// -----------------------------

// Load root-level Allegro categories and render tree in sidebar
async function loadCategoryTreeRoot(forceReload = false) {
    if (!validateAuth() || !isOAuthConnected) {
        return;
    }

    const rootKey = 'root';
    
    // If forcing reload, skip all cache checks and go directly to loadCategoryTreeLevel
    if (forceReload) {
        await loadCategoryTreeLevel(null, [], forceReload);
        return;
    }
    
    // If we have a tree with products (which includes counts), use it instead of cache
    if (Object.keys(categoryTreeWithProducts).length > 0) {
        await loadCategoryTreeLevel(null, [], forceReload);
        return;
    }
    
    // Otherwise, use cache if available and not forcing reload
    if (categoryTreeInitialized && categoryTreeCache[rootKey]) {
        await displayCategories(categoryTreeCache[rootKey], []);
        return;
    }

    await loadCategoryTreeLevel(null, [], forceReload);
}

// Load a specific level of the Allegro category tree by parent ID
async function loadCategoryTreeLevel(parentId = null, path = [], forceReload = false) {
    if (!validateAuth() || !isOAuthConnected) {
        return;
    }

    const categoriesListEl = document.getElementById('categoriesList');
    if (!categoriesListEl) return;

    const key = parentId || 'root';
    categoryTreePath = path || [];
    
    // If forcing reload, skip cache and only use fresh categoryTreeWithProducts if available
    if (forceReload) {
        // Only use categoryTreeWithProducts if it has data (fresh data from loadCategoriesFromOffers)
        // If no fresh data available yet, don't display anything - wait for fresh data
        if (Object.keys(categoryTreeWithProducts).length > 0) {
            const categories = getCategoryChildren(parentId, categoryTreeWithProducts);
            
            // Sort categories by name
            categories.sort((a, b) => {
                const nameA = (a.name || '').toLowerCase();
                const nameB = (b.name || '').toLowerCase();
                return nameA.localeCompare(nameB);
            });
            
            categoryTreeCache[key] = categories;
            categoryTreeInitialized = true;
            await displayCategories(categories, categoryTreePath);
            return;
        }
        // If forceReload but no fresh data yet, don't display anything - just return
        // This prevents displaying stale cached data
        return;
    } else {
        // If we have a built tree with products, use it instead of fetching from API
        if (Object.keys(categoryTreeWithProducts).length > 0) {
            const categories = getCategoryChildren(parentId, categoryTreeWithProducts);
            
            // Sort categories by name
            categories.sort((a, b) => {
                const nameA = (a.name || '').toLowerCase();
                const nameB = (b.name || '').toLowerCase();
                return nameA.localeCompare(nameB);
            });
            
            categoryTreeCache[key] = categories;
            categoryTreeInitialized = true;
            await displayCategories(categories, categoryTreePath);
            return;
        }

        // Fallback to cache if available and not forcing reload
        if (categoryTreeCache[key]) {
            await displayCategories(categoryTreeCache[key], categoryTreePath);
            categoryTreeInitialized = true;
            return;
        }
    }

    categoriesListEl.innerHTML = '<div style="text-align: center; padding: 20px; color: #1a73e8; font-size: 0.9em;">Loading Allegro categories…</div>';

    try {
        let url = `${API_BASE}/api/categories`;
        if (parentId) {
            url += `?parentId=${encodeURIComponent(parentId)}`;
        }

        const response = await fetch(url);
        if (!response.ok) {
            throw new Error('Failed to load categories from Allegro.');
        }

        const result = await response.json();
        const categories = result?.data?.categories || [];

        categoryTreeCache[key] = categories;
        categoryTreeInitialized = true;

        await displayCategories(categories, categoryTreePath);
    } catch (error) {
        console.error('Error loading Allegro category tree:', error);
        categoriesListEl.innerHTML = `<p style="text-align: center; padding: 20px; color: #c5221f;">Failed to load categories. ${escapeHtml(error.message || 'Please try again.')}</p>`;
    }
}

// Fetch category name by ID
async function fetchCategoryName(categoryId) {
    if (!categoryId || categoryId === 'N/A') {
        return 'N/A';
    }
    
    // Check cache first
    if (categoryNameCache[categoryId]) {
        return categoryNameCache[categoryId];
    }
    
    try {
        const response = await authFetch(`${API_BASE}/api/categories/${categoryId}`);
        if (!response.ok) {
            return 'N/A';
        }
        
        const result = await response.json();
        if (result.success && result.data && result.data.name) {
            const categoryName = result.data.name;
            // Cache it
            categoryNameCache[categoryId] = categoryName;
            return categoryName;
        }
    } catch (error) {
        console.log(`Error fetching category name for ID ${categoryId}:`, error);
    }
    
    return 'N/A';
}

// Display categories
async function displayCategories(categories, pathOverride) {
    const categoriesListEl = document.getElementById('categoriesList');
    if (!categoriesListEl) return;

    const path = Array.isArray(pathOverride) ? pathOverride : (categoryTreePath || []);
    let categoriesToDisplay = Array.isArray(categories) ? [...categories] : [];

    const htmlParts = [];

    // Breadcrumb showing where we are in the tree
    if (path.length > 0) {
        const breadcrumb = path
            .map(p => escapeHtml(p.name || `Category ${p.id}`))
            .join(' / ');
        htmlParts.push(`<div class="category-breadcrumb">${breadcrumb}</div>`);

        const prevPath = path.slice(0, -1);
        const prevName = prevPath.length > 0
            ? prevPath[prevPath.length - 1].name
            : 'root categories';
        htmlParts.push(`
            <div class="category-back" data-role="back">
                go back to ${escapeHtml(prevName || 'root categories')}
            </div>
        `);
    }

    // "All Categories" item to clear filter and go back to root
    const allCategoriesSelected = selectedCategoryId === null;
    // Use API totalCount if available (more accurate), otherwise fall back to loaded offers count
    const totalOffersCount = totalOffersCountFromAPI !== null ? totalOffersCountFromAPI : (allLoadedOffers ? allLoadedOffers.length : 0);
    htmlParts.push(`
        <div class="category-item ${allCategoriesSelected ? 'selected' : ''}" data-role="all">
            <span class="category-item-name">All Categories</span>
            ${totalOffersCount > 0 ? `<span class="category-item-count">${totalOffersCount}</span>` : ''}
        </div>
    `);

    if (!categoriesToDisplay || categoriesToDisplay.length === 0) {
        htmlParts.push('<p style="text-align: center; padding: 20px; color: #1a73e8;">No subcategories found.</p>');
        categoriesListEl.innerHTML = htmlParts.join('');
    } else {
        // Render current level categories
        htmlParts.push(
            categoriesToDisplay.map(category => {
                const isSelected = selectedCategoryId !== null &&
                    String(selectedCategoryId) === String(category.id);
                const safeName = escapeHtml(category.name || 'Unnamed Category');
                const isLeaf = !!category.leaf;
                const count = category.count || 0;
                return `
                    <div class="category-item ${isSelected ? 'selected' : ''}"
                         data-category-id="${category.id}"
                         data-category-name="${safeName}"
                         data-leaf="${isLeaf ? 'true' : 'false'}">
                        <span class="category-item-name">${safeName}</span>
                        <div class="category-item-right">
                            ${count > 0 ? `<span class="category-item-count">${count}</span>` : ''}
                            ${isLeaf ? '' : '<span class="category-chevron">›</span>'}
                        </div>
                    </div>
                `;
            }).join('')
        );

        categoriesListEl.innerHTML = htmlParts.join('');
    }

    // "All Categories" handler
    const allItem = categoriesListEl.querySelector('.category-item[data-role="all"]');
    if (allItem) {
        allItem.addEventListener('click', () => {
            selectCategory(null); // reset filter
            // Reset tree to root without forcing reload (will reuse cache)
            loadCategoryTreeRoot(false);
        });
    }

    // Back navigation handler
    const backEl = categoriesListEl.querySelector('.category-back[data-role="back"]');
    if (backEl) {
        backEl.addEventListener('click', () => {
            const prevPath = path.slice(0, -1);
            const prevParentId = prevPath.length > 0 ? prevPath[prevPath.length - 1].id : null;
            loadCategoryTreeLevel(prevParentId, prevPath);
        });
    }

    // Category click handlers (select + navigate deeper if non-leaf)
    categoriesListEl.querySelectorAll('.category-item[data-category-id]').forEach(item => {
        item.addEventListener('click', () => {
            const categoryId = item.dataset.categoryId;
            const categoryName = item.dataset.categoryName || '';
            const isLeaf = item.dataset.leaf === 'true';

            if (categoryId) {
                // Use standard selection logic to filter offers
                selectCategory(categoryId);
            }

            // Navigate to subcategories for non-leaf categories
            if (!isLeaf && categoryId) {
                const newPath = [...path, { id: categoryId, name: categoryName }];
                loadCategoryTreeLevel(categoryId, newPath);
            }
        });
    });
}

// Select a category
function selectCategory(categoryId) {
    selectedCategoryId = categoryId;
    
    // Update visual selection
    document.querySelectorAll('.category-item').forEach(item => {
        const itemCategoryId = item.dataset.categoryId;
        if (categoryId === null && itemCategoryId === 'all') {
            item.classList.add('selected');
        } else if (categoryId !== null && itemCategoryId === categoryId) {
            item.classList.add('selected');
        } else {
            item.classList.remove('selected');
        }
    });
    
    // Update select dropdown
    const selectedCategorySelect = document.getElementById('selectedCategory');
    if (selectedCategorySelect) {
        selectedCategorySelect.value = categoryId || '';
    }
    
    // Filter and re-display existing offers if any are loaded
    if (allLoadedOffers.length > 0) {
        // Filter offers based on selected category
        let filteredOffers = allLoadedOffers;
        if (categoryId !== null) {
            // Include offers from the selected category AND all its subcategories
            const categoryIdsToMatch = getCategoryAndDescendantIds(categoryId);

            filteredOffers = allLoadedOffers.filter(offer => {
                let offerCategoryId = null;
                if (offer.category) {
                    if (typeof offer.category === 'string') {
                        offerCategoryId = offer.category;
                    } else if (offer.category.id) {
                        offerCategoryId = offer.category.id;
                    }
                }
                return offerCategoryId && categoryIdsToMatch.includes(String(offerCategoryId));
            });
        }
        
        // Update current offers and paginate
        currentOffers = filteredOffers;
        totalCount = filteredOffers.length;
        
        // Reset pagination
        currentOffset = 0;
        currentPageNumber = 1;
        pageHistory = [];
        totalProductsSeen = 0;
        
        // Display first page
        displayOffersPage();
    } else if (currentOffers.length > 0) {
        // Fallback: filter current offers if allLoadedOffers is empty
        displayOffers(currentOffers);
    }
}


// Update category select dropdown
function updateCategorySelect() {
    const selectedCategorySelect = document.getElementById('selectedCategory');
    if (!selectedCategorySelect) return;
    
    // Keep "All Categories" option
    selectedCategorySelect.innerHTML = '<option value="">All Categories</option>';
    
    // Add all categories
    allCategories.forEach(category => {
        const option = document.createElement('option');
        option.value = category.id;
        option.textContent = category.name || `Category ${category.id}`;
        selectedCategorySelect.appendChild(option);
    });
    
    // Restore selection if any
    if (selectedCategoryId) {
        selectedCategorySelect.value = selectedCategoryId;
    }
    
    // Remove existing listeners and add new one
    const newSelect = selectedCategorySelect.cloneNode(true);
    selectedCategorySelect.parentNode.replaceChild(newSelect, selectedCategorySelect);
    
    // Add change listener to new select element
    newSelect.addEventListener('change', (e) => {
        const categoryId = e.target.value || null;
        selectedCategoryId = categoryId;
        
        // Update visual selection in category list
        document.querySelectorAll('.category-item').forEach(item => {
            if (item.dataset.categoryId === categoryId) {
                item.classList.add('selected');
            } else {
                item.classList.remove('selected');
            }
        });
        
        // If no category selected (All Categories), clear selection and re-display all products
        if (!categoryId) {
            selectedCategoryId = null;
            document.querySelectorAll('.category-item').forEach(item => {
                if (item.dataset.categoryId === 'all') {
                    item.classList.add('selected');
                } else {
                    item.classList.remove('selected');
                }
            });
            // Re-display existing offers without category filter
            if (allLoadedOffers.length > 0) {
                currentOffers = allLoadedOffers;
                currentOffset = 0;
                currentPageNumber = 1;
                pageHistory = [];
                displayOffersPage();
            } else {
                document.getElementById('offersList').innerHTML = '';
                document.getElementById('pagination').style.display = 'none';
            }
            return;
        }
        
        // Filter and re-display existing offers if any are loaded
        if (allLoadedOffers.length > 0) {
            // Filter offers based on selected category
            currentOffers = allLoadedOffers.filter(offer => {
                let offerCategoryId = null;
                if (offer.category) {
                    if (typeof offer.category === 'string') {
                        offerCategoryId = offer.category;
                    } else if (offer.category.id) {
                        offerCategoryId = offer.category.id;
                    }
                }
                return offerCategoryId && String(offerCategoryId) === String(categoryId);
            });
            
            // Reset pagination
            currentOffset = 0;
            currentPageNumber = 1;
            pageHistory = [];
            displayOffersPage();
        }
    });
}

// Clear category selection
function clearCategorySelection() {
    selectedCategoryId = null; // null means "All Categories"
    
    // Update select dropdown
    const selectedCategorySelect = document.getElementById('selectedCategory');
    if (selectedCategorySelect) {
        selectedCategorySelect.value = '';
    }
    
    // Update visual selection - select "All Categories"
    document.querySelectorAll('.category-item').forEach(item => {
        if (item.dataset.categoryId === 'all') {
            item.classList.add('selected');
        } else {
            item.classList.remove('selected');
        }
    });
    
    // If we have loaded offers, show all of them
    if (allLoadedOffers.length > 0) {
        currentOffers = allLoadedOffers;
        currentOffset = 0;
        currentPageNumber = 1;
        pageHistory = [];
        totalProductsSeen = 0;
        displayOffersPage();
    } else {
        // Clear product results if no offers loaded
        document.getElementById('offersList').innerHTML = '';
        document.getElementById('pagination').style.display = 'none';
        currentOffers = [];
        currentOffset = 0;
        pageHistory = [];
        currentPageNumber = 1; // Reset to first page
        totalProductsSeen = 0;
    }
    updateImportButtons();
}

// Close error message
function closeErrorMessage() {
    const errorEl = document.getElementById('errorMessage');
    if (errorEl) {
        errorEl.classList.add('hiding');
        setTimeout(() => {
            errorEl.style.display = 'none';
            errorEl.classList.remove('hiding');
            errorEl.style.marginBottom = '0';
        }, 300);
    }
}

// Setup collapsible config panel
function setupConfigPanelToggle() {
    const toggle = document.getElementById('configPanelToggle');
    const wrapper = document.querySelector('.config-panel-wrapper');
    
    if (!toggle || !wrapper) {
        console.warn('Config panel toggle elements not found');
        return;
    }
    
    // Check if config is already set (both Allegro and PrestaShop)
    // Use safe checks for variables that might not be defined yet
    try {
        const isConfigured = checkAuthentication() && 
                            (typeof prestashopConfigured !== 'undefined' && prestashopConfigured) && 
                            (typeof prestashopAuthorized !== 'undefined' && prestashopAuthorized);
        if (isConfigured) {
            wrapper.classList.add('collapsed');
        }
    } catch (e) {
        // If variables don't exist, start with panel expanded (default)
        console.log('Config variables not initialized, starting with panel expanded');
    }
    
    // Remove any existing click listeners by using a named function we can remove
    // Store the handler function on the element for potential cleanup
    if (toggle._configToggleHandler) {
        toggle.removeEventListener('click', toggle._configToggleHandler);
    }
    
    // Create and store the handler
    toggle._configToggleHandler = function(e) {
        e.preventDefault();
        e.stopPropagation();
        wrapper.classList.toggle('collapsed');
    };
    
    // Add click event listener
    toggle.addEventListener('click', toggle._configToggleHandler);
}

// Setup tab navigation
function setupTabNavigation() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.getAttribute('data-tab');
            
            // Remove active class from all tabs and contents
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));
            
            // Add active class to clicked tab and corresponding content
            button.classList.add('active');
            const targetContent = document.getElementById(`tab-${targetTab}`);
            if (targetContent) {
                targetContent.classList.add('active');
                
                // Load sync statistics when sync-log tab is opened
                if (targetTab === 'sync-log') {
                    loadSyncStatistics();
                    checkSyncPrerequisites();
                    updateSyncControlButtons();
                    // Start real-time timer updates
                    startSyncTimer();
                } else if (targetTab === 'sync-category-log') {
                    // Load category sync status when category sync tab is opened
                    checkCategorySyncPrerequisites();
                    updateCategorySyncControlButtons();
                    // Start real-time timer updates
                    startCategorySyncTimer();
                    // Load category sync statistics
                    loadCategorySyncStatistics();
                } else if (targetTab === 'user-management') {
                    // Load users when user-management tab is opened
                    loadUsers();
                } else {
                    // Stop long polling when switching away from sync-log tab
                    if (window.syncStatisticsLongPoll) {
                        window.syncStatisticsLongPoll = false;
                    }
                    // Stop category sync statistics long polling when switching away
                    if (window.categorySyncStatisticsLongPoll) {
                        window.categorySyncStatisticsLongPoll = false;
                    }
                    // Stop timer when switching away
                    if (syncTimerInterval) {
                        clearInterval(syncTimerInterval);
                        syncTimerInterval = null;
                    }
                    // Stop category sync timer when switching away
                    if (categorySyncTimerInterval) {
                        clearInterval(categorySyncTimerInterval);
                        categorySyncTimerInterval = null;
                    }
                }
            }
        });
    });
}

// Update dashboard stats
function updateDashboardStats() {
    // Update offers count
    const statsOffersCount = document.getElementById('statsOffersCount');
    if (statsOffersCount) {
        try {
            const filteredOffers = typeof getOffersFilteredByStatus === 'function' ? getOffersFilteredByStatus() : allLoadedOffers;
            statsOffersCount.textContent = filteredOffers ? filteredOffers.length : (allLoadedOffers.length || 0);
        } catch (e) {
            statsOffersCount.textContent = allLoadedOffers.length || 0;
        }
    }
    
    // Update imported count
    const statsImportedCount = document.getElementById('statsImportedCount');
    if (statsImportedCount) {
        statsImportedCount.textContent = importedOffers.length || 0;
    }
    
    // Update categories count
    const statsCategoriesCount = document.getElementById('statsCategoriesCount');
    if (statsCategoriesCount) {
        statsCategoriesCount.textContent = allCategories.length || 0;
    }
    
    // Update active offers count
    const statsActiveCount = document.getElementById('statsActiveCount');
    if (statsActiveCount) {
        const activeOffers = (allLoadedOffers || []).filter(offer => 
            offer.publication && offer.publication.status === 'ACTIVE'
        );
        statsActiveCount.textContent = activeOffers.length || 0;
    }
}

// Utility functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function truncateText(text, maxLength) {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

// Sync Statistics Functions with Long Polling
let lastKnownSyncEndTime = null;

async function loadSyncStatistics() {
    const syncStatisticsList = document.getElementById('syncStatisticsList');
    const syncStatisticsLoading = document.getElementById('syncStatisticsLoading');
    
    if (!syncStatisticsList) return;
    
    try {
        // Show loading indicator if waiting for sync
        const userState = await getSyncStatus();
        if (userState && userState.running) {
            syncStatisticsLoading.style.display = 'block';
        }
        
        // Start long polling
        window.syncStatisticsLongPoll = true;
        await longPollSyncStatistics();
    } catch (error) {
        console.error('Error loading sync statistics:', error);
        syncStatisticsLoading.style.display = 'none';
        syncStatisticsList.innerHTML = '<div class="sync-statistics-empty">Error loading sync statistics. Please refresh.</div>';
    }
}

async function longPollSyncStatistics() {
    const syncStatisticsList = document.getElementById('syncStatisticsList');
    const syncStatisticsLoading = document.getElementById('syncStatisticsLoading');
    
    if (!window.syncStatisticsLongPoll) {
        syncStatisticsLoading.style.display = 'none';
        return;
    }
    
    try {
        const url = `/api/sync/statistics?longPoll=true&timeout=60000${lastKnownSyncEndTime ? `&lastSyncEndTime=${encodeURIComponent(lastKnownSyncEndTime)}` : ''}`;
        const response = await authFetch(url);
        const data = await response.json();
        
        if (data.success) {
            displaySyncStatistics(data.statistics);
            updateSyncStatus(data.lastSyncTime, data.nextSyncTime);
            
            // Update last known sync end time
            if (data.statistics && data.statistics.length > 0) {
                lastKnownSyncEndTime = data.statistics[0].syncEndTime;
            }
            
            // Hide loading if sync completed or if timeout occurred and sync is not running
            if (!data.running || (data.timeout && !data.running)) {
                syncStatisticsLoading.style.display = 'none';
            }
            
            // If sync is still running or we got a new sync, continue polling
            if (window.syncStatisticsLongPoll && (data.running || data.hasNewSync)) {
                // Immediately poll again if sync is running or new sync detected
                setTimeout(() => longPollSyncStatistics(), 100);
            } else if (window.syncStatisticsLongPoll) {
                // If not running, wait a bit longer before next poll
                setTimeout(() => longPollSyncStatistics(), 2000);
            }
        } else {
            syncStatisticsLoading.style.display = 'none';
            syncStatisticsList.innerHTML = '<div class="sync-statistics-empty">Error loading sync statistics.</div>';
            // Retry after delay
            if (window.syncStatisticsLongPoll) {
                setTimeout(() => longPollSyncStatistics(), 5000);
            }
        }
    } catch (error) {
        console.error('Error in long polling sync statistics:', error);
        syncStatisticsLoading.style.display = 'none';
        // Retry after delay
        if (window.syncStatisticsLongPoll) {
            setTimeout(() => longPollSyncStatistics(), 5000);
        }
    }
}

async function getSyncStatus() {
    try {
        const response = await authFetch('/api/sync/status');
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Error getting sync status:', error);
        return null;
    }
}

function displaySyncStatistics(statistics) {
    const syncStatisticsList = document.getElementById('syncStatisticsList');
    if (!syncStatisticsList) return;
    
    if (!statistics || statistics.length === 0) {
        syncStatisticsList.innerHTML = '<div class="sync-statistics-empty">No sync statistics yet. Sync will run automatically at configured intervals.</div>';
        return;
    }
    
    // Update input with x_rate from statistics (only if user hasn't manually changed it)
    if (statistics.length > 0 && statistics[0].xRate !== null && statistics[0].xRate !== undefined && !userChangedSlider) {
        const newXRate = parseFloat(statistics[0].xRate);
        lastXRate = newXRate;
        const input = document.getElementById('xRateInput');
        if (input && input.value !== newXRate.toString()) {
            input.value = newXRate;
        }
    }
    
    syncStatisticsList.innerHTML = statistics.map(stat => {
        const syncStartTime = stat.syncStartTime ? new Date(stat.syncStartTime).toLocaleString('en-US', {
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: true
        }) : 'N/A';
        
        const syncEndTime = stat.syncEndTime ? new Date(stat.syncEndTime).toLocaleString('en-US', {
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: true
        }) : 'N/A';
        
        const duration = stat.syncStartTime && stat.syncEndTime 
            ? formatDuration(new Date(stat.syncEndTime) - new Date(stat.syncStartTime))
            : 'N/A';
        
        return `
            <div class="sync-statistics-card">
                <div class="sync-statistics-header">
                    <div class="sync-statistics-time-section">
                        <div class="sync-statistics-time-item">
                            <div class="sync-statistics-icon time-icon">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/>
                                    <path d="M12 6V12L16 14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                                </svg>
                            </div>
                            <div class="sync-statistics-time-content">
                                <span class="sync-statistics-time-label">Start</span>
                                <span class="sync-statistics-time-value">${syncStartTime}</span>
                            </div>
                        </div>
                        <div class="sync-statistics-time-item">
                            <div class="sync-statistics-icon time-icon">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/>
                                    <path d="M12 6V12L16 14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                                </svg>
                            </div>
                            <div class="sync-statistics-time-content">
                                <span class="sync-statistics-time-label">End</span>
                                <span class="sync-statistics-time-value">${syncEndTime}</span>
                            </div>
                        </div>
                        <div class="sync-statistics-time-item">
                            <div class="sync-statistics-icon duration-icon">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M12 2L2 7L12 12L22 7L12 2Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                    <path d="M2 17L12 22L22 17" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                    <path d="M2 12L12 17L22 12" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            </div>
                            <div class="sync-statistics-time-content">
                                <span class="sync-statistics-time-label">Duration</span>
                                <span class="sync-statistics-time-value">${duration}</span>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="sync-statistics-metrics">
                    <div class="sync-statistics-metric-item">
                        <div class="sync-statistics-icon product-icon">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <path d="M21 16V8C20.9996 7.64928 20.9071 7.30481 20.7315 7.00116C20.556 6.69751 20.3037 6.44536 20 6.27L13 2.27C12.696 2.09446 12.3511 2.00205 12 2.00205C11.6489 2.00205 11.304 2.09446 11 2.27L4 6.27C3.69626 6.44536 3.44398 6.69751 3.26846 7.00116C3.09294 7.30481 3.00036 7.64928 3 8V16C3.00036 16.3507 3.09294 16.6952 3.26846 16.9988C3.44398 17.3025 3.69626 17.5546 4 17.73L11 21.73C11.304 21.9055 11.6489 21.9979 12 21.9979C12.3511 21.9979 12.696 21.9055 13 21.73L20 17.73C20.3037 17.5546 20.556 17.3025 20.7315 16.9988C20.9071 16.6952 20.9996 16.3507 21 16Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M3.27 6.96L12 12.01L20.73 6.96" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M12 22.08V12" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        </div>
                        <div class="sync-statistics-metric-content">
                            <span class="sync-statistics-metric-label">Prestashop product</span>
                            <span class="sync-statistics-metric-value">${stat.totalProductsChecked}</span>
                        </div>
                    </div>
                    <div class="sync-statistics-metric-item">
                        <div class="sync-statistics-icon stock-icon">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <path d="M6 9V20C6 20.5304 6.21071 21.0391 6.58579 21.4142C6.96086 21.7893 7.46957 22 8 22H16C16.5304 22 17.0391 21.7893 17.4142 21.4142C17.7893 21.0391 18 20.5304 18 20V9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M2 5H6V9H2V5Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M10 5H14V9H10V5Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M18 5H22V9H18V5Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M6 5V2C6 1.73478 6.10536 1.48043 6.29289 1.29289C6.48043 1.10536 6.73478 1 7 1H9C9.26522 1 9.51957 1.10536 9.70711 1.29289C9.89464 1.48043 10 1.73478 10 2V5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M14 5V2C14 1.73478 14.1054 1.48043 14.2929 1.29289C14.4804 1.10536 14.7348 1 15 1H17C17.2652 1 17.5196 1.10536 17.7071 1.29289C17.8946 1.48043 18 1.73478 18 2V5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        </div>
                        <div class="sync-statistics-metric-content">
                            <span class="sync-statistics-metric-label">Synced Stock</span>
                            <span class="sync-statistics-metric-value">${stat.stockSyncedCount}</span>
                        </div>
                    </div>
                    <div class="sync-statistics-metric-item">
                        <div class="sync-statistics-icon price-icon">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <path d="M12 2V22" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M17 5H9.5C8.57174 5 7.6815 5.36875 7.02513 6.02513C6.36875 6.6815 6 7.57174 6 8.5C6 9.42826 6.36875 10.3185 7.02513 10.9749C7.6815 11.6313 8.57174 12 9.5 12H14.5C15.4283 12 16.3185 12.3687 16.9749 13.0251C17.6313 13.6815 18 14.5717 18 15.5C18 16.4283 17.6313 17.3185 16.9749 17.9749C16.3185 18.6313 15.4283 19 14.5 19H6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        </div>
                        <div class="sync-statistics-metric-content">
                            <span class="sync-statistics-metric-label">Synced Price</span>
                            <span class="sync-statistics-metric-value">${stat.priceSyncedCount}</span>
                        </div>
                    </div>
                    ${stat.xRate !== null && stat.xRate !== undefined ? `
                    <div class="sync-statistics-metric-item">
                        <div class="sync-statistics-icon price-icon">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <circle cx="7" cy="7" r="3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <circle cx="17" cy="17" r="3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M19 5L5 19" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        </div>
                        <div class="sync-statistics-metric-content">
                            <span class="sync-statistics-metric-label">Price Rate (X)</span>
                            <span class="sync-statistics-metric-value price-rate-value">${parseFloat(stat.xRate).toFixed(2)}</span>
                        </div>
                    </div>
                    ` : ''}
                </div>
                ${stat.changedInfo && Array.isArray(stat.changedInfo) && stat.changedInfo.length > 0 ? `
                <div class="sync-statistics-changes">
                    <div class="sync-statistics-changes-header">
                        <h4>Changed Products (${stat.changedInfo.length})</h4>
                    </div>
                    <div class="sync-statistics-changes-list">
                        ${stat.changedInfo.map(change => {
                            const hasPriceChange = change.priceBefore !== change.priceAfter;
                            const hasStockChange = change.stockBefore !== change.stockAfter;
                            
                            return `
                            <div class="sync-statistics-change-item">
                                <div class="sync-statistics-change-product">
                                    <div class="sync-statistics-change-product-name">${escapeHtml(change.productName || 'Unknown Product')}</div>
                                    <div class="sync-statistics-change-product-ids">
                                        <span class="sync-statistics-change-id">PrestaShop ID: ${change.prestashopProductId}</span>
                                        ${change.allegroOfferId ? `<span class="sync-statistics-change-id">Allegro ID: ${change.allegroOfferId}</span>` : ''}
                                    </div>
                                </div>
                                <div class="sync-statistics-change-details">
                                    ${hasPriceChange ? `
                                    <div class="sync-statistics-change-detail">
                                        <span class="sync-statistics-change-label">Price:</span>
                                        <span class="sync-statistics-change-value">${formatPrice(change.priceBefore)} → ${formatPrice(change.priceAfter)}</span>
                                    </div>
                                    ` : ''}
                                    ${hasStockChange ? `
                                    <div class="sync-statistics-change-detail">
                                        <span class="sync-statistics-change-label">Stock:</span>
                                        <span class="sync-statistics-change-value">${change.stockBefore} → ${change.stockAfter}</span>
                                    </div>
                                    ` : ''}
                                </div>
                            </div>
                            `;
                        }).join('')}
                    </div>
                </div>
                ` : ''}
            </div>
        `;
    }).join('');
}

// Category Sync Statistics Functions with Long Polling
let lastKnownCategorySyncEndTime = null;

async function loadCategorySyncStatistics() {
    const categorySyncStatisticsList = document.getElementById('categorySyncStatisticsList');
    const categorySyncStatisticsLoading = document.getElementById('categorySyncStatisticsLoading');
    
    if (!categorySyncStatisticsList) return;
    
    try {
        // Show loading indicator
        categorySyncStatisticsLoading.style.display = 'block';
        
        // Start long polling
        window.categorySyncStatisticsLongPoll = true;
        await longPollCategorySyncStatistics();
    } catch (error) {
        console.error('Error loading category sync statistics:', error);
        if (categorySyncStatisticsLoading) {
            categorySyncStatisticsLoading.style.display = 'none';
        }
        if (categorySyncStatisticsList) {
            categorySyncStatisticsList.innerHTML = '<div class="sync-statistics-empty">Error loading category sync statistics. Please refresh.</div>';
        }
    }
}

async function longPollCategorySyncStatistics() {
    const categorySyncStatisticsList = document.getElementById('categorySyncStatisticsList');
    const categorySyncStatisticsLoading = document.getElementById('categorySyncStatisticsLoading');
    
    if (!window.categorySyncStatisticsLongPoll) {
        if (categorySyncStatisticsLoading) {
            categorySyncStatisticsLoading.style.display = 'none';
        }
        return;
    }
    
    try {
        const url = `/api/category-sync/statistics?longPoll=true&timeout=60000${lastKnownCategorySyncEndTime ? `&lastSyncEndTime=${encodeURIComponent(lastKnownCategorySyncEndTime)}` : ''}`;
        const response = await authFetch(url);
        const data = await response.json();
        
        if (data.success) {
            displayCategorySyncStatistics(data.statistics);
            
            // Update last known sync end time
            if (data.statistics && data.statistics.length > 0) {
                lastKnownCategorySyncEndTime = data.statistics[0].syncEndTime;
            }
            
            // Hide loading
            if (categorySyncStatisticsLoading) {
                categorySyncStatisticsLoading.style.display = 'none';
            }
            
            // If we got a new sync, continue polling
            if (window.categorySyncStatisticsLongPoll && data.hasNewSync) {
                // Immediately poll again if new sync detected
                setTimeout(() => longPollCategorySyncStatistics(), 100);
            } else if (window.categorySyncStatisticsLongPoll) {
                // If not running, wait a bit longer before next poll
                setTimeout(() => longPollCategorySyncStatistics(), 2000);
            }
        } else {
            if (categorySyncStatisticsLoading) {
                categorySyncStatisticsLoading.style.display = 'none';
            }
            if (categorySyncStatisticsList) {
                categorySyncStatisticsList.innerHTML = '<div class="sync-statistics-empty">Error loading category sync statistics.</div>';
            }
            // Retry after delay
            if (window.categorySyncStatisticsLongPoll) {
                setTimeout(() => longPollCategorySyncStatistics(), 5000);
            }
        }
    } catch (error) {
        console.error('Error in long polling category sync statistics:', error);
        if (categorySyncStatisticsLoading) {
            categorySyncStatisticsLoading.style.display = 'none';
        }
        // Retry after delay
        if (window.categorySyncStatisticsLongPoll) {
            setTimeout(() => longPollCategorySyncStatistics(), 5000);
        }
    }
}

function displayCategorySyncStatistics(statistics) {
    const categorySyncStatisticsList = document.getElementById('categorySyncStatisticsList');
    if (!categorySyncStatisticsList) return;
    
    if (!statistics || statistics.length === 0) {
        categorySyncStatisticsList.innerHTML = '<div class="sync-statistics-empty">No category sync statistics available yet.</div>';
        return;
    }
    
    categorySyncStatisticsList.innerHTML = statistics.map(stat => {
        const syncStartTime = stat.syncStartTime ?
            new Date(stat.syncStartTime).toLocaleString('en-US', {
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: true
            }) : 'N/A';
        
        const syncEndTime = stat.syncEndTime ? new Date(stat.syncEndTime).toLocaleString('en-US', {
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: true
        }) : 'N/A';
        
        const duration = stat.syncStartTime && stat.syncEndTime 
            ? formatDuration(new Date(stat.syncEndTime) - new Date(stat.syncStartTime))
            : 'N/A';
        
        return `
            <div class="sync-statistics-card">
                <div class="sync-statistics-header">
                    <div class="sync-statistics-time-section">
                        <div class="sync-statistics-time-item">
                            <div class="sync-statistics-icon time-icon">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/>
                                    <path d="M12 6V12L16 14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                                </svg>
                            </div>
                            <div class="sync-statistics-time-content">
                                <span class="sync-statistics-time-label">Start</span>
                                <span class="sync-statistics-time-value">${syncStartTime}</span>
                            </div>
                        </div>
                        <div class="sync-statistics-time-item">
                            <div class="sync-statistics-icon time-icon">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/>
                                    <path d="M12 6V12L16 14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                                </svg>
                            </div>
                            <div class="sync-statistics-time-content">
                                <span class="sync-statistics-time-label">End</span>
                                <span class="sync-statistics-time-value">${syncEndTime}</span>
                            </div>
                        </div>
                        <div class="sync-statistics-time-item">
                            <div class="sync-statistics-icon time-icon">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M12 2L2 7L12 12L22 7L12 2Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                    <path d="M2 17L12 22L22 17" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                    <path d="M2 12L12 17L22 12" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            </div>
                            <div class="sync-statistics-time-content">
                                <span class="sync-statistics-time-label">Duration</span>
                                <span class="sync-statistics-time-value">${duration}</span>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="sync-statistics-body">
                    <div class="sync-statistics-time-section">
                        <div class="sync-statistics-time-item">
                            <div class="sync-statistics-icon time-icon">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M9 11L12 14L22 4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                    <path d="M21 12V19C21 19.5304 20.7893 20.0391 20.4142 20.4142C20.0391 20.7893 19.5304 21 19 21H5C4.46957 21 3.96086 20.7893 3.58579 20.4142C3.21071 20.0391 3 19.5304 3 19V5C3 4.46957 3.21071 3.96086 3.58579 3.58579C3.96086 3.21071 4.46957 3 5 3H16" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            </div>
                            <div class="sync-statistics-time-content">
                                <span class="sync-statistics-time-label">Total Checked</span>
                                <span class="sync-statistics-time-value">${stat.totalCategoriesChecked || 0}</span>
                            </div>
                        </div>
                        <div class="sync-statistics-time-item">
                            <div class="sync-statistics-icon duration-icon">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M12 5V19M5 12H19" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            </div>
                            <div class="sync-statistics-time-content">
                                <span class="sync-statistics-time-label">Created</span>
                                <span class="sync-statistics-time-value">${stat.categoriesCreatedCount || 0}</span>
                            </div>
                        </div>
                        <div class="sync-statistics-time-item">
                            <div class="sync-statistics-icon time-icon">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M9 12L11 14L15 10M21 12C21 16.9706 16.9706 21 12 21C7.02944 21 3 16.9706 3 12C3 7.02944 7.02944 3 12 3C16.9706 3 21 7.02944 21 12Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            </div>
                            <div class="sync-statistics-time-content">
                                <span class="sync-statistics-time-label">PrestaShop Categories</span>
                                <span class="sync-statistics-time-value">${stat.categoriesExistingCount || 0}</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatPrice(price) {
    if (price === null || price === undefined) return 'N/A';
    return parseFloat(price).toFixed(2) + ' PLN';
}

function formatDuration(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
        return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    } else if (minutes > 0) {
        return `${minutes}m ${seconds % 60}s`;
    } else {
        return `${seconds}s`;
    }
}

// All old sync log display code removed - replaced with sync statistics display

// Store sync times for real-time updates
let currentLastSyncTime = null;
let currentNextSyncTime = null;
let syncTimerInterval = null;
let isTimerActive = false; // Track if sync timer is running

// Store category sync times for real-time updates
let currentCategoryLastSyncTime = null;
let currentCategoryNextSyncTime = null;
let categorySyncTimerInterval = null;
let isCategoryTimerActive = false; // Track if category sync timer is running
let categorySyncCheckInterval = null; // Interval to check if it's time to sync categories
let isCategorySyncInProgress = false; // Track if a manual category sync is currently in progress

function updateSyncStatus(lastSyncTime, nextSyncTime) {
    currentLastSyncTime = lastSyncTime;
    currentNextSyncTime = nextSyncTime;
    
    const lastSyncTimeEl = document.getElementById('lastSyncTime');
    const nextSyncTimeEl = document.getElementById('nextSyncTime');
    
    if (lastSyncTimeEl) {
        if (lastSyncTime) {
            const lastSync = new Date(lastSyncTime);
            lastSyncTimeEl.textContent = lastSync.toLocaleString('en-US', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
        } else {
            lastSyncTimeEl.textContent = 'Never';
        }
    }
    
    if (nextSyncTimeEl) {
        if (nextSyncTime) {
            const nextSync = new Date(nextSyncTime);
            nextSyncTimeEl.textContent = nextSync.toLocaleString('en-US', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
        } else {
            nextSyncTimeEl.textContent = 'Calculating...';
        }
    }
    
    // Start real-time timer updates
    startSyncTimer();
}

function startSyncTimer() {
    // Clear existing timer if any
    if (syncTimerInterval) {
        clearInterval(syncTimerInterval);
    }
    
    // Update immediately
    updateSyncTimers();
    
    // Update every second
    syncTimerInterval = setInterval(() => {
        updateSyncTimers();
    }, 1000);
}

function updateSyncTimers() {
    const timeSinceEl = document.getElementById('timeSinceLastSync');
    const timeUntilEl = document.getElementById('timeUntilNextSync');
    
    // Update "time since last sync"
    if (timeSinceEl && currentLastSyncTime) {
        const lastSync = new Date(currentLastSyncTime);
        const now = new Date();
        const elapsed = Math.floor((now - lastSync) / 1000); // seconds
        timeSinceEl.textContent = `(${formatTimeElapsed(elapsed)} ago)`;
        timeSinceEl.style.color = '#666';
    } else if (timeSinceEl) {
        timeSinceEl.textContent = '';
    }
    
    // Update "time until next sync"
    if (timeUntilEl) {
        if (!isTimerActive) {
            // Timer is stopped - don't show next sync time
            timeUntilEl.textContent = '';
        } else if (currentNextSyncTime) {
            const nextSync = new Date(currentNextSyncTime);
            const now = new Date();
            const remaining = Math.floor((nextSync - now) / 1000); // seconds
            
            if (remaining > 0) {
                timeUntilEl.textContent = `(in ${formatTimeRemaining(remaining)})`;
                timeUntilEl.style.color = '#1a73e8';
            } else {
                // Timer is active and time has passed - sync should be running
                timeUntilEl.textContent = '(sync running...)';
                timeUntilEl.style.color = '#34a853';
            }
        } else {
            timeUntilEl.textContent = '';
        }
    }
}

function formatTimeElapsed(seconds) {
    if (seconds < 60) {
        return `${seconds}s`;
    } else if (seconds < 3600) {
        const minutes = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${minutes}m ${secs}s`;
    } else {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${minutes}m`;
    }
}

function formatTimeRemaining(seconds) {
    if (seconds < 60) {
        return `${seconds}s`;
    } else if (seconds < 3600) {
        const minutes = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${minutes}m ${secs}s`;
    } else {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${minutes}m`;
    }
}

// ============================================
// Sync Timer Control Functions
// ============================================

// Check if prerequisites are met for sync
async function checkSyncPrerequisites() {
    try {
        const response = await authFetch(`${API_BASE}/api/sync/prerequisites`);
        const data = await response.json();
        
        const msgEl = document.getElementById('syncPrerequisitesMsg');
        if (!msgEl) return;
        
        if (data.success && data.prerequisitesMet) {
            msgEl.style.display = 'none';
            return true;
        } else {
            msgEl.style.display = 'block';
            msgEl.className = 'message error';
            
            // Check if data.details exists before accessing it
            if (data.details) {
                const missing = [];
                if (!data.details.prestashopConfigured) missing.push('PrestaShop');
                if (!data.details.allegroConfigured) missing.push('Allegro');
                if (!data.details.hasOAuthToken) missing.push('Allegro OAuth');
                
                if (missing.length > 0) {
                    msgEl.textContent = `Missing prerequisites: ${missing.join(', ')}. Please configure all required settings first.`;
                } else if (data.message) {
                    msgEl.textContent = data.message;
                } else {
                    msgEl.textContent = 'Missing prerequisites. Please configure Allegro and PrestaShop first.';
                }
            } else if (data.message) {
                msgEl.textContent = data.message;
            } else if (data.error) {
                msgEl.textContent = `Error checking prerequisites: ${data.error}`;
            } else {
                msgEl.textContent = 'Unable to check prerequisites. Please try again.';
            }
            return false;
        }
    } catch (error) {
        console.error('Error checking prerequisites:', error);
        const msgEl = document.getElementById('syncPrerequisitesMsg');
        if (msgEl) {
            msgEl.style.display = 'block';
            msgEl.className = 'message error';
            msgEl.textContent = `Error checking prerequisites: ${error.message || 'Unknown error'}. Please try again.`;
        }
        return false;
    }
}

// Update sync control buttons based on status
async function updateSyncControlButtons() {
    try {
        const response = await authFetch(`${API_BASE}/api/sync/status`);
        const data = await response.json();
        
        const startBtn = document.getElementById('startSyncBtn');
        const stopBtn = document.getElementById('stopSyncBtn');
        const triggerBtn = document.getElementById('triggerSyncBtn');
        const statusEl = document.getElementById('syncTimerStatus');
        
        const prerequisitesMet = await checkSyncPrerequisites();
        
        if (startBtn) {
            startBtn.disabled = !prerequisitesMet || data.timerActive;
            if (data.timerActive) {
                startBtn.style.display = 'none';
            } else {
                startBtn.style.display = 'inline-block';
            }
        }
        
        if (stopBtn) {
            stopBtn.style.display = data.timerActive ? 'inline-block' : 'none';
        }
        
        if (triggerBtn) {
            triggerBtn.disabled = !prerequisitesMet;
        }
        
        if (statusEl) {
            statusEl.textContent = data.timerActive ? 'Running' : 'Stopped';
            statusEl.style.color = data.timerActive ? '#34a853' : '#ea4335';
        }
        
        // Store timer active state for use in updateSyncTimers
        isTimerActive = data.timerActive || false;
        
        // Update sync times
        if (data.lastSyncTime || data.nextSyncTime) {
            updateSyncStatus(data.lastSyncTime, data.nextSyncTime);
        } else {
            // If no next sync time and timer is stopped, clear it
            if (!data.timerActive) {
                currentNextSyncTime = null;
                const timeUntilEl = document.getElementById('timeUntilNextSync');
                if (timeUntilEl) {
                    timeUntilEl.textContent = '';
                }
            }
        }
    } catch (error) {
        console.error('Error updating sync control buttons:', error);
    }
}

// Update sync status from server
async function updateSyncStatusFromServer() {
    try {
        const response = await authFetch(`${API_BASE}/api/sync/status`);
        const data = await response.json();
        
        const statusEl = document.getElementById('syncTimerStatus');
        if (statusEl) {
            statusEl.textContent = data.timerActive ? 'Running' : 'Stopped';
            statusEl.style.color = data.timerActive ? '#34a853' : '#ea4335';
        }
        
        // Store timer active state for use in updateSyncTimers
        isTimerActive = data.timerActive || false;
        
        if (data.lastSyncTime || data.nextSyncTime) {
            updateSyncStatus(data.lastSyncTime, data.nextSyncTime);
        } else {
            // If no next sync time and timer is stopped, clear it
            if (!data.timerActive) {
                currentNextSyncTime = null;
                const timeUntilEl = document.getElementById('timeUntilNextSync');
                if (timeUntilEl) {
                    timeUntilEl.textContent = '';
                }
            }
        }
    } catch (error) {
        console.error('Error updating sync status:', error);
    }
}

// Start sync timer
async function startSyncTimerControl() {
    const startBtn = document.getElementById('startSyncBtn');
    const input = document.getElementById('xRateInput');
    
    if (!input) {
        showToast('Price rate input not found', 'error');
        return;
    }
    
    // Validate input value
    const rawValue = parseFloat(input.value);
    if (isNaN(rawValue) || rawValue < 0 || rawValue > 500) {
        showToast('Price rate must be between 0 and 500', 'error');
        input.focus();
        return;
    }
    
    const currentXRate = rawValue;
    
    // Check if x_rate differs from last sync
    if (lastXRate !== null && lastXRate !== undefined && Math.abs(currentXRate - lastXRate) > 0.01) {
        const confirmed = confirm(
            `The current price rate (X=${currentXRate}) differs from the last sync rate (X=${lastXRate}).\n\n` +
            `Do you want to use the current value (X=${currentXRate}) for automatic syncs?\n\n` +
            `Formula: PrestaShop price = Allegro price × ${currentXRate}/100\n\n` +
            `Note: A sync will be triggered immediately with this rate to save it.`
        );
        
        if (!confirmed) {
            return; // User cancelled
        }
        
        // Trigger a sync with the new x_rate to save it
        try {
            const syncResponse = await authFetch(`${API_BASE}/api/sync/trigger`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ xRate: currentXRate })
            });
            const syncData = await syncResponse.json();
            if (!syncData.success) {
                showToast('Failed to save price rate: ' + (syncData.error || 'Unknown error'), 'error');
                return;
            }
        } catch (error) {
            console.error('Error triggering sync to save x_rate:', error);
            showToast('Failed to save price rate: ' + error.message, 'error');
            return;
        }
    }
    
    if (startBtn) {
        startBtn.disabled = true;
        startBtn.querySelector('span').textContent = 'Starting...';
    }
    
    try {
        const response = await authFetch(`${API_BASE}/api/sync/start`, {
            method: 'POST'
        });
        const data = await response.json();
        
        if (data.success) {
            showToast('Sync timer started successfully', 'success');
            await updateSyncControlButtons();
        } else {
            showToast(data.error || 'Failed to start sync timer', 'error');
            await updateSyncControlButtons();
        }
    } catch (error) {
        console.error('Error starting sync timer:', error);
        showToast('Failed to start sync timer: ' + error.message, 'error');
        await updateSyncControlButtons();
    }
}

// Stop sync timer
async function stopSyncTimerControl() {
    const stopBtn = document.getElementById('stopSyncBtn');
    if (stopBtn) {
        stopBtn.disabled = true;
        stopBtn.querySelector('span').textContent = 'Stopping...';
    }
    
    try {
        const response = await authFetch(`${API_BASE}/api/sync/stop`, {
            method: 'POST'
        });
        const data = await response.json();
        
        if (data.success) {
            showToast('Sync timer stopped successfully', 'info');
            await updateSyncControlButtons();
        } else {
            showToast(data.error || 'Failed to stop sync timer', 'error');
            await updateSyncControlButtons();
        }
    } catch (error) {
        console.error('Error stopping sync timer:', error);
        showToast('Failed to stop sync timer: ' + error.message, 'error');
        await updateSyncControlButtons();
    }
}

// Get last x_rate from statistics
let lastXRate = 100;
let userChangedSlider = false; // Track if user manually changed input

// Trigger sync now
async function triggerSyncNow() {
    const triggerBtn = document.getElementById('triggerSyncBtn');
    const input = document.getElementById('xRateInput');
    
    if (!input) {
        showToast('Price rate input not found', 'error');
        return;
    }
    
    // Validate input value
    const rawValue = parseFloat(input.value);
    if (isNaN(rawValue) || rawValue < 0 || rawValue > 500) {
        showToast('Price rate must be between 0 and 500', 'error');
        input.focus();
        return;
    }
    
    const currentXRate = rawValue;
    
    // Check if x_rate differs from last sync
    if (lastXRate !== null && lastXRate !== undefined && Math.abs(currentXRate - lastXRate) > 0.01) {
        const confirmed = confirm(
            `The current price rate (X=${currentXRate}) differs from the last sync rate (X=${lastXRate}).\n\n` +
            `Do you want to use the current value (X=${currentXRate}) for this sync?\n\n` +
            `Formula: PrestaShop price = Allegro price × ${currentXRate}/100`
        );
        
        if (!confirmed) {
            return; // User cancelled
        }
    }
    
    if (triggerBtn) {
        triggerBtn.disabled = true;
        triggerBtn.querySelector('span').textContent = 'Running...';
    }
    
    try {
        const response = await authFetch(`${API_BASE}/api/sync/trigger`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ xRate: currentXRate })
        });
        const data = await response.json();
        
        if (data.success) {
            showToast('Sync triggered successfully', 'success');
            // Reset user changed flag after sync starts
            userChangedSlider = false;
            // Refresh statistics after a short delay
            setTimeout(() => {
                loadSyncStatistics();
                updateSyncStatusFromServer();
            }, 2000);
        } else {
            showToast(data.error || 'Failed to trigger sync', 'error');
        }
    } catch (error) {
        console.error('Error triggering sync:', error);
        showToast('Failed to trigger sync: ' + error.message, 'error');
    } finally {
        if (triggerBtn) {
            triggerBtn.disabled = false;
            triggerBtn.querySelector('span').textContent = 'Sync Now';
        }
    }
}

// ============================================
// Category Sync Timer Functions
// ============================================

function updateCategorySyncStatus(lastSyncTime, nextSyncTime) {
    currentCategoryLastSyncTime = lastSyncTime;
    currentCategoryNextSyncTime = nextSyncTime;
    
    const lastSyncTimeEl = document.getElementById('lastCategorySyncTime');
    const nextSyncTimeEl = document.getElementById('nextCategorySyncTime');
    
    if (lastSyncTimeEl) {
        if (lastSyncTime) {
            const lastSync = new Date(lastSyncTime);
            lastSyncTimeEl.textContent = lastSync.toLocaleString('en-US', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
        } else {
            lastSyncTimeEl.textContent = 'Never';
        }
    }
    
    if (nextSyncTimeEl) {
        if (nextSyncTime) {
            const nextSync = new Date(nextSyncTime);
            nextSyncTimeEl.textContent = nextSync.toLocaleString('en-US', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
        } else {
            nextSyncTimeEl.textContent = 'Calculating...';
        }
    }
    
    // Start real-time timer updates
    startCategorySyncTimer();
}

function startCategorySyncTimer() {
    // Clear existing timer if any
    if (categorySyncTimerInterval) {
        clearInterval(categorySyncTimerInterval);
    }
    
    // Update immediately
    updateCategorySyncTimers();
    
    // Update every second
    categorySyncTimerInterval = setInterval(() => {
        updateCategorySyncTimers();
    }, 1000);
}

function updateCategorySyncTimers() {
    const timeSinceEl = document.getElementById('timeSinceLastCategorySync');
    const timeUntilEl = document.getElementById('timeUntilNextCategorySync');
    
    // Update "time since last sync"
    if (timeSinceEl && currentCategoryLastSyncTime) {
        const lastSync = new Date(currentCategoryLastSyncTime);
        const now = new Date();
        const elapsed = Math.floor((now - lastSync) / 1000); // seconds
        timeSinceEl.textContent = `(${formatTimeElapsed(elapsed)} ago)`;
        timeSinceEl.style.color = '#666';
    } else if (timeSinceEl) {
        timeSinceEl.textContent = '';
    }
    
    // Update "time until next sync"
    if (timeUntilEl) {
        if (!isCategoryTimerActive) {
            // Timer is stopped - don't show next sync time
            timeUntilEl.textContent = '';
        } else if (currentCategoryNextSyncTime) {
            const nextSync = new Date(currentCategoryNextSyncTime);
            const now = new Date();
            const remaining = Math.floor((nextSync - now) / 1000); // seconds
            
            if (remaining > 0) {
                timeUntilEl.textContent = `(in ${formatTimeRemaining(remaining)})`;
                timeUntilEl.style.color = '#1a73e8';
            } else {
                // Timer is active and time has passed - sync should be running
                timeUntilEl.textContent = '(sync running...)';
                timeUntilEl.style.color = '#34a853';
            }
        } else {
            timeUntilEl.textContent = '';
        }
    }
}

// Check if prerequisites are met for category sync
async function checkCategorySyncPrerequisites() {
    try {
        const response = await authFetch(`${API_BASE}/api/sync/prerequisites`);
        const data = await response.json();
        
        const msgEl = document.getElementById('categorySyncPrerequisitesMsg');
        if (!msgEl) return;
        
        if (data.success && data.prerequisitesMet) {
            msgEl.style.display = 'none';
            return true;
        } else {
            msgEl.style.display = 'block';
            msgEl.className = 'message error';
            
            if (data.details) {
                const missing = [];
                if (!data.details.prestashopConfigured) missing.push('PrestaShop');
                if (!data.details.allegroConfigured) missing.push('Allegro');
                if (!data.details.hasOAuthToken) missing.push('Allegro OAuth');
                
                if (missing.length > 0) {
                    msgEl.textContent = `Missing prerequisites: ${missing.join(', ')}. Please configure all required settings first.`;
                } else if (data.message) {
                    msgEl.textContent = data.message;
                } else {
                    msgEl.textContent = 'Missing prerequisites. Please configure Allegro and PrestaShop first.';
                }
            } else if (data.message) {
                msgEl.textContent = data.message;
            } else if (data.error) {
                msgEl.textContent = `Error checking prerequisites: ${data.error}`;
            } else {
                msgEl.textContent = 'Unable to check prerequisites. Please try again.';
            }
            return false;
        }
    } catch (error) {
        console.error('Error checking prerequisites:', error);
        const msgEl = document.getElementById('categorySyncPrerequisitesMsg');
        if (msgEl) {
            msgEl.style.display = 'block';
            msgEl.className = 'message error';
            msgEl.textContent = `Error checking prerequisites: ${error.message || 'Unknown error'}. Please try again.`;
        }
        return false;
    }
}

// Update category sync control buttons based on status
async function updateCategorySyncControlButtons() {
    try {
        const response = await authFetch(`${API_BASE}/api/category-sync/status`);
        const data = await response.json();
        
        const startBtn = document.getElementById('startCategorySyncBtn');
        const stopBtn = document.getElementById('stopCategorySyncBtn');
        const triggerBtn = document.getElementById('triggerCategorySyncBtn');
        const statusEl = document.getElementById('categorySyncTimerStatus');
        
        const prerequisitesMet = await checkCategorySyncPrerequisites();
        
        if (startBtn) {
            // Disable start button if prerequisites not met, timer is active, or manual sync is in progress
            startBtn.disabled = !prerequisitesMet || data.timerActive || isCategorySyncInProgress;
            if (data.timerActive) {
                startBtn.style.display = 'none';
            } else {
                startBtn.style.display = 'inline-block';
            }
        }
        
        if (stopBtn) {
            stopBtn.style.display = data.timerActive ? 'inline-block' : 'none';
        }
        
        if (triggerBtn) {
            // Disable trigger button if prerequisites not met or manual sync is in progress
            triggerBtn.disabled = !prerequisitesMet || isCategorySyncInProgress;
        }
        
        if (statusEl) {
            statusEl.textContent = data.timerActive ? 'Running' : 'Stopped';
            statusEl.style.color = data.timerActive ? '#34a853' : '#ea4335';
        }
        
        // Store timer active state for use in updateCategorySyncTimers
        isCategoryTimerActive = data.timerActive || false;
        
        // Update sync times
        if (data.lastSyncTime || data.nextSyncTime) {
            updateCategorySyncStatus(data.lastSyncTime, data.nextSyncTime);
        } else {
            // If no next sync time and timer is stopped, clear it
            if (!data.timerActive) {
                currentCategoryNextSyncTime = null;
                const timeUntilEl = document.getElementById('timeUntilNextCategorySync');
                if (timeUntilEl) {
                    timeUntilEl.textContent = '';
                }
            }
        }
    } catch (error) {
        console.error('Error updating category sync control buttons:', error);
    }
}

// Update category sync status from server
async function updateCategorySyncStatusFromServer() {
    try {
        const response = await authFetch(`${API_BASE}/api/category-sync/status`);
        const data = await response.json();
        
        const statusEl = document.getElementById('categorySyncTimerStatus');
        if (statusEl) {
            statusEl.textContent = data.timerActive ? 'Running' : 'Stopped';
            statusEl.style.color = data.timerActive ? '#34a853' : '#ea4335';
        }
        
        // Store timer active state for use in updateCategorySyncTimers
        isCategoryTimerActive = data.timerActive || false;
        
        if (data.lastSyncTime || data.nextSyncTime) {
            updateCategorySyncStatus(data.lastSyncTime, data.nextSyncTime);
        } else {
            // If no next sync time and timer is stopped, clear it
            if (!data.timerActive) {
                currentCategoryNextSyncTime = null;
                const timeUntilEl = document.getElementById('timeUntilNextCategorySync');
                if (timeUntilEl) {
                    timeUntilEl.textContent = '';
                }
            }
        }
    } catch (error) {
        console.error('Error updating category sync status:', error);
    }
}

// Start category sync timer
async function startCategorySyncTimerControl() {
    const startBtn = document.getElementById('startCategorySyncBtn');
    if (startBtn) {
        startBtn.disabled = true;
        startBtn.querySelector('span').textContent = 'Starting...';
    }
    
    try {
        const response = await authFetch(`${API_BASE}/api/category-sync/start`, {
            method: 'POST'
        });
        const data = await response.json();
        
        if (data.success) {
            showToast('Category sync timer started successfully (runs every 48 hours)', 'success');
            await updateCategorySyncControlButtons();
            // Start checking if it's time to sync
            startCategorySyncCheck();
        } else {
            showToast(data.error || 'Failed to start category sync timer', 'error');
            await updateCategorySyncControlButtons();
        }
    } catch (error) {
        console.error('Error starting category sync timer:', error);
        showToast('Failed to start category sync timer: ' + error.message, 'error');
        await updateCategorySyncControlButtons();
    }
}

// Stop category sync timer
async function stopCategorySyncTimerControl() {
    const stopBtn = document.getElementById('stopCategorySyncBtn');
    if (stopBtn) {
        stopBtn.disabled = true;
        stopBtn.querySelector('span').textContent = 'Stopping...';
    }
    
    try {
        const response = await authFetch(`${API_BASE}/api/category-sync/stop`, {
            method: 'POST'
        });
        const data = await response.json();
        
        if (data.success) {
            showToast('Category sync timer stopped successfully', 'info');
            await updateCategorySyncControlButtons();
            // Stop checking for sync time
            stopCategorySyncCheck();
        } else {
            showToast(data.error || 'Failed to stop category sync timer', 'error');
            await updateCategorySyncControlButtons();
        }
    } catch (error) {
        console.error('Error stopping category sync timer:', error);
        showToast('Failed to stop category sync timer: ' + error.message, 'error');
        await updateCategorySyncControlButtons();
    }
}

// Start checking if it's time to sync categories (check every minute)
function startCategorySyncCheck() {
    // Clear existing check interval if any
    if (categorySyncCheckInterval) {
        clearInterval(categorySyncCheckInterval);
    }
    
    // Check immediately
    checkAndTriggerCategorySync();
    
    // Then check every minute
    categorySyncCheckInterval = setInterval(() => {
        checkAndTriggerCategorySync();
    }, 60000); // Check every minute
}

// Stop checking for category sync time
function stopCategorySyncCheck() {
    if (categorySyncCheckInterval) {
        clearInterval(categorySyncCheckInterval);
        categorySyncCheckInterval = null;
    }
}

// Check if it's time to sync categories and trigger if needed
async function checkAndTriggerCategorySync() {
    if (!isCategoryTimerActive) {
        return; // Timer is not active, don't check
    }
    
    try {
        const response = await authFetch(`${API_BASE}/api/category-sync/status`);
        const data = await response.json();
        
        if (data.success && data.nextSyncTime) {
            const nextSync = new Date(data.nextSyncTime);
            const now = new Date();
            
            // If next sync time has passed, trigger the sync
            if (nextSync.getTime() <= now.getTime()) {
                console.log('Category sync time reached, triggering sync...');
                // Update status first
                updateCategorySyncStatus(data.lastSyncTime, data.nextSyncTime);
                
                // Trigger the category sync automatically (no confirmation)
                await triggerCategorySyncNow(false);
            }
        }
    } catch (error) {
        console.error('Error checking category sync time:', error);
    }
}

// Trigger category sync now (automatic sync - no confirmation)
async function triggerCategorySyncNow(showConfirmation = false) {
    const triggerBtn = document.getElementById('triggerCategorySyncBtn');
    const startBtn = document.getElementById('startCategorySyncBtn');
    
    // For automatic sync, don't require button to be enabled
    if (showConfirmation && triggerBtn && triggerBtn.disabled) {
        return;
    }
    
    // If this is a manual sync (showConfirmation = true), set the in-progress flag
    if (showConfirmation) {
        isCategorySyncInProgress = true;
        // Disable start button when manual sync starts
        if (startBtn) {
            startBtn.disabled = true;
        }
    }
    
    if (triggerBtn) {
        triggerBtn.disabled = true;
        triggerBtn.querySelector('span').textContent = 'Syncing...';
    }
    
    try {
        // Update last sync time on server
        await authFetch(`${API_BASE}/api/category-sync/trigger`, {
            method: 'POST'
        });
        
        // Perform the actual category sync
        await syncCategoriesToPrestashop();
        
        // Update status
        await updateCategorySyncStatusFromServer();
        
        if (!showConfirmation) {
            // For automatic sync, show a toast notification
            showToast('Category sync completed automatically', 'success');
        }
    } catch (error) {
        console.error('Error triggering category sync:', error);
        showToast('Failed to trigger category sync: ' + error.message, 'error');
    } finally {
        // Clear the in-progress flag when sync completes (only for manual syncs)
        if (showConfirmation) {
            isCategorySyncInProgress = false;
        }
        
        // Update button states
        await updateCategorySyncControlButtons();
        
        if (triggerBtn) {
            triggerBtn.querySelector('span').textContent = 'Sync Now';
        }
    }
}

// ============================================
// User Management Functions
// ============================================

// Load and display all users
async function loadUsers() {
    const loadingEl = document.getElementById('usersLoading');
    const errorEl = document.getElementById('usersErrorMessage');
    const tableEl = document.getElementById('usersTable');
    const tableBodyEl = document.getElementById('usersTableBody');

    if (!tableBodyEl) return;

    try {
        loadingEl.style.display = 'block';
        errorEl.style.display = 'none';
        tableEl.style.display = 'none';

        const response = await authFetch(`${API_BASE}/api/admin/users`);
        if (!response.ok) {
            throw new Error('Failed to load users');
        }

        const data = await response.json();
        if (!data.success) {
            throw new Error(data.error || 'Failed to load users');
        }

        const users = data.users || [];
        
        if (users.length === 0) {
            tableBodyEl.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 40px; color: #999;">No users found</td></tr>';
        } else {
            tableBodyEl.innerHTML = users.map(user => {
                const lastLogin = user.last_login_at 
                    ? new Date(user.last_login_at).toLocaleString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
                    : 'Never';
                const isActive = user.is_active !== false && user.is_active !== 0;
                // Display suspended_at if user is suspended, otherwise display "live"
                const suspendDate = user.suspended_at
                    ? new Date(user.suspended_at).toLocaleString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
                    : 'live';
                const isLocked = user.lock_until && new Date(user.lock_until).getTime() > Date.now();
                // Disable switch if user is locked (locked takes precedence)
                const canToggle = !isLocked;
                const adminCount = users.filter(u => u.role === 'admin').length;
                const isLastAdmin = user.role === 'admin' && adminCount === 1;

                return `
                    <tr>
                        <td>${user.id}</td>
                        <td>${user.email}</td>
                        <td><span class="user-role-badge ${user.role}">${user.role}</span></td>
                        <td>${lastLogin}</td>
                        <td>${suspendDate}</td>
                        <td>
                            <label class="user-status-switch" title="${isLocked ? 'User is locked' : isLastAdmin ? 'Cannot deactivate the last admin' : isActive ? 'Click to deactivate' : 'Click to activate'}">
                                <input type="checkbox" ${isActive ? 'checked' : ''} ${!canToggle || isLastAdmin ? 'disabled' : ''} onchange="toggleUserStatus(${user.id}, ${isActive}, '${user.email.replace(/'/g, "\\'")}')">
                                <span class="user-status-switch-slider"></span>
                            </label>
                        </td>
                        <td>
                            <div class="user-actions">
                                <button class="btn btn-secondary btn-small" onclick="editUser(${user.id}, '${user.email.replace(/'/g, "\\'")}', '${user.role}')">Edit</button>
                                <button class="btn btn-secondary btn-small" onclick="deleteUser(${user.id}, '${user.email.replace(/'/g, "\\'")}')" ${isLastAdmin ? 'disabled title="Cannot delete the last admin user"' : ''}>Delete</button>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');
        }

        loadingEl.style.display = 'none';
        tableEl.style.display = 'table';
    } catch (error) {
        console.error('Error loading users:', error);
        loadingEl.style.display = 'none';
        errorEl.textContent = error.message || 'Failed to load users';
        errorEl.style.display = 'block';
    }
}

// Reset user form to default state
function resetUserForm() {
    const userIdEl = document.getElementById('userId');
    const emailEl = document.getElementById('userEmail');
    const passwordEl = document.getElementById('userPassword');
    const roleEl = document.getElementById('userRole');
    const errorEl = document.getElementById('userFormError');
    const form = document.getElementById('userForm');
    
    if (userIdEl) userIdEl.value = '';
    if (emailEl) emailEl.value = '';
    if (passwordEl) {
        passwordEl.value = '';
        passwordEl.required = true;
    }
    // Role defaults to user for new users
    if (roleEl) roleEl.value = 'user';
    const roleDisplayEl = document.getElementById('userRoleDisplay');
    if (roleDisplayEl) roleDisplayEl.textContent = 'User';
    if (errorEl) errorEl.style.display = 'none';
    if (form) form.reset(); // Reset form to clear any validation states
}

// Open modal for creating a new user
function createUser() {
    resetUserForm();
    document.getElementById('userPassword').required = true;
    document.getElementById('userModalTitle').textContent = 'Create User';
    document.getElementById('userModal').style.display = 'flex';
    
    // Focus on email field for better UX
    setTimeout(() => {
        const emailEl = document.getElementById('userEmail');
        if (emailEl) emailEl.focus();
    }, 100);
}

// Open modal for editing an existing user
function editUser(id, email, role) {
    // Hide error message first
    const errorEl = document.getElementById('userFormError');
    if (errorEl) errorEl.style.display = 'none';
    
    // Show modal first
    document.getElementById('userModal').style.display = 'flex';
    document.getElementById('userModalTitle').textContent = 'Edit User';
    
    // Set values after modal is shown - use requestAnimationFrame for better timing
    requestAnimationFrame(() => {
        const userIdEl = document.getElementById('userId');
        // Get the input element from the form specifically to avoid conflict with span element
        const userForm = document.getElementById('userForm');
        const emailEl = userForm ? userForm.querySelector('input[name="userEmail"]') : document.getElementById('userEmail');
        const passwordEl = document.getElementById('userPassword');
        const roleEl = document.getElementById('userRole');
        const roleDisplayEl = document.getElementById('userRoleDisplay');
        
        // Set values directly - ensure proper string conversion
        if (userIdEl) userIdEl.value = String(id || '');
        if (emailEl) {
            emailEl.value = String(email || '');
            // Trigger events to ensure value is recognized by browser
            emailEl.dispatchEvent(new Event('input', { bubbles: true }));
            emailEl.dispatchEvent(new Event('change', { bubbles: true }));
        }
        if (passwordEl) {
            passwordEl.value = '';
            passwordEl.required = false;
        }
        // Display role in read-only field (use existing user's role)
        if (roleDisplayEl) {
            const roleDisplay = role ? role.charAt(0).toUpperCase() + role.slice(1) : 'User';
            roleDisplayEl.textContent = roleDisplay;
        }
        // Set hidden input to existing user's role
        if (roleEl) roleEl.value = String(role || 'user');
        
        // Focus and select email field for better UX
        if (emailEl && (emailEl.tagName === 'INPUT' || emailEl.tagName === 'TEXTAREA')) {
            emailEl.focus();
            // Select all text for easy editing - only if select method exists
            if (typeof emailEl.select === 'function') {
                setTimeout(() => emailEl.select(), 10);
            }
        }
        
        // Debug log to verify values are set
        console.log('Edit User - Values set:', {
            id: userIdEl?.value,
            email: emailEl?.value,
            role: roleEl?.value || role,
            receivedParams: { id, email, role }
        });
    });
}

// Delete a user
async function deleteUser(id, email) {
    if (!confirm(`Are you sure you want to delete user "${email}"? This action cannot be undone.`)) {
        return;
    }

    try {
        const response = await authFetch(`${API_BASE}/api/admin/users/${id}`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'Failed to delete user');
        }

        showToast(`User "${email}" deleted successfully`, 'success');
        await loadUsers();
    } catch (error) {
        console.error('Error deleting user:', error);
        showToast(error.message || 'Failed to delete user', 'error');
    }
}

// Toggle user activation status
async function toggleUserStatus(userId, currentStatus, email) {
    const newStatus = !currentStatus;
    
    try {
        const response = await authFetch(`${API_BASE}/api/admin/users/${userId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                is_active: newStatus
            })
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'Failed to update user status');
        }

        const statusText = newStatus ? 'activated' : 'deactivated';
        showToast(`User "${email}" ${statusText} successfully`, 'success');
        await loadUsers();
    } catch (error) {
        console.error('Error toggling user status:', error);
        showToast(error.message || 'Failed to update user status', 'error');
        // Reload users to reset the switch to its previous state
        await loadUsers();
    }
}

// Save user (create or update)
async function saveUser(event) {
    if (event) {
        event.preventDefault();
    }

    const userIdEl = document.getElementById('userId');
    const emailEl = document.getElementById('userEmail');
    const passwordEl = document.getElementById('userPassword');
    const roleEl = document.getElementById('userRole');
    const errorEl = document.getElementById('userFormError');
    const saveBtn = document.getElementById('saveUserBtn');

    // Try multiple methods to get values
    // Method 1: Direct element access
    const userId = userIdEl ? userIdEl.value : '';
    const emailRaw = emailEl ? emailEl.value : '';
    const email = emailRaw.trim();
    const password = passwordEl ? passwordEl.value : '';
    const role = roleEl ? roleEl.value : '';
    
    // Method 2: FormData (more reliable)
    const form = document.getElementById('userForm');
    let formDataEmail = '';
    let formDataPassword = '';
    let formDataRole = '';
    if (form && event && event.target) {
        const formData = new FormData(event.target);
        formDataEmail = formData.get('userEmail') || '';
        formDataPassword = formData.get('userPassword') || '';
        formDataRole = formData.get('userRole') || '';
    }

    // Log field values for debugging
    console.log('=== User Form Field Values ===');
    console.log('User ID:', userId || '(empty - new user)');
    console.log('  → Explanation: Empty means creating a new user. If editing, this contains the user\'s database ID.');
    console.log('');
    console.log('--- Method 1: Direct Element Access ---');
    console.log('Email (raw):', JSON.stringify(emailRaw), '| Length:', emailRaw.length);
    console.log('Email (trimmed):', email || '(empty)');
    console.log('  → Element found:', !!emailEl);
    if (emailEl) {
        console.log('  → Element value property:', JSON.stringify(emailEl.value));
        console.log('  → Element type:', emailEl.type);
        console.log('  → Element required:', emailEl.required);
        console.log('  → Element id:', emailEl.id);
        console.log('  → Element name:', emailEl.name || '(no name attribute)');
    }
    console.log('Password:', password ? '***' + password.length + ' characters***' : '(empty)');
    console.log('Role:', role || '(empty)');
    console.log('');
    console.log('--- Method 2: FormData ---');
    console.log('Email (FormData):', formDataEmail || '(empty)');
    console.log('Password (FormData):', formDataPassword ? '***' + formDataPassword.length + ' characters***' : '(empty)');
    console.log('Role (FormData):', formDataRole || '(empty)');
    console.log('=============================');
    
    // Use FormData values if direct access failed
    const finalEmail = email || formDataEmail.trim();
    const finalPassword = password || formDataPassword;
    // Get role from hidden input (will be 'user' for new users, existing role for edits)
    const finalRole = roleEl ? roleEl.value : (formDataRole || 'user');

    errorEl.style.display = 'none';

    // Validation - use finalEmail which tries both methods
    if (!finalEmail) {
        errorEl.textContent = 'Email is required';
        errorEl.style.display = 'block';
        return;
    }

    const isEdit = userId !== '';
    if (!isEdit && !finalPassword) {
        errorEl.textContent = 'Password is required for new users';
        errorEl.style.display = 'block';
        return;
    }

    try {
        saveBtn.disabled = true;
        saveBtn.textContent = 'Saving...';

        if (isEdit) {
            // Update existing user
            const updateData = { email: finalEmail, role: finalRole };
            if (finalPassword) {
                updateData.password = finalPassword;
            }

            const response = await authFetch(`${API_BASE}/api/admin/users/${userId}`, {
                method: 'PUT',
                body: JSON.stringify(updateData)
            });

            if (!response.ok) {
                const data = await response.json();
                throw new Error(data.error || 'Failed to update user');
            }

            showToast(`User "${finalEmail}" updated successfully`, 'success');
        } else {
            // Create new user
            if (!finalPassword) {
                throw new Error('Password is required');
            }

            const response = await authFetch(`${API_BASE}/api/admin/users`, {
                method: 'POST',
                body: JSON.stringify({ email: finalEmail, password: finalPassword, role: finalRole })
            });

            if (!response.ok) {
                const data = await response.json();
                throw new Error(data.error || 'Failed to create user');
            }

            showToast(`User "${finalEmail}" created successfully`, 'success');
        }

        // Close modal, reset form, and refresh list
        document.getElementById('userModal').style.display = 'none';
        resetUserForm(); // Clear form fields after successful save
        await loadUsers();
    } catch (error) {
        console.error('Error saving user:', error);
        errorEl.textContent = error.message || 'Failed to save user';
        errorEl.style.display = 'block';
    } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = 'Save';
    }
}

// Setup user management event listeners
function setupUserManagement() {
    // Show/hide User Management tab and content based on user role
    const userManagementTab = document.getElementById('userManagementTab');
    const userManagementContent = document.getElementById('tab-user-management');
    
    if (userManagementTab && currentUser && currentUser.role === 'admin') {
        userManagementTab.style.display = 'flex';
        // Don't force display - let tab switching logic handle visibility
    } else {
        if (userManagementTab) {
            userManagementTab.style.display = 'none';
        }
        if (userManagementContent) {
            userManagementContent.style.display = 'none';
        }
    }

    // Set Timer button
    const setTimerBtn = document.getElementById('setTimerBtn');
    if (setTimerBtn) {
        setTimerBtn.addEventListener('click', openTimerModal);
    }

    // Create user button
    const createUserBtn = document.getElementById('createUserBtn');
    if (createUserBtn) {
        createUserBtn.addEventListener('click', createUser);
    }

    // Refresh users button
    const refreshUsersBtn = document.getElementById('refreshUsersBtn');
    if (refreshUsersBtn) {
        refreshUsersBtn.addEventListener('click', loadUsers);
    }

    // User form submit
    const userForm = document.getElementById('userForm');
    if (userForm) {
        userForm.addEventListener('submit', saveUser);
    }

    // Close modal buttons
    const closeUserModal = document.getElementById('closeUserModal');
    const cancelUserBtn = document.getElementById('cancelUserBtn');
    if (closeUserModal) {
        closeUserModal.addEventListener('click', () => {
            document.getElementById('userModal').style.display = 'none';
            resetUserForm(); // Clear form when closing
        });
    }
    if (cancelUserBtn) {
        cancelUserBtn.addEventListener('click', () => {
            document.getElementById('userModal').style.display = 'none';
            resetUserForm(); // Clear form when canceling
        });
    }

    // Close modal when clicking outside
    const userModal = document.getElementById('userModal');
    if (userModal) {
        userModal.addEventListener('click', (e) => {
            if (e.target === userModal) {
                userModal.style.display = 'none';
                resetUserForm(); // Clear form when clicking outside
            }
        });
    }

    // Timer form submit
    const timerForm = document.getElementById('timerForm');
    if (timerForm) {
        timerForm.addEventListener('submit', saveTimerSettings);
    }

    // Close timer modal buttons
    const closeTimerModal = document.getElementById('closeTimerModal');
    const cancelTimerBtn = document.getElementById('cancelTimerBtn');
    if (closeTimerModal) {
        closeTimerModal.addEventListener('click', () => {
            document.getElementById('timerModal').style.display = 'none';
        });
    }
    if (cancelTimerBtn) {
        cancelTimerBtn.addEventListener('click', () => {
            document.getElementById('timerModal').style.display = 'none';
        });
    }

    // Close timer modal when clicking outside
    const timerModal = document.getElementById('timerModal');
    if (timerModal) {
        timerModal.addEventListener('click', (e) => {
            if (e.target === timerModal) {
                timerModal.style.display = 'none';
            }
        });
    }
}

// Open timer settings modal
async function openTimerModal() {
    const timerModal = document.getElementById('timerModal');
    const errorEl = document.getElementById('timerFormError');
    
    if (errorEl) {
        errorEl.style.display = 'none';
        errorEl.textContent = '';
    }
    
    if (timerModal) {
        timerModal.style.display = 'flex';
        
        // Load current settings
        try {
            const token = getAuthToken();
            if (!token) {
                throw new Error('Not authenticated');
            }

            const response = await fetch('/api/admin/timer-settings', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                let errorMessage = 'Failed to load timer settings';
                try {
                    const errorData = await response.json();
                    errorMessage = errorData.error || errorMessage;
                } catch (e) {
                    // If response is not JSON, use status text
                    errorMessage = response.statusText || errorMessage;
                }
                throw new Error(errorMessage);
            }

            const data = await response.json();

            if (data.success && data.settings) {
                document.getElementById('categorySyncInterval').value = data.settings.categorySyncIntervalHours;
                document.getElementById('stockSyncInterval').value = data.settings.stockSyncIntervalMinutes;
            } else {
                // If response is OK but data format is unexpected, log it
                console.warn('Timer settings response format unexpected:', data);
            }
        } catch (error) {
            console.error('Error loading timer settings:', error);
            if (errorEl) {
                // Show the actual error message from server, or fallback to generic message
                const errorMessage = error.message || 'Failed to load timer settings. Using defaults.';
                errorEl.textContent = errorMessage;
                errorEl.style.display = 'block';
            }
        }
    }
}

// Save timer settings
async function saveTimerSettings(event) {
    event.preventDefault();
    
    const errorEl = document.getElementById('timerFormError');
    const saveBtn = document.getElementById('saveTimerBtn');
    
    if (errorEl) {
        errorEl.style.display = 'none';
        errorEl.textContent = '';
    }

    const categorySyncInterval = document.getElementById('categorySyncInterval').value;
    const stockSyncInterval = document.getElementById('stockSyncInterval').value;

    if (!categorySyncInterval || !stockSyncInterval) {
        if (errorEl) {
            errorEl.textContent = 'Please fill in all fields';
            errorEl.style.display = 'block';
        }
        return;
    }

    if (saveBtn) {
        saveBtn.disabled = true;
        saveBtn.textContent = 'Saving...';
    }

    try {
        const token = getAuthToken();
        if (!token) {
            throw new Error('Not authenticated');
        }

        const response = await fetch('/api/admin/timer-settings', {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                categorySyncIntervalHours: parseInt(categorySyncInterval, 10),
                stockSyncIntervalMinutes: parseInt(stockSyncInterval, 10)
            })
        });

        if (!response.ok) {
            let errorMessage = 'Failed to save timer settings';
            try {
                const errorData = await response.json();
                errorMessage = errorData.error || errorMessage;
            } catch (e) {
                errorMessage = response.statusText || errorMessage;
            }
            throw new Error(errorMessage);
        }

        const data = await response.json();

        if (!data.success) {
            throw new Error(data.error || 'Failed to save timer settings');
        }

        // Show success message
        showToast('Timer settings saved successfully', 'success');
        
        // Close modal
        document.getElementById('timerModal').style.display = 'none';
    } catch (error) {
        console.error('Error saving timer settings:', error);
        if (errorEl) {
            errorEl.textContent = error.message || 'Failed to save timer settings';
            errorEl.style.display = 'block';
        }
    } finally {
        if (saveBtn) {
            saveBtn.disabled = false;
            saveBtn.textContent = 'Save';
        }
    }
}



