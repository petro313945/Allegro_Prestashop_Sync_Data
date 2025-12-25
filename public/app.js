// State management
let currentOffers = [];
let allLoadedOffers = []; // Store all loaded offers for filtering
let importedOffers = [];
let currentOffset = 0; // Kept for display purposes
let currentLimit = 30; // Default products per page
let totalCount = 0; // Current page product count
let totalProductsSeen = 0; // Total products seen across all pages in current category
let isAuthenticated = false;
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

function clearAuth() {
    authToken = null;
    currentUser = null;
    localStorage.removeItem('auth_token');
    localStorage.removeItem('current_user');
}

// Authenticated fetch wrapper
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

    const response = await fetch(url, {
        ...options,
        headers
    });

    // If unauthorized, clear token and show login
    if (response.status === 401) {
        clearAuth();
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
        localStorage.setItem('current_user', JSON.stringify(data.user));
        
        // Update user email display
        updateUserDisplay(data.user);
        
        return data;
    } catch (error) {
        throw error;
    }
}

// Logout function
async function logout() {
    try {
        // Capture user info before clearing auth
        const savedUser = localStorage.getItem('current_user');
        const user = savedUser ? JSON.parse(savedUser) : currentUser;
        const token = getAuthToken();
        if (token) {
            await authFetch(`${API_BASE}/api/logout`, {
                method: 'POST'
            });
        }

        // Show logout info toast
        if (user && user.email) {
            const logoutTime = new Date().toLocaleString();
            showToast(`${user.email} logged out at ${logoutTime}`, 'info', 5000);
        }
    } catch (error) {
        console.error('Logout error:', error);
    } finally {
        clearAuth();
        showLoginScreen();
    }
}

// Show/hide login screen
function showLoginScreen() {
    document.getElementById('loginScreen').style.display = 'flex';
    document.getElementById('mainApp').style.display = 'none';
}

// Check if user is logged in on page load
async function checkAuth() {
    const token = getAuthToken();
    if (!token) {
        showLoginScreen();
        return false;
    }

    // Verify token is still valid by checking a protected endpoint
    try {
        const response = await authFetch(`${API_BASE}/api/health`);
        if (response.ok) {
            const savedUser = localStorage.getItem('current_user');
            if (savedUser) {
                currentUser = JSON.parse(savedUser);
                // Update user display
                updateUserDisplay(currentUser);
            }
            showMainInterface();
            
            // Show message that user is already logged in
            if (currentUser && currentUser.email) {
                const now = new Date();
                const dateStr = now.toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric' });
                const timeStr = now.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                showToast(`${currentUser.email} already logged in at ${dateStr}, ${timeStr}`, 'info', 4000);
            }
            
            return true;
        }
    } catch (error) {
        console.error('Auth check failed:', error);
        showLoginScreen();
        return false;
    }

    showLoginScreen();
    return false;
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
            
            // Initialize app components (these may fail, but UI should already be shown)
            try {
                setupEventListeners();
                loadImportedOffers();
                loadPrestashopConfig();
                checkPrestashopStatus();
                await loadSavedCredentials();
                updateUIState(false);
                updateButtonStates();
                if (typeof updateSyncCategoryButtonState === 'function') {
                    updateSyncCategoryButtonState();
                }
            } catch (initError) {
                console.error('Error initializing app components:', initError);
                // UI is already shown, so just log the error
            }
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
    if (!isAuthenticated || !isOAuthConnected || !prestashopAuthorized) {
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

// Load saved credentials and restore authentication state
async function loadSavedCredentials() {
    const savedClientId = localStorage.getItem('allegro_clientId');
    const savedClientSecret = localStorage.getItem('allegro_clientSecret');
    
    if (savedClientId && savedClientSecret) {
        // Restore credentials to input fields
        const clientIdInput = document.getElementById('clientId');
        const clientSecretInput = document.getElementById('clientSecret');
        
        if (clientIdInput) {
            clientIdInput.value = savedClientId;
        }
        if (clientSecretInput) {
            clientSecretInput.value = savedClientSecret;
        }
        
        // Send credentials to backend to ensure they're loaded
        try {
            const credentialsResponse = await authFetch(`${API_BASE}/api/credentials`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    clientId: savedClientId,
                    clientSecret: savedClientSecret
                })
            });
            
            const credentialsData = await credentialsResponse.json();
            
            if (!credentialsData.success) {
                // Credentials failed to save - clear them
                localStorage.removeItem('allegro_clientId');
                localStorage.removeItem('allegro_clientSecret');
                if (clientIdInput) clientIdInput.value = '';
                if (clientSecretInput) clientSecretInput.value = '';
                return;
            }
            
            // Check if credentials are still valid by testing authentication
            const authResponse = await authFetch(`${API_BASE}/api/test-auth`);
            const authData = await authResponse.json();
            
            if (authData.success) {
                // Credentials are valid - restore authentication state
                isAuthenticated = true;
                const authStatusEl = document.getElementById('authStatus');
                if (authStatusEl) {
                    authStatusEl.textContent = 'Allegro Auth: Authenticated';
                    authStatusEl.className = 'quick-status-badge success';
                }
                
                // Show disconnect button
                const clearBtn = document.getElementById('clearCredentialsBtn');
                if (clearBtn) {
                    clearBtn.style.display = 'block';
                }
                
                // Update config status indicators and button states
                updateConfigStatuses();
                
                // Check OAuth status (this will also try to refresh expired tokens)
                await checkOAuthStatus();
                
                // Update UI state
                updateUIState(true);
            } else {
                // Credentials are invalid - clear them
                localStorage.removeItem('allegro_clientId');
                localStorage.removeItem('allegro_clientSecret');
                if (clientIdInput) clientIdInput.value = '';
                if (clientSecretInput) clientSecretInput.value = '';
            }
        } catch (error) {
            console.error('Error checking saved credentials:', error);
            // On error, don't restore state - user will need to reconnect
        }
    }
}

// Update config status indicators
function updateConfigStatuses() {
    // Update Allegro status
    const allegroStatus = document.getElementById('allegroConfigStatus');
    if (allegroStatus) {
        if (isAuthenticated) {
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
        if (isAuthenticated) {
            allegroQuickStatus.textContent = 'Allegro: Connected';
            allegroQuickStatus.className = 'quick-status-badge success';
        } else {
            allegroQuickStatus.textContent = 'Allegro: Not Configured';
            allegroQuickStatus.className = 'quick-status-badge error';
        }
    }
    
    // Update PrestaShop status
    const prestashopStatusEl = document.getElementById('prestashopConfigStatus');
    if (prestashopStatusEl) {
        if (prestashopConfigured && prestashopAuthorized) {
            prestashopStatusEl.textContent = 'Connected';
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
        if (isAuthenticated) {
            // Connected state: grey, disabled, shows "Connected"
            allegroConnectBtn.textContent = 'Connected';
            allegroConnectBtn.className = 'btn btn-connected';
            allegroConnectBtn.disabled = true;
            
            // Show disconnect and authorize buttons
            if (clearBtn) {
                clearBtn.style.display = 'block';
            }
            if (authorizeBtn) {
                authorizeBtn.style.display = 'block';
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
    const syncCategoriesBtn = document.getElementById('syncCategoriesBtn');
    if (!syncCategoriesBtn) return;
    
    // Enable button only if categories are loaded and PrestaShop is configured and authorized
    const hasCategories = allCategories && allCategories.length > 0;
    const canSync = hasCategories && prestashopConfigured && prestashopAuthorized;
    
    syncCategoriesBtn.disabled = !canSync;
    
    if (!hasCategories) {
        syncCategoriesBtn.title = 'Load categories first';
    } else if (!prestashopConfigured || !prestashopAuthorized) {
        syncCategoriesBtn.title = 'PrestaShop must be configured and authorized';
    } else {
        syncCategoriesBtn.title = '';
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

// Setup event listeners
function setupEventListeners() {
    // Logout button - remove old listener before adding new one
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        // Remove existing listener if it exists
        if (logoutHandler) {
            logoutBtn.removeEventListener('click', logoutHandler);
        }
        // Create new handler function
        logoutHandler = async () => {
            if (confirm('Are you sure you want to log out?')) {
                await logout();
            }
        };
        // Add the new listener
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
    
    // Removed loadCategoriesBtn and clearCategoryBtn - categories load automatically after OAuth
    document.getElementById('clearImportedBtn').addEventListener('click', clearImportedProducts);
    document.getElementById('exportToPrestashopBtn').addEventListener('click', exportToPrestashop);
    
    // Sync Categories button event listener
    const syncCategoriesBtn = document.getElementById('syncCategoriesBtn');
    if (syncCategoriesBtn) {
        syncCategoriesBtn.addEventListener('click', async () => {
            if (syncCategoriesBtn.disabled) return;
            
            // Show confirmation alert
            if (!confirm('Are you sure you want to sync categories to PrestaShop.\nOnly use this feature if there are no categories in PrestaShop.\nIf there are categories in PrestaShop, they can be duplicated.')) {
                return;
            }
            
            syncCategoriesBtn.disabled = true;
            syncCategoriesBtn.textContent = 'Syncing...';
            
            try {
                await syncCategoriesToPrestashop();
                // Note: syncCategoriesToPrestashop() already shows toast notifications
            } catch (error) {
                console.error('Error syncing categories:', error);
                showToast('Failed to sync categories. Please try again.', 'error');
            } finally {
                syncCategoriesBtn.disabled = false;
                syncCategoriesBtn.textContent = 'Sync Category';
                updateSyncCategoryButtonState();
            }
        });
    }
    
    // Removed Created Products feature - no longer needed
    
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
    
    // Sync Stock Log event listeners (removed - logs auto-clear on sync start)
    
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
    
    // Disable button during authentication
    connectBtn.disabled = true;
    connectBtn.textContent = 'Connecting...';
    
    try {
        // Step 1: Send credentials to backend
        const credentialsResponse = await authFetch(`${API_BASE}/api/credentials`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                clientId: clientId,
                clientSecret: clientSecret
            })
        });
        
        const credentialsData = await credentialsResponse.json();
        
        if (!credentialsData.success) {
            throw new Error(credentialsData.error || 'Failed to save credentials');
        }
        
        // Step 2: Test authentication immediately
        const authResponse = await authFetch(`${API_BASE}/api/test-auth`);
        
        // Check for 401 status before parsing JSON
        if (!authResponse.ok && authResponse.status === 401) {
            throw new Error('Invalid credentials. Please check your Client ID and Client Secret.');
        }
        
        const authData = await authResponse.json();
        
        if (authData.success) {
            // Authentication successful - show detail interface
            localStorage.setItem('allegro_clientId', clientId);
            localStorage.setItem('allegro_clientSecret', clientSecret);
            
            showToast('Authentication successful!', 'success');
            
            // Show main content
            showMainInterface();
            
            // Set authenticated state
            isAuthenticated = true;
            const authStatusEl = document.getElementById('authStatus');
            if (authStatusEl) {
                authStatusEl.textContent = 'Allegro Auth: Authenticated';
                authStatusEl.className = 'quick-status-badge success';
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
        let errorMessage = 'Authentication failed. Please check your credentials.';
        if (error.message && !error.message.includes('status code')) {
            errorMessage = error.message;
        }
        showToast(errorMessage, 'error');
        hideMainInterface();
        updateUIState(false);
    } finally {
        // Update button state based on authentication status
        updateButtonStates();
    }
}

// This function is no longer used - authentication happens in saveCredentials()
// Keeping for backward compatibility if needed elsewhere
async function sendCredentialsToBackend(clientId, clientSecret) {
    try {
        const response = await authFetch(`${API_BASE}/api/credentials`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                clientId: clientId,
                clientSecret: clientSecret
            })
        });
        
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
    document.getElementById('clientSecret').value = '';
    localStorage.removeItem('allegro_clientId');
    localStorage.removeItem('allegro_clientSecret');
    
    const messageEl = document.getElementById('credentialsMessage');
    if (messageEl) {
        messageEl.style.display = 'none';
    }
    
    // Disconnect OAuth
    try {
        await authFetch(`${API_BASE}/api/oauth/disconnect`, {
            method: 'POST'
        });
    } catch (error) {
        console.error('Error disconnecting OAuth:', error);
    }
    
    updateUIState(false);
    
    // Hide main interface
    hideMainInterface();
    
    // Clear auth status
    const authStatusEl = document.getElementById('authStatus');
    const oauthStatusEl = document.getElementById('oauthStatus');
    if (authStatusEl) {
        authStatusEl.textContent = 'Allegro Auth: Pending';
        authStatusEl.className = 'quick-status-badge error';
    }
    if (oauthStatusEl) {
        oauthStatusEl.textContent = 'Account: Not Connected';
        oauthStatusEl.className = 'quick-status-badge error';
    }
    isAuthenticated = false;
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
    document.getElementById('prestashopApiKey').value = '';
    
    // Remove from localStorage
    localStorage.removeItem('prestashopConfig');
    
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
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        if (data.success) {
            showToast('All configuration files cleared successfully', 'success');
        } else {
            showToast('Error clearing configuration: ' + (data.error || 'Unknown error'), 'error');
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
    return authStatusEl && authStatusEl.className.includes('success') && authStatusEl.textContent === 'Allegro Auth: Authenticated';
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
    // Removed loadCategoriesBtn - categories load automatically after OAuth
    
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

// Check API status (no longer displayed in header, but still used for internal checks)
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
        const data = await response.json();
        
        const oauthStatusEl = document.getElementById('oauthStatus');
        const authorizeBtn = document.getElementById('authorizeAccountBtn');
        const oauthInfoEl = document.getElementById('oauthInfo');
        
        isOAuthConnected = data.connected || false;
        
        if (oauthStatusEl) {
            if (isOAuthConnected) {
                oauthStatusEl.textContent = 'Account: Connected';
                oauthStatusEl.className = 'quick-status-badge success';
            } else {
                oauthStatusEl.textContent = 'Account: Not Connected';
                oauthStatusEl.className = 'quick-status-badge error';
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
        if (authorizeBtn) {
            if (isAuthenticated) {
                if (isOAuthConnected) {
                    authorizeBtn.style.display = 'none';
                } else {
                    authorizeBtn.style.display = 'block';
                }
            } else {
                authorizeBtn.style.display = 'none';
            }
        }
        
        // Update UI state to refresh Load Offers button and other controls
        updateUIState(true);

        // When OAuth is connected, ensure the Allegro category tree is loaded
        if (isOAuthConnected) {
            await loadCategoryTreeRoot(false);
        }

        // If everything is configured on this device, auto-load offers after refresh
        await autoLoadOffersIfReady();
    } catch (error) {
        console.error('Error checking OAuth status:', error);
        const oauthStatusEl = document.getElementById('oauthStatus');
        if (oauthStatusEl) {
            oauthStatusEl.textContent = 'Account: Error';
            oauthStatusEl.className = 'quick-status-badge error';
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
    if (!isAuthenticated) {
        showToast('Please connect with Client ID and Secret first', 'error');
        return;
    }
    
    try {
        // Get OAuth authorization URL from backend
        const response = await authFetch(`${API_BASE}/api/oauth/authorize`);
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
                    showToast('Account authorized successfully!', 'success');
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
        authStatusEl.textContent = 'Allegro Auth: Testing';
        authStatusEl.className = 'quick-status-badge pending';
    }
    
    const clientId = document.getElementById('clientId').value.trim();
    const clientSecret = document.getElementById('clientSecret').value.trim();
    
    if (!clientId || !clientSecret) {
        if (authStatusEl) {
            authStatusEl.textContent = 'Allegro Auth: Credentials required';
            authStatusEl.className = 'quick-status-badge error';
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
            throw new Error('Invalid credentials. Please check your Client ID and Client Secret.');
        }
        
        const data = await response.json();
        
        if (data.success) {
            if (authStatusEl) {
                authStatusEl.textContent = 'Allegro Auth: Authenticated';
                authStatusEl.className = 'quick-status-badge success';
            }
            isAuthenticated = true;
            updateUIState(true);
            showToast('Authentication successful', 'success');
            // Categories will be loaded automatically after OAuth authorization
        } else {
            if (authStatusEl) {
                authStatusEl.textContent = 'Allegro Auth: Failed';
                authStatusEl.className = 'quick-status-badge error';
            }
            isAuthenticated = false;
            updateUIState(false);
            showToast('Authentication failed. Please check your credentials.', 'error');
        }
    } catch (error) {
        if (authStatusEl) {
            authStatusEl.textContent = 'Allegro Auth: Error';
            authStatusEl.className = 'quick-status-badge error';
        }
        isAuthenticated = false;
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
// Product count is now fixed to 30 per page and the UI selector was removed,
// so this function is kept as a no-op for backward compatibility.
async function handleProductCountChange() {
    return;
}

// Fetch all offers from API (loads all pages)
async function fetchAllOffers() {
    // Validate authentication
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
            
            const response = await authFetch(`${API_BASE}/api/offers?${params}`);
            
            // Check for 401 status before parsing JSON
            if (!response.ok && response.status === 401) {
                throw new Error('Invalid credentials. Please check your Client ID and Client Secret.');
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
        
        const response = await authFetch(`${API_BASE}/api/offers?${params}`);
        
        // Check for 401 status before parsing JSON
        if (!response.ok && response.status === 401) {
            throw new Error('Invalid credentials. Please check your Client ID and Client Secret.');
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
    // Clear any existing rotation for this card
    if (card.dataset.rotationInterval) {
        clearInterval(parseInt(card.dataset.rotationInterval));
    }
    
    let currentIndex = 0;
    
    // Function to rotate to next image
    const rotateImage = () => {
        if (!card.isConnected || !document.contains(card)) {
            // Card was removed from DOM, stop rotation
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
        const batchSize = 5;
        for (let i = 0; i < productsToFetch.length; i += batchSize) {
            const batch = productsToFetch.slice(i, i + batchSize);
            await Promise.all(batch.map(product => fetchProductDetails(product.id)));
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
                             onerror="this.onerror=null; this.style.display='none'; this.nextElementSibling.style.display='flex';">
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
                             onerror="this.onerror=null; this.style.display='none'; this.nextElementSibling.style.display='flex';">
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
                             onerror="this.onerror=null; this.style.display='none'; this.nextElementSibling.style.display='flex';">
                    ${totalImageCount > 0 ? `
                        <div class="offer-image-count-badge" title="${totalImageCount} image${totalImageCount > 1 ? 's' : ''} available from Allegro${totalImageCount > 1 ? ' - Click image to navigate' : ''}">
                            <span class="offer-image-count-icon">📷</span>
                            <span class="offer-image-count-number">${totalImageCount}</span>
                        </div>
                    ` : ''}
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
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                baseUrl: url,
                apiKey: apiKey
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('PrestaShop configuration saved successfully!', 'success');
            localStorage.setItem('prestashopConfig', JSON.stringify({ url, apiKey }));
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
        // Save temporarily for test
        const response = await authFetch(`${API_BASE}/api/prestashop/configure`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                baseUrl: url,
                apiKey: apiKey
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Failed to save configuration');
        }
        
        // Test connection
        const testResponse = await authFetch(`${API_BASE}/api/prestashop/test`);
        const testData = await testResponse.json();
        
        if (testData.success) {
            // Save to localStorage when test succeeds
            localStorage.setItem('prestashopConfig', JSON.stringify({ url, apiKey }));
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

function loadPrestashopConfig() {
    const saved = localStorage.getItem('prestashopConfig');
    if (saved) {
        try {
            const config = JSON.parse(saved);
            // Always use saved URL as default (user's entered URL)
            document.getElementById('prestashopUrl').value = config.url || '';
            document.getElementById('prestashopApiKey').value = config.apiKey || '';
            
            // Show saved configuration info
            updatePrestashopSavedConfigDisplay(config.url);
            
        } catch (e) {
            console.error('Error loading PrestaShop config:', e);
            // Fallback to empty if parsing fails
            document.getElementById('prestashopUrl').value = '';
            document.getElementById('prestashopApiKey').value = '';
            hidePrestashopSavedConfigDisplay();
        }
    } else {
        // No saved config - leave empty so user enters their URL
        document.getElementById('prestashopUrl').value = '';
        document.getElementById('prestashopApiKey').value = '';
        hidePrestashopSavedConfigDisplay();
    }
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
        const data = await response.json();
        
        prestashopConfigured = data.configured;
        
        // If PrestaShop is configured, check if connection is authorized by testing it
        // Only set authorized to true if we can successfully test the connection
        if (prestashopConfigured) {
            try {
                const testResponse = await authFetch(`${API_BASE}/api/prestashop/test`);
                const testData = await testResponse.json();
                prestashopAuthorized = testData.success || false;
            } catch (error) {
                prestashopAuthorized = false;
            }
        } else {
            prestashopAuthorized = false;
        }
        
        // Show/hide saved config display based on configured status
        if (prestashopConfigured) {
            const saved = localStorage.getItem('prestashopConfig');
            if (saved) {
                try {
                    const config = JSON.parse(saved);
                    updatePrestashopSavedConfigDisplay(config.url);
                } catch (e) {
                    hidePrestashopSavedConfigDisplay();
                }
            }
        } else {
            hidePrestashopSavedConfigDisplay();
        }
        
        // Update config panel status (header status removed) and button states
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

    // Map to store Allegro category ID -> PrestaShop category ID
    const categoryIdMap = new Map();
    // Map to store category name + parent -> PrestaShop category ID (for finding existing categories)
    // Key format: "name|parentId" to handle same name under different parents
    const categoryNameParentMap = new Map();
    
    let createdCount = 0;
    let existingCount = 0;
    let errorCount = 0;

    // Step 1: Collect all unique categories from all paths (including parents)
    const allCategoryNodes = new Map(); // Map<categoryId, {id, name, parentId, level}>
    const processedPaths = new Set();
    
    // Fetch parent paths for all categories
    for (const category of allCategories) {
        // Skip if category doesn't have a valid name
        if (!category.name || category.name === `Category ${category.id}` || category.name === 'N/A') {
            continue;
        }

        const categoryId = String(category.id);
        const pathKey = `path_${categoryId}`;
        
        if (processedPaths.has(pathKey)) {
            continue;
        }

        try {
            // Fetch the full parent path for this category
            const path = await fetchCategoryPath(categoryId);
            
            if (path && path.length > 0) {
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
            } else {
                // If no path found, treat as root level category
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
            // Still add the category itself even if path fetch fails
            if (!allCategoryNodes.has(categoryId)) {
                allCategoryNodes.set(categoryId, {
                    id: categoryId,
                    name: category.name,
                    parentId: null,
                    level: 0
                });
            }
        }
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
            let prestashopParentId = 2; // Default to Home (ID: 2)
            
            if (allegroParentId && categoryIdMap.has(allegroParentId)) {
                // Use mapped PrestaShop parent ID (parent was created in previous level)
                prestashopParentId = categoryIdMap.get(allegroParentId);
            } else if (allegroParentId) {
                // Parent should have been created in a previous level
                // If not found in map, it might already exist in PrestaShop or wasn't processed yet
                // Since we process level by level, if parent is not in map, use Home as fallback
                // The backend API will handle finding existing categories by name+parent correctly
                console.warn(`Parent category ${allegroParentId} not found in map for "${categoryName}", using Home as parent`);
                prestashopParentId = 2; // Fallback to Home
            }

            // Check if we've already processed a category with the same name and parent in this sync session
            // This prevents duplicate API calls for the same category
            const categoryKey = `${categoryName}|${prestashopParentId}`;
            if (categoryNameParentMap.has(categoryKey)) {
                // Category with same name and parent already processed, use existing mapping
                const existingPrestashopId = categoryNameParentMap.get(categoryKey);
                categoryIdMap.set(allegroCategoryId, existingPrestashopId);
                existingCount++;
                console.log(`Category "${categoryName}" (Parent: ${prestashopParentId}) already processed in this sync session (ID: ${existingPrestashopId}), skipping API call`);
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
                        active: 1
                    })
                });

                const result = await response.json();

                if (result.success && result.category && result.category.id) {
                    const prestashopCategoryId = result.category.id;
                    
                    // Store mapping using composite key (name + parent) to handle duplicates
                    const categoryKey = `${categoryName}|${prestashopParentId}`;
                    categoryIdMap.set(allegroCategoryId, prestashopCategoryId);
                    categoryNameParentMap.set(categoryKey, prestashopCategoryId);
                    
                    if (result.existing) {
                        existingCount++;
                        console.log(`Category "${categoryName}" already exists in PrestaShop (ID: ${prestashopCategoryId}, Parent: ${prestashopParentId})`);
                    } else {
                        createdCount++;
                        console.log(`Created category "${categoryName}" in PrestaShop (ID: ${prestashopCategoryId}, Parent: ${prestashopParentId})`);
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

    // Show summary
    if (createdCount > 0 || existingCount > 0 || errorCount > 0) {
        const message = `Category sync completed: ${createdCount} created, ${existingCount} already existed, ${errorCount} errors`;
        console.log(message);
        
        // Show toast notification if there were results
        if (createdCount > 0 || errorCount > 0) {
            showToast(message, errorCount > 0 ? 'warning' : 'success');
        }
    }
}

// Removed loadPrestashopCategories() and displayPrestashopCategories() functions
// Categories are automatically managed by the backend during export
// The backend checks for existing categories and creates them if needed

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
    if (errorCount > 0) {
        showToast(`Export completed: ${successCount} success, ${errorCount} errors`, 'error', 10000);
        console.error('Export errors:', errors);
    } else {
        showToast(`Successfully exported ${successCount} product(s) to PrestaShop!`, 'success', 10000);
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

// Removed Created Products feature - no longer needed

// Removed localStorage caching - data is always loaded fresh from Allegro API

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
        await Promise.all(batch.map(async (catId) => {
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
    if (!validateAuth() || !isOAuthConnected) {
        return;
    }
    
    const categoriesListEl = document.getElementById('categoriesList');
    if (!categoriesListEl) return;
    
    // Show a short, friendly loading message
    categoriesListEl.innerHTML = '<div style="text-align: center; padding: 20px; color: #1a73e8; font-size: 0.9em;">Loading categories from your offers...</div>';
    
    try {
        // Fetch ACTIVE offers by default to match Allegro website count
        // This ensures category counts match what Allegro displays
        let allOffers = [];
        let offset = 0;
        const limit = 1000; // Maximum allowed by API
        let hasMore = true;
        let totalCountFromAPI = null; // Store API's totalCount for accurate display
        
        while (hasMore) {
            // Filter by ACTIVE status to match Allegro website (which shows ACTIVE offers by default)
            const response = await authFetch(`${API_BASE}/api/offers?offset=${offset}&limit=${limit}&status=ACTIVE`);
            
            if (!response.ok) {
                if (response.status === 401) {
                    throw new Error('Invalid credentials. Please check your Client ID and Client Secret.');
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
        
        // Filter to only active offers for accurate counts
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
        
        // Extract unique categories from offers with counts
        // Only count offers with ACTIVE status
        const categoriesFromOffers = new Map();
        
        // Use the already filtered active offers for counting
        let offersWithCategories = 0;
        let offersWithoutCategories = 0;
        
        activeOffersForCount.forEach(offer => {
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
                const catId = String(offerCategoryId);
                if (!categoriesFromOffers.has(catId)) {
                    categoriesFromOffers.set(catId, {
                        id: catId,
                        name: offerCategoryName || categoryNameCache[catId] || `Category ${catId}`,
                        count: 0
                    });
                }
                categoriesFromOffers.get(catId).count++;
            } else {
                offersWithoutCategories++;
            }
        });
        
        console.log(`Category extraction: ${offersWithCategories} offers with categories, ${offersWithoutCategories} offers without categories`);
        
        // Convert map to array and fetch category names if needed
        const categoriesArray = Array.from(categoriesFromOffers.values());
        
        console.log(`Found ${categoriesArray.length} unique categories from ${activeOffersForCount.length} active offers`);
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
        await Promise.all(categoriesArray.map(async (cat) => {
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
            // Display the category tree in the sidebar
            await loadCategoryTreeRoot(false);
            
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
        categoriesListEl.innerHTML = '<p style="text-align: center; padding: 20px; color: #c5221f;">Failed to load categories. Please try again.</p>';
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
    
    // If we have a tree with products (which includes counts), use it instead of cache
    if (Object.keys(categoryTreeWithProducts).length > 0) {
        await loadCategoryTreeLevel(null, [], forceReload);
        return;
    }
    
    // Otherwise, use cache if available and not forcing reload
    if (!forceReload && categoryTreeInitialized && categoryTreeCache[rootKey]) {
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

    // Fallback to API if tree not built yet
    if (!forceReload && categoryTreeCache[key]) {
        await displayCategories(categoryTreeCache[key], categoryTreePath);
        categoryTreeInitialized = true;
        return;
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
        const isConfigured = (typeof isAuthenticated !== 'undefined' && isAuthenticated) && 
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
                
                // Load sync logs when sync-log tab is opened
                if (targetTab === 'sync-log') {
                    loadSyncLogs();
                    // Auto-refresh sync logs every 2 seconds when tab is active for real-time updates
                    if (window.syncLogInterval) {
                        clearInterval(window.syncLogInterval);
                    }
                    window.syncLogInterval = setInterval(() => {
                        if (targetContent.classList.contains('active')) {
                            loadSyncLogs();
                        }
                    }, 2000); // Poll every 2 seconds for real-time updates
                    
                    // Start real-time timer updates
                    startSyncTimer();
                } else if (targetTab === 'user-management') {
                    // Load users when user-management tab is opened
                    loadUsers();
                } else {
                    // Clear interval when switching away from sync-log tab
                    if (window.syncLogInterval) {
                        clearInterval(window.syncLogInterval);
                        window.syncLogInterval = null;
                    }
                    // Stop timer when switching away
                    if (syncTimerInterval) {
                        clearInterval(syncTimerInterval);
                        syncTimerInterval = null;
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

// Sync Stock Log Functions
async function loadSyncLogs() {
    try {
        const response = await authFetch('/api/sync/logs?limit=200');
        const data = await response.json();
        
        if (data.success) {
            displaySyncLogs(data.logs);
            updateSyncStatus(data.lastSyncTime, data.nextSyncTime);
        } else {
            console.error('Failed to load sync logs:', data.error);
        }
    } catch (error) {
        console.error('Error loading sync logs:', error);
    }
}

function displaySyncLogs(logs) {
    const syncLogList = document.getElementById('syncLogList');
    const productCheckingList = document.getElementById('productCheckingList');
    const productCheckingItems = document.getElementById('productCheckingItems');
    const checkingProgress = document.getElementById('checkingProgress');
    
    if (!syncLogList) return;
    
    if (!logs || logs.length === 0) {
        syncLogList.innerHTML = '<div class="sync-log-empty">No sync logs yet. Stock sync will run automatically every 5 minutes.</div>';
        if (productCheckingList) productCheckingList.style.display = 'none';
        return;
    }
    
    // Separate product checking logs from summary/info logs
    const productLogs = logs.filter(log => log.productName && log.status !== 'info');
    const summaryLogs = logs.filter(log => !log.productName || log.status === 'info');
    
    // Display product checking list if there are product logs
    if (productLogs.length > 0 && productCheckingList && productCheckingItems) {
        productCheckingList.style.display = 'block';
        
        // Group products by name to show latest status
        const productStatusMap = new Map();
        productLogs.forEach(log => {
            const key = log.prestashopProductId || log.offerId || log.productName;
            if (!productStatusMap.has(key) || new Date(log.timestamp) > new Date(productStatusMap.get(key).timestamp)) {
                productStatusMap.set(key, log);
            }
        });
        
        const productArray = Array.from(productStatusMap.values());
        const checkingCount = productArray.filter(p => p.status === 'checking').length;
        const syncedCount = productArray.filter(p => p.status === 'success').length;
        const unchangedCount = productArray.filter(p => p.status === 'unchanged').length;
        const errorCount = productArray.filter(p => p.status === 'error').length;
        const skippedCount = productArray.filter(p => p.status === 'warning' || p.status === 'skipped').length;
        const totalCount = productArray.length;
        
        // Update progress
        if (checkingProgress) {
            const completed = totalCount - checkingCount;
            checkingProgress.textContent = `Progress: ${completed}/${totalCount} checked (${syncedCount} synced, ${unchangedCount} unchanged, ${skippedCount} skipped, ${errorCount} errors)`;
        }
        
        // Sort by timestamp (oldest first for checking list to show progress)
        productArray.sort((a, b) => {
            const dateA = new Date(a.timestamp);
            const dateB = new Date(b.timestamp);
            return dateA - dateB; // Oldest first
        });
        
        productCheckingItems.innerHTML = productArray.map(log => {
            const statusClass = log.status || 'info';
            const statusIcon = getStatusIcon(statusClass);
            const statusText = getStatusText(statusClass);
            
            let stockInfo = '';
            if (log.stockChange && log.stockChange.from !== null && log.stockChange.to !== null) {
                stockInfo = `<span class="product-check-stock">Stock: ${log.stockChange.from} → ${log.stockChange.to}</span>`;
            }
            
            let idsInfo = '';
            if (log.offerId || log.prestashopProductId) {
                const parts = [];
                if (log.offerId) parts.push(`Allegro: ${log.offerId}`);
                if (log.prestashopProductId) parts.push(`PrestaShop: ${log.prestashopProductId}`);
                idsInfo = `<span>${parts.join(' | ')}</span>`;
            }
            
            let productDisplayName = '';
            if (log.productName && log.productName.trim() !== '' && !log.productName.startsWith('Offer ')) {
                productDisplayName = escapeHtml(log.productName);
            } else if (log.offerId) {
                productDisplayName = `Offer ${escapeHtml(log.offerId)}`;
            } else if (log.prestashopProductId) {
                productDisplayName = `Product ID ${escapeHtml(log.prestashopProductId)}`;
            } else {
                productDisplayName = 'Unknown Product';
            }
            
            if (log.categoryName) {
                productDisplayName += `<span style="font-weight: 400; color: #666; font-size: 0.9em;"> • ${escapeHtml(log.categoryName)}</span>`;
            }
            
            // Format sync date from timestamp
            let syncDateDisplay = '';
            if (log.timestamp) {
                const syncDate = new Date(log.timestamp);
                syncDateDisplay = syncDate.toLocaleString('en-US', {
                    year: 'numeric',
                    month: '2-digit',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                    hour12: false
                });
            }
            
            return `
                <div class="product-checking-item ${statusClass}">
                    <div class="product-check-status ${statusClass}">${statusIcon}</div>
                    <div class="product-check-info">
                        <div class="product-check-name">${productDisplayName}</div>
                        <div class="product-check-details">
                            <span>${statusText}</span>
                            ${stockInfo}
                            ${idsInfo}
                        </div>
                    </div>
                    <div class="product-check-sync-date">${syncDateDisplay}</div>
                </div>
            `;
        }).join('');
    } else {
        if (productCheckingList) productCheckingList.style.display = 'none';
    }
    
    // Display summary logs (excluding info status logs)
    const sortedLogs = [...summaryLogs]
        .filter(log => (log.status || 'info') !== 'info') // Filter out info logs
        .sort((a, b) => {
            const dateA = new Date(a.timestamp);
            const dateB = new Date(b.timestamp);
            return dateB - dateA; // Newest first
        });
    
    syncLogList.innerHTML = sortedLogs.map(log => {
        const timestamp = new Date(log.timestamp).toLocaleString();
        const statusClass = log.status || 'info';
        
        let stockChangeHtml = '';
        if (log.stockChange && log.stockChange.from !== null && log.stockChange.to !== null) {
            stockChangeHtml = `
                <div class="sync-log-stock-change">
                    Stock: ${log.stockChange.from} <span class="stock-arrow">→</span> ${log.stockChange.to}
                </div>
            `;
        }
        
        // Display product name prominently - use product name if available, otherwise show offer ID
        let productInfo = '';
        let displayName = '';
        let categoryInfo = '';
        
        if (log.categoryName) {
            categoryInfo = `<span style="font-weight: 400; color: #666; font-size: 0.9em;"> • ${escapeHtml(log.categoryName)}</span>`;
        }
        
        if (log.productName && log.productName.trim() !== '' && !log.productName.startsWith('Offer ')) {
            // Product name is available and not a fallback "Offer {ID}" format
            displayName = escapeHtml(log.productName);
        } else if (log.offerId) {
            // Fallback to showing offer ID if no proper product name
            displayName = `Offer ${escapeHtml(log.offerId)}`;
        } else if (log.prestashopProductId) {
            // Last resort: show PrestaShop ID
            displayName = `Product ID ${escapeHtml(log.prestashopProductId)}`;
        } else {
            displayName = 'Unknown Product';
        }
        
        if (displayName) {
            productInfo = `<div class="sync-log-product" style="font-weight: 600; margin-bottom: 4px;">${displayName}${categoryInfo}</div>`;
        }
        
        let detailsHtml = '';
        if (log.offerId || log.prestashopProductId) {
            const parts = [];
            if (log.offerId) parts.push(`Allegro: ${log.offerId}`);
            if (log.prestashopProductId) parts.push(`PrestaShop: ${log.prestashopProductId}`);
            detailsHtml = `<div style="font-size: 0.85em; color: #999; margin-top: 4px;">${parts.join(' | ')}</div>`;
        }
        
        // Skip "checking" status logs in the main log list (they're shown in checking list)
        if (statusClass === 'checking') {
            return '';
        }
        
        return `
            <div class="sync-log-entry ${statusClass}">
                <div class="sync-log-header">
                    <div class="sync-log-timestamp">${timestamp}</div>
                    <span class="sync-log-status ${statusClass}">${statusClass}</span>
                </div>
                <div class="sync-log-details">
                    ${productInfo}
                    <div class="sync-log-message">${escapeHtml(log.message || '')}</div>
                    ${stockChangeHtml}
                    ${detailsHtml}
                </div>
            </div>
        `;
    }).filter(html => html !== '').join('');
}

function getStatusIcon(status) {
    switch(status) {
        case 'checking': return '⟳';
        case 'success': return '✓';
        case 'unchanged': return '○';
        case 'error': return '✗';
        case 'warning':
        case 'skipped': return '⚠';
        default: return '•';
    }
}

function getStatusText(status) {
    switch(status) {
        case 'checking': return 'Checking...';
        case 'success': return 'Synced';
        case 'unchanged': return 'Unchanged';
        case 'error': return 'Error';
        case 'warning':
        case 'skipped': return 'Skipped';
        default: return 'Info';
    }
}

// Store sync times for real-time updates
let currentLastSyncTime = null;
let currentNextSyncTime = null;
let syncTimerInterval = null;

function updateSyncStatus(lastSyncTime, nextSyncTime) {
    currentLastSyncTime = lastSyncTime;
    currentNextSyncTime = nextSyncTime;
    
    const lastSyncTimeEl = document.getElementById('lastSyncTime');
    const nextSyncTimeEl = document.getElementById('nextSyncTime');
    
    if (lastSyncTimeEl) {
        if (lastSyncTime) {
            const lastSync = new Date(lastSyncTime);
            lastSyncTimeEl.textContent = lastSync.toLocaleString();
        } else {
            lastSyncTimeEl.textContent = 'Never';
        }
    }
    
    if (nextSyncTimeEl) {
        if (nextSyncTime) {
            const nextSync = new Date(nextSyncTime);
            nextSyncTimeEl.textContent = nextSync.toLocaleString();
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
    if (timeUntilEl && currentNextSyncTime) {
        const nextSync = new Date(currentNextSyncTime);
        const now = new Date();
        const remaining = Math.floor((nextSync - now) / 1000); // seconds
        
        if (remaining > 0) {
            timeUntilEl.textContent = `(in ${formatTimeRemaining(remaining)})`;
            timeUntilEl.style.color = '#1a73e8';
        } else {
            timeUntilEl.textContent = '(sync running...)';
            timeUntilEl.style.color = '#34a853';
        }
    } else if (timeUntilEl) {
        timeUntilEl.textContent = '';
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
                const createdAt = new Date(user.created_at).toLocaleString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
                const isActive = user.is_active !== false && user.is_active !== 0;
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
                        <td>${createdAt}</td>
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
        if (userManagementContent) {
            userManagementContent.style.display = 'block';
        }
    } else {
        if (userManagementTab) {
            userManagementTab.style.display = 'none';
        }
        if (userManagementContent) {
            userManagementContent.style.display = 'none';
        }
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
}



