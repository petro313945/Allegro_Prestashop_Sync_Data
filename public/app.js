// State management
let currentOffers = [];
let allLoadedOffers = []; // Store all loaded offers for filtering
let importedOffers = [];
let currentOffset = 0; // Kept for display purposes
let currentLimit = 20;
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

// PrestaShop state
let prestashopCategories = [];
let prestashopConfigured = false;

// API Base URL
const API_BASE = '';

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    // Show main interface immediately - no modal
    showMainInterface();
    setupEventListeners();
    loadImportedOffers();
    loadPrestashopConfig();
    checkPrestashopStatus();
    // Initially disable all actions until authenticated
    updateUIState(false);
});

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
            allegroStatus.className = 'config-status';
        }
    }
    
    // Update PrestaShop status
    const prestashopStatusEl = document.getElementById('prestashopConfigStatus');
    if (prestashopStatusEl) {
        if (prestashopConfigured) {
            prestashopStatusEl.textContent = 'Configured';
            prestashopStatusEl.className = 'config-status success';
        } else {
            prestashopStatusEl.textContent = 'Not Configured';
            prestashopStatusEl.className = 'config-status';
        }
    }
}

// Setup event listeners
function setupEventListeners() {
    document.getElementById('saveCredentialsBtn').addEventListener('click', saveCredentials);
    const clearBtn = document.getElementById('clearCredentialsBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', clearCredentials);
    }
    const clearBtnHeader = document.getElementById('clearCredentialsBtnHeader');
    if (clearBtnHeader) {
        clearBtnHeader.addEventListener('click', clearCredentials);
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
    
    // Listen for OAuth success message from popup
    window.addEventListener('message', function(event) {
        if (event.data && event.data.type === 'oauth_success') {
            checkOAuthStatus();
        }
    });
    
    // Add event listener for load offers button
    const loadOffersBtn = document.getElementById('loadOffersBtn');
    if (loadOffersBtn) {
        loadOffersBtn.addEventListener('click', () => {
            const limit = parseInt(document.getElementById('limit').value);
            currentLimit = limit;
            currentOffset = 0;
            currentPageNumber = 1;
            totalProductsSeen = 0;
            allLoadedOffers = []; // Clear previous offers
            fetchAllOffers(); // Fetch all offers
        });
    }
    
    // Add event listener for product count change
    const limitSelect = document.getElementById('limit');
    if (limitSelect) {
        limitSelect.addEventListener('change', handleProductCountChange);
    }
    document.getElementById('importSelectedBtn').addEventListener('click', importSelected);
    document.getElementById('importAllBtn').addEventListener('click', importAll);
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
    
    document.getElementById('loadCategoriesBtn').addEventListener('click', loadCategories);
    document.getElementById('clearCategoryBtn').addEventListener('click', clearCategorySelection);
    document.getElementById('clearImportedBtn').addEventListener('click', clearImportedProducts);
    document.getElementById('exportToPrestashopBtn').addEventListener('click', exportToPrestashop);
    
    // PrestaShop event listeners
    const savePrestashopBtn = document.getElementById('savePrestashopBtn');
    if (savePrestashopBtn) {
        savePrestashopBtn.addEventListener('click', savePrestashopConfig);
    }
    const testPrestashopBtn = document.getElementById('testPrestashopBtn');
    if (testPrestashopBtn) {
        testPrestashopBtn.addEventListener('click', testPrestashopConnection);
    }
    const loadPrestashopCategoriesBtn = document.getElementById('loadPrestashopCategoriesBtn');
    if (loadPrestashopCategoriesBtn) {
        loadPrestashopCategoriesBtn.addEventListener('click', loadPrestashopCategories);
    }
    
    // Load PrestaShop config on startup
    loadPrestashopConfig();
    checkPrestashopStatus();
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
    connectBtn.textContent = 'CONNECTING...';
    
    try {
        // Step 1: Send credentials to backend
        const credentialsResponse = await fetch(`${API_BASE}/api/credentials`, {
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
        const authResponse = await fetch(`${API_BASE}/api/test-auth`);
        
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
                authStatusEl.textContent = 'Authenticated';
                authStatusEl.className = 'status-value success';
            }
            
            // Show disconnect button in header
            const clearBtnHeader = document.getElementById('clearCredentialsBtnHeader');
            if (clearBtnHeader) {
                clearBtnHeader.style.display = 'block';
            }
            
            // Update config status indicators
            updateConfigStatuses();
            
            // Update UI state
            updateUIState(true);
            
            // Check API status
            await checkApiStatus();
            
            // Check OAuth status
            await checkOAuthStatus();
            
            // Auto-load categories when authenticated
            await loadCategories();
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
        // Re-enable button
        connectBtn.disabled = false;
        connectBtn.textContent = 'CONNECT';
    }
}

// This function is no longer used - authentication happens in saveCredentials()
// Keeping for backward compatibility if needed elsewhere
async function sendCredentialsToBackend(clientId, clientSecret) {
    try {
        const response = await fetch(`${API_BASE}/api/credentials`, {
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
    const mainApp = document.getElementById('mainApp');
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
        await fetch(`${API_BASE}/api/oauth/disconnect`, {
            method: 'POST'
        });
    } catch (error) {
        console.error('Error disconnecting OAuth:', error);
    }
    
    updateUIState(false);
    
    // Hide main interface
    hideMainInterface();
    
    // Clear API status
    const apiStatusEl = document.getElementById('apiStatus');
    const authStatusEl = document.getElementById('authStatus');
    const oauthStatusEl = document.getElementById('oauthStatus');
    if (apiStatusEl) {
        apiStatusEl.textContent = 'Disconnected';
        apiStatusEl.className = 'status-value error';
    }
    if (authStatusEl) {
        authStatusEl.textContent = 'Pending';
        authStatusEl.className = 'status-value';
    }
    if (oauthStatusEl) {
        oauthStatusEl.textContent = 'Not Connected';
        oauthStatusEl.className = 'status-value error';
    }
    isAuthenticated = false;
    isOAuthConnected = false;
    updateUIState(false);
    
    // Hide disconnect button and authorize button in header
    const clearBtnHeader = document.getElementById('clearCredentialsBtnHeader');
    const authorizeBtn = document.getElementById('authorizeAccountBtn');
    if (clearBtnHeader) {
        clearBtnHeader.style.display = 'none';
    }
    if (authorizeBtn) {
        authorizeBtn.style.display = 'none';
    }
    
}

// Check if user is authenticated
function checkAuthentication() {
    const authStatusEl = document.getElementById('authStatus');
    return authStatusEl && authStatusEl.className.includes('success') && authStatusEl.textContent === 'Authenticated';
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
    const importAllBtn = document.getElementById('importAllBtn');
    const limitSelect = document.getElementById('limit');
    const selectedCategorySelect = document.getElementById('selectedCategory');
    
    // Disable all actions and inputs if not authenticated
    const authenticated = checkAuthentication();
    const authRequiredMessage = document.getElementById('authRequiredMessage');
    
    if (authRequiredMessage) {
        authRequiredMessage.style.display = authenticated ? 'none' : 'block';
    }
    
    // Enable product count based on authentication (no longer requires category)
    if (limitSelect) {
        limitSelect.disabled = !authenticated;
    }
    
    const loadCategoriesBtn = document.getElementById('loadCategoriesBtn');
    const loadOffersBtn = document.getElementById('loadOffersBtn');
    
    if (selectedCategorySelect) {
        selectedCategorySelect.disabled = !authenticated;
    }
    
    if (loadCategoriesBtn) {
        loadCategoriesBtn.disabled = !authenticated;
    }
    
    if (loadOffersBtn) {
        loadOffersBtn.disabled = !authenticated;
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
    
    if (importAllBtn) {
        importAllBtn.disabled = !authenticated || currentOffers.length === 0;
        if (!authenticated) {
            importAllBtn.title = 'Authentication required';
        } else {
            importAllBtn.title = '';
        }
    }
}

// Check API status
async function checkApiStatus() {
    try {
        const response = await fetch(`${API_BASE}/api/health`);
        const data = await response.json();
        
        const statusEl = document.getElementById('apiStatus');
        if (statusEl) {
            if (data.configured) {
                statusEl.textContent = 'Configured';
                statusEl.className = 'status-value success';
            } else {
                statusEl.textContent = 'Disconnected';
                statusEl.className = 'status-value error';
            }
        }
    } catch (error) {
        const statusEl = document.getElementById('apiStatus');
        if (statusEl) {
            statusEl.textContent = 'Error';
            statusEl.className = 'status-value error';
        }
    }
}

// Check OAuth connection status
async function checkOAuthStatus() {
    try {
        const response = await fetch(`${API_BASE}/api/oauth/status`);
        const data = await response.json();
        
        const oauthStatusEl = document.getElementById('oauthStatus');
        const authorizeBtn = document.getElementById('authorizeAccountBtn');
        
        isOAuthConnected = data.connected || false;
        
        if (oauthStatusEl) {
            if (isOAuthConnected) {
                oauthStatusEl.textContent = 'Connected';
                oauthStatusEl.className = 'status-value success';
            } else {
                oauthStatusEl.textContent = 'Not Connected';
                oauthStatusEl.className = 'status-value error';
            }
        }
        
        // Show/hide authorize button based on authentication and OAuth status
        if (authorizeBtn && isAuthenticated) {
            if (isOAuthConnected) {
                authorizeBtn.style.display = 'none';
            } else {
                authorizeBtn.style.display = 'block';
            }
        }
    } catch (error) {
        console.error('Error checking OAuth status:', error);
        const oauthStatusEl = document.getElementById('oauthStatus');
        if (oauthStatusEl) {
            oauthStatusEl.textContent = 'Error';
            oauthStatusEl.className = 'status-value error';
        }
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
        const response = await fetch(`${API_BASE}/api/oauth/authorize`);
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
                // If connected, refresh offers
                if (isOAuthConnected) {
                    showToast('Account authorized successfully!', 'success');
                    // Refresh offers if already loaded
                    if (currentOffers.length > 0 || currentPageNumber > 1) {
                        await fetchOffers(currentOffset, currentLimit);
                    }
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
        authStatusEl.textContent = 'Testing';
        authStatusEl.className = 'status-value pending';
    }
    
    const clientId = document.getElementById('clientId').value.trim();
    const clientSecret = document.getElementById('clientSecret').value.trim();
    
    if (!clientId || !clientSecret) {
        if (authStatusEl) {
            authStatusEl.textContent = 'Credentials required';
            authStatusEl.className = 'status-value error';
        }
        showToast('Credentials required', 'error');
        return;
    }
    
    // Ensure credentials are sent to backend
    try {
        await sendCredentialsToBackend(clientId, clientSecret);
    } catch (error) {
        if (authStatusEl) {
            authStatusEl.textContent = 'Error';
            authStatusEl.className = 'status-value error';
        }
        showToast('Failed to save credentials', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/api/test-auth`);
        
        // Check for 401 status before parsing JSON
        if (!response.ok && response.status === 401) {
            throw new Error('Invalid credentials. Please check your Client ID and Client Secret.');
        }
        
        const data = await response.json();
        
        if (data.success) {
            if (authStatusEl) {
                authStatusEl.textContent = 'Authenticated';
                authStatusEl.className = 'status-value success';
            }
            isAuthenticated = true;
            updateUIState(true);
            showToast('Authentication successful', 'success');
            // Auto-load categories when authenticated
            await loadCategories();
        } else {
            if (authStatusEl) {
                authStatusEl.textContent = 'Failed';
                authStatusEl.className = 'status-value error';
            }
            isAuthenticated = false;
            updateUIState(false);
            showToast('Authentication failed. Please check your credentials.', 'error');
        }
    } catch (error) {
        if (authStatusEl) {
            authStatusEl.textContent = 'Error';
            authStatusEl.className = 'status-value error';
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

// Handle product count change - automatically fetch offers if already loaded
async function handleProductCountChange() {
    // Validate authentication first
    if (!validateAuth()) {
        return;
    }
    
    const limitSelect = document.getElementById('limit');
    const limit = parseInt(limitSelect.value);
    
    // Only update if we already have offers loaded (user has clicked "Load My Offers")
    if (allLoadedOffers.length > 0 || currentOffers.length > 0 || currentPageNumber > 1) {
        // Reset pagination state for new limit
        currentOffset = 0;
        currentLimit = limit;
        pageHistory = [];
        currentPageNumber = 1; // Reset to first page
        totalProductsSeen = 0; // Reset total products seen
        
        // Just update the display with new limit (no need to re-fetch)
        displayOffersPage();
    }
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
    offersListEl.innerHTML = '<div style="text-align: center; padding: 40px; color: #1a73e8;">Loading all offers...</div>';
    
    try {
        let allOffers = [];
        let offset = 0;
        const limit = 1000; // Use maximum limit to fetch more at once
        let hasMore = true;
        let totalCountFromAPI = null;
        
        // Fetch all pages
        while (hasMore) {
            const params = new URLSearchParams();
            params.append('offset', offset);
            params.append('limit', limit);
            
            const response = await fetch(`${API_BASE}/api/offers?${params}`);
            
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
        
        // Store all loaded offers
        allLoadedOffers = allOffers;
        totalCount = totalCountFromAPI || allOffers.length;
        
        // Log first offer to debug structure
        if (allOffers.length > 0) {
            console.log(`Loaded ${allOffers.length} total offers`);
            console.log('First offer from API:', JSON.stringify(allOffers[0], null, 2));
            console.log('Offer category structure:', allOffers[0].category);
        }
        
        // Apply category filter if selected
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
        
        // Reset pagination
        currentOffset = 0;
        currentPageNumber = 1;
        pageHistory = [];
        totalProductsSeen = 0;
        
        // Display first page
        displayOffersPage();
        updateImportButtons();
        
        // Update categories to show only those with products
        if (allCategories.length > 0) {
            displayCategories(allCategories);
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
        
        const response = await fetch(`${API_BASE}/api/offers?${params}`);
        
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
    
    // Update categories to show only those with products
    if (allCategories.length > 0) {
        displayCategories(allCategories);
    }
}

// Display current page of offers
async function displayOffersPage() {
    const offersListEl = document.getElementById('offersList');
    const resultsCountEl = document.getElementById('resultsCount');
    
    // Get offers for current page
    const startIndex = currentOffset;
    const endIndex = Math.min(startIndex + currentLimit, currentOffers.length);
    const pageOffers = currentOffers.slice(startIndex, endIndex);
    
    // Update results count with total filtered count
    resultsCountEl.textContent = currentOffers.length;
    
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
    
    // Fetch full product details for products without images
    // This is done asynchronously to not block the UI
    const productsWithoutImages = pageOffers.filter(p => {
        // Check if product has no image in primaryImage or images array
        const hasPrimaryImage = p.primaryImage && p.primaryImage.url;
        const hasImages = p.images && Array.isArray(p.images) && p.images.length > 0;
        return !hasPrimaryImage && !hasImages;
    });
    if (productsWithoutImages.length > 0) {
        console.log(`Fetching details for ${productsWithoutImages.length} products without images...`);
        // Fetch details for first few products to avoid too many requests
        const productsToFetch = productsWithoutImages.slice(0, 10);
        await Promise.all(productsToFetch.map(product => fetchProductDetails(product.id)));
    }
    
    updatePagination();
}

// Fetch full product details including images
async function fetchProductDetails(productId) {
    try {
        const response = await fetch(`${API_BASE}/api/products/${productId}`);
        if (!response.ok) return;
        
        const result = await response.json();
        if (result.success && result.data) {
            const product = result.data;
            const card = document.querySelector(`[data-product-id="${productId}"]`);
            if (!card) return;
            
            let imageUrl = '';
            
            // Check primaryImage first (Allegro /sale/offers format)
            if (product.primaryImage && product.primaryImage.url) {
                imageUrl = product.primaryImage.url;
            }
            // Check images array
            else if (product.images && Array.isArray(product.images) && product.images.length > 0) {
                const firstImage = product.images[0];
                imageUrl = firstImage.url || firstImage.uri || firstImage.path || firstImage.src || '';
            }
            
            // Update the card if we found an image
            if (imageUrl) {
                const imageWrapper = card.querySelector('.offer-image-wrapper');
                if (imageWrapper) {
                    imageWrapper.innerHTML = `
                        <img src="${imageUrl}" alt="${escapeHtml(product.name || 'Product')}" class="offer-image" 
                             loading="lazy"
                             onerror="this.onerror=null; this.style.display='none'; this.nextElementSibling.style.display='flex';">
                        <div class="offer-image-placeholder" style="display: none;">
                            <span>No Image</span>
                        </div>
                    `;
                }
            }
        }
    } catch (error) {
        console.error(`Error fetching product details for ${productId}:`, error);
    }
}

// Create offer card HTML (for products from /sale/products endpoint)
function createOfferCard(product) {
    // Extract product image - check multiple possible locations
    let mainImage = '';
    
    // Method 1: Check primaryImage.url (Allegro /sale/offers API format)
    if (product.primaryImage && product.primaryImage.url) {
        mainImage = product.primaryImage.url;
    }
    // Method 2: Check product.images array (standard Allegro API format)
    else if (product.images) {
        if (Array.isArray(product.images) && product.images.length > 0) {
            const firstImage = product.images[0];
            if (typeof firstImage === 'object' && firstImage !== null) {
                // Try common image URL properties
                mainImage = firstImage.url || firstImage.uri || firstImage.path || firstImage.src || firstImage.link || '';
            } else if (typeof firstImage === 'string' && firstImage.startsWith('http')) {
                mainImage = firstImage;
            }
        } else if (typeof product.images === 'string' && product.images.startsWith('http')) {
            mainImage = product.images;
        } else if (typeof product.images === 'object' && product.images !== null) {
            mainImage = product.images.url || product.images.uri || product.images.path || product.images.src || '';
        }
    }
    // Method 3: Check alternative image locations (some APIs use different fields)
    else if (!mainImage) {
        mainImage = product.image || product.imageUrl || product.photo || product.thumbnail || '';
    }
    // Method 4: Check if images are in a nested structure
    else if (!mainImage && product.media && product.media.images) {
        if (Array.isArray(product.media.images) && product.media.images.length > 0) {
            const firstMediaImage = product.media.images[0];
            mainImage = firstMediaImage.url || firstMediaImage.uri || firstMediaImage || '';
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
                    const card = document.querySelector(`[data-product-id="${productId}"]`);
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
    if (product.stock) {
        const available = product.stock.available || 0;
        const sold = product.stock.sold || 0;
        if (available > 0) {
            stockInfo = `Stock: ${available}${sold > 0 ? ` (${sold} sold)` : ''}`;
        } else if (sold > 0) {
            stockInfo = `Sold: ${sold}`;
        }
    }
    
    // Extract stats information
    let statsInfo = null;
    if (product.stats) {
        const watchers = product.stats.watchersCount || 0;
        const visits = product.stats.visitsCount || 0;
        const statsParts = [];
        if (watchers > 0) {
            statsParts.push(`${watchers} watcher${watchers !== 1 ? 's' : ''}`);
        }
        if (visits > 0) {
            statsParts.push(`${visits} visit${visits !== 1 ? 's' : ''}`);
        }
        if (statsParts.length > 0) {
            statsInfo = statsParts.join(', ');
        }
    }
    
    return `
        <div class="offer-card" data-product-id="${productId}">
            <div class="offer-image-wrapper">
                ${mainImage ? `
                    <img src="${mainImage}" alt="${escapeHtml(productName)}" class="offer-image" 
                         loading="lazy"
                         onerror="this.onerror=null; this.style.display='none'; this.nextElementSibling.style.display='flex';">
                    <div class="offer-image-placeholder" style="display: none;">
                        <span>No Image</span>
                    </div>
                ` : `
                    <div class="offer-image-placeholder">
                        <span>No Image</span>
                    </div>
                `}
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
                            } else if (badge === 'ACTIVE') {
                                return `<span class="offer-badge badge-active">${badge}</span>`;
                            } else if (badge === 'INACTIVE') {
                                return `<span class="offer-badge badge-inactive">${badge}</span>`;
                            } else if (badge === 'ENDED') {
                                return `<span class="offer-badge badge-ended">${badge}</span>`;
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
                    ${stockInfo ? `
                        <div class="stock-info">
                            <span>${stockInfo}</span>
                        </div>
                    ` : ''}
                    ${statsInfo ? `
                        <div class="stats-info">
                            <span>${statsInfo}</span>
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
        </div>
    `;
}

// Update pagination
function updatePagination() {
    const paginationEl = document.getElementById('pagination');
    const pageInfoEl = document.getElementById('pageInfo');
    const totalCountInfoEl = document.getElementById('totalCountInfo');
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const pageJumpInput = document.getElementById('pageJumpInput');
    
    if (currentOffers.length === 0 && currentPageNumber === 1) {
        paginationEl.style.display = 'none';
        return;
    }
    
    paginationEl.style.display = 'flex';
    
    // Calculate max page number based on filtered offers
    let maxPage = 1;
    if (currentOffers.length > 0 && currentLimit > 0) {
        maxPage = Math.ceil(currentOffers.length / currentLimit);
    }
    
    // Update page jump input
    if (pageJumpInput) {
        pageJumpInput.value = currentPageNumber;
        pageJumpInput.max = maxPage;
        pageJumpInput.min = 1;
    }
    
    // Calculate current page offers count
    const startIndex = currentOffset;
    const endIndex = Math.min(startIndex + currentLimit, currentOffers.length);
    const pageOffersCount = endIndex - startIndex;
    
    // Check if there are more pages
    const hasMorePages = currentOffset + currentLimit < currentOffers.length;
    
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
        totalCountInfoEl.textContent = `Total: ${currentOffers.length} offer${currentOffers.length !== 1 ? 's' : ''}`;
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
    
    // Calculate max page based on filtered offers
    let maxPage = 1;
    if (currentOffers.length > 0 && currentLimit > 0) {
        maxPage = Math.ceil(currentOffers.length / currentLimit);
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
    const importAllBtn = document.getElementById('importAllBtn');
    const authenticated = checkAuthentication();
    
    if (importSelectedBtn) {
        importSelectedBtn.disabled = !authenticated || selectedCheckboxes.length === 0;
    }
    
    if (importAllBtn) {
        importAllBtn.disabled = !authenticated || currentOffers.length === 0;
    }
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
}

// Import all offers
function importAll() {
    // Validate authentication
    if (!validateAuth()) {
        return;
    }
    
    importOffers(currentOffers);
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
    const importedCountEl = document.getElementById('importedCount');
    const clearImportedBtn = document.getElementById('clearImportedBtn');
    const exportToPrestashopBtn = document.getElementById('exportToPrestashopBtn');
    
    importedCountEl.textContent = importedOffers.length;
    
    // Enable/disable buttons based on imported products count
    if (clearImportedBtn) {
        clearImportedBtn.disabled = importedOffers.length === 0;
    }
    
    // Update export button state (checks both imported offers and PrestaShop config)
    updateExportButtonState();
    
    if (importedOffers.length === 0) {
        importedListEl.innerHTML = '<p style="text-align: center; padding: 20px; color: #1a73e8;">No products imported yet</p>';
        return;
    }
    
    importedListEl.innerHTML = importedOffers.map(offer => {
        // Extract product image - same logic as createOfferCard
        let mainImage = '';
        
        // Method 1: Check primaryImage.url (Allegro /sale/offers API format)
        if (offer.primaryImage && offer.primaryImage.url) {
            mainImage = offer.primaryImage.url;
        }
        // Method 2: Check offer.images array
        else if (offer.images) {
            if (Array.isArray(offer.images) && offer.images.length > 0) {
                const firstImage = offer.images[0];
                if (typeof firstImage === 'object' && firstImage !== null) {
                    mainImage = firstImage.url || firstImage.uri || firstImage.path || firstImage.src || firstImage.link || '';
                } else if (typeof firstImage === 'string' && firstImage.startsWith('http')) {
                    mainImage = firstImage;
                }
            } else if (typeof offer.images === 'string' && offer.images.startsWith('http')) {
                mainImage = offer.images;
            } else if (typeof offer.images === 'object' && offer.images !== null) {
                mainImage = offer.images.url || offer.images.uri || offer.images.path || offer.images.src || '';
            }
        }
        // Method 3: Check alternative image locations
        else if (!mainImage) {
            mainImage = offer.image || offer.imageUrl || offer.photo || offer.thumbnail || '';
        }
        
        const productName = offer.name || 'Untitled Product';
        // Truncate product name to keep it short
        const shortName = productName.length > 50 ? productName.substring(0, 47) + '...' : productName;
        // Shorten product ID for display
        const shortId = offer.id.length > 12 ? offer.id.substring(0, 8) + '...' : offer.id;
        
        return `
        <div class="imported-item" data-offer-id="${offer.id}">
            <div class="imported-item-image">
                ${mainImage ? `
                    <img src="${mainImage}" alt="${escapeHtml(productName)}" class="imported-item-img" 
                         loading="lazy"
                         onerror="this.onerror=null; this.style.display='none'; this.nextElementSibling.style.display='flex';">
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
    
    if (offer.product?.description) {
        return offer.product.description;
    }
    
    if (offer.details?.description) {
        return offer.details.description;
    }
    
    // Check for HTML description
    if (offer.descriptionHtml) {
        return offer.descriptionHtml;
    }
    
    return '';
}

// PrestaShop Configuration Functions

async function savePrestashopConfig() {
    const url = document.getElementById('prestashopUrl').value.trim();
    const apiKey = document.getElementById('prestashopApiKey').value.trim();
    const disableStockSync = document.getElementById('disableStockSyncToAllegro').checked;
    
    if (!url || !apiKey) {
        showToast('Please fill in all PrestaShop fields', 'error');
        return;
    }
    
    // Hide any previous messages
    const messageEl = document.getElementById('prestashopMessage');
    if (messageEl) messageEl.style.display = 'none';
    
    try {
        const response = await fetch(`${API_BASE}/api/prestashop/configure`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                baseUrl: url,
                apiKey: apiKey,
                disableStockSyncToAllegro: disableStockSync
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('✓ PrestaShop configuration saved successfully!', 'success');
            localStorage.setItem('prestashopConfig', JSON.stringify({ url, apiKey, disableStockSync }));
            prestashopConfigured = true;
            checkPrestashopStatus();
            updateExportButtonState();
        } else {
            showToast('✗ ' + (data.error || 'Failed to save configuration'), 'error', 8000);
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
    testBtn.textContent = 'Testing...';
    
    try {
        // Save temporarily for test
        const response = await fetch(`${API_BASE}/api/prestashop/configure`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                baseUrl: url,
                apiKey: apiKey,
                disableStockSyncToAllegro: document.getElementById('disableStockSyncToAllegro').checked
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Failed to save configuration');
        }
        
        // Test connection
        const testResponse = await fetch(`${API_BASE}/api/prestashop/test`);
        const testData = await testResponse.json();
        
        if (testData.success) {
            // Save to localStorage when test succeeds
            const disableStockSync = document.getElementById('disableStockSyncToAllegro').checked;
            localStorage.setItem('prestashopConfig', JSON.stringify({ url, apiKey, disableStockSync }));
            showToast('✓ ' + testData.message, 'success');
            prestashopConfigured = true;
            updateConfigStatuses();
            checkPrestashopStatus();
        } else {
            // Show error with line breaks if it contains \n
            const errorMsg = (testData.error || 'Connection failed').replace(/\n/g, '<br>');
            showToast('✗ ' + errorMsg, 'error', 10000);
        }
    } catch (error) {
        // Format error message for better readability
        let errorMsg = error.message;
        if (errorMsg.includes('\n')) {
            errorMsg = errorMsg.replace(/\n/g, '<br>• ');
            errorMsg = '• ' + errorMsg;
        }
        showToast('✗ ' + errorMsg, 'error', 10000);
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
            document.getElementById('disableStockSyncToAllegro').checked = config.disableStockSync || false;
        } catch (e) {
            console.error('Error loading PrestaShop config:', e);
            // Fallback to empty if parsing fails
            document.getElementById('prestashopUrl').value = '';
            document.getElementById('prestashopApiKey').value = '';
        }
    } else {
        // No saved config - leave empty so user enters their URL
        document.getElementById('prestashopUrl').value = '';
        document.getElementById('prestashopApiKey').value = '';
    }
}

async function checkPrestashopStatus() {
    try {
        const response = await fetch(`${API_BASE}/api/prestashop/status`);
        const data = await response.json();
        
        prestashopConfigured = data.configured;
        
        // Update header status
        const statusEl = document.getElementById('prestashopStatus');
        if (statusEl) {
            statusEl.textContent = data.configured ? 'Configured' : 'Not Configured';
            statusEl.style.color = data.configured ? '#28a745' : '#dc3545';
        }
        
        // Update config panel status
        updateConfigStatuses();
        updateExportButtonState();
    } catch (error) {
        console.error('Error checking PrestaShop status:', error);
    }
}

async function loadPrestashopCategories() {
    if (!prestashopConfigured) {
        showToast('Please configure PrestaShop first', 'error');
        return;
    }
    
    try {
        showToast('Loading PrestaShop categories...', 'info');
        const response = await fetch(`${API_BASE}/api/prestashop/categories`);
        const data = await response.json();
        
        if (data.success && data.categories) {
            prestashopCategories = data.categories;
            displayPrestashopCategories();
            document.getElementById('prestashopCategoriesSection').style.display = 'block';
            showToast(`Loaded ${prestashopCategories.length} categories`, 'success');
        } else {
            showToast(data.error || 'Failed to load categories', 'error');
        }
    } catch (error) {
        showToast('Error loading categories: ' + error.message, 'error');
    }
}

function displayPrestashopCategories() {
    const listEl = document.getElementById('prestashopCategoriesList');
    if (!listEl) return;
    
    if (prestashopCategories.length === 0) {
        listEl.innerHTML = '<p style="padding: 20px; color: #666;">No categories found</p>';
        return;
    }
    
    listEl.innerHTML = prestashopCategories.map(cat => {
        const catData = cat.category || cat;
        const id = catData.id || cat.id;
        const name = (catData.name && Array.isArray(catData.name)) 
            ? catData.name[0]?.value || catData.name[0] || 'Unnamed'
            : (catData.name || 'Unnamed');
        
        return `
            <div class="imported-item" style="padding: 10px; border-bottom: 1px solid #eee;">
                <strong>${name}</strong> <span style="color: #666;">(ID: ${id})</span>
            </div>
        `;
    }).join('');
}

function updateExportButtonState() {
    const exportBtn = document.getElementById('exportToPrestashopBtn');
    const loadCategoriesBtn = document.getElementById('loadPrestashopCategoriesBtn');
    
    if (exportBtn) {
        exportBtn.disabled = importedOffers.length === 0 || !prestashopConfigured;
    }
    if (loadCategoriesBtn) {
        loadCategoriesBtn.disabled = !prestashopConfigured;
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
    
    const autoCreateCategories = document.getElementById('autoCreateCategories')?.checked || false;
    
    // Confirm before export
    if (!confirm(`Export ${importedOffers.length} product(s) to PrestaShop?`)) {
        return;
    }
    
    showToast('Starting export to PrestaShop...', 'info');
    
    let successCount = 0;
    let errorCount = 0;
    const errors = [];
    
    // Export products one by one
    for (let i = 0; i < importedOffers.length; i++) {
        const offer = importedOffers[i];
        
        try {
            // Find category mapping
            let categoryId = null;
            if (offer.category) {
                const allegroCategoryId = typeof offer.category === 'string' 
                    ? offer.category 
                    : offer.category.id;
                
                // Try to find matching PrestaShop category
                // For now, we'll use auto-create or default
                categoryId = null; // Will be handled by backend if auto-create is enabled
            }
            
            const response = await fetch(`${API_BASE}/api/prestashop/products`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    offer: offer,
                    categoryId: categoryId,
                    autoCreateCategory: autoCreateCategories
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
    }
    
    // Show final results
    if (errorCount > 0) {
        showToast(`Export completed: ${successCount} success, ${errorCount} errors`, 'error', 10000);
        console.error('Export errors:', errors);
    } else {
        showToast(`Successfully exported ${successCount} product(s) to PrestaShop!`, 'success', 10000);
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

// Clear search
function clearSearch() {
    document.getElementById('selectedCategory').value = '';
    document.getElementById('offersList').innerHTML = '';
    document.getElementById('resultsCount').textContent = '0';
    document.getElementById('pagination').style.display = 'none';
    document.getElementById('errorMessage').style.display = 'none';
    
    // Clear visual selection - select "All Categories"
    document.querySelectorAll('.category-item').forEach(item => {
        if (item.dataset.categoryId === 'all') {
            item.classList.add('selected');
        } else {
            item.classList.remove('selected');
        }
    });
    
    // Enable product count (can still load offers without category)
    const limitSelect = document.getElementById('limit');
    if (limitSelect) {
        limitSelect.disabled = false;
    }
    
    // Clear all loaded offers
    allLoadedOffers = [];
    currentOffers = [];
    currentOffset = 0;
    pageHistory = [];
    selectedCategoryId = null; // null means "All Categories"
    currentPageNumber = 1; // Reset to first page
    totalProductsSeen = 0;
    updateImportButtons();
}

// Load categories from API
async function loadCategories() {
    if (!validateAuth()) {
        return;
    }
    
    const errorEl = document.getElementById('errorMessage');
    const categoriesListEl = document.getElementById('categoriesList');
    const loadCategoriesBtn = document.getElementById('loadCategoriesBtn');
    
    errorEl.style.display = 'none';
    categoriesListEl.innerHTML = '<div style="text-align: center; padding: 40px; color: #1a73e8;">Loading categories...</div>';
    loadCategoriesBtn.disabled = true;
    loadCategoriesBtn.textContent = 'Loading...';
    
    try {
        const response = await fetch(`${API_BASE}/api/categories`);
        
        // Check for 401 status before parsing JSON
        if (!response.ok && response.status === 401) {
            throw new Error('Invalid credentials. Please check your Client ID and Client Secret.');
        }
        
        const result = await response.json();
        
        if (result.success) {
            // Handle both direct array and wrapped in categories property
            allCategories = result.data.categories || result.data || [];
            displayCategories(allCategories);
            updateCategorySelect();
        } else {
            throw new Error(result.error?.message || 'Failed to fetch categories');
        }
    } catch (error) {
        // Show user-friendly error message
        let errorMessage = error.message || 'Failed to fetch categories';
        if (errorMessage.includes('status code')) {
            errorMessage = 'Invalid credentials. Please check your Client ID and Client Secret.';
        }
        const errorContentEl = errorEl.querySelector('.error-message-content');
        if (errorContentEl) {
            errorContentEl.textContent = `Failed to fetch categories: ${errorMessage}`;
        } else {
            errorEl.innerHTML = `<div class="error-message-content">Failed to fetch categories: ${errorMessage}</div><button class="error-message-close" onclick="closeErrorMessage()" title="Close">×</button>`;
        }
        errorEl.style.display = 'flex';
        categoriesListEl.innerHTML = '<p style="text-align: center; padding: 20px; color: #c5221f;">Failed to load categories. Please try again.</p>';
    } finally {
        loadCategoriesBtn.disabled = false;
        loadCategoriesBtn.textContent = 'Reload';
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
        const response = await fetch(`${API_BASE}/api/categories/${categoryId}`);
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
async function displayCategories(categories) {
    const categoriesListEl = document.getElementById('categoriesList');
    
    // Extract unique category IDs and names from loaded offers
    const categoriesFromOffers = new Map(); // Map<categoryId, {id, name, count}>
    
    if (allLoadedOffers.length > 0) {
        allLoadedOffers.forEach(offer => {
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
            
            // Also check other possible locations
            if (!offerCategoryId && offer.product?.category) {
                if (typeof offer.product.category === 'string') {
                    offerCategoryId = offer.product.category;
                } else if (offer.product.category.id) {
                    offerCategoryId = offer.product.category.id;
                    offerCategoryName = offer.product.category.name || null;
                }
            }
            
            if (offerCategoryId) {
                const catId = String(offerCategoryId);
                if (!categoriesFromOffers.has(catId)) {
                    categoriesFromOffers.set(catId, {
                        id: catId,
                        name: offerCategoryName || categoryNameCache[catId] || `Category ${catId}`,
                        count: 0
                    });
                }
                categoriesFromOffers.get(catId).count++;
            }
        });
        
        console.log(`Found ${categoriesFromOffers.size} unique categories in offers`);
        console.log('Sample offer structure:', allLoadedOffers[0] ? {
            hasCategory: !!allLoadedOffers[0].category,
            categoryType: typeof allLoadedOffers[0].category,
            categoryValue: allLoadedOffers[0].category
        } : 'No offers');
    }
    
    // Filter categories to only show those with products if we have loaded offers
    let categoriesToDisplay = categories;
    if (categoriesFromOffers.size > 0) {
        // First, try to match with API categories
        const matchedCategories = categories.filter(category => {
            return categoriesFromOffers.has(String(category.id));
        });
        
        // If we found matches, use them (they have proper names from API)
        if (matchedCategories.length > 0) {
            categoriesToDisplay = matchedCategories;
            // Update category names from offers if available
            matchedCategories.forEach(cat => {
                const offerCat = categoriesFromOffers.get(String(cat.id));
                if (offerCat && offerCat.name && offerCat.name !== `Category ${cat.id}`) {
                    cat.name = offerCat.name;
                }
            });
        } else {
            // No matches with API categories, create categories from offers
            categoriesToDisplay = Array.from(categoriesFromOffers.values()).map(cat => ({
                id: cat.id,
                name: cat.name
            }));
            console.log('Created categories from offers:', categoriesToDisplay.length);
        }
        
        categoriesWithProducts = categoriesToDisplay;
    } else {
        // If no offers loaded yet, show all categories
        categoriesWithProducts = categories;
    }
    
    if (categoriesToDisplay.length === 0 && categories.length > 0 && allLoadedOffers.length === 0) {
        categoriesListEl.innerHTML = '<p style="text-align: center; padding: 20px; color: #1a73e8;">No categories with products found. Load offers first.</p>';
        return;
    } else if (categoriesToDisplay.length === 0 && categories.length === 0) {
        categoriesListEl.innerHTML = '<p style="text-align: center; padding: 20px; color: #1a73e8;">No categories found.</p>';
        return;
    } else if (categoriesToDisplay.length === 0 && allLoadedOffers.length > 0) {
        // Offers loaded but no categories found - this shouldn't happen, but show a message
        categoriesListEl.innerHTML = '<p style="text-align: center; padding: 20px; color: #1a73e8;">No categories found in offers. Offers may not have category information.</p>';
        return;
    }
    
    // Render "All Categories" option first
    const allCategoriesSelected = selectedCategoryId === null;
    let html = `
        <div class="category-item ${allCategoriesSelected ? 'selected' : ''}" data-category-id="all">
            <span class="category-item-name">All Categories</span>
        </div>
    `;
    
    // Render categories
    html += categoriesToDisplay.map(category => {
        const isSelected = selectedCategoryId === category.id;
        return `
            <div class="category-item ${isSelected ? 'selected' : ''}" data-category-id="${category.id}">
                <span class="category-item-name">${escapeHtml(category.name || 'Unnamed Category')}</span>
            </div>
        `;
    }).join('');
    
    categoriesListEl.innerHTML = html;
    
    // Add click listeners
    document.querySelectorAll('.category-item').forEach(item => {
        item.addEventListener('click', () => {
            const categoryId = item.dataset.categoryId;
            if (categoryId === 'all') {
                selectCategory(null); // null means "All Categories"
            } else {
                selectCategory(categoryId);
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
    
    // Enable product count when category is selected
    const limitSelect = document.getElementById('limit');
    if (limitSelect) {
        limitSelect.disabled = false;
    }
    
    // Filter and re-display existing offers if any are loaded
    if (allLoadedOffers.length > 0) {
        // Filter offers based on selected category
        let filteredOffers = allLoadedOffers;
        if (categoryId !== null) {
            filteredOffers = allLoadedOffers.filter(offer => {
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
        
        // Enable/disable product count based on category selection
        const limitSelect = document.getElementById('limit');
        if (limitSelect) {
            limitSelect.disabled = !categoryId;
        }
        
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
                document.getElementById('resultsCount').textContent = '0';
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
    
    // Enable product count (can still load offers without category)
    const limitSelect = document.getElementById('limit');
    if (limitSelect) {
        limitSelect.disabled = false;
    }
    
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
        document.getElementById('resultsCount').textContent = '0';
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

