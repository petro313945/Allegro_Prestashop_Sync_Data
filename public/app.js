// State management
let currentOffers = [];
let importedOffers = [];
let currentOffset = 0; // Kept for display purposes
let currentLimit = 20;
let totalCount = 0; // Current page product count
let totalProductsSeen = 0; // Total products seen across all pages in current category
let isAuthenticated = false;
let isOAuthConnected = false; // Track OAuth connection status
let allCategories = [];
let selectedCategoryId = null;
let currentNextPage = null; // For cursor-based pagination
let pageHistory = []; // Track page history for going back
let currentPhrase = ''; // Track current search phrase
let currentPageNumber = 1; // Track current page number
let priceInfoMessageShown = false; // Track if price info message has been shown in this session

// API Base URL
const API_BASE = '';

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    // Always start with first interface - no auto-loading
    hideMainInterface();
    setupEventListeners();
    loadImportedOffers();
    // Initially disable all actions until authenticated
    updateUIState(false);
});

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
            currentOffset = 0;
            currentPageNumber = 1;
            totalProductsSeen = 0;
            fetchOffers(0, limit);
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
    document.getElementById('loadCategoriesBtn').addEventListener('click', loadCategories);
    document.getElementById('clearCategoryBtn').addEventListener('click', clearCategorySelection);
    document.getElementById('clearImportedBtn').addEventListener('click', clearImportedProducts);
    document.getElementById('exportToPrestashopBtn').addEventListener('click', exportToPrestashop);
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
    
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <span class="toast-message">${escapeHtml(message)}</span>
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
            priceInfoMessageShown = false; // Reset message flag for new authentication
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
    const credentialsOverlay = document.getElementById('credentialsOverlay');
    const mainApp = document.getElementById('mainApp');
    if (credentialsOverlay) {
        credentialsOverlay.style.display = 'none';
    }
    if (mainApp) {
        mainApp.style.display = 'flex';
    }
}

// Hide main interface
function hideMainInterface() {
    const credentialsOverlay = document.getElementById('credentialsOverlay');
    const mainApp = document.getElementById('mainApp');
    if (credentialsOverlay) {
        credentialsOverlay.style.display = 'flex';
    }
    if (mainApp) {
        mainApp.style.display = 'none';
    }
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
    priceInfoMessageShown = false; // Reset message flag when disconnecting
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
    
    // Hide price info message
    const priceInfoMessage = document.getElementById('priceInfoMessage');
    if (priceInfoMessage) {
        priceInfoMessage.style.display = 'none';
        priceInfoMessage.style.marginBottom = '0';
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
            priceInfoMessageShown = false; // Reset message flag for new authentication
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
    
    // Only fetch if we already have offers loaded (user has clicked "Load My Offers")
    if (currentOffers.length > 0 || currentPageNumber > 1) {
        // Reset pagination state for new limit
        currentOffset = 0;
        currentLimit = limit;
        pageHistory = [];
        currentPageNumber = 1; // Reset to first page
        totalProductsSeen = 0; // Reset total products seen
        
        await fetchOffers(currentOffset, limit);
    }
}

// Fetch offers from API
// Note: Uses /sale/offers endpoint which returns only the authenticated user's own offers
// This endpoint uses offset-based pagination and doesn't require phrase or category
async function fetchOffers(offset = 0, limit = 20) {
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
            currentOffers = result.data.offers || [];
            // Use totalCount from API if available, otherwise use count or current offers length
            totalCount = result.data.totalCount || result.data.count || currentOffers.length;
            
            // Update current offset for pagination
            currentOffset = offset;
            currentLimit = limit;
            
            // Calculate total products seen (use totalCount if available, otherwise calculate)
            if (result.data.totalCount) {
                totalProductsSeen = Math.min(offset + currentOffers.length, result.data.totalCount);
            } else {
                totalProductsSeen = offset + currentOffers.length;
            }
            
            // Log first offer to debug structure
            if (currentOffers.length > 0) {
                console.log('First offer from API:', JSON.stringify(currentOffers[0], null, 2));
                console.log('Offer category structure:', currentOffers[0].category);
            }
            
            displayOffers(currentOffers);
            updatePagination();
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

// Display offers
async function displayOffers(offers) {
    const offersListEl = document.getElementById('offersList');
    const resultsCountEl = document.getElementById('resultsCount');
    
    resultsCountEl.textContent = totalCount;
    
    // Show price info message only once per authentication session
    if (!priceInfoMessageShown && isAuthenticated) {
        const priceInfoMessage = document.getElementById('priceInfoMessage');
        if (priceInfoMessage) {
            priceInfoMessage.style.display = 'flex';
            priceInfoMessage.style.marginBottom = '20px';
            priceInfoMessageShown = true;
            startPriceInfoMessageTimer();
        }
    }
    
    if (offers.length === 0) {
        offersListEl.innerHTML = '<p style="text-align: center; padding: 40px; color: #1a73e8;">No product offers found in this category. Try selecting a different category.</p>';
        return;
    }
    
    // Render cards first
    offersListEl.innerHTML = offers.map(offer => createOfferCard(offer)).join('');
    
    // Add checkbox listeners
    document.querySelectorAll('.offer-checkbox').forEach(checkbox => {
        checkbox.addEventListener('change', updateImportButtons);
    });
    
    // Fetch full product details for products without images
    // This is done asynchronously to not block the UI
    const productsWithoutImages = offers.filter(p => !p.images || (Array.isArray(p.images) && p.images.length === 0));
    if (productsWithoutImages.length > 0) {
        console.log(`Fetching details for ${productsWithoutImages.length} products without images...`);
        // Fetch details for first few products to avoid too many requests
        const productsToFetch = productsWithoutImages.slice(0, 10);
        await Promise.all(productsToFetch.map(product => fetchProductDetails(product.id)));
    }
}

// Fetch full product details including images
async function fetchProductDetails(productId) {
    try {
        const response = await fetch(`${API_BASE}/api/products/${productId}`);
        if (!response.ok) return;
        
        const result = await response.json();
        if (result.success && result.data) {
            const product = result.data;
            // Update the card if product has images
            if (product.images && Array.isArray(product.images) && product.images.length > 0) {
                const card = document.querySelector(`[data-product-id="${productId}"]`);
                if (card) {
                    const imageWrapper = card.querySelector('.offer-image-wrapper');
                    if (imageWrapper) {
                        const firstImage = product.images[0];
                        const imageUrl = firstImage.url || firstImage.uri || firstImage.path || firstImage.src || '';
                        if (imageUrl) {
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
    
    // Debug: Log product structure to understand image location
    if (!product.images || (Array.isArray(product.images) && product.images.length === 0)) {
        console.log('Product without images:', {
            id: product.id,
            name: product.name,
            allKeys: Object.keys(product),
            hasImages: !!product.images,
            imagesValue: product.images
        });
    }
    
    // Method 1: Check product.images array (standard Allegro API format)
    if (product.images) {
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
    
    // Method 2: Check alternative image locations (some APIs use different fields)
    if (!mainImage) {
        mainImage = product.image || product.imageUrl || product.photo || product.thumbnail || '';
    }
    
    // Method 3: Check if images are in a nested structure
    if (!mainImage && product.media && product.media.images) {
        if (Array.isArray(product.media.images) && product.media.images.length > 0) {
            const firstMediaImage = product.media.images[0];
            mainImage = firstMediaImage.url || firstMediaImage.uri || firstMediaImage || '';
        }
    }
    
    // Log result
    if (mainImage) {
        console.log(`Found image for product ${product.id}:`, mainImage);
    } else {
        console.log(`No image found for product ${product.id} - will fetch details`);
    }
    
    // Product ID
    const productId = product.id || 'N/A';
    
    // Category ID and Name
    // Check multiple possible category structures
    let categoryId = 'N/A';
    if (product.category) {
        if (typeof product.category === 'string') {
            categoryId = product.category;
        } else if (product.category.id) {
            categoryId = product.category.id;
        }
    }
    
    // Get category name - check multiple sources
    let categoryName = 'N/A';
    
    // First, check if category name is directly available in product.category
    if (product.category?.name) {
        categoryName = product.category.name;
    }
    // Second, try to find category name from allCategories array
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
        } else {
            // Debug: log when category not found
            console.log(`Category not found for ID: ${categoryId}`, {
                productId: product.id,
                productCategory: product.category,
                availableCategoryIds: allCategories.slice(0, 10).map(c => c.id)
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
    
    // Extract delivery information
    let deliveryInfo = null;
    if (product.delivery) {
        if (product.delivery.shippingRates) {
            const shippingRate = product.delivery.shippingRates[0];
            if (shippingRate?.time) {
                deliveryInfo = shippingRate.time;
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
                    ${!paymentInfo && !deliveryInfo ? '<div class="no-data-text">none yet</div>' : ''}
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
    
    if (currentOffers.length === 0 && currentPageNumber === 1) {
        paginationEl.style.display = 'none';
        return;
    }
    
    paginationEl.style.display = 'flex';
    
    // For offset-based pagination, check if we have more results
    // If totalCount is available, use it to determine if there are more pages
    // Otherwise, if we got fewer results than the limit, we're on the last page
    const hasMorePages = totalCount > 0 
        ? (currentOffset + currentOffers.length) < totalCount
        : currentOffers.length >= currentLimit;
    let pageInfoText = `Page ${currentPageNumber}`;
    
    if (currentOffers.length > 0) {
        pageInfoText += ` (${currentOffers.length} offer${currentOffers.length !== 1 ? 's' : ''} on this page)`;
    }
    
    pageInfoEl.textContent = pageInfoText;
    
    // Show total count info
    if (totalCountInfoEl) {
        if (hasMorePages) {
            totalCountInfoEl.textContent = `Showing ${totalProductsSeen}+ offers`;
        } else {
            totalCountInfoEl.textContent = `Total: ${totalProductsSeen} offer${totalProductsSeen !== 1 ? 's' : ''}`;
        }
    }
    
    // Prev button: enabled if we have history to go back to (not on first page)
    prevBtn.disabled = currentPageNumber === 1;
    
    // Next button: enabled if we have more results
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
        
        await fetchOffers(currentOffset, currentLimit);
    } else if (direction === -1) {
        // Previous page: go back in history
        if (pageHistory.length === 0 || currentPageNumber === 1) {
            // Reset to first page
            pageHistory = [];
            currentOffset = 0;
            currentPageNumber = 1;
            totalProductsSeen = 0;
            await fetchOffers(0, currentLimit);
        } else {
            // Go back to previous page from history
            const previousPage = pageHistory.pop();
            currentOffset = previousPage.offset;
            currentPageNumber = previousPage.pageNumber;
            totalProductsSeen = currentOffset;
            await fetchOffers(currentOffset, currentLimit);
        }
    }
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
    if (exportToPrestashopBtn) {
        exportToPrestashopBtn.disabled = importedOffers.length === 0;
    }
    
    if (importedOffers.length === 0) {
        importedListEl.innerHTML = '<p style="text-align: center; padding: 20px; color: #1a73e8;">No products imported yet</p>';
        return;
    }
    
    importedListEl.innerHTML = importedOffers.map(offer => {
        // Extract product image - same logic as createOfferCard
        let mainImage = '';
        
        if (offer.images) {
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
        
        if (!mainImage) {
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

// Export to PrestaShop
function exportToPrestashop() {
    if (importedOffers.length === 0) {
        showToast('No products to export', 'error');
        return;
    }
    
    // Create export data in PrestaShop format
    const exportData = {
        products: importedOffers.map(offer => ({
            id: offer.id,
            name: offer.name || 'Untitled Product',
            category: offer.category?.name || offer.category?.id || 'N/A',
            categoryId: offer.category?.id || null,
            images: offer.images || [],
            // Add other fields that PrestaShop might need
            description: offer.description || '',
            price: offer.price || null,
            reference: offer.id
        })),
        exportDate: new Date().toISOString(),
        totalProducts: importedOffers.length
    };
    
    // Convert to JSON and download
    const dataStr = JSON.stringify(exportData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `prestashop_export_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    showToast(`Exported ${importedOffers.length} product(s) to PrestaShop`, 'success');
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
    
    // Clear visual selection
    document.querySelectorAll('.category-item').forEach(item => {
        item.classList.remove('selected');
    });
    
    // Disable product count when no category selected
    const limitSelect = document.getElementById('limit');
    if (limitSelect) {
        limitSelect.disabled = true;
    }
    
    currentOffers = [];
    currentOffset = 0;
    pageHistory = [];
    selectedCategoryId = null;
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

// Display categories
async function displayCategories(categories) {
    const categoriesListEl = document.getElementById('categoriesList');
    
    if (categories.length === 0) {
        categoriesListEl.innerHTML = '<p style="text-align: center; padding: 20px; color: #1a73e8;">No categories found.</p>';
        return;
    }
    
    // Render categories
    categoriesListEl.innerHTML = categories.map(category => {
        const isSelected = selectedCategoryId === category.id;
        return `
            <div class="category-item ${isSelected ? 'selected' : ''}" data-category-id="${category.id}">
                <span class="category-item-name">${escapeHtml(category.name || 'Unnamed Category')}</span>
            </div>
        `;
    }).join('');
    
    // Add click listeners
    document.querySelectorAll('.category-item').forEach(item => {
        item.addEventListener('click', () => {
            const categoryId = item.dataset.categoryId;
            selectCategory(categoryId);
        });
    });
}

// Select a category
function selectCategory(categoryId) {
    selectedCategoryId = categoryId;
    
    // Update visual selection
    document.querySelectorAll('.category-item').forEach(item => {
        if (item.dataset.categoryId === categoryId) {
            item.classList.add('selected');
        } else {
            item.classList.remove('selected');
        }
    });
    
    // Update select dropdown
    const selectedCategorySelect = document.getElementById('selectedCategory');
    if (selectedCategorySelect) {
        selectedCategorySelect.value = categoryId;
    }
    
    // Enable product count when category is selected
    const limitSelect = document.getElementById('limit');
    if (limitSelect) {
        limitSelect.disabled = false;
    }
    
        // Automatically fetch user's offers
        // Reset pagination state
        currentOffset = 0;
        pageHistory = [];
        currentPageNumber = 1; // Reset to first page
        totalProductsSeen = 0;
        const limit = parseInt(document.getElementById('limit').value);
    
    // Show loading indicator
    const loadingEl = document.getElementById('loadingIndicator');
    if (loadingEl) {
        loadingEl.style.display = 'block';
    }
    
    // Fetch and display user's offers
    fetchOffers(currentOffset, limit);
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
        
        // If no category selected, clear selection and products
        if (!categoryId) {
            document.querySelectorAll('.category-item').forEach(item => {
                item.classList.remove('selected');
            });
            document.getElementById('offersList').innerHTML = '';
            document.getElementById('resultsCount').textContent = '0';
            document.getElementById('pagination').style.display = 'none';
            currentOffers = [];
            return;
        }
        
        // Automatically fetch user's offers when category selection changes
        // Reset pagination state
        currentOffset = 0;
        pageHistory = [];
        currentPageNumber = 1; // Reset to first page
        totalProductsSeen = 0;
        const limit = parseInt(document.getElementById('limit').value);
        
        // Show loading indicator
        const loadingEl = document.getElementById('loadingIndicator');
        if (loadingEl) {
            loadingEl.style.display = 'block';
        }
        
        // Always fetch user's offers when category selection changes (though category is not used for filtering)
        fetchOffers(currentOffset, limit);
    });
}

// Clear category selection
function clearCategorySelection() {
    selectedCategoryId = null;
    document.getElementById('selectedCategory').value = '';
    
    // Clear visual selection
    document.querySelectorAll('.category-item').forEach(item => {
        item.classList.remove('selected');
    });
    
    // Disable product count when no category selected
    const limitSelect = document.getElementById('limit');
    if (limitSelect) {
        limitSelect.disabled = true;
    }
    
    // Clear product results
    document.getElementById('offersList').innerHTML = '';
    document.getElementById('resultsCount').textContent = '0';
    document.getElementById('pagination').style.display = 'none';
    currentOffers = [];
    currentOffset = 0;
    pageHistory = [];
    currentPageNumber = 1; // Reset to first page
    totalProductsSeen = 0;
    updateImportButtons();
}

// Close price info message
function closePriceInfoMessage() {
    // Clear the auto-close timer if it exists
    if (priceInfoMessageTimer) {
        clearTimeout(priceInfoMessageTimer);
        priceInfoMessageTimer = null;
    }
    
    const messageEl = document.getElementById('priceInfoMessage');
    if (messageEl) {
        messageEl.classList.add('hiding');
        setTimeout(() => {
            messageEl.style.display = 'none';
            messageEl.classList.remove('hiding');
            // Remove margin to prevent empty space
            messageEl.style.marginBottom = '0';
        }, 300);
    }
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

// Auto-close price info message after 15 seconds
let priceInfoMessageTimer = null;
function startPriceInfoMessageTimer() {
    // Clear any existing timer
    if (priceInfoMessageTimer) {
        clearTimeout(priceInfoMessageTimer);
    }
    
    // Set new timer for 15 seconds
    priceInfoMessageTimer = setTimeout(() => {
        closePriceInfoMessage();
    }, 15000);
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

