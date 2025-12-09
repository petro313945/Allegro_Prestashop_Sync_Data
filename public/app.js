// State management
let currentOffers = [];
let importedOffers = [];
let currentOffset = 0; // Kept for display purposes
let currentLimit = 20;
let totalCount = 0;
let isAuthenticated = false;
let allCategories = [];
let selectedCategoryId = null;
let currentNextPage = null; // For cursor-based pagination
let pageHistory = []; // Track page history for going back
let currentPhrase = ''; // Track current search phrase

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
    const testAuthBtn = document.getElementById('testAuthBtn');
    if (testAuthBtn) {
        testAuthBtn.addEventListener('click', testAuthentication);
    }
    document.getElementById('searchBtn').addEventListener('click', searchOffers);
    document.getElementById('clearBtn').addEventListener('click', clearSearch);
    document.getElementById('importSelectedBtn').addEventListener('click', importSelected);
    document.getElementById('importAllBtn').addEventListener('click', importAll);
    document.getElementById('prevBtn').addEventListener('click', () => changePage(-1));
    document.getElementById('nextBtn').addEventListener('click', () => changePage(1));
    document.getElementById('loadCategoriesBtn').addEventListener('click', loadCategories);
    document.getElementById('clearCategoryBtn').addEventListener('click', clearCategorySelection);
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
            const authStatusEl = document.getElementById('authStatus');
            if (authStatusEl) {
                authStatusEl.textContent = 'Authenticated';
                authStatusEl.className = 'status-value success';
            }
            
            // Update UI state
            updateUIState(true);
            
            // Check API status
            await checkApiStatus();
            
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
    const mainContent = document.getElementById('mainContent');
    const container = document.querySelector('.container');
    if (mainContent) {
        mainContent.style.display = 'block';
    }
    if (container) {
        container.style.maxWidth = '1400px';
    }
}

// Hide main interface
function hideMainInterface() {
    const mainContent = document.getElementById('mainContent');
    const container = document.querySelector('.container');
    if (mainContent) {
        mainContent.style.display = 'none';
    }
    if (container) {
        container.style.maxWidth = '500px';
    }
}

// Clear credentials
function clearCredentials() {
    document.getElementById('clientId').value = '';
    document.getElementById('clientSecret').value = '';
    localStorage.removeItem('allegro_clientId');
    localStorage.removeItem('allegro_clientSecret');
    
    const messageEl = document.getElementById('credentialsMessage');
    messageEl.style.display = 'none';
    
    updateUIState(false);
    
    // Hide main interface
    hideMainInterface();
    
    // Clear API status
    document.getElementById('apiStatus').textContent = 'Disconnected';
    document.getElementById('apiStatus').className = 'status-value error';
    document.getElementById('authStatus').textContent = 'Pending';
    document.getElementById('authStatus').className = 'status-value';
    isAuthenticated = false;
    updateUIState(false);
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
            errorEl.textContent = 'Authentication required. Please test connection first.';
            errorEl.style.display = 'block';
            setTimeout(() => {
                errorEl.style.display = 'none';
            }, 5000);
        }
        return false;
    }
    return true;
}

// Update UI state based on credentials and authentication
function updateUIState(configured) {
    const searchBtn = document.getElementById('searchBtn');
    const importSelectedBtn = document.getElementById('importSelectedBtn');
    const importAllBtn = document.getElementById('importAllBtn');
    const limitSelect = document.getElementById('limit');
    
    // Disable all actions and inputs if not authenticated
    const authenticated = checkAuthentication();
    const authRequiredMessage = document.getElementById('authRequiredMessage');
    
    if (authRequiredMessage) {
        authRequiredMessage.style.display = authenticated ? 'none' : 'block';
    }
    
    if (searchBtn) {
        searchBtn.disabled = !authenticated;
        if (!authenticated) {
            searchBtn.title = 'Authentication required';
        } else {
            searchBtn.title = '';
        }
    }
    
    if (limitSelect) {
        limitSelect.disabled = !authenticated;
    }
    
    const selectedCategorySelect = document.getElementById('selectedCategory');
    const loadCategoriesBtn = document.getElementById('loadCategoriesBtn');
    
    if (selectedCategorySelect) {
        selectedCategorySelect.disabled = !authenticated;
    }
    
    if (loadCategoriesBtn) {
        loadCategoriesBtn.disabled = !authenticated;
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

// Search offers
async function searchOffers() {
    // Validate authentication first
    if (!validateAuth()) {
        return;
    }
    
    // Check if credentials are set
    const clientId = document.getElementById('clientId').value.trim();
    const clientSecret = document.getElementById('clientSecret').value.trim();
    
    if (!clientId || !clientSecret) {
        const errorEl = document.getElementById('errorMessage');
        if (errorEl) {
            errorEl.textContent = 'Credentials required';
            errorEl.style.display = 'block';
        }
        return;
    }
    
    // Ensure credentials are sent to backend
    await sendCredentialsToBackend(clientId, clientSecret);
    
    // Double check auth after sending credentials
    if (!checkAuthentication()) {
        const errorEl = document.getElementById('errorMessage');
        if (errorEl) {
            errorEl.textContent = 'Authentication required. Please test connection first.';
            errorEl.style.display = 'block';
        }
        return;
    }
    
    const limit = parseInt(document.getElementById('limit').value);
    const categoryId = document.getElementById('selectedCategory').value || null;
    
    // Reset pagination state for new search
    currentOffset = 0;
    currentLimit = limit;
    currentNextPage = null;
    pageHistory = [];
    currentPhrase = ''; // Will be set to 'aa' by server if category selected
    
    await fetchOffers('', currentOffset, limit, categoryId, null);
}

// Fetch offers from API
// Note: Allegro /sale/products API requires at least 'phrase' parameter (min 2 chars)
// When category is selected, we use "  " (two spaces) as a minimal valid phrase to get all products in that category
async function fetchOffers(phrase = '', offset = 0, limit = 20, categoryId = null, pageId = null) {
    // Validate authentication
    if (!checkAuthentication()) {
        const errorEl = document.getElementById('errorMessage');
        if (errorEl) {
            errorEl.textContent = 'Authentication required. Please test connection first.';
            errorEl.style.display = 'block';
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
        
        // Allegro /sale/products API requires at least 'phrase' parameter (minimum 2 characters, non-whitespace)
        // If category is selected but no phrase provided, server will use minimal valid phrase
        // If phrase is provided, use it (but ensure it's at least 2 chars after trim)
        let searchPhrase = '';
        if (phrase && typeof phrase === 'string') {
            const trimmedPhrase = phrase.trim();
            if (trimmedPhrase.length >= 2) {
                searchPhrase = trimmedPhrase;
            }
        }
        
        // If we have a category but no valid phrase, let server handle it
        // Server will use 'aa' as minimal valid phrase when category is selected
        if (searchPhrase) {
            params.append('phrase', searchPhrase);
        }
        
        // category.id can only be used when searching by phrase
        // Send categoryId - server will add it as 'category.id' if phrase is valid
        if (categoryId) {
            params.append('categoryId', categoryId);
        }
        
        // Use pageId for pagination (cursor-based) instead of offset
        if (pageId) {
            params.append('pageId', pageId);
        }
        
        // Note: limit parameter is not directly supported by /sale/products
        // The API uses cursor-based pagination
        
        const response = await fetch(`${API_BASE}/api/offers?${params}`);
        
        // Check for 401 status before parsing JSON
        if (!response.ok && response.status === 401) {
            throw new Error('Invalid credentials. Please check your Client ID and Client Secret.');
        }
        
        const result = await response.json();
        
        if (result.success) {
            currentOffers = result.data.offers || [];
            totalCount = result.data.count || currentOffers.length;
            
            // Store nextPage for pagination
            currentNextPage = result.data.nextPage || null;
            
            // Update current phrase for pagination
            let searchPhrase = '';
            if (phrase && typeof phrase === 'string') {
                const trimmedPhrase = phrase.trim();
                if (trimmedPhrase.length >= 2) {
                    searchPhrase = trimmedPhrase;
                }
            }
            // If category selected but no phrase, server uses 'produkt' as default
            if (categoryId && !searchPhrase) {
                searchPhrase = 'produkt'; // Server will use this when category is selected
            }
            currentPhrase = searchPhrase;
            
            displayOffers(currentOffers);
            updatePagination();
            updateImportButtons();
        } else {
            // Show the actual error message from the API
            const errorMsg = result.error || result.error?.message || 'Failed to fetch product offers';
            throw new Error(errorMsg);
        }
    } catch (error) {
        // Show detailed error message
        let errorMsg = error.message || 'Request failed';
        
        // If it's a network error, provide more context
        if (error.message === 'Failed to fetch' || error.message === 'NetworkError') {
            errorMsg = 'Network error: Could not connect to server. Please check your connection.';
        }
        
        errorEl.textContent = `Failed to fetch product offers: ${errorMsg}`;
        errorEl.style.display = 'block';
    } finally {
        loadingEl.style.display = 'none';
    }
}

// Display offers
function displayOffers(offers) {
    const offersListEl = document.getElementById('offersList');
    const resultsCountEl = document.getElementById('resultsCount');
    
    resultsCountEl.textContent = totalCount;
    
    if (offers.length === 0) {
        offersListEl.innerHTML = '<p style="text-align: center; padding: 40px; color: #1a73e8;">No product offers found in this category. Try selecting a different category.</p>';
        return;
    }
    
    offersListEl.innerHTML = offers.map(offer => createOfferCard(offer)).join('');
    
    // Add checkbox listeners
    document.querySelectorAll('.offer-checkbox').forEach(checkbox => {
        checkbox.addEventListener('change', updateImportButtons);
    });
}

// Create offer card HTML
function createOfferCard(offer) {
    const price = offer.sellingMode?.price?.amount 
        ? `${parseFloat(offer.sellingMode.price.amount).toFixed(2)} ${offer.sellingMode.price.currency || 'PLN'}`
        : 'N/A';
    
    const images = offer.images || [];
    const mainImage = images.length > 0 ? images[0].url : '';
    
    return `
        <div class="offer-card" data-offer-id="${offer.id}">
            <div class="offer-header">
                <div class="offer-title">${escapeHtml(offer.name || 'Untitled')}</div>
                <input type="checkbox" class="offer-checkbox" data-offer-id="${offer.id}">
            </div>
            ${mainImage ? `<img src="${mainImage}" alt="${escapeHtml(offer.name)}" style="max-width: 200px; max-height: 200px; border-radius: 6px; margin-bottom: 15px;">` : ''}
            <div class="offer-details">
                <div class="offer-detail">
                    <span class="detail-label">Price</span>
                    <span class="detail-value price">${price}</span>
                </div>
                <div class="offer-detail">
                    <span class="detail-label">ID</span>
                    <span class="detail-value">${offer.id}</span>
                </div>
                <div class="offer-detail">
                    <span class="detail-label">Category</span>
                    <span class="detail-value">${offer.category?.id || 'N/A'}</span>
                </div>
                <div class="offer-detail">
                    <span class="detail-label">Stock</span>
                    <span class="detail-value">${offer.stock?.available || 0}</span>
                </div>
                <div class="offer-detail">
                    <span class="detail-label">Seller</span>
                    <span class="detail-value">${offer.seller?.login || 'N/A'}</span>
                </div>
                <div class="offer-detail">
                    <span class="detail-label">Status</span>
                    <span class="detail-value">${offer.publication?.status || 'N/A'}</span>
                </div>
            </div>
            ${offer.description ? `<div style="margin-top: 10px; color: #1a73e8; font-size: 0.9em;">${truncateText(escapeHtml(offer.description), 200)}</div>` : ''}
        </div>
    `;
}

// Update pagination
function updatePagination() {
    const paginationEl = document.getElementById('pagination');
    const pageInfoEl = document.getElementById('pageInfo');
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    
    if (totalCount === 0) {
        paginationEl.style.display = 'none';
        return;
    }
    
    paginationEl.style.display = 'flex';
    
    // For cursor-based pagination, we can't calculate exact page numbers
    // Show approximate page based on current offset
    const currentPage = Math.floor(currentOffset / currentLimit) + 1;
    const totalPages = Math.ceil(totalCount / currentLimit) || 1;
    
    pageInfoEl.textContent = `Page ${currentPage}${totalPages > 1 ? ` of ~${totalPages}` : ''} (${totalCount} products)`;
    
    // Prev button: enabled if we have history to go back to
    prevBtn.disabled = pageHistory.length === 0;
    
    // Next button: enabled if we have a nextPage cursor
    nextBtn.disabled = !currentNextPage || !currentNextPage.id;
}

// Change page (cursor-based pagination)
async function changePage(direction) {
    const categoryId = document.getElementById('selectedCategory').value || null;
    
    if (direction === 1) {
        // Next page: use currentNextPage.id
        if (!currentNextPage || !currentNextPage.id) {
            return;
        }
        
        // Save current page to history (we'll use a marker since we don't have prev cursor)
        // For simplicity, we'll track that we're on page N
        pageHistory.push({
            offset: currentOffset,
            pageId: null // We don't have previous page cursor
        });
        
        currentOffset += currentLimit; // Approximate for display
        await fetchOffers(currentPhrase, currentOffset, currentLimit, categoryId, currentNextPage.id);
    } else if (direction === -1) {
        // Previous page: go back in history
        if (pageHistory.length === 0) {
            // Reset to first page
            pageHistory = [];
            currentOffset = 0;
            currentNextPage = null;
            await fetchOffers(currentPhrase, 0, currentLimit, categoryId, null);
        } else {
            // For now, just reset to first page since we don't have previous page cursors
            // In a full implementation, we'd need to track all page cursors
            pageHistory = [];
            currentOffset = 0;
            currentNextPage = null;
            await fetchOffers(currentPhrase, 0, currentLimit, categoryId, null);
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
    const selectedIds = Array.from(selectedCheckboxes).map(cb => cb.dataset.offerId);
    
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
    
    importedCountEl.textContent = importedOffers.length;
    
    if (importedOffers.length === 0) {
        importedListEl.innerHTML = '<p style="text-align: center; padding: 20px; color: #1a73e8;">No products imported yet</p>';
        return;
    }
    
    importedListEl.innerHTML = importedOffers.map(offer => `
        <div class="imported-item">
            <div>
                <div class="imported-item-title">${escapeHtml(offer.name || 'Untitled')}</div>
                <div class="imported-item-id">ID: ${offer.id}</div>
            </div>
        </div>
    `).join('');
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
    currentOffers = [];
    currentOffset = 0;
    currentNextPage = null;
    pageHistory = [];
    currentPhrase = '';
    selectedCategoryId = null;
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
    loadCategoriesBtn.textContent = 'LOADING...';
    
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
        errorEl.textContent = `Failed to fetch categories: ${errorMessage}`;
        errorEl.style.display = 'block';
        categoriesListEl.innerHTML = '<p style="text-align: center; padding: 20px; color: #c5221f;">Failed to load categories. Please try again.</p>';
    } finally {
        loadCategoriesBtn.disabled = false;
        loadCategoriesBtn.textContent = 'LOAD CATEGORIES';
    }
}

// Display categories
function displayCategories(categories) {
    const categoriesListEl = document.getElementById('categoriesList');
    
    if (categories.length === 0) {
        categoriesListEl.innerHTML = '<p style="text-align: center; padding: 20px; color: #1a73e8;">No categories found.</p>';
        return;
    }
    
    categoriesListEl.innerHTML = categories.map(category => {
        const isSelected = selectedCategoryId === category.id;
        return `
            <div class="category-item ${isSelected ? 'selected' : ''}" data-category-id="${category.id}">
                <span class="category-item-name">${escapeHtml(category.name || 'Unnamed Category')}</span>
                <span class="category-item-id">ID: ${category.id}</span>
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
    
    // Automatically search for products in this category
    // Reset pagination state
    currentOffset = 0;
    currentNextPage = null;
    pageHistory = [];
    currentPhrase = 'produkt'; // Use meaningful phrase when category selected (server will set this)
    const limit = parseInt(document.getElementById('limit').value);
    
    // Show loading indicator
    const loadingEl = document.getElementById('loadingIndicator');
    if (loadingEl) {
        loadingEl.style.display = 'block';
    }
    
    // Fetch and display products for selected category
    // Pass empty phrase - fetchOffers will use '  ' (two spaces) when category is selected
    fetchOffers('', currentOffset, limit, categoryId, null);
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
        
        // If no category selected, clear selection
        if (!categoryId) {
            document.querySelectorAll('.category-item').forEach(item => {
                item.classList.remove('selected');
            });
        }
        
        // Automatically search for products when category changes
        // Reset pagination state
        currentOffset = 0;
        currentNextPage = null;
        pageHistory = [];
        currentPhrase = categoryId ? 'produkt' : ''; // Use meaningful phrase when category selected (server will set this)
        const limit = parseInt(document.getElementById('limit').value);
        
        // Show loading indicator
        const loadingEl = document.getElementById('loadingIndicator');
        if (loadingEl) {
            loadingEl.style.display = 'block';
        }
        
        // Always fetch products when category is selected
        // Pass empty phrase - fetchOffers will use '  ' (two spaces) when category is selected
        fetchOffers('', currentOffset, limit, categoryId, null);
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
    
    // Clear product results
    document.getElementById('offersList').innerHTML = '';
    document.getElementById('resultsCount').textContent = '0';
    document.getElementById('pagination').style.display = 'none';
    currentOffers = [];
    currentOffset = 0;
    currentNextPage = null;
    pageHistory = [];
    currentPhrase = '';
    updateImportButtons();
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

