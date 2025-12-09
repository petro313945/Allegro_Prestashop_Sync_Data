// State management
let currentOffers = [];
let importedOffers = [];
let currentOffset = 0; // Kept for display purposes
let currentLimit = 20;
let totalCount = 0; // Current page product count
let isAuthenticated = false;
let allCategories = [];
let selectedCategoryId = null;
let currentNextPage = null; // For cursor-based pagination
let pageHistory = []; // Track page history for going back
let currentPhrase = ''; // Track current search phrase
let currentPageNumber = 1; // Track current page number

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
            
            // Show disconnect button in header
            const clearBtnHeader = document.getElementById('clearCredentialsBtnHeader');
            if (clearBtnHeader) {
                clearBtnHeader.style.display = 'block';
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
function clearCredentials() {
    document.getElementById('clientId').value = '';
    document.getElementById('clientSecret').value = '';
    localStorage.removeItem('allegro_clientId');
    localStorage.removeItem('allegro_clientSecret');
    
    const messageEl = document.getElementById('credentialsMessage');
    if (messageEl) {
        messageEl.style.display = 'none';
    }
    
    updateUIState(false);
    
    // Hide main interface
    hideMainInterface();
    
    // Clear API status
    const apiStatusEl = document.getElementById('apiStatus');
    const authStatusEl = document.getElementById('authStatus');
    if (apiStatusEl) {
        apiStatusEl.textContent = 'Disconnected';
        apiStatusEl.className = 'status-value error';
    }
    if (authStatusEl) {
        authStatusEl.textContent = 'Pending';
        authStatusEl.className = 'status-value';
    }
    isAuthenticated = false;
    updateUIState(false);
    
    // Hide disconnect button in header
    const clearBtnHeader = document.getElementById('clearCredentialsBtnHeader');
    if (clearBtnHeader) {
        clearBtnHeader.style.display = 'none';
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
    currentPageNumber = 1; // Reset to first page
    
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
        
        // Send limit parameter to server (will be used to limit results)
        if (limit) {
            params.append('limit', limit);
        }
        
        const response = await fetch(`${API_BASE}/api/offers?${params}`);
        
        // Check for 401 status before parsing JSON
        if (!response.ok && response.status === 401) {
            throw new Error('Invalid credentials. Please check your Client ID and Client Secret.');
        }
        
        const result = await response.json();
        
        if (result.success) {
            currentOffers = result.data.offers || [];
            totalCount = currentOffers.length; // Count of products on current page
            
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
            
            // Log first product to debug structure
            if (currentOffers.length > 0) {
                console.log('First product from API:', JSON.stringify(currentOffers[0], null, 2));
            }
            
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
async function displayOffers(offers) {
    const offersListEl = document.getElementById('offersList');
    const resultsCountEl = document.getElementById('resultsCount');
    
    resultsCountEl.textContent = totalCount;
    
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
    const categoryId = product.category?.id || 'N/A';
    
    // Get category name - check multiple sources
    let categoryName = 'N/A';
    
    // First, check if category name is directly available in product.category
    if (product.category?.name) {
        categoryName = product.category.name;
    }
    // Second, try to find category name from allCategories array
    else if (categoryId !== 'N/A' && allCategories && allCategories.length > 0) {
        // Try exact match first
        let category = allCategories.find(cat => cat.id === categoryId);
        
        // If not found, try with type conversion (string vs number)
        if (!category) {
            category = allCategories.find(cat => 
                String(cat.id) === String(categoryId) || 
                cat.id === String(categoryId) ||
                String(cat.id) === categoryId
            );
        }
        
        if (category && category.name) {
            categoryName = category.name;
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
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    
    if (totalCount === 0 && currentPageNumber === 1) {
        paginationEl.style.display = 'none';
        return;
    }
    
    paginationEl.style.display = 'flex';
    
    // For cursor-based pagination, we track page numbers manually
    // Show current page number and product count
    const hasMorePages = currentNextPage && currentNextPage.id;
    let pageInfoText = `Page ${currentPageNumber}`;
    
    if (totalCount > 0) {
        pageInfoText += ` (${totalCount} product${totalCount !== 1 ? 's' : ''})`;
    }
    
    if (hasMorePages) {
        pageInfoText += ' - More available';
    }
    
    pageInfoEl.textContent = pageInfoText;
    
    // Prev button: enabled if we have history to go back to (not on first page)
    prevBtn.disabled = currentPageNumber === 1;
    
    // Next button: enabled if we have a nextPage cursor
    nextBtn.disabled = !hasMorePages;
}

// Change page (cursor-based pagination)
async function changePage(direction) {
    const categoryId = document.getElementById('selectedCategory').value || null;
    
    if (direction === 1) {
        // Next page: use currentNextPage.id
        if (!currentNextPage || !currentNextPage.id) {
            return;
        }
        
        // Save current page to history for going back
        pageHistory.push({
            offset: currentOffset,
            pageId: null, // We don't have previous page cursor
            pageNumber: currentPageNumber
        });
        
        // Increment page number
        currentPageNumber++;
        currentOffset += currentLimit; // Approximate for display
        
        await fetchOffers(currentPhrase, currentOffset, currentLimit, categoryId, currentNextPage.id);
    } else if (direction === -1) {
        // Previous page: go back in history
        if (pageHistory.length === 0 || currentPageNumber === 1) {
            // Reset to first page
            pageHistory = [];
            currentOffset = 0;
            currentNextPage = null;
            currentPageNumber = 1;
            await fetchOffers(currentPhrase, 0, currentLimit, categoryId, null);
        } else {
            // Go back to previous page
            // Since we don't have previous page cursors from API, reset to first page
            // In a full implementation, we'd need to track all page cursors
            pageHistory = [];
            currentOffset = 0;
            currentNextPage = null;
            currentPageNumber = 1;
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
    currentPageNumber = 1; // Reset to first page
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
        errorEl.textContent = `Failed to fetch categories: ${errorMessage}`;
        errorEl.style.display = 'block';
        categoriesListEl.innerHTML = '<p style="text-align: center; padding: 20px; color: #c5221f;">Failed to load categories. Please try again.</p>';
    } finally {
        loadCategoriesBtn.disabled = false;
        loadCategoriesBtn.textContent = 'Reload';
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
        currentPageNumber = 1; // Reset to first page
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
        currentPageNumber = 1; // Reset to first page
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
    currentPageNumber = 1; // Reset to first page
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

