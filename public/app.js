// State management
let currentOffers = [];
let importedOffers = [];
let currentOffset = 0;
let currentLimit = 20;
let totalCount = 0;
let isAuthenticated = false;
let allCategories = [];
let selectedCategoryId = null;

// API Base URL
const API_BASE = '';

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    loadSavedCredentials();
    checkApiStatus();
    setupEventListeners();
    loadImportedOffers();
    // Initially disable all actions until authenticated
    updateUIState(false);
});

// Setup event listeners
function setupEventListeners() {
    document.getElementById('saveCredentialsBtn').addEventListener('click', saveCredentials);
    document.getElementById('clearCredentialsBtn').addEventListener('click', clearCredentials);
    document.getElementById('testAuthBtn').addEventListener('click', testAuthentication);
    document.getElementById('searchBtn').addEventListener('click', searchOffers);
    document.getElementById('clearBtn').addEventListener('click', clearSearch);
    document.getElementById('importSelectedBtn').addEventListener('click', importSelected);
    document.getElementById('importAllBtn').addEventListener('click', importAll);
    document.getElementById('prevBtn').addEventListener('click', () => changePage(-1));
    document.getElementById('nextBtn').addEventListener('click', () => changePage(1));
    document.getElementById('loadCategoriesBtn').addEventListener('click', loadCategories);
    document.getElementById('clearCategoryBtn').addEventListener('click', clearCategorySelection);
}

// Load saved credentials from localStorage
function loadSavedCredentials() {
    const savedClientId = localStorage.getItem('allegro_clientId');
    const savedClientSecret = localStorage.getItem('allegro_clientSecret');
    
    if (savedClientId && savedClientSecret) {
        document.getElementById('clientId').value = savedClientId;
        document.getElementById('clientSecret').value = savedClientSecret;
        // Automatically send credentials to backend and show interface
        sendCredentialsToBackend(savedClientId, savedClientSecret);
    } else {
        // Hide main interface if no credentials
        hideMainInterface();
    }
}

// Save credentials
async function saveCredentials() {
    const clientId = document.getElementById('clientId').value.trim();
    const clientSecret = document.getElementById('clientSecret').value.trim();
    const messageEl = document.getElementById('credentialsMessage');
    
    if (!clientId || !clientSecret) {
        messageEl.textContent = 'Credentials required';
        messageEl.className = 'message error';
        messageEl.style.display = 'block';
        return;
    }
    
    // Save to localStorage
    localStorage.setItem('allegro_clientId', clientId);
    localStorage.setItem('allegro_clientSecret', clientSecret);
    
    // Send to backend
    await sendCredentialsToBackend(clientId, clientSecret);
}

// Send credentials to backend
async function sendCredentialsToBackend(clientId, clientSecret) {
    const messageEl = document.getElementById('credentialsMessage');
    messageEl.style.display = 'none';
    
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
        
        if (data.success) {
            messageEl.textContent = 'Connected';
            messageEl.className = 'message success';
            messageEl.style.display = 'block';
            
            // Show main content
            showMainInterface();
            
            // Update UI state but don't enable actions until auth is tested
            updateUIState(true);
            
            // Check API status
            await checkApiStatus();
            
            // Reset auth status - user must test auth
            document.getElementById('authStatus').textContent = 'Pending';
            document.getElementById('authStatus').className = 'status-value';
            isAuthenticated = false;
            updateUIState(true);
        } else {
            throw new Error(data.error || 'Failed to save credentials');
        }
    } catch (error) {
        messageEl.textContent = error.message || 'Connection failed';
        messageEl.className = 'message error';
        messageEl.style.display = 'block';
        updateUIState(false);
        hideMainInterface();
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
    const testAuthBtn = document.getElementById('testAuthBtn');
    const searchBtn = document.getElementById('searchBtn');
    const importSelectedBtn = document.getElementById('importSelectedBtn');
    const importAllBtn = document.getElementById('importAllBtn');
    const searchPhraseInput = document.getElementById('searchPhrase');
    const limitSelect = document.getElementById('limit');
    
    if (configured) {
        testAuthBtn.disabled = false;
    } else {
        testAuthBtn.disabled = true;
    }
    
    // Disable all actions and inputs if not authenticated
    const authenticated = checkAuthentication();
    const authRequiredMessage = document.getElementById('authRequiredMessage');
    
    if (authRequiredMessage) {
        authRequiredMessage.style.display = authenticated ? 'none' : 'block';
    }
    
    if (searchBtn) {
        searchBtn.disabled = !authenticated;
        if (!authenticated) {
            searchBtn.title = 'Authentication required. Please test connection first.';
        } else {
            searchBtn.title = '';
        }
    }
    
    if (searchPhraseInput) {
        searchPhraseInput.disabled = !authenticated;
        if (!authenticated) {
            searchPhraseInput.placeholder = 'Authentication required';
        } else {
            searchPhraseInput.placeholder = 'Enter product name or keyword';
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
            importSelectedBtn.title = 'Authentication required. Please test connection first.';
        } else {
            importSelectedBtn.title = '';
        }
    }
    
    if (importAllBtn) {
        importAllBtn.disabled = !authenticated || currentOffers.length === 0;
        if (!authenticated) {
            importAllBtn.title = 'Authentication required. Please test connection first.';
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
        if (data.configured) {
            statusEl.textContent = 'Connected';
            statusEl.className = 'status-value success';
            showMainInterface();
            // Don't enable actions until auth is tested
            updateUIState(true);
        } else {
            statusEl.textContent = 'Disconnected';
            statusEl.className = 'status-value error';
            isAuthenticated = false;
            updateUIState(false);
            hideMainInterface();
        }
    } catch (error) {
        document.getElementById('apiStatus').textContent = 'Error';
        document.getElementById('apiStatus').className = 'status-value error';
        isAuthenticated = false;
        updateUIState(false);
        hideMainInterface();
    }
}

// Test authentication
async function testAuthentication() {
    const authStatusEl = document.getElementById('authStatus');
    authStatusEl.textContent = 'Testing';
    authStatusEl.className = 'status-value pending';
    
    const clientId = document.getElementById('clientId').value.trim();
    const clientSecret = document.getElementById('clientSecret').value.trim();
    
    if (!clientId || !clientSecret) {
        authStatusEl.textContent = 'Credentials required';
        authStatusEl.className = 'status-value error';
        return;
    }
    
    // Ensure credentials are sent to backend
    await sendCredentialsToBackend(clientId, clientSecret);
    
    try {
        const response = await fetch(`${API_BASE}/api/test-auth`);
        const data = await response.json();
        
        if (data.success) {
            authStatusEl.textContent = 'Authenticated';
            authStatusEl.className = 'status-value success';
            isAuthenticated = true;
            updateUIState(true);
            // Auto-load categories when authenticated
            await loadCategories();
        } else {
            authStatusEl.textContent = 'Failed';
            authStatusEl.className = 'status-value error';
            isAuthenticated = false;
            updateUIState(false);
        }
    } catch (error) {
        authStatusEl.textContent = 'Error';
        authStatusEl.className = 'status-value error';
        isAuthenticated = false;
        updateUIState(false);
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
    
    const phrase = document.getElementById('searchPhrase').value.trim();
    const limit = parseInt(document.getElementById('limit').value);
    const categoryId = document.getElementById('selectedCategory').value || null;
    
    currentOffset = 0;
    currentLimit = limit;
    
    await fetchOffers(phrase, currentOffset, limit, categoryId);
}

// Fetch offers from API
async function fetchOffers(phrase = '', offset = 0, limit = 20, categoryId = null) {
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
        const params = new URLSearchParams({
            limit: limit.toString(),
            offset: offset.toString()
        });
        
        if (phrase) {
            params.append('phrase', phrase);
        }
        
        if (categoryId) {
            params.append('categoryId', categoryId);
        }
        
        const response = await fetch(`${API_BASE}/api/offers?${params}`);
        const result = await response.json();
        
        if (result.success) {
            currentOffers = result.data.offers || [];
            totalCount = result.data.count || currentOffers.length;
            
            displayOffers(currentOffers);
            updatePagination();
            updateImportButtons();
        } else {
            throw new Error(result.error?.message || 'Failed to fetch product offers');
        }
    } catch (error) {
        errorEl.textContent = `Failed to fetch product offers: ${error.message || 'Request failed'}`;
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
        offersListEl.innerHTML = '<p style="text-align: center; padding: 40px; color: #1a73e8;">No product offers found. Try a different search term.</p>';
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
    const currentPage = Math.floor(currentOffset / currentLimit) + 1;
    const totalPages = Math.ceil(totalCount / currentLimit);
    
    pageInfoEl.textContent = `Page ${currentPage} of ${totalPages}`;
    prevBtn.disabled = currentOffset === 0;
    nextBtn.disabled = currentOffset + currentLimit >= totalCount;
}

// Change page
async function changePage(direction) {
    const newOffset = currentOffset + (direction * currentLimit);
    
    if (newOffset < 0 || newOffset >= totalCount) {
        return;
    }
    
    currentOffset = newOffset;
    const phrase = document.getElementById('searchPhrase').value.trim();
    const categoryId = document.getElementById('selectedCategory').value || null;
    await fetchOffers(phrase, currentOffset, currentLimit, categoryId);
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
    document.getElementById('searchPhrase').value = '';
    document.getElementById('selectedCategory').value = '';
    document.getElementById('offersList').innerHTML = '';
    document.getElementById('resultsCount').textContent = '0';
    document.getElementById('pagination').style.display = 'none';
    document.getElementById('errorMessage').style.display = 'none';
    currentOffers = [];
    currentOffset = 0;
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
        errorEl.textContent = `Failed to fetch categories: ${error.message || 'Request failed'}`;
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
    const phrase = document.getElementById('searchPhrase').value.trim();
    currentOffset = 0;
    const limit = parseInt(document.getElementById('limit').value);
    
    // Show loading indicator
    const loadingEl = document.getElementById('loadingIndicator');
    if (loadingEl) {
        loadingEl.style.display = 'block';
    }
    
    // Fetch and display products for selected category
    fetchOffers(phrase, currentOffset, limit, categoryId);
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
        const phrase = document.getElementById('searchPhrase').value.trim();
        currentOffset = 0;
        const limit = parseInt(document.getElementById('limit').value);
        
        // Show loading indicator
        const loadingEl = document.getElementById('loadingIndicator');
        if (loadingEl) {
            loadingEl.style.display = 'block';
        }
        
        // Always fetch products when category is selected (even without phrase)
        fetchOffers(phrase, currentOffset, limit, categoryId);
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

