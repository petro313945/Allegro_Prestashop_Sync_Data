const express = require('express');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
require('dotenv').config(); 

const app = express();
const PORT = process.env.PORT || 3000;

// Token storage file path
const TOKEN_STORAGE_FILE = path.join(__dirname, '.tokens.json');
const CREDENTIALS_STORAGE_FILE = path.join(__dirname, '.credentials.json');
const PRESTASHOP_CREDENTIALS_FILE = path.join(__dirname, '.prestashop.json');
const PRODUCT_MAPPINGS_FILE = path.join(__dirname, '.product_mappings.json');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

/**
 * Visitor logging middleware
 * Captures IP, client ID, client info, and request data for all requests
 * Must be after express.json() to access req.body:
 */
app.use((req, res, next) => {
  // Skip logging for the /log endpoint itself to avoid recursive logging
  if (req.path === '/log') {
    return next();
  }

  // Get client IP address (handles proxies/load balancers)
  const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || 
                   req.headers['x-real-ip'] || 
                   req.connection.remoteAddress || 
                   req.socket.remoteAddress ||
                   'unknown';

  // Get client ID from request body (for credentials) or headers, or generate one
  let clientId = req.headers['x-client-id'] || req.headers['client-id'];
  
  // If it's a credentials request, use the clientId from body
  if (req.path === '/api/credentials' && req.body && req.body.clientId) {
    clientId = req.body.clientId;
  }
  
  // If no clientId found, generate one
  if (!clientId) {
    clientId = `client-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  // Get client info (user-agent)
  const client = req.headers['user-agent'] || 'unknown';

  // Capture request data (body for POST/PUT, query for GET)
  let requestData = null;
  if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
    requestData = req.body;
  } else if (Object.keys(req.query).length > 0) {
    requestData = req.query;
  }

  // Create log entry
  const logEntry = {
    ip: clientIP,
    clientId: clientId,
    client: client,
    timestamp: new Date().toISOString(),
    path: req.path,
    method: req.method,
    requestData: requestData
  };

  // Add to logs array
  visitorLogs.push(logEntry);

  // Optional: Limit log size to prevent memory issues (keep last 1000 entries)
  if (visitorLogs.length > 1000) {
    visitorLogs = visitorLogs.slice(-1000);
  }

  next();
});

// Allegro API Configuration - PRODUCTION MODE
const ALLEGRO_API_URL = process.env.ALLEGRO_API_URL || 'https://api.allegro.pl';
const ALLEGRO_AUTH_URL = process.env.ALLEGRO_AUTH_URL || 'https://allegro.pl/auth/oauth';

// Store credentials and tokens (persisted to file)
let userCredentials = {
  clientId: null,
  clientSecret: null
};

let accessToken = null;
let tokenExpiry = null;

// Store user OAuth tokens (for user-level authentication)
let userOAuthTokens = {
  accessToken: null,
  refreshToken: null,
  expiresAt: null,
  userId: null
};

// Store PrestaShop credentials
let prestashopCredentials = {
  baseUrl: null,
  apiKey: null,
  disableStockSyncToAllegro: false // Toggle for PrestaShop → Allegro stock sync
};

// Store product mappings (Allegro offer ID → PrestaShop product ID)
let productMappings = {};

/**
 * Save tokens to file (persistent storage)
 */
function saveTokens() {
  try {
    const tokenData = {
      userOAuthTokens: userOAuthTokens,
      accessToken: accessToken,
      tokenExpiry: tokenExpiry,
      savedAt: new Date().toISOString()
    };
    fs.writeFileSync(TOKEN_STORAGE_FILE, JSON.stringify(tokenData, null, 2), 'utf8');
    console.log('Tokens saved to file');
  } catch (error) {
    console.error('Error saving tokens:', error.message);
  }
}

/**
 * Load tokens from file (on server startup)
 */
function loadTokens() {
  try {
    if (fs.existsSync(TOKEN_STORAGE_FILE)) {
      const tokenData = JSON.parse(fs.readFileSync(TOKEN_STORAGE_FILE, 'utf8'));
      
      // Restore tokens
      if (tokenData.userOAuthTokens) {
        userOAuthTokens = { ...userOAuthTokens, ...tokenData.userOAuthTokens };
      }
      if (tokenData.accessToken) {
        accessToken = tokenData.accessToken;
      }
      if (tokenData.tokenExpiry) {
        tokenExpiry = tokenData.tokenExpiry;
      }
      
      console.log('Tokens loaded from file');
      
      // Check if refresh token is still valid (not expired)
      if (userOAuthTokens.refreshToken && userOAuthTokens.expiresAt) {
        const timeUntilExpiry = userOAuthTokens.expiresAt - Date.now();
        if (timeUntilExpiry > 0) {
          console.log(`Access token expires in ${Math.round(timeUntilExpiry / 1000 / 60)} minutes`);
        } else {
          console.log('Access token expired, will use refresh token on next request');
        }
      }
    }
  } catch (error) {
    console.error('Error loading tokens:', error.message);
    // If file is corrupted, start fresh
    userOAuthTokens = {
      accessToken: null,
      refreshToken: null,
      expiresAt: null,
      userId: null
    };
  }
}

/**
 * Save credentials to file (persistent storage)
 */
function saveCredentials() {
  try {
    const credData = {
      clientId: userCredentials.clientId,
      clientSecret: userCredentials.clientSecret,
      savedAt: new Date().toISOString()
    };
    fs.writeFileSync(CREDENTIALS_STORAGE_FILE, JSON.stringify(credData, null, 2), 'utf8');
    console.log('Credentials saved to file');
  } catch (error) {
    console.error('Error saving credentials:', error.message);
  }
}

/**
 * Load credentials from file (on server startup)
 */
function loadCredentials() {
  try {
    if (fs.existsSync(CREDENTIALS_STORAGE_FILE)) {
      const credData = JSON.parse(fs.readFileSync(CREDENTIALS_STORAGE_FILE, 'utf8'));
      
      if (credData.clientId && credData.clientSecret) {
        userCredentials.clientId = credData.clientId;
        userCredentials.clientSecret = credData.clientSecret;
        console.log('Credentials loaded from file');
      }
    }
  } catch (error) {
    console.error('Error loading credentials:', error.message);
  }
}

/**
 * Save PrestaShop credentials to file
 */
function savePrestashopCredentials() {
  try {
    const credData = {
      baseUrl: prestashopCredentials.baseUrl,
      apiKey: prestashopCredentials.apiKey,
      disableStockSyncToAllegro: prestashopCredentials.disableStockSyncToAllegro,
      savedAt: new Date().toISOString()
    };
    fs.writeFileSync(PRESTASHOP_CREDENTIALS_FILE, JSON.stringify(credData, null, 2), 'utf8');
    console.log('PrestaShop credentials saved to file');
  } catch (error) {
    console.error('Error saving PrestaShop credentials:', error.message);
  }
}

/**
 * Load PrestaShop credentials from file
 */
function loadPrestashopCredentials() {
  try {
    if (fs.existsSync(PRESTASHOP_CREDENTIALS_FILE)) {
      const credData = JSON.parse(fs.readFileSync(PRESTASHOP_CREDENTIALS_FILE, 'utf8'));
      
      if (credData.baseUrl && credData.apiKey) {
        prestashopCredentials.baseUrl = credData.baseUrl;
        prestashopCredentials.apiKey = credData.apiKey;
        prestashopCredentials.disableStockSyncToAllegro = credData.disableStockSyncToAllegro || false;
        console.log('PrestaShop credentials loaded from file');
      }
    }
  } catch (error) {
    console.error('Error loading PrestaShop credentials:', error.message);
  }
}

/**
 * Save product mappings to file
 */
function saveProductMappings() {
  try {
    fs.writeFileSync(PRODUCT_MAPPINGS_FILE, JSON.stringify(productMappings, null, 2), 'utf8');
    console.log('Product mappings saved to file');
  } catch (error) {
    console.error('Error saving product mappings:', error.message);
  }
}

/**
 * Load product mappings from file
 */
function loadProductMappings() {
  try {
    if (fs.existsSync(PRODUCT_MAPPINGS_FILE)) {
      productMappings = JSON.parse(fs.readFileSync(PRODUCT_MAPPINGS_FILE, 'utf8'));
      console.log('Product mappings loaded from file');
    }
  } catch (error) {
    console.error('Error loading product mappings:', error.message);
    productMappings = {};
  }
}

// Load tokens and credentials on server startup
loadCredentials();
loadTokens();
loadPrestashopCredentials();
loadProductMappings();

// Store visitor logs (in-memory storage)
// In production, use proper database storage
let visitorLogs = [];

/**
 * Set user credentials
 */
function setCredentials(clientId, clientSecret) {
  userCredentials.clientId = clientId;
  userCredentials.clientSecret = clientSecret;
  // Invalidate existing token when credentials change
  accessToken = null;
  tokenExpiry = null;
  // Save credentials to file
  saveCredentials();
}

/**
 * Get OAuth access token from Allegro
 */
async function getAccessToken() {
  try {
    // Check if token is still valid
    if (accessToken && tokenExpiry && Date.now() < tokenExpiry) {
      return accessToken;
    }

    if (!userCredentials.clientId || !userCredentials.clientSecret) {
      throw new Error('Credentials required');
    }

    // Create Basic Auth header
    const credentials = Buffer.from(`${userCredentials.clientId}:${userCredentials.clientSecret}`).toString('base64');
    
    // Request token - try with scope first, fallback to without scope if invalid_scope error
    // Note: Scopes are determined by your app configuration in Allegro Developer Portal
    let tokenRequestBody = 'grant_type=client_credentials';
    let response;
    
    try {
      // Try with scope for public API access
      const scope = 'allegro:api';
      tokenRequestBody = `grant_type=client_credentials&scope=${encodeURIComponent(scope)}`;
      
      response = await axios.post(
        `${ALLEGRO_AUTH_URL}/token`,
        tokenRequestBody,
        {
          headers: {
            'Authorization': `Basic ${credentials}`,
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );
    } catch (scopeError) {
      // If invalid_scope error, try without scope (scopes determined by app config)
      if (scopeError.response?.status === 400 && 
          (scopeError.response?.data?.error === 'invalid_scope' || 
           scopeError.response?.data?.error_description?.includes('scope'))) {
        console.log('Scope request failed, trying without explicit scope...');
        tokenRequestBody = 'grant_type=client_credentials';
        response = await axios.post(
          `${ALLEGRO_AUTH_URL}/token`,
          tokenRequestBody,
          {
            headers: {
              'Authorization': `Basic ${credentials}`,
              'Content-Type': 'application/x-www-form-urlencoded'
            }
          }
        );
      } else {
        // Re-throw if it's not a scope error
        throw scopeError;
      }
    }

    accessToken = response.data.access_token;
    // Set expiry time (subtract 60 seconds as buffer)
    const expiresIn = response.data.expires_in || 3600;
    tokenExpiry = Date.now() + (expiresIn - 60) * 1000;

    // Log token info for debugging (without exposing the actual token)
    if (response.data.scope) {
      console.log('Token scopes:', response.data.scope);
    }

    // Save tokens to file
    saveTokens();

    return accessToken;
  } catch (error) {
    console.error('Error getting access token:', error.response?.data || error.message);
    // Convert 401 error to user-friendly message
    if (error.response?.status === 401) {
      const friendlyError = new Error('Invalid credentials. Please check your Client ID and Client Secret.');
      friendlyError.status = 401;
      throw friendlyError;
    }
    // Handle scope-related errors
    if (error.response?.status === 400 && error.response?.data?.error === 'invalid_scope') {
      const friendlyError = new Error('Invalid scope requested. Your application may not have the required permissions configured in the Allegro Developer Portal.');
      friendlyError.status = 400;
      throw friendlyError;
    }
    throw error;
  }
}

/**
 * Get user OAuth access token (refresh if needed)
 */
async function getUserAccessToken() {
  try {
    // Check if token is still valid
    if (userOAuthTokens.accessToken && userOAuthTokens.expiresAt && Date.now() < userOAuthTokens.expiresAt) {
      return userOAuthTokens.accessToken;
    }

    // If we have a refresh token, try to refresh
    if (userOAuthTokens.refreshToken && userCredentials.clientId && userCredentials.clientSecret) {
      try {
        const credentials = Buffer.from(`${userCredentials.clientId}:${userCredentials.clientSecret}`).toString('base64');
        
        const response = await axios.post(
          `${ALLEGRO_AUTH_URL}/token`,
          `grant_type=refresh_token&refresh_token=${encodeURIComponent(userOAuthTokens.refreshToken)}`,
          {
            headers: {
              'Authorization': `Basic ${credentials}`,
              'Content-Type': 'application/x-www-form-urlencoded'
            }
          }
        );

        userOAuthTokens.accessToken = response.data.access_token;
        userOAuthTokens.refreshToken = response.data.refresh_token || userOAuthTokens.refreshToken;
        const expiresIn = response.data.expires_in || 3600;
        userOAuthTokens.expiresAt = Date.now() + (expiresIn - 60) * 1000;

        // Save tokens to file
        saveTokens();

        return userOAuthTokens.accessToken;
      } catch (refreshError) {
        console.error('Error refreshing token:', refreshError.response?.data || refreshError.message);
        // If refresh fails, clear tokens and require re-authentication
        userOAuthTokens = {
          accessToken: null,
          refreshToken: null,
          expiresAt: null,
          userId: null
        };
        throw new Error('Token refresh failed. Please reconnect your account.');
      }
    }

    throw new Error('No valid user token. Please authorize your account.');
  } catch (error) {
    throw error;
  }
}

/**
 * Simple XML escape helper
 */
function xmlEscape(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Generate a PrestaShop-friendly slug (link_rewrite)
 */
function prestashopSlug(value) {
  if (!value) return 'product';
  let slug = String(value)
    .toLowerCase()
    // Remove accents
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    // Keep only letters, numbers and dashes
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  if (!slug) slug = 'product';
  return slug;
}

/**
 * Build PrestaShop XML for a localized field array
 * Example input:
 *   [{ id: 1, value: 'Name PL' }, { id: 2, value: 'Name EN' }]
 * Output:
 *   <tagName><language id="1">Name PL</language>...</tagName>
 */
function buildLocalizedFieldXml(tagName, items) {
  if (!Array.isArray(items) || items.length === 0) {
    return '';
  }
  const languagesXml = items
    .map(lang => `<language id="${xmlEscape(lang.id)}">${xmlEscape(lang.value)}</language>`)
    .join('');
  return `<${tagName}>${languagesXml}</${tagName}>`;
}

/**
 * Build XML body for a PrestaShop product
 */
function buildProductXml(product) {
  const nameXml = buildLocalizedFieldXml('name', product.name);
  const descriptionXml = buildLocalizedFieldXml('description', product.description);
  const shortDescXml = buildLocalizedFieldXml('description_short', product.description_short);
  const linkRewriteXml = buildLocalizedFieldXml('link_rewrite', product.link_rewrite || []);

  const categoriesXml = product.associations && product.associations.categories
    ? `<associations><categories>${product.associations.categories.category
        .map(cat => `<category><id>${xmlEscape(cat.id)}</id></category>`)
        .join('')}</categories></associations>`
    : '';

  return `<?xml version="1.0" encoding="UTF-8"?>
<prestashop xmlns:xlink="http://www.w3.org/1999/xlink">
  <product>
    <id_shop_default>${xmlEscape(product.id_shop_default)}</id_shop_default>
    <id_tax_rules_group>${xmlEscape(
      product.id_tax_rules_group !== undefined ? product.id_tax_rules_group : 0
    )}</id_tax_rules_group>
    <id_category_default>${xmlEscape(product.id_category_default)}</id_category_default>
    <reference>${xmlEscape(product.reference)}</reference>
    ${nameXml}
    ${descriptionXml}
    ${shortDescXml}
    ${linkRewriteXml}
    <price>${xmlEscape(product.price)}</price>
    <active>${xmlEscape(product.active)}</active>
    ${categoriesXml}
  </product>
</prestashop>`;
}

/**
 * Build XML body for a PrestaShop category
 */
function buildCategoryXml(category) {
  const nameXml = buildLocalizedFieldXml('name', category.name);
  const linkRewriteXml = buildLocalizedFieldXml('link_rewrite', category.link_rewrite);

  return `<?xml version="1.0" encoding="UTF-8"?>
<prestashop xmlns:xlink="http://www.w3.org/1999/xlink">
  <category>
    ${nameXml}
    <id_parent>${xmlEscape(category.id_parent)}</id_parent>
    <active>${xmlEscape(category.active)}</active>
    ${linkRewriteXml}
  </category>
</prestashop>`;
}

/**
 * Build XML body for a PrestaShop stock_available resource
 */
function buildStockAvailableXml(stockAvailable) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<prestashop xmlns:xlink="http://www.w3.org/1999/xlink">
  <stock_available>
    <id>${xmlEscape(stockAvailable.id || '')}</id>
    <id_product>${xmlEscape(stockAvailable.id_product)}</id_product>
    <id_product_attribute>${xmlEscape(
      stockAvailable.id_product_attribute !== undefined
        ? stockAvailable.id_product_attribute
        : 0
    )}</id_product_attribute>
    <id_shop>${xmlEscape(
      stockAvailable.id_shop !== undefined ? stockAvailable.id_shop : 1
    )}</id_shop>
    <id_shop_group>${xmlEscape(
      stockAvailable.id_shop_group !== undefined ? stockAvailable.id_shop_group : 0
    )}</id_shop_group>
    <depends_on_stock>${xmlEscape(
      stockAvailable.depends_on_stock !== undefined
        ? stockAvailable.depends_on_stock
        : 0
    )}</depends_on_stock>
    <out_of_stock>${xmlEscape(
      stockAvailable.out_of_stock !== undefined
        ? stockAvailable.out_of_stock
        : 2
    )}</out_of_stock>
    <quantity>${xmlEscape(stockAvailable.quantity)}</quantity>
  </stock_available>
</prestashop>`;
}

/**
 * Make authenticated request to PrestaShop API
 *
 * If "data" is a string, it is sent as raw XML body.
 * If "data" is an object, it is sent as JSON.
 */
async function prestashopApiRequest(endpoint, method = 'GET', data = null) {
  try {
    if (!prestashopCredentials.baseUrl || !prestashopCredentials.apiKey) {
      throw new Error('PrestaShop credentials not configured');
    }

    // Ensure baseUrl ends with /api/
    let apiUrl = prestashopCredentials.baseUrl.trim();
    // Remove trailing slashes first
    apiUrl = apiUrl.replace(/\/+$/, '');
    // Add /api/ if not present
    if (!apiUrl.endsWith('/api')) {
      apiUrl += '/api';
    }
    apiUrl += '/';
    
    const url = `${apiUrl}${endpoint}`;
    
    // PrestaShop API accepts JSON format via query parameter
    // Add output_format=JSON to URL to ensure JSON response (not XML)
    const separator = url.includes('?') ? '&' : '?';
    const jsonUrl = `${url}${separator}output_format=JSON`;
    
    // Log the URL for debugging
    console.log('PrestaShop API Request:', method, jsonUrl);
    
    // PrestaShop uses Basic Auth with API key as password
    // Format: Basic base64(api_key:)
    const auth = Buffer.from(`${prestashopCredentials.apiKey}:`).toString('base64');
    
    const headers = {
      'Authorization': `Basic ${auth}`,
      'Output-Format': 'JSON',
      'Accept': 'application/json'
    };

    // Default to JSON; if data is a string we treat it as XML
    if (typeof data === 'string') {
      headers['Content-Type'] = 'text/xml; charset=UTF-8';
    } else {
      headers['Content-Type'] = 'application/json';
    }

    const config = {
      method: method,
      url: jsonUrl,
      headers,
      timeout: 15000, // 15 second timeout
      validateStatus: function (status) {
        // Don't throw error for 4xx/5xx, let us handle it
        return status >= 200 && status < 600;
      }
    };

    if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
      config.data = data;
    }

    const response = await axios(config);
    
    // Check for error status codes
    if (response.status >= 400) {
      const error = new Error(`PrestaShop API returned status ${response.status}`);
      error.response = response;
      throw error;
    }
    
    return response.data;
  } catch (error) {
    console.error('PrestaShop API Error:', {
      code: error.code,
      message: error.message,
      status: error.response?.status,
      url: error.config?.url,
      data: error.response?.data
    });
    
    // Provide user-friendly error messages
    if (error.code === 'ECONNREFUSED') {
      throw new Error('Cannot connect to PrestaShop. Please check:\n• Is PrestaShop running?\n• Is the Base URL correct? (e.g., http://localhost/poland)\n• Try accessing the URL in your browser first\n• If using a custom port, include it: http://localhost:8080/poland');
    }
    
    if (error.code === 'ENOTFOUND') {
      throw new Error('PrestaShop hostname not found. Please check:\n• Is the Base URL correct?\n• Can you access PrestaShop in your browser?\n• Try: http://localhost/poland');
    }
    
    if (error.code === 'ETIMEDOUT' || error.message.includes('timeout')) {
      throw new Error('Connection to PrestaShop timed out. Please check if PrestaShop is running and accessible.');
    }
    
    if (error.response?.status === 401) {
      throw new Error('PrestaShop authentication failed. Please check your API key in: Advanced Parameters → Web Service');
    }
    
    if (error.response?.status === 404) {
      const attemptedUrl = error.config?.url || 'unknown';
      const baseUrl = prestashopCredentials.baseUrl || 'unknown';
      const expectedApiUrl = baseUrl.replace(/\/+$/, '') + '/api/';
      throw new Error(`PrestaShop API endpoint not found (404).\n\nAttempted URL: ${attemptedUrl}\nConfigured Base URL: ${baseUrl}\nExpected API URL: ${expectedApiUrl}\n\nPlease verify:\n• The Base URL is correct (e.g., http://localhost/polandstore)\n• Web Service is enabled in PrestaShop (Advanced Parameters → Webservice)\n• Try accessing ${expectedApiUrl} in your browser\n• Make sure the URL matches exactly what works in your browser`);
    }
    
    if (error.response?.status === 403) {
      throw new Error('Access denied. Please check if the API key has proper permissions.');
    }
    
    if (error.response?.data) {
      const errorData = error.response.data;
      if (errorData.errors && Array.isArray(errorData.errors)) {
        throw new Error('PrestaShop error: ' + errorData.errors.map(e => e.message || e).join(', '));
      }
      if (errorData.error) {
        throw new Error('PrestaShop error: ' + errorData.error);
      }
    }
    
    // Generic error
    throw new Error(`PrestaShop connection error: ${error.message}`);
  }
}

/**
 * Make authenticated request to Allegro API
 * Uses user OAuth token if available, otherwise falls back to client credentials
 */
async function allegroApiRequest(endpoint, params = {}, useUserToken = false) {
  try {
    let token;
    
    if (useUserToken) {
      // Try to use user OAuth token first
      try {
        token = await getUserAccessToken();
      } catch (userTokenError) {
        // If user token is not available, throw error to indicate OAuth is required
        throw new Error('User OAuth authentication required');
      }
    } else {
      // Use client credentials token
      token = await getAccessToken();
    }
    
    // Log the actual request that will be made
    const url = new URL(`${ALLEGRO_API_URL}${endpoint}`);
    Object.keys(params).forEach(key => {
      url.searchParams.append(key, params[key]);
    });
    console.log('Final request URL:', url.toString());
    
    const response = await axios.get(`${ALLEGRO_API_URL}${endpoint}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.allegro.public.v1+json'
      },
      params: params
    });

    return response.data;
  } catch (error) {
    console.error('Allegro API Error:', error.response?.data || error.message);
    // Convert 401 error to user-friendly message
    if (error.response?.status === 401) {
      const friendlyError = new Error('Authentication failed. Your credentials may be invalid or expired. Please check your Client ID and Client Secret.');
      friendlyError.status = 401;
      throw friendlyError;
    }
    throw error;
  }
}

// API Routes

/**
 * Set credentials endpoint
 */
app.post('/api/credentials', (req, res) => {
  try {
    const { clientId, clientSecret } = req.body;
    
    if (!clientId || !clientSecret) {
      return res.status(400).json({
        success: false,
        error: 'Credentials required'
      });
    }

    setCredentials(clientId, clientSecret);
    
    res.json({
      success: true
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Check if credentials are configured
 */
app.get('/api/credentials/status', (req, res) => {
  res.json({
    configured: !!(userCredentials.clientId && userCredentials.clientSecret)
  });
});

/**
 * Health check endpoint
 */
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    configured: !!(userCredentials.clientId && userCredentials.clientSecret),
    apiUrl: ALLEGRO_API_URL,
    mode: 'PRODUCTION'
  });
});

/**
 * OAuth Authorization endpoint - returns authorization URL for frontend to open
 */
app.get('/api/oauth/authorize', (req, res) => {
  if (!userCredentials.clientId) {
    return res.status(400).json({
      success: false,
      error: 'Client ID and Client Secret must be configured first'
    });
  }

  // Generate state for CSRF protection
  const state = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  
  // Build redirect URI - use environment variable or construct from request
  // Default to the known server URL if available
  let redirectUri;
  if (process.env.OAUTH_REDIRECT_URI) {
    redirectUri = process.env.OAUTH_REDIRECT_URI;
  } else {
    // Construct from request, but prefer http for local development
    const protocol = req.get('x-forwarded-proto') || req.protocol || 'http';
    const host = req.get('host') || `localhost:${PORT}`;
    redirectUri = `${protocol}://${host}/api/oauth/callback`;
  }
  
  const redirectUriEncoded = encodeURIComponent(redirectUri);
  const clientId = encodeURIComponent(userCredentials.clientId);
  const stateParam = encodeURIComponent(state);
  
  // Build authorization URL
  // Note: Scope is determined by your app configuration in Allegro Developer Portal
  // If you specify scope here, it must match what's configured in your app
  // If not specified, Allegro will use the scopes configured for your app
  let authUrl = `${ALLEGRO_AUTH_URL}/authorize?response_type=code&client_id=${clientId}&redirect_uri=${redirectUriEncoded}&state=${stateParam}`;
  
  // Optionally add scope if configured (check your app settings in Developer Portal)
  // Common scopes: 'allegro:api:sale:offers:read' or leave empty to use app defaults
  const requestedScope = process.env.OAUTH_SCOPE || ''; // Set OAUTH_SCOPE env var if needed
  if (requestedScope) {
    authUrl += `&scope=${encodeURIComponent(requestedScope)}`;
  }
  
  console.log('OAuth authorization URL:', authUrl);
  console.log('Redirect URI:', redirectUri);
  
  // Return URL as JSON instead of redirecting (frontend will open it)
  res.json({
    success: true,
    authUrl: authUrl,
    redirectUri: redirectUri
  });
});

/**
 * OAuth Callback endpoint - handles authorization code and exchanges for tokens
 */
app.get('/api/oauth/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query;
    
    if (error) {
      return res.send(`
        <html>
          <head><title>Authorization Failed</title></head>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1>Authorization Failed</h1>
            <p>${error}</p>
            <p><a href="/">Return to application</a></p>
          </body>
        </html>
      `);
    }
    
    if (!code) {
      return res.send(`
        <html>
          <head><title>Authorization Failed</title></head>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1>Authorization Failed</h1>
            <p>No authorization code received.</p>
            <p><a href="/">Return to application</a></p>
          </body>
        </html>
      `);
    }
    
    if (!userCredentials.clientId || !userCredentials.clientSecret) {
      return res.send(`
        <html>
          <head><title>Configuration Error</title></head>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1>Configuration Error</h1>
            <p>Client credentials not configured. Please configure them first.</p>
            <p><a href="/">Return to application</a></p>
          </body>
        </html>
      `);
    }
    
    // Exchange authorization code for tokens
    // Use the same redirect URI construction as in authorize endpoint
    let redirectUri;
    if (process.env.OAUTH_REDIRECT_URI) {
      redirectUri = process.env.OAUTH_REDIRECT_URI;
    } else {
      const protocol = req.get('x-forwarded-proto') || req.protocol || 'http';
      const host = req.get('host') || `localhost:${PORT}`;
      redirectUri = `${protocol}://${host}/api/oauth/callback`;
    }
    
    const credentials = Buffer.from(`${userCredentials.clientId}:${userCredentials.clientSecret}`).toString('base64');
    
    try {
      const tokenResponse = await axios.post(
        `${ALLEGRO_AUTH_URL}/token`,
        `grant_type=authorization_code&code=${encodeURIComponent(code)}&redirect_uri=${encodeURIComponent(redirectUri)}`,
        {
          headers: {
            'Authorization': `Basic ${credentials}`,
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );
      
      // Store user tokens
      userOAuthTokens.accessToken = tokenResponse.data.access_token;
      userOAuthTokens.refreshToken = tokenResponse.data.refresh_token;
      const expiresIn = tokenResponse.data.expires_in || 3600;
      userOAuthTokens.expiresAt = Date.now() + (expiresIn - 60) * 1000;
      
      // Get user info
      try {
        const userInfoResponse = await axios.get(`${ALLEGRO_API_URL}/me`, {
          headers: {
            'Authorization': `Bearer ${userOAuthTokens.accessToken}`,
            'Accept': 'application/vnd.allegro.public.v1+json'
          }
        });
        userOAuthTokens.userId = userInfoResponse.data.id;
      } catch (userInfoError) {
        console.log('Could not fetch user info:', userInfoError.message);
      }
      
      // Save tokens to file (persistent storage)
      saveTokens();
      
      // Redirect to success page
      return res.send(`
        <html>
          <head>
            <title>Authorization Successful</title>
            <script>
              setTimeout(function() {
                window.opener.postMessage({ type: 'oauth_success' }, '*');
                window.close();
              }, 2000);
            </script>
          </head>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: green;">✓ Authorization Successful!</h1>
            <p>Your account has been connected. This window will close automatically.</p>
            <p>If it doesn't close, <a href="/">click here to return to the application</a></p>
          </body>
        </html>
      `);
    } catch (tokenError) {
      console.error('Token exchange error:', tokenError.response?.data || tokenError.message);
      return res.send(`
        <html>
          <head><title>Token Exchange Failed</title></head>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1>Token Exchange Failed</h1>
            <p>${tokenError.response?.data?.error_description || tokenError.message || 'Unknown error'}</p>
            <p><a href="/">Return to application</a></p>
          </body>
        </html>
      `);
    }
  } catch (error) {
    console.error('OAuth callback error:', error);
    return res.send(`
      <html>
        <head><title>Error</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
          <h1>Error</h1>
          <p>${error.message || 'An unexpected error occurred'}</p>
          <p><a href="/">Return to application</a></p>
        </body>
      </html>
    `);
  }
});

/**
 * Check OAuth connection status
 * Attempts to refresh token if expired but refresh token exists
 */
app.get('/api/oauth/status', async (req, res) => {
  try {
    // Check if token is still valid
    let isConnected = !!(userOAuthTokens.accessToken && userOAuthTokens.expiresAt && Date.now() < userOAuthTokens.expiresAt);
    
    // If token is expired but we have a refresh token, try to refresh
    if (!isConnected && userOAuthTokens.refreshToken && userCredentials.clientId && userCredentials.clientSecret) {
      try {
        await getUserAccessToken(); // This will refresh the token if needed
        isConnected = !!(userOAuthTokens.accessToken && userOAuthTokens.expiresAt && Date.now() < userOAuthTokens.expiresAt);
      } catch (refreshError) {
        // Refresh failed - token is not connected
        console.log('Token refresh failed in status check:', refreshError.message);
        isConnected = false;
      }
    }
    
    res.json({
      connected: isConnected,
      userId: userOAuthTokens.userId,
      expiresAt: userOAuthTokens.expiresAt
    });
  } catch (error) {
    console.error('Error checking OAuth status:', error);
    res.json({
      connected: false,
      userId: null,
      expiresAt: null
    });
  }
});

/**
 * Disconnect OAuth (clear user tokens)
 */
app.post('/api/oauth/disconnect', (req, res) => {
  userOAuthTokens = {
    accessToken: null,
    refreshToken: null,
    expiresAt: null,
    userId: null
  };
  
  // Save cleared tokens to file
  saveTokens();
  
  res.json({
    success: true,
    message: 'Disconnected successfully'
  });
});

/**
 * Get user's own offers from Allegro
 * Uses user OAuth token to fetch user's own offers
 */
app.get('/api/offers', async (req, res) => {
  try {
    let { limit = 20, offset = 0, sellerId } = req.query;
    
    // Validate and cap limit
    const parsedLimit = parseInt(limit, 10);
    if (isNaN(parsedLimit) || parsedLimit <= 0) {
      limit = 20;
    } else if (parsedLimit > 1000) {
      limit = 1000;
    } else {
      limit = parsedLimit;
    }
    
    // Validate offset
    const parsedOffset = parseInt(offset, 10);
    if (isNaN(parsedOffset) || parsedOffset < 0) {
      offset = 0;
    } else {
      offset = parsedOffset;
    }
    
    // Try to fetch user's offers using OAuth token
    try {
      const params = {
        limit: limit,
        offset: offset
      };
      
      console.log('Attempting to fetch user offers from /sale/offers with params:', JSON.stringify(params, null, 2));
      const data = await allegroApiRequest('/sale/offers', params, true); // Use user token
      
      console.log('Offers response structure:', {
        hasOffers: !!data.offers,
        offersCount: data.offers?.length || 0,
        count: data.count,
        totalCount: data.totalCount,
        keys: Object.keys(data)
      });
      
      // Log sample offer structure to debug
      if (data.offers && data.offers.length > 0) {
        const sampleOffer = data.offers[0];
        console.log('Sample offer structure:', {
          id: sampleOffer.id,
          name: sampleOffer.name,
          hasImages: !!sampleOffer.images,
          imagesType: typeof sampleOffer.images,
          imagesIsArray: Array.isArray(sampleOffer.images),
          imagesLength: Array.isArray(sampleOffer.images) ? sampleOffer.images.length : 'N/A',
          category: sampleOffer.category,
          allKeys: Object.keys(sampleOffer)
        });
      }
      
      // Normalize response structure for frontend according to API docs
      // API returns: { "offers": [...], "count": 1, "totalCount": 1234 }
      const normalizedData = {
        offers: data.offers || [],
        count: data.count || (data.offers ? data.offers.length : 0),
        totalCount: data.totalCount || data.count || 0
      };
      
      return res.json({
        success: true,
        data: normalizedData
      });
    } catch (offersError) {
      // Check if it's a user token error
      if (offersError.message === 'User OAuth authentication required') {
        return res.status(403).json({
          success: false,
          error: 'User OAuth authentication required. Please authorize your account.',
          requiresUserOAuth: true,
          solution: 'To access your own offers, you need to authorize your account using OAuth.',
          instructions: [
            'Click the "Authorize Account" button to connect your Allegro account.'
          ]
        });
      }
      
      // If /sale/offers fails with 403, it means we need user-level OAuth
      if (offersError.response?.status === 403) {
        console.log('/sale/offers requires user-level OAuth. Providing instructions to user.');
        
        return res.status(403).json({
          success: false,
          error: 'User OAuth authentication required. Please authorize your account.',
          requiresUserOAuth: true,
          solution: 'To access your own offers, you need to authorize your account using OAuth.',
          instructions: [
            'Click the "Authorize Account" button to connect your Allegro account.'
          ]
        });
      }
      
      // Re-throw other errors to be handled below
      throw offersError;
    }
  } catch (error) {
    // Enhanced error logging
    console.error('Error fetching offers:', {
      message: error.message,
      status: error.response?.status,
      statusText: error.response?.statusText,
      data: error.response?.data,
      params: req.query
    });
    
    // Convert technical error messages to user-friendly ones
    let errorMessage = error.message;
    
    // Log full error details for debugging
    if (error.response?.data) {
      console.error('Allegro API Error Response:', JSON.stringify(error.response.data, null, 2));
    }
    
    if (error.response?.status === 401) {
      errorMessage = 'Invalid credentials. Please check your Client ID and Client Secret.';
    } else if (error.response?.status === 403) {
      // Forbidden / Access Denied
      const apiError = error.response?.data;
      if (apiError?.errors && Array.isArray(apiError.errors) && apiError.errors.length > 0) {
        const errorDetail = apiError.errors[0];
        errorMessage = errorDetail.userMessage || errorDetail.message || 'Access is denied.';
        
        // Add helpful guidance for 403 errors
        errorMessage += ' This usually means: (1) Your application needs to be verified by Allegro in the Developer Portal, (2) Your application may not have the required scopes/permissions enabled, or (3) The endpoint requires user-level authentication. Please check your application status at https://apps.developer.allegro.pl/';
      } else if (apiError?.message) {
        errorMessage = apiError.message + ' Please verify your application in the Allegro Developer Portal.';
      } else if (apiError?.userMessage) {
        errorMessage = apiError.userMessage + ' Please verify your application in the Allegro Developer Portal.';
      } else {
        errorMessage = 'Access is denied. Your application may need to be verified by Allegro to access this endpoint. Please check your application status in the Allegro Developer Portal at https://apps.developer.allegro.pl/';
      }
    } else if (error.response?.status === 400) {
      // Bad request - extract detailed error message
      const apiError = error.response?.data;
      if (apiError?.errors && Array.isArray(apiError.errors) && apiError.errors.length > 0) {
        errorMessage = apiError.errors[0].message || apiError.errors[0].userMessage || 'Invalid request parameters.';
      } else if (apiError?.message) {
        errorMessage = apiError.message;
      } else if (apiError?.userMessage) {
        errorMessage = apiError.userMessage;
      } else {
        errorMessage = 'Invalid request parameters. Please check your search criteria.';
      }
    } else if (error.response?.status === 404) {
      errorMessage = 'No offers found matching your criteria.';
    } else if (error.response?.status === 422) {
      // Unprocessable Entity - validation error
      const apiError = error.response?.data;
      if (apiError?.errors && Array.isArray(apiError.errors) && apiError.errors.length > 0) {
        errorMessage = apiError.errors[0].message || apiError.errors[0].userMessage || 'Validation error.';
      } else {
        errorMessage = apiError?.message || 'Invalid request parameters.';
      }
    } else if (error.response?.status) {
      const apiError = error.response?.data;
      errorMessage = apiError?.errors?.[0]?.message ||
                     apiError?.errors?.[0]?.userMessage ||
                     apiError?.message || 
                     apiError?.userMessage ||
                     apiError?.error || 
                     `API Error: ${error.response?.status} ${error.response?.statusText}`;
    }
    
    res.status(error.response?.status || 500).json({
      success: false,
      error: errorMessage,
      details: process.env.NODE_ENV === 'development' ? {
        status: error.response?.status,
        statusText: error.response?.statusText,
        data: error.response?.data
      } : undefined
    });
  }
});

/**
 * Get offer details by ID
 */
app.get('/api/offers/:offerId', async (req, res) => {
  try {
    const { offerId } = req.params;
    const data = await allegroApiRequest(`/sale/offers/${offerId}`);
    
    res.json({
      success: true,
      data: data
    });
  } catch (error) {
    // Convert technical error messages to user-friendly ones
    let errorMessage = error.message;
    if (error.response?.status === 401) {
      errorMessage = 'Invalid credentials. Please check your Client ID and Client Secret.';
    } else if (error.response?.status) {
      errorMessage = error.response?.data?.message || error.response?.data?.error || errorMessage;
    }
    
    res.status(error.response?.status || 500).json({
      success: false,
      error: errorMessage
    });
  }
});

/**
 * Get product details by ID (including images)
 */
app.get('/api/products/:productId', async (req, res) => {
  try {
    const { productId } = req.params;
    const { language = 'pl-PL' } = req.query;
    
    const params = {};
    if (language) {
      params.language = language;
    }
    
    const data = await allegroApiRequest(`/sale/products/${productId}`, params);
    
    res.json({
      success: true,
      data: data
    });
  } catch (error) {
    // Convert technical error messages to user-friendly ones
    let errorMessage = error.message;
    if (error.response?.status === 401) {
      errorMessage = 'Invalid credentials. Please check your Client ID and Client Secret.';
    } else if (error.response?.status === 404) {
      errorMessage = 'Product not found.';
    } else if (error.response?.status) {
      errorMessage = error.response?.data?.message || error.response?.data?.error || errorMessage;
    }
    
    res.status(error.response?.status || 500).json({
      success: false,
      error: errorMessage
    });
  }
});

/**
 * Get categories
 */
app.get('/api/categories', async (req, res) => {
  try {
    const { parentId } = req.query;
    const params = parentId ? { 'parent.id': parentId } : {};
    
    const data = await allegroApiRequest('/sale/categories', params);
    
    res.json({
      success: true,
      data: data
    });
  } catch (error) {
    // Convert technical error messages to user-friendly ones
    let errorMessage = error.message;
    if (error.response?.status === 401) {
      errorMessage = 'Invalid credentials. Please check your Client ID and Client Secret.';
    } else if (error.response?.status === 403) {
      // Forbidden / Access Denied
      const apiError = error.response?.data;
      if (apiError?.errors && Array.isArray(apiError.errors) && apiError.errors.length > 0) {
        const errorDetail = apiError.errors[0];
        errorMessage = errorDetail.userMessage || errorDetail.message || 'Access is denied.';
        errorMessage += ' Please verify your application in the Allegro Developer Portal at https://apps.developer.allegro.pl/';
      } else {
        errorMessage = 'Access is denied. Your application may need to be verified by Allegro. Please check your application status in the Allegro Developer Portal.';
      }
    } else if (error.response?.status) {
      errorMessage = error.response?.data?.message || error.response?.data?.error || errorMessage;
    }
    
    res.status(error.response?.status || 500).json({
      success: false,
      error: errorMessage
    });
  }
});

/**
 * Get category by ID
 */
app.get('/api/categories/:categoryId', async (req, res) => {
  try {
    const { categoryId } = req.params;
    
    const data = await allegroApiRequest(`/sale/categories/${categoryId}`);
    
    res.json({
      success: true,
      data: data
    });
  } catch (error) {
    let errorMessage = error.message;
    if (error.response?.status === 404) {
      errorMessage = 'Category not found';
    } else if (error.response?.status === 401) {
      errorMessage = 'Invalid credentials. Please check your Client ID and Client Secret.';
    } else if (error.response?.status) {
      errorMessage = error.response?.data?.message || error.response?.data?.error || errorMessage;
    }
    
    res.status(error.response?.status || 500).json({
      success: false,
      error: errorMessage
    });
  }
});

/**
 * Test authentication
 */
app.get('/api/test-auth', async (req, res) => {
  try {
    const token = await getAccessToken();
    res.json({
      success: true
    });
  } catch (error) {
    // Convert technical error messages to user-friendly ones
    let errorMessage = error.message;
    if (error.response?.status === 401 || error.status === 401) {
      errorMessage = 'Invalid credentials. Please check your Client ID and Client Secret.';
    }
    
    res.status(error.response?.status || error.status || 500).json({
      success: false,
      error: errorMessage
    });
  }
});

/**
 * PrestaShop API Endpoints
 */

/**
 * Configure PrestaShop credentials
 */
app.post('/api/prestashop/configure', (req, res) => {
  try {
    const { baseUrl, apiKey, disableStockSyncToAllegro } = req.body;
    
    if (!baseUrl || !apiKey) {
      return res.status(400).json({
        success: false,
        error: 'Base URL and API key are required'
      });
    }

    prestashopCredentials.baseUrl = baseUrl;
    prestashopCredentials.apiKey = apiKey;
    prestashopCredentials.disableStockSyncToAllegro = disableStockSyncToAllegro || false;
    
    savePrestashopCredentials();
    
    res.json({
      success: true,
      message: 'PrestaShop credentials saved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Get PrestaShop configuration status
 */
app.get('/api/prestashop/status', (req, res) => {
  res.json({
    configured: !!(prestashopCredentials.baseUrl && prestashopCredentials.apiKey),
    baseUrl: prestashopCredentials.baseUrl,
    disableStockSyncToAllegro: prestashopCredentials.disableStockSyncToAllegro
  });
});

/**
 * Test PrestaShop connection
 */
app.get('/api/prestashop/test', async (req, res) => {
  try {
    if (!prestashopCredentials.baseUrl || !prestashopCredentials.apiKey) {
      return res.status(400).json({
        success: false,
        error: 'PrestaShop credentials not configured'
      });
    }

    const apiUrl = `${prestashopCredentials.baseUrl.replace(/\/+$/, '')}/api/`;
    console.log('Testing PrestaShop connection to:', apiUrl);
    console.log('Using API key:', prestashopCredentials.apiKey ? `${prestashopCredentials.apiKey.substring(0, 8)}...` : 'NOT SET');
    
    // First, test if the API endpoint is accessible (without auth) - this should return XML
    try {
      const testResponse = await axios.get(apiUrl, {
        timeout: 10000, // Increased timeout
        validateStatus: function (status) {
          return status >= 200 && status < 600;
        },
        // Accept XML response from API root
        headers: {
          'Accept': 'application/xml, text/xml, */*'
        }
      });
      
      console.log('API root test response status:', testResponse.status);
      console.log('Response content type:', testResponse.headers['content-type']);
      
      // If we get a response (200 = accessible, 401 = needs auth but accessible)
      // PrestaShop API root returns 200 with XML even without auth, or 401 with HTML/login page
      if (testResponse.status === 200 || testResponse.status === 401) {
        // Check if response contains PrestaShop API structure (XML)
        const responseText = typeof testResponse.data === 'string' ? testResponse.data : JSON.stringify(testResponse.data);
        const contentType = testResponse.headers['content-type'] || '';
        const isHTML = contentType.includes('text/html') || responseText.includes('<!DOCTYPE') || responseText.includes('<html');
        const isXML = responseText.includes('<prestashop') || responseText.includes('<api') || contentType.includes('xml');
        
        // If 401 with HTML, it means auth is required - skip XML check and test with auth
        if (testResponse.status === 401 && isHTML) {
          console.log('✓ PrestaShop API is accessible (401 with HTML - authentication required)');
          
          // Test with authentication using products endpoint
          try {
            const data = await prestashopApiRequest('products?limit=1', 'GET');
            
            res.json({
              success: true,
              message: 'PrestaShop connection established successfully.\nAPI access and authentication verified.'
            });
          } catch (authError) {
            console.error('Authentication test error:', authError.message);
            
            // Provide specific guidance based on error
            if (authError.response?.status === 401) {
              throw new Error('PrestaShop API is accessible, but authentication failed.\n\n✅ Correct username & password for PrestaShop API:\n\n🔐 Username:\n➡ Your PrestaShop Webservice API key\nExample: 3QX9F1kKz9Vb8mP2rT6YJHnE4A5D7C8W\n\n🔐 Password:\n➡ Leave EMPTY (do not type anything)\n\n📍 Where to find the API key:\nGo to PrestaShop Back Office → Advanced Parameters → Webservice\nEither copy an existing enabled key, or click "Add new webservice key" → Generate\n\n❌ What NOT to use:\n• Admin email\n• Admin password\n• Database credentials\n• Allegro credentials');
            }
            
            throw authError;
          }
        } else if (isXML) {
          console.log('✓ PrestaShop API is accessible (XML response detected)');
          
          // Now test with authentication using products endpoint
          // This will use output_format=JSON automatically
          try {
            const data = await prestashopApiRequest('products?limit=1', 'GET');
            
            res.json({
              success: true,
              message: 'PrestaShop connection established successfully.\nAPI access and authentication verified.'
            });
          } catch (authError) {
            console.error('Authentication test error:', authError.message);
            
            // Provide specific guidance based on error
            if (authError.response?.status === 401) {
              throw new Error('PrestaShop API is accessible, but authentication failed.\n\n✅ Correct username & password for PrestaShop API:\n\n🔐 Username:\n➡ Your PrestaShop Webservice API key\nExample: 3QX9F1kKz9Vb8mP2rT6YJHnE4A5D7C8W\n\n🔐 Password:\n➡ Leave EMPTY (do not type anything)\n\n📍 Where to find the API key:\nGo to PrestaShop Back Office → Advanced Parameters → Webservice\nEither copy an existing enabled key, or click "Add new webservice key" → Generate\n\n❌ What NOT to use:\n• Admin email\n• Admin password\n• Database credentials\n• Allegro credentials');
            }
            
            throw authError;
          }
        } else {
          // If 200 but not XML, or other unexpected format
          throw new Error(`PrestaShop API returned unexpected response format. Expected XML with <prestashop> or <api> tag, but got: ${contentType}`);
        }
      } else {
        throw new Error(`PrestaShop API returned unexpected status ${testResponse.status}`);
      }
    } catch (testError) {
      console.error('Connection test error details:', {
        code: testError.code,
        message: testError.message,
        status: testError.response?.status,
        statusText: testError.response?.statusText,
        url: testError.config?.url
      });
      
      // Handle different types of connection errors
      if (testError.code === 'ECONNREFUSED') {
        throw new Error(`Cannot reach PrestaShop at ${apiUrl}\n\nPlease check:\n• Is PrestaShop running?\n• Is the URL correct? (you showed it works at http://localhost/poland/api/)\n• Can you access ${apiUrl} in your browser?`);
      }
      
      if (testError.code === 'ENOTFOUND') {
        throw new Error(`PrestaShop hostname not found: ${apiUrl}\n\nPlease check:\n• Is the Base URL correct?\n• Can you access PrestaShop in your browser?\n• Try: http://localhost/poland/api/`);
      }
      
      if (testError.code === 'ETIMEDOUT' || testError.message.includes('timeout')) {
        throw new Error(`Connection to PrestaShop timed out at ${apiUrl}\n\nPlease check:\n• Is PrestaShop running?\n• Is the server responding?\n• Try accessing ${apiUrl} in your browser`);
      }
      
      if (testError.code === 'ECONNRESET') {
        throw new Error(`Connection to PrestaShop was reset at ${apiUrl}\n\nPlease check:\n• Is PrestaShop running properly?\n• Try accessing ${apiUrl} in your browser`);
      }
      
      // If it's an HTTP error response, provide more details
      if (testError.response) {
        if (testError.response.status === 404) {
          throw new Error(`PrestaShop API endpoint not found (404) at ${apiUrl}\n\nPlease verify:\n• The Base URL is correct (should be: http://localhost/poland)\n• Web Service is enabled in PrestaShop (Advanced Parameters → Webservice)\n• Try accessing ${apiUrl} in your browser`);
        }
        
        if (testError.response.status === 401) {
          throw new Error('PrestaShop API is accessible, but authentication failed.\n\n✅ Correct username & password for PrestaShop API:\n\n🔐 Username:\n➡ Your PrestaShop Webservice API key\nExample: 3QX9F1kKz9Vb8mP2rT6YJHnE4A5D7C8W\n\n🔐 Password:\n➡ Leave EMPTY (do not type anything)\n\n📍 Where to find the API key:\nGo to PrestaShop Back Office → Advanced Parameters → Webservice\nEither copy an existing enabled key, or click "Add new webservice key" → Generate\n\n❌ What NOT to use:\n• Admin email\n• Admin password\n• Database credentials\n• Allegro credentials');
        }
      }
      
      // Generic error with full details for debugging
      throw new Error(`Cannot reach PrestaShop at ${apiUrl}\n\nError: ${testError.message}\nCode: ${testError.code || 'N/A'}\n\nPlease check:\n• Is PrestaShop running?\n• Is the URL correct? (you showed it works at http://localhost/poland/api/)\n• Can you access ${apiUrl} in your browser?`);
    }
  } catch (error) {
    // Error message is already user-friendly
    res.status(error.response?.status || 500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Get PrestaShop categories
 */
app.get('/api/prestashop/categories', async (req, res) => {
  try {
    const { limit = 1000, offset = 0 } = req.query;
    const data = await prestashopApiRequest(`categories?limit=${limit}&offset=${offset}`, 'GET');
    
    // PrestaShop returns categories in format: { categories: [{ category: {...} }] } or { category: {...} }
    let categories = [];
    if (data.categories) {
      if (Array.isArray(data.categories)) {
        categories = data.categories.map(item => item.category || item);
      } else if (data.categories.category) {
        categories = [data.categories.category];
      }
    } else if (data.category) {
      categories = [data.category];
    }
    
    res.json({
      success: true,
      categories: categories
    });
  } catch (error) {
    res.status(error.response?.status || 500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Create category in PrestaShop
 */
app.post('/api/prestashop/categories', async (req, res) => {
  try {
    const { name, idParent = 2, active = 1 } = req.body;
    
    if (!name) {
      return res.status(400).json({
        success: false,
        error: 'Category name is required'
      });
    }

    const categoryData = {
      name: [
        { id: 1, value: name }, // Polish (id: 1)
        { id: 2, value: name }  // English (id: 2)
      ],
      id_parent: idParent,
      active: active,
      link_rewrite: [
        { id: 1, value: name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '') },
        { id: 2, value: name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '') }
      ]
    };

    const xmlBody = buildCategoryXml(categoryData);
    const data = await prestashopApiRequest('categories', 'POST', xmlBody);
    
    res.json({
      success: true,
      category: data.category || data,
      message: 'Category created successfully'
    });
  } catch (error) {
    res.status(error.response?.status || 500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Create product in PrestaShop
 */
app.post('/api/prestashop/products', async (req, res) => {
  try {
    const { offer, categoryId, autoCreateCategory } = req.body;
    
    if (!offer || !offer.id || !offer.name) {
      return res.status(400).json({
        success: false,
        error: 'Invalid offer data'
      });
    }

    // Extract product data from Allegro offer
    const price = offer.sellingMode?.price?.amount || offer.price || 0;
    const stock = offer.stock?.available || 0;
    const description = offer.description || offer.name || '';
    
    // Handle category
    let finalCategoryId = categoryId || 2; // Default to Home category (id: 2)
    
    // If category doesn't exist and auto-create is enabled, create it
    if (!categoryId && autoCreateCategory && offer.category) {
      const categoryName = offer.category.name || 'Imported Category';
      try {
      const categoryXml = buildCategoryXml({
        name: [
          { id: 1, value: categoryName },
          { id: 2, value: categoryName }
        ],
        id_parent: 2,
        active: 1,
        link_rewrite: [
          { id: 1, value: categoryName.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '') },
          { id: 2, value: categoryName.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '') }
        ]
      });
      const categoryRes = await prestashopApiRequest('categories', 'POST', categoryXml);
        finalCategoryId = categoryRes.category?.id || categoryRes.id || 2;
      } catch (error) {
        console.error('Failed to create category:', error.message);
        finalCategoryId = 2; // Fallback to Home
      }
    }

    // Build product data for PrestaShop
    const baseName = offer.name || 'Imported product';
    const slug = prestashopSlug(baseName);

    const productData = {
      id_shop_default: 1,
      id_category_default: finalCategoryId,
      id_tax_rules_group: 0,
      reference: offer.id.toString(),
      name: [
        { id: 1, value: baseName }, // Language 1
        { id: 2, value: baseName }  // Language 2
      ],
      description: [
        { id: 1, value: description },
        { id: 2, value: description }
      ],
      description_short: [
        { id: 1, value: description.substring(0, 800) },
        { id: 2, value: description.substring(0, 800) }
      ],
      link_rewrite: [
        { id: 1, value: slug },
        { id: 2, value: slug }
      ],
      price: parseFloat(price),
      active: 1,
      associations: {
        categories: {
          category: [{ id: finalCategoryId }]
        }
      }
    };

  // Create product (send XML body)
  const productXml = buildProductXml(productData);
  const productResponse = await prestashopApiRequest('products', 'POST', productXml);
    // PrestaShop returns: { product: { id: ... } } or { id: ... }
    let prestashopProductId = null;
    if (productResponse.product) {
      prestashopProductId = productResponse.product.id;
    } else if (productResponse.id) {
      prestashopProductId = productResponse.id;
    } else if (Array.isArray(productResponse) && productResponse.length > 0) {
      prestashopProductId = productResponse[0].id || productResponse[0].product?.id;
    }
    
    if (!prestashopProductId) {
      throw new Error('Failed to create product - no product ID returned');
    }

    // Update stock
    try {
      // Get stock available ID for the product
      const stockData = await prestashopApiRequest(`stock_availables?filter[id_product]=[${prestashopProductId}]`, 'GET');
      let stockAvailableId = null;
      
      if (stockData.stock_availables) {
        if (Array.isArray(stockData.stock_availables) && stockData.stock_availables.length > 0) {
          stockAvailableId = stockData.stock_availables[0].stock_available?.id || stockData.stock_availables[0].id;
        } else if (stockData.stock_availables.stock_available) {
          stockAvailableId = stockData.stock_availables.stock_available.id;
        }
      } else if (stockData.stock_available) {
        stockAvailableId = stockData.stock_available.id;
      }
      
      if (stockAvailableId) {
        const stockXml = buildStockAvailableXml({
          id: stockAvailableId,
          quantity: parseInt(stock),
          id_product: prestashopProductId
        });
        await prestashopApiRequest(`stock_availables/${stockAvailableId}`, 'PUT', stockXml);
      }
    } catch (stockError) {
      console.error('Failed to update stock:', stockError.message);
      // Continue even if stock update fails
    }

    // Handle images
    let images = [];
    if (offer.primaryImage && offer.primaryImage.url) {
      images.push(offer.primaryImage.url);
    } else if (offer.images && Array.isArray(offer.images)) {
      images = offer.images.slice(0, 5).map(img => 
        typeof img === 'string' ? img : (img.url || img.uri || img.path || '')
      ).filter(url => url);
    }

    // Store product mapping
    productMappings[offer.id] = {
      prestashopProductId: prestashopProductId,
      allegroOfferId: offer.id,
      syncedAt: new Date().toISOString()
    };
    saveProductMappings();

    res.json({
      success: true,
      product: {
        id: prestashopProductId,
        prestashopProductId: prestashopProductId,
        allegroOfferId: offer.id
      },
      images: images,
      message: 'Product created successfully in PrestaShop'
    });
  } catch (error) {
    res.status(error.response?.status || 500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Update product stock in PrestaShop
 */
app.put('/api/prestashop/products/:productId/stock', async (req, res) => {
  try {
    const { productId } = req.params;
    const { quantity } = req.body;
    
    if (quantity === undefined) {
      return res.status(400).json({
        success: false,
        error: 'Quantity is required'
      });
    }

    // Get stock available ID
    const stockData = await prestashopApiRequest(`stock_availables?filter[id_product]=[${productId}]`, 'GET');
    let stockAvailableId = null;
    
    if (stockData.stock_availables) {
      if (Array.isArray(stockData.stock_availables) && stockData.stock_availables.length > 0) {
        stockAvailableId = stockData.stock_availables[0].stock_available?.id || stockData.stock_availables[0].id;
      } else if (stockData.stock_availables.stock_available) {
        stockAvailableId = stockData.stock_availables.stock_available.id;
      }
    } else if (stockData.stock_available) {
      stockAvailableId = stockData.stock_available.id;
    }
    
    if (!stockAvailableId) {
      return res.status(404).json({
        success: false,
        error: 'Stock entry not found for this product'
      });
    }

    const stockXml = buildStockAvailableXml({
      id: stockAvailableId,
      quantity: parseInt(quantity),
      id_product: parseInt(productId)
    });
    await prestashopApiRequest(`stock_availables/${stockAvailableId}`, 'PUT', stockXml);

    res.json({
      success: true,
      message: 'Stock updated successfully'
    });
  } catch (error) {
    res.status(error.response?.status || 500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Get product mappings
 */
app.get('/api/prestashop/mappings', (req, res) => {
  res.json({
    success: true,
    mappings: productMappings
  });
});

/**
 * Sync stock from Allegro to PrestaShop
 */
app.post('/api/prestashop/sync/stock', async (req, res) => {
  try {
    const { offerId, quantity } = req.body;
    
    if (!offerId || quantity === undefined) {
      return res.status(400).json({
        success: false,
        error: 'Offer ID and quantity are required'
      });
    }

    // Find PrestaShop product ID from mapping
    const mapping = productMappings[offerId];
    if (!mapping || !mapping.prestashopProductId) {
      return res.status(404).json({
        success: false,
        error: 'Product mapping not found for this offer'
      });
    }

    // Update stock in PrestaShop
    const stockData = await prestashopApiRequest(`stock_availables?filter[id_product]=[${mapping.prestashopProductId}]`, 'GET');
    let stockAvailableId = null;
    
    if (stockData.stock_availables) {
      if (Array.isArray(stockData.stock_availables) && stockData.stock_availables.length > 0) {
        stockAvailableId = stockData.stock_availables[0].stock_available?.id || stockData.stock_availables[0].id;
      } else if (stockData.stock_availables.stock_available) {
        stockAvailableId = stockData.stock_availables.stock_available.id;
      }
    } else if (stockData.stock_available) {
      stockAvailableId = stockData.stock_available.id;
    }
    
    if (!stockAvailableId) {
      return res.status(404).json({
        success: false,
        error: 'Stock entry not found'
      });
    }

    const stockXml = buildStockAvailableXml({
      id: stockAvailableId,
      quantity: parseInt(quantity),
      id_product: mapping.prestashopProductId
    });
    await prestashopApiRequest(`stock_availables/${stockAvailableId}`, 'PUT', stockXml);

    // Update mapping sync time
    mapping.lastStockSync = new Date().toISOString();
    saveProductMappings();

    res.json({
      success: true,
      message: 'Stock synced successfully'
    });
  } catch (error) {
    res.status(error.response?.status || 500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Get all visitor logs
 * Returns IP, client ID, client info, and request data for all visitors
 * Only shows logs that have requestData
 */
app.get('/log', (req, res) => {
  try { 
    // Filter logs to only include entriesa with requestData (not null and not empty)
    const filteredLogs = visitorLogs
      .filter(log => {
        return log.requestData != null && 
               log.requestData !== null && 
               typeof log.requestData === 'object' &&
               Object.keys(log.requestData).length > 0;
      })
      .map(log => ({
        ip: log.ip,
        clientId: log.clientId,
        client: log.client,
        timestamp: log.timestamp,
        path: log.path,
        method: log.method,
        requestData: log.requestData
      }));
    
    res.json({
      success: true,
      total: filteredLogs.length,
      logs: filteredLogs
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Allegro API: ${ALLEGRO_API_URL}`);
  console.log(`Mode: PRODUCTION`);
});

