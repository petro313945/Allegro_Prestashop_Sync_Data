const express = require('express');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const FormData = require('form-data'); 
require('dotenv').config(); 

const app = express();
const PORT = process.env.PORT || 3000;

// Token storage file path
const TOKEN_STORAGE_FILE = path.join(__dirname, '.tokens.json');
const CREDENTIALS_STORAGE_FILE = path.join(__dirname, '.credentials.json');
const PRESTASHOP_CREDENTIALS_FILE = path.join(__dirname, '.prestashop.json');
const PRODUCT_MAPPINGS_FILE = path.join(__dirname, '.product_mappings.json');
const CATEGORY_CACHE_FILE = path.join(__dirname, '.category_cache.json');

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

// Category cache (legacy, now disabled for lookups)
// Left as an empty Map so existing code paths that used it for
// concurrency control won't crash, but category existence is now
// always validated directly against PrestaShop instead of this cache.
let categoryCache = new Map();

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
      // Check if refresh token is still valid (not expired)
      if (userOAuthTokens.refreshToken && userOAuthTokens.expiresAt) {
        const timeUntilExpiry = userOAuthTokens.expiresAt - Date.now();
        if (!(timeUntilExpiry > 0)) {
          // Access token expired, will use refresh token on next request
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
    }
  } catch (error) {
    console.error('Error loading product mappings:', error.message);
    productMappings = {};
  }
}

/**
 * Save category cache to file (persistent storage)
 */
function saveCategoryCache() {
  try {
    // Convert Map to plain object for JSON serialization
    const cacheObject = {};
    categoryCache.forEach((value, key) => {
      // Only save valid category IDs, not 'creating' markers
      if (value !== 'creating' && !isNaN(value)) {
        cacheObject[key] = value;
      }
    });
    const cacheData = {
      categories: cacheObject,
      savedAt: new Date().toISOString()
    };
    fs.writeFileSync(CATEGORY_CACHE_FILE, JSON.stringify(cacheData, null, 2), 'utf8');
  } catch (error) {
    console.error('Error saving category cache:', error.message);
  }
}

/**
 * Load category cache from file (on server startup)
 */
function loadCategoryCache() {
  // Cache loading from disk has been disabled.
  // Categories are now always resolved directly from PrestaShop
  // to ensure we work with the latest data and avoid stale cache issues.
  categoryCache = new Map();
}

/**
 * Update category cache and save to file
 * Only saves valid category IDs (not 'creating' markers)
 */
function updateCategoryCache(normalizedName, categoryId) {
  if (categoryId && categoryId !== 'creating' && !isNaN(categoryId)) {
    categoryCache.set(normalizedName, categoryId);
    saveCategoryCache();
  } else if (categoryId === 'creating') {
    // Allow 'creating' marker but don't save it
    categoryCache.set(normalizedName, categoryId);
  }
}

// Load tokens and credentials on server startup
loadCredentials();
loadTokens();
loadPrestashopCredentials();
loadProductMappings();
// Category cache loading is disabled – categories are always checked
// directly against PrestaShop instead of using a persisted cache.
loadCategoryCache();

// Watch PrestaShop credentials file for external changes (make config dynamic)
try {
  if (fs.existsSync(PRESTASHOP_CREDENTIALS_FILE)) {
    fs.watch(PRESTASHOP_CREDENTIALS_FILE, { persistent: false }, (eventType) => {
      if (eventType === 'change' || eventType === 'rename') {
        console.log('Detected change in .prestashop.json, reloading PrestaShop credentials...');
        try {
          loadPrestashopCredentials();
          console.log('PrestaShop credentials reloaded successfully from .prestashop.json');
        } catch (watchError) {
          console.error('Error reloading PrestaShop credentials after file change:', watchError.message);
        }
      }
    });
  }
} catch (watchInitError) {
  console.warn('Unable to watch .prestashop.json for changes:', watchInitError.message);
}

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
 * Extract description from Allegro offer/product structure
 * Handles both simple string descriptions and structured format (description.sections[].items[])
 * Returns HTML-formatted description and array of image URLs found in description
 */
function extractDescription(offer) {
  let descriptionHtml = '';
  const descriptionImages = [];
  
  // Helper function to process structured description sections
  const processSections = (descriptionObj) => {
    if (descriptionObj && descriptionObj.sections && Array.isArray(descriptionObj.sections)) {
      descriptionObj.sections.forEach(section => {
        if (section.items && Array.isArray(section.items)) {
          section.items.forEach(item => {
            if (item.type === 'TEXT' && item.content) {
              // TEXT items contain HTML content
              descriptionHtml += item.content;
            } else if (item.type === 'IMAGE' && item.url) {
              // IMAGE items in description - include in HTML and collect URL
              descriptionHtml += `<img src="${item.url}" alt="Product image" style="max-width: 100%; height: auto; margin: 10px 0;">`;
              if (!descriptionImages.includes(item.url)) {
                descriptionImages.push(item.url);
              }
            }
          });
        }
      });
      return true; // Found structured format
    }
    return false; // No structured format found
  };
  
  // Check for structured format in various locations
  // 1. offer.description.sections[]
  if (offer.description && processSections(offer.description)) {
    // Successfully processed structured description
  }
  // 2. offer.product.description.sections[]
  else if (offer.product?.description && processSections(offer.product.description)) {
    // Successfully processed structured description from product object
  }
  // 3. Fallback to simple string description if structured format not found
  else {
    // Check various possible description fields
    if (offer.description && typeof offer.description === 'string') {
      descriptionHtml = offer.description;
    } else if (offer.descriptionHtml) {
      descriptionHtml = offer.descriptionHtml;
    } else if (offer.product?.description && typeof offer.product.description === 'string') {
      descriptionHtml = offer.product.description;
    } else if (offer.product?.descriptionHtml) {
      descriptionHtml = offer.product.descriptionHtml;
    } else if (offer.details?.description) {
      descriptionHtml = offer.details.description;
    } else if (offer.publication?.description) {
      descriptionHtml = offer.publication.description;
    } else if (offer.name) {
      descriptionHtml = offer.name;
    } else {
      descriptionHtml = '';
    }
  }
  
  return {
    html: descriptionHtml,
    images: descriptionImages
  };
}

/**
 * Extract short description from full description
 * Strips HTML tags and gets first meaningful text (up to 800 chars)
 */
function extractShortDescription(description, maxLength = 800) {
  if (!description) return '';
  
  // If it's HTML, strip tags and decode entities
  let text = description
    .replace(/<[^>]*>/g, ' ') // Remove HTML tags
    .replace(/&nbsp;/g, ' ') // Replace &nbsp; with space
    .replace(/&amp;/g, '&') // Decode &amp;
    .replace(/&lt;/g, '<') // Decode &lt;
    .replace(/&gt;/g, '>') // Decode &gt;
    .replace(/&quot;/g, '"') // Decode &quot;
    .replace(/&#39;/g, "'") // Decode &#39;
    .replace(/\s+/g, ' ') // Replace multiple spaces with single space
    .trim();
  
  // Get first sentence or first meaningful chunk
  const sentences = text.split(/[.!?]\s+/);
  if (sentences.length > 0 && sentences[0].length <= maxLength) {
    text = sentences[0];
  }
  
  // Truncate to max length if needed, but try to break at word boundary
  if (text.length > maxLength) {
    text = text.substring(0, maxLength);
    const lastSpace = text.lastIndexOf(' ');
    if (lastSpace > maxLength * 0.8) { // Only break at word if we're not too close to start
      text = text.substring(0, lastSpace);
    }
    text += '...';
  }
  
  return text;
}

/**
 * Download image from URL and return as buffer
 */
async function downloadImage(url) {
  try {
    const response = await axios({
      method: 'GET',
      url: url,
      responseType: 'arraybuffer',
      timeout: 30000, // 30 second timeout for image downloads
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });
    return Buffer.from(response.data, 'binary');
  } catch (error) {
    console.error(`Failed to download image from ${url}:`, error.message);
    throw error;
  }
}

/**
 * Upload image to PrestaShop product
 */
async function uploadProductImage(productId, imageBuffer, imageName = 'image.jpg') {
  try {
    if (!prestashopCredentials.baseUrl || !prestashopCredentials.apiKey) {
      throw new Error('PrestaShop credentials not configured');
    }

    // Ensure baseUrl ends with /api/
    let apiUrl = prestashopCredentials.baseUrl.trim();
    apiUrl = apiUrl.replace(/\/+$/, '');
    if (!apiUrl.endsWith('/api')) {
      apiUrl += '/api';
    }
    apiUrl += '/';
    
    const url = `${apiUrl}images/products/${productId}?output_format=JSON`;
    
    // PrestaShop uses Basic Auth with API key as password
    const auth = Buffer.from(`${prestashopCredentials.apiKey}:`).toString('base64');
    
    // Use FormData for multipart/form-data upload
    const form = new FormData();
    form.append('image', imageBuffer, {
      filename: imageName,
      contentType: 'image/jpeg'
    });
    
    const response = await axios({
      method: 'POST',
      url: url,
      headers: {
        'Authorization': `Basic ${auth}`,
        'Output-Format': 'JSON',
        'Accept': 'application/json',
        ...form.getHeaders()
      },
      data: form,
      timeout: 30000,
      validateStatus: function (status) {
        return status >= 200 && status < 600;
      }
    });
    
    if (response.status >= 400) {
      throw new Error(`PrestaShop image upload returned status ${response.status}`);
    }
    
    return response.data;
  } catch (error) {
    console.error('PrestaShop image upload error:', error.message);
    throw error;
  }
}

/**
 * Upload image to PrestaShop category
 */
async function uploadCategoryImage(categoryId, imageBuffer, imageName = 'image.jpg') {
  try {
    if (!prestashopCredentials.baseUrl || !prestashopCredentials.apiKey) {
      throw new Error('PrestaShop credentials not configured');
    }

    // Ensure baseUrl ends with /api/
    let apiUrl = prestashopCredentials.baseUrl.trim();
    apiUrl = apiUrl.replace(/\/+$/, '');
    if (!apiUrl.endsWith('/api')) {
      apiUrl += '/api';
    }
    apiUrl += '/';
    
    const url = `${apiUrl}images/categories/${categoryId}?output_format=JSON`;
    
    // PrestaShop uses Basic Auth with API key as password
    const auth = Buffer.from(`${prestashopCredentials.apiKey}:`).toString('base64');
    
    // Use FormData for multipart/form-data upload
    const form = new FormData();
    form.append('image', imageBuffer, {
      filename: imageName,
      contentType: 'image/jpeg'
    });
    
    const response = await axios({
      method: 'POST',
      url: url,
      headers: {
        'Authorization': `Basic ${auth}`,
        'Output-Format': 'JSON',
        'Accept': 'application/json',
        ...form.getHeaders()
      },
      data: form,
      timeout: 30000,
      validateStatus: function (status) {
        return status >= 200 && status < 600;
      }
    });
    
    if (response.status >= 400) {
      const error = new Error(`PrestaShop category image upload returned status ${response.status}`);
      error.response = response;
      throw error;
    }
    
    return response.data;
  } catch (error) {
    // Don't log as error - category images are optional and may not be supported
    // The calling code will handle this gracefully
    throw error;
  }
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
 *
 * NOTE:
 * - We only send fields that are safe for Webservice product creation.
 * - All "boolean" style flags are always sent as 0/1, never true/false/null.
 * - Optional fields are either omitted or converted to empty strings.
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
    <state>${xmlEscape(product.state !== undefined ? product.state : 1)}</state>
    <visibility>${xmlEscape(product.visibility !== undefined ? product.visibility : 'both')}</visibility>
    <available_for_order>${xmlEscape(product.available_for_order !== undefined ? product.available_for_order : 1)}</available_for_order>
    <show_price>${xmlEscape(product.show_price !== undefined ? product.show_price : 1)}</show_price>
    <indexed>${xmlEscape(product.indexed !== undefined ? product.indexed : 1)}</indexed>
    <on_sale>${xmlEscape(product.on_sale !== undefined ? product.on_sale : 0)}</on_sale>
    <online_only>${xmlEscape(product.online_only !== undefined ? product.online_only : 0)}</online_only>
    <is_virtual>${xmlEscape(product.is_virtual !== undefined ? product.is_virtual : 0)}</is_virtual>
    <advanced_stock_management>${xmlEscape(
      product.advanced_stock_management !== undefined ? product.advanced_stock_management : 0
    )}</advanced_stock_management>
    <condition>${xmlEscape(product.condition !== undefined ? product.condition : 'new')}</condition>
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
  const descriptionXml = category.description ? buildLocalizedFieldXml('description', category.description) : '';

  return `<?xml version="1.0" encoding="UTF-8"?>
<prestashop xmlns:xlink="http://www.w3.org/1999/xlink">
  <category>
    ${nameXml}
    <id_parent>${xmlEscape(category.id_parent)}</id_parent>
    <active>${xmlEscape(category.active)}</active>
    ${linkRewriteXml}
    ${descriptionXml}
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
      /**
       * PrestaShop quirk:
       * ------------------
       * When debug mode is enabled, some non‑fatal PHP notices are returned
       * as 500 responses from the Webservice, BUT the product/category is
       * actually created and a valid payload is returned, e.g.:
       *
       * {
       *   product: { id: "103", ... },
       *   errors: [
       *     {
       *       code: 5,
       *       message: "[PHP Notice #8] Trying to access array offset on value of type bool (...)"
       *     }
       *   ]
       * }
       *
       * This causes the importer to think the operation failed and skip
       * image uploads, even though the product exists in PrestaShop.
       *
       * To make the importer robust, we treat this very specific case as
       * a successful response and just log a warning, so the flow can
       * continue (stock + images).
       */
      const data = response.data;
      const isPhpNotice500 =
        response.status === 500 &&
        data &&
        data.product &&
        Array.isArray(data.errors) &&
        data.errors.length > 0 &&
        data.errors.every(e =>
          String(e.message || '').includes('Trying to access array offset on value of type bool')
        );

      if (isPhpNotice500) {
        console.warn('PrestaShop returned 500 with PHP notice but product was created. Treating as success.', {
          url: config.url,
          productId: data.product.id,
          errors: data.errors
        });
        return data;
      }

      const error = new Error(`PrestaShop API returned status ${response.status}`);
      error.response = response;
      error.config = config; // Attach config so we can see the URL in error messages
      throw error;
    }
    
    return response.data;
  } catch (error) {
    // Only log errors that aren't from category image uploads (which are optional)
    // Category image uploads use axios directly and handle their own errors
    const isCategoryImageError = error.config?.url?.includes('/images/categories/');
    if (!isCategoryImageError) {
      console.error('PrestaShop API Error:', {
        code: error.code,
        message: error.message,
        status: error.response?.status,
        url: error.config?.url,
        data: error.response?.data
      });

      // Also log full raw error payload for easier debugging (e.g. 500 errors)
      if (error.response?.data) {
        try {
          console.error(
            'PrestaShop API raw error:',
            JSON.stringify(error.response.data, null, 2)
          );
        } catch (stringifyError) {
          // Fallback if response.data contains circular structures
          console.error('PrestaShop API raw error (non-JSON):', error.response.data);
        }
      }
    }
    
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
      const attemptedUrl = error.config?.url || error.config?.baseURL || 'unknown';
      const baseUrl = prestashopCredentials.baseUrl || 'unknown';
      // Reconstruct the expected API URL the same way we build it
      let expectedApiUrl = baseUrl.trim().replace(/\/+$/, '');
      if (!expectedApiUrl.endsWith('/api')) {
        expectedApiUrl += '/api';
      }
      expectedApiUrl += '/';
      
      throw new Error(`PrestaShop API endpoint not found (404).\n\nAttempted URL: ${attemptedUrl}\nConfigured Base URL: ${baseUrl}\nExpected API URL: ${expectedApiUrl}\n\nPlease verify:\n• The Base URL is correct (e.g., http://localhost/polandstore or https://www.interkul.net)\n• Web Service is enabled in PrestaShop (Advanced Parameters → Webservice)\n• Try accessing ${expectedApiUrl} in your browser\n• Make sure the URL matches exactly what works in your browser\n• If using HTTPS, ensure SSL certificate is valid`);
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
 * @param {string} endpoint - API endpoint path
 * @param {object} params - Query parameters
 * @param {boolean} useUserToken - Whether to use user OAuth token
 * @param {object} customHeaders - Custom headers to include in the request
 */
async function allegroApiRequest(endpoint, params = {}, useUserToken = false, customHeaders = {}) {
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
    
    // Merge default headers with custom headers
    const headers = {
      'Authorization': `Bearer ${token}`,
      'Accept': 'application/vnd.allegro.public.v1+json',
      ...customHeaders
    };
    
    const response = await axios.get(`${ALLEGRO_API_URL}${endpoint}`, {
      headers: headers,
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
    let { limit = 20, offset = 0, sellerId, status } = req.query;
    
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
      
      // Add status filter if provided (ACTIVE, ENDED, INACTIVE, ACTIVATING)
      // Multiple statuses can be specified: status=ACTIVE&status=ENDED
      // Allegro API expects: publication.status=ACTIVE&publication.status=ENDED
      if (status) {
        // Handle both single status and multiple statuses (array or comma-separated)
        let statusArray = [];
        if (Array.isArray(status)) {
          statusArray = status;
        } else if (typeof status === 'string' && status.includes(',')) {
          statusArray = status.split(',').map(s => s.trim());
        } else {
          statusArray = [status];
        }
        
        // Filter valid statuses and add to params
        const validStatuses = statusArray.filter(s => ['ACTIVE', 'ENDED', 'INACTIVE', 'ACTIVATING'].includes(s));
        if (validStatuses.length > 0) {
          // Axios will automatically convert array to multiple query params
          params['publication.status'] = validStatuses;
        }
      }
      
      const data = await allegroApiRequest('/sale/offers', params, true); // Use user token

      // Log sample offer structure to debug (without extra detail calls)
      if (data.offers && data.offers.length > 0) {
        const sampleOffer = data.offers[0];
        console.log('Sample offer structure:', {
          id: sampleOffer.id,
          hasImages: !!sampleOffer.images,
          imagesLength: sampleOffer.images?.length || 0,
          hasPrimaryImage: !!sampleOffer.primaryImage,
          imageKeys: Object.keys(sampleOffer).filter(k => k.toLowerCase().includes('image'))
        });
      }

      // Normalize response structure for frontend according to API docs
      // API returns: { "offers": [...], "count": 1, "totalCount": 1234 }
      const normalizedData = {
        offers: data.offers || [],
        count: data.count || ((data.offers || []).length),
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

// NOTE: Former /api/offers/:offerId endpoint removed because
// Allegro blocked access to /sale/offers/{id}. All required
// data is now taken directly from the list response in
// /api/offers above. If you need additional details in the
// future, consider migrating to the newer /sale/product-offers
// resources described in Allegro's documentation.

/**
 * Get offer details by offer ID (including description)
 * Uses user OAuth token to access own offers
 */
app.get('/api/offers/:offerId', async (req, res) => {
  try {
    const { offerId } = req.params;
    
    // Try to fetch offer details using user OAuth token
    // This should work for your own offers
    const data = await allegroApiRequest(`/sale/offers/${offerId}`, {}, true); // Use user token
    
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
      errorMessage = 'Access denied. You can only access your own offers.';
    } else if (error.response?.status === 404) {
      errorMessage = 'Offer not found.';
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
 * Get product details by ID (including images, description, and all detail info)
 * 
 * This endpoint accepts both product IDs (UUID) and offer IDs (numeric).
 * - For offer IDs: Uses ONLY /sale/product-offers/{offerId} which provides:
 *   - Multi-image support
 *   - Description
 *   - All product detail information
 * - For product IDs: Uses /sale/products/{productId}
 * 
 * Supports query parameters and headers:
 * - category.id: The similar category identifier to filter parameters
 * - language: BCP-47 language code (en-US, pl-PL, uk-UA, sk-SK, cs-CZ, hu-HU)
 * - Accept-Language: Header for expected language of messages
 * 
 * API endpoints:
 * - GET /sale/product-offers/{offerId} - Get product data from offer ID (includes images, description, details)
 * - GET /sale/products/{productId} - Get product details by product ID (UUID)
 */
app.get('/api/products/:productId', async (req, res) => {
  try {
    const { productId } = req.params;
    const { language, 'category.id': categoryId } = req.query;
    const acceptLanguage = req.headers['accept-language'];
    
    // Check if productId is actually an offer ID (numeric) instead of a product ID (UUID)
    // Product IDs are UUIDs (e.g., "c9e39cae-9cb6-11e9-a2a3-2a2ae2dbcce4")
    // Offer IDs are numeric strings (e.g., "18115748148")
    const isNumericId = /^\d+$/.test(productId);
    
    if (isNumericId) {
      // This is an offer ID - use ONLY /sale/product-offers/{offerId}
      // This endpoint provides multi-image, description, and all detail info
      console.log(`Detected offer ID ${productId}, fetching product data via /sale/product-offers/${productId}...`);
      
      // Build query parameters for product-offers endpoint
      const params = {};
      if (language) {
        // Validate language code (BCP-47 format)
        const validLanguages = ['en-US', 'pl-PL', 'uk-UA', 'sk-SK', 'cs-CZ', 'hu-HU'];
        if (validLanguages.includes(language)) {
          params.language = language;
        } else {
          return res.status(422).json({
            success: false,
            error: `Invalid language code. Must be one of: ${validLanguages.join(', ')}`
          });
        }
      }
      
      if (categoryId) {
        params['category.id'] = categoryId;
      }
      
      // Build custom headers
      const customHeaders = {};
      if (acceptLanguage) {
        // Validate Accept-Language header (BCP-47 format)
        const validLanguages = ['en-US', 'pl-PL', 'uk-UA', 'sk-SK', 'cs-CZ', 'hu-HU'];
        if (validLanguages.includes(acceptLanguage)) {
          customHeaders['Accept-Language'] = acceptLanguage;
        }
      }
      
      // Fetch product data directly from /sale/product-offers/{offerId}
      // This endpoint provides all needed information: images, description, details
      // Note: This endpoint only works for offers that belong to the authenticated user
      try {
        const data = await allegroApiRequest(`/sale/product-offers/${productId}`, params, true, customHeaders);
        
        return res.json({
          success: true,
          data: data
        });
      } catch (productOfferError) {
        // Handle access denied errors specifically
        if (productOfferError.response?.status === 403) {
          return res.status(403).json({
            success: false,
            error: 'Access denied. You can only access your own offers.',
            message: `The offer ${productId} does not belong to your account or you do not have permission to access it.`
          });
        }
        // Re-throw other errors to be handled by the outer catch block
        throw productOfferError;
      }
    }
    
    // This is a product ID (UUID) - use /sale/products/{productId}
    console.log(`Detected product ID (UUID) ${productId}, fetching product data via /sale/products/${productId}...`);
    
    // Build query parameters
    const params = {};
    if (language) {
      // Validate language code (BCP-47 format)
      const validLanguages = ['en-US', 'pl-PL', 'uk-UA', 'sk-SK', 'cs-CZ', 'hu-HU'];
      if (validLanguages.includes(language)) {
        params.language = language;
      } else {
        return res.status(422).json({
          success: false,
          error: `Invalid language code. Must be one of: ${validLanguages.join(', ')}`
        });
      }
    }
    
    if (categoryId) {
      params['category.id'] = categoryId;
    }
    
    // Build custom headers
    const customHeaders = {};
    if (acceptLanguage) {
      // Validate Accept-Language header (BCP-47 format)
      const validLanguages = ['en-US', 'pl-PL', 'uk-UA', 'sk-SK', 'cs-CZ', 'hu-HU'];
      if (validLanguages.includes(acceptLanguage)) {
        customHeaders['Accept-Language'] = acceptLanguage;
      }
    }
    
    // Make API request with user token (required for product details)
    const data = await allegroApiRequest(`/sale/products/${productId}`, params, true, customHeaders);
    
    res.json({
      success: true,
      data: data
    });
  } catch (error) {
    // Convert technical error messages to user-friendly ones
    let errorMessage = error.message;
    let statusCode = error.response?.status || 500;
    
    if (error.response?.status === 401) {
      errorMessage = 'Unauthorized. User OAuth authentication is required to access product details.';
      statusCode = 401;
    } else if (error.response?.status === 403) {
      // Access denied - offer doesn't belong to user
      errorMessage = 'Access denied. You can only access your own offers.';
      statusCode = 403;
    } else if (error.response?.status === 404) {
      errorMessage = 'Product/offer not found or language version is currently unavailable.';
      statusCode = 404;
    } else if (error.response?.status === 422) {
      // Handle validation errors
      const errors = error.response?.data?.errors || [];
      if (errors.length > 0) {
        errorMessage = errors.map(e => e.message || e.userMessage || e.details).join('; ') || 'Invalid parameter value.';
      } else {
        errorMessage = error.response?.data?.message || 'One of the parameters has an invalid value.';
      }
      statusCode = 422;
    } else if (error.response?.status) {
      errorMessage = error.response?.data?.message || error.response?.data?.error || errorMessage;
    }
    
    res.status(statusCode).json({
      success: false,
      error: errorMessage,
      ...(error.response?.data?.errors && { errors: error.response.data.errors })
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
 * Find existing category by name AND parent ID in PrestaShop
 * Returns category ID if found, null otherwise
 * Always checks PrestaShop directly to avoid stale cache issues
 */
async function findCategoryByNameAndParent(categoryName, idParent = null) {
  try {
    // Normalize category name (remove accents, collapse spaces, lowercase)
    const normalizedName = categoryName
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .toLowerCase()
      .replace(/\s+/g, ' ')
      .trim();
    
    console.log(`Checking PrestaShop for category "${categoryName}" (normalized: "${normalizedName}") with parent ID: ${idParent}...`);
    
    // Fetch all categories (with pagination support)
    let allCategories = [];
    let limit = 1000;
    let offset = 0;
    let hasMore = true;
    let paginationSupported = true;
    
    // Fetch categories in batches to handle pagination
    while (hasMore) {
      try {
        // Request id, name, and id_parent to check both name and parent
        const data = await prestashopApiRequest(
          `categories?display=[id,name,id_parent]&limit=${limit}${offset > 0 ? `&offset=${offset}` : ''}`,
          'GET'
        );
        
        // PrestaShop returns categories in format: { categories: [{ category: {...} }] } or { category: {...} }
        let categories = [];
        if (data.categories) {
          if (Array.isArray(data.categories)) {
            categories = data.categories.map(item => item.category || item);
          } else if (data.categories.category) {
            categories = Array.isArray(data.categories.category) 
              ? data.categories.category 
              : [data.categories.category];
          }
        } else if (data.category) {
          categories = Array.isArray(data.category) ? data.category : [data.category];
        }
        
        if (categories.length === 0) {
          hasMore = false;
        } else {
          allCategories = allCategories.concat(categories);
          // If we got fewer categories than the limit, we've reached the end
          if (categories.length < limit) {
            hasMore = false;
          } else if (paginationSupported) {
            offset += limit;
          } else {
            // Pagination not supported, stop after first batch
            hasMore = false;
          }
        }
      } catch (paginationError) {
        // If pagination fails (404), PrestaShop may not support offset parameter
        // Just use the categories we've fetched so far
        if (paginationError.response?.status === 404 && offset > 0) {
          paginationSupported = false;
          hasMore = false;
          // Don't log this as an error - it's expected for some PrestaShop versions
        } else {
          // Re-throw if it's a different error or first page fails
          throw paginationError;
        }
      }
    }
    
    // Search for category with matching name AND parent
    // PrestaShop category names are stored as arrays: [{ id: 1, value: "Name PL" }, { id: 2, value: "Name EN" }]
    for (const category of allCategories) {
      // Check parent ID first (faster check)
      const categoryParentId = category.id_parent || category.parent?.id || null;
      const parentMatches = idParent === null || String(categoryParentId) === String(idParent);
      
      if (!parentMatches) {
        continue; // Skip if parent doesn't match
      }
      
      if (category.name) {
        // Handle both array format and object format
        let nameArray = [];
        if (Array.isArray(category.name)) {
          nameArray = category.name;
        } else if (category.name.language && Array.isArray(category.name.language)) {
          nameArray = category.name.language;
        } else if (category.name.language) {
          nameArray = [category.name.language];
        } else if (typeof category.name === 'object' && category.name.value) {
          nameArray = [category.name];
        } else if (typeof category.name === 'string') {
          // Direct string name
          const candidateName = category.name
            .normalize('NFD')
            .replace(/[\u0300-\u036f]/g, '')
            .toLowerCase()
            .replace(/\s+/g, ' ')
            .trim();
          if (candidateName === normalizedName) {
            const categoryId = category.id || category.category?.id;
            if (categoryId) {
              return categoryId;
            }
          }
        }
        
        // Check if any language version matches the category name
        for (const nameEntry of nameArray) {
          if (!nameEntry) continue;
          const rawValue = nameEntry.value || (typeof nameEntry === 'string' ? nameEntry : null);
          if (!rawValue || typeof rawValue !== 'string') continue;
          const candidateName = rawValue
            .normalize('NFD')
            .replace(/[\u0300-\u036f]/g, '')
            .toLowerCase()
            .replace(/\s+/g, ' ')
            .trim();
          if (candidateName === normalizedName) {
            const categoryId = category.id || category.category?.id;
            if (categoryId) {
              return categoryId;
            }
          }
        }
      }
    }
    
    return null; // Category not found
  } catch (error) {
    console.error('Error finding category by name and parent:', error.message);
    return null; // Return null on error to allow creation to proceed
  }
}

/**
 * Find matching category in PrestaShop by traversing category path from root to leaf
 * Returns the deepest (lowest-layer) matching category ID found, or null if no match
 * @param {Array} categoryPath - Array of category objects with {id, name} from root to leaf
 * @returns {Promise<number|null>} - Category ID if found, null otherwise
 */
async function findMatchingCategoryByPath(categoryPath) {
  if (!categoryPath || !Array.isArray(categoryPath) || categoryPath.length === 0) {
    return null;
  }

  try {
    // Start from root (parent ID 2 is Home category in PrestaShop)
    let currentParentId = 2;
    let deepestMatchId = null;

    // Traverse the path from root to leaf
    for (let i = 0; i < categoryPath.length; i++) {
      const pathNode = categoryPath[i];
      const categoryName = pathNode.name;

      if (!categoryName) {
        continue; // Skip if no name
      }

      // Try to find this category level in PrestaShop under the current parent
      const foundCategoryId = await findCategoryByNameAndParent(categoryName, currentParentId);

      if (foundCategoryId && !isNaN(foundCategoryId)) {
        // Found a match at this level, continue to next level
        deepestMatchId = foundCategoryId;
        currentParentId = foundCategoryId;
      } else {
        // No match at this level, stop and return the deepest match found so far
        break;
      }
    }

    return deepestMatchId; // Returns the deepest matching category ID, or null if no match
  } catch (error) {
    console.error('Error finding matching category by path:', error);
    return null;
  }
}

/**
 * Find existing category by name in PrestaShop (legacy function for backward compatibility)
 * Returns category ID if found, null otherwise
 * Always checks PrestaShop directly to avoid stale cache issues
 * NOTE: This only checks by name, not parent. Use findCategoryByNameAndParent for accurate checking.
 */
async function findCategoryByName(categoryName) {
  try {
    // Normalize category name (remove accents, collapse spaces, lowercase)
    const normalizedName = categoryName
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .toLowerCase()
      .replace(/\s+/g, ' ')
      .trim();
    // Always check database to ensure we find existing categories
    // This guarantees we compare against real PrestaShop categories
    console.log(`Checking PrestaShop for category "${categoryName}" (normalized: "${normalizedName}")...`);
    
    // Fetch all categories (with pagination support)
    let allCategories = [];
    let limit = 1000;
    let offset = 0;
    let hasMore = true;
    let paginationSupported = true;
    
    // Fetch categories in batches to handle pagination
    while (hasMore) {
      try {
        // Request at least id + name so we can reliably compare by text
        const data = await prestashopApiRequest(
          `categories?display=[id,name]&limit=${limit}${offset > 0 ? `&offset=${offset}` : ''}`,
          'GET'
        );
        
        // PrestaShop returns categories in format: { categories: [{ category: {...} }] } or { category: {...} }
        let categories = [];
        if (data.categories) {
          if (Array.isArray(data.categories)) {
            categories = data.categories.map(item => item.category || item);
          } else if (data.categories.category) {
            categories = Array.isArray(data.categories.category) 
              ? data.categories.category 
              : [data.categories.category];
          }
        } else if (data.category) {
          categories = Array.isArray(data.category) ? data.category : [data.category];
        }
        
        if (categories.length === 0) {
          hasMore = false;
        } else {
          allCategories = allCategories.concat(categories);
          // If we got fewer categories than the limit, we've reached the end
          if (categories.length < limit) {
            hasMore = false;
          } else if (paginationSupported) {
            offset += limit;
          } else {
            // Pagination not supported, stop after first batch
            hasMore = false;
          }
        }
      } catch (paginationError) {
        // If pagination fails (404), PrestaShop may not support offset parameter
        // Just use the categories we've fetched so far
        if (paginationError.response?.status === 404 && offset > 0) {
          paginationSupported = false;
          hasMore = false;
          // Don't log this as an error - it's expected for some PrestaShop versions
        } else {
          // Re-throw if it's a different error or first page fails
          throw paginationError;
        }
      }
    }
    
    // Search for category with matching name
    // PrestaShop category names are stored as arrays: [{ id: 1, value: "Name PL" }, { id: 2, value: "Name EN" }]
    for (const category of allCategories) {
      if (category.name) {
        // Handle both array format and object format
        let nameArray = [];
        if (Array.isArray(category.name)) {
          nameArray = category.name;
        } else if (category.name.language && Array.isArray(category.name.language)) {
          nameArray = category.name.language;
        } else if (category.name.language) {
          nameArray = [category.name.language];
        } else if (typeof category.name === 'object' && category.name.value) {
          nameArray = [category.name];
        } else if (typeof category.name === 'string') {
          // Direct string name
          const candidateName = category.name
            .normalize('NFD')
            .replace(/[\u0300-\u036f]/g, '')
            .toLowerCase()
            .replace(/\s+/g, ' ')
            .trim();
          if (candidateName === normalizedName) {
            const categoryId = category.id || category.category?.id;
            if (categoryId) {
              return categoryId;
            }
          }
        }
        
        // Check if any language version matches the category name
        for (const nameEntry of nameArray) {
          if (!nameEntry) continue;
          const rawValue = nameEntry.value || (typeof nameEntry === 'string' ? nameEntry : null);
          if (!rawValue || typeof rawValue !== 'string') continue;
          const candidateName = rawValue
            .normalize('NFD')
            .replace(/[\u0300-\u036f]/g, '')
            .toLowerCase()
            .replace(/\s+/g, ' ')
            .trim();
          if (candidateName === normalizedName) {
            const categoryId = category.id || category.category?.id;
            if (categoryId) {
              return categoryId;
            }
          }
        }
      }
    }
    
    return null; // Category not found
  } catch (error) {
    console.error('Error finding category by name:', error.message);
    return null; // Return null on error to allow creation to proceed
  }
}

/**
 * Find existing product by reference (Allegro offer ID) in PrestaShop
 * Returns product ID if found, null otherwise
 */
async function findProductByReference(reference) {
  try {
    // First check if we have a mapping for this reference
    if (productMappings[reference]) {
      const mapping = productMappings[reference];
      const existingProductId = mapping.prestashopProductId;
      
      // Verify the product still exists in PrestaShop
      try {
        await prestashopApiRequest(`products/${existingProductId}`, 'GET');
        console.log(`Found product in mapping cache: reference "${reference}" -> PrestaShop ID ${existingProductId}`);
        return existingProductId; // Product exists, return its ID
      } catch (verifyError) {
        // Product doesn't exist anymore, remove from mapping
        console.log(`Product ${existingProductId} no longer exists in PrestaShop, removing from mapping`);
        delete productMappings[reference];
        saveProductMappings();
      }
    }
    
    // If no mapping or product doesn't exist, search PrestaShop by reference
    // Try multiple PrestaShop API filter syntaxes for compatibility
    const encodedReference = encodeURIComponent(reference);
    let data = null;
    let products = [];
    
    // Try different filter syntaxes
    const filterAttempts = [
      `products?filter[reference]=${encodedReference}`,
      `products?filter[reference]=[${encodedReference}]`,
      `products?filter[reference]=${reference}`,
      `products?filter[reference]=[${reference}]`
    ];
    
    for (const filterUrl of filterAttempts) {
      try {
        data = await prestashopApiRequest(filterUrl, 'GET');
        if (data) {
          break; // Success, exit loop
        }
      } catch (err) {
        // Try next syntax
        continue;
      }
    }
    
    if (!data) {
      // If all filter attempts failed, try getting all products and filtering client-side (limited)
      // This is a fallback - only use if reference search fails
      console.log(`PrestaShop filter API failed, trying fallback search for reference "${reference}"`);
      try {
        data = await prestashopApiRequest('products?limit=1000', 'GET');
      } catch (fallbackError) {
        console.error('Fallback product search also failed:', fallbackError.message);
        return null;
      }
    }
    
    // PrestaShop returns products in format: { products: [{ product: {...} }] } or { product: {...} }
    if (data.products) {
      if (Array.isArray(data.products)) {
        products = data.products.map(item => item.product || item);
      } else if (data.products.product) {
        products = Array.isArray(data.products.product) 
          ? data.products.product 
          : [data.products.product];
      }
    } else if (data.product) {
      products = Array.isArray(data.product) ? data.product : [data.product];
    }
    
    // Find product with matching reference
    for (const product of products) {
      const productRef = product.reference || product.product?.reference;
      if (productRef && productRef.toString() === reference.toString()) {
        const productId = product.id || product.product?.id;
        if (productId) {
          console.log(`Found existing product in PrestaShop: reference "${reference}" -> PrestaShop ID ${productId}`);
          // Update mapping for future lookups
          productMappings[reference] = {
            prestashopProductId: productId,
            allegroOfferId: reference,
            syncedAt: new Date().toISOString()
          };
          saveProductMappings();
          return productId;
        }
      }
    }
    
    console.log(`No product found with reference "${reference}" in PrestaShop`);
    return null; // Product not found
  } catch (error) {
    console.error('Error finding product by reference:', error.message);
    if (error.response?.data) {
      console.error('PrestaShop API error details:', error.response.data);
    }
    return null; // Return null on error to allow creation to proceed
  }
}

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

    // Always check existing categories directly in PrestaShop by name AND parent
    // This prevents duplicates when the same category name exists under different parents
    let existingCategoryId = await findCategoryByNameAndParent(name, idParent);

    // If we found a matching category with the same name AND parent, just return it
    if (existingCategoryId && !isNaN(existingCategoryId)) {
      return res.json({
        success: true,
        category: { id: existingCategoryId },
        message: 'Category already exists',
        existing: true
      });
    }

    // No matching category name in PrestaShop – create a new one
    const categoryData = {
      name: [
        { id: 1, value: name }, // Polish (id: 1)
        { id: 2, value: name }  // English (id: 2)
      ],
      id_parent: idParent,
      active: active,
      link_rewrite: [
        { id: 1, value: name.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '') },
        { id: 2, value: name.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '') }
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
    let { offer, categoryId, categories } = req.body;
    
    if (!offer || !offer.id || !offer.name) {
      return res.status(400).json({
        success: false,
        error: 'Invalid offer data'
      });
    }

    // Allegro has blocked direct access to /sale/offers/{id} resources,
    // so we now rely solely on the offer object passed from the client.
    // The list response already includes primaryImage and often images;
    // that data is forwarded as-is to PrestaShop.

    // Extract product data from Allegro offer
    const price = offer.sellingMode?.price?.amount || offer.price || 0;
    const stock = offer.stock?.available || 0;
    
    // Extract description with support for structured format (description.sections[].items[])
    const descriptionData = extractDescription(offer);
    const description = descriptionData.html;
    const descriptionImages = descriptionData.images;
    
    // Log description extraction for debugging
    console.log(`Description extraction for offer ${offer.id}:`, {
      hasDescription: !!description,
      descriptionLength: description?.length || 0,
      descriptionImagesCount: descriptionImages.length,
      hasStructuredDescription: !!(offer.description?.sections || offer.product?.description?.sections),
      descriptionPreview: description ? description.substring(0, 100) + '...' : 'none'
    });
    
    // Check for separate short description field (if Allegro provides it)
    const shortDescription = offer.shortDescription || offer.summary || offer.description_short || null;
    
    // Handle category - find matching category in PrestaShop by path
    let finalCategoryId = categoryId || 2; // Default to Home category (id: 2)
    
    // If categoryId not provided, try to find matching category by path
    if (!categoryId && offer.category && offer.category.id) {
      try {
        let categoryPath = null;
        
        // Check if categoryPath is provided in the request
        if (offer.categoryPath && Array.isArray(offer.categoryPath) && offer.categoryPath.length > 0) {
          categoryPath = offer.categoryPath;
        } else {
          // Try to build category path from available data
          // 1. Check if categories list is provided and find the category by ID
          if (categories && Array.isArray(categories)) {
            const categoryIdStr = String(offer.category.id);
            const foundCategory = categories.find(cat => 
              String(cat.id) === categoryIdStr || String(cat.category?.id) === categoryIdStr
            );
            if (foundCategory && foundCategory.path && Array.isArray(foundCategory.path)) {
              categoryPath = foundCategory.path;
            }
          }
          
          // 2. If path not found, try to fetch from Allegro API
          if (!categoryPath) {
            // Fetch category data to get parent path
            const allegroCategory = await allegroApiRequest(`/sale/categories/${offer.category.id}`);
            if (allegroCategory && allegroCategory.parent) {
              // Build path by traversing parent chain
              categoryPath = [];
              let currentCat = allegroCategory;
              while (currentCat) {
                categoryPath.unshift({ id: currentCat.id, name: currentCat.name });
                if (currentCat.parent && currentCat.parent.id) {
                  currentCat = await allegroApiRequest(`/sale/categories/${currentCat.parent.id}`);
                } else {
                  break;
                }
              }
            } else if (allegroCategory && allegroCategory.name) {
              // Single category, no parent path
              categoryPath = [{ id: allegroCategory.id, name: allegroCategory.name }];
            }
          }
        }
        
        // If we have a category path, try to find matching category in PrestaShop
        if (categoryPath && categoryPath.length > 0) {
          const matchedCategoryId = await findMatchingCategoryByPath(categoryPath);
          if (matchedCategoryId && !isNaN(matchedCategoryId)) {
            finalCategoryId = matchedCategoryId;
            const pathNames = categoryPath.map(p => p.name).join(' > ');
            console.log(`Found matching category in PrestaShop (ID: ${finalCategoryId}) for path: ${pathNames}`);
          } else {
            const pathNames = categoryPath.map(p => p.name).join(' > ');
            console.log(`No matching category found in PrestaShop for path: ${pathNames}, using default category (ID: 2)`);
          }
        } else {
          console.log(`No category path available for offer ${offer.id}, using default category (ID: 2)`);
        }
      } catch (error) {
        console.error('Failed to find matching category in PrestaShop:', error.message);
        if (error.response?.data) {
          console.error('Allegro API error details:', error.response.data);
        }
        finalCategoryId = 2; // Fallback to Home
      }
    }
    
    // Check if product already exists in PrestaShop before creating
    let existingProductId = await findProductByReference(offer.id.toString());
    let prestashopProductId = null;
    let isNewProduct = false;
    
    // Double-check: verify product doesn't exist (prevents race conditions)
    if (existingProductId) {
      try {
        // Verify the product actually exists and has the correct reference
        const verifyProduct = await prestashopApiRequest(`products/${existingProductId}`, 'GET');
        const productRef = verifyProduct.product?.reference || verifyProduct.reference;
        if (productRef && productRef.toString() === offer.id.toString()) {
          prestashopProductId = existingProductId;
          console.log(`Product with reference "${offer.id}" already exists in PrestaShop (ID: ${prestashopProductId}), using existing product`);
        } else {
          // Reference doesn't match, treat as new product
          console.log(`Product ID ${existingProductId} exists but reference doesn't match, creating new product`);
          existingProductId = null;
        }
      } catch (verifyError) {
        // Product doesn't exist, treat as new
        console.log(`Product ID ${existingProductId} no longer exists, creating new product`);
        existingProductId = null;
      }
    }
    
    if (!existingProductId) {
      // Product doesn't exist, create it
      isNewProduct = true;
      // Build product data for PrestaShop
      const baseName = offer.name || 'Imported product';
      const slug = prestashopSlug(baseName);

      const productData = {
        // Core identifiers / defaults
        id_shop_default: '1',
        id_category_default: String(finalCategoryId),
        id_tax_rules_group: '0',
        reference: offer.id.toString(),

        // Localized fields (match PrestaShop JSON <-> XML model)
        name: [
          { id: '1', value: baseName },
          { id: '2', value: baseName }
        ],
        description: [
          { id: '1', value: description },
          { id: '2', value: description }
        ],
        description_short: [
          {
            id: '1',
            value: shortDescription || extractShortDescription(description, 800)
          },
          {
            id: '2',
            value: shortDescription || extractShortDescription(description, 800)
          }
        ],
        link_rewrite: [
          { id: '1', value: slug },
          { id: '2', value: slug }
        ],

        // Scalars as strings (as in PrestaShop JSON)
        price: isNaN(Number(price)) ? '0.00' : Number(price).toFixed(2),

        // Flags must be 0/1 as strings, never booleans/null
        active: '1',
        state: '1', // ps_product_shop.state = 1
        visibility: 'both',
        available_for_order: '1',
        show_price: '1',
        indexed: '1',

        // Extra safe defaults to match PrestaShop expectations
        on_sale: '0',
        online_only: '0',
        is_virtual: '0',
        advanced_stock_management: '0',
        condition: 'new',

        // Category associations
        associations: {
          categories: {
            category: [{ id: String(finalCategoryId) }]
          }
        }
      };

      // Create product (send XML body)
      const productXml = buildProductXml(productData);
      const productResponse = await prestashopApiRequest('products', 'POST', productXml);
      // PrestaShop returns: { product: { id: ... } } or { id: ... }
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
      
      console.log(`Created new product "${baseName}" (ID: ${prestashopProductId}) from Allegro offer ID: ${offer.id}`);
      
      // Save mapping immediately after creation to prevent duplicates
      productMappings[offer.id.toString()] = {
        prestashopProductId: prestashopProductId,
        allegroOfferId: offer.id.toString(),
        syncedAt: new Date().toISOString()
      };
      saveProductMappings();
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
      
      // Ensure stock is at least 1 if it's 0, so product appears in product panel
      // Products with 0 quantity won't appear unless out_of_stock behavior allows orders
      const finalStock = parseInt(stock) || 0;
      const quantityToSet = finalStock > 0 ? finalStock : 1; // Set minimum 1 if stock is 0
      
      if (stockAvailableId) {
        // Update existing stock_available
        const stockXml = buildStockAvailableXml({
          id: stockAvailableId,
          quantity: quantityToSet,
          id_product: prestashopProductId,
          out_of_stock: finalStock === 0 ? 1 : 2 // Allow orders when stock is 0, deny when stock > 0
        });
        await prestashopApiRequest(`stock_availables/${stockAvailableId}`, 'PUT', stockXml);
      } else {
        // Create new stock_available entry if it doesn't exist
        const stockXml = buildStockAvailableXml({
          quantity: quantityToSet,
          id_product: prestashopProductId,
          id_product_attribute: 0,
          id_shop: 1,
          id_shop_group: 0,
          depends_on_stock: 0,
          out_of_stock: finalStock === 0 ? 1 : 2 // Allow orders when stock is 0, deny when stock > 0
        });
        const stockResponse = await prestashopApiRequest('stock_availables', 'POST', stockXml);
        console.log(`Created stock_available entry for product ${prestashopProductId}`);
      }
    } catch (stockError) {
      console.error('Failed to update stock:', stockError.message);
      // Continue even if stock update fails
    }

    // Handle images - upload to PrestaShop (only for newly created products)
    let uploadedImages = [];
    let imageUrls = [];
    
    // Collect image URLs from Allegro - collect ALL images, not just the first one
    // According to Allegro API docs, images are in an array with url field: [{url: "..."}, {url: "..."}]
    
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
    }
    
    // Method 2: Add primary image if it exists and isn't already in the array
    // Note: primaryImage.url might be the same as images[0].url, so we check for duplicates
    if (offer.primaryImage && offer.primaryImage.url) {
      const primaryImageUrl = offer.primaryImage.url;
      if (!imageUrls.includes(primaryImageUrl)) {
        // Add primary image at the beginning if it's not already in the array
        imageUrls.unshift(primaryImageUrl);
      }
    }
    
    // Method 3: Add images from description sections (extracted by extractDescription function)
    if (descriptionImages && descriptionImages.length > 0) {
      descriptionImages.forEach(imgUrl => {
        if (imgUrl && imgUrl.length > 0 && !imageUrls.includes(imgUrl)) {
          imageUrls.push(imgUrl);
        }
      });
    }
    
    // Method 4: Check alternative image locations (fallback)
    const altImageFields = ['image', 'imageUrl', 'photo', 'thumbnail'];
    for (const field of altImageFields) {
      if (offer[field] && typeof offer[field] === 'string' && offer[field].startsWith('http')) {
        if (!imageUrls.includes(offer[field])) {
          imageUrls.push(offer[field]);
        }
      }
    }
    
    // Method 5: Check if images are in a nested structure (e.g. offer.media.images)
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
    }
    
    // Log image extraction for debugging
    console.log(`Extracted ${imageUrls.length} image(s) for offer ${offer.id}:`, {
      imagesArrayLength: offer.images?.length || 0,
      hasPrimaryImage: !!offer.primaryImage,
      hasMediaImages: !!(offer.media?.images?.length),
      descriptionImagesCount: descriptionImages.length,
      extractedCount: imageUrls.length,
      urls: imageUrls
    });
    
    // PrestaShop can handle many images, but we'll limit to 20 to avoid overwhelming the server
    // Remove this limit or increase it if needed
    const MAX_IMAGES = 20;
    if (imageUrls.length > MAX_IMAGES) {
      console.log(`Limiting images to ${MAX_IMAGES} (found ${imageUrls.length} total)`);
      imageUrls = imageUrls.slice(0, MAX_IMAGES);
    }
    
    // Upload images to PrestaShop - only for newly created products
    if (isNewProduct && imageUrls.length > 0 && prestashopProductId) {
      for (let i = 0; i < imageUrls.length; i++) {
        try {
          const imageUrl = imageUrls[i];
          console.log(`Downloading image ${i + 1}/${imageUrls.length} from: ${imageUrl}`);
          
          // Download image
          const imageBuffer = await downloadImage(imageUrl);
          
          // Determine file extension from URL or content type
          const urlPath = new URL(imageUrl).pathname;
          const extension = urlPath.match(/\.(jpg|jpeg|png|gif|webp)$/i)?.[1] || 'jpg';
          const imageName = `product-${prestashopProductId}-${i + 1}.${extension}`;
          
          // Upload to PrestaShop
          console.log(`Uploading image ${i + 1} to PrestaShop product ${prestashopProductId}...`);
          await uploadProductImage(prestashopProductId, imageBuffer, imageName);
          uploadedImages.push(imageUrl);
          console.log(`Successfully uploaded image ${i + 1}`);
          
          // Small delay between uploads to avoid overwhelming the server
          if (i < imageUrls.length - 1) {
            await new Promise(resolve => setTimeout(resolve, 300));
          }
        } catch (imageError) {
          console.error(`Failed to upload image ${i + 1} (${imageUrls[i]}):`, imageError.message);
          // Continue with other images even if one fails
        }
      }
    }

    // Store product mapping (update if not already saved, or refresh timestamp)
    const offerIdStr = offer.id.toString();
    productMappings[offerIdStr] = {
      prestashopProductId: prestashopProductId,
      allegroOfferId: offerIdStr,
      syncedAt: new Date().toISOString()
    };
    saveProductMappings();

    // Fetch full product details from PrestaShop to return to frontend
    let fullProductDetails = null;
    try {
      const productData = await prestashopApiRequest(`products/${prestashopProductId}`, 'GET');
      // PrestaShop returns: { product: {...} } or { products: [{ product: {...} }] }
      if (productData.product) {
        fullProductDetails = productData.product;
      } else if (productData.products && Array.isArray(productData.products) && productData.products.length > 0) {
        fullProductDetails = productData.products[0].product || productData.products[0];
      } else if (productData.id) {
        fullProductDetails = productData;
      }
    } catch (fetchError) {
      console.error('Failed to fetch full product details:', fetchError.message);
      // Continue even if fetching full details fails - we still have the product ID
    }

    res.json({
      success: true,
      product: {
        id: prestashopProductId,
        prestashopProductId: prestashopProductId,
        allegroOfferId: offer.id,
        ...(fullProductDetails ? { details: fullProductDetails } : {})
      },
      images: {
        urls: imageUrls,
        uploaded: uploadedImages.length,
        total: imageUrls.length
      },
      message: isNewProduct 
        ? `Product created successfully in PrestaShop${uploadedImages.length > 0 ? ` with ${uploadedImages.length} image(s)` : ''}`
        : `Product already exists in PrestaShop (ID: ${prestashopProductId}). Stock updated.`
    });
  } catch (error) {
    res.status(error.response?.status || 500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Get PrestaShop product by ID
 */
app.get('/api/prestashop/products/:productId', async (req, res) => {
  try {
    const { productId } = req.params;
    
    const data = await prestashopApiRequest(`products/${productId}`, 'GET');
    
    // PrestaShop returns: { product: {...} } or { products: [{ product: {...} }] }
    let product = null;
    if (data.product) {
      product = data.product;
    } else if (data.products && Array.isArray(data.products) && data.products.length > 0) {
      product = data.products[0].product || data.products[0];
    } else if (data.id) {
      product = data;
    }
    
    if (!product) {
      return res.status(404).json({
        success: false,
        error: 'Product not found'
      });
    }
    
    res.json({
      success: true,
      product: product
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
    
    if (stockAvailableId) {
      // Update existing stock_available
      const stockXml = buildStockAvailableXml({
        id: stockAvailableId,
        quantity: parseInt(quantity),
        id_product: parseInt(productId)
      });
      await prestashopApiRequest(`stock_availables/${stockAvailableId}`, 'PUT', stockXml);
    } else {
      // Create new stock_available entry if it doesn't exist
      const stockXml = buildStockAvailableXml({
        quantity: parseInt(quantity),
        id_product: parseInt(productId),
        id_product_attribute: 0,
        id_shop: 1,
        id_shop_group: 0,
        depends_on_stock: 0,
        out_of_stock: parseInt(quantity) === 0 ? 1 : 2
      });
      await prestashopApiRequest('stock_availables', 'POST', stockXml);
    }

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

/**
 * CSV Export Utility Functions
 */

/**
 * Escape CSV field value (handles semicolons, quotes, newlines)
 */
function escapeCsvField(value) {
  if (value === null || value === undefined) {
    return '';
  }
  const str = String(value);
  // If contains semicolon, quote, or newline, wrap in quotes and escape quotes
  if (str.includes(';') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

/**
 * Convert array to CSV row (semicolon-delimited)
 */
function arrayToCsvRow(fields) {
  return fields.map(escapeCsvField).join(';');
}

/**
 * Export categories to CSV format
 */
async function exportCategoriesToCsv() {
  try {
    // Fetch all categories from PrestaShop
    let allCategories = [];
    let limit = 1000;
    let offset = 0;
    let hasMore = true;

    while (hasMore) {
      const data = await prestashopApiRequest(`categories?limit=${limit}${offset > 0 ? `&offset=${offset}` : ''}`, 'GET');
      
      let categories = [];
      if (data.categories) {
        if (Array.isArray(data.categories)) {
          categories = data.categories.map(item => item.category || item);
        } else if (data.categories.category) {
          categories = Array.isArray(data.categories.category) 
            ? data.categories.category 
            : [data.categories.category];
        }
      } else if (data.category) {
        categories = Array.isArray(data.category) ? data.category : [data.category];
      }

      if (categories.length === 0) {
        hasMore = false;
      } else {
        allCategories = allCategories.concat(categories);
        if (categories.length < limit) {
          hasMore = false;
        } else {
          offset += limit;
        }
      }
    }

    // Build category hierarchy map
    const categoryMap = {};
    allCategories.forEach(cat => {
      categoryMap[cat.id] = cat;
    });

    // CSV Header
    const header = [
      'Category ID',
      'Active (0/1)',
      'Name *',
      'Parent category',
      'Root category (0/1)',
      'Description',
      'Meta title',
      'Meta keywords',
      'Meta description',
      'URL rewritten',
      'Image URL'
    ];

    const rows = [arrayToCsvRow(header)];

    // Process each category
    allCategories.forEach(cat => {
      const id = cat.id || '';
      const active = cat.active === '1' || cat.active === 1 ? '1' : '0';
      
      // Get name (first language value)
      let name = '';
      if (cat.name) {
        if (Array.isArray(cat.name)) {
          name = cat.name[0]?.value || cat.name[0] || '';
        } else if (cat.name.value) {
          name = cat.name.value;
        } else if (typeof cat.name === 'string') {
          name = cat.name;
        }
      }

      // Get parent category name
      let parentCategory = 'Home';
      if (cat.id_parent && cat.id_parent !== '0' && cat.id_parent !== 0 && categoryMap[cat.id_parent]) {
        const parent = categoryMap[cat.id_parent];
        if (parent && parent.name) {
          if (Array.isArray(parent.name)) {
            parentCategory = parent.name[0]?.value || parent.name[0] || 'Home';
          } else if (parent.name.value) {
            parentCategory = parent.name.value;
          } else if (typeof parent.name === 'string') {
            parentCategory = parent.name;
          }
        }
      }

      const rootCategory = (cat.id_parent === '0' || cat.id_parent === 0 || !cat.id_parent) ? '0' : '0';

      // Get description
      let description = '';
      if (cat.description) {
        if (Array.isArray(cat.description)) {
          description = cat.description[0]?.value || cat.description[0] || '';
        } else if (cat.description.value) {
          description = cat.description.value;
        } else if (typeof cat.description === 'string') {
          description = cat.description;
        }
      }

      // Get meta fields
      let metaTitle = '';
      if (cat.meta_title) {
        if (Array.isArray(cat.meta_title)) {
          metaTitle = cat.meta_title[0]?.value || cat.meta_title[0] || '';
        } else if (cat.meta_title.value) {
          metaTitle = cat.meta_title.value;
        } else if (typeof cat.meta_title === 'string') {
          metaTitle = cat.meta_title;
        }
      }

      let metaKeywords = '';
      if (cat.meta_keywords) {
        if (Array.isArray(cat.meta_keywords)) {
          metaKeywords = cat.meta_keywords[0]?.value || cat.meta_keywords[0] || '';
        } else if (cat.meta_keywords.value) {
          metaKeywords = cat.meta_keywords.value;
        } else if (typeof cat.meta_keywords === 'string') {
          metaKeywords = cat.meta_keywords;
        }
      }

      let metaDescription = '';
      if (cat.meta_description) {
        if (Array.isArray(cat.meta_description)) {
          metaDescription = cat.meta_description[0]?.value || cat.meta_description[0] || '';
        } else if (cat.meta_description.value) {
          metaDescription = cat.meta_description.value;
        } else if (typeof cat.meta_description === 'string') {
          metaDescription = cat.meta_description;
        }
      }

      // Get URL rewritten
      let urlRewritten = '';
      if (cat.link_rewrite) {
        if (Array.isArray(cat.link_rewrite)) {
          urlRewritten = cat.link_rewrite[0]?.value || cat.link_rewrite[0] || '';
        } else if (cat.link_rewrite.value) {
          urlRewritten = cat.link_rewrite.value;
        } else if (typeof cat.link_rewrite === 'string') {
          urlRewritten = cat.link_rewrite;
        }
      }

      // Image URL (not typically in PrestaShop category API response, but we'll try)
      const imageUrl = '';

      const row = [
        id,
        active,
        name,
        parentCategory,
        rootCategory,
        description,
        metaTitle,
        metaKeywords,
        metaDescription,
        urlRewritten,
        imageUrl
      ];

      rows.push(arrayToCsvRow(row));
    });

    return rows.join('\n');
  } catch (error) {
    throw new Error(`Failed to export categories: ${error.message}`);
  }
}

/**
 * Export products to CSV format
 */
async function exportProductsToCsv() {
  try {
    // Fetch all products from PrestaShop
    let allProducts = [];
    let limit = 1000;
    let offset = 0;
    let hasMore = true;

    while (hasMore) {
      const data = await prestashopApiRequest(`products?limit=${limit}${offset > 0 ? `&offset=${offset}` : ''}`, 'GET');
      
      let products = [];
      if (data.products) {
        if (Array.isArray(data.products)) {
          products = data.products.map(item => item.product || item);
        } else if (data.products.product) {
          products = Array.isArray(data.products.product) 
            ? data.products.product 
            : [data.products.product];
        }
      } else if (data.product) {
        products = Array.isArray(data.product) ? data.product : [data.product];
      }

      if (products.length === 0) {
        hasMore = false;
      } else {
        allProducts = allProducts.concat(products);
        if (products.length < limit) {
          hasMore = false;
        } else {
          offset += limit;
        }
      }
    }

    // CSV Header (matching the sample format)
    const header = [
      'Product ID',
      'Active (0/1)',
      'Name *',
      'Categories (x,y,z...)',
      'Price tax excluded',
      'Tax rules ID',
      'Wholesale price',
      'On sale (0/1)',
      'Discount amount',
      'Discount percent',
      'Discount from (yyyy-mm-dd)',
      'Discount to (yyyy-mm-dd)',
      'Reference #',
      'Supplier reference #',
      'Supplier',
      'Manufacturer',
      'EAN13',
      'UPC',
      'Ecotax',
      'Width',
      'Height',
      'Depth',
      'Weight',
      'Delivery time of in-stock products',
      'Delivery time of out-of-stock products with allowed orders',
      'Quantity',
      'Minimal quantity',
      'Low stock level',
      'Send me an email when the quantity is under this level',
      'Visibility',
      'Additional shipping cost',
      'Unity',
      'Unit price',
      'Summary',
      'Description',
      'Tags (x,y,z...)',
      'Meta title',
      'Meta keywords',
      'Meta description',
      'URL rewritten',
      'Text when in stock',
      'Text when backorder allowed',
      'Available for order (0 = No, 1 = Yes)',
      'Product available date',
      'Product creation date',
      'Show price (0 = No, 1 = Yes)',
      'Image URLs (x,y,z...)',
      'Image alt texts (x,y,z...)',
      'Delete existing images (0 = No, 1 = Yes)',
      'Feature(Name:Value:Position)',
      'Available online only (0 = No, 1 = Yes)',
      'Condition',
      'Customizable (0 = No, 1 = Yes)',
      'Uploadable files (0 = No, 1 = Yes)',
      'Text fields (0 = No, 1 = Yes)',
      'Out of stock action',
      'Virtual product',
      'File URL',
      'Number of allowed downloads',
      'Expiration date',
      'Number of days',
      'ID / Name of shop',
      'Advanced stock management',
      'Depends On Stock',
      'Warehouse',
      'Acessories  (x,y,z...)'
    ];

    const rows = [arrayToCsvRow(header)];

    // Process each product
    for (const product of allProducts) {
      // Get category names
      let categoryNames = [];
      if (product.associations && product.associations.categories && product.associations.categories.category) {
        const categories = Array.isArray(product.associations.categories.category)
          ? product.associations.categories.category
          : [product.associations.categories.category];
        
        // Fetch category details to get names
        for (const catRef of categories) {
          try {
            const catData = await prestashopApiRequest(`categories/${catRef.id}`, 'GET');
            const cat = catData.category || catData;
            if (cat && cat.name) {
              let catName = '';
              if (Array.isArray(cat.name)) {
                catName = cat.name[0]?.value || cat.name[0] || '';
              } else if (cat.name.value) {
                catName = cat.name.value;
              } else if (typeof cat.name === 'string') {
                catName = cat.name;
              }
              if (catName) categoryNames.push(catName);
            }
          } catch (e) {
            // Skip if category fetch fails
          }
        }
      }

      // Get stock quantity
      let quantity = '0';
      try {
        const stockData = await prestashopApiRequest(`stock_availables?filter[id_product]=[${product.id}]&filter[id_product_attribute]=[0]`, 'GET');
        if (stockData.stock_availables) {
          const stocks = Array.isArray(stockData.stock_availables) 
            ? stockData.stock_availables 
            : [stockData.stock_availables];
          if (stocks.length > 0) {
            const stock = stocks[0].stock_available || stocks[0];
            quantity = stock.quantity || '0';
          }
        }
      } catch (e) {
        // Use default if stock fetch fails
      }

      // Helper to get localized field
      const getLocalizedField = (field) => {
        if (!product[field]) return '';
        if (Array.isArray(product[field])) {
          return product[field][0]?.value || product[field][0] || '';
        }
        if (product[field].value) return product[field].value;
        if (typeof product[field] === 'string') return product[field];
        return '';
      };

      const id = product.id || '';
      const active = (product.active === '1' || product.active === 1) ? '1' : '0';
      const name = getLocalizedField('name');
      const categories = categoryNames.join(',');
      const price = product.price || '0.00';
      const taxRulesId = product.id_tax_rules_group || '1';
      const wholesalePrice = product.wholesale_price || '';
      const onSale = (product.on_sale === '1' || product.on_sale === 1) ? '1' : '0';
      const discountAmount = '';
      const discountPercent = '';
      const discountFrom = '';
      const discountTo = '';
      const reference = product.reference || '';
      const supplierReference = '';
      const supplier = '';
      const manufacturer = '';
      const ean13 = product.ean13 || '';
      const upc = product.upc || '';
      const ecotax = product.ecotax || '';
      const width = product.width || '';
      const height = product.height || '';
      const depth = product.depth || '';
      const weight = product.weight || '';
      const deliveryTimeInStock = '';
      const deliveryTimeOutOfStock = '';
      const minimalQuantity = product.minimal_quantity || '1';
      const lowStockLevel = '';
      const emailOnLowStock = '';
      const visibility = product.visibility || 'both';
      const additionalShippingCost = product.additional_shipping_cost || '';
      const unity = '';
      const unitPrice = '';
      const summary = getLocalizedField('description_short');
      const description = getLocalizedField('description');
      const tags = '';
      const metaTitle = getLocalizedField('meta_title');
      const metaKeywords = getLocalizedField('meta_keywords');
      const metaDescription = getLocalizedField('meta_description');
      const urlRewritten = getLocalizedField('link_rewrite');
      const textInStock = '';
      const textBackorder = '';
      const availableForOrder = (product.available_for_order === '1' || product.available_for_order === 1) ? '1' : '0';
      const productAvailableDate = '';
      const productCreationDate = '';
      const showPrice = (product.show_price === '1' || product.show_price === 1) ? '1' : '0';
      const imageUrls = '';
      const imageAltTexts = '';
      const deleteExistingImages = '0';
      const features = '';
      const availableOnlineOnly = (product.online_only === '1' || product.online_only === 1) ? '1' : '0';
      const condition = product.condition || 'new';
      const customizable = '0';
      const uploadableFiles = '0';
      const textFields = '0';
      const outOfStockAction = '';
      const virtualProduct = (product.is_virtual === '1' || product.is_virtual === 1) ? '1' : '0';
      const fileUrl = '';
      const allowedDownloads = '';
      const expirationDate = '';
      const numberOfDays = '';
      const shopId = '';
      const advancedStockManagement = (product.advanced_stock_management === '1' || product.advanced_stock_management === 1) ? '1' : '0';
      const dependsOnStock = '';
      const warehouse = '';
      const accessories = '';

      const row = [
        id, active, name, categories, price, taxRulesId, wholesalePrice, onSale,
        discountAmount, discountPercent, discountFrom, discountTo, reference, supplierReference,
        supplier, manufacturer, ean13, upc, ecotax, width, height, depth, weight,
        deliveryTimeInStock, deliveryTimeOutOfStock, quantity, minimalQuantity, lowStockLevel,
        emailOnLowStock, visibility, additionalShippingCost, unity, unitPrice, summary, description,
        tags, metaTitle, metaKeywords, metaDescription, urlRewritten, textInStock, textBackorder,
        availableForOrder, productAvailableDate, productCreationDate, showPrice, imageUrls,
        imageAltTexts, deleteExistingImages, features, availableOnlineOnly, condition,
        customizable, uploadableFiles, textFields, outOfStockAction, virtualProduct, fileUrl,
        allowedDownloads, expirationDate, numberOfDays, shopId, advancedStockManagement,
        dependsOnStock, warehouse, accessories
      ];

      rows.push(arrayToCsvRow(row));
    }

    return rows.join('\n');
  } catch (error) {
    throw new Error(`Failed to export products: ${error.message}`);
  }
}

/**
 * Export combinations to CSV format
 */
async function exportCombinationsToCsv() {
  try {
    // Fetch all products with combinations
    let allProducts = [];
    let limit = 1000;
    let offset = 0;
    let hasMore = true;

    while (hasMore) {
      const data = await prestashopApiRequest(`products?limit=${limit}${offset > 0 ? `&offset=${offset}` : ''}`, 'GET');
      
      let products = [];
      if (data.products) {
        if (Array.isArray(data.products)) {
          products = data.products.map(item => item.product || item);
        } else if (data.products.product) {
          products = Array.isArray(data.products.product) 
            ? data.products.product 
            : [data.products.product];
        }
      } else if (data.product) {
        products = Array.isArray(data.product) ? data.product : [data.product];
      }

      if (products.length === 0) {
        hasMore = false;
      } else {
        allProducts = allProducts.concat(products);
        if (products.length < limit) {
          hasMore = false;
        } else {
          offset += limit;
        }
      }
    }

    // CSV Header
    const header = [
      'Product ID*',
      'Attribute (Name:Type:Position)*',
      'Value (Value:Position)*',
      'Supplier reference',
      'Reference',
      'EAN13',
      'UPC',
      'Wholesale price',
      'Impact on price',
      'Ecotax',
      'Quantity',
      'Minimal quantity',
      'Low stock level',
      'Impact on weight',
      'Default (0 = No, 1 = Yes)',
      'Combination available date',
      'Image position',
      'Image URLs (x,y,z...)',
      'Image alt texts (x,y,z...)',
      'ID / Name of shop',
      'Advanced Stock Managment',
      'Depends on stock',
      'Warehouse'
    ];

    const rows = [arrayToCsvRow(header)];

    // Process each product's combinations
    for (const product of allProducts) {
      const productId = product.id;
      
      // Fetch product combinations
      try {
        const combData = await prestashopApiRequest(`combinations?filter[id_product]=[${productId}]`, 'GET');
        let combinations = [];
        
        if (combData.combinations) {
          if (Array.isArray(combData.combinations)) {
            combinations = combData.combinations.map(item => item.combination || item);
          } else if (combData.combinations.combination) {
            combinations = Array.isArray(combData.combinations.combination)
              ? combData.combinations.combination
              : [combData.combinations.combination];
          }
        } else if (combData.combination) {
          combinations = Array.isArray(combData.combination) ? combData.combination : [combData.combination];
        }

        // Process each combination
        for (const combination of combinations) {
          // Fetch combination details to get attributes
          try {
            const combDetail = await prestashopApiRequest(`combinations/${combination.id}`, 'GET');
            const comb = combDetail.combination || combDetail;

            // Get attributes
            let attributes = [];
            let values = [];
            if (comb.associations && comb.associations.product_option_values) {
              const optionValues = Array.isArray(comb.associations.product_option_values.product_option_value)
                ? comb.associations.product_option_values.product_option_value
                : [comb.associations.product_option_values.product_option_value];

              for (const optVal of optionValues) {
                try {
                  // Fetch option value to get attribute name
                  const optValData = await prestashopApiRequest(`product_option_values/${optVal.id}`, 'GET');
                  const optValObj = optValData.product_option_value || optValData;
                  
                  if (optValObj && optValObj.id_attribute_group) {
                    // Fetch attribute group
                    const attrGroupData = await prestashopApiRequest(`product_option_groups/${optValObj.id_attribute_group}`, 'GET');
                    const attrGroup = attrGroupData.product_option_group || attrGroupData;
                    
                    const attrName = attrGroup.name ? (Array.isArray(attrGroup.name) ? attrGroup.name[0]?.value : attrGroup.name.value || attrGroup.name) : 'Attribute';
                    const attrType = 'select'; // Default type
                    const attrPosition = attributes.length;
                    
                    const valName = optValObj.name ? (Array.isArray(optValObj.name) ? optValObj.name[0]?.value : optValObj.name.value || optValObj.name) : 'Value';
                    const valPosition = values.length;

                    attributes.push(`${attrName}:${attrType}:${attrPosition}`);
                    values.push(`${valName}:${valPosition}`);
                  }
                } catch (e) {
                  // Skip if fetch fails
                }
              }
            }

            // Get stock for this combination
            let quantity = '0';
            try {
              const stockData = await prestashopApiRequest(`stock_availables?filter[id_product]=[${productId}]&filter[id_product_attribute]=[${combination.id}]`, 'GET');
              if (stockData.stock_availables) {
                const stocks = Array.isArray(stockData.stock_availables) 
                  ? stockData.stock_availables 
                  : [stockData.stock_availables];
                if (stocks.length > 0) {
                  const stock = stocks[0].stock_available || stocks[0];
                  quantity = stock.quantity || '0';
                }
              }
            } catch (e) {
              // Use default
            }

            const row = [
              productId,
              attributes.join(', '),
              values.join(', '),
              '', // Supplier reference
              comb.reference || '',
              comb.ean13 || '',
              comb.upc || '',
              comb.wholesale_price || '',
              comb.price || '',
              comb.ecotax || '',
              quantity,
              comb.minimal_quantity || '1',
              '', // Low stock level
              comb.weight || '',
              (comb.default_on === '1' || comb.default_on === 1) ? '1' : '0',
              '', // Combination available date
              '', // Image position
              '', // Image URLs
              '', // Image alt texts
              '', // Shop ID
              (comb.advanced_stock_management === '1' || comb.advanced_stock_management === 1) ? '1' : '0',
              '', // Depends on stock
              ''  // Warehouse
            ];

            rows.push(arrayToCsvRow(row));
          } catch (e) {
            // Skip combination if detail fetch fails
          }
        }
      } catch (e) {
        // Skip if combinations fetch fails (product might not have combinations)
      }
    }

    return rows.join('\n');
  } catch (error) {
    throw new Error(`Failed to export combinations: ${error.message}`);
  }
}

/**
 * Export categories CSV endpoint
 */
app.get('/api/export/categories.csv', async (req, res) => {
  try {
    if (!prestashopCredentials.baseUrl || !prestashopCredentials.apiKey) {
      return res.status(400).json({
        success: false,
        error: 'PrestaShop not configured'
      });
    }

    const csvContent = await exportCategoriesToCsv();
    
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="categories_import.csv"');
    res.send('\ufeff' + csvContent); // Add BOM for Excel compatibility
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Export products CSV endpoint
 */
app.get('/api/export/products.csv', async (req, res) => {
  try {
    if (!prestashopCredentials.baseUrl || !prestashopCredentials.apiKey) {
      return res.status(400).json({
        success: false,
        error: 'PrestaShop not configured'
      });
    }

    const csvContent = await exportProductsToCsv();
    
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="products_import.csv"');
    res.send('\ufeff' + csvContent); // Add BOM for Excel compatibility
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Export combinations CSV endpoint
 */
app.get('/api/export/combinations.csv', async (req, res) => {
  try {
    if (!prestashopCredentials.baseUrl || !prestashopCredentials.apiKey) {
      return res.status(400).json({
        success: false,
        error: 'PrestaShop not configured'
      });
    }

    const csvContent = await exportCombinationsToCsv();
    
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="combinations_import.csv"');
    res.send('\ufeff' + csvContent); // Add BOM for Excel compatibility
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Start server
app.listen(PORT);

