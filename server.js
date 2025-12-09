const express = require('express');
const cors = require('cors');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

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

// Store credentials and tokens (in-memory storage)
// In production, use proper session management or database
let userCredentials = {
  clientId: null,
  clientSecret: null
};

let accessToken = null;
let tokenExpiry = null;

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
 * Make authenticated request to Allegro API
 */
async function allegroApiRequest(endpoint, params = {}) {
  try {
    const token = await getAccessToken();
    
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
 * Get products from Allegro
 * Note: Uses /sale/products endpoint which requires at least 'phrase' or 'ean' parameter
 * category.id can only be used when searching by phrase
 */
app.get('/api/offers', async (req, res) => {
  try {
    let { limit = 20, pageId, phrase, categoryId, ean, language = 'pl-PL' } = req.query;
    
    // Validate and cap limit at 30
    const parsedLimit = parseInt(limit, 10);
    if (isNaN(parsedLimit) || parsedLimit <= 0) {
      limit = 20;
    } else if (parsedLimit > 30) {
      limit = 30;
    } else {
      limit = parsedLimit;
    }
    
    const params = {};

    // Add language parameter
    if (language && language.trim()) {
      params.language = language.trim();
    }

    // Allegro /sale/products API requires at least 'phrase' OR 'ean' parameter
    // phrase must be at least 2 characters long (max 1024), and cannot be whitespace-only
    // category.id can only be used when searching by phrase
    let searchPhrase = '';
    
    // Check if phrase is provided and valid (non-empty after trim and at least 2 chars)
    if (phrase && typeof phrase === 'string') {
      const trimmedPhrase = phrase.trim();
      if (trimmedPhrase.length >= 2) {
        searchPhrase = trimmedPhrase;
      }
    }
    
    // If category is selected but no valid phrase provided, use a minimal valid phrase
    // Using a more meaningful phrase that's likely to match products in any category
    // The API requires at least 2 characters, but very short phrases might be rejected
    if (categoryId && categoryId.trim() && !searchPhrase) {
      // Use a common word that appears in many product names
      searchPhrase = 'produkt'; // "product" in Polish - more meaningful than 'ab'
    }
    
    // Validate and set phrase parameter
    if (searchPhrase && typeof searchPhrase === 'string' && searchPhrase.length >= 2 && searchPhrase.length <= 1024) {
      params.phrase = searchPhrase;
      // category.id can only be used when searching by phrase
      if (categoryId && categoryId.trim()) {
        params['category.id'] = categoryId.trim();
      }
    } else if (ean && ean.trim()) {
      params.ean = ean.trim();
      // category.id cannot be used with ean search
    } else {
      // If no valid phrase or ean provided, return error
      console.error('No valid phrase or ean provided. searchPhrase:', searchPhrase, 'categoryId:', categoryId);
      return res.status(400).json({
        success: false,
        error: 'Please provide a search phrase (at least 2 characters) or select a category to view products. The products API requires at least a phrase parameter with minimum 2 characters.'
      });
    }
    
    // Final validation - ensure we have at least phrase or ean
    if (!params.phrase && !params.ean) {
      console.error('No phrase or ean in params after processing:', params);
      return res.status(400).json({
        success: false,
        error: 'Invalid request: Missing required phrase or ean parameter.'
      });
    }

    // Add pagination - use page.id (cursor) instead of offset for /sale/products
    if (pageId && pageId.trim()) {
      params['page.id'] = pageId.trim();
    }

    // Note: /sale/products doesn't use limit/offset, it uses cursor-based pagination
    // The limit parameter is not directly supported by the API, but we can limit results client-side
    
    console.log('Fetching products with params:', JSON.stringify(params, null, 2));
    console.log('Request URL will be:', `${ALLEGRO_API_URL}/sale/products`);
    console.log('Raw query params received:', { phrase, categoryId, ean, pageId, language });
    console.log('Processed searchPhrase:', searchPhrase);
    console.log('Params object keys:', Object.keys(params));
    console.log('Params object values:', Object.values(params));
    
    // IMPORTANT: /sale/products requires bearer-token-for-user (user-level auth)
    // If using client credentials, ensure your app has the right scopes/permissions
    const data = await allegroApiRequest('/sale/products', params);
    
    console.log('Products response structure:', {
      hasProducts: !!data.products,
      productsCount: data.products?.length || 0,
      hasCategories: !!data.categories,
      hasFilters: !!data.filters,
      hasNextPage: !!data.nextPage,
      keys: Object.keys(data)
    });
    
    // Log sample product structure to debug image extraction
    if (data.products && data.products.length > 0) {
      const sampleProduct = data.products[0];
      console.log('Sample product structure:', {
        id: sampleProduct.id,
        name: sampleProduct.name,
        hasImages: !!sampleProduct.images,
        imagesType: typeof sampleProduct.images,
        imagesIsArray: Array.isArray(sampleProduct.images),
        imagesLength: Array.isArray(sampleProduct.images) ? sampleProduct.images.length : 'N/A',
        imagesSample: sampleProduct.images ? (Array.isArray(sampleProduct.images) ? sampleProduct.images[0] : sampleProduct.images) : 'N/A',
        category: sampleProduct.category,
        allKeys: Object.keys(sampleProduct)
      });
    }
    
    // Normalize response structure for frontend
    // /sale/products returns: { products: [], categories: {}, filters: [], nextPage: {} }
    // Convert to expected format: { offers: [], count: number, nextPage: {} }
    
    // Apply limit to results if specified (Allegro API doesn't support limit directly)
    // Note: limit is already validated and capped at 30 above
    let products = data.products || [];
    if (products.length > limit) {
      products = products.slice(0, limit);
    }
    
    const normalizedData = {
      offers: products,
      count: products.length,
      categories: data.categories || {},
      filters: data.filters || [],
      nextPage: data.nextPage || null
    };
    
    res.json({
      success: true,
      data: normalizedData
    });
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

