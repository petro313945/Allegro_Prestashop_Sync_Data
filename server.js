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

// Load tokens and credentials on server startup
loadCredentials();
loadTokens();

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
 */
app.get('/api/oauth/status', (req, res) => {
  const isConnected = !!(userOAuthTokens.accessToken && userOAuthTokens.expiresAt && Date.now() < userOAuthTokens.expiresAt);
  
  res.json({
    connected: isConnected,
    userId: userOAuthTokens.userId,
    expiresAt: userOAuthTokens.expiresAt
  });
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

