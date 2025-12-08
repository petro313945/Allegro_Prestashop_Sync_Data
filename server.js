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
 * Must be after express.json() to access req.body
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
    
    const response = await axios.post(
      `${ALLEGRO_AUTH_URL}/token`,
      'grant_type=client_credentials',
      {
        headers: {
          'Authorization': `Basic ${credentials}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    accessToken = response.data.access_token;
    // Set expiry time (subtract 60 seconds as buffer)
    const expiresIn = response.data.expires_in || 3600;
    tokenExpiry = Date.now() + (expiresIn - 60) * 1000;

    return accessToken;
  } catch (error) {
    console.error('Error getting access token:', error.response?.data || error.message);
    // Convert 401 error to user-friendly message
    if (error.response?.status === 401) {
      const friendlyError = new Error('Invalid credentials. Please check your Client ID and Client Secret.');
      friendlyError.status = 401;
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
 * Get offers from Allegro
 */
app.get('/api/offers', async (req, res) => {
  try {
    const { limit = 20, offset = 0, phrase, categoryId, sellerId } = req.query;
    
    const params = {
      limit: parseInt(limit),
      offset: parseInt(offset)
    };

    if (phrase) params.phrase = phrase;
    if (categoryId) params['category.id'] = categoryId;
    if (sellerId) params['seller.id'] = sellerId;

    const data = await allegroApiRequest('/sale/offers', params);
    
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
 */
app.get('/log', (req, res) => {
  try {
    res.json({
      success: true,
      total: visitorLogs.length,
      logs: visitorLogs.map(log => ({
        ip: log.ip,
        clientId: log.clientId,
        client: log.client,
        timestamp: log.timestamp,
        path: log.path,
        method: log.method,
        requestData: log.requestData || null
      }))
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

