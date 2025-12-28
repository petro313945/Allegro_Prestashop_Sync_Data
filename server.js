const express = require('express');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const mysql = require('mysql2/promise');
const FormData = require('form-data'); 

// Load environment variables from .env file (explicitly from project root)
const envPath = path.join(__dirname, '.env');
console.log(`Looking for .env file at: ${envPath}`);

// Check if .env file exists
if (!fs.existsSync(envPath)) {
  console.warn(`Warning: .env file not found at: ${envPath}`);
} else {
  console.log(`✓ .env file found at: ${envPath}`);
}

// Load .env file - dotenv doesn't expand variables by default, so $ in passwords should be fine
const dotenvResult = require('dotenv').config({ path: envPath });

if (dotenvResult.error) {
  console.error('Error loading .env file:', dotenvResult.error.message);
  console.warn('Using default values or system environment variables.');
} else {
  console.log('✓ .env file loaded successfully');
  // Debug: Show which variables were loaded
  if (dotenvResult.parsed) {
    const loadedVars = Object.keys(dotenvResult.parsed);
    console.log(`  Loaded ${loadedVars.length} environment variables: ${loadedVars.join(', ')}`);
    // Show actual values for debugging (be careful with sensitive data)
    console.log('  Sample values:');
    if (dotenvResult.parsed.DB_NAME) console.log(`    DB_NAME="${dotenvResult.parsed.DB_NAME}"`);
    if (dotenvResult.parsed.ADMIN_EMAIL) console.log(`    ADMIN_EMAIL="${dotenvResult.parsed.ADMIN_EMAIL}"`);
    if (dotenvResult.parsed.ADMIN_PASSWORD) console.log(`    ADMIN_PASSWORD="${dotenvResult.parsed.ADMIN_PASSWORD ? '*** (set)' : '(not set)'}"`);
  } else {
    console.warn('  Warning: dotenv.parsed is null or undefined - no variables were parsed!');
    console.warn('  This usually means the .env file format is incorrect or the file is empty.');
  }
}

const app = express();
const PORT = process.env.PORT || 3000;

// Product mappings and other file paths (not migrated to database)
const PRODUCT_MAPPINGS_FILE = path.join(__dirname, '.product_mappings.json');
const CATEGORY_CACHE_FILE = path.join(__dirname, '.category_cache.json');
const SYNC_LOG_FILE = path.join(__dirname, '.sync_log.json');

// MariaDB configuration (environment variables - REQUIRED)
const DB_HOST = process.env.DB_HOST;
const DB_PORT = process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 3306;
const DB_USER = process.env.DB_USER;
const DB_PASSWORD = process.env.DB_PASSWORD;
const DB_NAME = process.env.DB_NAME;

// Validate required database configuration
if (!DB_HOST || !DB_USER || !DB_NAME) {
  console.error('❌ ERROR: Required database configuration missing in .env file:');
  if (!DB_HOST) console.error('   Missing: DB_HOST');
  if (!DB_USER) console.error('   Missing: DB_USER');
  if (!DB_NAME) console.error('   Missing: DB_NAME');
  console.error('Please set all required database variables in your .env file.');
  process.exit(1);
}

// Log database configuration (without showing password)
console.log('Database Configuration:');
console.log(`  Host: ${DB_HOST}`);
console.log(`  Port: ${DB_PORT}`);
console.log(`  User: ${DB_USER}`);
console.log(`  Database: ${DB_NAME}`);
console.log(`  Password: ${DB_PASSWORD ? '*** (set)' : '(not set - using empty)'}`);

// Log admin configuration status
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
console.log('Admin Configuration:');
console.log(`  ADMIN_EMAIL: ${ADMIN_EMAIL ? `"${ADMIN_EMAIL}"` : '(not set)'}`);
console.log(`  ADMIN_PASSWORD: ${ADMIN_PASSWORD ? '*** (set)' : '(not set)'}`);
if (ADMIN_EMAIL && ADMIN_PASSWORD) {
  console.log(`  → Admin user "${ADMIN_EMAIL}" will be created if not exists`);
} else {
  console.warn('  ⚠ Warning: ADMIN_EMAIL or ADMIN_PASSWORD not set. Admin user will not be auto-created.');
  if (!ADMIN_EMAIL) console.warn('    Missing: ADMIN_EMAIL');
  if (!ADMIN_PASSWORD) console.warn('    Missing: ADMIN_PASSWORD');
}

// Session and security configuration
const SESSION_IDLE_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes
const SESSION_MAX_LIFETIME_MS = 20 * 60 * 1000; // 20 minutes
const MAX_FAILED_LOGINS = 5;
const LOGIN_LOCK_DURATION_MS = 60 * 1000; // 60 seconds

// Database connection pool (initialized later)
let dbPool = null;

// In-memory session store (token -> session data)
// NOTE: Tokens are not persisted across server restarts by design.
const sessions = new Map();

/**
 * Hash a password using PBKDF2 with per-user salt
 */
function hashPassword(password, salt = null) {
  if (!salt) {
    salt = crypto.randomBytes(16).toString('hex');
  }
  const hash = crypto
    .pbkdf2Sync(password, salt, 100000, 64, 'sha512')
    .toString('hex');
  return { hash, salt };
}

/**
 * Constant‑time password verification
 */
function verifyPassword(password, storedHash, storedSalt) {
  const { hash } = hashPassword(password, storedSalt);
  const hashBuffer = Buffer.from(hash, 'hex');
  const storedBuffer = Buffer.from(storedHash, 'hex');

  if (hashBuffer.length !== storedBuffer.length) {
    return false;
  }
  return crypto.timingSafeEqual(hashBuffer, storedBuffer);
}

/**
 * Create a new session token for a user
 */
function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  sessions.set(token, {
    userId: user.id,
    role: user.role,
    createdAt: now,
    lastActivity: now
  });
  return token;
}

/**
 * Validate a session token and enforce idle / absolute timeouts
 */
function validateSession(token) {
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;

  const now = Date.now();

  // Absolute timeout
  if (now - session.createdAt > SESSION_MAX_LIFETIME_MS) {
    sessions.delete(token);
    return null;
  }

  // Idle timeout
  if (now - session.lastActivity > SESSION_IDLE_TIMEOUT_MS) {
    sessions.delete(token);
    return null;
  }

  // Refresh activity timestamp
  session.lastActivity = now;
  return session;
}

/**
 * Invalidate a session token
 */
function invalidateSession(token) {
  if (token) {
    sessions.delete(token);
  }
}

/**
 * Express middleware: authenticate requests using Bearer token
 */
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.substring(7)
    : null;

  const session = validateSession(token);
  if (!session) {
    return res.status(401).json({
      success: false,
      error: 'Unauthorized'
    });
  }

  req.user = session;
  next();
}

/**
 * Express middleware: require admin role
 */
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      error: 'Admin access required'
    });
  }
  next();
}

/**
 * Initialize MariaDB database and users table (idempotent)
 */
async function initDatabase() {
  // Create database if it does not exist (connect without DB first)
  const rootConnection = await mysql.createConnection({
    host: DB_HOST,
    port: DB_PORT,
    user: DB_USER,
    password: DB_PASSWORD
  });

  await rootConnection.query(
    `CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`
  );
  await rootConnection.end();

  // Create pool bound to the application database
  dbPool = mysql.createPool({
    host: DB_HOST,
    port: DB_PORT,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });

  // Create users table if it does not exist
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      password_salt VARCHAR(64) NOT NULL,
      role ENUM('admin','user') NOT NULL DEFAULT 'user',
      failed_attempts INT UNSIGNED NOT NULL DEFAULT 0,
      lock_until DATETIME NULL,
      is_active TINYINT(1) NOT NULL DEFAULT 1,
      last_login_at DATETIME NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  // Add is_active column if it doesn't exist (for existing databases)
  try {
    const [columns] = await dbPool.query(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = 'users' 
      AND COLUMN_NAME = 'is_active'
    `);
    
    if (columns.length === 0) {
      await dbPool.query(`
        ALTER TABLE users 
        ADD COLUMN is_active TINYINT(1) NOT NULL DEFAULT 1
      `);
      console.log('✓ Added is_active column to users table');
    }
  } catch (error) {
    console.warn('Warning: Could not add is_active column:', error.message);
  }

  // Create allegro_credentials table (single row configuration)
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS allegro_credentials (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      client_id VARCHAR(255) NULL,
      client_secret VARCHAR(255) NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY single_row (id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  // Create oauth_tokens table (single row configuration)
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS oauth_tokens (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      access_token TEXT NULL,
      refresh_token TEXT NULL,
      expires_at BIGINT NULL,
      user_id VARCHAR(255) NULL,
      client_access_token TEXT NULL,
      client_token_expiry BIGINT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY single_row (id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  // Create prestashop_credentials table (single row configuration)
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS prestashop_credentials (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      base_url VARCHAR(500) NULL,
      api_key VARCHAR(255) NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY single_row (id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  // Initialize single row for each configuration table if not exists
  await dbPool.query(`
    INSERT IGNORE INTO allegro_credentials (id, client_id, client_secret) VALUES (1, NULL, NULL)
  `);
  await dbPool.query(`
    INSERT IGNORE INTO oauth_tokens (id, access_token, refresh_token, expires_at, user_id, client_access_token, client_token_expiry) 
    VALUES (1, NULL, NULL, NULL, NULL, NULL, NULL)
  `);
  await dbPool.query(`
    INSERT IGNORE INTO prestashop_credentials (id, base_url, api_key) VALUES (1, NULL, NULL)
  `);

  console.log('✓ Configuration tables created/verified');

  // Ensure at least one admin user exists if ADMIN_EMAIL / ADMIN_PASSWORD are provided
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (adminEmail && adminPassword) {
    // Check if any admin user exists
    const [adminUsers] = await dbPool.query('SELECT id FROM users WHERE role = ?', ['admin']);
    
    if (adminUsers.length === 0) {
      // No admin users exist, check if the specific admin email exists
      const [rows] = await dbPool.query('SELECT id FROM users WHERE email = ?', [
        adminEmail
      ]);
      if (rows.length === 0) {
        const { hash, salt } = hashPassword(adminPassword);
        await dbPool.query(
          'INSERT INTO users (email, password_hash, password_salt, role) VALUES (?, ?, ?, ?)',
          [adminEmail, hash, salt, 'admin']
        );
        console.log(`✓ Created initial admin user: ${adminEmail}`);
      } else {
        console.log(`✓ Admin user already exists: ${adminEmail}`);
      }
    } else {
      console.log(`✓ Admin user(s) already exist, skipping initial-seed-admin creation`);
    }
  } else {
    console.warn('⚠ Admin user not created: ADMIN_EMAIL or ADMIN_PASSWORD not set in .env file');
  }
}

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
  apiKey: null
};

// Store product mappings (Allegro offer ID → PrestaShop product ID)
let productMappings = {};

// Store sync logs in memory only (cleared when sync starts - only current session logs)
let syncLogs = [];
const MAX_SYNC_LOGS = 1000; // Keep last 1000 log entries

// Sync job state
let syncJobRunning = false;
let lastSyncTime = null;
let nextSyncTime = null;
const SYNC_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

// Sync timer control
let syncTimerInterval = null; // Store interval ID for stopping
let syncTimerActive = false; // Track if timer is running

// Configuration: Use setInterval timer (true) or rely on external cron (false)
// Set to false on Ubuntu to use system cron instead
const USE_INTERVAL_TIMER = process.env.USE_INTERVAL_TIMER !== 'false'; // Default: true (for Windows dev)

/**
 * Save tokens to database (persistent storage)
 */
async function saveTokens() {
  try {
    if (!dbPool) {
      console.warn('Database not initialized, cannot save tokens');
      return;
    }
    
    await dbPool.query(`
      UPDATE oauth_tokens SET
        access_token = ?,
        refresh_token = ?,
        expires_at = ?,
        user_id = ?,
        client_access_token = ?,
        client_token_expiry = ?,
        updated_at = NOW()
      WHERE id = 1
    `, [
      userOAuthTokens.accessToken || null,
      userOAuthTokens.refreshToken || null,
      userOAuthTokens.expiresAt || null,
      userOAuthTokens.userId || null,
      accessToken || null,
      tokenExpiry || null
    ]);
  } catch (error) {
    console.error('Error saving tokens to database:', error.message);
  }
}

/**
 * Load tokens from database (on server startup)
 */
async function loadTokens() {
  try {
    if (!dbPool) {
      console.warn('Database not initialized, cannot load tokens');
      return;
    }
    
    const [rows] = await dbPool.query('SELECT * FROM oauth_tokens WHERE id = 1');
    
    if (rows.length > 0) {
      const row = rows[0];
      
      // Restore user OAuth tokens
      if (row.access_token || row.refresh_token) {
        userOAuthTokens = {
          accessToken: row.access_token || null,
          refreshToken: row.refresh_token || null,
          expiresAt: row.expires_at || null,
          userId: row.user_id || null
        };
      }
      
      // Restore client credentials token
      if (row.client_access_token) {
        accessToken = row.client_access_token;
        tokenExpiry = row.client_token_expiry || null;
      }
    }
  } catch (error) {
    console.error('Error loading tokens from database:', error.message);
    // If database error, start fresh
    userOAuthTokens = {
      accessToken: null,
      refreshToken: null,
      expiresAt: null,
      userId: null
    };
  }
}

/**
 * Save credentials to database (persistent storage)
 */
async function saveCredentials() {
  try {
    if (!dbPool) {
      console.warn('Database not initialized, cannot save credentials');
      return;
    }
    
    await dbPool.query(`
      UPDATE allegro_credentials SET
        client_id = ?,
        client_secret = ?,
        updated_at = NOW()
      WHERE id = 1
    `, [
      userCredentials.clientId || null,
      userCredentials.clientSecret || null
    ]);
  } catch (error) {
    console.error('Error saving credentials to database:', error.message);
  }
}

/**
 * Load credentials from database (on server startup)
 */
async function loadCredentials() {
  try {
    if (!dbPool) {
      console.warn('Database not initialized, cannot load credentials');
      return;
    }
    
    const [rows] = await dbPool.query('SELECT * FROM allegro_credentials WHERE id = 1');
    
    if (rows.length > 0) {
      const row = rows[0];
      if (row.client_id && row.client_secret) {
        userCredentials.clientId = row.client_id;
        userCredentials.clientSecret = row.client_secret;
      }
    }
  } catch (error) {
    console.error('Error loading credentials from database:', error.message);
  }
}

/**
 * Save PrestaShop credentials to database
 */
async function savePrestashopCredentials() {
  try {
    if (!dbPool) {
      console.warn('Database not initialized, cannot save PrestaShop credentials');
      return;
    }
    
    await dbPool.query(`
      UPDATE prestashop_credentials SET
        base_url = ?,
        api_key = ?,
        updated_at = NOW()
      WHERE id = 1
    `, [
      prestashopCredentials.baseUrl || null,
      prestashopCredentials.apiKey || null
    ]);
  } catch (error) {
    console.error('Error saving PrestaShop credentials to database:', error.message);
  }
}

/**
 * Load PrestaShop credentials from database
 */
async function loadPrestashopCredentials() {
  try {
    if (!dbPool) {
      console.warn('Database not initialized, cannot load PrestaShop credentials');
      return;
    }
    
    const [rows] = await dbPool.query('SELECT * FROM prestashop_credentials WHERE id = 1');
    
    if (rows.length > 0) {
      const row = rows[0];
      
      // Only load if both values exist and are non-empty strings (after trimming)
      const baseUrl = row.base_url ? String(row.base_url).trim() : '';
      const apiKey = row.api_key ? String(row.api_key).trim() : '';
      
      if (baseUrl && apiKey) {
        prestashopCredentials.baseUrl = baseUrl;
        prestashopCredentials.apiKey = apiKey;
      } else {
        // Clear credentials if they're empty
        prestashopCredentials.baseUrl = null;
        prestashopCredentials.apiKey = null;
      }
    }
  } catch (error) {
    console.error('Error loading PrestaShop credentials from database:', error.message);
    // Clear credentials on error
    prestashopCredentials.baseUrl = null;
    prestashopCredentials.apiKey = null;
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

// Sync logs are stored in memory only - no file persistence
// Logs are cleared when sync starts to show only current session logs

/**
 * Extract product name from PrestaShop product data
 * PrestaShop stores names as: { name: { language: [{ id: '1', value: 'Name' }] } } or { name: [{ id: '1', value: 'Name' }] }
 */
function extractProductNameFromPrestashop(productData) {
  if (!productData) return null;
  
  let nameArray = null;
  
  // Handle different PrestaShop response structures
  if (productData.name) {
    // Case 1: Direct string
    if (typeof productData.name === 'string') {
      return productData.name;
    }
    
    // Case 2: Array format [{ id: '1', value: 'Name' }, { id: '2', value: 'Name' }]
    if (Array.isArray(productData.name)) {
      nameArray = productData.name;
    } 
    // Case 3: Object with language property { language: [{ id: '1', value: 'Name' }] }
    else if (productData.name.language) {
      nameArray = Array.isArray(productData.name.language) 
        ? productData.name.language 
        : [productData.name.language];
    } 
    // Case 4: Direct value property { value: 'Name' }
    else if (productData.name.value) {
      return productData.name.value;
    }
    // Case 5: Object with nested structure
    else if (typeof productData.name === 'object') {
      // Try to find any value property in the object
      for (const key in productData.name) {
        if (productData.name[key] && typeof productData.name[key] === 'object') {
          if (productData.name[key].value) {
            return productData.name[key].value;
          }
        }
      }
    }
  }
  
  // Extract first available name value from array
  if (nameArray && nameArray.length > 0) {
    const firstLang = nameArray[0];
    if (firstLang) {
      // Try value property first
      if (firstLang.value) {
        return firstLang.value;
      }
      // If it's a string directly
      if (typeof firstLang === 'string') {
        return firstLang;
      }
      // Try to find value in nested structure
      if (typeof firstLang === 'object') {
        for (const key in firstLang) {
          if (key === 'value' || key === 'name') {
            return firstLang[key];
          }
        }
      }
    }
  }
  
  return null;
}

/**
 * Extract category name from PrestaShop product data
 * Returns category name string or null if not found
 */
async function extractCategoryNameFromPrestashop(productData) {
  if (!productData) return null;
  
  try {
    // First try to get category ID from id_category_default
    let categoryId = productData.id_category_default;
    
    // If not available, try to get from associations
    if (!categoryId && productData.associations && productData.associations.categories && productData.associations.categories.category) {
      const categories = Array.isArray(productData.associations.categories.category)
        ? productData.associations.categories.category
        : [productData.associations.categories.category];
      
      if (categories.length > 0) {
        categoryId = categories[0].id;
      }
    }
    
    if (!categoryId) {
      return null;
    }
    
    // Fetch category details to get the name
    const categoryData = await prestashopApiRequest(`categories/${categoryId}`, 'GET');
    const category = categoryData.category || categoryData;
    
    if (category && category.name) {
      // Handle different name formats
      if (Array.isArray(category.name)) {
        return category.name[0]?.value || category.name[0] || null;
      } else if (category.name.value) {
        return category.name.value;
      } else if (typeof category.name === 'string') {
        return category.name;
      }
    }
    
    return null;
  } catch (error) {
    // If category fetch fails, return null (non-blocking)
    console.warn(`Failed to fetch category name for product:`, error.message);
    return null;
  }
}

/**
 * Add a sync log entry
 */
function addSyncLog(entry) {
  const logEntry = {
    ...entry,
    timestamp: new Date().toISOString()
  };
  syncLogs.push(logEntry);

  // Enforce MAX_SYNC_LOGS limit
  if (syncLogs.length > MAX_SYNC_LOGS) {
    syncLogs = syncLogs.slice(-MAX_SYNC_LOGS);
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

// Initialize MariaDB database (creates DB and users table if they do not exist)
// Then load tokens and credentials from database
initDatabase()
  .then(async () => {
    console.log(`MariaDB database '${DB_NAME}' initialized`);
    // Load configuration from database (after database is initialized)
    await loadCredentials();
    await loadTokens();
    await loadPrestashopCredentials();
    loadProductMappings();
    // Sync logs are stored in memory only - no file loading needed
    // Category cache loading is disabled – categories are always checked
    // directly against PrestaShop instead of using a persisted cache.
    loadCategoryCache();
  })
  .catch((error) => {
    console.error('Error initializing MariaDB database:', error.message);
  });

/**
 * Authentication & user management routes
 * These are defined before other /api routes.
 */

/**
 * Login endpoint
 * - Email + password only
 * - Brute‑force protection: 5 attempts -> 60s lock
 * - Returns token and basic user info
 */
app.post('/api/login', async (req, res) => {
  try {
    if (!dbPool) {
      return res.status(503).json({
        success: false,
        error: 'Authentication service not initialized yet'
      });
    }

    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password are required'
      });
    }

    const [rows] = await dbPool.query(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    if (rows.length === 0) {
      // Do not reveal whether the email exists
      return res.status(401).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

    const user = rows[0];

    // Check if account is active
    if (user.is_active === 0 || user.is_active === false) {
      return res.status(403).json({
        success: false,
        error: 'Account is deactivated. Please contact an administrator.'
      });
    }

    // Check for lock
    if (user.lock_until && new Date(user.lock_until).getTime() > Date.now()) {
      const secondsLeft = Math.ceil(
        (new Date(user.lock_until).getTime() - Date.now()) / 1000
      );
      return res.status(423).json({
        success: false,
        error: `Account temporarily locked. Try again in ${secondsLeft} seconds.`
      });
    }

    const passwordOk = verifyPassword(
      password,
      user.password_hash,
      user.password_salt
    );

    if (!passwordOk) {
      const failedAttempts = (user.failed_attempts || 0) + 1;
      let lockUntil = null;

      if (failedAttempts >= MAX_FAILED_LOGINS) {
        lockUntil = new Date(Date.now() + LOGIN_LOCK_DURATION_MS);
      }

      await dbPool.query(
        'UPDATE users SET failed_attempts = ?, lock_until = ? WHERE id = ?',
        [failedAttempts, lockUntil, user.id]
      );

      return res.status(401).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

    // Successful login -> reset counters and set last_login_at
    await dbPool.query(
      'UPDATE users SET failed_attempts = 0, lock_until = NULL, last_login_at = NOW() WHERE id = ?',
      [user.id]
    );

    const token = createSession(user);

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role
      },
      session: {
        idleTimeoutMinutes: SESSION_IDLE_TIMEOUT_MS / 60000,
        maxLifetimeMinutes: SESSION_MAX_LIFETIME_MS / 60000
      }
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({
      success: false,
      error: 'Login failed'
    });
  }
});

/**
 * Logout endpoint
 */
app.post('/api/logout', (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.substring(7)
    : null;

  invalidateSession(token);

  res.json({
    success: true
  });
});

/**
 * Admin: create user account
 * - Only admins can create accounts
 * - Users cannot self‑register
 */
app.post('/api/admin/users', authMiddleware, requireAdmin, async (req, res) => {
  try {
    if (!dbPool) {
      return res.status(503).json({
        success: false,
        error: 'Authentication service not initialized yet'
      });
    }

    const { email, password, role } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password are required'
      });
    }

    const normalizedRole = role === 'admin' ? 'admin' : 'user';

    const [existing] = await dbPool.query(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );
    if (existing.length > 0) {
      return res.status(409).json({
        success: false,
        error: 'User with this email already exists'
      });
    }

    const { hash, salt } = hashPassword(password);
    const [result] = await dbPool.query(
      'INSERT INTO users (email, password_hash, password_salt, role) VALUES (?, ?, ?, ?)',
      [email, hash, salt, normalizedRole]
    );

    res.status(201).json({
      success: true,
      user: {
        id: result.insertId,
        email,
        role: normalizedRole
      }
    });
  } catch (error) {
    console.error('Create user error:', error.message);
    res.status(500).json({
      success: false,
      error: 'Could not create user'
    });
  }
});

/**
 * Admin: list all users
 * - Only admins can view user list
 */
app.get('/api/admin/users', authMiddleware, requireAdmin, async (req, res) => {
  try {
    if (!dbPool) {
      return res.status(503).json({
        success: false,
        error: 'Authentication service not initialized yet'
      });
    }

    const [rows] = await dbPool.query(
      'SELECT id, email, role, failed_attempts, lock_until, is_active, last_login_at, created_at, updated_at FROM users ORDER BY created_at DESC'
    );

    res.json({
      success: true,
      users: rows.map(user => ({
        id: user.id,
        email: user.email,
        role: user.role,
        failed_attempts: user.failed_attempts,
        lock_until: user.lock_until,
        is_active: user.is_active === 1 || user.is_active === true,
        last_login_at: user.last_login_at,
        created_at: user.created_at,
        updated_at: user.updated_at
      }))
    });
  } catch (error) {
    console.error('List users error:', error.message);
    res.status(500).json({
      success: false,
      error: 'Could not list users'
    });
  }
});

/**
 * Admin: update user account
 * - Only admins can update accounts
 * - Can update email, password, and role
 */
app.put('/api/admin/users/:id', authMiddleware, requireAdmin, async (req, res) => {
  try {
    if (!dbPool) {
      return res.status(503).json({
        success: false,
        error: 'Authentication service not initialized yet'
      });
    }

    const userId = parseInt(req.params.id, 10);
    if (isNaN(userId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid user ID'
      });
    }

    const { email, password, role, is_active } = req.body || {};
    
    // Check if user exists
    const [existing] = await dbPool.query(
      'SELECT id FROM users WHERE id = ?',
      [userId]
    );
    if (existing.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    const updates = [];
    const values = [];

    // Update email if provided
    if (email !== undefined) {
      // Check if email is already taken by another user
      const [emailCheck] = await dbPool.query(
        'SELECT id FROM users WHERE email = ? AND id != ?',
        [email, userId]
      );
      if (emailCheck.length > 0) {
        return res.status(409).json({
          success: false,
          error: 'Email already in use by another user'
        });
      }
      updates.push('email = ?');
      values.push(email);
    }

    // Update password if provided
    if (password !== undefined && password !== '') {
      const { hash, salt } = hashPassword(password);
      updates.push('password_hash = ?', 'password_salt = ?');
      values.push(hash, salt);
    }

    // Update role if provided
    if (role !== undefined) {
      const normalizedRole = role === 'admin' ? 'admin' : 'user';
      updates.push('role = ?');
      values.push(normalizedRole);
    }

    // Update is_active if provided
    if (is_active !== undefined) {
      updates.push('is_active = ?');
      values.push(is_active ? 1 : 0);
    }

    if (updates.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'No fields to update'
      });
    }

    values.push(userId);
    await dbPool.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
      values
    );

    // Fetch updated user
    const [updated] = await dbPool.query(
      'SELECT id, email, role, failed_attempts, lock_until, is_active, last_login_at, created_at, updated_at FROM users WHERE id = ?',
      [userId]
    );

    res.json({
      success: true,
      user: {
        id: updated[0].id,
        email: updated[0].email,
        role: updated[0].role,
        failed_attempts: updated[0].failed_attempts,
        lock_until: updated[0].lock_until,
        is_active: updated[0].is_active === 1 || updated[0].is_active === true,
        last_login_at: updated[0].last_login_at,
        created_at: updated[0].created_at,
        updated_at: updated[0].updated_at
      }
    });
  } catch (error) {
    console.error('Update user error:', error.message);
    res.status(500).json({
      success: false,
      error: 'Could not update user'
    });
  }
});

/**
 * Admin: delete user account
 * - Only admins can delete accounts
 * - Prevents deleting the last admin user
 */
app.delete('/api/admin/users/:id', authMiddleware, requireAdmin, async (req, res) => {
  try {
    if (!dbPool) {
      return res.status(503).json({
        success: false,
        error: 'Authentication service not initialized yet'
      });
    }

    const userId = parseInt(req.params.id, 10);
    if (isNaN(userId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid user ID'
      });
    }

    // Check if user exists and get their role
    const [existing] = await dbPool.query(
      'SELECT id, role FROM users WHERE id = ?',
      [userId]
    );
    if (existing.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Prevent deleting the last admin user
    if (existing[0].role === 'admin') {
      const [adminCount] = await dbPool.query(
        'SELECT COUNT(*) as count FROM users WHERE role = ?',
        ['admin']
      );
      if (adminCount[0].count <= 1) {
        return res.status(400).json({
          success: false,
          error: 'Cannot delete the last admin user'
        });
      }
    }

    await dbPool.query('DELETE FROM users WHERE id = ?', [userId]);

    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    console.error('Delete user error:', error.message);
    res.status(500).json({
      success: false,
      error: 'Could not delete user'
    });
  }
});

// File watcher removed - credentials are now stored in database
// Changes are automatically reflected when loadPrestashopCredentials() is called

// Store visitor logs (in-memory storage)
// In production, use proper database storage
let visitorLogs = [];

/**
 * Set user credentials
 */
async function setCredentials(clientId, clientSecret) {
  userCredentials.clientId = clientId;
  userCredentials.clientSecret = clientSecret;
  // Invalidate existing token when credentials change
  accessToken = null;
  tokenExpiry = null;
  // Save credentials to database
  await saveCredentials();
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

    // Save tokens to database
    await saveTokens();

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
 * Reloads tokens from file to ensure we're using the latest token
 */
async function getUserAccessToken() {
  try {
    // Reload tokens from database to ensure we have the latest token
    // This is important because tokens can be updated by OAuth callback
    // while the server is running
    try {
      if (dbPool) {
        const [rows] = await dbPool.query('SELECT * FROM oauth_tokens WHERE id = 1');
        if (rows.length > 0) {
          const row = rows[0];
          if (row.access_token || row.refresh_token) {
            // Replace the entire object, don't merge, to ensure we get the latest values
            userOAuthTokens = {
              accessToken: row.access_token || null,
              refreshToken: row.refresh_token || null,
              expiresAt: row.expires_at || null,
              userId: row.user_id || null
            };
          }
        }
      }
    } catch (reloadError) {
      // If reload fails, continue with in-memory token
      console.warn('Warning: Could not reload tokens from database:', reloadError.message);
    }

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

        // Save tokens to database
        await saveTokens();

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
        await saveTokens(); // Save cleared tokens
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
 * Normalize localized field from PrestaShop API format to buildProductXml format
 * Handles different PrestaShop API response formats
 */
function normalizeLocalizedField(field, fallbackValue = '') {
  if (!field) {
    return [{ id: '1', value: fallbackValue }, { id: '2', value: fallbackValue }];
  }
  
  // If already in correct format: [{id: '1', value: '...'}, ...]
  if (Array.isArray(field) && field.length > 0 && field[0].id && field[0].value !== undefined) {
    return field;
  }
  
  // If it's an object with language keys: {1: '...', 2: '...'}
  if (typeof field === 'object' && !Array.isArray(field)) {
    const result = [];
    for (const [langId, value] of Object.entries(field)) {
      if (langId !== 'id' && value !== undefined && value !== null) {
        result.push({ id: langId, value: String(value) });
      }
    }
    if (result.length > 0) return result;
  }
  
  // If it's a simple string, convert to array format
  if (typeof field === 'string') {
    return [{ id: '1', value: field }, { id: '2', value: field }];
  }
  
  // Fallback
  return [{ id: '1', value: fallbackValue }, { id: '2', value: fallbackValue }];
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

  // Include ID if provided (required for PUT/update operations)
  const idXml = product.id ? `<id><![CDATA[${product.id}]]></id>` : '';
  
  return `<?xml version="1.0" encoding="UTF-8"?>
<prestashop xmlns:xlink="http://www.w3.org/1999/xlink">
  <product>
    ${idXml}
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
 * Build minimal XML for updating only product price in PrestaShop
 * This is a partial update - only the price field will be changed, all other fields are preserved
 */
function buildProductPriceUpdateXml(productId, price) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<prestashop xmlns:xlink="http://www.w3.org/1999/xlink">
  <product>
    <id><![CDATA[${productId}]]></id>
    <price><![CDATA[${Number(price).toFixed(2)}]]></price>
  </product>
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
    // Convert 403 error to user-friendly message
    if (error.response?.status === 403) {
      const friendlyError = new Error('Access forbidden. Your OAuth token may be expired or missing required permissions. Please reconnect your Allegro account.');
      friendlyError.status = 403;
      throw friendlyError;
    }
    throw error;
  }
}

// API Routes

/**
 * Set credentials endpoint
 */
app.post('/api/credentials', authMiddleware, async (req, res) => {
  try {
    const { clientId, clientSecret } = req.body;
    
    if (!clientId || !clientSecret) {
      return res.status(400).json({
        success: false,
        error: 'Credentials required'
      });
    }

    await setCredentials(clientId, clientSecret);
    
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
app.get('/api/credentials/status', authMiddleware, (req, res) => {
  res.json({
    configured: !!(userCredentials.clientId && userCredentials.clientSecret)
  });
});

/**
 * Health check endpoint
 */
app.get('/api/health', authMiddleware, (req, res) => {
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
app.get('/api/oauth/authorize', authMiddleware, (req, res) => {
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
 * Note: This endpoint does NOT require authentication as it's the entry point
 * where users are redirected after authorizing with Allegro
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
      
      // Save tokens to database (persistent storage)
      await saveTokens();
      
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
app.get('/api/oauth/status', authMiddleware, async (req, res) => {
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
app.post('/api/oauth/disconnect', authMiddleware, async (req, res) => {
  userOAuthTokens = {
    accessToken: null,
    refreshToken: null,
    expiresAt: null,
    userId: null
  };
  
  // Save cleared tokens to database
  await saveTokens();
  
  res.json({
    success: true,
    message: 'Disconnected successfully'
  });
});

/**
 * Get user's own offers from Allegro
 * Uses user OAuth token to fetch user's own offers
 */
app.get('/api/offers', authMiddleware, async (req, res) => {
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
 * Updated to use /sale/product-offers/{offerId} (old /sale/offers/{offerId} was deprecated in 2024)
 */
app.get('/api/offers/:offerId', authMiddleware, async (req, res) => {
  try {
    const { offerId } = req.params;
    
    // Use the new /sale/product-offers/{offerId} endpoint
    // The old /sale/offers/{offerId} endpoint was deprecated and removed in 2024
    const data = await allegroApiRequest(`/sale/product-offers/${offerId}`, {}, true); // Use user token
    
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
      // Check if it's a deprecated endpoint error
      const isDeprecatedError = error.response?.data?.userMessage?.includes('no longer supported') || 
                               error.response?.data?.errors?.some(e => e.userMessage?.includes('no longer supported'));
      if (isDeprecatedError) {
        errorMessage = 'This endpoint is no longer supported by Allegro. The application has been updated to use the new API.';
      } else {
        errorMessage = 'Access denied. You can only access your own offers.';
      }
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
app.get('/api/products/:productId', authMiddleware, async (req, res) => {
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
app.get('/api/categories', authMiddleware, async (req, res) => {
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
app.get('/api/categories/:categoryId', authMiddleware, async (req, res) => {
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
app.get('/api/test-auth', authMiddleware, async (req, res) => {
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
app.post('/api/prestashop/configure', authMiddleware, async (req, res) => {
  try {
    const { baseUrl, apiKey } = req.body;
    
    // Validate that both values exist and are non-empty strings (after trimming)
    const trimmedBaseUrl = baseUrl ? String(baseUrl).trim() : '';
    const trimmedApiKey = apiKey ? String(apiKey).trim() : '';
    
    if (!trimmedBaseUrl || !trimmedApiKey) {
      return res.status(400).json({
        success: false,
        error: 'Base URL and API key are required and cannot be empty'
      });
    }

    prestashopCredentials.baseUrl = trimmedBaseUrl;
    prestashopCredentials.apiKey = trimmedApiKey;
    
    await savePrestashopCredentials();
    
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
 * Disconnect PrestaShop (clear all configuration from database)
 */
app.post('/api/prestashop/disconnect', authMiddleware, async (req, res) => {
  try {
    // Clear PrestaShop credentials
    prestashopCredentials.baseUrl = null;
    prestashopCredentials.apiKey = null;
    
    // Clear PrestaShop credentials from database
    if (dbPool) {
      try {
        await dbPool.query('UPDATE prestashop_credentials SET base_url = NULL, api_key = NULL, updated_at = NOW() WHERE id = 1');
      } catch (error) {
        console.error('Error clearing PrestaShop credentials from database:', error.message);
      }
    }
    
    // Clear Allegro credentials from database
    if (dbPool) {
      try {
        await dbPool.query('UPDATE allegro_credentials SET client_id = NULL, client_secret = NULL, updated_at = NOW() WHERE id = 1');
        // Also clear in-memory credentials
        userCredentials.clientId = null;
        userCredentials.clientSecret = null;
      } catch (error) {
        console.error('Error clearing Allegro credentials from database:', error.message);
      }
    }
    
    // Clear tokens from database
    if (dbPool) {
      try {
        await dbPool.query(`
          UPDATE oauth_tokens SET
            access_token = NULL,
            refresh_token = NULL,
            expires_at = NULL,
            user_id = NULL,
            client_access_token = NULL,
            client_token_expiry = NULL,
            updated_at = NOW()
          WHERE id = 1
        `);
        // Also clear in-memory tokens
        userOAuthTokens = {
          accessToken: null,
          refreshToken: null,
          expiresAt: null,
          userId: null
        };
        accessToken = null;
        tokenExpiry = null;
      } catch (error) {
        console.error('Error clearing tokens from database:', error.message);
      }
    }
    
    res.json({
      success: true,
      message: 'All configuration cleared successfully from database'
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
app.get('/api/prestashop/status', authMiddleware, (req, res) => {
  // Check if both values exist and are non-empty strings (after trimming)
  const baseUrl = prestashopCredentials.baseUrl ? String(prestashopCredentials.baseUrl).trim() : '';
  const apiKey = prestashopCredentials.apiKey ? String(prestashopCredentials.apiKey).trim() : '';
  const configured = !!(baseUrl && apiKey);
  
  res.json({
    configured: configured,
    baseUrl: configured ? baseUrl : null
  });
});

/**
 * Test PrestaShop connection
 */
app.get('/api/prestashop/test', authMiddleware, async (req, res) => {
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
app.get('/api/prestashop/categories', authMiddleware, async (req, res) => {
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
app.post('/api/prestashop/categories', authMiddleware, async (req, res) => {
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
app.post('/api/prestashop/products', authMiddleware, async (req, res) => {
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
      // Get stock available ID for the product (filter by id_product_attribute=0 to get base product stock)
      const stockData = await prestashopApiRequest(`stock_availables?filter[id_product]=[${prestashopProductId}]&filter[id_product_attribute]=[0]`, 'GET');
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
      
      // Use the actual stock value - stock should display correct current stock
      // The out_of_stock setting controls whether orders are allowed when stock is 0
      const finalStock = parseInt(stock) || 0;
      
      if (stockAvailableId) {
        // Update existing stock_available
        const stockXml = buildStockAvailableXml({
          id: stockAvailableId,
          quantity: finalStock, // Use actual stock value, not artificially inflated
          id_product: prestashopProductId,
          out_of_stock: finalStock === 0 ? 1 : 2 // Allow orders when stock is 0, deny when stock > 0
        });
        await prestashopApiRequest(`stock_availables/${stockAvailableId}`, 'PUT', stockXml);
      } else {
        // Stock entry doesn't exist - PrestaShop API doesn't allow POST for stock_availables
        // Stock entries should be created automatically when products are created
        // Log a warning and continue (product creation will handle stock)
        console.warn(`Stock entry not found for product ${prestashopProductId}. Stock entries should be created automatically when products are created.`);
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
app.get('/api/prestashop/products/:productId', authMiddleware, async (req, res) => {
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
    
    // Fetch stock information for the product
    let stock = 0;
    try {
      const stockEndpoint = `stock_availables?filter[id_product]=[${productId}]&filter[id_product_attribute]=[0]`;
      const stockData = await prestashopApiRequest(stockEndpoint, 'GET');
      
      // Extract stock_available ID from the response
      let stockAvailableId = null;
      if (stockData.stock_availables) {
        const stocks = Array.isArray(stockData.stock_availables) 
          ? stockData.stock_availables 
          : [stockData.stock_availables];
        
        if (stocks.length > 0) {
          stockAvailableId = stocks[0].stock_available?.id || stocks[0].id;
        }
      } else if (stockData.stock_available) {
        stockAvailableId = stockData.stock_available.id;
      }
      
      // If we got an ID but no quantity, fetch the full stock_available record
      if (stockAvailableId) {
        try {
          const fullStockData = await prestashopApiRequest(`stock_availables/${stockAvailableId}`, 'GET');
          
          if (fullStockData.stock_available) {
            const quantity = fullStockData.stock_available.quantity;
            if (quantity !== undefined && quantity !== null) {
              stock = parseInt(quantity) || 0;
            }
          } else if (fullStockData.quantity !== undefined && fullStockData.quantity !== null) {
            stock = parseInt(fullStockData.quantity) || 0;
          }
        } catch (fetchError) {
          // Try to get quantity from the initial response if available
          if (stockData.stock_availables) {
            const stocks = Array.isArray(stockData.stock_availables) 
              ? stockData.stock_availables 
              : [stockData.stock_availables];
            if (stocks.length > 0) {
              const stockEntry = stocks[0].stock_available || stocks[0];
              const quantity = stockEntry.quantity;
              if (quantity !== undefined && quantity !== null) {
                stock = parseInt(quantity) || 0;
              }
            }
          }
        }
      }
    } catch (stockError) {
      console.warn(`Failed to fetch stock for product ${productId}:`, stockError.message);
      // Continue without stock if fetch fails
    }
    
    res.json({
      success: true,
      product: product,
      stock: stock
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
app.put('/api/prestashop/products/:productId/stock', authMiddleware, async (req, res) => {
  try {
    const { productId } = req.params;
    const { quantity } = req.body;
    
    if (quantity === undefined) {
      return res.status(400).json({
        success: false,
        error: 'Quantity is required'
      });
    }

    // Get stock available ID (filter by id_product_attribute=0 to get base product stock)
    const stockData = await prestashopApiRequest(`stock_availables?filter[id_product]=[${productId}]&filter[id_product_attribute]=[0]`, 'GET');
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
      // Stock entry doesn't exist - PrestaShop API doesn't allow POST for stock_availables
      // Stock entries should be created automatically when products are created
      return res.status(404).json({
        success: false,
        error: 'Stock entry not found for this product. Stock entries should be created automatically when products are created in PrestaShop.'
      });
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
app.get('/api/prestashop/mappings', authMiddleware, (req, res) => {
  res.json({
    success: true,
    mappings: productMappings
  });
});

/**
 * Sync stock from Allegro to PrestaShop
 */
app.post('/api/prestashop/sync/stock', authMiddleware, async (req, res) => {
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

    // Update stock in PrestaShop (filter by id_product_attribute=0 to get base product stock)
    const stockData = await prestashopApiRequest(`stock_availables?filter[id_product]=[${mapping.prestashopProductId}]&filter[id_product_attribute]=[0]`, 'GET');
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

    // Build category hierarchy map (for parent lookups)
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

    // Process each category - fetch full details
    for (const cat of allCategories) {
      // Fetch full category details - list endpoint only returns basic fields
      let fullCategory = cat;
      if (cat.id) {
        try {
          const categoryData = await prestashopApiRequest(`categories/${cat.id}`, 'GET');
          // PrestaShop returns: { category: {...} } or { categories: [{ category: {...} }] }
          if (categoryData.category) {
            fullCategory = categoryData.category;
          } else if (categoryData.categories && Array.isArray(categoryData.categories) && categoryData.categories.length > 0) {
            fullCategory = categoryData.categories[0].category || categoryData.categories[0];
          } else if (categoryData.id) {
            fullCategory = categoryData;
          }
        } catch (e) {
          console.warn(`Failed to fetch full details for category ${cat.id}, using basic data:`, e.message);
          // Continue with basic category data if full fetch fails
        }
      }
      const id = fullCategory.id || '';
      const active = (fullCategory.active === '1' || fullCategory.active === 1) ? '1' : '0';
      
      // Helper to get localized field
      const getLocalizedField = (field) => {
        if (!fullCategory[field]) return '';
        if (Array.isArray(fullCategory[field])) {
          return fullCategory[field][0]?.value || fullCategory[field][0] || '';
        }
        if (fullCategory[field].value) return fullCategory[field].value;
        if (typeof fullCategory[field] === 'string') return fullCategory[field];
        return '';
      };

      const name = getLocalizedField('name');

      // Get parent category name or ID
      let parentCategory = '';
      const parentId = fullCategory.id_parent || fullCategory.id_parent_default || '';
      if (parentId && parentId !== '0' && parentId !== 0 && parentId !== '1' && parentId !== 1) {
        // Try to get parent name from map first
        if (categoryMap[parentId]) {
          const parent = categoryMap[parentId];
          if (parent && parent.name) {
            if (Array.isArray(parent.name)) {
              parentCategory = parent.name[0]?.value || parent.name[0] || parentId;
            } else if (parent.name.value) {
              parentCategory = parent.name.value;
            } else if (typeof parent.name === 'string') {
              parentCategory = parent.name;
            } else {
              parentCategory = parentId;
            }
          } else {
            parentCategory = parentId;
          }
        } else {
          // If not in map, try to fetch it
          try {
            const parentData = await prestashopApiRequest(`categories/${parentId}`, 'GET');
            const parent = parentData.category || parentData;
            if (parent && parent.name) {
              if (Array.isArray(parent.name)) {
                parentCategory = parent.name[0]?.value || parent.name[0] || parentId;
              } else if (parent.name.value) {
                parentCategory = parent.name.value;
              } else if (typeof parent.name === 'string') {
                parentCategory = parent.name;
              } else {
                parentCategory = parentId;
              }
            } else {
              parentCategory = parentId;
            }
          } catch (e) {
            // If fetch fails, use parent ID
            parentCategory = parentId;
          }
        }
      } else {
        // Root category (parent is 0, 1, or Home)
        parentCategory = 'Home';
      }

      // Root category: 1 if it's a root category (parent is 0, 1, or Home), 0 otherwise
      const rootCategory = (parentId === '0' || parentId === 0 || parentId === '1' || parentId === 1 || !parentId) ? '1' : '0';

      const description = getLocalizedField('description');
      const metaTitle = getLocalizedField('meta_title');
      const metaKeywords = getLocalizedField('meta_keywords');
      const metaDescription = getLocalizedField('meta_description');
      const urlRewritten = getLocalizedField('link_rewrite');

      // Extract image URL from category
      let imageUrl = '';
      if (fullCategory.id) {
        // Build image URL: baseUrl/img/c/{id1}/{id2}/{id3}/{id}.jpg
        const catId = fullCategory.id.toString();
        const id1 = catId.slice(-1);
        const id2 = catId.length > 1 ? catId.slice(-2, -1) : '0';
        const id3 = catId.length > 2 ? catId.slice(-3, -2) : '0';
        const baseUrl = prestashopCredentials.baseUrl.trim().replace(/\/+$/, '');
        imageUrl = `${baseUrl}/img/c/${id3}/${id2}/${id1}/${catId}.jpg`;
        
        // Verify image exists by checking if we can get category image info
        // (We'll include the URL anyway, PrestaShop will handle if it doesn't exist)
      }

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
    }

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
      // Fetch full product details - list endpoint only returns basic fields
      let fullProduct = product;
      if (product.id) {
        try {
          const productData = await prestashopApiRequest(`products/${product.id}`, 'GET');
          // PrestaShop returns: { product: {...} } or { products: [{ product: {...} }] }
          if (productData.product) {
            fullProduct = productData.product;
          } else if (productData.products && Array.isArray(productData.products) && productData.products.length > 0) {
            fullProduct = productData.products[0].product || productData.products[0];
          } else if (productData.id) {
            fullProduct = productData;
          }
        } catch (e) {
          console.warn(`Failed to fetch full details for product ${product.id}, using basic data:`, e.message);
          // Continue with basic product data if full fetch fails
        }
      }

      // Get category names
      let categoryNames = [];
      if (fullProduct.associations && fullProduct.associations.categories && fullProduct.associations.categories.category) {
        const categories = Array.isArray(fullProduct.associations.categories.category)
          ? fullProduct.associations.categories.category
          : [fullProduct.associations.categories.category];
        
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
      // Filter endpoint only returns ID, so we need to fetch full record by ID
      let quantity = '0';
      try {
        const stockData = await prestashopApiRequest(`stock_availables?filter[id_product]=[${fullProduct.id}]&filter[id_product_attribute]=[0]`, 'GET');
        
        // Extract stock_available ID from the filter response
        let stockAvailableId = null;
        if (stockData.stock_availables) {
          const stocks = Array.isArray(stockData.stock_availables) 
            ? stockData.stock_availables 
            : [stockData.stock_availables];
          if (stocks.length > 0) {
            stockAvailableId = stocks[0].stock_available?.id || stocks[0].id;
          }
        } else if (stockData.stock_available) {
          stockAvailableId = stockData.stock_available.id;
        }
        
        // Fetch full stock_available record to get quantity
        if (stockAvailableId) {
          try {
            const fullStockData = await prestashopApiRequest(`stock_availables/${stockAvailableId}`, 'GET');
            if (fullStockData.stock_available) {
              quantity = fullStockData.stock_available.quantity || '0';
            } else if (fullStockData.quantity !== undefined && fullStockData.quantity !== null) {
              quantity = String(fullStockData.quantity);
            }
          } catch (fetchError) {
            // Fallback: try to get quantity from initial response if available
            if (stockData.stock_availables) {
              const stocks = Array.isArray(stockData.stock_availables) 
                ? stockData.stock_availables 
                : [stockData.stock_availables];
              if (stocks.length > 0) {
                const stock = stocks[0].stock_available || stocks[0];
                quantity = stock.quantity || '0';
              }
            }
          }
        }
      } catch (e) {
        // Use default if stock fetch fails
      }

      // Helper to get localized field
      const getLocalizedField = (field) => {
        if (!fullProduct[field]) return '';
        if (Array.isArray(fullProduct[field])) {
          return fullProduct[field][0]?.value || fullProduct[field][0] || '';
        }
        if (fullProduct[field].value) return fullProduct[field].value;
        if (typeof fullProduct[field] === 'string') return fullProduct[field];
        return '';
      };

      const id = fullProduct.id || '';
      const active = (fullProduct.active === '1' || fullProduct.active === 1) ? '1' : '0';
      const name = getLocalizedField('name');
      const categories = categoryNames.join(',');
      const price = fullProduct.price || '0.00';
      const taxRulesId = fullProduct.id_tax_rules_group || '1';
      const wholesalePrice = fullProduct.wholesale_price || '';
      const onSale = (fullProduct.on_sale === '1' || fullProduct.on_sale === 1) ? '1' : '0';
      const discountAmount = '';
      const discountPercent = '';
      const discountFrom = '';
      const discountTo = '';
      const reference = fullProduct.reference || '';
      const supplierReference = '';
      const supplier = '';
      const manufacturer = '';
      const ean13 = fullProduct.ean13 || '';
      const upc = fullProduct.upc || '';
      const ecotax = fullProduct.ecotax || '';
      const width = fullProduct.width || '';
      const height = fullProduct.height || '';
      const depth = fullProduct.depth || '';
      const weight = fullProduct.weight || '';
      const deliveryTimeInStock = '';
      const deliveryTimeOutOfStock = '';
      const minimalQuantity = fullProduct.minimal_quantity || '1';
      const lowStockLevel = '';
      const emailOnLowStock = '';
      const visibility = fullProduct.visibility || 'both';
      const additionalShippingCost = fullProduct.additional_shipping_cost || '';
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
      const availableForOrder = (fullProduct.available_for_order === '1' || fullProduct.available_for_order === 1) ? '1' : '0';
      const productAvailableDate = fullProduct.available_date || '';
      const productCreationDate = fullProduct.date_add || '';
      const showPrice = (fullProduct.show_price === '1' || fullProduct.show_price === 1) ? '1' : '0';
      
      // Extract image URLs from product associations
      let imageUrls = [];
      let imageAltTexts = [];
      if (fullProduct.associations && fullProduct.associations.images && fullProduct.associations.images.image) {
        const images = Array.isArray(fullProduct.associations.images.image)
          ? fullProduct.associations.images.image
          : [fullProduct.associations.images.image];
        
        // Get link_rewrite for image filename
        let linkRewrite = 'product';
        if (fullProduct.link_rewrite) {
          if (Array.isArray(fullProduct.link_rewrite)) {
            linkRewrite = fullProduct.link_rewrite[0]?.value || fullProduct.link_rewrite[0] || 'product';
          } else if (typeof fullProduct.link_rewrite === 'object' && fullProduct.link_rewrite.value) {
            linkRewrite = fullProduct.link_rewrite.value;
          } else if (typeof fullProduct.link_rewrite === 'string') {
            linkRewrite = fullProduct.link_rewrite;
          }
        }
        
        for (const img of images) {
          if (img.id) {
            // Build image URL: baseUrl/img/p/{id1}/{id2}/{id3}/{id}/{hash}.jpg
            const imgId = img.id.toString();
            const id1 = imgId.slice(-1);
            const id2 = imgId.length > 1 ? imgId.slice(-2, -1) : '0';
            const id3 = imgId.length > 2 ? imgId.slice(-3, -2) : '0';
            const baseUrl = prestashopCredentials.baseUrl.trim().replace(/\/+$/, '');
            const imageUrl = `${baseUrl}/img/p/${id3}/${id2}/${id1}/${imgId}/${linkRewrite}-${imgId}.jpg`;
            imageUrls.push(imageUrl);
            imageAltTexts.push(name || `Product ${id} image ${imgId}`);
          }
        }
      }
      const imageUrlsStr = imageUrls.join(',');
      const imageAltTextsStr = imageAltTexts.join(',');
      const deleteExistingImages = '0';
      const features = '';
      const availableOnlineOnly = (fullProduct.online_only === '1' || fullProduct.online_only === 1) ? '1' : '0';
      const condition = fullProduct.condition || 'new';
      const customizable = '0';
      const uploadableFiles = '0';
      const textFields = '0';
      const outOfStockAction = '';
      const virtualProduct = (fullProduct.is_virtual === '1' || fullProduct.is_virtual === 1) ? '1' : '0';
      const fileUrl = '';
      const allowedDownloads = '';
      const expirationDate = '';
      const numberOfDays = '';
      const shopId = '';
      const advancedStockManagement = (fullProduct.advanced_stock_management === '1' || fullProduct.advanced_stock_management === 1) ? '1' : '0';
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
        availableForOrder, productAvailableDate, productCreationDate, showPrice, imageUrlsStr,
        imageAltTextsStr, deleteExistingImages, features, availableOnlineOnly, condition,
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
 * Export categories CSV endpoint
 */
app.get('/api/export/categories.csv', authMiddleware, async (req, res) => {
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
app.get('/api/export/products.csv', authMiddleware, async (req, res) => {
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
 * Sync stock and price from Allegro to PrestaShop
 * 
 * How it works:
 * 1. Fetches all products from PrestaShop
 * 2. For each product, reads the 'reference' field which contains the Allegro offer ID
 * 3. Uses the Allegro offer ID to fetch current stock and price from Allegro API
 * 4. Compares Allegro stock/price with PrestaShop stock/price
 * 5. Updates PrestaShop stock and price if different
 * 
 * Requirements:
 * - PrestaShop products must have the Allegro offer ID saved in the 'reference' field
 * - This is automatically set when products are exported from Allegro to PrestaShop
 * 
 * Optimized: Only syncs products that exist in PrestaShop (by reference field)
 * This is much more efficient than checking all Allegro offers
 */
async function syncStockFromAllegroToPrestashop() {
  if (syncJobRunning) {
    console.log('Stock sync already running, skipping...');
    return;
  }

  // Check if basic configuration is ready.
  // If Allegro or PrestaShop are not configured yet, silently skip sync
  // instead of polluting the Sync Stock Log with warnings during setup.
  const hasPrestashopConfig =
    !!(prestashopCredentials.baseUrl && prestashopCredentials.apiKey);
  const hasAllegroConfig =
    !!(
      (userOAuthTokens.accessToken || userOAuthTokens.refreshToken) &&
      userCredentials.clientId &&
      userCredentials.clientSecret
    );

  if (!hasPrestashopConfig || !hasAllegroConfig) {
    console.log(
      'Stock sync prerequisites not met (Allegro/PrestaShop not fully configured). Sync skipped.'
    );
    return;
  }

  // Try to validate token by attempting to refresh it if needed
  // This also reloads the latest token from file to ensure we're using the most recent token
  try {
    const token = await getUserAccessToken();
    if (!token) {
      throw new Error('No token available');
    }
    console.log('Token validated successfully, proceeding with sync...');
  } catch (tokenError) {
    console.error('Token validation error:', tokenError.message);
    addSyncLog({
      status: 'error',
      message: `OAuth token validation failed: ${tokenError.message}. Please reconnect your Allegro account in the Settings tab.`,
      productName: null,
      offerId: null,
      prestashopProductId: null,
      stockChange: null
    });
    syncJobRunning = false;
    return;
  }

  syncJobRunning = true;
  
  // Clear old logs when sync starts - only show current session logs
  syncLogs = [];
  
  const syncStartTime = new Date().toISOString();
  let syncedCount = 0;
  let errorCount = 0;
  let skippedCount = 0;
  let unchangedCount = 0;
  let priceSyncedCount = 0;
  let priceUnchangedCount = 0;
  let priceErrorCount = 0;
  let consecutive403Errors = 0;
  const MAX_CONSECUTIVE_403 = 3; // Stop after 3 consecutive 403 errors

  try {
    console.log('Starting stock & price sync from Allegro to PrestaShop...');
    console.log('Fetching PrestaShop products and syncing only existing products...');
    
    // Fetch all PrestaShop products (only products that exist in PrestaShop)
    let allPrestashopProducts = [];
    let offset = 0;
    const limit = 1000; // Maximum allowed by API
    let hasMore = true;
    
    while (hasMore) {
      try {
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
          allPrestashopProducts = allPrestashopProducts.concat(products);
          if (products.length < limit) {
            hasMore = false;
          } else {
            offset += limit;
          }
        }
      } catch (fetchError) {
        console.error('Error fetching PrestaShop products:', fetchError.message);
        // If we got some products, continue with what we have
        if (allPrestashopProducts.length > 0) {
          hasMore = false;
        } else {
          throw fetchError;
        }
      }
    }
    
    console.log(`Found ${allPrestashopProducts.length} PrestaShop products to check for stock sync`);
    
    // Log start of sync with product count
    addSyncLog({
      status: 'info',
      message: `Starting stock sync: Found ${allPrestashopProducts.length} products in PrestaShop. Checking stock for each product...`,
      productName: null,
      offerId: null,
      prestashopProductId: null,
      stockChange: null,
      totalProductsChecked: allPrestashopProducts.length
    });
    
    if (allPrestashopProducts.length === 0) {
      addSyncLog({
        status: 'info',
        message: 'No products found in PrestaShop. Nothing to sync.',
        productName: null,
        offerId: null,
        prestashopProductId: null,
        stockChange: null
      });
      syncJobRunning = false;
      return;
    }

    // Process in batches to avoid overwhelming the API
    const batchSize = 10;
    for (let i = 0; i < allPrestashopProducts.length; i += batchSize) {
      // Stop if we've hit too many consecutive 403 errors
      if (consecutive403Errors >= MAX_CONSECUTIVE_403) {
        addSyncLog({
          status: 'error',
          message: `Stopped sync due to multiple authentication errors. Please reconnect your Allegro account in the Settings tab.`,
          productName: null,
          offerId: null,
          prestashopProductId: null,
          stockChange: null
        });
        break;
      }
      
      const batch = allPrestashopProducts.slice(i, i + batchSize);
      
      await Promise.all(batch.map(async (prestashopProduct) => {
        // Initialize variables for error handling
        let productName = null;
        let categoryName = null;
        let offerId = null;
        let prestashopPrice = null;
        let allegroPrice = null;
        
        try {
          const prestashopProductId = prestashopProduct.id?.toString();
          if (!prestashopProductId) {
            skippedCount++;
            return;
          }
          
          // Fetch full product details - list endpoint only returns basic fields (doesn't include reference)
          // We need to fetch individual product to get the reference field, name, and price
          let fullProduct = prestashopProduct;
          try {
            // Try with display parameter first to explicitly request needed fields
            // Note: associations field is not available via display parameter, so we use id_category_default instead
            let productData;
            try {
              productData = await prestashopApiRequest(`products/${prestashopProductId}?display=[id,name,reference,id_category_default,price]`, 'GET');
            } catch (displayError) {
              // If display parameter fails, try without it (some PrestaShop versions might not support it)
              productData = await prestashopApiRequest(`products/${prestashopProductId}`, 'GET');
            }
            
            // PrestaShop returns: { product: {...} } or { products: [{ product: {...} }] }
            if (productData.product) {
              fullProduct = productData.product;
            } else if (productData.products && Array.isArray(productData.products) && productData.products.length > 0) {
              fullProduct = productData.products[0].product || productData.products[0];
            } else if (productData.id) {
              fullProduct = productData;
            }
            
            // Extract price from PrestaShop product
            if (fullProduct.price !== undefined && fullProduct.price !== null) {
              const priceValue = fullProduct.price;
              if (typeof priceValue === 'string' || typeof priceValue === 'number') {
                prestashopPrice = parseFloat(priceValue) || null;
              }
            }
          } catch (fetchError) {
            console.warn(`Failed to fetch full details for product ${prestashopProductId}, using basic data:`, fetchError.message);
            // Continue with basic product data if full fetch fails
          }
          
          // Get product name from PrestaShop using the same logic as CSV export
          productName = extractProductNameFromPrestashop(fullProduct);
          
          // Debug logging if product name extraction fails (only log first few to avoid spam)
          if (!productName && fullProduct && skippedCount < 3) {
            console.log(`Product name extraction failed for product ${prestashopProductId}. Product data structure:`, JSON.stringify({
              hasName: !!fullProduct.name,
              nameType: typeof fullProduct.name,
              nameIsArray: Array.isArray(fullProduct.name),
              nameValue: fullProduct.name ? (typeof fullProduct.name === 'string' ? fullProduct.name.substring(0, 100) : JSON.stringify(fullProduct.name).substring(0, 200)) : null
            }, null, 2));
          }
          
          // Get category name from PrestaShop
          categoryName = await extractCategoryNameFromPrestashop(fullProduct);
          
          // Get reference field (Allegro offer ID) from PrestaShop product
          // Handle different PrestaShop API response structures
          let reference = fullProduct.reference || fullProduct.product?.reference;
          
          if (!reference || (typeof reference === 'string' && reference.trim() === '')) {
            // Product has no reference (Allegro offer ID) - skip it
            skippedCount++;
            addSyncLog({
              status: 'skipped',
              message: `Skipped: No Allegro offer ID (reference) found in PrestaShop product`,
              productName: productName || `Product ID ${prestashopProductId}`,
              categoryName: categoryName,
              offerId: null,
              prestashopProductId: prestashopProductId,
              stockChange: null,
              allegroPrice: null,
              prestashopPrice: prestashopPrice
            });
            return;
          }
          
          // Convert reference to string and validate it's a valid Allegro offer ID (numeric)
          const offerId = reference.toString().trim();
          
          // Validate offer ID format (Allegro offer IDs are numeric)
          if (!/^\d+$/.test(offerId)) {
            skippedCount++;
            addSyncLog({
              status: 'skipped',
              message: `Skipped: Invalid Allegro offer ID format in reference field: "${offerId}"`,
              productName: productName || `Product ID ${prestashopProductId}`,
              offerId: offerId,
              prestashopProductId: prestashopProductId,
              stockChange: null,
              allegroPrice: null,
              prestashopPrice: prestashopPrice
            });
            return;
          }
          
          // Don't set fallback here - let the frontend handle it
          // This way we can distinguish between actual product names and fallbacks

          // Log that we're checking this product with the Allegro offer ID
          addSyncLog({
            status: 'checking',
            message: `Checking stock for Allegro offer ID: ${offerId}`,
            productName: productName,
            categoryName: categoryName,
            offerId: offerId,
            prestashopProductId: prestashopProductId,
            stockChange: null,
            allegroPrice: null,
            prestashopPrice: prestashopPrice
          });

          // Get current stock and price from Allegro for this offer ID
          // Use the new /sale/product-offers/{offerId} endpoint (old /sale/offers/{offerId} was deprecated in 2024)
          // Try to get stock and price from the parts endpoint first (more efficient), fallback to full offer data
          let allegroStock = 0;
          try {
            // First try the parts endpoint for stock and price information (more efficient)
            // This endpoint allows fetching only specific parts like stock and price without the full offer data
            // Format: ?include=stock&include=price (multiple include parameters)
            let stockData = null;
            let priceData = null;
            try {
              // Pass include as array - axios will convert to multiple query params: ?include=stock&include=price
              const partsData = await allegroApiRequest(`/sale/product-offers/${offerId}/parts`, { include: ['stock', 'price'] }, true);
              // Check if stock information is in the parts response
              if (partsData.stock) {
                stockData = partsData.stock;
              }
              // Check if price information is in the parts response
              if (partsData.price || partsData.sellingMode?.price) {
                priceData = partsData.price || partsData.sellingMode?.price;
              }
            } catch (partsError) {
              // If parts endpoint fails (might not be available or might need different params), fall back to full offer data
              // This is expected for some API versions, so we don't log it as an error
            }
            
            // If we didn't get stock or price from parts, fetch full offer data
            if (!stockData || !priceData) {
              const offerData = await allegroApiRequest(`/sale/product-offers/${offerId}`, {}, true);
              // Stock is in stock.available according to Allegro API documentation
              if (!stockData && offerData.stock) {
                stockData = offerData.stock;
              }
              // Price is in sellingMode.price.amount according to Allegro API documentation
              if (!priceData && (offerData.sellingMode?.price || offerData.price)) {
                priceData = offerData.sellingMode?.price || offerData.price;
              }
            }
            
            // Extract stock value from stock object
            if (stockData && stockData.available !== undefined) {
              allegroStock = parseInt(stockData.available) || 0;
            }
            
            // Extract price value from price object
            if (priceData) {
              if (typeof priceData === 'object') {
                allegroPrice = priceData.amount || priceData.value || null;
              } else if (typeof priceData === 'number' || typeof priceData === 'string') {
                allegroPrice = priceData;
              }
              // Convert to number if it's a string
              if (allegroPrice !== null && typeof allegroPrice === 'string') {
                allegroPrice = parseFloat(allegroPrice) || null;
              }
            }
            
            // Reset 403 counter on success
            consecutive403Errors = 0;
          } catch (error) {
            console.error(`Error fetching Allegro offer ${offerId} (from PrestaShop product ${prestashopProductId} reference):`, error.message);
            
            // Check if this is a 403 error, 404 (offer not found), or deprecated endpoint error
            const is403Error = error.response?.status === 403 || error.status === 403;
            const is404Error = error.response?.status === 404 || error.status === 404;
            const isDeprecatedError = error.response?.data?.userMessage?.includes('no longer supported') || 
                                     error.response?.data?.errors?.some(e => e.userMessage?.includes('no longer supported'));
            
            if (is403Error || isDeprecatedError) {
              consecutive403Errors++;
            } else {
              consecutive403Errors = 0; // Reset counter for non-403 errors
            }
            
            // Provide more specific error message
            let errorMessage = error.message;
            if (is404Error) {
              errorMessage = `Allegro offer ID ${offerId} not found. The offer may have been deleted or the reference field in PrestaShop is incorrect.`;
            } else if (isDeprecatedError) {
              errorMessage = 'This endpoint is no longer supported by Allegro. Please update the application.';
            } else if (is403Error) {
              errorMessage = 'Access forbidden. OAuth token expired or missing permissions. Please reconnect your Allegro account in the Settings tab.';
            } else if (error.message.includes('OAuth')) {
              errorMessage = 'OAuth authentication required. Please connect your Allegro account in the Settings tab.';
            }
            
            addSyncLog({
              status: 'error',
              message: `Failed to fetch stock from Allegro (offer ID: ${offerId}): ${errorMessage}`,
              productName: productName,
              categoryName: categoryName,
              offerId: offerId,
              prestashopProductId: prestashopProductId,
              stockChange: null,
              allegroPrice: null,
              prestashopPrice: prestashopPrice
            });
            errorCount++;
            return;
          }

          // Get current stock from PrestaShop
          // Filter endpoint only returns ID, so we need to fetch full record by ID
          let prestashopStock = 0;
          try {
            const stockData = await prestashopApiRequest(`stock_availables?filter[id_product]=[${prestashopProductId}]&filter[id_product_attribute]=[0]`, 'GET');
            
            // Extract stock_available ID from the filter response
            let stockAvailableId = null;
            if (stockData.stock_availables) {
              const stocks = Array.isArray(stockData.stock_availables) 
                ? stockData.stock_availables 
                : [stockData.stock_availables];
              
              if (stocks.length > 0) {
                stockAvailableId = stocks[0].stock_available?.id || stocks[0].id;
              }
            } else if (stockData.stock_available) {
              stockAvailableId = stockData.stock_available.id;
            }
            
            // Fetch full stock_available record to get quantity
            if (stockAvailableId) {
              try {
                const fullStockData = await prestashopApiRequest(`stock_availables/${stockAvailableId}`, 'GET');
                
                if (fullStockData.stock_available) {
                  const quantity = fullStockData.stock_available.quantity;
                  if (quantity !== undefined && quantity !== null) {
                    prestashopStock = parseInt(quantity);
                    // Validate parsed value
                    if (isNaN(prestashopStock)) {
                      console.warn(`Invalid stock quantity format for product ${prestashopProductId}: "${quantity}". Defaulting to 0.`);
                      prestashopStock = 0;
                    }
                  } else {
                    console.warn(`No quantity field found in full stock data for product ${prestashopProductId}`);
                    prestashopStock = 0;
                  }
                } else if (fullStockData.quantity !== undefined && fullStockData.quantity !== null) {
                  prestashopStock = parseInt(fullStockData.quantity) || 0;
                } else {
                  console.warn(`No quantity field found in full stock data for product ${prestashopProductId}. Response:`, JSON.stringify(fullStockData).substring(0, 200));
                  prestashopStock = 0;
                }
              } catch (fetchError) {
                console.warn(`Failed to fetch full stock_available details for product ${prestashopProductId}:`, fetchError.message);
                // Try to get quantity from the initial response if available (fallback)
                if (stockData.stock_availables) {
                  const stocks = Array.isArray(stockData.stock_availables) 
                    ? stockData.stock_availables 
                    : [stockData.stock_availables];
                  if (stocks.length > 0) {
                    const stock = stocks[0].stock_available || stocks[0];
                    const quantity = stock.quantity;
                    if (quantity !== undefined && quantity !== null) {
                      prestashopStock = parseInt(quantity) || 0;
                    }
                  }
                }
              }
            } else {
              console.warn(`No stock_available ID found for product ${prestashopProductId}. Response:`, JSON.stringify(stockData).substring(0, 300));
              prestashopStock = 0;
            }
          } catch (error) {
            console.error(`Error fetching PrestaShop stock for product ${prestashopProductId}:`, error.message);
            if (error.response?.data) {
              console.error(`PrestaShop API error details:`, JSON.stringify(error.response.data).substring(0, 300));
            }
            addSyncLog({
              status: 'error',
              message: `Failed to fetch stock from PrestaShop: ${error.message}`,
              productName: productName,
              categoryName: categoryName,
              offerId: offerId,
              prestashopProductId: prestashopProductId,
              stockChange: null,
              allegroPrice: allegroPrice,
              prestashopPrice: prestashopPrice
            });
            errorCount++;
            return;
          }

          // Only update if stock has changed
          // Use strict comparison with type coercion to handle string vs number differences
          const allegroStockNum = parseInt(allegroStock) || 0;
          const prestashopStockNum = parseInt(prestashopStock) || 0;
          
          // Log stock comparison for debugging
          console.log(`Stock comparison for product ${prestashopProductId} (Allegro offer ${offerId}): Allegro=${allegroStockNum}, PrestaShop=${prestashopStockNum}`);
          
          // Only sync if stocks differ (Allegro is the source of truth)
          if (allegroStockNum !== prestashopStockNum) {
            console.log(`Stock differs: Allegro=${allegroStockNum}, PrestaShop=${prestashopStockNum}. Syncing from Allegro to PrestaShop...`);
            try {
              // Get stock available ID (filter by id_product_attribute=0 to get base product stock)
              const stockData = await prestashopApiRequest(`stock_availables?filter[id_product]=[${prestashopProductId}]&filter[id_product_attribute]=[0]`, 'GET');
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
                // Update existing stock
                const stockXml = buildStockAvailableXml({
                  id: stockAvailableId,
                  quantity: allegroStockNum,
                  id_product: prestashopProductId
                });
                await prestashopApiRequest(`stock_availables/${stockAvailableId}`, 'PUT', stockXml);
              } else {
                // Stock entry doesn't exist - PrestaShop API doesn't allow POST for stock_availables
                // Try to trigger stock entry creation by updating the product
                // This sometimes causes PrestaShop to automatically create the stock entry
                try {
                  console.log(`Attempting to trigger stock entry creation for product ${prestashopProductId} by updating product...`);
                  const productData = await prestashopApiRequest(`products/${prestashopProductId}`, 'GET');
                  
                  if (productData.product) {
                    const product = productData.product;
                    // Update product with minimal change to trigger stock entry creation
                    // Enable stock management if not already enabled
                    const updateXml = `<?xml version="1.0" encoding="UTF-8"?>
<prestashop xmlns:xlink="http://www.w3.org/1999/xlink">
  <product>
    <id><![CDATA[${prestashopProductId}]]></id>
    <advanced_stock_management><![CDATA[0]]></advanced_stock_management>
  </product>
</prestashop>`;
                    await prestashopApiRequest(`products/${prestashopProductId}`, 'PUT', updateXml);
                    
                    // Wait a moment for PrestaShop to process
                    await new Promise(resolve => setTimeout(resolve, 500));
                    
                    // Check again if stock entry was created (filter by id_product_attribute=0 to get base product stock)
                    const stockDataRetry = await prestashopApiRequest(`stock_availables?filter[id_product]=[${prestashopProductId}]&filter[id_product_attribute]=[0]`, 'GET');
                    let stockAvailableIdRetry = null;
                    
                    if (stockDataRetry.stock_availables) {
                      if (Array.isArray(stockDataRetry.stock_availables) && stockDataRetry.stock_availables.length > 0) {
                        stockAvailableIdRetry = stockDataRetry.stock_availables[0].stock_available?.id || stockDataRetry.stock_availables[0].id;
                      } else if (stockDataRetry.stock_availables.stock_available) {
                        stockAvailableIdRetry = stockDataRetry.stock_availables.stock_available.id;
                      }
                    } else if (stockDataRetry.stock_available) {
                      stockAvailableIdRetry = stockDataRetry.stock_available.id;
                    }
                    
                    if (stockAvailableIdRetry) {
                      // Stock entry was created! Now update it
                      const stockXml = buildStockAvailableXml({
                        id: stockAvailableIdRetry,
                        quantity: allegroStockNum,
                        id_product: prestashopProductId
                      });
                      await prestashopApiRequest(`stock_availables/${stockAvailableIdRetry}`, 'PUT', stockXml);
                      
                      syncedCount++;
                      addSyncLog({
                        status: 'success',
                        message: `Stock synced from Allegro to PrestaShop: ${prestashopStockNum} → ${allegroStockNum} (stock entry created automatically)`,
                        productName: productName,
                        categoryName: categoryName,
                        offerId: offerId,
                        prestashopProductId: prestashopProductId,
                        stockChange: {
                          from: prestashopStockNum,
                          to: allegroStockNum
                        },
                        allegroPrice: allegroPrice,
                        prestashopPrice: prestashopPrice
                      });
                      return;
                    }
                  }
                } catch (triggerError) {
                  console.warn(`Failed to trigger stock entry creation for product ${prestashopProductId}:`, triggerError.message);
                }
                
                // If we get here, stock entry still doesn't exist
                console.warn(`Stock entry not found for product ${prestashopProductId}. Stock entries should be created automatically when products are created.`);
                addSyncLog({
                  status: 'warning',
                  message: `Stock entry not found for product. Please enable stock management for this product in PrestaShop back office, or recreate the product.`,
                  productName: productName,
                  categoryName: categoryName,
                  offerId: offerId,
                  prestashopProductId: prestashopProductId,
                  stockChange: null,
                  allegroPrice: allegroPrice,
                  prestashopPrice: prestashopPrice
                });
                skippedCount++;
                return;
              }

              syncedCount++;
              addSyncLog({
                status: 'success',
                message: `Stock synced from Allegro to PrestaShop: ${prestashopStockNum} → ${allegroStockNum}`,
                productName: productName,
                categoryName: categoryName,
                offerId: offerId,
                prestashopProductId: prestashopProductId,
                stockChange: {
                  from: prestashopStockNum,
                  to: allegroStockNum
                },
                allegroPrice: allegroPrice,
                prestashopPrice: prestashopPrice
              });
            } catch (error) {
              console.error(`Error updating PrestaShop stock for product ${prestashopProductId}:`, error.message);
              addSyncLog({
                status: 'error',
                message: `Failed to update stock in PrestaShop: ${error.message}`,
                productName: productName,
                categoryName: categoryName,
                offerId: offerId,
                prestashopProductId: prestashopProductId,
                stockChange: {
                  from: prestashopStockNum,
                  to: allegroStockNum
                },
                allegroPrice: allegroPrice,
                prestashopPrice: prestashopPrice
              });
              errorCount++;
            }
          } else {
            // Stock is the same - no update needed
            unchangedCount++;
            addSyncLog({
              status: 'unchanged',
              message: `Stock unchanged: Allegro=${allegroStockNum}, PrestaShop=${prestashopStockNum} (already in sync)`,
              productName: productName,
              categoryName: categoryName,
              offerId: offerId,
              prestashopProductId: prestashopProductId,
              stockChange: {
                from: prestashopStockNum,
                to: allegroStockNum
              },
              allegroPrice: allegroPrice,
              prestashopPrice: prestashopPrice
            });
          }

          // Price comparison and sync (after stock sync)
          if (allegroPrice !== null && prestashopPrice !== null) {
            // Compare prices with tolerance for floating point precision
            const priceDiff = Math.abs(allegroPrice - prestashopPrice);
            const priceTolerance = 0.01; // 1 grosz tolerance (0.01 PLN)
            
            if (priceDiff > priceTolerance) {
              // Prices differ - sync from Allegro to PrestaShop
              try {
                console.log(`Price differs for product ${prestashopProductId} (Allegro offer ${offerId}): Allegro=${allegroPrice.toFixed(2)}, PrestaShop=${prestashopPrice.toFixed(2)}. Syncing from Allegro to PrestaShop...`);
                
                // Fetch full product data to preserve all fields (name, description, categories, etc.)
                // We need all fields because PrestaShop API may clear fields if not included in PUT request
                let fullProductForUpdate = fullProduct;
                if (!fullProductForUpdate || !fullProductForUpdate.name) {
                  // If we don't have full product data, fetch it now
                  const productDataForUpdate = await prestashopApiRequest(`products/${prestashopProductId}`, 'GET');
                  if (productDataForUpdate.product) {
                    fullProductForUpdate = productDataForUpdate.product;
                  } else if (productDataForUpdate.products && Array.isArray(productDataForUpdate.products) && productDataForUpdate.products.length > 0) {
                    fullProductForUpdate = productDataForUpdate.products[0].product || productDataForUpdate.products[0];
                  } else if (productDataForUpdate.id) {
                    fullProductForUpdate = productDataForUpdate;
                  }
                }
                
                if (!fullProductForUpdate || !fullProductForUpdate.name) {
                  throw new Error('Failed to fetch complete product data for price update');
                }
                
                // Normalize localized fields to ensure they're in the correct format
                const normalizedName = normalizeLocalizedField(fullProductForUpdate.name, productName || 'Product');
                const normalizedDescription = normalizeLocalizedField(fullProductForUpdate.description, '');
                const normalizedDescriptionShort = normalizeLocalizedField(fullProductForUpdate.description_short, '');
                const normalizedLinkRewrite = normalizeLocalizedField(fullProductForUpdate.link_rewrite, '');
                
                // Handle categories associations
                let categories = [];
                if (fullProductForUpdate.associations && fullProductForUpdate.associations.categories) {
                  const cats = fullProductForUpdate.associations.categories.category;
                  if (Array.isArray(cats)) {
                    categories = cats.map(cat => ({ id: String(cat.id || cat) }));
                  } else if (cats && cats.id) {
                    categories = [{ id: String(cats.id) }];
                  }
                }
                // If no categories in associations, use id_category_default
                if (categories.length === 0 && fullProductForUpdate.id_category_default) {
                  categories = [{ id: String(fullProductForUpdate.id_category_default) }];
                }
                
                // Prepare product data with updated price, preserving all other fields
                const updatedProductData = {
                  id: String(prestashopProductId), // Required for PUT/update operations
                  id_shop_default: String(fullProductForUpdate.id_shop_default || '1'),
                  id_tax_rules_group: String(fullProductForUpdate.id_tax_rules_group !== undefined ? fullProductForUpdate.id_tax_rules_group : '0'),
                  id_category_default: String(fullProductForUpdate.id_category_default || '2'),
                  reference: fullProductForUpdate.reference || '',
                  name: normalizedName,
                  description: normalizedDescription,
                  description_short: normalizedDescriptionShort,
                  link_rewrite: normalizedLinkRewrite,
                  price: allegroPrice.toFixed(2), // Update only the price
                  active: String(fullProductForUpdate.active !== undefined ? fullProductForUpdate.active : '1'),
                  state: String(fullProductForUpdate.state !== undefined ? fullProductForUpdate.state : '1'),
                  visibility: fullProductForUpdate.visibility || 'both',
                  available_for_order: String(fullProductForUpdate.available_for_order !== undefined ? fullProductForUpdate.available_for_order : '1'),
                  show_price: String(fullProductForUpdate.show_price !== undefined ? fullProductForUpdate.show_price : '1'),
                  indexed: String(fullProductForUpdate.indexed !== undefined ? fullProductForUpdate.indexed : '1'),
                  on_sale: String(fullProductForUpdate.on_sale !== undefined ? fullProductForUpdate.on_sale : '0'),
                  online_only: String(fullProductForUpdate.online_only !== undefined ? fullProductForUpdate.online_only : '0'),
                  is_virtual: String(fullProductForUpdate.is_virtual !== undefined ? fullProductForUpdate.is_virtual : '0'),
                  advanced_stock_management: String(fullProductForUpdate.advanced_stock_management !== undefined ? fullProductForUpdate.advanced_stock_management : '0'),
                  condition: fullProductForUpdate.condition || 'new',
                  associations: categories.length > 0 ? {
                    categories: {
                      category: categories
                    }
                  } : undefined
                };
                
                // Build complete XML with all fields preserved, only price updated
                const productXml = buildProductXml(updatedProductData);
                await prestashopApiRequest(`products/${prestashopProductId}`, 'PUT', productXml);
                
                priceSyncedCount++;
                addSyncLog({
                  status: 'success',
                  message: `Price synced from Allegro to PrestaShop: ${prestashopPrice.toFixed(2)} PLN → ${allegroPrice.toFixed(2)} PLN`,
                  productName: productName,
                  categoryName: categoryName,
                  offerId: offerId,
                  prestashopProductId: prestashopProductId,
                  stockChange: {
                    from: prestashopStockNum,
                    to: allegroStockNum
                  },
                  priceChange: {
                    from: prestashopPrice,
                    to: allegroPrice
                  },
                  allegroPrice: allegroPrice,
                  prestashopPrice: prestashopPrice // Keep original PrestaShop price to show before/after in UI
                });
              } catch (priceError) {
                console.error(`Error updating PrestaShop price for product ${prestashopProductId}:`, priceError.message);
                priceErrorCount++;
                addSyncLog({
                  status: 'error',
                  message: `Failed to sync price: ${priceError.message}`,
                  productName: productName,
                  categoryName: categoryName,
                  offerId: offerId,
                  prestashopProductId: prestashopProductId,
                  stockChange: {
                    from: prestashopStockNum,
                    to: allegroStockNum
                  },
                  priceChange: {
                    from: prestashopPrice,
                    to: allegroPrice
                  },
                  allegroPrice: allegroPrice,
                  prestashopPrice: prestashopPrice
                });
              }
            } else {
              // Prices are the same (within tolerance) - no update needed
              priceUnchangedCount++;
              // Note: We don't log every unchanged price to avoid log spam
              // The price info is already included in stock sync logs above
            }
          } else {
            // One or both prices are missing - skip price sync
            // This is expected for some products, so we don't log it as an error
          }
        } catch (error) {
          const prestashopProductId = prestashopProduct.id?.toString();
          console.error(`Error processing PrestaShop product ${prestashopProductId} (offer ${offerId || 'unknown'}):`, error.message);
          addSyncLog({
            status: 'error',
            message: `Error processing product: ${error.message}`,
            productName: productName,
            categoryName: categoryName,
            offerId: offerId,
            prestashopProductId: prestashopProductId,
            stockChange: null,
            allegroPrice: null,
            prestashopPrice: null
          });
          errorCount++;
        }
      }));
    }

    // Calculate total products checked (synced + unchanged + skipped + errors)
    const totalProductsChecked = syncedCount + unchangedCount + skippedCount + errorCount;
    
    // Add summary log with product count information
    let summaryMessage = `Stock & Price sync completed: Checked ${totalProductsChecked} PrestaShop products. `;
    const parts = [];
    if (syncedCount > 0) parts.push(`${syncedCount} stock synced`);
    if (unchangedCount > 0) parts.push(`${unchangedCount} stock unchanged`);
    if (skippedCount > 0) parts.push(`${skippedCount} skipped (no/invalid Allegro offer ID)`);
    if (errorCount > 0) parts.push(`${errorCount} stock errors`);
    
    // Add price sync statistics
    const priceParts = [];
    if (priceSyncedCount > 0) priceParts.push(`${priceSyncedCount} prices synced`);
    if (priceUnchangedCount > 0) priceParts.push(`${priceUnchangedCount} prices unchanged`);
    if (priceErrorCount > 0) priceParts.push(`${priceErrorCount} price errors`);
    
    if (priceParts.length > 0) {
      summaryMessage += parts.join(', ') || 'No products processed';
      summaryMessage += ` | Price sync: ${priceParts.join(', ')}`;
    } else {
      summaryMessage += parts.join(', ') || 'No products processed';
    }
    
    addSyncLog({
      status: 'info',
      message: summaryMessage,
      productName: null,
      offerId: null,
      prestashopProductId: null,
      stockChange: null,
      totalProductsChecked: totalProductsChecked
    });

    lastSyncTime = syncStartTime;
    // Logs are in-memory only - no file saving needed
    console.log(`Stock & Price sync completed: Checked ${totalProductsChecked} PrestaShop products. Stock: ${syncedCount} synced, ${unchangedCount} unchanged, ${skippedCount} skipped, ${errorCount} errors. Price: ${priceSyncedCount} synced, ${priceUnchangedCount} unchanged, ${priceErrorCount} errors`);
  } catch (error) {
    console.error('Stock sync error:', error.message);
    addSyncLog({
      status: 'error',
      message: `Stock sync failed: ${error.message}`,
      productName: null,
      offerId: null,
      prestashopProductId: null,
      stockChange: null
    });
  } finally {
    syncJobRunning = false;
  }
}

/**
 * Start the stock sync cron job
 * Uses setInterval on Windows (development) or can be disabled for Ubuntu cron
 */
function startStockSyncCron() {
  if (USE_INTERVAL_TIMER) {
    // Use setInterval timer (good for Windows development)
    const now = Date.now();
    nextSyncTime = new Date(now + SYNC_INTERVAL_MS).toISOString();
    
    // Run sync immediately on startup (after a short delay to let server initialize)
    setTimeout(() => {
      syncStockFromAllegroToPrestashop();
    }, 10000); // Wait 10 seconds after server starts

    // Then run every 5 minutes
    syncTimerInterval = setInterval(() => {
      nextSyncTime = new Date(Date.now() + SYNC_INTERVAL_MS).toISOString();
      syncStockFromAllegroToPrestashop();
    }, SYNC_INTERVAL_MS);
    
    syncTimerActive = true;

    console.log('Stock sync timer started (runs every 5 minutes using setInterval)');
  } else {
    // Timer disabled - use external cron on Ubuntu
    console.log('Stock sync timer disabled. Use system cron to call /api/sync/trigger endpoint.');
    console.log('On Ubuntu, add to crontab: */5 * * * * curl -X POST http://localhost:3000/api/sync/trigger');
  }
}

/**
 * Stop the sync timer
 */
function stopStockSyncCron() {
  if (syncTimerInterval) {
    clearInterval(syncTimerInterval);
    syncTimerInterval = null;
    syncTimerActive = false;
    nextSyncTime = null;
    console.log('Stock sync timer stopped');
  }
}

/**
 * Start the sync timer manually
 */
function startStockSyncCronManual() {
  if (syncTimerActive) {
    return { success: false, error: 'Sync timer is already running' };
  }
  
  if (!USE_INTERVAL_TIMER) {
    return { success: false, error: 'Internal timer is disabled. Use external cron instead.' };
  }
  
  // Clear any existing interval
  if (syncTimerInterval) {
    clearInterval(syncTimerInterval);
  }
  
  // Start new interval
  const now = Date.now();
  nextSyncTime = new Date(now + SYNC_INTERVAL_MS).toISOString();
  
  syncTimerInterval = setInterval(() => {
    nextSyncTime = new Date(Date.now() + SYNC_INTERVAL_MS).toISOString();
    syncStockFromAllegroToPrestashop();
  }, SYNC_INTERVAL_MS);
  
  syncTimerActive = true;
  console.log('Stock sync timer started manually (runs every 5 minutes)');
  
  return { success: true, message: 'Sync timer started' };
}

/**
 * API: Get sync logs
 */
app.get('/api/sync/logs', authMiddleware, (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const status = req.query.status; // Optional filter by status
    
    let filteredLogs = [...syncLogs];
    
    // Filter by status if provided
    if (status) {
      filteredLogs = filteredLogs.filter(log => log.status === status);
    }
    
    // Sort by timestamp (newest first) and limit
    filteredLogs = filteredLogs
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, limit);
    
    res.json({
      success: true,
      logs: filteredLogs,
      total: syncLogs.length,
      lastSyncTime: lastSyncTime,
      nextSyncTime: nextSyncTime
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * API: Clear sync logs
 */
app.post('/api/sync/logs/clear', authMiddleware, (req, res) => {
  try {
    syncLogs = [];
    // Logs are in-memory only - no file saving needed
    res.json({
      success: true,
      message: 'Sync logs cleared'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * API: Trigger manual stock sync
 * Can be called manually or by external cron (Ubuntu)
 * Note: Does not require user session auth - sync runs independently using server-stored credentials
 * The sync function itself validates that Allegro OAuth tokens and PrestaShop credentials exist in DB
 */
app.post('/api/sync/trigger', async (req, res) => {
  try {
    if (syncJobRunning) {
      return res.status(400).json({
        success: false,
        error: 'Stock sync is already running'
      });
    }

    // Run sync in background (don't wait for completion)
    // syncStockFromAllegroToPrestashop() uses server-stored credentials from DB:
    // - userOAuthTokens (Allegro OAuth tokens)
    // - userCredentials (Allegro Client ID/Secret)
    // - prestashopCredentials (PrestaShop API keys)
    // These are independent of user login sessions
    syncStockFromAllegroToPrestashop().catch(error => {
      console.error('Sync error:', error);
    });

    // Return immediately - sync runs in background
    res.json({
      success: true,
      message: 'Stock sync triggered',
      status: 'running'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * API: Check if prerequisites are met for sync
 */
app.get('/api/sync/prerequisites', authMiddleware, (req, res) => {
  try {
    const hasPrestashopConfig =
      !!(prestashopCredentials.baseUrl && prestashopCredentials.apiKey);
    const hasAllegroConfig =
      !!(
        (userOAuthTokens.accessToken || userOAuthTokens.refreshToken) &&
        userCredentials.clientId &&
        userCredentials.clientSecret
      );

    const prerequisitesMet = hasPrestashopConfig && hasAllegroConfig;

    res.json({
      success: true,
      prerequisitesMet,
      details: {
        prestashopConfigured: hasPrestashopConfig,
        allegroConfigured: hasAllegroConfig,
        hasOAuthToken: !!(userOAuthTokens.accessToken || userOAuthTokens.refreshToken),
        hasClientCredentials: !!(userCredentials.clientId && userCredentials.clientSecret)
      },
      message: prerequisitesMet
        ? 'All prerequisites are met. Sync can be started.'
        : 'Missing prerequisites. Please configure Allegro and PrestaShop first.'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * API: Start sync timer
 */
app.post('/api/sync/start', authMiddleware, (req, res) => {
  try {
    // Check prerequisites first
    const hasPrestashopConfig =
      !!(prestashopCredentials.baseUrl && prestashopCredentials.apiKey);
    const hasAllegroConfig =
      !!(
        (userOAuthTokens.accessToken || userOAuthTokens.refreshToken) &&
        userCredentials.clientId &&
        userCredentials.clientSecret
      );

    if (!hasPrestashopConfig || !hasAllegroConfig) {
      return res.status(400).json({
        success: false,
        error: 'Prerequisites not met. Please configure Allegro and PrestaShop first.',
        prerequisitesMet: false
      });
    }

    const result = startStockSyncCronManual();
    if (result.success) {
      res.json({
        success: true,
        message: result.message,
        timerActive: syncTimerActive
      });
    } else {
      res.status(400).json({
        success: false,
        error: result.error
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * API: Stop sync timer
 */
app.post('/api/sync/stop', authMiddleware, (req, res) => {
  try {
    stopStockSyncCron();
    res.json({
      success: true,
      message: 'Sync timer stopped',
      timerActive: syncTimerActive
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * API: Get sync status (for cron monitoring)
 */
app.get('/api/sync/status', authMiddleware, (req, res) => {
  res.json({
    success: true,
    running: syncJobRunning,
    lastSyncTime: lastSyncTime,
    nextSyncTime: nextSyncTime,
    timerActive: syncTimerActive,
    useIntervalTimer: USE_INTERVAL_TIMER
  });
});

// SSL Certificate configuration
const SSL_KEY_PATH = process.env.SSL_KEY_PATH || path.join(__dirname, 'ssl', 'server.key');
const SSL_CERT_PATH = process.env.SSL_CERT_PATH || path.join(__dirname, 'ssl', 'server.crt');
const HTTPS_PORT = process.env.HTTPS_PORT || 3300;
const FORCE_HTTPS = process.env.FORCE_HTTPS === 'true';

// Check if SSL certificates exist
const sslKeyExists = fs.existsSync(SSL_KEY_PATH);
const sslCertExists = fs.existsSync(SSL_CERT_PATH);
const hasSSLCertificates = sslKeyExists && sslCertExists;

// Start server
if (hasSSLCertificates) {
  // HTTPS server
  try {
    const httpsOptions = {
      key: fs.readFileSync(SSL_KEY_PATH),
      cert: fs.readFileSync(SSL_CERT_PATH)
    };

    const httpsServer = https.createServer(httpsOptions, app);
    httpsServer.listen(HTTPS_PORT, '0.0.0.0', () => {
      console.log(`HTTPS Server running on port ${HTTPS_PORT} (accessible from all network interfaces)`);
      // Sync timer is now controlled by user via UI - don't auto-start
      console.log('Sync timer is stopped. Use the UI to start/stop sync timer.');
    });

    // Optionally redirect HTTP to HTTPS
    if (FORCE_HTTPS) {
      const httpApp = express();
      httpApp.use((req, res) => {
        res.redirect(`https://${req.get('host').replace(/:\d+$/, '')}:${HTTPS_PORT}${req.url}`);
      });
      http.createServer(httpApp).listen(PORT, '0.0.0.0', () => {
        console.log(`HTTP Server running on port ${PORT} (redirecting to HTTPS)`);
      });
    } else {
      // Also start HTTP server on default port if not forcing HTTPS
      http.createServer(app).listen(PORT, '0.0.0.0', () => {
        console.log(`HTTP Server also running on port ${PORT}`);
      });
    }
  } catch (error) {
    console.error('Error starting HTTPS server:', error.message);
    console.log('Falling back to HTTP server...');
    http.createServer(app).listen(PORT, '0.0.0.0', () => {
      console.log(`HTTP Server running on port ${PORT} (accessible from all network interfaces)`);
      // Sync timer is now controlled by user via UI - don't auto-start
      console.log('Sync timer is stopped. Use the UI to start/stop sync timer.');
    });
  }
} else {
  // HTTP server only (development mode)
  http.createServer(app).listen(PORT, '0.0.0.0', () => {
    console.log(`HTTP Server running on port ${PORT} (accessible from all network interfaces)`);
    if (process.env.NODE_ENV !== 'production') {
      console.log('Note: HTTPS not configured. SSL certificates not found.');
      console.log(`Expected paths: ${SSL_KEY_PATH}, ${SSL_CERT_PATH}`);
    }
    // Sync timer is now controlled by user via UI - don't auto-start
    console.log('Sync timer is stopped. Use the UI to start/stop sync timer.');
  });
}

