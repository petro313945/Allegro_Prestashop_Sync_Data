Hi qlkub K, Im petro.
My telegram address is @petrob22

---

## Allegro → PrestaShop Integration Tool

A comprehensive Node.js application for synchronizing product data between Allegro.pl marketplace and PrestaShop e-commerce platform. This tool provides a web-based interface for importing products, managing categories, and automatically syncing stock and prices.

### Features

- 🔐 **User Authentication**: Secure JWT-based authentication with admin/user roles
- 🔌 **Allegro API Integration**: OAuth 2.0 authentication and product import from Allegro.pl
- 🛒 **PrestaShop Integration**: Full integration with PrestaShop API for product management
- 📦 **Product Import**: Import offers from Allegro to PrestaShop with images and descriptions
- 🔄 **Automatic Sync**: Automatic stock and price synchronization every 5 minutes
- 📊 **Category Management**: Sync and manage product categories
- 📈 **Sync Logging**: Track all synchronization activities
- 👥 **User Management**: Admin panel for managing users (admin role only)
- 📄 **CSV Export**: Export categories and products to CSV files
- 🔒 **HTTPS Support**: Secure connections with SSL/TLS certificates

---

## 1. Requirements

- **Node.js**: LTS version (recommended 18 or higher)
  - Download from: [https://nodejs.org](https://nodejs.org)
- **npm**: Comes bundled with Node.js
- **MariaDB/MySQL**: Database server (version 5.7+ or MariaDB 10.3+)
  - The application will automatically create the database and tables on first run

---

## 2. Installation & Setup

### Step 1: Clone or Download the Project

Download or clone this repository to your computer.

### Step 2: Install Dependencies

Open a terminal/PowerShell in the project folder and run:

```bash
npm install
```

This will install all required Node.js packages listed in `package.json`.

### Step 3: Configure Environment Variables

Create a `.env` file in the project root directory (same folder as `server.js`):

```env
# Database Configuration (REQUIRED)
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_database_password
DB_NAME=your_database_name

# Admin User Configuration (REQUIRED)
# These credentials will be used to create the initial admin user
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=your_secure_password

# Server Configuration (OPTIONAL)
PORT=3000                    # HTTP server port (default: 3000)
HTTPS_PORT=3300              # HTTPS server port (default: 3300)
USE_INTERVAL_TIMER=true      # Use internal timer for sync (default: true)
DB_CONNECTION_LIMIT=100      # Database connection pool limit (default: 100)

# Security (OPTIONAL)
JWT_SECRET=                  # Auto-generated if not provided
JWT_EXPIRES_IN=24h           # JWT token expiration (default: 24h)

# SSL Configuration (OPTIONAL - for custom certificate paths)
SSL_KEY_PATH=/path/to/key.pem
SSL_CERT_PATH=/path/to/cert.pem
FORCE_HTTPS=false            # Force HTTPS redirect (default: false)

# OAuth Configuration (OPTIONAL - for Allegro OAuth)
OAUTH_REDIRECT_URI=http://localhost:3000/api/oauth/callback  # Must match Allegro Developer Portal
OAUTH_SCOPE=                  # Optional: OAuth scopes (leave empty to use app defaults)
```

**Important Notes:**
- Replace `your_database_password` with your actual MariaDB/MySQL password
- Replace `your_database_name` with your desired database name
- Replace `admin@example.com` with your admin email address
- Replace `your_secure_password` with a strong password for the admin user
- The database and admin user will be created automatically when you start the server
- If the database already exists, it will be used (not recreated)
- If the admin user already exists, it will not be recreated

**OAuth Redirect URI Configuration:**
- The `OAUTH_REDIRECT_URI` must **exactly match** the redirect URI registered in your Allegro Developer Portal
- If not set, the application will automatically use `http://localhost:3000/api/oauth/callback` (or your server's host/port)
- **For localhost development:** Register `http://localhost:3000/api/oauth/callback` in your Allegro app settings
- **For production:** Set `OAUTH_REDIRECT_URI` to your production URL (e.g., `https://yourdomain.com/api/oauth/callback`)
- If you get a "redirect_uri_mismatch" error, check that the redirect URI in Allegro Developer Portal matches exactly (including http/https, port, and path)

---

## 3. Starting the Server

### Option A: Normal Start (with internal sync timer)

```bash
npm start
```

The server will:
- Start on HTTP port **3000** (or as configured)
- Automatically create the database and tables if they don't exist
- Create the admin user if specified in `.env`
- Enable HTTPS on port **3300** if SSL certificates are found

### Option B: Start without Internal Timer (for cron use)

```bash
USE_INTERVAL_TIMER=false node server.js
```

Use this option if you want to control sync timing via external cron jobs instead of the internal timer.

### Option C: Development Mode (with auto-reload)

```bash
npm run dev
```

Requires `nodemon` to be installed. Automatically restarts the server when files change.

---

## 4. HTTPS Configuration

The server automatically detects SSL certificates and enables HTTPS if available.

### For Development (Windows - Recommended)

**Easy method - Using Node.js (no OpenSSL needed):**
```bash
npm run generate-cert
```

This will automatically generate self-signed certificates in the `ssl/` folder using the `selfsigned` package.

**Alternative - Using OpenSSL (if installed):**
```bash
mkdir ssl
openssl req -x509 -newkey rsa:4096 -keyout ssl/server.key -out ssl/server.crt -days 365 -nodes
```

### For Production (Ubuntu/Linux)

1. **Obtain SSL certificates** (from Let's Encrypt, your hosting provider, etc.)
2. **Place certificates in the `ssl` folder:**
   - `ssl/server.key` - Private key file
   - `ssl/server.crt` - Certificate file

3. **Or set custom paths via environment variables:**
   ```bash
   SSL_KEY_PATH=/path/to/your/key.pem SSL_CERT_PATH=/path/to/your/cert.pem npm start
   ```

4. **Optional: Force HTTPS redirect** (redirects HTTP to HTTPS):
   ```bash
   FORCE_HTTPS=true npm start
   ```

5. **Custom HTTPS port** (default is 3300):
   ```bash
   HTTPS_PORT=443 npm start
   ```

**Note:** If SSL certificates are not found, the server will run in HTTP mode only (development mode).

---

## 5. Using the Application

### Access the Web Interface

1. Open your web browser and navigate to:
   - **HTTP**: `http://localhost:3000`
   - **HTTPS**: `https://localhost:3300` (if SSL is configured)

2. **Login** with the admin credentials you configured in `.env`

### Initial Configuration

1. **Configure Allegro API**:
   - Go to the Configuration panel
   - Enter your Allegro Client ID and Client Secret
   - Click "Connect" to save credentials
   - Click "Authorize Account" to complete OAuth authentication

2. **Configure PrestaShop**:
   - Enter your PrestaShop Base URL (e.g., `https://www.yourstore.com`)
   - Enter your PrestaShop API Key
   - Click "Connect" to test and save the connection

### Features Overview

- **Allegro Offers Tab**: Browse and import products from your Allegro account
- **Imported Products Tab**: View and manage products imported to PrestaShop
- **CSV Export Tab**: Export categories and products to CSV files
- **Sync Stock Log Tab**: Monitor automatic stock and price synchronization
- **User Management Tab**: Manage users (admin only)

### Automatic Stock & Price Sync

The application can automatically sync stock and prices from Allegro to PrestaShop:

- **Internal Timer**: Enabled by default, runs every 5 minutes
- **Manual Trigger**: Use "Run Sync Now" button in the Sync Stock Log tab
- **Start/Stop Timer**: Control the automatic sync timer from the web interface

**Sync Behavior:**
- Only products that exist in PrestaShop are checked and synced
- Stock changes in PrestaShop do not affect Allegro stock (one-way sync)
- Sync logs are available in the Sync Stock Log tab

---

## 6. Automatic Sync with Cron (Linux/Ubuntu)

If you prefer to use system cron instead of the internal timer:

1. **Start the server without internal timer:**
   ```bash
   USE_INTERVAL_TIMER=false node server.js
   ```

2. **Open crontab for editing:**
   ```bash
   crontab -e
   ```

3. **Add cron job** (choose based on your setup):

   **If using HTTP:**
   ```bash
   */5 * * * * curl -X POST http://localhost:3000/api/sync/trigger
   ```

   **If using HTTPS:**
   ```bash
   */5 * * * * curl -k -X POST https://localhost:3300/api/sync/trigger
   ```
   (The `-k` flag skips certificate verification for self-signed certs)

4. **Save and exit:**
   - **nano**: `Ctrl + X`, then `Y`, then `Enter`
   - **vim**: `Esc`, type `:wq`, then `Enter`

5. **Verify the cron job:**
   ```bash
   crontab -l
   ```

The sync will now be triggered automatically every 5 minutes via cron.

---

## 7. API Endpoints

The application provides a RESTful API for programmatic access:

### Authentication
- `POST /api/login` - User login
- `POST /api/logout` - User logout
- `GET /api/auth/validate` - Validate authentication token

### Allegro Integration
- `GET /api/offers` - Get Allegro offers (paginated)
- `GET /api/offers/:offerId` - Get offer details
- `GET /api/products/:productId` - Get product details
- `GET /api/categories` - Get Allegro categories
- `POST /api/credentials` - Save Allegro API credentials
- `GET /api/oauth/authorize` - Initiate OAuth flow
- `GET /api/oauth/callback` - OAuth callback handler

### PrestaShop Integration
- `POST /api/prestashop/configure` - Configure PrestaShop connection
- `GET /api/prestashop/status` - Check PrestaShop connection status
- `POST /api/prestashop/products` - Create product in PrestaShop
- `GET /api/prestashop/categories` - Get PrestaShop categories
- `POST /api/prestashop/sync/stock` - Sync stock
- `POST /api/prestashop/sync/price` - Sync prices

### Sync Management
- `POST /api/sync/trigger` - Trigger manual sync
- `POST /api/sync/start` - Start automatic sync timer
- `POST /api/sync/stop` - Stop automatic sync timer
- `GET /api/sync/status` - Get sync status
- `GET /api/sync/logs` - Get sync logs

### Export
- `GET /api/export/categories.csv` - Export categories as CSV
- `GET /api/export/products.csv` - Export products as CSV

### User Management (Admin Only)
- `GET /api/admin/users` - List all users
- `POST /api/admin/users` - Create new user
- `PUT /api/admin/users/:id` - Update user
- `DELETE /api/admin/users/:id` - Delete user

---

## 8. Database Schema

The application uses MariaDB/MySQL and automatically creates the following tables:

- **users**: User accounts with authentication
- **allegro_credentials**: Allegro API credentials (per user)
- **oauth_tokens**: OAuth tokens for Allegro authentication (per user)
- **prestashop_credentials**: PrestaShop API credentials (per user)
- **product_mappings**: Mapping between Allegro offers and PrestaShop products
- **category_cache**: Cached Allegro category data
- **sync_logs**: Logs of synchronization activities

---

## 9. Troubleshooting

### Database Connection Issues

- Verify MariaDB/MySQL is running
- Check database credentials in `.env`
- Ensure the database user has CREATE DATABASE privileges

### Allegro API Issues

- Verify Client ID and Client Secret are correct
- Complete OAuth authorization flow
- Check that OAuth tokens haven't expired

### PrestaShop API Issues

- Verify PrestaShop URL is accessible
- Check API key permissions in PrestaShop
- Ensure API key has product read/write permissions

### SSL Certificate Issues

- For development, use `npm run generate-cert` to generate self-signed certificates
- For production, ensure certificates are valid and not expired
- Check file permissions on certificate files

---

## 10. Security Notes

- Passwords are hashed using PBKDF2 with SHA-512
- JWT tokens are used for authentication
- Failed login attempts are rate-limited
- Admin-only endpoints are protected
- Database credentials are stored securely per user

---

## 11. Stopping the Server

In the terminal where the server is running, press:

- **Windows/Linux**: `Ctrl + C`
- **Mac**: `Cmd + C`

---

## License

MIT License

---

## Support

For issues or questions, contact: @petrob22 (Telegram)
