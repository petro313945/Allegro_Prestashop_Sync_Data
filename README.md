Hi qlkub K, Im petro.
My telegram address is @petrob22


## Allegro PrestaShop Sync Data

Simple guide to run this tool on your own computer.

---

## 1. Requirements

- **Node.js**: Install the LTS version (recommended 18+).  
  - Download from: `https://nodejs.org`
- **npm**: Comes together with Node.js.

---

## 2. First Setup (one time)

1. **Download or copy the project folder** to your computer.
2. Open a **terminal / PowerShell** in the project folder  
   (the folder that contains `package.json` and `server.js`).
3. Install all Node modules:

   ```bash
   npm install
   ```

   This will create the `node_modules` folder automatically.

4. **Create a `.env` file** in the project root directory (same folder as `server.js`):
   
   Create a file named `.env` with the following content:
   
   ```env
   # Database Configuration
   DB_HOST=localhost
   DB_PORT=3306
   DB_USER=root
   DB_PASSWORD=your_database_password
   DB_NAME=your_database_name
   
   # Admin User Configuration
   # These credentials will be used to create the initial admin user
   ADMIN_EMAIL=admin@example.com
   ADMIN_PASSWORD=your_secure_password
   ```
   
   **Important Notes:**
   - Replace `your_database_password` with your actual MariaDB/MySQL password
   - Replace `your_database_name` with your desired database name
   - Replace `admin@example.com` with your admin email address
   - Replace `your_secure_password` with a strong password for the admin user
   - The database and admin user will be created automatically when you start the server
   - If the database already exists, it will be used (not recreated)
   - If the admin user already exists, it will not be recreated
   
   **Optional environment variables:**
   ```env
   PORT=3000                    # HTTP server port (default: 3000)
   HTTPS_PORT=3300              # HTTPS server port (default: 3300)
   USE_INTERVAL_TIMER=true      # Use internal timer for sync (default: true)
   ```

---

## 3. Start the Server

### Option A – Normal start (default)

```bash
npm start
```

The server will start on port **3000** (or as configured in the code).

### Option B – Start without internal timer (for cron use)

```bash
USE_INTERVAL_TIMER=false node server.js
```

---

## 3.5. HTTPS Configuration (for Production / Ubuntu)

The server automatically detects SSL certificates and enables HTTPS if available.

### For Development (Windows - Recommended)

**Easy method - Using Node.js (no OpenSSL needed):**
```bash
npm run generate-cert
```
This will automatically generate self-signed certificates in the `ssl/` folder.

**Alternative - Using OpenSSL (if installed):**
```bash
mkdir ssl
openssl req -x509 -newkey rsa:4096 -keyout ssl/server.key -out ssl/server.crt -days 365 -nodes
```

### For Production (Ubuntu)

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

**Note:** If SSL certificates are not found, the server will run in HTTP mode (development mode).

---

## 4. Automatic Sync with Cron (Ubuntu / Linux)

If you want the sync to run automatically every 5 minutes:

1. Open crontab for editing:

   ```bash
   crontab -e
   ```

2. If asked, choose an editor (for beginners, **nano** is easiest).

3. Add this line at the end of the file:

   **If using HTTP:**
   ```bash
   */5 * * * * curl -X POST http://localhost:3000/api/sync/trigger
   ```

   **If using HTTPS:**
   ```bash
   */5 * * * * curl -k -X POST https://localhost:3300/api/sync/trigger
   ```
   (The `-k` flag skips certificate verification for self-signed certs)

4. Save and exit:
   - **nano**: `Ctrl + X`, then `Y`, then `Enter`
   - **vim**: `Esc`, type `:wq`, then `Enter`

5. Check that the cron job was added:

   ```bash
   crontab -l
   ```

Now the sync will be triggered automatically every 5 minutes.

---

## 5. Stop the Server

In the terminal where the server is running, press:

- `Ctrl + C`
