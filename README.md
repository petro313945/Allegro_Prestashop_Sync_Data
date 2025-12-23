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

## 4. Automatic Sync with Cron (Ubuntu / Linux)

If you want the sync to run automatically every 5 minutes:

1. Open crontab for editing:

   ```bash
   crontab -e
   ```

2. If asked, choose an editor (for beginners, **nano** is easiest).

3. Add this line at the end of the file:

   ```bash
   */5 * * * * curl -X POST http://localhost:3000/api/sync/trigger
   ```

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
