Hi qlwik2 Im petro.

As i said, I want to work with you on outside from Freelancer.

Because freelancer withdraw term and fee is not good for me.

Please contact me via Telegram @petro2.

Telegram is real time chatting and easy to send necessary data.

Thx.

# Allegro PrestaShop Sync Data

## Quick Ubuntu Setup

### 1. Start Server

Start the server with the interval timer disabled:

```bash
USE_INTERVAL_TIMER=false node server.js
```

### 2. Setup Cron Job

To automatically trigger the sync every 5 minutes using cron:

1. Open your crontab for editing:
   ```bash
   crontab -e
   ```

2. If prompted, choose your preferred editor (nano is recommended for beginners)

3. Add the following line to the file:
   ```
   */5 * * * * curl -X POST http://localhost:3000/api/sync/trigger
   ```

4. Save and exit:
   - If using **nano**: Press `Ctrl+X`, then `Y`, then `Enter`
   - If using **vim**: Press `Esc`, type `:wq`, then `Enter`

5. Verify the crontab was added:
   ```bash
   crontab -l
   ```

The cron job will now run every 5 minutes automatically.

### 3. Done

Your sync will now be triggered automatically every 5 minutes via cron.
