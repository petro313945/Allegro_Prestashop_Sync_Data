#!/bin/bash
# Stock Sync Script for Ubuntu Cron
# This script is called by cron every 5 minutes to sync stock from Allegro to PrestaShop

# Configuration
SERVER_URL="http://localhost:3000"
ENDPOINT="/api/sync/trigger"

# Make HTTP POST request to trigger sync
curl -X POST "${SERVER_URL}${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -s -o /dev/null \
  -w "Sync triggered at $(date): HTTP %{http_code}\n"

# Exit with success
exit 0
