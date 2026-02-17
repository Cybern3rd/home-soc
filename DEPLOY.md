# Home SOC - Deployment Guide

## Quick Deploy to VPS (10 minutes)

### Prerequisites
- VPS running (Hetzner: 178.156.230.195)
- Node.js installed
- Port 3000 open (or use nginx proxy)

### 1. Clone/Copy to VPS

```bash
ssh clawduser@178.156.230.195 -p 2222

# Create directory
mkdir -p ~/home-soc
cd ~/home-soc

# Copy files from local development (or git clone)
```

### 2. Install Dependencies

```bash
# No external dependencies needed - uses Node.js built-ins
# Just verify Node.js is installed
node --version  # Should be >= v18
```

### 3. Configure (Optional - for enhanced features)

Create `.env` file:

```bash
# Optional: Add these API keys for more threat sources
ABUSEIPDB_API_KEY=your_key_here
GREYNOISE_API_KEY=your_key_here
DISCORD_WEBHOOK_URL=your_webhook_url_here
```

### 4. Test Threat Aggregator

```bash
node src/threat-aggregator.js
```

You should see:
```
✅ Ransomware.live: 100 items
✅ URLhaus: X items
✅ ThreatFox: X items
```

### 5. Start Dashboard Server

```bash
# Test run
node server.js

# Should see:
# 🛡️  Home SOC Dashboard running on http://localhost:3000
```

Visit `http://178.156.230.195:3000` to verify dashboard loads.

### 6. Set Up as SystemD Service (Production)

Create `/etc/systemd/system/home-soc.service`:

```ini
[Unit]
Description=Home SOC Threat Intelligence Dashboard
After=network.target

[Service]
Type=simple
User=clawduser
WorkingDirectory=/home/clawduser/home-soc
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=10
Environment=NODE_ENV=production
Environment=PORT=3000

# Logging
StandardOutput=append:/home/clawduser/home-soc/logs/dashboard.log
StandardError=append:/home/clawduser/home-soc/logs/dashboard-error.log

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable home-soc
sudo systemctl start home-soc
sudo systemctl status home-soc
```

### 7. Set Up Cron for Data Collection

```bash
crontab -e
```

Add this line (runs every 5 minutes):

```cron
*/5 * * * * cd /home/clawduser/home-soc && /usr/bin/node src/threat-aggregator.js >> logs/aggregator.log 2>&1
```

### 8. Configure Nginx Reverse Proxy (Optional)

If you want to serve on port 80/443 with SSL:

```nginx
server {
    listen 80;
    server_name soc.yourdomain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

Then get SSL cert:
```bash
sudo certbot --nginx -d soc.yourdomain.com
```

## Done!

Your Home SOC dashboard is now running at:
- Direct: http://178.156.230.195:3000
- Proxied: https://soc.yourdomain.com

## Monitoring

### View Logs

```bash
# Dashboard logs
sudo journalctl -u home-soc -f

# Aggregator logs
tail -f ~/home-soc/logs/aggregator.log
```

### Check Service Status

```bash
sudo systemctl status home-soc
```

### View Latest Threat Data

```bash
cat ~/home-soc/data/threat-cache.json | jq '.summary'
```

## Adding More Threat Sources

### 1. GreyNoise (IP Reputation)

Sign up: https://www.greynoise.io/viz/signup

Add key to `.env`:
```
GREYNOISE_API_KEY=your_key_here
```

The aggregator will automatically use it.

### 2. AbuseIPDB (IP Abuse)

Sign up: https://www.abuseipdb.com/register

Add key to `.env`:
```
ABUSEIPDB_API_KEY=your_key_here
```

### 3. Discord Alerts

Create webhook in Discord server settings.

Add to `.env`:
```
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

Modify `src/threat-aggregator.js` to send alerts on high-severity threats.

## Troubleshooting

**Dashboard not loading:**
- Check service is running: `sudo systemctl status home-soc`
- Check port 3000 is open: `sudo netstat -tlnp | grep 3000`
- Check logs: `sudo journalctl -u home-soc -n 50`

**No threat data showing:**
- Run aggregator manually: `node src/threat-aggregator.js`
- Check if `data/threat-cache.json` exists
- Verify APIs are responding (check aggregator logs)

**High CPU usage:**
- Reduce cron frequency (run every 15 min instead of 5)
- Add rate limiting in aggregator code
- Check for infinite loops in aggregator logs

## Next Steps

1. Add Discord webhook notifications for critical threats
2. Integrate GreyNoise and AbuseIPDB (sign up for keys)
3. Add geolocation mapping for attack sources
4. Build trend analysis (threats over time charts)
5. Add email alerting (using AgentMail API)
6. Expand to monitor specific IPs/domains (watchlist)

## Security Notes

- Dashboard has no authentication (run behind VPN or add basic auth via nginx)
- API keys stored in `.env` (make sure it's not committed to git)
- Consider IP whitelisting in nginx if exposing publicly
- Regularly update Node.js and dependencies
