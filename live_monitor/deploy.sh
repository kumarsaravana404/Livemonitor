#!/bin/bash
# SecureWatch v3.0 — One-command production deploy script
# Usage: DOMAIN=yourdomain.com EMAIL=you@email.com bash deploy.sh
set -e

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   SecureWatch v3.0 — Production Deploy       ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# 1. Install Python dependencies
echo "[1/5] Installing Python dependencies..."
pip install -r requirements.txt

# 2. Copy .env if not exists
if [ ! -f ".env" ]; then
  echo "[2/5] Creating .env from .env.example..."
  cp .env.example .env
  echo "      ⚠  Edit .env and set SECUREWATCH_API_KEY before continuing!"
  exit 1
else
  echo "[2/5] .env already exists — skipping."
fi

# 3. Install systemd service
echo "[3/5] Installing systemd service..."
sudo mkdir -p /var/log/securewatch
sudo cp securewatch.service /etc/systemd/system/securewatch.service
sudo systemctl daemon-reload
sudo systemctl enable securewatch
sudo systemctl restart securewatch
echo "      ✓ Service started"

# 4. Install nginx config
echo "[4/5] Installing nginx config..."
sudo apt-get install -y nginx 2>/dev/null || true
sudo cp nginx.conf /etc/nginx/sites-available/securewatch
sudo ln -sf /etc/nginx/sites-available/securewatch /etc/nginx/sites-enabled/securewatch
sudo nginx -t && sudo systemctl reload nginx
echo "      ✓ nginx configured"

# 5. HTTPS via certbot
if [ -n "$DOMAIN" ] && [ -n "$EMAIL" ]; then
  echo "[5/5] Requesting Let's Encrypt certificate for $DOMAIN..."
  sudo apt-get install -y certbot python3-certbot-nginx 2>/dev/null || true
  sudo certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL"
  echo "      ✓ HTTPS enabled"
else
  echo "[5/5] Skipping HTTPS — set DOMAIN and EMAIL env vars to enable certbot."
fi

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   Deploy Complete! 🎉                        ║"
echo "║                                              ║"
echo "║   Test SSE  : curl -N http://localhost/api/stream"
echo "║   Test auth : curl -X POST http://localhost/api/clear"
echo "║               (should return 401)            ║"
echo "╚══════════════════════════════════════════════╝"
