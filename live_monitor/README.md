# SecureWatch v3.0 — CyberGuard Engine

![Status](https://img.shields.io/badge/Status-Production_Ready-success)
![Version](https://img.shields.io/badge/Version-3.0-blue)
![Backend](https://img.shields.io/badge/Backend-Python_Flask-yellow)
![DB](https://img.shields.io/badge/Storage-SQLite-orange)
![SSE](https://img.shields.io/badge/Realtime-SSE-cyan)

SecureWatch is a **full-stack, production-hardened unauthorized login detection and threat monitoring dashboard**. It acts as a real-time SIEM (Security Information and Event Management) system — capturing login telemetry, enriching it with live geo-IP intelligence, persisting data in SQLite, and broadcasting live events to all connected clients via Server-Sent Events (SSE).

---

## 🚀 Feature List

| Feature                       | Details                                                                       |
| ----------------------------- | ----------------------------------------------------------------------------- |
| **Real-Time SSE Streaming**   | Zero-latency event push via Server-Sent Events — no polling required          |
| **Persistent SQLite Storage** | All attempts stored in `securewatch.db` — survives server restarts            |
| **Live Geo-IP Intelligence**  | Per-IP lookup via `ipapi.co` — city, country, ISP, ASN, coordinates           |
| **Geo-IP Caching**            | Each unique IP is only looked up once per session — prevents rate limits      |
| **API Key Authentication**    | All write endpoints protected by `X-API-Key` header or `api_key` query param  |
| **Deep Scan Engine**          | OSINT trace — VPS detection, reverse DNS, breach database check, risk scoring |
| **Forensic Evidence Reports** | 6-section cyber complaint report with legal guidance (IT Act 2000 §66)        |
| **Input Sanitisation**        | All user-supplied fields sanitised with `html.escape()` before storage        |
| **SSE Client Cap**            | Maximum 50 concurrent SSE connections to prevent memory exhaustion            |
| **Structured Logging**        | All events written to `securewatch.log` with timestamps                       |
| **Gunicorn + nginx Ready**    | Production deploy with single-worker gunicorn and SSE-compatible nginx config |
| **HTTPS via certbot**         | One-command Let's Encrypt TLS setup included in `deploy.sh`                   |

---

## ⚙️ Local Setup

```bash
# 1. Clone the repository
git clone https://github.com/kumarsaravana404/Livemonitor.git
cd Livemonitor

# 2. Create and activate a virtual environment (recommended)
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment variables
cp .env.example .env
# Edit .env with your own SECUREWATCH_API_KEY

# 5. Start the backend
python app.py
# Open http://localhost:5001 in your browser
```

> On first load, the browser will prompt you for the API key (same value as `SECUREWATCH_API_KEY` in your `.env`).

---

## 🔐 API Endpoints

| Endpoint       | Method | Auth Required | Description                              |
| -------------- | ------ | ------------- | ---------------------------------------- |
| `/api/me`      | GET    | No            | Returns client's public IP + geo data    |
| `/api/history` | GET    | No            | Returns recent attempts (newest first)   |
| `/api/stats`   | GET    | No            | Aggregated counts from SQLite            |
| `/api/log`     | POST   | ✅ Yes        | Log a new attempt (enriched with geo-IP) |
| `/api/clear`   | POST   | ✅ Yes        | Delete all history from database         |
| `/api/stream`  | GET    | ✅ Yes        | SSE stream for real-time updates         |
| `/api/scan`    | POST   | No            | OSINT deep scan for IP or email          |

**Authentication:** Send `X-API-Key: your-key` header or `?api_key=your-key` query param on protected endpoints.

---

## 🏭 Production Deployment (VPS / Linux)

### Prerequisites

- Ubuntu 22.04+ VPS
- Domain name pointing to your VPS IP
- Python 3.10+, nginx, certbot

### Step-by-Step

```bash
# On your VPS:
git clone https://github.com/kumarsaravana404/Livemonitor.git /var/www/securewatch
cd /var/www/securewatch

# Configure environment
cp .env.example .env
nano .env   # Set SECUREWATCH_API_KEY to a strong random string

# One-command deploy (installs gunicorn, nginx, systemd service, HTTPS)
DOMAIN=yourdomain.com EMAIL=you@email.com bash deploy.sh
```

### Manual Gunicorn Command

```bash
# Single worker is REQUIRED for SSE broadcast to work
gunicorn -w 1 -b 127.0.0.1:5001 --timeout 120 app:app
```

### Test the Deployment

```bash
# SSE stream should respond with heartbeat pings
curl -N -H "X-API-Key: your-key" http://yourdomain.com/api/stream

# Clear endpoint should return 401 without key
curl -X POST http://yourdomain.com/api/clear
# Expected: {"error": "Unauthorized — invalid or missing API key"}
```

---

## 📁 Project Structure

```
Livemonitor/
├── app.py              # Flask backend — all API endpoints
├── index.html          # Dashboard HTML
├── script.js           # Frontend logic — SSE, table, scan, reports
├── style.css           # Cyberpunk dark theme
├── requirements.txt    # Python dependencies
├── .env.example        # Environment template (copy to .env)
├── .gitignore          # Excludes .env, *.db, *.log
├── nginx.conf          # nginx reverse proxy config (SSE-ready)
├── securewatch.service # systemd unit for auto-restart
├── deploy.sh           # One-command production deploy script
└── README.md           # This file
```

---

## ⚠️ Important Notes

- **SSE requires single-worker gunicorn** (`-w 1`). Multiple workers break real-time broadcasting because each worker has its own `_sse_clients` list.
- **Never commit `.env`** — it contains your API key. It is listed in `.gitignore`.
- The `securewatch.db` SQLite file and `securewatch.log` are also gitignored.
- For high-traffic production, consider switching to Redis pub/sub for multi-worker SSE broadcasting.

---

## 📄 Legal

Built for **simulated security analytics and educational purposes**. The threat evaluation structures and OSINT mechanisms mirror enterprise SIEM systems. Do not use as a replacement for production WAFs or Edge security without proper hardening.
