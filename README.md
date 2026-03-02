# SecureWatch v3.0 — Production Deployment Guide

Real-time unauthorized login detection and threat monitoring dashboard powered by CyberGuard Engine v3.0.

---

## Project Structure

```
securewatch/
├── backend/
│   ├── app.py              # Flask backend (production-hardened)
│   ├── requirements.txt    # Python dependencies
│   └── .env.example        # Environment variable template
├── frontend/
│   ├── index.html          # Main dashboard
│   ├── script.js           # Frontend controller (all bugs fixed)
│   └── style.css           # Cyberpunk UI styles
└── deployment/
    ├── Dockerfile          # Multi-stage Docker image
    ├── docker-compose.yml  # Local production testing
    ├── ci-cd.yml           # GitHub Actions → AWS ECS pipeline
    └── nginx.conf          # Nginx reverse proxy config
```

---

## Bugs Fixed & Improvements Made

### Backend (`app.py`)
| # | Issue | Fix |
|---|-------|-----|
| 1 | `SECUREWATCH_API_KEY` defaulted to `"change-this-key"` — ships to prod insecurely | Hard startup error if env var not set |
| 2 | SSE client list mutated during iteration → race condition / IndexError | Snapshot copy before iterating |
| 3 | SSE cap silently dropped oldest client instead of rejecting | Returns HTTP 503 when cap reached |
| 4 | `require_api_key` returned wrong type on 401 (status set on wrong object) | Fixed status code assignment |
| 5 | Geo-IP cache had no TTL → stale data forever, unbounded memory | Added per-entry TTL with short failure TTL |
| 6 | `logging.basicConfig` with plain file — no rotation | `RotatingFileHandler` (10 MB × 5 backups) |
| 7 | `get_db()` created a new SQLite connection on every call | Thread-local connections + WAL mode |
| 8 | `/api/clear` had no rate limiting → trivial DoS | Per-IP rate limiter (3 calls/60 s) |
| 9 | CORS wildcard hardcoded — not configurable | `CORS_ORIGINS` env var |
| 10 | No request body size limit | `MAX_CONTENT_LENGTH` = 64 KB |
| 11 | `status` and `severity` fields not validated on `/api/log` | Allowlist validation |
| 12 | IP not validated before geo lookup | `validate_ip()` with IPv4 octet range check |
| 13 | No graceful shutdown → dirty DB state on SIGTERM | `signal.signal(SIGTERM/SIGINT, _shutdown)` |
| 14 | No `/health` endpoint for load balancers | Added `/health` with DB ping |
| 15 | `MAX_HISTORY` env var read but never enforced in DB | Prune query after every INSERT |
| 16 | `/api/scan` used `random` for breach results with no disclaimer | Marked as SIMULATED; added real disposable-email check |

### Frontend (`script.js`)
| # | Issue | Fix |
|---|-------|-----|
| 1 | `currentAlert` was never defined in module scope → `blockCurrentAlert()` threw ReferenceError | Module-level `let currentAlert = null` |
| 2 | SSE had no reconnection logic → silent failure on disconnect | Exponential backoff retry (max 10 attempts, 30 s cap) |
| 3 | `clearLog()` called API but never cleared `attempts[]` array → stale UI | Cleared in-memory array + re-rendered table |
| 4 | `simulateBurst()` called `simulateAttack()` 5× synchronously → server spike | 600 ms stagger between each call |
| 5 | `exportAll()` used `document.write()` → destroyed the page | Blob + `URL.createObjectURL` download |
| 6 | `copyReport()` used deprecated `execCommand` only | Clipboard API with `execCommand` fallback |
| 7 | `runDeepScan()` had no loading/disabled state → double-click fired parallel requests | Debounce + `scanRunning` guard + button disabled |
| 8 | Map dots accumulated forever → DOM bloat | Capped at 20 dots; oldest removed |
| 9 | Toasts were appended but never removed → DOM leak | Auto-removed after fade-out |
| 10 | `clockInterval` never cleared → interval leak on SPA navigation | Stored ref + cleared on `beforeunload` |
| 11 | `changeEmail()` accepted empty string / non-email input | Validated before saving |
| 12 | No XSS protection on rendered attempt data from server | All values passed through `esc()` (HTML escape) |
| 13 | Stats only fetched on page load, not after SSE events | `refreshStats()` called on every `new_attempt` event |
| 14 | `blockIP()` rendered items using `.innerHTML = ip` directly | All values escaped through `esc()` |
| 15 | No API key sent to SSE endpoint → 401 on authenticated backends | `api_key` query param appended to SSE URL |

---

## Quick Start (Local)

```bash
# 1. Clone and enter the project
git clone https://github.com/kumarsaravana404/Livemonitor.git
cd Livemonitor

# 2. Set up Python environment
cd backend
python3 -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env → set SECUREWATCH_API_KEY to a strong secret key

# 4. Run
python app.py
# → Open http://localhost:5001
```

---

## Docker Deployment (Recommended)

```bash
# Build and run with Docker Compose
cd deployment
cp ../backend/.env.example .env
# Edit .env — set SECUREWATCH_API_KEY

docker compose up -d

# View logs
docker compose logs -f

# Stop
docker compose down
```

---

## Cloud Deployment: AWS ECS (Fargate)

### Prerequisites
- AWS account with ECS, ECR, and IAM configured
- GitHub repository secrets: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- ECS Cluster, Service, and Task Definition already created

### Steps

1. **Create ECR repository:**
   ```bash
   aws ecr create-repository --repository-name securewatch --region us-east-1
   ```

2. **Push initial image:**
   ```bash
   aws ecr get-login-password --region us-east-1 | \
     docker login --username AWS --password-stdin <your-account-id>.dkr.ecr.us-east-1.amazonaws.com

   docker build -f deployment/Dockerfile -t securewatch .
   docker tag securewatch:latest <your-account-id>.dkr.ecr.us-east-1.amazonaws.com/securewatch:latest
   docker push <your-account-id>.dkr.ecr.us-east-1.amazonaws.com/securewatch:latest
   ```

3. **Set GitHub secrets:**
   - `AWS_ACCESS_KEY_ID`
   - `AWS_SECRET_ACCESS_KEY`

4. **Update `ci-cd.yml`** with your ECR repo, ECS cluster, and service names.

5. **Copy CI/CD pipeline to your repo:**
   ```bash
   mkdir -p .github/workflows
   cp deployment/ci-cd.yml .github/workflows/deploy.yml
   ```

6. **Push to `main`** → GitHub Actions automatically builds, tests, and deploys.

### ECS Task Definition Environment Variables

In your ECS task definition, add these environment variables (use AWS Secrets Manager for sensitive values):

| Variable | Value |
|---|---|
| `SECUREWATCH_API_KEY` | From Secrets Manager |
| `FLASK_PORT` | `5001` |
| `CORS_ORIGINS` | `https://your-domain.com` |
| `MAX_HISTORY` | `500` |

---

## HTTPS Setup with Nginx + Certbot (VPS)

```bash
# Install
sudo apt install nginx certbot python3-certbot-nginx -y

# Copy config
sudo cp deployment/nginx.conf /etc/nginx/sites-available/securewatch
sudo ln -s /etc/nginx/sites-available/securewatch /etc/nginx/sites-enabled/

# Edit domain name
sudo sed -i 's/your-domain.com/youractual.domain.com/g' /etc/nginx/sites-available/securewatch

# Get TLS certificate
sudo certbot --nginx -d youractual.domain.com

# Reload
sudo systemctl reload nginx
```

---

## Security Checklist for Production

- [ ] `SECUREWATCH_API_KEY` set to a random 32-byte token (`python3 -c "import secrets; print(secrets.token_urlsafe(32))"`)
- [ ] `CORS_ORIGINS` set to your exact frontend domain (not `*`)
- [ ] HTTPS enabled (Certbot / ACM / Cloudflare)
- [ ] `.env` file not committed to version control
- [ ] SQLite data directory mounted as a persistent volume
- [ ] Firewall: only ports 80, 443 open publicly; 5001 internal only
- [ ] Log rotation configured (handled automatically by `RotatingFileHandler`)
- [ ] Health check endpoint responding at `/health`

---

## API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET`  | `/`         | —   | Frontend dashboard |
| `GET`  | `/health`   | —   | Health check (for load balancers) |
| `GET`  | `/api/me`   | —   | Caller's IP + geo info |
| `GET`  | `/api/history?limit=N` | — | Recent attempt log |
| `GET`  | `/api/stats` | —  | Aggregate statistics |
| `POST` | `/api/log`  | ✅  | Log a new login attempt |
| `POST` | `/api/clear`| ✅  | Clear all history |
| `GET`  | `/api/stream`| ✅ | SSE event stream |
| `POST` | `/api/scan` | —   | OSINT deep scan |

**Authenticated routes** require `X-API-Key: <your-key>` header or `?api_key=<your-key>` query param.

---

## License

MIT — see LICENSE file.
