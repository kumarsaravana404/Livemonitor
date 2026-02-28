# 🛡️ SecureWatch — Unauthorized Login Detection System

A production-ready web service that monitors your accounts for unauthorized login attempts, captures attacker IP addresses, locations, ISPs, and device info — and generates evidence reports for filing cybercrime complaints.

---

## ✨ Features

- **Real-time login attempt monitoring** with live dashboard
- **Attacker IP capture** with geolocation (city, country, ISP)
- **Device fingerprinting** (OS, browser, device type)
- **Auto-block IPs** after configurable failed attempt threshold
- **Evidence PDF reports** ready to submit to cybercrime authorities
- **Multi-account support** — monitor multiple email accounts
- **Simple JS snippet** — integrate into any website in minutes
- **REST API** — connect from any platform

---

## 🚀 Deployment Options

### Option 1: Railway (Easiest — Free tier available)
1. Fork or upload this project to GitHub
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
3. Set environment variables (see below)
4. Railway auto-detects Python and deploys

### Option 2: Render (Free tier available)
1. Push code to GitHub
2. Go to [render.com](https://render.com) → New Web Service
3. Connect your repo, set build command: `pip install -r backend/requirements.txt`
4. Start command: `cd backend && gunicorn wsgi:app`

### Option 3: Docker (Any VPS)
```bash
git clone your-repo
cd securewatch
docker-compose up -d
```

### Option 4: Manual VPS (Ubuntu/Debian)
```bash
# Install dependencies
sudo apt update && sudo apt install python3-pip nginx certbot -y
pip3 install -r backend/requirements.txt

# Run with gunicorn
cd backend
gunicorn --bind 0.0.0.0:8000 --workers 4 wsgi:app &

# Setup nginx
sudo cp nginx/securewatch.conf /etc/nginx/sites-available/securewatch
sudo ln -s /etc/nginx/sites-available/securewatch /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# SSL certificate (replace your-domain.com)
sudo certbot --nginx -d your-domain.com
```

---

## ⚙️ Environment Variables

| Variable | Description | Default |
|---|---|---|
| `PORT` | Server port | `8000` |
| `SECRET_KEY` | Random secret (CHANGE THIS!) | auto-generated |
| `DB_PATH` | SQLite database path | `securewatch.db` |
| `MAX_ATTEMPTS` | Failed attempts before auto-block | `5` |
| `BASE_URL` | Your deployed domain | `http://localhost:5000` |
| `FLASK_ENV` | `development` or `production` | `production` |

---

## 🔌 Integration Guide

### Step 1: Register & Add Account
1. Open your SecureWatch URL
2. Create an account
3. Go to **Accounts** tab → Add your email to monitor

### Step 2: Add Snippet to Your Login Page
Go to **Integrate** tab → Select your account → Copy snippet → Paste before `</body>` on your login page.

### Step 3: Call the Tracker
```javascript
// When login FAILS:
SecureWatch.track('FAILED');

// When login SUCCEEDS:
SecureWatch.track('SUCCESS');
```

### Example: Express.js backend
```javascript
app.post('/login', async (req, res) => {
  const user = await findUser(req.body.email, req.body.password);
  if (!user) {
    // Log to SecureWatch
    await fetch('https://your-securewatch.com/api/track', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': 'YOUR_KEY' },
      body: JSON.stringify({ account_id: 1, status: 'FAILED', user_agent: req.headers['user-agent'] })
    });
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  // ...
});
```

---

## 📋 Filing a Cybercrime Complaint

When SecureWatch detects an unauthorized attempt:

1. Go to Dashboard → Click on the IP address → **Generate Report**
2. The report contains:
   - Attacker IP address
   - ISP / Network provider
   - Location
   - Device fingerprint
   - Exact timestamp
3. Submit to:
   - **India:** [cybercrime.gov.in](https://cybercrime.gov.in)
   - **International:** Your local police cybercrime unit
   - **Legal basis (India):** IT Act 2000, Section 66

Law enforcement contacts the ISP with the IP + timestamp. ISPs are legally required to disclose subscriber identity.

---

## 🔒 Security Notes

- Change `SECRET_KEY` before deploying
- Use HTTPS in production (free via Let's Encrypt)
- Back up the `securewatch.db` file regularly
- Consider upgrading to PostgreSQL for high traffic

---

## 📁 Project Structure

```
securewatch/
├── backend/
│   ├── app.py          # Flask API (all routes)
│   ├── wsgi.py         # Gunicorn entry point
│   └── requirements.txt
├── frontend/
│   └── dist/
│       └── index.html  # Complete single-file frontend
├── nginx/
│   └── securewatch.conf # Nginx reverse proxy config
├── Dockerfile
├── docker-compose.yml
└── README.md
```
