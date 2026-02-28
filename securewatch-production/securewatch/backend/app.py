"""
SecureWatch — Production Backend
Flask REST API with SQLite (upgradeable to PostgreSQL)
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
import os
import json
import re
from datetime import datetime
from functools import wraps

app = Flask(__name__, static_folder='../frontend/dist', static_url_path='')
_ = CORS(app, origins=["*"])

DB_PATH = os.environ.get('DB_PATH', 'securewatch.db')
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
MAX_ATTEMPTS_BEFORE_BLOCK = int(os.environ.get('MAX_ATTEMPTS', 5))

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            api_key     TEXT UNIQUE NOT NULL,
            created_at  TEXT NOT NULL,
            plan        TEXT DEFAULT 'free'
        );
        CREATE TABLE IF NOT EXISTS monitored_accounts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            email       TEXT NOT NULL,
            label       TEXT,
            created_at  TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS login_attempts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id      INTEGER NOT NULL,
            ip_address      TEXT NOT NULL,
            city            TEXT,
            region          TEXT,
            country         TEXT,
            isp             TEXT,
            device_type     TEXT,
            os_name         TEXT,
            browser         TEXT,
            user_agent      TEXT,
            status          TEXT NOT NULL,
            timestamp       TEXT NOT NULL,
            is_blocked      INTEGER DEFAULT 0,
            FOREIGN KEY(account_id) REFERENCES monitored_accounts(id)
        );
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id  INTEGER NOT NULL,
            ip_address  TEXT NOT NULL,
            reason      TEXT,
            blocked_at  TEXT NOT NULL,
            UNIQUE(account_id, ip_address),
            FOREIGN KEY(account_id) REFERENCES monitored_accounts(id)
        );
        CREATE INDEX IF NOT EXISTS idx_attempts_account ON login_attempts(account_id);
        CREATE INDEX IF NOT EXISTS idx_attempts_ip ON login_attempts(ip_address);
        CREATE INDEX IF NOT EXISTS idx_attempts_ts ON login_attempts(timestamp);
        """)

init_db()

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        token = None
        if auth.startswith('Bearer '):
            token = auth[7:]
        if not token:
            token = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not token:
            return jsonify({'error': 'Unauthorized'}), 401
        with get_db() as db:
            user = db.execute('SELECT * FROM users WHERE api_key=?', (token,)).fetchone()
        if not user:
            return jsonify({'error': 'Invalid token'}), 401
        setattr(request, 'current_user', dict(user)) # type: ignore
        return f(*args, **kwargs)
    return decorated

def parse_user_agent(ua):
    ua = ua or ''
    if 'Windows NT 10.0' in ua or 'Windows NT 11' in ua:
        os_name = 'Windows 10/11'
    elif 'Windows NT 6.1' in ua:
        os_name = 'Windows 7'
    elif 'Mac OS X' in ua:
        os_name = 'macOS'
    elif 'Android' in ua:
        os_name = 'Android'
    elif 'iPhone' in ua or 'iPad' in ua:
        os_name = 'iOS'
    elif 'Linux' in ua:
        os_name = 'Linux'
    else:
        os_name = 'Unknown OS'

    if 'Edg/' in ua:
        browser = 'Edge'
    elif 'Chrome/' in ua:
        browser = 'Chrome'
    elif 'Firefox/' in ua:
        browser = 'Firefox'
    elif 'Safari/' in ua and 'Chrome' not in ua:
        browser = 'Safari'
    elif 'curl' in ua:
        browser = 'curl'
    elif 'python' in ua.lower():
        browser = 'Python Script'
    else:
        browser = 'Unknown'

    if any(x in ua for x in ['Mobile', 'Android', 'iPhone']):
        device_type = 'Mobile'
    elif 'iPad' in ua:
        device_type = 'Tablet'
    elif 'curl' in ua or 'python' in ua.lower():
        device_type = 'Bot/Script'
    else:
        device_type = 'Desktop'

    return os_name, browser, device_type

def get_geo_info(ip):
    try:
        import urllib.request
        with urllib.request.urlopen(f"https://ipapi.co/{ip}/json/", timeout=3) as resp:
            data = json.loads(resp.read())
            return {
                'city':    data.get('city', 'Unknown'),
                'region':  data.get('region', ''),
                'country': data.get('country_name', 'Unknown'),
                'isp':     data.get('org', 'Unknown ISP'),
            }
    except Exception:
        return {'city': 'Unknown', 'region': '', 'country': 'Unknown', 'isp': 'Unknown ISP'}

# ── AUTH ─────────────────────────────────────────────────────────────────────

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({'error': 'Invalid email'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    api_key = 'sw_' + secrets.token_urlsafe(32)
    try:
        with get_db() as db:
            db.execute('INSERT INTO users (email,password,api_key,created_at) VALUES (?,?,?,?)',
                       (email, hash_password(password), api_key, datetime.utcnow().isoformat()))
        return jsonify({'message': 'Account created', 'token': api_key, 'email': email}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already registered'}), 409

@app.route('/api/auth/login', methods=['POST'])
def login_route():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    with get_db() as db:
        user = db.execute('SELECT * FROM users WHERE email=? AND password=?',
                          (email, hash_password(password))).fetchone()
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    u = dict(user)
    return jsonify({'token': u['api_key'], 'email': email, 'user_id': u['id']})

@app.route('/api/auth/me', methods=['GET'])
@require_auth
def me():
    u = request.current_user
    with get_db() as db:
        accounts = db.execute('SELECT COUNT(*) as c FROM monitored_accounts WHERE user_id=?', (u['id'],)).fetchone()['c']
        attempts = db.execute('SELECT COUNT(*) as c FROM login_attempts la JOIN monitored_accounts ma ON la.account_id=ma.id WHERE ma.user_id=?', (u['id'],)).fetchone()['c']
    return jsonify({'email': u['email'], 'api_key': u['api_key'], 'plan': u['plan'],
                    'accounts_count': accounts, 'total_attempts': attempts, 'created_at': u['created_at']})

# ── ACCOUNTS ─────────────────────────────────────────────────────────────────

@app.route('/api/accounts', methods=['GET'])
@require_auth
def list_accounts():
    with get_db() as db:
        rows = db.execute('SELECT * FROM monitored_accounts WHERE user_id=?', (request.current_user['id'],)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/accounts', methods=['POST'])
@require_auth
def add_account():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip()
    label = data.get('label', email)
    if not email:
        return jsonify({'error': 'Email required'}), 400
    with get_db() as db:
        cur = db.execute('INSERT INTO monitored_accounts (user_id,email,label,created_at) VALUES (?,?,?,?)',
                         (request.current_user['id'], email, label, datetime.utcnow().isoformat()))
        aid = cur.lastrowid
    snippet = _make_snippet(aid, request.current_user['api_key'])
    return jsonify({'id': aid, 'email': email, 'label': label, 'snippet': snippet}), 201

@app.route('/api/accounts/<int:aid>', methods=['DELETE'])
@require_auth
def delete_account(aid):
    with get_db() as db:
        db.execute('DELETE FROM monitored_accounts WHERE id=? AND user_id=?', (aid, request.current_user['id']))
    return jsonify({'message': 'Removed'})

# ── TRACKING ─────────────────────────────────────────────────────────────────

@app.route('/api/track', methods=['POST', 'OPTIONS'])
def track():
    if request.method == 'OPTIONS':
        r = jsonify({})
        r.headers['Access-Control-Allow-Origin'] = '*'
        r.headers['Access-Control-Allow-Headers'] = 'Content-Type,X-API-Key'
        return r, 200

    key = request.headers.get('X-API-Key') or request.args.get('api_key')
    if not key:
        return jsonify({'error': 'API key required'}), 401
    with get_db() as db:
        user = db.execute('SELECT * FROM users WHERE api_key=?', (key,)).fetchone()
    if not user:
        return jsonify({'error': 'Invalid API key'}), 401

    data = request.get_json() or {}
    account_id = data.get('account_id')
    status = data.get('status', 'FAILED')
    ua = data.get('user_agent') or request.headers.get('User-Agent', '')

    with get_db() as db:
        account = db.execute('SELECT * FROM monitored_accounts WHERE id=? AND user_id=?',
                             (account_id, dict(user)['id'])).fetchone()
    if not account:
        return jsonify({'error': 'Account not found'}), 404

    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()

    with get_db() as db:
        blocked = db.execute('SELECT id FROM blocked_ips WHERE account_id=? AND ip_address=?', (account_id, ip)).fetchone()
    if blocked:
        status = 'BLOCKED'

    os_name, browser, device_type = parse_user_agent(ua)
    geo = get_geo_info(ip)
    ts = datetime.utcnow().isoformat()

    with get_db() as db:
        db.execute("""INSERT INTO login_attempts
            (account_id,ip_address,city,region,country,isp,device_type,os_name,browser,user_agent,status,timestamp,is_blocked)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (account_id, ip, geo['city'], geo['region'], geo['country'],
             geo['isp'], device_type, os_name, browser, ua, status, ts,
             1 if status == 'BLOCKED' else 0))

        recent = db.execute("""SELECT COUNT(*) as c FROM login_attempts
            WHERE account_id=? AND ip_address=? AND status='FAILED'
            AND timestamp > datetime('now','-1 hour')""", (account_id, ip)).fetchone()['c']

        if recent >= MAX_ATTEMPTS_BEFORE_BLOCK and not blocked:
            try:
                db.execute('INSERT OR IGNORE INTO blocked_ips (account_id,ip_address,reason,blocked_at) VALUES (?,?,?,?)',
                           (account_id, ip, f'Auto-blocked after {MAX_ATTEMPTS_BEFORE_BLOCK} failed attempts', ts))
            except Exception:
                pass

    return jsonify({'logged': True, 'ip': ip, 'location': f"{geo['city']}, {geo['country']}", 'blocked': status == 'BLOCKED'})

# ── DASHBOARD DATA ────────────────────────────────────────────────────────────

@app.route('/api/attempts', methods=['GET'])
@require_auth
def get_attempts():
    uid = request.current_user['id']
    account_id = request.args.get('account_id')
    limit = min(int(request.args.get('limit', 100)), 500)
    with get_db() as db:
        if account_id:
            rows = db.execute("""SELECT la.*,ma.email as account_email FROM login_attempts la
                JOIN monitored_accounts ma ON la.account_id=ma.id
                WHERE ma.user_id=? AND la.account_id=? ORDER BY la.timestamp DESC LIMIT ?""",
                (uid, account_id, limit)).fetchall()
        else:
            rows = db.execute("""SELECT la.*,ma.email as account_email FROM login_attempts la
                JOIN monitored_accounts ma ON la.account_id=ma.id
                WHERE ma.user_id=? ORDER BY la.timestamp DESC LIMIT ?""",
                (uid, limit)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/stats', methods=['GET'])
@require_auth
def get_stats():
    uid = getattr(request, 'current_user', {}).get('id') # type: ignore
    with get_db() as db:
        def q(sql, *a): return db.execute(sql, a).fetchone()['c']
        base = "FROM login_attempts la JOIN monitored_accounts ma ON la.account_id=ma.id WHERE ma.user_id=?"
        total     = q(f"SELECT COUNT(*) as c {base}", uid)
        failed    = q(f"SELECT COUNT(*) as c {base} AND la.status='FAILED'", uid)
        blocked   = q("SELECT COUNT(*) as c FROM blocked_ips bi JOIN monitored_accounts ma ON bi.account_id=ma.id WHERE ma.user_id=?", uid)
        countries = q(f"SELECT COUNT(DISTINCT country) as c {base}", uid)
        today     = q(f"SELECT COUNT(*) as c {base} AND la.timestamp > datetime('now','-24 hours')", uid)
        top_ips   = db.execute(f"""SELECT ip_address,COUNT(*) as hits,country,city {base}
            GROUP BY ip_address ORDER BY hits DESC LIMIT 5""", (uid,)).fetchall()
        by_country = db.execute(f"""SELECT country,COUNT(*) as hits {base}
            GROUP BY country ORDER BY hits DESC LIMIT 8""", (uid,)).fetchall()
    return jsonify({
        'total': total, 'failed': failed, 'blocked': blocked,
        'countries': countries, 'today': today,
        'top_ips': [dict(r) for r in top_ips],
        'by_country': [dict(r) for r in by_country],
    })

# ── BLOCKED IPs ───────────────────────────────────────────────────────────────

@app.route('/api/blocked', methods=['GET'])
@require_auth
def list_blocked():
    uid = request.current_user['id']
    with get_db() as db:
        rows = db.execute("""SELECT bi.* FROM blocked_ips bi
            JOIN monitored_accounts ma ON bi.account_id=ma.id
            WHERE ma.user_id=? ORDER BY bi.blocked_at DESC""", (uid,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/blocked', methods=['POST'])
@require_auth
def block_ip():
    data = request.get_json() or {}
    ip = (data.get('ip_address') or '').strip()
    account_id = data.get('account_id')
    reason = data.get('reason', 'Manual block')
    if not ip or not account_id:
        return jsonify({'error': 'ip_address and account_id required'}), 400
    with get_db() as db:
        db.execute('INSERT OR IGNORE INTO blocked_ips (account_id,ip_address,reason,blocked_at) VALUES (?,?,?,?)',
                   (account_id, ip, reason, datetime.utcnow().isoformat()))
    return jsonify({'message': f'IP {ip} blocked'}), 201

@app.route('/api/blocked/<int:bid>', methods=['DELETE'])
@require_auth
def unblock_ip(bid):
    uid = request.current_user['id']
    with get_db() as db:
        db.execute("""DELETE FROM blocked_ips WHERE id=? AND account_id IN
            (SELECT id FROM monitored_accounts WHERE user_id=?)""", (bid, uid))
    return jsonify({'message': 'Unblocked'})

# ── REPORTS ───────────────────────────────────────────────────────────────────

@app.route('/api/report/<int:attempt_id>', methods=['GET'])
@require_auth
def get_report(attempt_id):
    uid = request.current_user['id']
    with get_db() as db:
        attempt = db.execute("""SELECT la.*,ma.email as account_email FROM login_attempts la
            JOIN monitored_accounts ma ON la.account_id=ma.id WHERE la.id=? AND ma.user_id=?""",
            (attempt_id, uid)).fetchone()
        if not attempt:
            return jsonify({'error': 'Not found'}), 404
        related = db.execute("""SELECT timestamp,status FROM login_attempts
            WHERE account_id=? AND ip_address=? ORDER BY timestamp DESC LIMIT 20""",
            (dict(attempt)['account_id'], dict(attempt)['ip_address'])).fetchall()
    return jsonify({
        'attempt': dict(attempt),
        'related_attempts': [dict(r) for r in related],
        'report_id': f"SW-{attempt_id:06d}",
        'generated_at': datetime.utcnow().isoformat(),
        'legal_refs': {
            'India': 'IT Act 2000 §66 — Unauthorized Computer Access',
            'International': 'Budapest Convention on Cybercrime, Article 2',
            'Complaint_Portal': 'cybercrime.gov.in',
        }
    })

# ── SNIPPET ───────────────────────────────────────────────────────────────────

def _make_snippet(account_id, api_key):
    base = os.environ.get('BASE_URL', 'https://your-domain.com')
    return f"""<!-- SecureWatch Snippet | Place before </body> on your login page -->
<script>
(function(){{
  window.SecureWatch = {{
    track: function(status) {{
      fetch('{base}/api/track', {{
        method:'POST',
        headers:{{'Content-Type':'application/json','X-API-Key':'{api_key}'}},
        body: JSON.stringify({{account_id:{account_id},status:status,user_agent:navigator.userAgent}})
      }}).catch(function(){{}});
    }}
  }};
}})();
</script>
<!-- Usage: SecureWatch.track('FAILED') or SecureWatch.track('SUCCESS') -->"""

@app.route('/api/snippet/<int:aid>', methods=['GET'])
@require_auth
def get_snippet(aid):
    with get_db() as db:
        a = db.execute('SELECT * FROM monitored_accounts WHERE id=? AND user_id=?',
                       (aid, request.current_user['id'])).fetchone()
    if not a:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'snippet': _make_snippet(aid, request.current_user['api_key'])})

# ── SERVE FRONTEND ────────────────────────────────────────────────────────────

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    dist = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'dist')
    fp = os.path.join(dist, path)
    if path and os.path.exists(fp):
        return send_from_directory(dist, path)
    idx = os.path.join(dist, 'index.html')
    if os.path.exists(idx):
        return send_from_directory(dist, 'index.html')
    return jsonify({'service': 'SecureWatch API', 'version': '1.0.0'}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 SecureWatch backend running on http://0.0.0.0:{port}")
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_ENV') == 'development')
