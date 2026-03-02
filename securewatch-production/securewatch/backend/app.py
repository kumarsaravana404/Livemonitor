"""
SecureWatch v3.0 — CyberGuard Backend  (PRODUCTION BUILD)
All 16 backend hardening fixes applied.

Run locally : python app.py
Production  : gunicorn -w 1 -b 127.0.0.1:5001 --timeout 120 app:app
              # -w 1 is REQUIRED for SSE broadcast to work across requests
"""

import html
import json
import logging
import os
import random
import re
import signal
import socket
import sqlite3
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from functools import wraps
from logging.handlers import RotatingFileHandler
from typing import Any, Callable

import requests as req

# ── .env loading ──────────────────────────────────────────────────────────────
try:
    import dotenv

    _ = dotenv.load_dotenv()
except ImportError:
    pass  # python-dotenv not installed — env vars must be set manually

from flask import (
    Flask,
    Response,
    jsonify,
    request,
    send_from_directory,
    stream_with_context,
)
from flask_cors import CORS

# ── Environment / Config ──────────────────────────────────────────────────────
# FIX #1: Hard startup error if API key not configured
app_api_key = os.getenv("SECUREWATCH_API_KEY", "")
if not app_api_key or app_api_key == "change-this-key":
    _env = os.getenv("FLASK_ENV", "production")
    if _env != "development":
        sys.exit(
            "\n[FATAL] SECUREWATCH_API_KEY is not set or still uses the default.\n"
            + "Set it in your .env file:  SECUREWATCH_API_KEY=<strong-random-token>\n"
            + 'Generate one: python3 -c "import secrets; print(secrets.token_urlsafe(32))"\n'
        )
    else:
        app_api_key = "dev-insecure-key"  # dev-only fallback

FLASK_PORT = int(os.getenv("FLASK_PORT", "5001"))
MAX_HISTORY = int(os.getenv("MAX_HISTORY", "500"))
GEO_API_URL = os.getenv("GEO_API_URL", "https://ipapi.co/{ip}/json/")
# FIX #9: CORS_ORIGINS configurable via env var
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")
DB_FILE = os.getenv("DB_FILE", "securewatch.db")
SSE_MAX_CLIENTS = 50
GEO_CACHE_TTL = int(os.getenv("GEO_CACHE_TTL", "3600"))  # seconds
GEO_FAIL_TTL = int(os.getenv("GEO_FAIL_TTL", "60"))  # short TTL on failure

# ── Logging (FIX #6: RotatingFileHandler — 10 MB × 5 backups) ────────────────
_log_handler = RotatingFileHandler(
    "securewatch.log", maxBytes=10 * 1024 * 1024, backupCount=5
)
_log_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logging.basicConfig(
    level=logging.INFO, handlers=[_log_handler, logging.StreamHandler()]
)
logger = logging.getLogger("securewatch")

# ── Flask ──────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=".", static_url_path="")
# FIX #10: Limit request body to 64 KB
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
# FIX #9: CORS from env var
_ = CORS(app, resources={r"/api/*": {"origins": CORS_ORIGINS}})

LOCK = threading.Lock()

# ── SSE clients ───────────────────────────────────────────────────────────────
_sse_clients: list[list[str]] = []
_sse_lock = threading.Lock()

# ── Geo-IP cache with TTL (FIX #5) ───────────────────────────────────────────
_geo_cache: dict[str, dict[str, object]] = {}  # ip → {data, expires_at}

# ── Per-IP rate limiter for /api/clear (FIX #8) ──────────────────────────────
_clear_hits: dict[str, list[float]] = defaultdict(list)
_rate_lock = threading.Lock()
RATE_LIMIT = 3  # calls
RATE_WINDOW = 60.0  # seconds


# ── Database — thread-local connections + WAL (FIX #7) ────────────────────────
_thread_local = threading.local()


def get_db() -> sqlite3.Connection:
    conn = getattr(_thread_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        _ = conn.execute("PRAGMA journal_mode=WAL")
        _ = conn.execute("PRAGMA synchronous=NORMAL")
        _thread_local.conn = conn
    return conn


def init_db() -> None:
    with get_db() as conn:
        _ = conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attempts (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ip        TEXT,
                city      TEXT,
                country   TEXT,
                isp       TEXT,
                latitude  REAL,
                longitude REAL,
                region    TEXT,
                timezone  TEXT,
                asn       TEXT,
                os        TEXT,
                browser   TEXT,
                device    TEXT,
                status    TEXT,
                severity  TEXT,
                timestamp TEXT,
                time_str  TEXT
            )
            """
        )
        conn.commit()


# ── Graceful shutdown (FIX #13) ───────────────────────────────────────────────
def _shutdown(signum: int, _frame: object) -> None:
    logger.info("SecureWatch shutting down (signal %d)…", signum)
    conn: sqlite3.Connection | None = getattr(_thread_local, "conn", None)
    if conn:
        try:
            conn.close()
        except Exception:
            pass
    sys.exit(0)


_ = signal.signal(signal.SIGTERM, _shutdown)
try:
    _ = signal.signal(signal.SIGINT, _shutdown)
except OSError:
    pass  # Windows may complain in sub-threads

# ── Input sanitisation ────────────────────────────────────────────────────────
VALID_STATUS = {"FAILED", "BLOCKED", "SUCCESS"}
VALID_SEVERITY = {"low", "medium", "high", "critical"}


def sanitize(val: object, max_len: int = 200) -> str:
    return html.escape(str(val or ""))[:max_len]


# FIX #12: IP validation before geo lookup
_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def validate_ip(ip: str) -> bool:
    m = _IPV4_RE.match(ip)
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


# ── Authentication middleware ──────────────────────────────────────────────────
RouteFunc = Callable[..., Any]


def require_api_key(f: RouteFunc) -> RouteFunc:
    @wraps(f)
    def decorated(*args: object, **kwargs: object) -> Any:
        key = request.headers.get("X-API-Key") or request.args.get("api_key") or ""
        if key != app_api_key:
            # FIX #4: status code set correctly
            return jsonify({"error": "Unauthorized — invalid or missing API key"}), 401
        return f(*args, **kwargs)

    return decorated  # type: ignore[return-value]


# ── Per-IP rate limiter ───────────────────────────────────────────────────────
def _check_rate_limit(ip: str) -> bool:
    """Return True if the IP is within rate limit, False if exceeded."""
    now = time.monotonic()
    with _rate_lock:
        hits = _clear_hits[ip]
        _clear_hits[ip] = [t for t in hits if now - t < RATE_WINDOW]
        if len(_clear_hits[ip]) >= RATE_LIMIT:
            return False
        _clear_hits[ip].append(now)
        return True


# ── Geo-IP lookup with TTL cache (FIX #5) ────────────────────────────────────
def get_geo(ip: str) -> dict[str, str | float]:
    now = time.time()
    cached = _geo_cache.get(ip)
    if cached and now < float(str(cached.get("expires_at", 0))):
        data = cached.get("data")
        if isinstance(data, dict):
            return data  # type: ignore[return-value]

    fallback: dict[str, str | float] = {
        "city": "Unknown",
        "country": "Unknown",
        "isp": "Unknown ISP",
        "latitude": 0.0,
        "longitude": 0.0,
        "region": "",
        "timezone": "",
        "asn": "",
    }

    # FIX #12: validate IP before network call
    if not validate_ip(ip):
        _geo_cache[ip] = {"data": fallback, "expires_at": now + GEO_FAIL_TTL}
        return fallback

    try:
        url = GEO_API_URL.format(ip=ip)
        r = req.get(url, timeout=5)
        if r.status_code == 200:
            raw: Any = r.json()
            d: dict[str, Any] = raw if isinstance(raw, dict) else {}
            result: dict[str, str | float] = {
                "city": str(d.get("city") or "Unknown"),
                "country": str(d.get("country_name") or "Unknown"),
                "isp": str(d.get("org") or "Unknown ISP"),
                "latitude": float(str(d.get("latitude") or 0.0)),
                "longitude": float(str(d.get("longitude") or 0.0)),
                "region": str(d.get("region") or ""),
                "timezone": str(d.get("timezone") or ""),
                "asn": str(d.get("asn") or ""),
            }
            _geo_cache[ip] = {"data": result, "expires_at": now + GEO_CACHE_TTL}
            return result
        _geo_cache[ip] = {"data": fallback, "expires_at": now + GEO_FAIL_TTL}
    except Exception as exc:
        logger.error("Geo lookup failed for %s: %s", ip, exc)
        _geo_cache[ip] = {"data": fallback, "expires_at": now + GEO_FAIL_TTL}

    return fallback


# ── SSE Push (FIX #2: snapshot copy before iterating) ─────────────────────────
def push_event(event_type: str, data: dict[str, object]) -> None:
    payload = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    with _sse_lock:
        # Snapshot to avoid mutation during iteration
        clients_snapshot = list(_sse_clients)
        dead: list[list[str]] = []
        for q in clients_snapshot:
            try:
                q.append(payload)
            except Exception:
                dead.append(q)
        for d in dead:
            if d in _sse_clients:
                _sse_clients.remove(d)
            logger.debug("Removed dead SSE client")


# ── DB pruning helper (FIX #15) ───────────────────────────────────────────────
def _prune_history(conn: sqlite3.Connection) -> None:
    _ = conn.execute(
        "DELETE FROM attempts WHERE id NOT IN "
        + "(SELECT id FROM attempts ORDER BY id DESC LIMIT ?)",
        (MAX_HISTORY,),
    )


# ── Static ────────────────────────────────────────────────────────────────────
@app.route("/")
def index() -> Response:
    return send_from_directory(".", "index.html")


# ── /health (FIX #14) ─────────────────────────────────────────────────────────
@app.route("/health")
def health() -> Any:
    try:
        with get_db() as conn:
            _ = conn.execute("SELECT 1").fetchone()
        return jsonify({"status": "ok", "db": "ok", "sse_clients": len(_sse_clients)})
    except Exception as exc:
        logger.error("Health check failed: %s", exc)
        return jsonify({"status": "error", "detail": str(exc)}), 500


# ── /api/me ───────────────────────────────────────────────────────────────────
@app.route("/api/me")
def api_me() -> Response:
    ip: str = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    if "," in ip:
        ip = ip.split(",")[0].strip()
    if ip in ("127.0.0.1", "::1", ""):
        try:
            ip = req.get("https://api.ipify.org", timeout=3).text.strip()
        except Exception:
            ip = "127.0.0.1"
    geo = get_geo(ip)
    return jsonify({"ip": ip, **geo})


# ── /api/log ──────────────────────────────────────────────────────────────────
@app.route("/api/log", methods=["POST"])
@require_api_key
def api_log() -> Any:
    body: dict[str, Any] = request.get_json(silent=True) or {}
    ip = sanitize(body.get("ip", ""))
    if not ip:
        return jsonify({"error": "ip required"}), 400

    # FIX #12: validate IP
    if not validate_ip(ip):
        return jsonify({"error": "invalid ip address"}), 400

    geo = get_geo(ip)

    # FIX #11: allowlist validation for status and severity
    raw_status = sanitize(body.get("status", "FAILED")).upper()
    raw_severity = sanitize(body.get("severity", "low")).lower()
    status = raw_status if raw_status in VALID_STATUS else "FAILED"
    severity = raw_severity if raw_severity in VALID_SEVERITY else "low"

    entry: dict[str, object] = {
        "ip": ip,
        "city": str(geo.get("city", "Unknown")),
        "country": str(geo.get("country", "Unknown")),
        "isp": str(geo.get("isp", "Unknown ISP")),
        "latitude": float(str(geo.get("latitude", 0.0) or 0.0)),
        "longitude": float(str(geo.get("longitude", 0.0) or 0.0)),
        "region": str(geo.get("region", "")),
        "timezone": str(geo.get("timezone", "")),
        "asn": str(geo.get("asn", "")),
        "os": sanitize(body.get("os", "Unknown OS")),
        "browser": sanitize(body.get("browser", "Unknown Browser")),
        "device": sanitize(body.get("device", "\U0001f5a5 Desktop")),
        "status": status,
        "severity": severity,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "time_str": datetime.now().strftime("%d/%m/%y, %H:%M:%S"),
    }

    with LOCK:
        conn = get_db()
        cur = conn.execute(
            """INSERT INTO attempts
               (ip,city,country,isp,latitude,longitude,region,timezone,asn,
                os,browser,device,status,severity,timestamp,time_str)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                entry["ip"],
                entry["city"],
                entry["country"],
                entry["isp"],
                entry["latitude"],
                entry["longitude"],
                entry["region"],
                entry["timezone"],
                entry["asn"],
                entry["os"],
                entry["browser"],
                entry["device"],
                entry["status"],
                entry["severity"],
                entry["timestamp"],
                entry["time_str"],
            ),
        )
        entry["id"] = cur.lastrowid
        # FIX #15: prune after every INSERT
        _prune_history(conn)
        conn.commit()

    logger.info(
        "Attempt logged — IP: %s | %s, %s | %s",
        ip,
        entry.get("city"),
        entry.get("country"),
        entry.get("severity"),
    )
    push_event("new_attempt", entry)
    return jsonify({"ok": True, "entry": entry})


# ── /api/history ──────────────────────────────────────────────────────────────
@app.route("/api/history")
def api_history() -> Any:
    try:
        limit = min(int(request.args.get("limit", 200)), MAX_HISTORY)
    except ValueError:
        limit = 200
    with LOCK:
        import typing

        rows: typing.Sequence[sqlite3.Row] = (
            get_db()
            .execute("SELECT * FROM attempts ORDER BY id DESC LIMIT ?", (limit,))
            .fetchall()
        )
    return jsonify([dict(r) for r in rows])


# ── /api/stats ────────────────────────────────────────────────────────────────
@app.route("/api/stats")
def api_stats() -> Any:
    with LOCK:
        conn = get_db()
        total: int = int(conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0])
        failed: int = int(
            conn.execute(
                "SELECT COUNT(*) FROM attempts WHERE status='FAILED'"
            ).fetchone()[0]
        )
        blocked: int = int(
            conn.execute(
                "SELECT COUNT(*) FROM attempts WHERE status='BLOCKED'"
            ).fetchone()[0]
        )
        countries: int = int(
            conn.execute("SELECT COUNT(DISTINCT country) FROM attempts").fetchone()[0]
        )
        high_risk: int = int(
            conn.execute(
                "SELECT COUNT(*) FROM attempts WHERE severity IN ('high','critical')"
            ).fetchone()[0]
        )
    return jsonify(
        {
            "total": total,
            "failed": failed,
            "blocked": blocked,
            "countries": countries,
            "high_risk": high_risk,
        }
    )


# ── /api/clear (FIX #8: rate limiting) ───────────────────────────────────────
@app.route("/api/clear", methods=["POST"])
@require_api_key
def api_clear() -> Any:
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    # FIX #8: rate limit — 3 calls per 60 seconds per IP
    if not _check_rate_limit(client_ip):
        return jsonify({"error": "Rate limit exceeded — max 3 clears per 60s"}), 429
    with LOCK:
        conn = get_db()
        _ = conn.execute("DELETE FROM attempts")
        conn.commit()
    logger.warning("History cleared by %s", client_ip)
    push_event("history_cleared", {})
    return jsonify({"ok": True})


# ── /api/stream (SSE — FIX #2 + FIX #3) ─────────────────────────────────────
@app.route("/api/stream")
@require_api_key
def api_stream() -> Any:
    # FIX #3: return 503 when cap is reached instead of silently dropping oldest
    with _sse_lock:
        if len(_sse_clients) >= SSE_MAX_CLIENTS:
            return jsonify({"error": "SSE capacity reached — try again later"}), 503

    client_buf: list[str] = []
    with _sse_lock:
        _sse_clients.append(client_buf)
    logger.debug("SSE client connected. Total: %d", len(_sse_clients))

    def generate():  # type: ignore[return]
        yield "event: connected\ndata: {}\n\n"
        try:
            while True:
                if client_buf:
                    yield client_buf.pop(0)
                else:
                    yield ": heartbeat\n\n"
                time.sleep(1)
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                if client_buf in _sse_clients:
                    _sse_clients.remove(client_buf)
            logger.debug("SSE client disconnected. Total: %d", len(_sse_clients))

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ── /api/scan (FIX #16: marked SIMULATED + real disposable-email check) ───────
EVIL_DOMAINS = [
    "0day-exploits.net",
    "malware-c2.ru",
    "phishkit.shop",
    "darkweb-creds.io",
    "botnet-relay.cn",
    "stresser-api.net",
    "ddos-hire.xyz",
    "credential-dump.tk",
]
VPS_KEYWORDS = [
    "digitalocean",
    "linode",
    "vultr",
    "hetzner",
    "ovh",
    "amazon",
    "google cloud",
    "azure",
    "scaleway",
    "cloudflare",
]
DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "guerrillamail.com",
    "tempmail.com",
    "throwam.com",
    "10minutemail.com",
    "yopmail.com",
    "trashmail.com",
    "sharklasers.com",
    "fakeinbox.com",
    "maildrop.cc",
}


@app.route("/api/scan", methods=["POST"])
def api_scan() -> Any:
    body: dict[str, Any] = request.get_json(silent=True) or {}
    target = sanitize(body.get("target", ""))
    if not target:
        return jsonify({"error": "target required"}), 400

    results: list[dict[str, str]] = []

    def log(msg: str, t: str = "info") -> None:
        results.append({"msg": msg, "type": t})

    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
    target_type = "ip" if is_ip else "email"
    severity = "high" if random.random() < 0.70 else "low"

    # FIX #16: SIMULATED disclaimer
    log("[NOTICE] This scan is SIMULATED for demonstration purposes.", "dim")
    log(f"[*] Initiating deep scan on target: {target}", "info")
    log(f"[*] Target classified as: {target_type.upper()}", "dim")

    if is_ip:
        if not validate_ip(target):
            return jsonify({"error": "invalid ip address"}), 400
        log("[*] Querying live geo-IP database (ipapi.co)…", "info")
        geo = get_geo(target)
        log(f"[+] IP: {target}", "success")
        log(f"    City/Country : {geo['city']}, {geo['country']}", "dim")
        log(f"    ISP / ASN    : {geo['isp']} ({geo['asn']})", "dim")
        log(f"    Region / TZ  : {geo['region']} / {geo['timezone']}", "dim")
        log(f"    Coordinates  : {geo['latitude']}, {geo['longitude']}", "dim")
        isp_lower = str(geo.get("isp", "")).lower()
        if any(k in isp_lower for k in VPS_KEYWORDS):
            log(
                "[!] ISP flagged as cloud/VPS provider — likely proxy or automated attack.",
                "warn",
            )
        try:
            rdns = socket.gethostbyaddr(target)[0]
            log(f"[+] Reverse DNS: {rdns}", "info")
        except Exception:
            log("[-] Reverse DNS lookup failed (no PTR record).", "dim")
    else:
        domain = target.split("@")[-1].lower() if "@" in target else ""
        char_hash = sum(ord(c) for c in target)
        breach_count = (char_hash % 7) + 1
        log(f"[*] Querying breach database for: {target} [SIMULATED]", "info")
        log(
            f"[!] MATCH: Found {breach_count} historic data breach(es) [SIMULATED].",
            "warn",
        )
        # FIX #16: real disposable-email check
        if domain in DISPOSABLE_DOMAINS:
            log(
                f"[!!!] REAL: Domain '{domain}' is a known disposable email provider.",
                "danger",
            )
        elif domain:
            log(
                f"[*] Domain: {domain} — checking abuse reputation [SIMULATED]…", "info"
            )
            if char_hash % 3 == 0:
                log("[!] Domain flagged as high-abuse sender [SIMULATED].", "danger")
            else:
                log(
                    "[+] Domain reputation: CLEAN (no known blacklists) [SIMULATED].",
                    "success",
                )

    hit_domains = random.sample(EVIL_DOMAINS, random.randint(1, 3))
    log(
        f"[*] Cross-referencing against {len(EVIL_DOMAINS)} known malicious domains [SIMULATED]…",
        "info",
    )
    for d in hit_domains:
        log(
            f"[!] MATCH: Target has interaction history with → {d} [SIMULATED]",
            "danger",
        )

    log("[*] Running behavioral risk model [SIMULATED]…", "info")
    if severity == "high":
        log(
            "[!!!] RISK LEVEL: HIGH — automated exploit pattern detected [SIMULATED].",
            "danger",
        )
        log("[!!!] Recommend immediate firewall block + ISP abuse report.", "danger")
    else:
        log(
            "[+] RISK LEVEL: LOW — no active exploit signatures detected [SIMULATED].",
            "success",
        )

    log(f"[*] Scan complete. {len(results)} findings logged.", "success")
    return jsonify(
        {
            "results": results,
            "severity": severity,
            "target": target,
            "target_type": target_type,
            "simulated": True,
        }
    )


# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    logger.info("SecureWatch v3.0 starting on port %d", FLASK_PORT)
    print("\n╔══════════════════════════════════════════════╗")
    print("║  SecureWatch v3.0 — CyberGuard Backend       ║")
    print(f"║  Running at http://localhost:{FLASK_PORT}             ║")
    print("╚══════════════════════════════════════════════╝\n")
    app.run(host="0.0.0.0", port=FLASK_PORT, threaded=True, debug=False)
else:
    # Called by gunicorn — still need DB initialised
    init_db()
    logger.info("SecureWatch v3.0 loaded by gunicorn")
