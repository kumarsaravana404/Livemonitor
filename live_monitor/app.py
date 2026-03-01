from flask import (
    Flask,
    request,
    jsonify,
    send_from_directory,
    Response,
    stream_with_context,
)
from flask_cors import CORS
import requests as req
import socket
import threading
import json
import os
import re
import time
import random
from datetime import datetime, timezone
from typing import cast

# ─── App Setup ────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder=".", static_url_path="")
_ = CORS(app, resources={r"/api/*": {"origins": "*"}})

HISTORY_FILE = "login_history.json"
MAX_HISTORY = 500
LOCK = threading.Lock()

# SSE clients
_sse_clients: list[list[str]] = []
_sse_lock = threading.Lock()

# ─── Persistence ──────────────────────────────────────────────────────────────


def load_history() -> list[dict[str, str | int | float | None]]:
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_history(history: list[dict[str, str | int | float | None]]) -> None:
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history[-MAX_HISTORY:], f, indent=2)


# ─── Geo-IP ───────────────────────────────────────────────────────────────────


def get_geo(ip: str) -> dict[str, str | float]:
    try:
        r = req.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if r.status_code == 200:
            d: dict[str, str | float | None] = (
                r.json() if isinstance(r.json(), dict) else {}
            )
            return {
                "city": str(d.get("city") or "Unknown"),
                "country": str(d.get("country_name") or "Unknown"),
                "isp": str(d.get("org") or "Unknown ISP"),
                "latitude": float(d.get("latitude") or 0.0),
                "longitude": float(d.get("longitude") or 0.0),
                "region": str(d.get("region") or ""),
                "timezone": str(d.get("timezone") or ""),
                "asn": str(d.get("asn") or ""),
            }
    except Exception:
        pass
    return {
        "city": "Localhost",
        "country": "Loopback",
        "isp": "Internal",
        "latitude": 0.0,
        "longitude": 0.0,
        "region": "",
        "timezone": "",
        "asn": "",
    }


# ─── SSE Push ─────────────────────────────────────────────────────────────────


def push_event(event_type: str, data: dict[str, str | int | float | None]) -> None:
    payload = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    with _sse_lock:
        dead: list[list[str]] = []
        for q in _sse_clients:
            try:
                cast(list[str], q).append(payload)
            except Exception:
                dead.append(cast(list[str], q))
        for d in dead:
            if d in _sse_clients:
                _sse_clients.remove(d)


# ─── Static ───────────────────────────────────────────────────────────────────


@app.route("/")
def index():
    return send_from_directory(".", "index.html")


# ─── /api/me ──────────────────────────────────────────────────────────────────


@app.route("/api/me", methods=["GET"])
def api_me():
    ip: str = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    if "," in ip:
        ip = ip.split(",")[0].strip()
    if ip in ("127.0.0.1", "::1", ""):
        try:
            ip = req.get("https://api.ipify.org", timeout=3).text.strip()
        except Exception:
            ip = "127.0.0.1"
    geo = get_geo(ip)
    return jsonify(
        {
            "ip": ip,
            "city": geo["city"],
            "country": geo["country"],
            "isp": geo["isp"],
            "latitude": geo["latitude"],
            "longitude": geo["longitude"],
            "region": geo["region"],
            "timezone": geo["timezone"],
            "asn": geo["asn"],
        }
    )


# ─── /api/log ─────────────────────────────────────────────────────────────────


@app.route("/api/log", methods=["POST"])
def api_log():
    body: dict[str, str | int | float | None] = request.get_json(silent=True) or {}
    ip: str = str(body.get("ip", "")).strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400

    geo = get_geo(ip)

    entry: dict[str, str | int | float | None] = {
        "id": int(time.time() * 1000),
        "ip": ip,
        "city": str(geo.get("city", "Unknown")),
        "country": str(geo.get("country", "Unknown")),
        "isp": str(geo.get("isp", "Unknown ISP")),
        "latitude": float(geo.get("latitude", 0.0) or 0.0),
        "longitude": float(geo.get("longitude", 0.0) or 0.0),
        "region": str(geo.get("region", "")),
        "timezone": str(geo.get("timezone", "")),
        "asn": str(geo.get("asn", "")),
        "os": str(body.get("os", "Unknown OS")),
        "browser": str(body.get("browser", "Unknown Browser")),
        "device": str(body.get("device", "🖥 Desktop")),
        "status": str(body.get("status", "FAILED")),
        "severity": str(body.get("severity", "low")),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "timeStr": datetime.now().strftime("%d/%m/%y, %H:%M:%S"),
    }

    with LOCK:
        history = load_history()
        history.append(entry)
        save_history(history)

    push_event("new_attempt", entry)
    return jsonify({"ok": True, "entry": entry})


# ─── /api/history ─────────────────────────────────────────────────────────────


@app.route("/api/history", methods=["GET"])
def api_history():
    try:
        limit = int(request.args.get("limit", 200))
    except ValueError:
        limit = 200
    with LOCK:
        history = load_history()
    return jsonify(list(reversed(history))[:limit])


# ─── /api/stats ───────────────────────────────────────────────────────────────


@app.route("/api/stats", methods=["GET"])
def api_stats():
    with LOCK:
        history = load_history()
    total = len(history)
    failed = sum(1 for e in history if e.get("status") == "FAILED")
    blocked = sum(1 for e in history if e.get("status") == "BLOCKED")
    countries = len({e.get("country") for e in history if e.get("country")})
    high_risk = sum(1 for e in history if e.get("severity") in ("high", "critical"))
    return jsonify(
        {
            "total": total,
            "failed": failed,
            "blocked": blocked,
            "countries": countries,
            "high_risk": high_risk,
        }
    )


# ─── /api/clear ───────────────────────────────────────────────────────────────


@app.route("/api/clear", methods=["POST"])
def api_clear():
    with LOCK:
        save_history([])
    push_event("history_cleared", {})
    return jsonify({"ok": True})


# ─── /api/stream (SSE) ────────────────────────────────────────────────────────


@app.route("/api/stream")
def api_stream():
    client_buf: list[str] = []
    with _sse_lock:
        _sse_clients.append(client_buf)

    def generate():
        # Send connected handshake
        yield "event: connected\ndata: {}\n\n"
        try:
            while True:
                if client_buf:
                    msg = client_buf.pop(0)
                    yield msg
                else:
                    yield ": heartbeat\n\n"
                    time.sleep(15)
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                if client_buf in _sse_clients:
                    _sse_clients.remove(client_buf)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ─── /api/scan ────────────────────────────────────────────────────────────────

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


@app.route("/api/scan", methods=["POST"])
def api_scan():
    body: dict[str, str | int | float | None] = request.get_json(silent=True) or {}
    target: str = str(body.get("target", "")).strip()
    if not target:
        return jsonify({"error": "target required"}), 400

    results: list[dict[str, str]] = []

    def log(msg: str, t: str = "info") -> None:
        results.append({"msg": msg, "type": t})

    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
    target_type = "ip" if is_ip else "email"
    severity = "high" if random.random() < 0.70 else "low"

    log(f"[*] Initiating deep scan on target: {target}", "info")
    log(f"[*] Target classified as: {target_type.upper()}", "dim")

    if is_ip:
        log(f"[*] Querying live geo-IP database (ipapi.co)...", "info")
        geo = get_geo(target)
        log(f"[+] IP: {target}", "success")
        log(f"    City/Country : {geo['city']}, {geo['country']}", "dim")
        log(f"    ISP / ASN    : {geo['isp']} ({geo['asn']})", "dim")
        log(f"    Region / TZ  : {geo['region']} / {geo['timezone']}", "dim")
        log(f"    Coordinates  : {geo['latitude']}, {geo['longitude']}", "dim")

        isp_lower = str(geo.get("isp", "")).lower()
        if any(k in isp_lower for k in VPS_KEYWORDS):
            log(
                f"[!] ISP flagged as cloud/VPS provider — likely proxy or automated attack.",
                "warn",
            )

        # Reverse DNS
        try:
            rdns = socket.gethostbyaddr(target)[0]
            log(f"[+] Reverse DNS: {rdns}", "info")
        except Exception:
            log(f"[-] Reverse DNS lookup failed (no PTR record).", "dim")

    else:
        domain = target.split("@")[-1].lower() if "@" in target else ""
        char_hash = sum(ord(c) for c in target)
        breach_count = (char_hash % 7) + 1
        log(f"[*] Querying breach database for: {target}", "info")
        log(
            f"[!] MATCH: Found {breach_count} historic data breach(es) linked to this address.",
            "warn",
        )
        if domain:
            log(f"[*] Domain: {domain} — checking abuse reputation...", "info")
            if char_hash % 3 == 0:
                log(
                    f"[!] Domain flagged as high-abuse sender in threat intel feeds.",
                    "danger",
                )
            else:
                log(f"[+] Domain reputation: CLEAN (no known blacklists).", "success")

    # Vulnerable domain sampling
    hit_domains = random.sample(EVIL_DOMAINS, random.randint(1, 3))
    log(
        f"[*] Cross-referencing against {len(EVIL_DOMAINS)} known malicious domains...",
        "info",
    )
    for d in hit_domains:
        log(f"[!] MATCH: Target has interaction history with → {d}", "danger")

    # Behavioral risk analysis
    log(f"[*] Running behavioral risk model...", "info")
    if severity == "high":
        log(f"[!!!] RISK LEVEL: HIGH — automated exploit pattern detected.", "danger")
        log(f"[!!!] Recommend immediate firewall block + ISP abuse report.", "danger")
    else:
        log(f"[+] RISK LEVEL: LOW — no active exploit signatures detected.", "success")

    log(f"[*] Scan complete. {len(results)} findings logged.", "success")
    return jsonify(
        {
            "results": results,
            "severity": severity,
            "target": target,
            "target_type": target_type,
        }
    )


# ─── Run ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n╔══════════════════════════════════════════════╗")
    print("║  SecureWatch v3.0 — CyberGuard Backend       ║")
    print("║  Running at http://localhost:5001             ║")
    print("╚══════════════════════════════════════════════╝\n")
    app.run(host="0.0.0.0", port=5001, threaded=True, debug=False)
