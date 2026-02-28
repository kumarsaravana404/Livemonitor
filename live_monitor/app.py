from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import re
import socket
import time

app = Flask(__name__, static_folder=".", static_url_path="")
_ = CORS(app)


def get_geo_info(ip: str) -> dict[str, str | float | None]:
    try:
        resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if resp.status_code == 200:
            jn = resp.json()  # type: ignore
            data: dict[str, str | int | float | None] = jn if isinstance(jn, dict) else {}  # type: ignore
            return {
                "city": str(data.get("city") or "Unknown"),
                "country": str(data.get("country_name") or "Unknown"),
                "isp": str(data.get("org") or "Unknown ISP"),
                "latitude": float(data.get("latitude") or 0.0),
                "longitude": float(data.get("longitude") or 0.0),
            }
    except Exception:
        pass
    return {"city": "Localhost", "country": "Loopback", "isp": "Internal"}


@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/<path:path>")
def serve_file(path: str):
    return send_from_directory(".", str(path))


@app.route("/api/me", methods=["GET"])
def api_me():
    # Get public IP address if possible, otherwise use proxy
    ip: str | None = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip and "," in ip:
        ip = ip.split(",")[0].strip()

    # Let's hit ipify if it's localhost
    if ip == "127.0.0.1" or ip == "::1":
        try:
            ip = requests.get("https://api.ipify.org", timeout=3).text
        except:
            pass

    geo: dict[str, str | float | None] = get_geo_info(ip or "")

    return jsonify(
        {"ip": ip, "city": geo["city"], "country": geo["country"], "isp": geo["isp"]}
    )


@app.route("/api/scan", methods=["POST"])
def api_scan():
    jn = request.get_json()  # type: ignore
    data: dict[str, str | int | float | None] = jn if isinstance(jn, dict) else {}  # type: ignore
    target: str = str(data.get("target") or "").strip()

    if not target:
        return jsonify({"error": "Target required"}), 400

    is_ip = re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", target)
    target_type = "IP ADDRESS" if is_ip else "EMAIL ID"

    results: list[dict[str, str]] = []

    def log(msg: str, type: str = "info"):
        results.append({"msg": msg, "type": type})

    log(f"INITIATING DEEP SCAN FOR {target_type} [{target}]...", "info")

    if is_ip:
        log("Fetching geographical and ASN data for IP...", "info")
        geo = get_geo_info(target)
        log(f"ISP: {geo['isp']} | Location: {geo['city']}, {geo['country']}", "dim")

        try:
            hostname = socket.gethostbyaddr(target)[0]
            log(f"Resolved Hostname: {hostname}", "dim")
        except:
            log("No PTR record found (Could not resolve hostname).", "dim")

        # Simulate checking threat intel
        log("Checking against known malicious IP databases (OSINT)...", "info")
        time.sleep(0.5)  # Simulate processing

    else:
        log("Querying Dark Web databases for email leak history...", "info")
        time.sleep(0.5)
        # Mock results based on hash to be consistent
        target_hash = sum(ord(c) for c in target)
        if target_hash % 2 == 0:
            log("Found 2 potential credential dumps from 2023.", "dim")
        else:
            log("No major public data breaches found for this email.", "dim")

    log("EXTRACTING TRAFFIC HISTORY & DOMAIN LOGS...", "info")

    vulnerable_domains = [
        "http://unsecure-portal.local.net",
        "http://legacy-admin.login.internal",
        "http://sql-vulnerable-site.test",
        "http://pwned-forum-db.net",
        "http://open-dir.storage-bucket.com",
        "http://malicious-phishing-trap.ru",
    ]

    import random

    visited_domains = random.sample(vulnerable_domains, random.randint(1, 3))

    log("Scanning for interactions with known vulnerable domains...", "info")

    for domain in visited_domains:
        log(f"[!] MATCH FOUND: Target connected to [{domain}]", "warn")

    is_suspicious = random.random() > 0.3

    log("Analyzing behavioral risk patterns...", "info")

    if is_suspicious:
        log("[CRITICAL] HIGH RISK ALERTS GENERATED!", "danger")
        log(
            "> History indicates exposure to cross-site scripting (XSS) payloads.",
            "danger",
        )
        log(
            "> Target has interacted with blacklisted phishing infrastructure.",
            "danger",
        )
        log(
            "> RECOMMENDATION: Immediate network blacklisting and credential rotation.",
            "danger",
        )
        severity = "high"
    else:
        log("[!] MINOR ALERTS: Connection to unencrypted HTTP nodes detected.", "warn")
        log(
            "[✓] SCAN COMPLETE: No severe malicious payloads found in history.",
            "success",
        )
        severity = "low"

    return jsonify({"results": results, "severity": severity})


if __name__ == "__main__":
    app.run(port=5001, debug=True)
