# SecureWatch v3.0 — CyberGuard Engine

![SecureWatch Dashboard](https://img.shields.io/badge/Status-Active-success) ![Version](https://img.shields.io/badge/Version-3.0-blue) ![Python](https://img.shields.io/badge/Backend-Python_Flask-yellow) ![JS](https://img.shields.io/badge/Frontend-Vanilla_JS-orange)

SecureWatch is an advanced, full-stack cybersecurity dashboard designed to monitor, log, and analyze unauthorized access attempts in real-time. Acting as a live SIEM (Security Information and Event Management) interface, it captures telemetry data via REST APIs, evaluates threats, and broadcasts live events dynamically using Server-Sent Events (SSE).

## 🚀 Features

- **Real-Time Telemetry Tracking**: Instant monitoring of login attempts with an active stream pushed to the frontend via SSE.
- **Live Attack Geo-Mapping**: Visually tracks the origin of attack vectors on a world map using public IP OSINT data.
- **Deep Scan Engine**: Allows manual OSINT investigation of suspicious IP addresses or email identifiers to check against known threats, malicious ASNs, and proxy/VPS providers (DigitalOcean, Vultr, etc.).
- **Automated Threat Evaluation**: Ranks attempt severity (Low, Medium, High, Critical) and provides firewall-level mock blocking mechanisms.
- **Data Persistence**: Full session history safely tracked and re-loaded seamlessly via local JSON states across server reboots.
- **Forensic Reports**: Generate structured cyber complaint evidence reports that can be printed or exported as PDFs.

## 🛠 Technology Stack

- **Frontend**: HTML5, Vanilla JavaScript, CSS3 (Modern, animated grid interface).
- **Backend**: Python 3.10+, Flask, Flask-CORS.
- **Data Transport**: RESTful JSON APIs (`/api/log`, `/api/scan`, `/api/stats`) and Server-Sent Events (SSE) for zero-latency DOM updates (`/api/stream`).

## ⚙️ Installation & Setup

1.  **Clone the Repository**

    ```bash
    git clone https://github.com/kumarsaravana404/Livemonitor.git
    cd Livemonitor
    ```

2.  **Install Python Dependencies**
    Ensure you have Python installed, then install Flask and other network requirements.

    ```bash
    pip install -r requirements.txt
    ```

    _(If `requirements.txt` is missing, manually install: `pip install flask flask-cors requests`)_

3.  **Boot the CyberGuard Engine (Backend)**

    ```bash
    python app.py
    ```

    The engine will start running on `http://localhost:5001`.

4.  **Launch the Dashboard**
    Simply double-click `index.html` in your file explorer, or serve it using any local development server (e.g., Live Server extension in VSCode).

## 📡 API Endpoints

- `GET /api/me`: Resolves the client's public internet IP.
- `GET /api/stats`: Fetches total telemetry aggregates (blocks, fails, risk loads).
- `GET /api/history`: Returns up to 500 recent login/attack attempts.
- `POST /api/log`: Triggers a new login attempt, generates OSINT data, and fires SSE pushes across active monitoring clients.
- `POST /api/scan`: Deep-scan an IP or Email for trace history and botnet heuristics.
- `POST /api/clear`: Flushes the history cache entirely.
- `GET /api/stream`: Subscribes the client to an open EventSource for real-time pushing.

## 🔒 Disclaimer

This tool is created for **Simulated Security Analytics & Educational Purposes**. While the threat evaluation structures, IP trace mechanisms, and web socket handling resemble enterprise SIEM systems, do not use it as a blanket firewall replacement in production environments without deploying standard WAFs or Edge protections natively.
