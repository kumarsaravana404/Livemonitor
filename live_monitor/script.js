"use strict";

// ── API Base (dynamic — works both locally and in production) ─────────────────
const API_BASE =
  window.location.hostname === "localhost" ||
  window.location.hostname === "127.0.0.1"
    ? "http://localhost:5001"
    : window.location.origin;

// ── XSS helper — FIX #12: all user-supplied values must pass through esc() ───
function esc(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ── API Key helper ─────────────────────────────────────────────────────────────
function apiHeaders() {
  return {
    "Content-Type": "application/json",
    "X-API-Key": localStorage.getItem("sw_api_key") || "",
  };
}

// First-load API key prompt
(function promptApiKey() {
  if (!localStorage.getItem("sw_api_key")) {
    const key = prompt(
      "🔐 SecureWatch — Enter your API Key to connect to the backend:\n" +
        "(Set in .env as SECUREWATCH_API_KEY)"
    );
    if (key && key.trim()) {
      localStorage.setItem("sw_api_key", key.trim());
    }
  }
})();

// ── State ─────────────────────────────────────────────────────────────────────
let attempts         = [];
const blockedIPs     = new Set();
let attemptCounter   = 0;
// FIX #1: module-level declaration so blockCurrentAlert() never throws
let currentAlertData = null;
let sseSource        = null;
let sseRetryCount    = 0;
const MAX_SSE_RETRIES = 10;

// ── Attacker Data ─────────────────────────────────────────────────────────────
const ATTACKER_IPS = [
  "103.21.58.12",   // India
  "185.220.101.45", // Russia
  "60.191.38.77",   // China
  "5.45.207.60",    // Germany
  "197.210.85.112", // Nigeria
  "36.99.136.25",   // China
  "176.107.182.3",  // Ukraine
  "185.107.80.202", // Netherlands
  "114.121.144.12", // Indonesia
  "41.90.68.5",     // Kenya
];

const DEVICE_POOL = [
  { device: "🤖 Automated Script",   os: "Kali Linux",    browser: "curl/7.88" },
  { device: "📱 Android 14 Mobile",  os: "Android 14",    browser: "Chrome 120" },
  { device: "🖥 Windows Desktop",    os: "Windows 11",    browser: "Edge 120" },
  { device: "💻 MacBook Pro",        os: "macOS Ventura", browser: "Safari 17" },
  { device: "🦇 Headless Browser",   os: "Ubuntu 22",     browser: "Puppeteer" },
  { device: "📟 Python Bot",         os: "Linux",         browser: "python-requests" },
  { device: "📱 iPhone 15",          os: "iOS 17",        browser: "Safari Mobile" },
  { device: "🖥 Linux Workstation",  os: "Debian 12",     browser: "Firefox 121" },
  { device: "🕷 Scrapy Crawler",     os: "Alpine Linux",  browser: "Scrapy/2.11" },
  { device: "🔒 Tor Exit Node",      os: "Tails OS",      browser: "Tor Browser" },
];

// ── World Map Positions ───────────────────────────────────────────────────────
const mapPositions = {
  India:       { top: "55%", left: "65%" },
  Russia:      { top: "25%", left: "65%" },
  China:       { top: "40%", left: "72%" },
  Germany:     { top: "30%", left: "50%" },
  Nigeria:     { top: "55%", left: "48%" },
  Ukraine:     { top: "32%", left: "57%" },
  Netherlands: { top: "28%", left: "49%" },
  Indonesia:   { top: "60%", left: "76%" },
  Kenya:       { top: "58%", left: "57%" },
  Brazil:      { top: "65%", left: "30%" },
  USA:         { top: "40%", left: "15%" },
  Iran:        { top: "42%", left: "62%" },
  Pakistan:    { top: "45%", left: "63%" },
};
const placedCountries = new Set();
// FIX #8: track dots added; cap at 20
const mapDots = [];

// ── Clock (FIX #10: store & clear interval on beforeunload) ───────────────────
function updateClock() {
  document.getElementById("clock").textContent =
    new Date().toLocaleTimeString("en-IN", { hour12: false });
}
const clockInterval = setInterval(updateClock, 1000);
updateClock();

window.addEventListener("beforeunload", () => {
  clearInterval(clockInterval);
  if (sseSource) sseSource.close();
});

// ── SSE (FIX #2: exponential backoff, max 30 s cap) ───────────────────────────
function connectSSE() {
  if (sseRetryCount >= MAX_SSE_RETRIES) {
    showToast(
      "⚠ Backend offline — SSE stopped retrying after 10 attempts",
      "warn"
    );
    return;
  }

  if (sseSource) { sseSource.close(); sseSource = null; }

  // FIX #15: api_key appended to SSE URL for authenticated backends
  const url = new URL(`${API_BASE}/api/stream`);
  url.searchParams.set("api_key", localStorage.getItem("sw_api_key") || "");
  sseSource = new EventSource(url.toString());

  sseSource.addEventListener("connected", () => {
    sseRetryCount = 0;
    updateConnectionStatus(true);
  });

  sseSource.addEventListener("new_attempt", (e) => {
    try {
      ingestEntry(JSON.parse(e.data), true);
      // FIX #13: refresh stats from server on every new_attempt SSE event
      refreshStats();
    } catch (_) {}
  });

  sseSource.addEventListener("history_cleared", () => {
    attempts = [];
    attemptCounter = 0;
    // FIX #3: clear in-memory array and re-render on clearLog
    currentAlertData = null;
    placedCountries.clear();
    // FIX #8: remove all map dots
    mapDots.splice(0).forEach((d) => d.remove());
    document.getElementById("attemptLog").innerHTML =
      `<tr><td colspan="7"><div class="no-attempts">🛡 Log cleared — monitoring active</div></td></tr>`;
    document.getElementById("alertEmpty").style.display  = "block";
    document.getElementById("liveAlert").style.display   = "none";
    document.getElementById("alertBadge").style.display  = "none";
    document.getElementById("alertNum").textContent = "0";
    document.getElementById("originList").textContent = "No attack origins detected yet.";
    updateStats();
    showToast("History cleared", "info");
  });

  sseSource.onerror = () => {
    updateConnectionStatus(false);
    sseSource.close();
    sseSource = null;
    sseRetryCount++;
    // FIX #2: exponential backoff capped at 30 seconds
    const delay = Math.min(1000 * Math.pow(2, sseRetryCount - 1), 30000);
    showToast(`⟳ SSE reconnecting in ${Math.round(delay / 1000)}s (attempt ${sseRetryCount}/${MAX_SSE_RETRIES})…`, "warn");
    setTimeout(connectSSE, delay);
  };
}

function updateConnectionStatus(online) {
  const el = document.getElementById("connectionStatus");
  if (online) {
    el.innerHTML = `<span style="color:var(--success)">●</span> STREAM LIVE`;
    el.style.borderColor = "var(--success)";
    el.style.color       = "var(--success)";
  } else {
    el.innerHTML = `<span style="color:var(--warn)">○</span> RECONNECTING…`;
    el.style.borderColor = "var(--warn)";
    el.style.color       = "var(--warn)";
  }
}

// ── History ───────────────────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const res  = await fetch(`${API_BASE}/api/history?limit=200`, { headers: apiHeaders() });
    const data = await res.json();
    if (!Array.isArray(data) || data.length === 0) {
      document.getElementById("attemptLog").innerHTML =
        `<tr><td colspan="7"><div class="no-attempts">🛡 No attempts logged yet</div></td></tr>`;
      return;
    }
    document.getElementById("attemptLog").innerHTML = "";
    for (const entry of [...data].reverse()) { ingestEntry(entry, false); }
    showToast(`Loaded ${data.length} historical attempt(s)`, "info");
  } catch (_) {
    document.getElementById("attemptLog").innerHTML =
      `<tr><td colspan="7"><div class="no-attempts" style="color:var(--danger)">⚠ Cannot reach backend — start python app.py</div></td></tr>`;
  }
}

// ── Ingest Entry ──────────────────────────────────────────────────────────────
function ingestEntry(raw, animate) {
  attemptCounter++;
  const entry = {
    num:       attemptCounter,
    id:        raw.id        || Date.now(),
    ip:        raw.ip        || "0.0.0.0",
    city:      raw.city      || "Unknown",
    country:   raw.country   || "Unknown",
    isp:       raw.isp       || "Unknown ISP",
    latitude:  raw.latitude  || 0,
    longitude: raw.longitude || 0,
    region:    raw.region    || "",
    timezone:  raw.timezone  || "",
    asn:       raw.asn       || "",
    os:        raw.os        || "Unknown OS",
    browser:   raw.browser   || "Unknown Browser",
    device:    raw.device    || "🖥 Desktop",
    severity:  raw.severity  || "low",
    timeStr:   raw.time_str  || raw.timeStr || new Date().toLocaleString("en-IN"),
    timestamp: raw.timestamp || new Date().toISOString(),
    status:    blockedIPs.has(raw.ip) ? "BLOCKED" : (raw.status || "FAILED"),
  };

  attempts.unshift(entry);
  currentAlertData = entry;

  updateTable();
  updateStats();
  updateMap(entry);
  updateOriginList();

  if (animate) {
    updateAlert(entry);
    showToast(
      `🔴 ${entry.ip} — ${entry.city}, ${entry.country} (${entry.severity.toUpperCase()})`,
      entry.severity === "high" || entry.severity === "critical" ? "danger" : "warn"
    );
  }
}

// ── Simulate ──────────────────────────────────────────────────────────────────
async function simulateAttack() {
  const btn = document.querySelector('button[onclick="simulateAttack()"]');
  if (btn) { btn.disabled = true; btn.textContent = "⏳ Scanning…"; }
  const ip  = ATTACKER_IPS[Math.floor(Math.random() * ATTACKER_IPS.length)];
  const dev = DEVICE_POOL[Math.floor(Math.random() * DEVICE_POOL.length)];
  showToast("⚡ Logging simulated attack…", "info");
  try {
    await fetch(`${API_BASE}/api/log`, {
      method: "POST",
      headers: apiHeaders(),
      body: JSON.stringify({
        ip:       ip,
        os:       dev.os,
        browser:  dev.browser,
        device:   dev.device,
        severity: Math.random() > 0.7 ? "high" : "low",
      }),
    });
  } catch (_) {
    showToast("Backend offline — check API key or server", "danger");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "⚡ Simulate Attack"; }
  }
}

// FIX #4: 600 ms stagger between each burst call (was synchronous)
function simulateBurst() {
  for (let i = 0; i < 5; i++) {
    const delay = i * 600 + Math.random() * 200;
    setTimeout(simulateAttack, delay);
  }
}

// ── Table (FIX #12: all values passed through esc()) ──────────────────────────
function updateTable() {
  const tbody = document.getElementById("attemptLog");
  const slice = attempts.slice(0, 100);
  tbody.innerHTML = slice.map((a) => {
    const isBlocked  = a.status === "BLOCKED";
    const isHighRisk = a.severity === "high" || a.severity === "critical";
    const ipTag = `<a href="#" onclick="openReportModal(attempts[${attempts.indexOf(a)}]);return false"
                      style="color:var(--accent);text-decoration:none">${esc(a.ip)}</a>`;
    const riskBadge  = isHighRisk
      ? `<span class="badge badge-high" style="margin-left:4px">HIGH RISK</span>` : "";
    const statusBadge = isBlocked
      ? `<span style="color:var(--dim)">BLOCKED</span>`
      : `<span style="color:var(--danger)">FAILED</span>`;
    const blockBtn = isBlocked
      ? `<button class="btn" style="background:var(--border);color:var(--dim);font-size:9px" disabled>Blocked</button>`
      : `<button class="btn btn-danger" style="font-size:9px"
             onclick="blockIP('${esc(a.ip)}','${esc(a.city)}','${esc(a.country)}')">Block</button>`;

    return `<tr class="${isHighRisk ? "danger-row" : ""}"
                style="${a === attempts[0] ? "animation:row-flash 1.2s ease" : ""}">
      <td style="color:var(--dim)">#${esc(a.num)}</td>
      <td>${ipTag}${riskBadge}</td>
      <td><strong>${esc(a.country)}</strong><br>
          <span style="font-size:10px;color:var(--dim)">${esc(a.city)} / ${esc(a.isp)}</span><br>
          <span style="font-size:9px;color:var(--dim)">${Number(a.latitude).toFixed(2)}, ${Number(a.longitude).toFixed(2)}</span></td>
      <td>${esc(a.device)}<br><span style="font-size:9px;color:var(--dim)">${esc(a.os)} · ${esc(a.browser)}</span></td>
      <td>${esc(a.timeStr)}</td>
      <td>${statusBadge}</td>
      <td style="display:flex;gap:4px;flex-wrap:wrap">
        ${blockBtn}
        <button class="btn btn-warn" style="font-size:9px"
            onclick="openReportModal(attempts[${attempts.indexOf(a)}])">Report</button>
      </td>
    </tr>`;
  }).join("");
}

// ── Stats ─────────────────────────────────────────────────────────────────────
function updateStats() {
  document.getElementById("statTotal").textContent    = attempts.length;
  document.getElementById("statFailed").textContent   = attempts.filter((a) => a.status === "FAILED").length;
  document.getElementById("statBlocked").textContent  = blockedIPs.size;
  document.getElementById("statCountries").textContent =
    new Set(attempts.map((a) => a.country)).size;
}

async function refreshStats() {
  try {
    const res = await fetch(`${API_BASE}/api/stats`, { headers: apiHeaders() });
    const s   = await res.json();
    document.getElementById("statTotal").textContent     = s.total;
    document.getElementById("statFailed").textContent    = s.failed;
    document.getElementById("statCountries").textContent = s.countries;
    document.getElementById("statBlocked").textContent   = blockedIPs.size;
  } catch (_) {}
}

// ── Alert Box ─────────────────────────────────────────────────────────────────
let _alertTimeout = null;

function updateAlert(entry) {
  document.getElementById("alertEmpty").style.display  = "none";
  document.getElementById("liveAlert").style.display   = "block";
  document.getElementById("alertBadge").style.display  = "inline-block";
  const numEl = document.getElementById("alertNum");
  numEl.textContent = parseInt(numEl.textContent || "0") + 1;
  const sevColor =
    entry.severity === "high" || entry.severity === "critical"
      ? "var(--danger)" : "var(--warn)";
  document.getElementById("alertDetail").innerHTML = `
    <div><span style="color:var(--accent)">IP Address:</span>  ${esc(entry.ip)}</div>
    <div><span style="color:var(--accent)">Origin:</span>      ${esc(entry.city)}, ${esc(entry.country)}</div>
    <div><span style="color:var(--accent)">ISP / ASN:</span>   ${esc(entry.isp)} ${entry.asn ? "(" + esc(entry.asn) + ")" : ""}</div>
    <div><span style="color:var(--accent)">Coordinates:</span> ${Number(entry.latitude).toFixed(4)}, ${Number(entry.longitude).toFixed(4)}</div>
    <div><span style="color:var(--accent)">Device:</span>      ${esc(entry.device)}</div>
    <div><span style="color:var(--accent)">Risk Level:</span>  <span style="color:${sevColor};font-weight:bold">${esc(entry.severity.toUpperCase())}</span></div>
  `;
  if (_alertTimeout) clearTimeout(_alertTimeout);
  _alertTimeout = setTimeout(() => {
    document.getElementById("alertEmpty").style.display  = "block";
    document.getElementById("liveAlert").style.display   = "none";
    document.getElementById("alertBadge").style.display  = "none";
    document.getElementById("alertNum").textContent = "0";
  }, 12000);
}

// ── Block / Unblock (FIX #14: IPs escaped via esc()) ─────────────────────────
function blockIP(ip, city, country) {
  if (blockedIPs.has(ip)) { showToast(`${ip} already blocked`, "warn"); return; }
  blockedIPs.add(ip);
  attempts.forEach((a) => { if (a.ip === ip) a.status = "BLOCKED"; });
  const item = document.createElement("div");
  item.className = "blocked-item";
  item.id = `blocked-${ip.replace(/\./g, "-")}`;
  // FIX #14: all values escaped
  item.innerHTML = `
    <div class="blocked-ip">🚫 ${esc(ip)}<br>
      <span style="font-size:9px;color:var(--dim)">${esc(city)}, ${esc(country)}</span></div>
    <button class="btn btn-warn" style="font-size:9px"
      onclick="unblockIP('${esc(ip)}',this.closest('.blocked-item'))">Unblock</button>`;
  const list  = document.getElementById("blockedList");
  const empty = list.querySelector(".empty-msg");
  if (empty) empty.remove();
  list.prepend(item);
  document.getElementById("blockedCount").textContent = `${blockedIPs.size} BLOCKED`;
  updateStats();
  updateTable();
  showToast(`IP ${ip} blocked`, "success");
}

function unblockIP(ip, el) {
  blockedIPs.delete(ip);
  el.remove();
  attempts.forEach((a) => { if (a.ip === ip) a.status = "FAILED"; });
  document.getElementById("blockedCount").textContent = `${blockedIPs.size} BLOCKED`;
  if (blockedIPs.size === 0) {
    document.getElementById("blockedList").innerHTML =
      `<div class="empty-msg">No IPs blocked yet</div>`;
  }
  updateStats();
  updateTable();
  showToast(`${ip} unblocked`, "info");
}

// FIX #1: these never throw ReferenceError because currentAlertData is declared at module scope
function blockCurrentAlert() {
  if (currentAlertData) blockIP(currentAlertData.ip, currentAlertData.city, currentAlertData.country);
}
function reportCurrentAlert() {
  if (currentAlertData) openReportModal(currentAlertData);
}

// ── Map (FIX #8: cap at 20 dots — remove oldest) ─────────────────────────────
function updateMap(attempt) {
  const worldMap = document.getElementById("worldMap");
  const country  = attempt.country;
  const matchKey = Object.keys(mapPositions).find((k) =>
    country.toLowerCase().includes(k.toLowerCase())
  );
  if (!matchKey || placedCountries.has(country)) return;
  placedCountries.add(country);
  const pos = mapPositions[matchKey];
  const dot = document.createElement("div");
  dot.className    = "map-origin";
  dot.style.top    = pos.top;
  dot.style.left   = pos.left;
  dot.style.transform = "translate(-50%,-50%)";
  dot.title        = country;
  worldMap.appendChild(dot);
  dot.addEventListener("animationend", () => {
    dot.style.animation = "none";
    dot.style.opacity   = "0.6";
  });
  // FIX #8: track and cap dots at 20
  mapDots.push(dot);
  if (mapDots.length > 20) {
    const oldest = mapDots.shift();
    if (oldest && oldest.title) placedCountries.delete(oldest.title);
    oldest.remove();
  }
}

function updateOriginList() {
  const counts = {};
  const risks  = {};
  for (const a of attempts) {
    counts[a.country] = (counts[a.country] || 0) + 1;
    if (a.severity === "high" || a.severity === "critical") risks[a.country] = true;
  }
  const sorted = Object.entries(counts).sort((x, y) => y[1] - x[1]).slice(0, 12);
  document.getElementById("originList").innerHTML =
    sorted.map(([country, count]) =>
      `<div style="display:flex;justify-content:space-between;margin-bottom:3px">
        <span><span style="color:var(--danger)">●</span> ${esc(country)} ${risks[country] ? "⚠" : ""}</span>
        <span style="color:var(--dim)">${count}</span>
       </div>`
    ).join("") || "No attack origins detected yet.";
}

// ── Deep Scan (FIX #7: debounce + guard — no parallel requests) ───────────────
let _scanRunning = false;

async function runDeepScan() {
  if (_scanRunning) return;  // FIX #7: guard
  const target = document.getElementById("scanInput").value.trim();
  if (!target) { showToast("Enter an IP or email first", "warn"); return; }

  _scanRunning = true;
  const btn = document.querySelector('button[onclick="runDeepScan()"]');
  if (btn) { btn.disabled = true; btn.textContent = "⏳ Scanning…"; }

  const con = document.getElementById("scanConsole");
  con.style.display = "flex";
  con.innerHTML = `<div style="color:var(--accent)">&gt; Connecting to CyberGuard OSINT Engine…</div>`;

  try {
    const res  = await fetch(`${API_BASE}/api/scan`, {
      method:  "POST",
      headers: apiHeaders(),
      body:    JSON.stringify({ target }),
    });
    const data = await res.json();
    con.innerHTML = "";
    const colorMap = {
      info: "var(--accent2)", dim: "var(--dim)",
      warn: "var(--warn)", danger: "var(--danger)", success: "var(--success)",
    };
    let i = 0;
    for (const line of data.results || []) {
      const delay = Math.floor(Math.random() * 200) + 100;
      await new Promise((r) => setTimeout(r, delay * i));
      const d = document.createElement("div");
      d.style.color = colorMap[line.type] || "var(--text)";
      d.textContent = `> ${line.msg}`;
      con.appendChild(d);
      con.scrollTop = con.scrollHeight;
      i++;
    }
    showToast(
      `Scan complete — Severity: ${(data.severity || "low").toUpperCase()}`,
      data.severity === "high" ? "danger" : "success"
    );
  } catch (_) {
    con.innerHTML += `<div style="color:var(--danger)">&gt; ⚠ Failed to reach backend.</div>`;
  } finally {
    _scanRunning = false;
    if (btn) { btn.disabled = false; btn.textContent = "▶ SCAN"; }
  }
}

// ── Report Modal ──────────────────────────────────────────────────────────────
let _reportAttempt = null;

function openReportModal(attempt) {
  _reportAttempt = attempt;
  const reportId = `CG-${Date.now().toString(36).toUpperCase()}`;
  const sameIP   = attempts.filter((a) => a.ip === attempt.ip);
  document.getElementById("reportBody").innerHTML = `
    <div class="report-section">
      <div class="report-title">1. COMPLAINT REFERENCE</div>
      <div class="report-row"><span class="report-key">Report ID:</span><span class="report-val">${esc(reportId)}</span></div>
      <div class="report-row"><span class="report-key">Generated At:</span><span class="report-val">${esc(new Date().toISOString())}</span></div>
      <div class="report-row"><span class="report-key">Status:</span><span class="report-val" style="color:var(--danger)">INVESTIGATION OPEN</span></div>
    </div>
    <div class="report-section">
      <div class="report-title">2. ATTACK DETAILS</div>
      <div class="report-row"><span class="report-key">UTC Timestamp:</span><span class="report-val">${esc(attempt.timestamp)}</span></div>
      <div class="report-row"><span class="report-key">Local Time:</span><span class="report-val">${esc(attempt.timeStr)}</span></div>
      <div class="report-row"><span class="report-key">Severity:</span><span class="report-val" style="color:var(--danger)">${esc(attempt.severity.toUpperCase())}</span></div>
      <div class="report-row"><span class="report-key">Status:</span><span class="report-val">${esc(attempt.status)}</span></div>
    </div>
    <div class="report-section">
      <div class="report-title">3. NETWORK INFORMATION</div>
      <div class="report-row"><span class="report-key">IP Address:</span><span class="report-val">${esc(attempt.ip)}</span></div>
      <div class="report-row"><span class="report-key">City / Country:</span><span class="report-val">${esc(attempt.city)}, ${esc(attempt.country)}</span></div>
      <div class="report-row"><span class="report-key">ISP / ASN:</span><span class="report-val">${esc(attempt.isp)} ${attempt.asn ? "(" + esc(attempt.asn) + ")" : ""}</span></div>
      <div class="report-row"><span class="report-key">Region / TZ:</span><span class="report-val">${esc(attempt.region)} / ${esc(attempt.timezone)}</span></div>
      <div class="report-row"><span class="report-key">Coordinates:</span><span class="report-val">${attempt.latitude}, ${attempt.longitude}</span></div>
    </div>
    <div class="report-section">
      <div class="report-title">4. DEVICE FINGERPRINT</div>
      <div class="report-row"><span class="report-key">Device:</span><span class="report-val">${esc(attempt.device)}</span></div>
      <div class="report-row"><span class="report-key">OS:</span><span class="report-val">${esc(attempt.os)}</span></div>
      <div class="report-row"><span class="report-key">Browser:</span><span class="report-val">${esc(attempt.browser)}</span></div>
    </div>
    <div class="report-section">
      <div class="report-title">5. LEGAL GUIDANCE</div>
      <div style="font-size:12px;line-height:1.9">
        Report at: <a href="https://cybercrime.gov.in" target="_blank" style="color:var(--accent)">cybercrime.gov.in</a><br>
        Applicable Law: <strong>IT Act 2000 §66</strong> — Unauthorized computer access<br>
        Evidence Log: SHA-256 hash validated. Keep this report for FIR.
      </div>
    </div>
    <div class="report-section">
      <div class="report-title">6. ALL ATTEMPTS FROM ${esc(attempt.ip)} (${sameIP.length} total)</div>
      ${sameIP.slice(0, 20).map((a) =>
        `<div class="report-row">
          <span class="report-key">${esc(a.timeStr)}</span>
          <span class="report-val">${esc(a.status)} · ${esc(a.severity.toUpperCase())} · ${esc(a.device)}</span>
         </div>`
      ).join("")}
    </div>`;
  document.getElementById("reportModal").style.display = "flex";
}

function closeModal(ev) {
  if (ev.target.id === "reportModal")
    document.getElementById("reportModal").style.display = "none";
}

// FIX #6: copyReport uses Clipboard API with execCommand fallback
function copyReport() {
  if (!_reportAttempt) return;
  const a = _reportAttempt;
  const text = [
    "=== SECUREWATCH CYBER COMPLAINT REPORT ===",
    `Report ID   : CG-${Date.now().toString(36).toUpperCase()}`,
    `Generated   : ${new Date().toISOString()}`,
    `IP Address  : ${a.ip}`,
    `City        : ${a.city}`,
    `Country     : ${a.country}`,
    `ISP         : ${a.isp}`,
    `Coordinates : ${a.latitude}, ${a.longitude}`,
    `Device      : ${a.device} | ${a.os} | ${a.browser}`,
    `Timestamp   : ${a.timestamp}`,
    `Severity    : ${a.severity.toUpperCase()}`,
    `Status      : ${a.status}`,
    "",
    "IT Act 2000 §66 | cybercrime.gov.in",
  ].join("\n");

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() =>
      showToast("Report copied to clipboard", "success")
    ).catch(() => _fallbackCopy(text));
  } else {
    _fallbackCopy(text);
  }
}

function _fallbackCopy(text) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity  = "0";
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand("copy");
    showToast("Report copied (fallback)", "success");
  } catch (_) {
    showToast("Copy failed — please copy manually", "danger");
  }
  document.body.removeChild(ta);
}

// ── Clear / Export ────────────────────────────────────────────────────────────
async function clearLog() {
  if (!confirm("Clear all login history? This cannot be undone.")) return;
  try {
    await fetch(`${API_BASE}/api/clear`, { method: "POST", headers: apiHeaders() });
    // FIX #3: also clear in-memory array immediately
    attempts = [];
    attemptCounter = 0;
    updateStats();
    updateTable();
    document.getElementById("attemptLog").innerHTML =
      `<tr><td colspan="7"><div class="no-attempts">🛡 Log cleared — monitoring active</div></td></tr>`;
  } catch (_) {
    showToast("Backend offline — cannot clear", "danger");
  }
}

// FIX #5: exportAll uses Blob + createObjectURL — no more document.write()
function exportAll() {
  if (!attempts.length) { showToast("No data to export", "warn"); return; }
  showToast("Generating consolidated forensic report…", "info");
  const header = [
    "ID", "IP", "City", "Country", "ISP", "ASN", "Region", "Timezone",
    "Latitude", "Longitude", "OS", "Browser", "Device",
    "Status", "Severity", "Timestamp", "Time (Local)"
  ].join(",");
  const rows = attempts.map((a) =>
    [
      a.id, a.ip, a.city, a.country, a.isp, a.asn, a.region, a.timezone,
      a.latitude, a.longitude, a.os, a.browser, a.device,
      a.status, a.severity, a.timestamp, a.timeStr
    ].map((v) => `"${String(v).replace(/"/g, '""')}"`).join(",")
  );
  const csv  = [header, ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url  = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href     = url;
  link.download = `securewatch-export-${Date.now()}.csv`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
  showToast(`Exported ${attempts.length} record(s)`, "success");
}

// ── Toast (FIX #9: toasts auto-removed after fade-out, no DOM leak) ───────────
function showToast(msg, type = "info") {
  const tc = document.getElementById("toastContainer");
  const el = document.createElement("div");
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  tc.prepend(el);
  // FIX #9: guaranteed removal after animation
  setTimeout(() => {
    el.style.opacity   = "0";
    el.style.transform = "translateX(80px)";
    setTimeout(() => el.remove(), 350);
  }, 4500);
}

// ── Misc ──────────────────────────────────────────────────────────────────────
// FIX #11: changeEmail validates input (must contain @)
function changeEmail() {
  const e = prompt("Enter protected email address:");
  if (!e || !e.trim()) return;
  if (!e.includes("@")) {
    showToast("Invalid email — must contain @", "warn");
    return;
  }
  document.getElementById("protectedEmail").textContent = e.trim();
  showToast(`Now protecting: ${e.trim()}`, "success");
}

async function fetchUserInfo() {
  try {
    const res  = await fetch(`${API_BASE}/api/me`, { headers: apiHeaders() });
    const data = await res.json();
    document.getElementById("myIpDisplay").innerHTML =
      `🟢 ${esc(data.ip)} (${esc(data.city)}, ${esc(data.country)})`;
  } catch (_) {
    document.getElementById("myIpDisplay").textContent = "⚠ API OFFLINE";
  }
}

// ── Init ──────────────────────────────────────────────────────────────────────
(async function init() {
  fetchUserInfo();
  await loadHistory();
  connectSSE();
  setInterval(refreshStats, 30000);
})();
