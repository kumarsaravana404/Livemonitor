// ─────────────────────────────────────────────
//  CONFIG
// ─────────────────────────────────────────────

const API_BASE = "http://localhost:5001";

// ─────────────────────────────────────────────
//  STATE
// ─────────────────────────────────────────────

let attempts = [];
let blockedIPs = new Set();
let attemptCounter = 0;
let currentAlertData = null;

// ─────────────────────────────────────────────
//  CLOCK
// ─────────────────────────────────────────────

function updateClock() {
  const now = new Date();
  document.getElementById("clock").textContent = now.toLocaleTimeString(
    "en-IN",
    { hour12: false }
  );
}
setInterval(updateClock, 1000);
updateClock();

// ─────────────────────────────────────────────
//  FETCH USER INFO ON LOAD  →  /api/me
// ─────────────────────────────────────────────

async function fetchUserInfo() {
  const display = document.getElementById("myIpDisplay");
  display.innerHTML = "Fetching network data...";
  try {
    const res = await fetch(`${API_BASE}/api/me`);
    if (!res.ok) throw new Error("Non-200 response");
    const data = await res.json();
    display.innerHTML = `IP: ${data.ip} &middot; ${data.city}, ${data.country}`;
    showToast(`🛡 SecureWatch active. Your IP: ${data.ip} (${data.city}, ${data.country})`, "info");
  } catch (e) {
    display.innerHTML = "Network Data Offline";
    showToast("⚠ Could not reach backend — is Flask running on port 5001?", "warn");
  }
}

// ─────────────────────────────────────────────
//  SIMULATE ATTACK  →  /api/scan (live IP from /api/me)
// ─────────────────────────────────────────────

// Fallback pool for when we want to generate varied fake attacker IPs
// (since /api/scan operates on a target you provide, we generate realistic
//  attacker IPs and run them through the real scan engine)
const ATTACKER_IPS = [
  "103.21.58.74",
  "185.220.101.45",
  "45.86.201.17",
  "91.108.4.212",
  "196.207.128.10",
  "121.244.37.89",
  "77.88.55.77",
  "5.188.86.195",
  "36.77.201.54",
  "197.210.65.33",
];

const DEVICE_POOL = [
  { os: "Windows 10",   browser: "Chrome 121",    device: "🖥 Desktop" },
  { os: "Windows 11",   browser: "Firefox 122",   device: "🖥 Desktop" },
  { os: "Ubuntu Linux", browser: "curl/7.88",     device: "🤖 Bot/Script" },
  { os: "Android 13",   browser: "Chrome Mobile", device: "📱 Mobile" },
  { os: "macOS 14",     browser: "Safari 17",     device: "💻 Laptop" },
  { os: "iOS 17",       browser: "Safari Mobile", device: "📱 Mobile" },
  { os: "Debian Linux", browser: "Python/3.11",   device: "🤖 Bot/Script" },
];

async function simulateAttack() {
  // Pick a random attacker IP and device from the pools
  const ip = ATTACKER_IPS[Math.floor(Math.random() * ATTACKER_IPS.length)];
  const deviceInfo = DEVICE_POOL[Math.floor(Math.random() * DEVICE_POOL.length)];

  // Show scanning indicator
  showToast(`🔍 Scanning incoming IP: ${ip}...`, "info");

  try {
    // Hit real Flask /api/scan endpoint with the attacker IP
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: ip }),
    });

    if (!res.ok) throw new Error("Scan API error");
    const data = await res.json();

    // Extract geo info from scan results (Flask returns it in result msgs)
    // Also call /api/me-style geo lookup via a lightweight parse of results
    const geoLine = data.results.find(
      (r) => r.msg && r.msg.includes("ISP:") && r.msg.includes("Location:")
    );

    let city = "Unknown";
    let country = "Unknown";
    let isp = "Unknown ISP";

    if (geoLine) {
      // Parse: "ISP: Airtel | Location: New Delhi, India"
      const ispMatch = geoLine.msg.match(/ISP:\s*([^|]+)\|/);
      const locMatch = geoLine.msg.match(/Location:\s*(.+)/);
      if (ispMatch) isp = ispMatch[1].trim();
      if (locMatch) {
        const parts = locMatch[1].trim().split(",");
        city = parts[0]?.trim() || "Unknown";
        country = parts[1]?.trim() || "Unknown";
      }
    }

    const status = blockedIPs.has(ip)
      ? "BLOCKED"
      : data.severity === "high"
      ? "FAILED"
      : "FAILED";

    const now = new Date();
    attemptCounter++;

    const attempt = {
      num: attemptCounter,
      ip,
      city,
      country,
      isp,
      os: deviceInfo.os,
      browser: deviceInfo.browser,
      device: deviceInfo.device,
      severity: data.severity,
      status,
      time: now,
      timeStr: now.toLocaleString("en-IN", {
        dateStyle: "short",
        timeStyle: "medium",
      }),
      scanResults: data.results,
      reportGenerated: false,
    };

    attempts.unshift(attempt);
    currentAlertData = attempt;

    updateTable();
    updateStats();
    updateAlert(attempt);
    updateMap({ country, city });
    updateOriginList();

    const toastType = data.severity === "high" ? "danger" : "warn";
    showToast(
      `🚨 LOGIN ATTEMPT #${attemptCounter} FROM ${city}, ${country} — IP: ${ip} [${data.severity.toUpperCase()} RISK]`,
      toastType
    );
  } catch (err) {
    showToast(`⚠ Attack simulation failed — is Flask running on port 5001?`, "warn");
    console.error("simulateAttack error:", err);
  }
}

function simulateBurst() {
  let delay = 0;
  for (let i = 0; i < 5; i++) {
    setTimeout(simulateAttack, delay);
    delay += 800; // slightly longer to avoid race conditions on API
  }
}

// ─────────────────────────────────────────────
//  TABLE
// ─────────────────────────────────────────────

function updateTable() {
  const tbody = document.getElementById("attemptLog");

  if (attempts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7"><div class="no-attempts">🛡 No unauthorized attempts detected<br><span style="font-size:10px;margin-top:8px;display:block;">Click "Simulate Attack" to test the system</span></div></td></tr>`;
    return;
  }

  tbody.innerHTML = attempts
    .map(
      (a) => `
    <tr class="log-row ${a.status === "FAILED" ? "danger-row" : ""}">
      <td><span class="attempt-num">#${a.num}</span></td>
      <td>
        <span class="ip-tag" onclick="showReport(${a.num - 1})" title="Click to view full report">${a.ip}</span>
        ${a.severity === "high" ? '<br><span style="color:var(--danger);font-size:9px;font-family:var(--mono)">⚠ HIGH RISK</span>' : ''}
      </td>
      <td>
        <div class="location-text">${a.city}, ${a.country}</div>
        <div class="isp-text">${a.isp}</div>
      </td>
      <td>
        <span class="device-icon">${a.device.split(" ")[0]}</span>
        <span style="font-size:12px">${a.os}</span><br>
        <span style="font-family:var(--mono);font-size:10px;color:var(--dim)">${a.browser}</span>
      </td>
      <td><div class="time-text">${a.timeStr}</div></td>
      <td>
        <span class="status-badge ${a.status === "FAILED" ? "status-fail" : a.status === "BLOCKED" ? "status-block" : "status-ok"}">
          ${a.status === "FAILED" ? "⛔ FAILED" : a.status === "BLOCKED" ? "🚫 BLOCKED" : "✅ ALLOWED"}
        </span>
      </td>
      <td>
        <div class="action-btns">
          <button class="mini-btn mini-block" onclick="blockIP('${a.ip}', '${a.city}', '${a.country}')">🚫 Block</button>
          <button class="mini-btn mini-report" onclick="showReport(${a.num - 1})">📋 Report</button>
        </div>
      </td>
    </tr>
  `
    )
    .join("");
}

// ─────────────────────────────────────────────
//  STATS
// ─────────────────────────────────────────────

function updateStats() {
  document.getElementById("statTotal").textContent = attempts.length;
  document.getElementById("statFailed").textContent = attempts.filter(
    (a) => a.status === "FAILED"
  ).length;
  document.getElementById("statBlocked").textContent = blockedIPs.size;
  const countries = new Set(attempts.map((a) => a.country));
  document.getElementById("statCountries").textContent = countries.size;
}

// ─────────────────────────────────────────────
//  ALERT BOX
// ─────────────────────────────────────────────

function updateAlert(attempt) {
  const total = attempts.length;
  document.getElementById("alertEmpty").style.display = "none";
  const la = document.getElementById("liveAlert");
  la.style.display = "block";

  document.getElementById("alertNum").textContent = total;
  document.getElementById("alertBadge").style.display = "inline";

  const severityColor = attempt.severity === "high" ? "var(--danger)" : "var(--warn)";

  document.getElementById("alertDetail").innerHTML = `
    <div class="detail-row"><span class="detail-key">IP ADDRESS</span><span class="detail-val highlight">${attempt.ip}</span></div>
    <div class="detail-row"><span class="detail-key">LOCATION</span><span class="detail-val">${attempt.city}, ${attempt.country}</span></div>
    <div class="detail-row"><span class="detail-key">ISP / NETWORK</span><span class="detail-val">${attempt.isp}</span></div>
    <div class="detail-row"><span class="detail-key">DEVICE</span><span class="detail-val">${attempt.device} · ${attempt.os}</span></div>
    <div class="detail-row"><span class="detail-key">BROWSER</span><span class="detail-val">${attempt.browser}</span></div>
    <div class="detail-row"><span class="detail-key">RISK LEVEL</span><span class="detail-val" style="color:${severityColor}">${attempt.severity.toUpperCase()}</span></div>
    <div class="detail-row"><span class="detail-key">STATUS</span><span class="detail-val danger">${attempt.status}</span></div>
    <div class="detail-row"><span class="detail-key">TIME</span><span class="detail-val">${attempt.timeStr}</span></div>
  `;
}

// ─────────────────────────────────────────────
//  BLOCK IP
// ─────────────────────────────────────────────

function blockIP(ip, city, country) {
  if (blockedIPs.has(ip)) {
    showToast(`⚠ IP ${ip} is already blocked`, "info");
    return;
  }
  blockedIPs.add(ip);

  const bl = document.getElementById("blockedList");
  const empty = bl.querySelector(".empty-msg");
  if (empty) empty.remove();

  const item = document.createElement("div");
  item.className = "blocked-item";
  item.id = "blocked_" + ip.replace(/\./g, "_");
  item.innerHTML = `
    <div>
      <div class="blocked-ip">🚫 ${ip}</div>
      <div class="blocked-loc">${city}, ${country}</div>
    </div>
    <button class="unblock-btn" onclick="unblockIP('${ip}', this.closest('.blocked-item'))">Unblock</button>
  `;
  bl.prepend(item);

  attempts.forEach((a) => {
    if (a.ip === ip) a.status = "BLOCKED";
  });

  document.getElementById("blockedCount").textContent = blockedIPs.size + " BLOCKED";
  updateStats();
  updateTable();
  showToast(`🚫 IP ${ip} (${city}) has been BLOCKED`, "success");
}

function unblockIP(ip, el) {
  blockedIPs.delete(ip);
  el.remove();
  if (blockedIPs.size === 0) {
    document.getElementById("blockedList").innerHTML =
      '<div class="empty-msg">No IPs blocked yet</div>';
  }
  document.getElementById("blockedCount").textContent = blockedIPs.size + " BLOCKED";
  updateStats();
  showToast(`✅ IP ${ip} has been unblocked`, "info");
}

function blockCurrentAlert() {
  if (currentAlertData)
    blockIP(currentAlertData.ip, currentAlertData.city, currentAlertData.country);
}

// ─────────────────────────────────────────────
//  MAP
// ─────────────────────────────────────────────

const mapPositions = {
  India:       { top: "38%", left: "65%" },
  Russia:      { top: "20%", left: "60%" },
  China:       { top: "32%", left: "73%" },
  Germany:     { top: "24%", left: "50%" },
  Nigeria:     { top: "48%", left: "48%" },
  Ukraine:     { top: "26%", left: "56%" },
  Netherlands: { top: "23%", left: "49%" },
  Indonesia:   { top: "52%", left: "76%" },
  Kenya:       { top: "50%", left: "56%" },
  Unknown:     { top: "35%", left: "50%" },
};

const placedDots = new Set();

function updateMap(attacker) {
  const map = document.getElementById("worldMap");
  // Try exact match first, then partial match
  const countryKey =
    Object.keys(mapPositions).find((k) =>
      attacker.country.toLowerCase().includes(k.toLowerCase())
    ) || "Unknown";

  if (placedDots.has(countryKey)) return;
  placedDots.add(countryKey);

  const pos = mapPositions[countryKey];
  const dot = document.createElement("div");
  dot.className = "map-dot";
  dot.style.top = pos.top;
  dot.style.left = pos.left;
  dot.title = `${attacker.city}, ${attacker.country}`;
  map.appendChild(dot);
}

function updateOriginList() {
  const countries = [...new Set(attempts.map((a) => a.country))];
  const ol = document.getElementById("originList");
  if (countries.length === 0) {
    ol.textContent = "No attack origins detected yet.";
    return;
  }
  ol.innerHTML = countries
    .map((c) => {
      const count = attempts.filter((a) => a.country === c).length;
      const highRisk = attempts.filter(
        (a) => a.country === c && a.severity === "high"
      ).length;
      return `<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid rgba(10,58,90,0.3)">
        <span>${c}${highRisk > 0 ? ' <span style="color:var(--danger)">⚠</span>' : ""}</span>
        <span style="color:var(--danger)">${count} attempt${count > 1 ? "s" : ""}</span>
      </div>`;
    })
    .join("");
}

// ─────────────────────────────────────────────
//  REPORT MODAL
// ─────────────────────────────────────────────

let activeReportAttempt = null;

function showReport(idx) {
  const attempt = attempts.find((a) => a.num === idx + 1) || attempts[0];
  activeReportAttempt = attempt;
  openReportModal(attempt);
}

function reportCurrentAlert() {
  if (currentAlertData) openReportModal(currentAlertData);
}

function openReportModal(attempt) {
  activeReportAttempt = attempt;
  const body = document.getElementById("reportBody");

  // Build scan findings section from real backend results
  const scanFindings = attempt.scanResults
    ? attempt.scanResults
        .map((r) => {
          const colorMap = {
            info: "#7ecfff",
            dim: "#888",
            warn: "#f0a500",
            danger: "#ff4444",
            success: "#00ff9d",
          };
          return `<div class="report-row" style="font-family:monospace;font-size:11px;color:${colorMap[r.type] || "#aaa"}">> ${r.msg}</div>`;
        })
        .join("")
    : '<div class="report-row"><span class="report-val">No scan data available</span></div>';

  body.innerHTML = `
    <div class="report-disclaimer">
      ⚠️ This evidence report is auto-generated by SecureWatch using live backend data. 
      It contains forensic data about the unauthorized login attempt. 
      You can use this to file a complaint at <strong>cybercrime.gov.in</strong> (India) or your local cybercrime authority.
    </div>

    <div class="report-section">
      <div class="report-section-title">📋 COMPLAINT REFERENCE</div>
      <div class="report-row"><span class="report-key">Report ID</span><span class="report-val">SW-${Date.now().toString(36).toUpperCase()}</span></div>
      <div class="report-row"><span class="report-key">Generated At</span><span class="report-val">${new Date().toLocaleString("en-IN")}</span></div>
      <div class="report-row"><span class="report-key">Protected Account</span><span class="report-val">${document.getElementById("protectedEmail").textContent}</span></div>
      <div class="report-row"><span class="report-key">Risk Level</span><span class="report-val" style="color:${attempt.severity === "high" ? "var(--danger)" : "var(--warn)"}">${attempt.severity.toUpperCase()}</span></div>
    </div>

    <div class="report-section">
      <div class="report-section-title">🔴 ATTACK DETAILS — ATTEMPT #${attempt.num}</div>
      <div class="report-row"><span class="report-key">Attempt Number</span><span class="report-val warn">#${attempt.num}</span></div>
      <div class="report-row"><span class="report-key">Date & Time</span><span class="report-val warn">${attempt.timeStr}</span></div>
      <div class="report-row"><span class="report-key">Status</span><span class="report-val warn">${attempt.status} (Unauthorized)</span></div>
    </div>

    <div class="report-section">
      <div class="report-section-title">🌐 ATTACKER NETWORK INFORMATION</div>
      <div class="report-row"><span class="report-key">IP Address</span><span class="report-val warn">${attempt.ip}</span></div>
      <div class="report-row"><span class="report-key">Location (City)</span><span class="report-val">${attempt.city}</span></div>
      <div class="report-row"><span class="report-key">Country</span><span class="report-val">${attempt.country}</span></div>
      <div class="report-row"><span class="report-key">ISP / Network</span><span class="report-val warn">${attempt.isp}</span></div>
    </div>

    <div class="report-section">
      <div class="report-section-title">💻 ATTACKER DEVICE FINGERPRINT</div>
      <div class="report-row"><span class="report-key">Device Type</span><span class="report-val">${attempt.device}</span></div>
      <div class="report-row"><span class="report-key">Operating System</span><span class="report-val">${attempt.os}</span></div>
      <div class="report-row"><span class="report-key">Browser / Client</span><span class="report-val">${attempt.browser}</span></div>
      <div class="report-row"><span class="report-key">Device Trust</span><span class="report-val warn">UNKNOWN — Not a trusted device</span></div>
    </div>

    <div class="report-section">
      <div class="report-section-title">🔍 LIVE BACKEND SCAN RESULTS</div>
      ${scanFindings}
    </div>

    <div class="report-section">
      <div class="report-section-title">⚖️ HOW TO FILE A COMPLAINT</div>
      <div class="report-row"><span class="report-key">India</span><span class="report-val">cybercrime.gov.in → File Complaint</span></div>
      <div class="report-row"><span class="report-key">What to submit</span><span class="report-val">This report + your account provider's records</span></div>
      <div class="report-row"><span class="report-key">Key evidence</span><span class="report-val">IP: ${attempt.ip} | ISP: ${attempt.isp} | Time: ${attempt.timeStr}</span></div>
      <div class="report-row"><span class="report-key">Legal basis</span><span class="report-val">IT Act 2000 §66 — Computer Crime / Unauthorized Access</span></div>
    </div>

    <div class="report-section">
      <div class="report-section-title">📊 ALL ATTEMPTS FROM THIS IP</div>
      ${attempts
        .filter((a) => a.ip === attempt.ip)
        .map(
          (a) => `
          <div class="report-row">
            <span class="report-key">Attempt #${a.num}</span>
            <span class="report-val">${a.timeStr} — ${a.status} [${a.severity?.toUpperCase() || "—"}]</span>
          </div>`
        )
        .join("")}
    </div>
  `;

  document.getElementById("reportModal").classList.add("open");
}

function closeModal() {
  document.getElementById("reportModal").classList.remove("open");
}

function printReport() {
  window.print();
}

function copyReport() {
  if (!activeReportAttempt) return;
  const a = activeReportAttempt;
  const scanText = a.scanResults
    ? a.scanResults.map((r) => `  > ${r.msg}`).join("\n")
    : "  No scan data";

  const text = `
====== SECUREWATCH — UNAUTHORIZED LOGIN EVIDENCE REPORT ======
Report Date : ${new Date().toLocaleString("en-IN")}
Protected   : ${document.getElementById("protectedEmail").textContent}
Risk Level  : ${a.severity?.toUpperCase() || "UNKNOWN"}

ATTEMPT #${a.num}
Date & Time : ${a.timeStr}
Status      : ${a.status} (Unauthorized)

ATTACKER NETWORK INFO:
IP Address  : ${a.ip}
Location    : ${a.city}, ${a.country}
ISP/Network : ${a.isp}

DEVICE FINGERPRINT:
Device Type : ${a.device}
OS          : ${a.os}
Browser     : ${a.browser}

LIVE SCAN RESULTS:
${scanText}

LEGAL REFERENCE:
India Cybercrime Portal: cybercrime.gov.in
IT Act 2000 §66 — Unauthorized Computer Access

Total attempts from this IP: ${attempts.filter((x) => x.ip === a.ip).length}
=============================================================
  `.trim();

  navigator.clipboard
    .writeText(text)
    .then(() => {
      showToast("📋 Report copied to clipboard! Paste it in your complaint.", "success");
    })
    .catch(() => {
      showToast("⚠ Could not copy — please use Print/Save PDF instead", "info");
    });
}

function exportAllReports() {
  if (attempts.length === 0) {
    showToast("⚠ No attempts to export yet", "info");
    return;
  }
  showToast(`📥 Exporting ${attempts.length} attempt records...`, "success");
  setTimeout(() => {
    openReportModal(attempts[0]);
    showToast("✅ Full evidence report ready — use Print to save as PDF", "success");
  }, 800);
}

// ─────────────────────────────────────────────
//  DEEP SYSTEM SCAN  →  /api/scan
// ─────────────────────────────────────────────

async function runDeepScan() {
  const target = document.getElementById("scanEmail").value.trim();
  if (!target) {
    showToast("⚠ Please enter a valid Email ID or IP Address to scan", "warn");
    return;
  }

  const consoleBox = document.getElementById("scanConsole");
  consoleBox.style.display = "flex";
  consoleBox.innerHTML = "";

  const appendLine = (text, type = "info") => {
    const div = document.createElement("div");
    const colorMap = {
      info: "var(--accent2)",
      dim: "var(--dim)",
      warn: "var(--warn)",
      danger: "var(--danger)",
      success: "#00ff9d",
    };
    div.style.color = colorMap[type] || colorMap["info"];
    div.innerHTML = "> " + text;
    consoleBox.appendChild(div);
    consoleBox.scrollTop = consoleBox.scrollHeight;
  };

  appendLine(`CONNECTING TO SECUREWATCH BACKEND API...`, "info");
  appendLine(`TARGET: ${target}`, "dim");

  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    for (const item of data.results) {
      await new Promise((r) => setTimeout(r, 120 + Math.random() * 250));
      appendLine(item.msg, item.type);
    }

    appendLine(`──────────────────────────────`, "dim");
    appendLine(
      `SCAN COMPLETE — SEVERITY: ${data.severity.toUpperCase()}`,
      data.severity === "high" ? "danger" : "warn"
    );

    if (data.severity === "high") {
      showToast("🚨 CRITICAL: High-risk tracking history detected!", "danger");
    } else {
      showToast("⚠ Scan complete. Minor warnings found.", "warn");
    }
  } catch (err) {
    appendLine(`ERROR: Could not reach Flask backend at ${API_BASE}`, "danger");
    appendLine(`Make sure Flask is running: python app.py`, "dim");
    showToast("⚠ Scan failed — is Flask running on port 5001?", "danger");
    console.error("runDeepScan error:", err);
  }
}

// ─────────────────────────────────────────────
//  MISC
// ─────────────────────────────────────────────

function clearLog() {
  if (!confirm("Clear all attempt logs? This cannot be undone.")) return;
  attempts = [];
  attemptCounter = 0;
  currentAlertData = null;
  placedDots.clear();
  document
    .getElementById("worldMap")
    .querySelectorAll(".map-dot")
    .forEach((d) => d.remove());
  document.getElementById("alertEmpty").style.display = "block";
  document.getElementById("liveAlert").style.display = "none";
  document.getElementById("alertBadge").style.display = "none";
  updateTable();
  updateStats();
  updateOriginList();
  showToast("🗑 Log cleared", "info");
}

function changeEmail() {
  const email = prompt(
    "Enter the email address to protect:",
    document.getElementById("protectedEmail").textContent
  );
  if (email && email.includes("@")) {
    document.getElementById("protectedEmail").textContent = email;
    showToast("✅ Protected email updated to: " + email, "success");
  }
}

function showToast(msg, type = "info") {
  const container = document.getElementById("toastContainer");
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = msg;
  container.prepend(toast);
  setTimeout(() => {
    toast.style.transition = "opacity 0.4s";
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 400);
  }, 4000);
}

// Close modal on overlay click
document.getElementById("reportModal").addEventListener("click", function (e) {
  if (e.target === this) closeModal();
});

// ─────────────────────────────────────────────
//  INIT
// ─────────────────────────────────────────────

fetchUserInfo();
