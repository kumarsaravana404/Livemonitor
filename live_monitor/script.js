function updateClock() {
  const now = new Date();
  document.getElementById("clock").innerText = now.toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}
setInterval(updateClock, 1000);
updateClock();

// --- STATE ---
let blockedList = new Set(); // We still track local UI blocks if we want

// --- API CONFIG ---
const API_BASE = "http://localhost:5001/api"; 

// --- CORE LOGIC ---

// 1. Fetch live public IP and update UI
async function fetchMyData() {
  try {
    const res = await fetch(`${API_BASE}/me`);
    const data = await res.json();
    document.getElementById("myIpDisplay").innerHTML = 
      `🟢 LIVE: ${data.ip} (${data.city}, ${data.country})`;
  } catch (e) {
    document.getElementById("myIpDisplay").innerText = "⚠️ API DISCONNECTED";
  }
}

// 2. Fetch Aggregated Stats
async function updateStats() {
  try {
    const res = await fetch(`${API_BASE}/stats`);
    const st = await res.json();
    document.getElementById("statTotal").innerText = st.total;
    document.getElementById("statFailed").innerText = st.failed;
    document.getElementById("statCountries").innerText = st.countries;
    document.getElementById("statBlocked").innerText = blockedList.size; 
  } catch (e) {}
}

// 3. Load full history on boot
async function loadHistory() {
  try {
    const res = await fetch(`${API_BASE}/history?limit=100`);
    const history = await res.json();
    document.getElementById("attemptLog").innerHTML = "";
    if (history.length === 0) {
      showEmptyState();
    } else {
      // reverse because API returns newest first, we will append them 
      history.reverse().forEach(entry => appendLogToTable(entry));
    }
  } catch (e) {
    console.error("Failed to load history", e);
  }
}

function showEmptyState() {
  document.getElementById("attemptLog").innerHTML = `
    <tr><td colspan="7">
      <div class="no-attempts">🛡 No unauthorized attempts detected yet</div>
    </td></tr>`;
}

// 4. Live Server-Sent Events (SSE) Stream
function connectSSE() {
  const sseLabel = document.getElementById("connectionStatus");
  const evtSource = new EventSource(`${API_BASE}/stream`);

  evtSource.onopen = () => {
    sseLabel.innerHTML = `<span style="color:var(--success)">●</span> STREAM CONNECTED`;
    sseLabel.style.borderColor = "var(--success)";
  };

  evtSource.addEventListener("new_attempt", (e) => {
    const entry = JSON.parse(e.data);
    
    // Remove empty state message if it's there
    const empty = document.querySelector(".no-attempts");
    if (empty) {
      document.getElementById("attemptLog").innerHTML = "";
    }
    
    appendLogToTable(entry);
    updateStats();
    triggerLiveAlert(entry);
    highlightMap(entry.country);
  });

  evtSource.addEventListener("history_cleared", () => {
    showEmptyState();
    updateStats();
  });

  evtSource.onerror = () => {
    sseLabel.innerHTML = `<span style="color:var(--danger)">○</span> RECONNECTING...`;
    sseLabel.style.borderColor = "var(--border)";
  };
}

// Helper: Insert entry row to HTML
function appendLogToTable(entry) {
  const tbody = document.getElementById("attemptLog");
  const tr = document.createElement("tr");
  
  // Blink animation for new rows
  tr.style.animation = "row-flash 1s ease";
  
  let severityHTML = "";
  if (entry.severity === "high") severityHTML = `<span class="badge badge-high">High Risk</span>`;
  else if (entry.severity === "critical") severityHTML = `<span class="badge badge-high" style="background:var(--accent2);color:#000">CRITICAL</span>`;
  
  let actionBtn = blockedList.has(entry.ip) 
    ? `<button class="btn" style="background:var(--border);color:var(--dim)" disabled>Blocked</button>`
    : `<button class="btn btn-danger" onclick="blockIP('${entry.ip}')">Block</button>`;

  tr.innerHTML = `
    <td style="color:var(--dim)">#${entry.id.toString().slice(-4)}</td>
    <td style="font-family:var(--mono);color:var(--accent)">
      ${entry.ip} <br>${severityHTML}
    </td>
    <td><strong>${entry.country}</strong><br><span style="font-size:10px;color:var(--dim)">${entry.city} / ${entry.isp}</span></td>
    <td>${entry.device}</td>
    <td>${entry.timeStr}</td>
    <td style="color:var(--danger)">${entry.status}</td>
    <td>${actionBtn}</td>
  `;
  
  // Prepend to top
  tbody.insertBefore(tr, tbody.firstChild);
  
  // Keep row count sane in UI
  if (tbody.children.length > 50) {
    if (tbody.lastChild) tbody.lastChild.remove();
  }
}

// Simulate a new attack by issuing POST to /api/log
function simulateAttack() {
  // We send a mock IP; the backend will trace it
  const badIP = `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`;
  const devices = ["Linux • Chrome", "Windows • Edge", "Mac • Safari", "Mullvad VPN Node", "Automated Script"];
  
  fetch(`${API_BASE}/log`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ip: badIP,
      os: "Simulated",
      device: devices[Math.floor(Math.random()*devices.length)],
      severity: Math.random() > 0.8 ? "high" : "low"
    })
  });
}

function simulateBurst() {
  for (let i = 0; i < 5; i++) {
    setTimeout(() => {
      simulateAttack();
    }, i * 300);
  }
}

let currentAlertTimeout = null;
let alertActive = false;

async function clearLog() {
  await fetch(`${API_BASE}/clear`, { method: "POST" });
  document.getElementById("alertEmpty").style.display   = "block";
  document.getElementById("liveAlert").style.display    = "none";
  document.getElementById("alertBadge").style.display   = "none";
  alertActive = false;
}

function triggerLiveAlert(data) {
  alertActive = true;
  document.getElementById("alertEmpty").style.display = "none";
  document.getElementById("liveAlert").style.display = "block";

  const numEl = document.getElementById("alertNum");
  numEl.innerText = parseInt(numEl.innerText) + 1;

  document.getElementById("alertDetail").innerHTML = `
    <span style="color:var(--accent)">Origin:</span> ${data.city}, ${data.country}<br>
    <span style="color:var(--accent)">IP Addr:</span> ${data.ip}<br>
    <span style="color:var(--accent)">ISP:</span> ${data.isp}<br>
    <span style="color:var(--accent)">Severity:</span> <span style="text-transform:uppercase;color:var(--accent2)">SCANNED</span>
  `;

  document.getElementById("alertBadge").style.display = "inline-block";
  document.getElementById("alertBadge").style.animation = "badge-pulse 1s infinite";

  if (currentAlertTimeout) clearTimeout(currentAlertTimeout);
  currentAlertTimeout = setTimeout(() => {
    alertActive = false;
    document.getElementById("alertEmpty").style.display = "block";
    document.getElementById("liveAlert").style.display = "none";
    document.getElementById("alertBadge").style.display = "none";
    document.getElementById("alertNum").innerText = "0";
  }, 10000);
}

function blockIP(ip) {
  if (!ip) return;
  if (blockedList.has(ip)) return;
  blockedList.add(ip);
  updateStats();
  renderBlockedList();
  showToast(`IP ${ip} permanently blocked at firewall level.`, "success");

  // Disable all buttons in table for this IP
  const btns = document.querySelectorAll("#attemptLog button");
  btns.forEach((b) => {
    if (b.innerText === "Block" && b.onclick.toString().includes(ip)) {
      b.disabled = true;
      b.style.background = "var(--border)";
      b.style.color = "var(--dim)";
      b.innerText = "Blocked";
    }
  });
}

function unblockIP(ip) {
  blockedList.delete(ip);
  updateStats();
  renderBlockedList();
  showToast(`IP ${ip} access restored.`, "warn");
}

function renderBlockedList() {
  const list = document.getElementById("blockedList");
  if (blockedList.size === 0) {
    list.innerHTML = `<div class="empty-msg">No IPs blocked yet</div>`;
    return;
  }
  list.innerHTML = Array.from(blockedList)
    .map(
      (ip) => `
      <div class="blocked-item">
        <div class="blocked-ip">${ip}</div>
        <button class="btn btn-warn" style="font-size:10px;padding:4px 8px" onclick="unblockIP('${ip}')">Unblock</button>
      </div>
    `
    )
    .join("");
}

function highlightMap(country) {
  const originList = document.getElementById("originList");
  if (originList.innerText.includes("No attack roles") || originList.innerText.includes("No attack origins")) {
    originList.innerHTML = "";
  }
  
  // Don't flood the HTML list
  if (originList.children.length < 10) {
    const d = document.createElement("div");
    d.style.marginBottom = "4px";
    d.innerHTML = `<span style="color:var(--danger)">●</span> ${country}`;
    originList.prepend(d);
  }

  const map = document.getElementById("worldMap");
  
  // Visual dot
  const dot = document.createElement("div");
  dot.className = "map-origin";
  dot.style.background  = "var(--danger)";
  dot.style.boxShadow   = "0 0 10px var(--danger)";

  dot.style.top  = Math.random() * 80 + 10 + "%";
  dot.style.left = Math.random() * 80 + 10 + "%";
  map.appendChild(dot);

  setTimeout(() => {
    if (dot.parentNode) dot.remove();
  }, 3000);
}

// Scan specific IP or Email against backend
async function runDeepScan() {
  const val = document.getElementById("scanEmail").value.trim();
  if (!val) {
    showToast("Please enter an email or IP", "error");
    return;
  }

  const consoleDiv = document.getElementById("scanConsole");
  consoleDiv.style.display = "flex";
  consoleDiv.innerHTML = `<div>&gt; Initiating engine scan...</div>`;

  try {
    const res = await fetch(`${API_BASE}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: val })
    });
    const info = await res.json();
    
    consoleDiv.innerHTML = `<div>&gt; Connected to Live Database...</div>`;
    
    // simulate typing effect for logs
    let i = 0;
    for (const log of info.results) {
        setTimeout(() => {
            const d = document.createElement("div");
            let color = "var(--accent2)";
            if (log.type === "warn") color = "var(--warn)";
            if (log.type === "danger") color = "var(--danger)";
            if (log.type === "success") color = "var(--success)";
            if (log.type === "dim") color = "var(--dim)";
            d.style.color = color;
            d.innerHTML = `&gt; ${log.msg}`;
            consoleDiv.appendChild(d);
            consoleDiv.scrollTop = consoleDiv.scrollHeight;
        }, i * 150);
        i++;
    }
  } catch (e) {
    consoleDiv.innerHTML += `<div style="color:var(--danger)">&gt; Backend connection failed! Ensure server is running.</div>`;
  }
}

function showToast(msg, type = "success") {
  const tc = document.getElementById("toastContainer");
  const el = document.createElement("div");
  el.className = `toast toast-${type}`;
  el.innerText = msg;
  tc.appendChild(el);
  setTimeout(() => {
    el.style.opacity = "0";
    el.style.transform = "translateX(100px)";
    setTimeout(() => el.remove(), 300);
  }, 3000);
}

function changeEmail() {
  const e = prompt("Enter new email to protect:");
  if (e && e.includes("@")) {
    document.getElementById("protectedEmail").innerText = e;
    showToast(`Now protecting ${e}`);
  }
}

function blockCurrentAlert() {
  // Try to find the latest unblocked IP
  const latestIP = document.getElementById("attemptLog").querySelector("tr").querySelector("td:nth-child(2)").innerText.split(" ")[0];
  if(latestIP) {
      blockIP(latestIP);
  }
}

function reportCurrentAlert() {
  showToast("Threat data compiled. Review report below.", "warn");
  setTimeout(generateReport, 800);
}

function closeModal() {
  document.getElementById("reportModal").style.display = "none";
}

function generateReport() {
  const modalCSS = `
    .report-header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 15px;
    }
    .report-header h2 { margin:0; font-family:var(--mono); color:var(--danger); }
    .report-header h4 { margin:5px 0 0 0; color:var(--text); }
    .report-section {
      margin-top: 20px;
    }
    .report-title {
      color: var(--accent);
      font-size: 14px;
      font-weight: bold;
      border-bottom: 1px solid var(--border);
      padding-bottom: 5px;
      margin-bottom: 15px;
    }
    .info-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 15px;
    }
    .info-item {
      font-family: var(--mono);
      font-size: 14px;
      margin-bottom: 8px;
    }
  `;

  const body = document.getElementById("reportBody");
  body.innerHTML = `
    <style>${modalCSS}</style>
    <div class="report-header">
      <h2>🚨 SECURITY INCIDENT REPORT</h2>
      <h4>Classification: Unauthorized Access Attempt (T1078)</h4>
    </div>
    <div class="report-section">
      <div class="report-title">1. INCIDENT METADATA</div>
      <div class="info-item"><span style="color:var(--dim)">Timestamp:</span> ${new Date().toISOString()}</div>
      <div class="info-item"><span style="color:var(--dim)">Status:</span> INVESTIGATION OPEN</div>
    </div>
    <div style="margin-top:20px;font-family:var(--mono);font-size:12px;color:var(--dim)">
      This auto-generated report contains sensitive telemetry data. Do not distribute outside authorized channels. System logs have been secured via SHA-256 hash validation.
    </div>
  `;
  document.getElementById("reportModal").style.display = "flex";
}

function exportAllReports() {
  showToast("Generating consolidated forensic report...", "success");
}

function printReport() {
  window.print();
}

function copyReport() {
  const el = document.getElementById("reportBody");
  navigator.clipboard.writeText(el.innerText).then(() => {
    showToast("Report copied to clipboard", "success");
  });
}

// Boot Sequence
fetchMyData();
updateStats();
loadHistory();
connectSSE();
