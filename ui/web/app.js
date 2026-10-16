// VeriDex AI - Frontend Reactive Controller (Crema Warm Minimalist Edition)

// Base API configuration: Automatically supports relative routing (Vercel rewrites & Render deployment)
// or an explicit backend URL if configured on window.VERIDEX_API_BASE
const API_BASE = (window.VERIDEX_API_BASE || '').replace(/\/+$/, '');

// Tab Switching
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.remove('active');
    btn.setAttribute('aria-selected', 'false');
  });
  document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
  
  if (event && event.currentTarget) {
    event.currentTarget.classList.add('active');
    event.currentTarget.setAttribute('aria-selected', 'true');
  }

  const targetTab = document.getElementById(`tab-${tabId}`);
  if (targetTab) {
    targetTab.classList.add('active');
  }

  if (tabId === 'threat-vault') {
    loadVaultLogs();
  }
}

// Preset Loaders
function loadSample(url) {
  const input = document.getElementById('urlInput');
  if (input) {
    input.value = url;
    scanUrl();
  }
}

function loadNlpPreset(type) {
  const nlpInput = document.getElementById('nlpInput');
  if (!nlpInput) return;

  if (type === 'urgency') {
    nlpInput.value = "URGENT SECURITY NOTICE: Your PayPal account has been temporarily suspended due to unauthorized access. You must act immediately within 24 hours to confirm your password, SSN, and verify your identity before your account is permanently deleted!";
  } else if (type === 'greed') {
    nlpInput.value = "CONGRATULATIONS! You are selected as the lucky winner of our exclusive crypto lottery. Claim your 5,000 USDT airdrop immediately! Provide your private wallet seed phrase to receive instant cash payout.";
  } else if (type === 'techsupport') {
    nlpInput.value = "CRITICAL WINDOWS DEFENDER ALERT: Virus detected! Trojan horse payload found on your system. Call toll-free Microsoft Support immediately at 1-800-555-0199 and download AnyDesk to allow our technician remote access.";
  } else if (type === 'safe') {
    nlpInput.value = "Hi team, please find attached the meeting minutes and presentation slides from today's architecture review. Let me know if you have any questions before Monday's sync.";
  }
  scanNlp();
}

// URL Scanner
async function scanUrl() {
  const input = document.getElementById('urlInput');
  const url = input ? input.value.trim() : "";
  if (!url) {
    alert("Please enter a valid target URL.");
    return;
  }

  const btn = document.getElementById('btnScanUrl');
  if (btn) {
    btn.innerText = "Analyzing On-Device...";
    btn.disabled = true;
  }

  try {
    const res = await fetch(`${API_BASE}/api/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url, source: 'WEB_DASHBOARD' })
    });
    const data = await res.json();
    renderUrlResult(data);
    loadStats();
  } catch (err) {
    console.error("Scan error:", err);
    alert("Failed to communicate with on-device engine: " + err.message);
  } finally {
    if (btn) {
      btn.innerText = "Verify On-Device";
      btn.disabled = false;
    }
  }
}

function renderUrlResult(data) {
  const container = document.getElementById('urlResultContainer');
  if (!container) return;
  container.classList.remove('hidden');

  // Verdict Header
  const title = document.getElementById('verdictTitle');
  const sub = document.getElementById('verdictSub');
  const badgeLatency = document.getElementById('badgeLatency');
  const badgeEngine = document.getElementById('badgeEngine');
  const badgeCategory = document.getElementById('badgeCategory');

  if (badgeLatency) badgeLatency.innerText = `${data.latency_ms} ms`;
  if (badgeEngine) badgeEngine.innerText = data.engine || "ONNX Runtime";

  if (data.classification && badgeCategory) {
    badgeCategory.innerText = data.classification.type_badge || "GENERAL_WEB";
    if (data.is_threat) {
      badgeCategory.style.borderColor = "var(--red-border)";
      badgeCategory.style.color = "var(--red)";
      badgeCategory.style.background = "var(--red-bg)";
    } else {
      badgeCategory.style.borderColor = "var(--green-border)";
      badgeCategory.style.color = "var(--green)";
      badgeCategory.style.background = "var(--green-bg)";
    }
  }

  if (title) {
    title.innerText = data.verdict;
    title.style.color = data.threat_color;
  }

  if (sub) {
    if (data.is_threat) {
      sub.innerText = data.classification ? data.classification.description : "Threat identified by on-device intelligence. Contextual mitigation triggered.";
    } else {
      sub.innerText = data.classification ? data.classification.description : "URL passed all structural, homoglyph, and on-device ML inspections.";
    }
  }

  // Legitimate Website Recommendation & Popup Modal
  const replicaBox = document.getElementById('replicaRecommendationBox');
  if (data.legitimate_website_suggestion) {
    if (replicaBox) {
      replicaBox.classList.remove('hidden');
      const badge = document.getElementById('replicaBrandBadge');
      if (badge) badge.innerText = data.legitimate_website_suggestion.spoofed_brand || "Verified Brand";
      const warnText = document.getElementById('replicaWarningText');
      if (warnText) warnText.innerText = data.legitimate_website_suggestion.warning_message || "The scanned link appears to be an unauthorized replica. Here is the verified official legal website:";
      const safeLink = document.getElementById('replicaSafeLink');
      if (safeLink) safeLink.href = data.legitimate_website_suggestion.official_url;
      const domText = document.getElementById('replicaOfficialDomain');
      if (domText) domText.innerText = `(${data.legitimate_website_suggestion.official_domain})`;
    }
    // Show pop up modal to redirect to official website
    showReplicaModal(data.url, data.legitimate_website_suggestion);
  } else {
    if (replicaBox) replicaBox.classList.add('hidden');
    closeReplicaModal();
  }

  // Score Circle
  const circle = document.getElementById('scoreCircle');
  const scoreText = document.getElementById('scoreText');
  const confidenceVal = document.getElementById('confidenceVal');

  if (circle) circle.style.borderColor = data.threat_color;
  if (scoreText) {
    scoreText.innerText = `${data.risk_score}%`;
    scoreText.style.color = data.threat_color;
  }
  if (confidenceVal) confidenceVal.innerText = `${data.confidence}%`;

  // Explainable AI (XAI)
  const xaiList = document.getElementById('xaiList');
  if (xaiList) {
    xaiList.innerHTML = '';
    
    if (data.risk_factors && data.risk_factors.length > 0) {
      data.risk_factors.forEach(factor => {
        const li = document.createElement('li');
        const isThreat = data.is_threat;
        li.className = `xai-item ${isThreat ? 'danger' : 'safe'}`;
        li.innerHTML = `<div>${factor}</div>`;
        xaiList.appendChild(li);
      });
    } else {
      const li = document.createElement('li');
      li.className = 'xai-item safe';
      li.innerHTML = `<div>No anomalies or threat cues detected. Normal web profile.</div>`;
      xaiList.appendChild(li);
    }
  }

  // Smooth scroll into results on mobile
  if (window.innerWidth <= 768) {
    container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

// NLP Scanner
async function scanNlp() {
  const input = document.getElementById('nlpInput');
  const text = input ? input.value.trim() : "";
  if (!text) {
    alert("Please paste text content to analyze.");
    return;
  }

  const btn = document.getElementById('btnScanNlp');
  if (btn) {
    btn.innerText = "Analyzing Text...";
    btn.disabled = true;
  }

  try {
    const res = await fetch(`${API_BASE}/api/scan/text`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: text })
    });
    const data = await res.json();
    renderNlpResult(data);
  } catch (err) {
    console.error("NLP error:", err);
    alert("NLP Analysis failed: " + err.message);
  } finally {
    if (btn) {
      btn.innerText = "Analyze Text Cues";
      btn.disabled = false;
    }
  }
}

function renderNlpResult(data) {
  const container = document.getElementById('nlpResultContainer');
  if (!container) return;
  container.classList.remove('hidden');

  const badge = document.getElementById('nlpThreatBadge');
  const summary = document.getElementById('nlpSummaryText');
  const latency = document.getElementById('nlpLatency');
  const cuesGrid = document.getElementById('cuesGrid');

  if (badge) {
    badge.innerText = `${data.threat_level} (${data.risk_score}%)`;
    if (data.threat_level === 'CRITICAL') {
      badge.style.background = 'var(--red-bg)';
      badge.style.color = 'var(--red)';
      badge.style.borderColor = 'var(--red-border)';
    } else if (data.threat_level === 'SUSPICIOUS') {
      badge.style.background = 'var(--amber-bg)';
      badge.style.color = 'var(--amber)';
      badge.style.borderColor = 'var(--amber-border)';
    } else {
      badge.style.background = 'var(--green-bg)';
      badge.style.color = 'var(--green)';
      badge.style.borderColor = 'var(--green-border)';
    }
  }

  if (summary) summary.innerText = data.summary;
  if (latency) latency.innerText = `${data.latency_ms} ms`;

  if (cuesGrid) {
    cuesGrid.innerHTML = '';
    if (data.detected_cues && data.detected_cues.length > 0) {
      data.detected_cues.forEach(cue => {
        const card = document.createElement('div');
        card.className = 'cue-card';
        const tokenPills = cue.matched_tokens.map(t => `<span class="token-pill">${t}</span>`).join(' ');
        card.innerHTML = `
          <h5>${cue.category.replace(/_/g, ' ')} <span>+${cue.category_risk}%</span></h5>
          <p>${cue.description}</p>
          <div class="cue-tokens">${tokenPills}</div>
        `;
        cuesGrid.appendChild(card);
      });
    } else {
      cuesGrid.innerHTML = `
        <div class="cue-card" style="grid-column: 1 / -1;">
          <h5 style="color: var(--green);">No Manipulation Cues Detected</h5>
          <p>Text appears neutral and does not use artificial urgency pressure, fear intimidation, or credential harvesting phrases.</p>
        </div>
      `;
    }
  }
}

// Vault Logs
async function loadVaultLogs() {
  const tbody = document.getElementById('vaultTableBody');
  if (!tbody) return;

  try {
    const res = await fetch(`${API_BASE}/api/vault/logs?limit=50`);
    const logs = await res.json();
    
    if (!logs || logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="table-loading-cell">Vault is clean. No threats recorded yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = '';
    logs.forEach(log => {
      const tr = document.createElement('tr');
      const isThreat = log.is_threat;
      const tagColor = isThreat ? 'var(--red)' : 'var(--green)';
      const tagBg = isThreat ? 'var(--red-bg)' : 'var(--green-bg)';
      const tagBorder = isThreat ? 'var(--red-border)' : 'var(--green-border)';

      tr.innerHTML = `
        <td style="font-family: var(--font-mono); color: var(--text-muted); font-size: 11.5px;">${log.timestamp}</td>
        <td class="url-cell" title="${log.url}">${log.url}</td>
        <td><span class="sample-tag" style="background: ${tagBg}; color: ${tagColor}; border-color: ${tagBorder}; font-weight: 600;">${log.verdict}</span></td>
        <td style="font-family: var(--font-mono); font-weight: 600;">${log.risk_score}%</td>
        <td style="font-family: var(--font-mono); color: var(--brand);">${log.latency_ms} ms</td>
        <td><span class="sample-tag">${log.source}</span></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Vault fetch error:", err);
  }
}

async function clearVault() {
  if (confirm("Are you sure you want to clear the encrypted local threat vault?")) {
    await fetch(`${API_BASE}/api/vault/clear`, { method: 'POST' });
    loadVaultLogs();
    loadStats();
  }
}

function exportVaultReport() {
  window.open(`${API_BASE}/api/vault/logs?limit=500`, '_blank');
}

// Stats Poller
async function loadStats() {
  try {
    const res = await fetch(`${API_BASE}/api/vault/stats`);
    const data = await res.json();
    const setElem = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.innerText = val;
    };
    setElem('metricTotalScans', data.total_scans);
    setElem('metricThreatsBlocked', data.threats_blocked);
    setElem('metricTyposquats', data.typosquats_detected);
    setElem('metricAvgLatency', `${data.avg_latency_ms} ms`);
  } catch (err) {
    console.error("Stats load error:", err);
  }
}

// Latency Benchmark
async function runBenchmark() {
  const btn = document.getElementById('btnBench');
  if (btn) {
    btn.innerText = "Running Stress Test...";
    btn.disabled = true;
  }

  try {
    const res = await fetch(`${API_BASE}/api/benchmark`);
    const data = await res.json();
    
    const results = document.getElementById('benchResults');
    if (results) results.classList.remove('hidden');

    const setElem = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.innerText = val;
    };
    setElem('benchAvg', `${data.avg_latency_ms} ms`);
    setElem('benchMin', `${data.min_latency_ms} ms`);
    setElem('benchP95', `${data.p95_latency_ms} ms`);
    setElem('benchEngine', data.engine);
  } catch (err) {
    alert("Benchmark failed: " + err.message);
  } finally {
    if (btn) {
      btn.innerText = "Run Latency Stress Test";
      btn.disabled = false;
    }
  }
}

// CSV Batch Scam Scanning & Model Retraining
async function runCsvBatchScan() {
  const btn = document.getElementById('btnRunCsvScan');
  if (btn) {
    btn.innerText = "Scanning CSV on CPU...";
    btn.disabled = true;
  }

  try {
    const res = await fetch(`${API_BASE}/api/scan/csv`, { method: 'POST' });
    const data = await res.json();

    const strip = document.getElementById('csvSummaryStrip');
    if (strip) strip.classList.remove('hidden');

    const setElem = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.innerText = val;
    };
    setElem('csvTotalRows', data.total_scanned);
    setElem('csvThreatsFound', data.threats_found);
    setElem('csvSafeFound', data.safe_found);
    setElem('csvThreatRatio', `${data.threat_ratio_percent}%`);

    // Populate Table
    const tbody = document.getElementById('csvTableBody');
    if (tbody) {
      tbody.innerHTML = '';

      data.all_results.forEach(r => {
        const tr = document.createElement('tr');
        const isScam = r.is_scam;
        const tagColor = isScam ? 'var(--red)' : 'var(--green)';
        const badgeBg = isScam ? 'var(--red-bg)' : 'var(--green-bg)';
        const badgeBorder = isScam ? 'var(--red-border)' : 'var(--green-border)';
        const factorsText = r.risk_factors && r.risk_factors.length > 0 ? r.risk_factors.slice(0, 2).join('; ') : 'Normal web profile';

        tr.innerHTML = `
          <td style="color: var(--text-muted); font-family: var(--font-mono);">${r.row_index}</td>
          <td class="url-cell" title="${r.url}">${r.url}</td>
          <td><span class="sample-tag" style="background: ${badgeBg}; color: ${tagColor}; border-color: ${badgeBorder}; font-weight: 700;">${r.verdict}</span></td>
          <td style="font-family: var(--font-mono); font-weight: 600;">${r.risk_score}%</td>
          <td><span class="sample-tag">${r.type_badge}</span></td>
          <td style="font-size: 12px; color: var(--text-muted); max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${factorsText}</td>
        `;
        tbody.appendChild(tr);
      });
    }

    loadStats();
  } catch (err) {
    alert("CSV Scan failed: " + err.message);
  } finally {
    if (btn) {
      btn.innerText = "Scan All URLs in CSV";
      btn.disabled = false;
    }
  }
}

async function retrainModelFromCsv() {
  const btn = document.getElementById('btnRetrainCsv');
  if (btn) {
    btn.innerText = "Training Model from CSV...";
    btn.disabled = true;
  }

  try {
    const res = await fetch(`${API_BASE}/api/model/retrain`, { method: 'POST' });
    const data = await res.json();

    const alertBox = document.getElementById('retrainAlertBox');
    if (alertBox) alertBox.classList.remove('hidden');

    const msg = document.getElementById('retrainMessage');
    if (msg) msg.innerText = data.message;

    const metricsBox = document.getElementById('retrainMetricsGrid');
    if (metricsBox && data.metrics) {
      const m = data.metrics;
      metricsBox.innerHTML = `
        <div class="badge-chip" style="color: var(--green);">Accuracy: ${m.accuracy}%</div>
        <div class="badge-chip" style="color: var(--blue);">Precision: ${m.precision}%</div>
        <div class="badge-chip" style="color: var(--brand);">Recall: ${m.recall}%</div>
        <div class="badge-chip" style="color: var(--amber);">F1 Score: ${m.f1_score}%</div>
        <div class="badge-chip">Rows: ${m.total_training_samples}</div>
        <div class="badge-chip">Features: ${m.features_count}</div>
      `;
    }

    loadStats();
    alert("Model successfully retrained from data/veridex_dataset.csv and compiled into ONNX runtime format.");
  } catch (err) {
    alert("Retraining failed: " + err.message);
  } finally {
    if (btn) {
      btn.innerText = "Retrain Model from CSV";
      btn.disabled = false;
    }
  }
}

function exportCsvResults() {
  window.open(`${API_BASE}/api/scan/csv`, '_blank');
}

// Popup Modal: Redirect to Official Website of Replica Scam Website
function showReplicaModal(scannedUrl, suggestion) {
  const modal = document.getElementById('replicaRedirectModal');
  if (!modal || !suggestion) return;

  const brandBadge = document.getElementById('modalBrandBadge');
  const title = document.getElementById('modalTitle');
  const desc = document.getElementById('modalDesc');
  const scannedEl = document.getElementById('modalScannedUrl');
  const officialEl = document.getElementById('modalOfficialDomain');
  const redirectBtn = document.getElementById('modalRedirectLink');

  const brandName = suggestion.spoofed_brand || "Verified Brand";
  const officialDomain = suggestion.official_domain || "";
  const legalEntity = suggestion.legal_entity ? ` (${suggestion.legal_entity})` : "";
  const officialUrl = suggestion.official_url || "#";

  if (brandBadge) brandBadge.innerText = brandName;
  if (title) title.innerText = `Unauthorized ${brandName} Replica Alert`;
  if (desc) desc.innerText = suggestion.warning_message || `The scanned link appears to be an unauthorized replica impersonating ${brandName}. Never enter credentials, passwords, or personal data on this site.`;
  if (scannedEl) scannedEl.innerText = scannedUrl || "-";
  if (officialEl) officialEl.innerText = `${officialDomain}${legalEntity}`;
  if (redirectBtn) {
    redirectBtn.href = officialUrl;
    const btnSpan = redirectBtn.querySelector('span');
    if (btnSpan) btnSpan.innerText = `Redirect to Official ${brandName} Website`;
  }

  modal.classList.remove('hidden');
}

function closeReplicaModal() {
  const modal = document.getElementById('replicaRedirectModal');
  if (modal) modal.classList.add('hidden');
}

// Global modal dismiss listeners (Escape key & backdrop click)
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeReplicaModal();
});

// Initialization
window.addEventListener('DOMContentLoaded', () => {
  loadStats();
  const modalEl = document.getElementById('replicaRedirectModal');
  if (modalEl) {
    modalEl.addEventListener('click', (e) => {
      if (e.target === modalEl) closeReplicaModal();
    });
  }
});
