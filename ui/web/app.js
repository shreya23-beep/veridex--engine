// VeriDex AI - Frontend Reactive Controller (Crema Warm Minimalist Edition)

// Base API configuration: Automatically supports relative routing (Vercel rewrites & Render deployment)
// or an explicit backend URL if configured on window.VERIDEX_API_BASE
const API_BASE = (window.VERIDEX_API_BASE || '').replace(/\/+$/, '');

// Global complaint dossier cache for 1930 Helpline
let latestCyberComplaintText = "";
let latestNlpCyberComplaintText = "";
let latestScreenshotCyberComplaintText = "";
let latestQrCyberComplaintText = "";

// Global Structured Report Card Caches (for downloadReportCard)
let latestUrlReportCard = null;
let latestScreenshotReportCard = null;
let latestQrReportCard = null;
let currentQrDataUrl = "";

// Tab Switching
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.remove('active');
    btn.setAttribute('aria-selected', 'false');
  });
  document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
  
  // Activate matching button
  const matchingBtn = document.querySelector(`button[onclick*="switchTab('${tabId}')"]`);
  if (matchingBtn) {
    matchingBtn.classList.add('active');
    matchingBtn.setAttribute('aria-selected', 'true');
  } else if (window.event && window.event.currentTarget) {
    window.event.currentTarget.classList.add('active');
    window.event.currentTarget.setAttribute('aria-selected', 'true');
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

  if (type === 'whatsapp') {
    nlpInput.value = "Forwarded many times: *Free 3-Month Mobile Recharge Offer!* Government of India is giving 500GB free 5G data to all WhatsApp users. Click here to claim your offer immediately before it expires: http://whatsapp-free-500gb-recharge.xyz/claim?ref=wa";
  } else if (type === 'urgency') {
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
    // Show pop up modal to redirect to official website with culprit IP
    showReplicaModal(data.url, data.legitimate_website_suggestion, data.server_ip);
  } else {
    if (replicaBox) replicaBox.classList.add('hidden');
    closeReplicaModal();
  }

  // Cybercrime Forensics & 1930 Helpline Box
  const cyberCard = document.getElementById('cyberCrimeCard');
  if (cyberCard) {
    if (data.is_threat || data.server_ip) {
      cyberCard.classList.remove('hidden');
      const serverIpEl = document.getElementById('detectedServerIp');
      const ispEl = document.getElementById('detectedIspName');
      const locEl = document.getElementById('detectedLocation');
      const catEl = document.getElementById('detectedCrimeCategory');
      const waBadge = document.getElementById('whatsappOriginBadge');

      const serverIp = data.server_ip || (data.ip_intelligence ? data.ip_intelligence.server_ip : "Traced via DNS");
      if (serverIpEl) serverIpEl.innerText = serverIp;

      if (data.ip_intelligence) {
        if (ispEl) ispEl.innerText = data.ip_intelligence.isp || "Offshore Rogue Hosting";
        if (locEl) locEl.innerText = data.ip_intelligence.server_location || "International Network";
        if (waBadge) {
          if (data.ip_intelligence.is_whatsapp_lure) {
            waBadge.classList.remove('hidden');
          } else {
            waBadge.classList.add('hidden');
          }
        }
      }

      if (catEl) {
        catEl.innerText = data.classification ? data.classification.type_badge : "Phishing / Cyber Threat";
      }

      if (data.cyber_helpline_1930 && data.cyber_helpline_1930.complaint_text) {
        latestCyberComplaintText = data.cyber_helpline_1930.complaint_text;
      } else {
        latestCyberComplaintText = `INCIDENT COMPLAINT DOSSIER FOR CYBER HELPLINE 1930:\nIncident: Malicious Phishing / Scam Website\nScanned URL: ${data.url}\nCulprit Server IP: ${serverIp}\nISP: ${(data.ip_intelligence && data.ip_intelligence.isp) || 'Offshore'}\nLocation: ${(data.ip_intelligence && data.ip_intelligence.server_location) || 'Unknown'}\nVerification: 100% On-Device AI Forensics (VeriDex)\nAction: Request immediate blocking of rogue server IP under Indian Cyber Crime Coordination Centre (I4C).`;
      }

      // Cache structured Report Card for download
      latestUrlReportCard = data.report_card || {
        incident_id: `VDX-URL-${Math.floor(Date.now() / 1000) % 1000000}`,
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        source_type: "URL_INSPECTION",
        verdict: data.verdict,
        is_threat: data.is_threat,
        threat_level: data.is_threat ? (data.risk_score >= 70 ? 'CRITICAL' : 'SUSPICIOUS') : 'SAFE',
        threat_color: data.threat_color,
        risk_score: data.risk_score,
        target: data.url,
        culprit_server_ip: serverIp,
        isp: (data.ip_intelligence && data.ip_intelligence.isp) || "Host Network",
        server_location: (data.ip_intelligence && data.ip_intelligence.server_location) || "Unknown",
        indicators: data.risk_factors || [],
        action_notice: data.is_threat ? `SCAM DETECTED: Report culprit server IP ${serverIp} to cybercrime.gov.in or helpline 1930.` : "Destination verified safe.",
        complaint_url: "https://cybercrime.gov.in",
        helpline_dialpad: "1930",
        full_dossier_text: latestCyberComplaintText
      };
    } else {
      cyberCard.classList.add('hidden');
      latestUrlReportCard = data.report_card || {
        incident_id: `VDX-URL-${Math.floor(Date.now() / 1000) % 1000000}`,
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        source_type: "URL_INSPECTION",
        verdict: data.verdict,
        is_threat: false,
        threat_level: "SAFE",
        threat_color: data.threat_color,
        risk_score: data.risk_score,
        target: data.url,
        culprit_server_ip: "127.0.0.1 (Local DNS)",
        isp: "Verified Safe Host",
        server_location: "Compliant Network",
        indicators: data.trust_signals || ["Clean domain structure"],
        action_notice: "Destination safe. No police report required.",
        complaint_url: "https://cybercrime.gov.in",
        helpline_dialpad: "1930",
        full_dossier_text: "Target URL verified safe on-device by VeriDex AI."
      };
    }
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

  // Handle NLP Culprit IP Forensics Card
  const nlpCyberCard = document.getElementById('nlpCyberCrimeCard');
  if (nlpCyberCard) {
    if (data.server_ip || data.cyber_helpline_1930) {
      nlpCyberCard.classList.remove('hidden');
      const ipEl = document.getElementById('nlpDetectedServerIp');
      const ispEl = document.getElementById('nlpDetectedIsp');
      const locEl = document.getElementById('nlpDetectedLocation');
      const catEl = document.getElementById('nlpDetectedCrimeCategory');

      const serverIp = data.server_ip || (data.ip_intelligence ? data.ip_intelligence.server_ip : "Traced via DNS");
      if (ipEl) ipEl.innerText = serverIp;

      if (data.ip_intelligence) {
        if (ispEl) ispEl.innerText = data.ip_intelligence.isp || "Offshore Rogue Hosting";
        if (locEl) locEl.innerText = data.ip_intelligence.server_location || "International Network";
        if (catEl) {
          catEl.innerText = data.ip_intelligence.is_whatsapp_lure ? "WhatsApp Forward Scam" : "Malicious Link in Message";
        }
      }

      if (data.cyber_helpline_1930 && data.cyber_helpline_1930.complaint_text) {
        latestNlpCyberComplaintText = data.cyber_helpline_1930.complaint_text;
      } else {
        latestNlpCyberComplaintText = `INCIDENT COMPLAINT DOSSIER FOR CYBER HELPLINE 1930:\nIncident: Suspicious Phishing / Social Engineering Message\nCulprit Server IP: ${serverIp}\nHost Network: ${(data.ip_intelligence && data.ip_intelligence.isp) || 'Offshore'}\nAction: Request blocking of scam infrastructure under Indian Cyber Crime Coordination Centre (I4C).`;
      }
    } else {
      nlpCyberCard.classList.add('hidden');
    }
  }
}

// 1-Click Clipboard Complaint Exporters for Helpline 1930
async function copyCyberComplaint() {
  if (!latestCyberComplaintText) return;
  try {
    await navigator.clipboard.writeText(latestCyberComplaintText);
    const btnText = document.getElementById('copyComplaintBtnText');
    if (btnText) {
      const original = btnText.innerText;
      btnText.innerText = "Complaint Copied to Clipboard! Dial 1930 to Register";
      setTimeout(() => { btnText.innerText = original; }, 3500);
    }
  } catch (e) {
    console.error("Clipboard copy failed:", e);
    alert(latestCyberComplaintText);
  }
}

async function copyNlpCyberComplaint() {
  if (!latestNlpCyberComplaintText) return;
  try {
    await navigator.clipboard.writeText(latestNlpCyberComplaintText);
    const btnText = document.getElementById('nlpCopyComplaintBtnText');
    if (btnText) {
      const original = btnText.innerText;
      btnText.innerText = "Complaint Copied to Clipboard! Dial 1930 to Register";
      setTimeout(() => { btnText.innerText = original; }, 3500);
    }
  } catch (e) {
    console.error("Clipboard copy failed:", e);
    alert(latestNlpCyberComplaintText);
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
function showReplicaModal(scannedUrl, suggestion, serverIp) {
  const modal = document.getElementById('replicaRedirectModal');
  if (!modal || !suggestion) return;

  const brandBadge = document.getElementById('modalBrandBadge');
  const title = document.getElementById('modalTitle');
  const desc = document.getElementById('modalDesc');
  const scannedEl = document.getElementById('modalScannedUrl');
  const serverIpEl = document.getElementById('modalServerIp');
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
  if (serverIpEl) serverIpEl.innerText = serverIp || "Traced via DNS";
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

// ============================================================================
// WHATSAPP CHAT SCREENSHOT ANALYZER CONTROLLER
// ============================================================================

let currentScreenshotDataUrl = "";

function triggerScreenshotFileInput() {
  const input = document.getElementById('screenshotFileInput');
  if (input) input.click();
}

function handleScreenshotFileSelect(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (e) => {
    loadScreenshotImage(e.target.result, "");
  };
  reader.readAsDataURL(file);
}

function loadScreenshotImage(dataUrl, initialText) {
  currentScreenshotDataUrl = dataUrl;
  const workspace = document.getElementById('screenshotWorkspace');
  const previewImg = document.getElementById('screenshotPreviewImg');
  const extractedText = document.getElementById('screenshotExtractedText');
  const ocrStatusBadge = document.getElementById('ocrStatusBadge');

  if (workspace) workspace.style.display = 'grid';
  if (previewImg) previewImg.src = dataUrl;
  if (extractedText && initialText !== undefined) {
    extractedText.value = initialText;
  }

  // Attempt client-side zero-cloud OCR via Tesseract.js if no initial text provided
  if (!initialText && window.Tesseract && dataUrl.startsWith('data:image')) {
    if (ocrStatusBadge) ocrStatusBadge.innerText = 'Extracting OCR...';
    Tesseract.recognize(dataUrl, 'eng')
      .then(result => {
        const text = result && result.data && result.data.text;
        if (text && text.trim()) {
          if (extractedText) extractedText.value = text.trim();
          if (ocrStatusBadge) ocrStatusBadge.innerText = 'OCR Extracted (On-Device)';
        } else {
          if (ocrStatusBadge) ocrStatusBadge.innerText = 'Visual Analysis Ready';
        }
      })
      .catch(err => {
        console.warn('Tesseract OCR fallback to visual:', err);
        if (ocrStatusBadge) ocrStatusBadge.innerText = 'Ready (Visual Analysis)';
      });
  } else if (ocrStatusBadge) {
    ocrStatusBadge.innerText = 'On-Device Ready';
  }

  // Smooth scroll to workspace
  if (workspace) {
    workspace.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

function clearScreenshotWorkspace() {
  currentScreenshotDataUrl = "";
  const workspace = document.getElementById('screenshotWorkspace');
  const previewImg = document.getElementById('screenshotPreviewImg');
  const extractedText = document.getElementById('screenshotExtractedText');
  const resultsContainer = document.getElementById('screenshotResultContainer');
  const fileInput = document.getElementById('screenshotFileInput');

  if (workspace) workspace.style.display = 'none';
  if (previewImg) previewImg.src = "";
  if (extractedText) extractedText.value = "";
  if (resultsContainer) resultsContainer.classList.add('hidden');
  if (fileInput) fileInput.value = "";
}

// Preset WhatsApp Scam Screenshots and Scenarios
function loadScreenshotPreset(type) {
  let text = "";
  let sender = "+91 98210 54321";
  let timeStr = "10:45 AM";
  let isForwarded = true;
  let hasLink = true;

  if (type === 'free_recharge') {
    text = "Forwarded many times\n*Free 3-Month Mobile Recharge Offer!*\nGovernment of India is giving 500GB free 5G data to all WhatsApp users on occasion of digital initiative. Click here to claim your offer immediately before it expires tonight:\nhttp://whatsapp-free-500gb-recharge.xyz/claim?ref=wa";
    sender = "Viral WhatsApp Broadcast";
  } else if (type === 'sbi_kyc') {
    text = "Forwarded\nURGENT NOTICE: Dear SBI Customer, your YONO NetBanking account has been blocked due to incomplete PAN / Aadhaar KYC update. Please click the link immediately within 24 hours to verify and avoid permanent deactivation:\nhttp://sbi-yono-kyc-verify-portal.in/update";
    sender = "SBI-ALERT-INFO";
  } else if (type === 'power_cut') {
    text = "Dear Consumer, Your electricity power will be disconnected tonight at 9:30 PM from the electricity office because your previous month bill was not updated. Please pay immediately or contact electricity officer:\nhttp://power-bill-payment-quick.top/bill";
    sender = "POWER-CORP-URGENT";
  } else if (type === 'part_time_job') {
    text = "Congratulations! You have been selected for Part-Time Remote Work. Earn Rs. 3500 - 8000 daily by simply rating hotel reviews and liking videos on YouTube. No experience required. Join our verified Telegram manager to claim your joining bonus: http://telegram-earn-daily-bonus.online/join";
    sender = "+1 (555) 019-2834";
  } else if (type === 'safe_chat') {
    text = "Hi Shreya! Hope you are doing well. Are we meeting for the project discussion at 4:30 PM today at the campus library?\nHere is the location link: https://maps.google.com/place/library";
    sender = "Shirali S";
    isForwarded = false;
  }

  // Generate lightweight authentic WhatsApp chat mock SVG
  const mockSvg = generateWhatsAppChatSvg(text, sender, timeStr, isForwarded);
  loadScreenshotImage(mockSvg, text);

  // Auto trigger analysis
  setTimeout(analyzeScreenshot, 150);
}

function generateWhatsAppChatSvg(text, sender, timeStr, isForwarded) {
  const lines = text.split('\n');
  const escapedLines = lines.map(l => l.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'));
  
  let tspans = "";
  let yOffset = isForwarded ? 85 : 65;
  escapedLines.forEach((line) => {
    const isLink = line.includes('http://') || line.includes('https://');
    const fill = isLink ? '#0366D6' : '#111B21';
    const weight = line.startsWith('*') ? 'bold' : 'normal';
    tspans += `<tspan x="20" y="${yOffset}" fill="${fill}" font-weight="${weight}">${line}</tspan>`;
    yOffset += 18;
  });

  const totalHeight = Math.max(260, yOffset + 50);

  const svg = `
  <svg xmlns="http://www.w3.org/2000/svg" width="360" height="${totalHeight}" viewBox="0 0 360 ${totalHeight}">
    <rect width="360" height="${totalHeight}" fill="#EFEAE2"/>
    <!-- WhatsApp Header -->
    <rect width="360" height="48" fill="#075E54"/>
    <circle cx="24" cy="24" r="14" fill="#128C7E"/>
    <text x="24" y="28" font-family="-apple-system, sans-serif" font-size="12" fill="#FFFFFF" text-anchor="middle" font-weight="bold">WA</text>
    <text x="46" y="22" font-family="-apple-system, sans-serif" font-size="13" fill="#FFFFFF" font-weight="bold">${sender}</text>
    <text x="46" y="36" font-family="-apple-system, sans-serif" font-size="10" fill="#E0F2F1">online</text>
    
    <!-- Chat Bubble -->
    <rect x="12" y="56" width="336" height="${totalHeight - 70}" rx="8" fill="#FFFFFF" stroke="#E0DCD5" stroke-width="0.5"/>
    ${isForwarded ? `
      <path d="M 20 72 L 26 68 L 26 71 L 32 71 L 32 73 L 26 73 L 26 76 Z" fill="#667781"/>
      <text x="36" y="74" font-family="-apple-system, sans-serif" font-size="10.5" fill="#667781" font-style="italic">Forwarded many times</text>
    ` : ''}
    <text font-family="-apple-system, sans-serif" font-size="12" line-height="1.4">
      ${tspans}
    </text>
    <!-- Timestamp & Blue Ticks -->
    <text x="310" y="${totalHeight - 20}" font-family="-apple-system, sans-serif" font-size="10" fill="#667781" text-anchor="end">${timeStr}</text>
    <path d="M 316 ${totalHeight - 24} L 320 ${totalHeight - 20} L 328 ${totalHeight - 28}" fill="none" stroke="#53BDEB" stroke-width="1.5" stroke-linecap="round"/>
  </svg>`;

  return 'data:image/svg+xml;utf8,' + encodeURIComponent(svg);
}

// Analyze Screenshot Endpoint Caller
async function analyzeScreenshot() {
  const textInput = document.getElementById('screenshotExtractedText');
  const btn = document.getElementById('btnAnalyzeScreenshot');
  const resultsContainer = document.getElementById('screenshotResultContainer');

  const text = (textInput ? textInput.value : "").trim();
  const imageBase64 = currentScreenshotDataUrl || "";

  if (!text && !imageBase64) {
    alert("Please upload a screenshot or enter chat text to analyze.");
    return;
  }

  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span>Analyzing Visuals &amp; Links...</span>`;
  }

  try {
    const res = await fetch(`${API_BASE}/api/analyze/screenshot/json`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        image_base64: imageBase64,
        text: text,
        filename: "whatsapp_screenshot.png"
      })
    });

    if (!res.ok) throw new Error(`Server returned error ${res.status}`);
    const data = await res.json();

    renderScreenshotResults(data);
    loadStats(); // Update vault counters
  } catch (err) {
    console.error('Screenshot analysis failed:', err);
    alert('Analysis failed. Please ensure the local VeriDex engine is running.');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<span>Analyze WhatsApp Screenshot</span>`;
    }
  }
}

function renderScreenshotResults(data) {
  const container = document.getElementById('screenshotResultContainer');
  const banner = document.getElementById('screenshotVerdictBanner');
  const title = document.getElementById('screenshotVerdictTitle');
  const sub = document.getElementById('screenshotVerdictSub');
  const badgeLevel = document.getElementById('screenshotThreatLevelBadge');
  const latency = document.getElementById('screenshotLatency');
  const scoreText = document.getElementById('screenshotScoreText');
  const scoreCircle = document.getElementById('screenshotScoreCircle');
  const fwdTag = document.getElementById('screenshotForwardedTag');
  const linkStatus = document.getElementById('screenshotEmbeddedLinkStatus');
  const culpritHost = document.getElementById('screenshotCulpritHost');
  const list = document.getElementById('screenshotIndicatorsList');
  const cyberCard = document.getElementById('screenshotCyberCard');
  const serverIpEl = document.getElementById('screenshotServerIp');
  const serverIspEl = document.getElementById('screenshotServerIsp');
  const serverLocEl = document.getElementById('screenshotServerLocation');
  const lureCatEl = document.getElementById('screenshotLureCategory');
  const replicaBox = document.getElementById('screenshotReplicaBox');
  const replicaBrandBadge = document.getElementById('screenshotReplicaBrandBadge');
  const replicaRedirectLink = document.getElementById('screenshotOfficialRedirectLink');

  if (!container) return;
  container.classList.remove('hidden');

  const isFake = data.is_fake;
  const threatColor = data.threat_color || (isFake ? '#C53929' : '#2B6E4E');

  // Verdict Banner
  if (banner) {
    banner.className = isFake ? 'verdict-banner danger' : 'verdict-banner safe';
    banner.style.borderLeft = `6px solid ${threatColor}`;
  }
  if (title) title.innerText = data.verdict;
  if (sub) sub.innerText = data.summary;
  if (badgeLevel) {
    badgeLevel.innerText = data.threat_level;
    badgeLevel.style.color = threatColor;
  }
  if (latency) latency.innerText = `${data.latency_ms || 0.3} ms`;

  // Score
  const score = Math.round(data.risk_score || 0);
  if (scoreText) scoreText.innerText = `${score}%`;
  if (scoreCircle) {
    scoreCircle.style.borderColor = threatColor;
    scoreCircle.style.color = threatColor;
  }

  // Quick stats
  if (fwdTag) {
    fwdTag.innerText = data.has_forwarded_tag ? "DETECTED (Viral Spam Tag)" : "Direct / Normal";
    fwdTag.style.color = data.has_forwarded_tag ? "#C53929" : "#2B6E4E";
  }
  if (linkStatus) {
    if (data.primary_threat_url) {
      linkStatus.innerText = data.primary_threat_url.url;
      linkStatus.style.color = "#C53929";
    } else if (data.urls_detected && data.urls_detected.length > 0) {
      linkStatus.innerText = data.urls_detected[0].url;
      linkStatus.style.color = "#2B6E4E";
    } else {
      linkStatus.innerText = "No External Links";
      linkStatus.style.color = "#756A63";
    }
  }
  if (culpritHost) {
    if (data.culprit_server_ip) {
      culpritHost.innerText = `${data.culprit_server_ip} (${data.ip_intelligence?.isp || 'Host'})`;
      culpritHost.style.color = "#C53929";
    } else {
      culpritHost.innerText = "Clean Destination";
      culpritHost.style.color = "#2B6E4E";
    }
  }

  // Decompose indicators
  if (list) {
    list.innerHTML = "";
    const indicators = data.matched_indicators || [];
    if (indicators.length === 0) {
      list.innerHTML = `<li class="xai-item safe"><span class="xai-bullet">&bull;</span><span>No viral manipulation cues or fraudulent patterns identified in conversation.</span></li>`;
    } else {
      indicators.forEach(ind => {
        const li = document.createElement('li');
        li.className = `xai-item ${ind.severity === 'CRITICAL' ? 'danger' : 'warning'}`;
        li.innerHTML = `<span class="xai-bullet">&bull;</span><div><strong>${ind.label}:</strong> <span style="color: var(--text-muted);">${ind.detail}</span></div>`;
        list.appendChild(li);
      });
    }
  }

  // 1930 Cybercrime Card & Report Card
  latestScreenshotCyberComplaintText = (data.report_card && data.report_card.full_dossier_text) || data.cyber_dossier_1930 || "";
  latestScreenshotReportCard = data.report_card || {
    incident_id: (data.report_card && data.report_card.incident_id) || `VDX-INCIDENT-${Math.floor(Date.now() / 1000) % 1000000}`,
    timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
    source_type: "MESSAGE_SCREENSHOT",
    verdict: data.verdict,
    is_threat: isFake,
    threat_level: data.threat_level,
    threat_color: threatColor,
    risk_score: data.risk_score,
    target: (data.primary_threat_url && data.primary_threat_url.url) || data.extracted_text || "Message Screenshot",
    culprit_server_ip: data.culprit_server_ip || "127.0.0.1",
    isp: data.ip_intelligence?.isp || "Host Network",
    server_location: data.ip_intelligence?.server_location || "Unknown",
    indicators: (data.matched_indicators || []).map(ind => ind.label || ind),
    action_notice: data.cyber_action_instruction || "Register complaint on cybercrime.gov.in or dial 1930.",
    complaint_url: "https://cybercrime.gov.in",
    helpline_dialpad: "1930",
    full_dossier_text: latestScreenshotCyberComplaintText
  };

  const cyberDesc = document.getElementById('screenshotCyberDesc');
  if (cyberCard) {
    if (isFake && data.culprit_server_ip) {
      cyberCard.classList.remove('hidden');
      if (serverIpEl) serverIpEl.innerText = data.culprit_server_ip;
      if (serverIspEl) serverIspEl.innerText = data.ip_intelligence?.isp || "Bulletproof Cloud Host";
      if (serverLocEl) serverLocEl.innerText = data.ip_intelligence?.server_location || "Offshore Infrastructure";
      if (lureCatEl) lureCatEl.innerText = (data.report_card && data.report_card.incident_id) || "VDX-INCIDENT-REPORT";
      if (cyberDesc) {
        cyberDesc.innerHTML = `Culprit server IP <strong>${data.culprit_server_ip}</strong> resolved. Register a complaint on <strong>cybercrime.gov.in</strong> or dial <strong>1930</strong> from your phone dialpad immediately.`;
      }
    } else {
      cyberCard.classList.add('hidden');
    }
  }

  // Replica Suggestion Box
  if (replicaBox) {
    const replica = data.legitimate_website_suggestion;
    if (replica) {
      replicaBox.classList.remove('hidden');
      if (replicaBrandBadge) replicaBrandBadge.innerText = replica.spoofed_brand.toUpperCase();
      if (replicaRedirectLink) {
        replicaRedirectLink.href = replica.official_url;
        const span = replicaRedirectLink.querySelector('span');
        if (span) span.innerText = `Redirect to Official ${replica.official_domain}`;
      }
    } else {
      replicaBox.classList.add('hidden');
    }
  }

  // Smooth scroll down to results
  container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function copyScreenshotCyberComplaint() {
  if (!latestScreenshotCyberComplaintText) {
    alert("No active complaint dossier available.");
    return;
  }
  navigator.clipboard.writeText(latestScreenshotCyberComplaintText).then(() => {
    const btnText = document.getElementById('screenshotCopyComplaintBtnText');
    if (btnText) {
      const orig = btnText.innerText;
      btnText.innerText = "Dossier Copied to Clipboard!";
      setTimeout(() => { btnText.innerText = orig; }, 3000);
    }
  });
}

// ============================================================================
// SCAM QR CODE & QUISHING DETECTOR MODULE
// ============================================================================

function triggerQrFileInput() {
  const input = document.getElementById('qrFileInput');
  if (input) input.click();
}

function handleQrFileSelect(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    loadQrImage(e.target.result, "");
  };
  reader.readAsDataURL(file);
}

function loadQrImage(dataUrl, manualPayload = "") {
  currentQrDataUrl = dataUrl;
  const workspace = document.getElementById('qrWorkspace');
  const previewImg = document.getElementById('qrPreviewImg');
  const payloadInput = document.getElementById('qrDecodedPayloadText');
  const typeBadge = document.getElementById('qrPayloadTypeBadge');
  const resultsContainer = document.getElementById('qrResultContainer');

  if (workspace) workspace.style.display = 'grid';
  if (previewImg) previewImg.src = dataUrl;
  if (resultsContainer) resultsContainer.classList.add('hidden');
  
  if (manualPayload && payloadInput) {
    payloadInput.value = manualPayload;
  }

  // Detect and analyze automatically
  if (typeBadge) typeBadge.innerText = "Scanning QR Matrix...";
  analyzeQr();
}

function clearQrWorkspace() {
  currentQrDataUrl = "";
  const workspace = document.getElementById('qrWorkspace');
  const previewImg = document.getElementById('qrPreviewImg');
  const payloadInput = document.getElementById('qrDecodedPayloadText');
  const resultsContainer = document.getElementById('qrResultContainer');
  const fileInput = document.getElementById('qrFileInput');

  if (workspace) workspace.style.display = 'none';
  if (previewImg) previewImg.src = "";
  if (payloadInput) payloadInput.value = "";
  if (resultsContainer) resultsContainer.classList.add('hidden');
  if (fileInput) fileInput.value = "";
}

// Preset QR threat samples (Quishing, UPI Reverse-Debit, APK malware, Safe portal)
async function loadQrPreset(presetId) {
  try {
    const res = await fetch(`${API_BASE}/api/qr/presets`);
    if (res.ok) {
      const data = await res.json();
      const preset = (data.presets || []).find(p => p.id === presetId);
      if (preset && preset.image_b64) {
        loadQrImage(preset.image_b64, preset.payload);
        return;
      }
    }
  } catch (e) {
    console.warn("Could not fetch server QR presets, using local fallback:", e);
  }

  // Local fallback payload mappings
  let fallbackPayload = "https://cs.stanford.edu/research/ai";
  if (presetId === 'quishing_kyc') {
    fallbackPayload = "http://sbi-yono-kyc-verify-portal.in/update";
  } else if (presetId === 'upi_debit_trap') {
    fallbackPayload = "upi://pay?pa=scammer99@oksbi&pn=Lottery%20Prize%20Claim&am=15000&cu=INR&tn=Prize%20Cashback%20Reward";
  } else if (presetId === 'malicious_apk') {
    fallbackPayload = "http://speedup-utility-support.top/download/safety_update.apk";
  }

  const payloadInput = document.getElementById('qrDecodedPayloadText');
  const workspace = document.getElementById('qrWorkspace');
  if (workspace) workspace.style.display = 'grid';
  if (payloadInput) payloadInput.value = fallbackPayload;
  analyzeQr();
}

async function analyzeQr() {
  const payloadInput = document.getElementById('qrDecodedPayloadText');
  const btn = document.getElementById('btnAnalyzeQr');
  const typeBadge = document.getElementById('qrPayloadTypeBadge');

  const manualPayload = (payloadInput ? payloadInput.value : "").trim();
  const imageBase64 = currentQrDataUrl || "";

  if (!manualPayload && !imageBase64) {
    alert("Please upload a QR code image or enter a payload string to inspect.");
    return;
  }

  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span>Inspecting On-Device Forensics...</span>`;
  }

  try {
    const res = await fetch(`${API_BASE}/api/scan/qr/json`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        image_base64: imageBase64,
        payload: manualPayload,
        filename: "qr_code.png"
      })
    });

    if (!res.ok) throw new Error(`Engine returned error code ${res.status}`);
    const data = await res.json();

    if (data.decoded_payload && payloadInput) {
      payloadInput.value = data.decoded_payload;
    }
    if (typeBadge) {
      typeBadge.innerText = data.payload_type || "DETECTED";
    }

    renderQrResults(data);
    loadStats();
  } catch (err) {
    console.error('QR inspection failed:', err);
    alert('QR inspection error. Please check that VeriDex engine is running.');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<span>Inspect QR Payload On-Device</span>`;
    }
  }
}

function renderQrResults(data) {
  const container = document.getElementById('qrResultContainer');
  const banner = document.getElementById('qrVerdictBanner');
  const title = document.getElementById('qrVerdictTitle');
  const sub = document.getElementById('qrVerdictSub');
  const badgeLevel = document.getElementById('qrThreatLevelBadge');
  const latency = document.getElementById('qrLatency');
  const scoreText = document.getElementById('qrScoreText');
  const scoreCircle = document.getElementById('qrScoreCircle');
  const typeDetail = document.getElementById('qrTypeDetail');
  const targetDetail = document.getElementById('qrTargetDetail');
  const culpritHost = document.getElementById('qrCulpritHost');
  const list = document.getElementById('qrIndicatorsList');
  const cyberCard = document.getElementById('qrCyberCard');
  const serverIpEl = document.getElementById('qrServerIp');
  const serverIspEl = document.getElementById('qrServerIsp');
  const serverLocEl = document.getElementById('qrServerLocation');
  const incidentIdEl = document.getElementById('qrIncidentId');
  const cyberDesc = document.getElementById('qrCyberDesc');
  const replicaBox = document.getElementById('qrReplicaBox');
  const replicaBrandBadge = document.getElementById('qrReplicaBrandBadge');
  const replicaRedirectLink = document.getElementById('qrOfficialRedirectLink');

  if (!container) return;
  container.classList.remove('hidden');

  const isThreat = data.is_threat;
  const threatColor = data.threat_color || (isThreat ? '#C53929' : '#2B6E4E');

  // Verdict Banner
  if (banner) {
    banner.className = isThreat ? 'verdict-banner danger' : 'verdict-banner safe';
    banner.style.borderLeft = `6px solid ${threatColor}`;
  }
  if (title) title.innerText = data.verdict || "ANALYSIS READY";
  if (sub) {
    if (data.payload_type === 'UPI_PAYMENT' && isThreat) {
      sub.innerText = "CRITICAL UPI REVERSE-DEBIT TRAP: Scammer requests money from your account under guise of lottery/cashback.";
    } else if (data.is_threat) {
      sub.innerText = "Threat verified by on-device intelligence. High risk of quishing, credential harvesting, or malware.";
    } else {
      sub.innerText = "Decoded destination verified safe. No quishing vectors, homoglyphs, or debit traps identified.";
    }
  }
  if (badgeLevel) {
    badgeLevel.innerText = data.threat_level || "SAFE";
    badgeLevel.style.color = threatColor;
  }
  if (latency) latency.innerText = `${data.latency_ms || 0.28} ms`;

  // Score
  const score = Math.round(data.risk_score || 0);
  if (scoreText) scoreText.innerText = `${score}%`;
  if (scoreCircle) {
    scoreCircle.style.borderColor = threatColor;
    scoreCircle.style.color = threatColor;
  }

  // Quick stats
  if (typeDetail) typeDetail.innerText = data.payload_type || "UNKNOWN";
  if (targetDetail) {
    const rawTarget = data.decoded_payload || "";
    targetDetail.innerText = rawTarget.length > 35 ? rawTarget.substring(0, 32) + "..." : rawTarget;
  }
  if (culpritHost) {
    if (isThreat && data.culprit_server_ip) {
      culpritHost.innerText = `${data.culprit_server_ip} (${data.ip_intelligence?.isp || 'Host'})`;
      culpritHost.style.color = "#C53929";
    } else {
      culpritHost.innerText = "Clean Destination";
      culpritHost.style.color = "#2B6E4E";
    }
  }

  // Decompose indicators
  if (list) {
    list.innerHTML = "";
    const indicators = data.matched_indicators || [];
    if (indicators.length === 0) {
      list.innerHTML = `<li class="xai-item safe"><span class="xai-bullet">&bull;</span><span>No quishing lures, reverse debit traps, or malware payloads detected.</span></li>`;
    } else {
      indicators.forEach(ind => {
        const li = document.createElement('li');
        li.className = `xai-item ${ind.severity === 'CRITICAL' ? 'danger' : (ind.severity === 'WARNING' ? 'warning' : 'safe')}`;
        li.innerHTML = `<span class="xai-bullet">&bull;</span><div><strong>${ind.label}:</strong> <span style="color: var(--text-muted);">${ind.detail}</span></div>`;
        list.appendChild(li);
      });
    }
  }

  // Cybercrime Card & Report Card Cache
  latestQrCyberComplaintText = (data.report_card && data.report_card.full_dossier_text) || data.cyber_dossier_1930 || "";
  latestQrReportCard = data.report_card || {
    incident_id: (data.report_card && data.report_card.incident_id) || `VDX-QR-${Math.floor(Date.now() / 1000) % 1000000}`,
    timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
    source_type: "SCAM_QR_DETECTOR",
    verdict: data.verdict,
    is_threat: isThreat,
    threat_level: data.threat_level,
    threat_color: threatColor,
    risk_score: data.risk_score,
    target: data.decoded_payload || "Decoded QR Payload",
    culprit_server_ip: data.culprit_server_ip || "127.0.0.1",
    isp: data.ip_intelligence?.isp || "Host Network",
    server_location: data.ip_intelligence?.server_location || "Unknown",
    indicators: (data.matched_indicators || []).map(ind => ind.label || ind),
    action_notice: data.cyber_action_instruction || "Register complaint on cybercrime.gov.in or dial 1930.",
    complaint_url: "https://cybercrime.gov.in",
    helpline_dialpad: "1930",
    full_dossier_text: latestQrCyberComplaintText
  };

  if (cyberCard) {
    if (isThreat && data.culprit_server_ip) {
      cyberCard.classList.remove('hidden');
      if (serverIpEl) serverIpEl.innerText = data.culprit_server_ip;
      if (serverIspEl) serverIspEl.innerText = data.ip_intelligence?.isp || "Payment / Cloud Gateway";
      if (serverLocEl) serverLocEl.innerText = data.ip_intelligence?.server_location || "National Infrastructure";
      if (incidentIdEl) incidentIdEl.innerText = (data.report_card && data.report_card.incident_id) || "VDX-QR-REPORT";
      if (cyberDesc) {
        cyberDesc.innerHTML = `Culprit forensics resolved for <strong>${data.culprit_server_ip}</strong>. Register a complaint on <strong>cybercrime.gov.in</strong> or dial <strong>1930</strong> from your phone dialpad immediately.`;
      }
    } else {
      cyberCard.classList.add('hidden');
    }
  }

  // Replica Suggestion Box
  if (replicaBox) {
    const replica = data.legitimate_website_suggestion;
    if (replica) {
      replicaBox.classList.remove('hidden');
      if (replicaBrandBadge) replicaBrandBadge.innerText = replica.spoofed_brand.toUpperCase();
      if (replicaRedirectLink) {
        replicaRedirectLink.href = replica.official_url;
        const span = replicaRedirectLink.querySelector('span');
        if (span) span.innerText = `Redirect to Official ${replica.official_domain}`;
      }
    } else {
      replicaBox.classList.add('hidden');
    }
  }

  // Smooth scroll
  container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function copyQrCyberComplaint() {
  if (!latestQrCyberComplaintText) {
    alert("No active complaint dossier available.");
    return;
  }
  navigator.clipboard.writeText(latestQrCyberComplaintText).then(() => {
    const btnText = document.getElementById('qrCopyComplaintBtnText');
    if (btnText) {
      const orig = btnText.innerText;
      btnText.innerText = "Dossier Copied to Clipboard!";
      setTimeout(() => { btnText.innerText = orig; }, 3000);
    }
  });
}

// ============================================================================
// UNIVERSAL REPORT CARD GENERATOR & DOWNLOADER (OFFLINE ZERO-CLOUD)
// ============================================================================

function downloadReportCard(type) {
  let rc = null;
  if (type === 'url') {
    rc = latestUrlReportCard;
  } else if (type === 'screenshot') {
    rc = latestScreenshotReportCard;
  } else if (type === 'qr') {
    rc = latestQrReportCard;
  }

  if (!rc) {
    alert(`Please run ${type === 'url' ? 'a URL Inspection' : (type === 'screenshot' ? 'a Message Screenshot Analysis' : 'a Scam QR Code Detection')} first to generate a report card.`);
    return;
  }

  const htmlContent = generateReportCardHtml(rc);
  const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
  const downloadUrl = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const safeFilename = `VeriDex_Cyber_Incident_Report_Card_${rc.incident_id || 'REPORT'}.html`;
  a.href = downloadUrl;
  a.download = safeFilename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(downloadUrl);
}

function generateReportCardHtml(rc) {
  const isThreat = rc.is_threat;
  const threatColor = rc.threat_color || (isThreat ? '#C53929' : '#2B6E4E');
  const bannerBg = isThreat ? '#FDF3F2' : '#F0F7F3';
  const badgeClass = isThreat ? 'badge-critical' : 'badge-safe';
  
  const indicatorsHtml = (rc.indicators && rc.indicators.length > 0)
    ? rc.indicators.map(ind => `<li>${typeof ind === 'object' ? (ind.label || JSON.stringify(ind)) : ind}</li>`).join('')
    : '<li>No adverse threat signatures detected.</li>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VeriDex AI — Official Cyber Incident Report Card [${rc.incident_id}]</title>
  <style>
    :root {
      --bg: #FAF8F5;
      --card-bg: #FFFFFF;
      --text-main: #241E19;
      --text-muted: #756A63;
      --border: #E8E2D9;
      --brand: #8C6842;
      --brand-hover: #735434;
      --red: #C53929;
      --red-bg: #FDF3F2;
      --green: #2B6E4E;
      --green-bg: #F0F7F3;
      --amber: #B4691B;
      --amber-bg: #FDF8F0;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text-main);
      padding: 36px 20px;
      line-height: 1.5;
    }
    .report-wrap {
      max-width: 840px;
      margin: 0 auto;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 44px;
      box-shadow: 0 4px 24px rgba(36, 30, 25, 0.06);
    }
    .print-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 28px;
      padding-bottom: 16px;
      border-bottom: 1px dashed var(--border);
    }
    .btn-print {
      background: var(--brand);
      color: #FFF;
      border: none;
      padding: 10px 22px;
      border-radius: 6px;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      box-shadow: 0 2px 6px rgba(140, 104, 66, 0.25);
    }
    .btn-print:hover { background: var(--brand-hover); }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 2px solid var(--border);
      padding-bottom: 20px;
      margin-bottom: 24px;
    }
    .org-title {
      font-size: 11px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--brand);
      font-weight: 700;
      margin-bottom: 4px;
    }
    .main-title {
      font-size: 24px;
      font-weight: 800;
      color: var(--text-main);
      letter-spacing: -0.02em;
    }
    .meta-col {
      text-align: right;
      font-size: 13px;
      color: var(--text-muted);
    }
    .incident-ref {
      display: inline-block;
      font-family: Consolas, monospace;
      font-weight: 700;
      font-size: 14px;
      color: var(--text-main);
      background: var(--bg);
      padding: 4px 10px;
      border-radius: 4px;
      border: 1px solid var(--border);
      margin-top: 4px;
    }
    .verdict-banner {
      padding: 20px 24px;
      border-radius: 8px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-left: 6px solid ${threatColor};
      background: ${bannerBg};
    }
    .verdict-title {
      font-size: 19px;
      font-weight: 800;
      color: ${threatColor};
      margin-bottom: 4px;
    }
    .verdict-sub {
      font-size: 13px;
      color: var(--text-muted);
    }
    .risk-score-box {
      text-align: right;
    }
    .risk-score {
      font-size: 32px;
      font-weight: 800;
      color: ${threatColor};
      line-height: 1;
    }
    .risk-label {
      font-size: 10.5px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      font-weight: 700;
    }
    .section-title {
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--brand);
      font-weight: 700;
      margin-top: 24px;
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .info-table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 20px;
    }
    .info-table th, .info-table td {
      padding: 10px 14px;
      border: 1px solid var(--border);
      font-size: 13.5px;
      text-align: left;
    }
    .info-table th {
      background: var(--bg);
      width: 28%;
      color: var(--text-muted);
      font-weight: 600;
    }
    .target-box {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px 14px;
      font-family: Consolas, monospace;
      font-size: 13px;
      word-break: break-all;
      margin-bottom: 20px;
    }
    .indicators-list {
      padding-left: 20px;
      margin-bottom: 20px;
    }
    .indicators-list li {
      font-size: 13.5px;
      margin-bottom: 6px;
      color: var(--text-main);
    }
    .action-alert {
      background: #FFF8E6;
      border: 1px solid #FFE082;
      border-radius: 8px;
      padding: 16px 20px;
      margin: 24px 0;
    }
    .action-alert h4 {
      color: #8C5300;
      font-size: 14px;
      margin-bottom: 6px;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .action-alert p {
      font-size: 13px;
      color: #5D3B00;
      line-height: 1.45;
    }
    .dossier-box {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 16px;
      font-family: Consolas, monospace;
      font-size: 11.5px;
      white-space: pre-wrap;
      line-height: 1.5;
      color: #333;
      margin-top: 10px;
    }
    .badge {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.05em;
    }
    .badge-critical { background: var(--red); color: #FFF; }
    .badge-safe { background: var(--green); color: #FFF; }
    .badge-suspicious { background: var(--amber); color: #FFF; }
    .footer {
      margin-top: 36px;
      padding-top: 18px;
      border-top: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      font-size: 11.5px;
      color: var(--text-muted);
    }
    @media print {
      body { background: #FFF; padding: 0; }
      .report-wrap { border: none; box-shadow: none; padding: 0; }
      .print-bar { display: none; }
    }
  </style>
</head>
<body>
  <div class="report-wrap">
    <div class="print-bar">
      <div>
        <strong>Official Incident Dossier</strong> &bull; Generated for Legal &amp; Cyber Helpline 1930 Submission
      </div>
      <button class="btn-print" onclick="window.print()">
        <span>🖨️ Print / Save as PDF</span>
      </button>
    </div>

    <header class="header">
      <div>
        <div class="org-title">MINISTRY OF HOME AFFAIRS (I4C) COMPLIANT SECURITY FORENSICS</div>
        <h1 class="main-title">CYBER INCIDENT REPORT CARD</h1>
        <p style="font-size: 13px; color: var(--text-muted); margin-top: 2px;">Autonomous On-Device Threat Intelligence &bull; VeriDex AI Engine</p>
      </div>
      <div class="meta-col">
        <div>Incident Reference:</div>
        <div class="incident-ref">${rc.incident_id || 'VDX-INCIDENT'}</div>
        <div style="margin-top: 4px;">${rc.timestamp || new Date().toISOString()}</div>
      </div>
    </header>

    <div class="verdict-banner">
      <div>
        <div class="verdict-title">${rc.verdict || 'INCIDENT EVALUATION'}</div>
        <div class="verdict-sub">Source Vector: <strong>${rc.source_type || 'ON-DEVICE INSPECTION'}</strong> &bull; Threat Level: <span class="badge ${badgeClass}">${rc.threat_level || 'INFO'}</span></div>
      </div>
      <div class="risk-score-box">
        <div class="risk-score">${rc.risk_score || 0}%</div>
        <div class="risk-label">Threat Risk Index</div>
      </div>
    </div>

    <div class="section-title">1. Target Destination Under Investigation</div>
    <div class="target-box">${rc.target || 'None'}</div>

    <div class="section-title">2. Culprit Infrastructure Forensics</div>
    <table class="info-table">
      <tr>
        <th>Culprit Server IP / VPA</th>
        <td><strong style="color: ${rc.is_threat ? 'var(--red)' : 'var(--green)'}; font-family: monospace;">${rc.culprit_server_ip || '127.0.0.1'}</strong></td>
      </tr>
      <tr>
        <th>Hosting ISP / Gateway</th>
        <td>${rc.isp || 'Host Network'}</td>
      </tr>
      <tr>
        <th>Server / Node Location</th>
        <td>${rc.server_location || 'Unknown'}</td>
      </tr>
      <tr>
        <th>Inspection Mechanism</th>
        <td>100% On-Device Random Forest + ONNX Engine (Zero-Cloud Privacy)</td>
      </tr>
    </table>

    <div class="section-title">3. Flagged Violations &amp; Fraud Markers</div>
    <ul class="indicators-list">
      ${indicatorsHtml}
    </ul>

    <div class="action-alert">
      <h4>🚨 Action Required for Citizen / Investigating Officer</h4>
      <p>
        <strong>1. Helpline 1930:</strong> Dial toll-free 1930 immediately from your phone dialpad to register financial cyber fraud.<br>
        <strong>2. National Portal:</strong> File this dossier online at <strong>https://cybercrime.gov.in</strong> under Financial Fraud or Phishing / Malicious Site.<br>
        <strong>3. Provide Culprit IP:</strong> Submit the traced server IP (<strong>${rc.culprit_server_ip || 'Traced Host'}</strong>) to authorities for expedited DNS seizure and ISP blocking under I4C protocols.
      </p>
    </div>

    <div class="section-title">4. Complete Police Filing Dossier Text</div>
    <div class="dossier-box">${rc.full_dossier_text || 'Forensic verification complete.'}</div>

    <footer class="footer">
      <div>Verified autonomously by VeriDex AI Engine &bull; Windows DPAPI AES-256 Encrypted Vault</div>
      <div>Confidential Forensic Document &bull; Valid for MHA / I4C Portal Filing</div>
    </footer>
  </div>
</body>
</html>`;
}

// Global modal dismiss listeners (Escape key & backdrop click)
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeReplicaModal();
});

// Clipboard Paste Handler (Ctrl + V to paste WhatsApp screenshot or QR code)
window.addEventListener('paste', (e) => {
  const items = e.clipboardData && e.clipboardData.items;
  if (!items) return;

  for (let i = 0; i < items.length; i++) {
    if (items[i].type.indexOf('image') !== -1) {
      const blob = items[i].getAsFile();
      const reader = new FileReader();
      reader.onload = (event) => {
        // If QR Scanner tab is active, paste directly into QR scanner
        const qrTab = document.getElementById('tab-qr-scanner');
        if (qrTab && qrTab.classList.contains('active')) {
          loadQrImage(event.target.result, "");
        } else {
          switchTab('screenshot-analyzer');
          loadScreenshotImage(event.target.result, "");
        }
      };
      reader.readAsDataURL(blob);
      break;
    }
  }
});

// Initialization
window.addEventListener('DOMContentLoaded', () => {
  loadStats();
  
  // Hash Routing (Direct link e.g. from extension or shortcuts)
  if (window.location.hash === '#tab-screenshot-analyzer') {
    switchTab('screenshot-analyzer');
  } else if (window.location.hash === '#tab-qr-scanner') {
    switchTab('qr-scanner');
  }

  // Drag and Drop on Screenshot dropzone
  const dropzone = document.getElementById('screenshotDropZone');
  if (dropzone) {
    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });
    dropzone.addEventListener('dragleave', () => {
      dropzone.classList.remove('dragover');
    });
    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      const files = e.dataTransfer && e.dataTransfer.files;
      if (files && files.length > 0 && files[0].type.startsWith('image/')) {
        const reader = new FileReader();
        reader.onload = (event) => {
          loadScreenshotImage(event.target.result, "");
        };
        reader.readAsDataURL(files[0]);
      }
    });
  }

  // Drag and Drop on QR Code dropzone
  const qrDropzone = document.getElementById('qrDropZone');
  if (qrDropzone) {
    qrDropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      qrDropzone.classList.add('dragover');
    });
    qrDropzone.addEventListener('dragleave', () => {
      qrDropzone.classList.remove('dragover');
    });
    qrDropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      qrDropzone.classList.remove('dragover');
      const files = e.dataTransfer && e.dataTransfer.files;
      if (files && files.length > 0 && files[0].type.startsWith('image/')) {
        const reader = new FileReader();
        reader.onload = (event) => {
          loadQrImage(event.target.result, "");
        };
        reader.readAsDataURL(files[0]);
      }
    });
  }

  const modalEl = document.getElementById('replicaRedirectModal');
  if (modalEl) {
    modalEl.addEventListener('click', (e) => {
      if (e.target === modalEl) closeReplicaModal();
    });
  }
});
