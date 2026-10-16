// VeriDex AI - Injected Browser Companion
(function () {
  if (document.getElementById('veridex-floating-badge')) return;

  const currentUrl = window.location.href;
  const logoUrl = chrome.runtime.getURL('logo.png');

  // Create badge element
  const badge = document.createElement('div');
  badge.id = 'veridex-floating-badge';
  badge.title = "VeriDex AI Autonomous On-Device Protection. Click to open dashboard.";

  badge.innerHTML = `
    <img src="${logoUrl}" alt="VeriDex Logo" class="veridex-logo" />
    <span class="veridex-dot"></span>
    <span class="veridex-text">VeriDex AI: Protected</span>
  `;

  document.body.appendChild(badge);

  // Click handler: Open local VeriDex AI Cyber-Dashboard
  badge.addEventListener('click', () => {
    window.open('http://127.0.0.1:8484', '_blank');
  });

  // Query VeriDex On-Device Engine
  async function inspectPage() {
    try {
      const res = await fetch('http://127.0.0.1:8484/api/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: currentUrl, source: 'BROWSER_EXTENSION' })
      });
      const data = await res.json();
      const dot = badge.querySelector('.veridex-dot');
      const text = badge.querySelector('.veridex-text');

      if (data.is_threat) {
        badge.classList.add('threat');
        if (data.legitimate_website_suggestion) {
          text.innerText = `VeriDex: Fake ${data.legitimate_website_suggestion.spoofed_brand}!`;
          badge.title = `WARNING: Replica impersonating ${data.legitimate_website_suggestion.spoofed_brand}. Click to open dashboard.`;
        } else {
          text.innerText = "VeriDex AI: Scam Detected!";
          badge.title = `Threat: ${data.verdict}`;
        }
      } else {
        badge.classList.remove('threat');
        text.innerText = "VeriDex AI: Safe & Verified";
        if (dot) dot.style.backgroundColor = "#22c55e";
      }
    } catch (e) {
      // Local engine offline or starting up: keep clean default badge
      const text = badge.querySelector('.veridex-text');
      if (text) text.innerText = "VeriDex AI: Protected";
    }
  }

  // Inspect after load
  setTimeout(inspectPage, 600);
})();
