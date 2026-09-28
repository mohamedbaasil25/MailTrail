import { login, logout, isAuthenticated } from "./auth.js";
import { submitAnalysis } from "./analyze.js";
import { searchVault, clearVault, verifyChain } from "./vault.js";
import { switchView, escapeHtml, shortHash, formatTime } from "./ui.js";
import { refreshDashboard } from "./dashboard.js";
import { refreshReportSelect, wireReports } from "./reports.js";
import { refreshGeo } from "./geo.js";

// DOMContentLoaded Initialization
document.addEventListener("DOMContentLoaded", () => {
  wireNav();
  wireLaunch();
  wireAnalyze();
  wireVault();
  wireReports();
  
  // Initially perform search to load recent emails
  setTimeout(() => {
    searchVault();
    refreshDashboard();
    refreshReportSelect();
    refreshGeo();
  }, 100);
});

function wireNav() {
  document.querySelectorAll(".sidebar .nav").forEach((btn) => btn.addEventListener("click", () => switchView(btn.dataset.view)));
  document.querySelectorAll("[data-view-jump]").forEach((btn) => btn.addEventListener("click", () => switchView(btn.dataset.viewJump)));
  document.querySelector("[data-logout]")?.addEventListener("click", logout);
  document.querySelector("[data-exit-app]")?.addEventListener("click", () => {
    document.getElementById("app").hidden = true;
    document.getElementById("site").hidden = false;
  });
}

function wireLaunch() {
  const modal = document.getElementById("loginModal");
  const loginForm = document.getElementById("loginForm");
  const loginError = document.getElementById("loginError");

  document.querySelectorAll("[data-launch-app]").forEach((btn) => btn.addEventListener("click", () => {
    if (isAuthenticated) {
      document.getElementById("site").hidden = true;
      document.getElementById("app").hidden = false;
      switchView(btn.dataset.targetView || "overview");
    } else {
      document.getElementById("loginUsername").value = "";
      document.getElementById("loginPassword").value = "";
      modal.hidden = false;
    }
  }));

  document.getElementById("closeLoginModal")?.addEventListener("click", () => {
    modal.hidden = true;
    loginError.hidden = true;
  });

  loginForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    loginError.hidden = true;
    
    const username = document.getElementById("loginUsername").value;
    const password = document.getElementById("loginPassword").value;
    
    const btn = loginForm.querySelector('button[type="submit"]');
    const originalText = btn.textContent;
    btn.textContent = "Authenticating...";
    btn.disabled = true;

    const success = await login(username, password);
    
    btn.textContent = originalText;
    btn.disabled = false;

    if (success) {
      modal.hidden = true;
      document.getElementById("site").hidden = true;
      document.getElementById("app").hidden = false;
      searchVault();
      refreshDashboard();
      refreshReportSelect();
      refreshGeo();
      switchView("overview");
    } else {
      loginError.textContent = "Invalid credentials";
      loginError.hidden = false;
    }
  });
}

function wireAnalyze() {
  const btn = document.getElementById("analyzeBtn");
  const err = document.getElementById("analyzeError");
  const panel = document.getElementById("resultPanel");

  // Sample data insertion
  document.querySelectorAll("[data-sample]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      // Dummy sample emails
      const samples = {
        high: `From: "SBI Alerts" <alerts@sbi-secure-verify.example>
Reply-To: verify-support@sbi-secure-verify.example
Received: from mail.relay-node.example ([203.0.113.42])
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=sbi-secure-verify.example; dkim=fail; dmarc=fail
Subject: URGENT: Your SBI account will be suspended within 24 hours

Dear Customer,

We have detected unusual activity on your account. Your account will be suspended within 24 hours unless you verify your details immediately.

Please login and verify your password and card number at the link below:
http://sbi-secure-verify.example/login

A copy of your latest statement is attached: Statement_2026.zip

Failure to verify immediately will result in permanent suspension of your account.

SBI Security Team`,
        medium: `From: "Parcel Delivery" <no-reply@express-shipping-notice.example>
Reply-To: no-reply@express-shipping-notice.example
Received: from mail.edge-node.example ([198.51.100.23])
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=express-shipping-notice.example; dkim=neutral; dmarc=none
Subject: Action required: reschedule your delivery within 24 hours

Hello,

Our courier attempted delivery of your parcel but was unable to complete it. Please reschedule within 24 hours or the parcel will be returned to the sender.

Track and reschedule here: https://express-shipping-notice.example/track?id=88213
Alternate short link: https://bit.ly/pkg88213

Thank you,
Express Shipping Notice`,
        low: `From: "Priya Nair" <priya.nair@example-corp.example>
Reply-To: priya.nair@example-corp.example
Received: from mail.example-corp.example ([192.0.2.10])
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example-corp.example; dkim=pass; dmarc=pass
Subject: Notes from today's design review

Hi team,

Thanks for joining today's design review. I've posted the updated mockups on the internal wiki:
https://wiki.example-corp.example/design/review-notes

Let me know if you have questions before Thursday's follow-up.

Best,
Priya`
      };
      const sampleKey = e.currentTarget.dataset.sample;
      document.getElementById("emailInput").value = samples[sampleKey] || samples["high"];
    });
  });

  btn?.addEventListener("click", async () => {
    const text = document.getElementById("emailInput").value.trim();
    if (!text) { err.textContent = "Please enter an email to analyze."; return; }
    err.textContent = "";
    btn.disabled = true;
    btn.textContent = "Analyzing...";
    
    try {
      const data = await submitAnalysis(text);
      if (data) {
        // Render Result UI
        panel.classList.remove("empty");
        const verdict = data.threat_level === "Malicious" ? "HIGH RISK" : data.threat_level === "Suspicious" ? "MEDIUM RISK" : "LOW RISK";
        const verdictClass = data.threat_level === "Malicious" ? "high" : data.threat_level === "Suspicious" ? "medium" : "low";
        
        // Extract indicators
        const urlRegex = /(https?:\/\/[^\s>]+)/g;
        const indicators = [...new Set(text.match(urlRegex) || [])];
        let indicatorsHtml = '';
        if (indicators.length > 0) {
          indicatorsHtml = `<h4 class="section-heading">Indicators</h4><div class="indicator-list">`;
          indicators.forEach(url => {
            // Strip any trailing punctuation
            url = url.replace(/[.,;!"']$/, '');
            const isShortener = url.includes('bit.ly') || url.includes('t.co') || url.includes('tinyurl');
            indicatorsHtml += `<div class="indicator-row"><span>${escapeHtml(url)}</span> ${isShortener ? '<span class="chip-shortener">shortener</span>' : ''}</div>`;
          });
          indicatorsHtml += `</div>`;
        }

        let signalsHtml = `<ul class="ioc-list">`;
        // Real values from the backend's haversine-distance calculation -
        // previously these were hardcoded placeholder strings that never
        // reflected the actual computed distance/speed.
        const speedString = (data.travel_speed_kmh ?? 0).toLocaleString();
        const distanceString = (data.travel_distance_km ?? 0).toLocaleString();
        data.detected_threats.forEach(t => {
          signalsHtml += `
            <li>
              <div class="ioc-header">
                <span class="ioc-title">${escapeHtml(t.title)}</span>
                <span class="ioc-points">+${t.points}</span>
              </div>
              <p class="ioc-desc">${escapeHtml(t.detail)}</p>
            </li>`;
        });
        signalsHtml += `</ul>`;

        const score = Math.round(data.risk_score);
        const dashOffset = 251 - (251 * score) / 100;
        const color = score > 70 ? 'var(--red)' : score > 30 ? 'var(--amber)' : 'var(--green)';

        // "Email details" - who/what was analyzed, with the extracted
        // sender IP always shown (even when it couldn't be resolved to a
        // location, or wasn't present in the headers at all) so it's never
        // silently missing from the results.
        let ipLine;
        if (data.sender_ip) {
          ipLine = escapeHtml(data.sender_ip) + (data.geolocation_info ? '' : ' (location could not be resolved)');
        } else {
          ipLine = 'Not present in this email\u2019s headers - paste the full email including a "Received:" line for IP attribution.';
        }
        const emailDetailsHtml = `
          <h4 class="section-heading">Email details</h4>
          <div class="geo-panel" style="margin-bottom: 24px;">
            <div class="geo-attr-row"><span>From</span><span>${escapeHtml(data.sender_email || 'Unknown')}</span></div>
            <div class="geo-attr-row"><span>To</span><span>${escapeHtml(data.recipient_email || 'Unknown')}</span></div>
            <div class="geo-attr-row"><span>Subject</span><span>${escapeHtml(data.subject || 'No subject')}</span></div>
            <div class="geo-attr-row"><span>Sender IP</span><span>${ipLine}</span></div>
          </div>
        `;

        let geoHtml = '';
        if (data.geolocation_info && data.geolocation_info.ip) {
          const geo = data.geolocation_info;
          const sourceText = geo.source === "simulated"
            ? "simulated — no GeoIP database installed or IP not in dataset"
            : "MaxMind GeoLite2";
          geoHtml = `
            <h4 class="section-heading">Geo attribution</h4>
            <div class="geo-panel">
              <div class="geo-attr-row"><span>Sender IP</span><span>${escapeHtml(geo.ip)} ${geo.source === "simulated" ? '(simulated)' : ''}</span></div>
              <div class="geo-attr-row"><span>Location</span><span>${escapeHtml(geo.city || 'Unknown')}, ${escapeHtml(geo.country || 'Unknown')}</span></div>
              <div class="geo-attr-row"><span>Source</span><span>${sourceText}</span></div>
              ${data.is_impossible_travel ? `<div class="travel-alert">⚠ Impossible travel: ~${distanceString} km from the previous sender location (implied speed ~${speedString} km/h).</div>` : ''}
            </div>
          `;
        }

        const chainHash = data.chain_hash || "N/A";
        const previousHash = data.previous_hash || "N/A";

        panel.innerHTML = `
          <div class="score-banner">
            <div class="score-left">
              <div class="score-circle">
                <svg width="80" height="80">
                  <circle cx="40" cy="40" r="36" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="8"></circle>
                  <circle cx="40" cy="40" r="36" fill="none" stroke="${color}" stroke-width="8" stroke-dasharray="226" stroke-dashoffset="${226 - (226 * score) / 100}" transform="rotate(-90 40 40)" stroke-linecap="round"></circle>
                </svg>
              </div>
              <div class="score-text">
                <span class="score-label">ensemble score</span>
                <span class="score-val">${score}%</span>
              </div>
            </div>
            <span class="badge ${verdictClass}">${verdict}</span>
          </div>
          
          <h4 class="section-heading">Why this score — ${data.detected_threats.length} signals</h4>
          ${signalsHtml}
          
          ${indicatorsHtml}
          ${emailDetailsHtml}
          ${geoHtml}

          <div class="hash-block" style="margin-bottom: 12px;">
            <p class="hash-label">Evidence hash (SHA-256)</p><p class="hash">${data.evidence_hash || "N/A"}</p>
          </div>
          <div class="hash-block" style="margin-bottom: 12px;">
            <p class="hash-label">Previous block hash</p><p class="hash">${previousHash}</p>
          </div>
          <div class="hash-block">
            <p class="hash-label">Chain hash</p><p class="hash">${chainHash}</p>
          </div>
          <div class="hash-block" style="margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border);">
            <p class="hash-label" style="display: flex; justify-content: space-between;">
                <span>Block Sequence</span>
                <span style="font-size: 14px; font-weight: 600; color: var(--text-main);">${data.sequence || "Unknown"}</span>
            </p>
          </div>
          
          <div class="result-actions" style="margin-top: 32px; display: flex; gap: 16px; align-items: center;">
             <button class="btn btn-secondary" onclick="document.querySelector('[data-view=\\'reports\\']').click();">Generate forensic report</button>
             <button class="btn btn-ghost" onclick="document.querySelector('[data-view=\\'evidence\\']').click();">View in evidence vault</button>
          </div>
        `;
        searchVault(); // Refresh evidence vault
        refreshDashboard();
        refreshReportSelect();
        refreshGeo();
      }
    } catch (e) {
      err.textContent = e.message;
    }
    
    btn.disabled = false;
    btn.textContent = "Run MailTrail analysis";
  });
}

function wireVault() {
  document.getElementById("clearVaultBtn")?.addEventListener("click", clearVault);
  document.getElementById("vaultSearchBtn")?.addEventListener("click", searchVault);
  document.getElementById("vaultSearchInput")?.addEventListener("keypress", (e) => {
    if (e.key === "Enter") searchVault();
  });
  
  document.getElementById("verifyChainBtn")?.addEventListener("click", verifyChain);
  document.getElementById("verifyChainBtnOverview")?.addEventListener("click", () => {
    const viewBtn = document.querySelector('[data-view="evidence"]');
    if (viewBtn) viewBtn.click();
    verifyChain();
  });
}

