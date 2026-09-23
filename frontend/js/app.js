import { login, logout, isAuthenticated } from "./auth.js";
import { submitAnalysis } from "./analyze.js";
import { searchVault, clearVault } from "./vault.js";
import { switchView, escapeHtml, shortHash, formatTime } from "./ui.js";

// DOMContentLoaded Initialization
document.addEventListener("DOMContentLoaded", () => {
  wireNav();
  wireLaunch();
  wireAnalyze();
  wireVault();
  
  // Initially perform search to load recent emails
  setTimeout(() => searchVault(), 100);
});

function wireNav() {
  document.querySelectorAll(".sidebar .nav").forEach((btn) => btn.addEventListener("click", () => switchView(btn.dataset.view)));
  document.querySelectorAll("[data-view-jump]").forEach((btn) => btn.addEventListener("click", () => switchView(btn.dataset.viewJump)));
  document.querySelector("[data-logout]")?.addEventListener("click", logout);
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
        high: "From: attacker@evil.com\\nSubject: Account Compromised\\n\\nPlease visit https://evil-phishing-site.com to secure your account immediately.",
        medium: "From: alerts@sbi.example.com\\nSubject: Update your account details\\n\\nLogin to confirm your details.",
        low: "From: hr@internal.example.com\\nSubject: Townhall\\n\\nJoin the townhall tomorrow at 10 AM."
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
        const verdict = data.threat_level === "Malicious" ? "HIGH" : data.threat_level === "Suspicious" ? "MEDIUM" : "LOW";
        let signalsHtml = `<ul class="ioc-list">`;
        data.detected_threats.forEach(t => {
          signalsHtml += `<li><span>${escapeHtml(t.title)}</span><span class="ioc-flags"><span class="flag">+${t.points}</span></span><p>${escapeHtml(t.detail)}</p></li>`;
        });
        signalsHtml += `</ul>`;

        panel.innerHTML = `
          <div class="result-header">
            <div><h3>Analysis complete</h3><div class="result-meta">Score: ${Math.round(data.risk_score)}%</div></div>
            <span class="badge ${verdict.toLowerCase()}">${verdict}</span>
          </div>
          <div class="hash-block">
            <p class="hash-label">Evidence hash (SHA-256)</p><p class="hash">${data.evidence_hash || "N/A"}</p>
          </div>
          <h4>Detection Signals</h4>
          ${signalsHtml}
        `;
        searchVault(); // Refresh evidence vault
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
}
