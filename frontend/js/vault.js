import { escapeHtml, shortHash, formatTime } from "./ui.js";

export async function searchVault() {
  const query = document.getElementById("vaultSearchInput").value;
  const btn = document.getElementById("vaultSearchBtn");
  if(!btn) return;
  btn.disabled = true;
  btn.textContent = "Searching...";
  
  try {
    const res = await fetch(`/api/v1/vault/search?query=${encodeURIComponent(query)}`);
    if (res.ok) {
      const data = await res.json();
      const el = document.getElementById("evidenceTable");
      if (!data.length) { 
        el.innerHTML = `<div class="empty-state">No matching records found.</div>`; 
      } else {
        const rows = data.map((r) => {
           const verdict = r.threat_level === "Malicious" ? "HIGH" : r.threat_level === "Suspicious" ? "MEDIUM" : "LOW";
           const senderIp = r.sender_ip || r.geolocation_info?.ip || "N/A";
           const geo = r.geolocation_info;
           const location = geo ? `${geo.city || "Unknown"}, ${geo.country || "Unknown"}${geo.source === "simulated" ? " (sim.)" : ""}` : "Unresolved";
           return `<div class="evidence-row vault-row">
             <span class="badge ${verdict.toLowerCase()}">${verdict}</span>
             <span>${Math.round(r.risk_score)}%</span>
             <span class="chain-ok" title="${escapeHtml(r.subject || "No Subject")}">${escapeHtml(r.sender_email || "N/A")}</span>
             <span title="Recipient">${escapeHtml(r.recipient_email || "N/A")}</span>
             <span style="font-family: var(--mono);" title="Sender IP">${escapeHtml(senderIp)}</span>
             <span title="Geo-attributed location">${escapeHtml(location)}</span>
             <span class="chain-ok" title="${escapeHtml(r.evidence_hash || "N/A")}">${shortHash(r.evidence_hash || "N/A")}</span>
             <span>${formatTime(r.timestamp)}</span>
           </div>`;
        }).join("");
        el.innerHTML = `<div class="evidence-row vault-row header"><span>Verdict</span><span>Score</span><span>Sender</span><span>Recipient</span><span>Sender IP</span><span>Location</span><span>Evidence hash</span><span>Time</span></div>${rows}`;
      }
    }
  } catch (e) {
    console.error(e);
  }
  
  btn.disabled = false;
  btn.textContent = "Search";
}

export async function clearVault() {
  const reason = prompt("Clear all evidence in this vault? This requires Admin privileges and cannot be undone.\n\nPlease enter a reason (min 10 chars):");
  if (!reason) return;
  if (reason.length < 10) {
    alert("Reason must be at least 10 characters long.");
    return;
  }
  
  try {
    const res = await fetch("/api/v1/investigations", { 
        method: "DELETE",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ reason })
    });
    
    if (res.status === 403) {
      alert("Permission denied. You need Admin privileges to clear the vault.");
      return;
    }
    if (!res.ok) {
        const errorData = await res.json();
        alert("Failed to clear vault: " + (errorData.detail || res.statusText));
        return;
    }
    if (res.ok) {
      // Clear UI
      document.getElementById("evidenceTable").innerHTML = `<div class="empty-state">No evidence yet.</div>`;
      alert("Vault cleared successfully.");
    }
  } catch(e) {
    console.error(e);
  }
}

export async function verifyChain() {
  const resultDiv = document.getElementById("chainVerifyResult");
  if (!resultDiv) return;
  
  const originalBtn = document.getElementById("verifyChainBtn");
  if (originalBtn) {
    originalBtn.disabled = true;
    originalBtn.textContent = "Verifying...";
  }
  
  resultDiv.innerHTML = `<div class="verify-status verifying" style="padding: 12px; margin-bottom: 16px; background: rgba(0, 132, 255, 0.1); border: 1px solid var(--accent-2); border-radius: 4px; color: var(--accent-1); font-family: var(--mono);">Verifying cryptographic ledger...</div>`;
  
  try {
    const res = await fetch("/api/v1/verify-chain");
    const data = await res.json();
    
    if (res.ok && data.valid) {
      resultDiv.innerHTML = `<div class="verify-status success" style="padding: 12px; margin-bottom: 16px; background: rgba(16, 185, 129, 0.1); border: 1px solid var(--green); border-radius: 4px; color: var(--green); font-family: var(--mono);">
        ✓ Ledger verified. ${data.checked_records} records are cryptographically intact.
      </div>`;
    } else {
      resultDiv.innerHTML = `<div class="verify-status error" style="padding: 12px; margin-bottom: 16px; background: rgba(220, 38, 38, 0.1); border: 1px solid #dc2626; border-radius: 4px; color: #dc2626; font-family: var(--mono);">
        ⚠ VERIFICATION FAILED: ${data.message} (Broken at sequence ${data.broken_at})
      </div>`;
    }
  } catch (e) {
    resultDiv.innerHTML = `<div class="verify-status error" style="padding: 12px; margin-bottom: 16px; background: rgba(220, 38, 38, 0.1); border: 1px solid #dc2626; border-radius: 4px; color: #dc2626; font-family: var(--mono);">
        ⚠ Connection failed.
      </div>`;
  }
  
  if (originalBtn) {
    originalBtn.disabled = false;
    originalBtn.textContent = "Verify chain";
  }
  
  // Clear message after 8 seconds
  setTimeout(() => {
    resultDiv.innerHTML = "";
  }, 8000);
}
