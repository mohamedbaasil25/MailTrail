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
           return `<div class="evidence-row">
             <span class="badge ${verdict.toLowerCase()}">${verdict}</span>
             <span>${Math.round(r.risk_score)}%</span>
             <span class="chain-ok">${shortHash(r.evidence_hash || "N/A")}</span>
             <span class="chain-ok" title="${escapeHtml(r.subject || "No Subject")}">${escapeHtml(r.sender_email || "N/A")}</span>
             <span>${formatTime(r.timestamp)}</span>
           </div>`;
        }).join("");
        el.innerHTML = `<div class="evidence-row header"><span>Verdict</span><span>Score</span><span>Evidence hash</span><span>Sender</span><span>Time</span></div>${rows}`;
      }
    }
  } catch (e) {
    console.error(e);
  }
  
  btn.disabled = false;
  btn.textContent = "Search";
}

export async function clearVault() {
  if (!confirm("Clear all evidence in this vault? This requires Admin privileges and cannot be undone.")) return;
  try {
    const res = await fetch("/api/v1/investigations", { method: "DELETE" });
    if (res.status === 403) {
      alert("Permission denied. You need Admin privileges to clear the vault.");
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
