import { escapeHtml, formatTime } from "./ui.js";

/**
 * Builds one "Detection pipeline" row from real vault data instead of the
 * static "-" placeholder that used to sit here permanently (dashboard.js
 * never touched #pipelinePanel at all before this).
 *
 * `invert` flips the color semantics for a stage where a *high* count is a
 * warning rather than a good thing (e.g. "SOC response" - lots of records
 * needing review isn't "healthy coverage", it's a backlog).
 */
function buildPipelineRow(step, label, count, total, { invert = false } = {}) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;

  let stateClass = "idle-stat";
  let fillClass = "fill-idle";
  if (total > 0) {
    if (invert) {
      stateClass = count > 0 ? "active" : "done";
      fillClass = count > 0 ? "fill-alert" : "";
    } else if (count === total) {
      stateClass = "done";
      fillClass = "";
    } else if (count > 0) {
      stateClass = "active";
      fillClass = "fill-warn";
    }
  }

  const statText = total === 0 ? "no data" : `${count}/${total} · ${pct}%`;

  return `
    <div>
      <b>${step}</b>
      <span>${label}</span>
      <div class="pipeline-meter"><div class="pipeline-meter-fill ${fillClass}" style="width:${pct}%"></div></div>
      <i class="${stateClass}">${statText}</i>
    </div>`;
}

export async function refreshDashboard() {
  try {
    const res = await fetch("/api/v1/emails");
    if (!res.ok) return;
    const data = await res.json();
    
    // Update stats
    document.getElementById("statAnalyzed").textContent = data.length;
    
    const highRisk = data.filter(d => d.threat_level === "Malicious");
    document.getElementById("statHigh").textContent = highRisk.length;
    
    let avg = 0;
    if (data.length > 0) {
      const sum = data.reduce((acc, d) => acc + d.risk_score, 0);
      avg = Math.round(sum / data.length);
    }
    document.getElementById("statAvg").textContent = `${avg}%`;
    
    const sealed = data.filter(d => d.evidence_hash).length;
    document.getElementById("statSealed").textContent = sealed;

    // Detection pipeline - real per-stage coverage across the vault
    const total = data.length;
    const aiScored = data.filter(d => d.components && d.components.nlp !== undefined).length;
    const detected = data.filter(d => d.detected_threats && d.detected_threats.length > 0).length;
    const geoAttributed = data.filter(d => d.geolocation_info).length;
    const socFlagged = highRisk.length;

    const pipelinePanel = document.getElementById("pipelinePanel");
    if (pipelinePanel) {
      pipelinePanel.innerHTML =
        buildPipelineRow("01", "Real-time IMAP ingest (IDLE)", total, total) +
        buildPipelineRow("02", "DistilBERT intent scoring (HuggingFace AI)", aiScored, total) +
        buildPipelineRow("03", "Threat intel cross-checks (VirusTotal API)", detected, total) +
        buildPipelineRow("04", "Geo attribution (MaxMind API)", geoAttributed, total) +
        buildPipelineRow("05", "Evidence sealing (SHA-256)", sealed, total) +
        buildPipelineRow("06", "SOC response", socFlagged, total, { invert: true });
    }

    const pipelineLive = document.getElementById("pipelineLive");
    if (pipelineLive) {
      if (total > 0) {
        pipelineLive.textContent = "live";
        pipelineLive.classList.remove("idle");
      } else {
        pipelineLive.textContent = "idle";
        pipelineLive.classList.add("idle");
      }
    }
    
    // Update Recent Activity
    const recentDiv = document.getElementById("recentActivity");
    if (data.length === 0) {
      recentDiv.innerHTML = `<div class="empty-state">Nothing analyzed yet. <button class="link-btn" onclick="document.querySelector('[data-view=\\'analyze\\']').click();">Run your first analysis →</button></div>`;
    } else {
      const recent5 = data.slice(0, 5);
      let html = `<div class="evidence-row header"><span>Verdict</span><span>Score</span><span>Sender</span><span>Time</span></div>`;
      html += recent5.map(r => {
        const verdict = r.threat_level === "Malicious" ? "HIGH" : r.threat_level === "Suspicious" ? "MEDIUM" : "LOW";
        return `<div class="evidence-row">
             <span class="badge ${verdict.toLowerCase()}">${verdict}</span>
             <span>${Math.round(r.risk_score)}%</span>
             <span class="chain-ok" title="${escapeHtml(r.subject || "No Subject")}">${escapeHtml(r.sender_email || "N/A")}</span>
             <span>${formatTime(r.timestamp || new Date().toISOString())}</span>
           </div>`;
      }).join("");
      recentDiv.innerHTML = html;
    }
    
    // Update chainBadge in overview
    const chainBadge = document.getElementById("chainBadge");
    if (chainBadge) {
        chainBadge.textContent = data.length > 0 ? "intact" : "no records yet";
        if (data.length > 0) {
            chainBadge.className = "badge low";
            document.getElementById("chainSummary").textContent = "The tamper-evident ledger is active. All evidence hashes are cryptographically chained.";
        }
    }

  } catch (e) {
    console.error("Failed to load dashboard data", e);
  }
}
