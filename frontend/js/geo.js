import { escapeHtml, formatTime } from "./ui.js";

export async function refreshGeo() {
  try {
    const res = await fetch("/api/v1/emails");
    if (!res.ok) return;
    const data = await res.json();
    
    // Filter emails that have geolocation_info
    const geoData = data.filter(d => d.geolocation_info && d.geolocation_info.ip);
    
    const geoInstrument = document.getElementById("geoInstrument");
    const geoHistoryTable = document.getElementById("geoHistoryTable");
    const geoHistoryCount = document.getElementById("geoHistoryCount");
    
    if (geoData.length === 0) {
      if (geoInstrument) {
        geoInstrument.innerHTML = `<div class="empty-state">No geo-tagged analysis yet. <button class="link-btn" onclick="document.querySelector('[data-view=\\'analyze\\']').click();">Run one →</button></div>`;
      }
      if (geoHistoryTable) {
        geoHistoryTable.innerHTML = `<div class="empty-state">Nothing traced yet.</div>`;
      }
      if (geoHistoryCount) {
        geoHistoryCount.textContent = "0 records";
      }
      return;
    }
    
    // Populate geoInstrument with the most recent one
    const mostRecent = geoData[0];
    const geo = mostRecent.geolocation_info;
    
    const sourceText = geo.source === "simulated"
      ? "simulated — no GeoIP database installed or IP not in dataset"
      : "MaxMind GeoLite2";
    
    // Real values from the backend's haversine-distance calculation - this
    // used to be a second, independent copy of the same hardcoded
    // "4,276,546"/"7,194" placeholder bug that app.js had, so every
    // impossible-travel alert on this page showed the same fake numbers
    // regardless of what was actually computed.
    const speedString = (mostRecent.travel_speed_kmh ?? 0).toLocaleString();
    const distanceString = (mostRecent.travel_distance_km ?? 0).toLocaleString();
    
    if (geoInstrument) {
        geoInstrument.innerHTML = `
          <h4 class="section-heading" style="margin-top: 0;">Latest attribution: ${escapeHtml(mostRecent.sender_email)}</h4>
          <div class="geo-panel">
            <div class="geo-attr-row"><span>Sender IP</span><span>${escapeHtml(geo.ip)} ${geo.source === "simulated" ? '(simulated)' : ''}</span></div>
            <div class="geo-attr-row"><span>Location</span><span>${escapeHtml(geo.city || 'Unknown')}, ${escapeHtml(geo.country || 'Unknown')}</span></div>
            <div class="geo-attr-row"><span>Source</span><span>${sourceText}</span></div>
            ${mostRecent.is_impossible_travel ? `<div class="travel-alert" style="margin-top: 16px;">⚠ Impossible travel: ~${distanceString} km from the previous sender location (implied speed ~${speedString} km/h).</div>` : ''}
          </div>
        `;
    }
    
    // Populate history table
    if (geoHistoryCount) {
        geoHistoryCount.textContent = `${geoData.length} records`;
    }
    
    if (geoHistoryTable) {
        let html = `<div class="evidence-row header"><span>IP Address</span><span>Location</span><span>Sender</span><span>Time</span></div>`;
        html += geoData.map(r => {
            const g = r.geolocation_info;
            const isAlert = r.is_impossible_travel;
            const cityCountry = `${g.city || 'Unknown'}, ${g.country || 'Unknown'}${g.source === "simulated" ? " (simulated)" : ""}`;
            
            return `<div class="evidence-row ${isAlert ? 'alert-row' : ''}" style="${isAlert ? 'background: rgba(239, 68, 68, 0.05); border-left: 3px solid var(--red);' : ''}">
                 <span style="font-family: var(--mono); ${isAlert ? 'color: var(--red); font-weight: 700;' : ''}">${escapeHtml(g.ip)}</span>
                 <span>${escapeHtml(cityCountry)}</span>
                 <span class="chain-ok" title="${escapeHtml(r.subject || "No Subject")}">${escapeHtml(r.sender_email || "N/A")}</span>
                 <span>${formatTime(r.timestamp || new Date().toISOString())}</span>
               </div>`;
        }).join("");
        geoHistoryTable.innerHTML = html;
    }

  } catch (e) {
    console.error("Failed to load geo data", e);
  }
}
