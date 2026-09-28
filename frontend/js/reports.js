import { escapeHtml, formatTime } from "./ui.js";

let reportDataCache = [];

// A native <select> only ever prints its *currently selected* option (and
// clips it to one line) - the dropdown list itself never appears on paper.
// To make "the records you could have chosen from" print clearly, we mirror
// the options into a print-only list (hidden on screen, shown by print.css)
// and flag the chosen one. It's deliberately compact and capped: this panel
// sits above the report, and a long vault must not push the report itself
// onto page 2. The chosen record is always included even when it falls
// outside the cap, so it can never be missing from the printed selection.
const PRINT_INDEX_LIMIT = 12;

function safeIdForHandler(id) {
  // message_id ultimately originates from an email's Message-ID header (or a
  // client-supplied value), so it's untrusted. It gets interpolated into an
  // inline onclick="...'...'" string below, and encodeURIComponent() alone is
  // NOT enough there - it leaves the single quote unescaped, which would let a
  // crafted id break out of the JS string literal. Percent-encode it as well.
  return encodeURIComponent(String(id ?? "")).replace(/'/g, "%27");
}

function verdictLabel(level) {
  return level === "Malicious" ? "HIGH" : level === "Suspicious" ? "MEDIUM" : "LOW";
}

function printRecordRow(r, rank, isSelected) {
  const verdict = verdictLabel(r.threat_level);
  return `
      <li class="print-record${isSelected ? " is-selected" : ""}">
        <span class="print-record-num">${rank}</span>
        <span class="print-record-subject">${isSelected ? '<span class="print-record-flag">Selected</span>' : ""}${escapeHtml(r.subject || "No subject")}</span>
        <span class="print-record-meta">${escapeHtml(r.sender_email || "Unknown sender")}</span>
        <span class="print-record-time">${escapeHtml(formatTime(r.timestamp))}</span>
        <span class="print-record-verdict verdict-${verdict.toLowerCase()}">${verdict} · ${Math.round(r.risk_score)}%</span>
      </li>`;
}

export function renderPrintIndex(data = reportDataCache, selectedId = "") {
  const container = document.getElementById("reportPrintIndex");
  if (!container) return;

  if (!data.length) {
    container.innerHTML = "";
    return;
  }

  const selIdx = selectedId ? data.findIndex((r) => r.message_id === selectedId) : -1;
  const selectedOutsideCap = selIdx >= PRINT_INDEX_LIMIT;

  let rows = data
    .slice(0, PRINT_INDEX_LIMIT)
    .map((r, i) => printRecordRow(r, i + 1, i === selIdx))
    .join("");

  if (selectedOutsideCap) {
    rows += `<li class="print-record-gap" aria-hidden="true">⋯</li>` + printRecordRow(data[selIdx], selIdx + 1, true);
  }

  const shownCount = PRINT_INDEX_LIMIT + (selectedOutsideCap ? 1 : 0);
  const hiddenCount = Math.max(0, data.length - shownCount);
  const overflow = hiddenCount > 0
    ? `<p class="print-record-overflow">…and ${hiddenCount} more record(s) in the evidence vault.</p>`
    : "";

  container.innerHTML = `
    <h4 class="print-index-title">Evidence records available (${data.length})</h4>
    <ol class="print-record-list">${rows}</ol>
    ${overflow}`;
}

export async function refreshReportSelect() {
  const select = document.getElementById("reportSelect");
  const btn = document.getElementById("reportBtn");
  const customOptionsContainer = document.getElementById("customSelectOptions");
  const customValueDisplay = document.getElementById("customSelectValue");
  try {
    const res = await fetch("/api/v1/emails");
    if (!res.ok) return;
    const data = await res.json();
    reportDataCache = data;

    if (!select) return;

    const previousValue = select.value;
    select.innerHTML = `<option value="">— select an evidence record —</option>`;
    if (customOptionsContainer) customOptionsContainer.innerHTML = '';

    if (data.length === 0) {
      if (btn) btn.disabled = true;
      if (customValueDisplay) customValueDisplay.textContent = "— no records available —";
      renderPrintIndex([], "");
      return;
    }

    data.forEach((r) => {
      // Native option for form behavior
      const option = document.createElement("option");
      option.value = r.message_id;
      const when = formatTime(r.timestamp || new Date().toISOString());
      const sender = r.sender_email || "Unknown sender";
      const subject = r.subject || "No subject";
      const formattedText = `${when} — ${sender} — ${subject}`.slice(0, 120);
      option.textContent = formattedText;
      select.appendChild(option);

      // Custom option for UI
      if (customOptionsContainer) {
        const customOpt = document.createElement("div");
        customOpt.className = "custom-option";
        customOpt.dataset.value = r.message_id;
        customOpt.innerHTML = `
          <div class="custom-option-top">
            <span class="custom-option-time">${escapeHtml(when)}</span>
            <span class="custom-option-sender">${escapeHtml(sender)}</span>
          </div>
          <div class="custom-option-subject">${escapeHtml(subject)}</div>
        `;
        customOpt.addEventListener("click", () => {
          select.value = r.message_id;
          if (customValueDisplay) customValueDisplay.textContent = formattedText;
          select.dispatchEvent(new Event("change"));
          document.getElementById("customSelectContainer").classList.remove("open");
          Array.from(customOptionsContainer.children).forEach(c => c.classList.remove("selected"));
          customOpt.classList.add("selected");
        });
        customOptionsContainer.appendChild(customOpt);
      }
    });

    if (btn) btn.disabled = false;
    
    // Restore previous value
    if (previousValue && data.some((r) => r.message_id === previousValue)) {
      select.value = previousValue;
      const match = data.find(r => r.message_id === previousValue);
      if (customValueDisplay && match) {
         const when = formatTime(match.timestamp || new Date().toISOString());
         const sender = match.sender_email || "Unknown sender";
         const subject = match.subject || "No subject";
         customValueDisplay.textContent = `${when} — ${sender} — ${subject}`.slice(0, 120);
      }
      if (customOptionsContainer) {
         Array.from(customOptionsContainer.children).forEach(c => {
             if (c.dataset.value === previousValue) c.classList.add("selected");
             else c.classList.remove("selected");
         });
      }
    } else {
      if (customValueDisplay) customValueDisplay.textContent = "— select an evidence record —";
    }
    
    renderPrintIndex(data, select.value);
  } catch (e) {
    console.error("Failed to load reports list", e);
  }
}

function isSimulatedSource(geo) {
  return !!geo && geo.source === "simulated";
}

export function renderReport(r, recordNumber) {
  const threatText = r.threat_level === 'Malicious' ? 'HIGH RISK' : r.threat_level === 'Suspicious' ? 'MEDIUM RISK' : 'LOW RISK';
  const threatColor = r.threat_level === 'Malicious' ? '#fecaca' : r.threat_level === 'Suspicious' ? '#fde047' : '#bbf7d0';
  const threatTextColor = r.threat_level === 'Malicious' ? '#dc2626' : r.threat_level === 'Suspicious' ? '#ca8a04' : '#16a34a';

  let geoIp = r.sender_ip || r.geolocation_info?.ip || 'Not present in headers';
  let geoLoc = r.geolocation_info ? `${r.geolocation_info.city || 'Unknown'}, ${r.geolocation_info.country || 'Unknown'}` : 'Unresolved';
  if (isSimulatedSource(r.geolocation_info)) {
    geoLoc += " (simulated — no GeoIP database installed or IP not in dataset)";
  }

  let iocUrls = [];
  if (r.detected_threats) {
    r.detected_threats.forEach(t => {
      const urls = t.detail.match(/(https?:\/\/[^\s>]+)/g);
      if (urls) iocUrls.push(...urls);
    });
  }
  iocUrls = [...new Set(iocUrls)];

  let iocSection = '';
  if (iocUrls.length > 0) {
    iocSection = `
    <section class="report-section">
      <h3 class="report-heading" style="font-family: var(--mono); font-size: 15px; margin-bottom: 16px; color: #475569; font-weight: 600;">Indicators of compromise</h3>
      <div class="report-ioc-list" style="margin-bottom: 40px; font-size: 13px; color: #0f172a;">
        ${iocUrls.map(url => `<div class="report-ioc" style="padding: 12px 0; border-bottom: 1px solid #f1f5f9;">${escapeHtml(url)}</div>`).join('')}
      </div>
    </section>
    `;
  }

  const evidenceHash = r.evidence_hash || 'Pending signature';
  const chainHash = r.chain_hash || 'Pending signature';
  const previousHash = r.previous_hash || 'Pending signature';
  const sequence = r.sequence || recordNumber;
  const idParts = (r.message_id || "").split('-');
  const caseId = idParts[0] + '-' + (idParts[1] || (r.message_id || "").slice(8, 12));

  return `
    <div class="report-document" style="background: #fff; color: #0f172a; padding: 48px; border-radius: 12px; margin-top: 24px; box-shadow: 0 4px 6px rgba(0,0,0,0.02); text-align: left; border: 1px solid #f1f5f9;">
      <header class="report-masthead">
        <div class="report-brand" style="display: flex; align-items: center; gap: 16px; margin-bottom: 32px;">
          <div class="report-brand-mark" style="background: #0f172a; color: #fff; width: 36px; height: 36px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: 700; font-family: var(--mono); font-size: 16px;">M</div>
          <h2 class="report-brand-name" style="margin: 0; font-size: 20px; font-weight: 600; font-family: var(--mono); letter-spacing: -0.5px;">MailTrail</h2>
        </div>

        <h1 class="report-title" style="font-family: var(--mono); font-size: 24px; margin: 0 0 16px 0; font-weight: 600; color: #0f172a; letter-spacing: -0.5px;">Forensic Investigation Report</h1>
        <div class="report-meta" style="color: #64748b; font-size: 13px; font-family: var(--mono); margin-bottom: 48px;">
          Case ${escapeHtml(caseId)} · generated ${formatTime(new Date().toISOString())} · record ${recordNumber} of ${reportDataCache.length}
        </div>
      </header>

      <section class="report-section">
        <h3 class="report-heading" style="font-family: var(--mono); font-size: 14px; margin-bottom: 16px; color: #475569; font-weight: 600;">Verdict</h3>
        <div class="report-verdict-row" style="display: flex; align-items: center; gap: 16px; margin-bottom: 48px; font-size: 15px; color: #0f172a;">
          <span class="report-pill" style="background: ${threatColor}; color: ${threatTextColor}; font-size: 11px; font-weight: 700; padding: 6px 12px; border-radius: 9999px; display: inline-block; letter-spacing: 0.5px;">${threatText}</span>
          <span>ensemble score <strong style="font-size: 20px; font-weight: 700;">${Math.round(r.risk_score)}%</strong></span>
          <span style="color: #64748b;">analyzed ${formatTime(r.timestamp)}</span>
        </div>
      </section>

      <section class="report-section">
        <h3 class="report-heading" style="font-family: var(--mono); font-size: 14px; margin-bottom: 16px; color: #475569; font-weight: 600;">Email details</h3>
        <table class="report-table" style="width: 100%; border-collapse: collapse; margin-bottom: 48px; font-size: 14px;">
          <tbody>
            <tr>
              <td style="padding: 16px 0; color: #334155; width: 30%;">From</td>
              <td style="padding: 16px 0; color: #0f172a;">${escapeHtml(r.sender_email || 'Unknown')}</td>
            </tr>
            <tr>
              <td style="padding: 16px 0; color: #334155;">To</td>
              <td style="padding: 16px 0; color: #0f172a;">${escapeHtml(r.recipient_email || 'Unknown')}</td>
            </tr>
            <tr>
              <td style="padding: 16px 0; color: #334155;">Subject</td>
              <td style="padding: 16px 0; color: #0f172a;">${escapeHtml(r.subject || 'No subject')}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section class="report-section report-section-flow">
        <h3 class="report-heading" style="font-family: var(--mono); font-size: 14px; margin-bottom: 16px; color: #475569; font-weight: 600;">Signal breakdown</h3>
        <table class="report-table report-signals" style="width: 100%; border-collapse: collapse; margin-bottom: 48px; font-size: 14px;">
          <thead>
            <tr style="border-bottom: 1px solid #e2e8f0; text-align: left;">
              <th style="padding: 12px 0 16px 0; font-weight: 600; color: #0f172a;">Signal</th>
              <th style="padding: 12px 0 16px 0; font-weight: 600; color: #0f172a;">Detail</th>
              <th style="padding: 12px 0 16px 0; font-weight: 600; color: #0f172a; text-align: right;">Points</th>
            </tr>
          </thead>
          <tbody>
            ${(r.detected_threats || []).map(t => `
              <tr>
                <td style="padding: 16px 0; color: #334155; width: 30%; padding-right: 16px;">${escapeHtml(t.title)}</td>
                <td style="padding: 16px 0; color: #475569; padding-right: 16px;">${escapeHtml(t.detail)}</td>
                <td style="padding: 16px 0; color: #334155; text-align: right;">+${t.points}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </section>

      ${iocSection}

      <section class="report-section">
        <h3 class="report-heading" style="font-family: var(--mono); font-size: 14px; margin-bottom: 16px; color: #475569; font-weight: 600;">Geo attribution</h3>
        <table class="report-table" style="width: 100%; border-collapse: collapse; margin-bottom: 48px; font-size: 14px;">
          <tbody>
            <tr>
              <td style="padding: 16px 0; color: #334155; width: 30%;">Sender IP</td>
              <td style="padding: 16px 0; color: #0f172a;">${escapeHtml(geoIp)}</td>
            </tr>
            <tr>
              <td style="padding: 16px 0; color: #334155;">Location</td>
              <td style="padding: 16px 0; color: #0f172a;">${escapeHtml(geoLoc)}</td>
            </tr>
            <tr>
              <td style="padding: 16px 0; color: #334155;">Impossible travel</td>
              <td style="padding: 16px 0; color: #0f172a;">${r.is_impossible_travel ? `Yes - ~${(r.travel_distance_km ?? 0).toLocaleString()} km, implied speed ~${(r.travel_speed_kmh ?? 0).toLocaleString()} km/h` : 'No prior location to compare'}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section class="report-section report-custody">
        <h3 class="report-heading" style="font-family: var(--mono); font-size: 14px; margin-bottom: 16px; color: #475569; font-weight: 600;">Evidence custody</h3>
        <div class="report-hash-block" style="margin-bottom: 20px;">
          <div class="report-hash-label" style="font-size: 14px; color: #334155; margin-bottom: 8px;">Evidence hash (SHA-256)</div>
          <div class="report-hash" style="background: #f8fafc; padding: 14px; border-radius: 6px; font-family: var(--mono); font-size: 13px; color: #0f172a; word-break: break-all;">${escapeHtml(evidenceHash)}</div>
        </div>
        <div class="report-hash-block" style="margin-bottom: 20px;">
          <div class="report-hash-label" style="font-size: 14px; color: #334155; margin-bottom: 8px;">Previous hash</div>
          <div class="report-hash" style="background: #f8fafc; padding: 14px; border-radius: 6px; font-family: var(--mono); font-size: 13px; color: #0f172a; word-break: break-all;">${escapeHtml(previousHash)}</div>
        </div>
        <div class="report-hash-block" style="margin-bottom: 20px;">
          <div class="report-hash-label" style="font-size: 14px; color: #334155; margin-bottom: 8px;">Chain hash</div>
          <div class="report-hash" style="background: #f8fafc; padding: 14px; border-radius: 6px; font-family: var(--mono); font-size: 13px; color: #0f172a; word-break: break-all;">${escapeHtml(chainHash)}</div>
        </div>
        <div class="report-sequence" style="display: flex; justify-content: space-between; font-size: 14px; color: #475569; margin-bottom: 48px;">
          <span>Chain position (Sequence)</span>
          <span>Record ${escapeHtml(String(sequence))}</span>
        </div>
      </section>

      <section class="report-section report-notes">
        <h3 class="report-heading" style="font-family: var(--mono); font-size: 14px; margin-bottom: 16px; color: #475569; font-weight: 600;">Investigator notes</h3>
        <textarea class="report-notes-input" style="width: 100%; min-height: 120px; padding: 16px; border: 1px solid #e2e8f0; border-radius: 6px; background: #fff; color: #0f172a; font-family: inherit; font-size: 14px; margin-bottom: 32px; resize: vertical;" placeholder="Add any notes for this case file..."></textarea>
        <div class="report-notes-print print-only" aria-hidden="true"></div>
      </section>

      <footer class="report-footnote" style="border-top: 1px dashed #cbd5e1; padding-top: 24px; margin-bottom: 32px;">
        <div style="font-size: 12px; color: #94a3b8; line-height: 1.6;">
          Generated by MailTrail's heuristic ensemble engine (v1) for Smart India Hackathon problem statement SIH26106. This is an MVP demonstration, not a certified forensic tool — scores come from transparent rules, not a trained model.
        </div>
      </footer>

      <div class="report-actions" style="display: flex; gap: 16px; padding-bottom: 8px;">
        <button onclick="window.print()" class="print-btn" style="background: #0d9488; color: #fff; border: none; padding: 10px 24px; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 14px; display: inline-flex; justify-content: center; align-items: center; transition: all 0.2s;">Print / save as PDF</button>
        <button onclick="window.open('/api/v1/report/${safeIdForHandler(r.message_id)}', '_blank')" style="background: #fff; color: #0f172a; border: 1px solid #e2e8f0; padding: 10px 24px; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 14px; display: inline-flex; justify-content: center; align-items: center; transition: all 0.2s;">Download forensic PDF</button>
      </div>
    </div>
    `;
}

export function wireReports() {
  const select = document.getElementById("reportSelect");
  const btn = document.getElementById("reportBtn");
  const outputDiv = document.getElementById("reportOutput");
  if (!select || !btn || !outputDiv) return;

  // Custom select interactions
  const trigger = document.getElementById("customSelectTrigger");
  const container = document.getElementById("customSelectContainer");
  if (trigger && container) {
    trigger.addEventListener("click", (e) => {
      e.stopPropagation();
      container.classList.toggle("open");
    });
    document.addEventListener("click", (e) => {
      if (!container.contains(e.target)) {
        container.classList.remove("open");
      }
    });
  }

  // Keep the print-only record list's "Selected" highlight in sync as the
  // analyst changes the dropdown, even before they hit Generate.
  select.addEventListener("change", () => renderPrintIndex(reportDataCache, select.value));

  // A <textarea> prints as a fixed-size box and clips anything past its
  // visible height, so mirror what's typed into a print-only element that
  // grows with its content. textContent (not innerHTML) - notes are free
  // text typed by the analyst, never markup.
  outputDiv.addEventListener("input", (e) => {
    if (!e.target.classList || !e.target.classList.contains("report-notes-input")) return;
    const mirror = e.target.parentElement.querySelector(".report-notes-print");
    if (mirror) mirror.textContent = e.target.value;
  });

  btn.addEventListener("click", () => {
    const messageId = select.value;
    if (!messageId) {
      outputDiv.innerHTML = `<div class="empty-state" style="margin-top: 16px;">Choose a record from the dropdown above first.</div>`;
      return;
    }

    const idx = reportDataCache.findIndex(d => d.message_id === messageId);
    const r = reportDataCache[idx];
    if (!r) {
      outputDiv.innerHTML = `<div class="empty-state" style="margin-top: 16px;">That record is no longer available — try refreshing the evidence vault.</div>`;
      return;
    }

    outputDiv.innerHTML = renderReport(r, idx + 1);
    renderPrintIndex(reportDataCache, messageId);
  });
}
