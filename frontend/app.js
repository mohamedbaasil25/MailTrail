(function () {
  "use strict";
  const LS_KEY = "mailtrail_vault_v1";

  const SAMPLES = {
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
Priya`,
  };

  const state = { backendAvailable: false, records: [], token: null };

  // ---------------- auth ----------------
  async function login() {
    try {
      const formData = new URLSearchParams();
      formData.append("username", "admin");
      formData.append("password", "secret123");
      const res = await fetch("/api/v1/auth/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: formData
      });
      if (res.ok) {
        const data = await res.json();
        state.token = data.access_token;
        connectWebSocket();
      }
    } catch (e) {
      console.error("Login failed", e);
    }
  }

  function connectWebSocket() {
    if (!state.token) return;
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${protocol}//${window.location.host}/api/v1/ws/updates?token=${state.token}`);
    
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        // If it's a new analysis report, append it to records
        if (data.message_id && data.risk_score !== undefined) {
           // We could recreate the record and push it here for a truly live dashboard
           console.log("Live threat received:", data);
           // Refresh page or trigger renderAll() 
        }
      } catch (e) {}
    };
  }

  // ---------------- storage ----------------
  function loadLocal() {
    try { return JSON.parse(localStorage.getItem(LS_KEY) || "[]"); } catch (e) { return []; }
  }
  function saveLocal(records) {
    try { localStorage.setItem(LS_KEY, JSON.stringify(records)); } catch (e) {}
  }

  // ---------------- crypto / chain ----------------
  async function sha256(text) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  function genesisHash() { return "0".repeat(64); }
  async function computeChainHash(evidenceHash, prevChainHash) { return sha256(evidenceHash + "|" + prevChainHash); }
  async function verifyChain(records) {
    let prev = genesisHash();
    for (let i = 0; i < records.length; i++) {
      const expected = await computeChainHash(records[i].evidenceHash, prev);
      if (expected !== records[i].chainHash) return { ok: false, brokenAt: i, total: records.length };
      prev = records[i].chainHash;
    }
    return { ok: true, brokenAt: null, total: records.length };
  }

  // Geo helpers (for legacy rendering)
  function bearingDeg(lat1, lon1, lat2, lon2) {
    const toRad = (d) => (d * Math.PI) / 180, toDeg = (r) => (r * 180) / Math.PI;
    const y = Math.sin(toRad(lon2 - lon1)) * Math.cos(toRad(lat2));
    const x = Math.cos(toRad(lat1)) * Math.sin(toRad(lat2)) - Math.sin(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.cos(toRad(lon2 - lon1));
    return (toDeg(Math.atan2(y, x)) + 360) % 360;
  }

  // ---------------- backend ----------------
  async function checkBackend() {
    try {
      const res = await fetch("/api/health", { cache: "no-store" });
      if (!res.ok) return false;
      const data = await res.json();
      return !!data.ok;
    } catch (e) { return false; }
  }
  function renderBackendStatus() {
    const el = document.getElementById("backendStatus");
    if (!el) return;
    if (state.backendAvailable) {
      el.className = "status";
      el.innerHTML = "<i></i> local server connected · evidence also logged server-side";
      el.style.display = "inline-flex";
    } else {
      el.style.display = "none";
    }
  }

  // ---------------- helpers ----------------
  function setText(id, val) { const el = document.getElementById(id); if (el) el.textContent = val; }
  function formatTime(iso) { return new Date(iso).toLocaleString(undefined, { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }); }
  function shortHash(h) { return h ? h.slice(0, 10) + "…" + h.slice(-4) : ""; }
  function shortId(id) { return id ? id.slice(0, 8) : ""; }
  function escapeHtml(str) { return String(str).replace(/[&<>"']/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m])); }
  function verdictBadgeHtml(v) { return `<span class="badge ${v.toLowerCase()}">${v} RISK</span>`; }
  function gaugeSvg(score) {
    const r = 30, c = 2 * Math.PI * r, pct = Math.max(0, Math.min(100, score)) / 100;
    const color = score >= 70 ? "#C13E4C" : score >= 40 ? "#C7841F" : "#1E8E5A";
    return `<svg width="76" height="76" viewBox="0 0 76 76">
      <circle cx="38" cy="38" r="${r}" fill="none" stroke="#EEEFF3" stroke-width="8"/>
      <circle cx="38" cy="38" r="${r}" fill="none" stroke="${color}" stroke-width="8"
        stroke-dasharray="${c}" stroke-dashoffset="${c * (1 - pct)}" stroke-linecap="round"
        transform="rotate(-90 38 38)"/>
    </svg>`;
  }

  // ---------------- navigation ----------------
  const VIEW_META = {
    overview: { title: "Threat overview", eyebrow: "security operations center" },
    analyze: { title: "Analyze email", eyebrow: "multi-signal analysis" },
    geo: { title: "Geo intelligence", eyebrow: "attribution instrument" },
    evidence: { title: "Evidence vault", eyebrow: "forensic evidence" },
    reports: { title: "Forensic reports", eyebrow: "response" },
  };
  function switchView(name) {
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("active-view"));
    const target = document.getElementById("view-" + name);
    if (target) target.classList.add("active-view");
    document.querySelectorAll(".sidebar .nav").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
    const meta = VIEW_META[name];
    if (meta) { setText("pageTitle", meta.title); setText("pageEyebrow", meta.eyebrow); }
    window.scrollTo(0, 0);
  }
  function wireNav() {
    document.querySelectorAll(".sidebar .nav").forEach((btn) => btn.addEventListener("click", () => switchView(btn.dataset.view)));
    document.querySelectorAll("[data-view-jump]").forEach((btn) => btn.addEventListener("click", () => switchView(btn.dataset.viewJump)));
  }
  function wireLaunch() {
    document.querySelectorAll("[data-launch-app]").forEach((btn) => btn.addEventListener("click", () => {
      document.getElementById("site").hidden = true;
      document.getElementById("app").hidden = false;
      switchView(btn.dataset.targetView || "overview");
    }));
    document.querySelectorAll("[data-exit-app]").forEach((btn) => btn.addEventListener("click", () => {
      document.getElementById("app").hidden = true;
      document.getElementById("site").hidden = false;
      window.scrollTo(0, 0);
    }));
  }

  // ---------------- analyze flow ----------------
  function wireAnalyze() {
    document.querySelectorAll("[data-sample]").forEach((btn) => btn.addEventListener("click", () => {
      document.getElementById("emailInput").value = SAMPLES[btn.dataset.sample].trim();
      document.getElementById("analyzeError").textContent = "";
    }));
    document.getElementById("analyzeBtn").addEventListener("click", runAnalysis);
  }

  async function runAnalysis() {
    const btn = document.getElementById("analyzeBtn");
    const input = document.getElementById("emailInput");
    const errEl = document.getElementById("analyzeError");
    const text = input.value.trim();
    errEl.textContent = "";
    if (text.length < 10) { errEl.textContent = "Paste at least a subject and a line of body text to analyze."; return; }

    btn.disabled = true;
    const original = btn.textContent;
    for (const s of ["Parsing headers…", "Scoring signals…", "Tracing geolocation…", "Sealing evidence…", "Updating dashboard…"]) {
      btn.textContent = s;
      await new Promise((r) => setTimeout(r, 220));
    }

    try {
      // Create a dummy email format since the backend expects sender_email, recipient_email, etc.
      const payload = {
          subject: "Analyzed via Dashboard",
          sender_email: "unknown@example.com",
          recipient_email: "soc@mailtrail.local",
          body_text: text,
          headers: []
      };
      
      const res = await fetch("/api/v1/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      
      if (!res.ok) throw new Error("Backend analysis failed");
      const data = await res.json();
      
      const prevChainHash = state.records.length ? state.records[state.records.length - 1].chainHash : genesisHash();
      const chainHash = await computeChainHash(data.evidence_hash, prevChainHash);

      const record = {
        id: data.message_id,
        evidenceHash: data.evidence_hash, 
        chainHash: chainHash,
        score: Math.round(data.risk_score), 
        verdict: data.threat_level === "Malicious" ? "HIGH" : data.threat_level === "Suspicious" ? "MEDIUM" : "LOW",
        signals: data.detected_threats,
        urls: [], // extracted URLs not returned by backend currently
        authResults: {},
        ip: data.geolocation_info ? data.geolocation_info.ip_address : null,
        ipClass: "public",
        geo: data.geolocation_info ? { available: true, lat: data.geolocation_info.latitude, lon: data.geolocation_info.longitude, name: data.geolocation_info.city, country: data.geolocation_info.country_iso_code, source: "backend" } : { available: false, reason: "No geo data provided" },
        impossibleTravel: data.is_impossible_travel ? { impossible: true, distanceKm: 1000, hours: 1, speedKmh: 1000 } : null,
        createdAt: new Date().toISOString(),
      };
      
      state.records.push(record);
      saveLocal(state.records);
    } catch (e) {
      errEl.textContent = "Error: " + e.message;
    }

    btn.textContent = original;
    btn.disabled = false;
    renderResult(record);
    renderAll();
  }

  function renderResult(record) {
    const panel = document.getElementById("resultPanel");
    panel.classList.remove("empty");

    const signalsHtml = record.signals.length ? record.signals.map((s) => `
      <div class="reason">
        <div class="reason-top"><span>${escapeHtml(s.title)}</span><span class="reason-points ${s.points < 0 ? "neg" : ""}">${s.points > 0 ? "+" : ""}${s.points}</span></div>
        <p>${escapeHtml(s.detail)}</p>
      </div>`).join("") : `<div class="reason"><p>No individual risk signals were triggered.</p></div>`;

    const urlsHtml = `<p class="panel-copy">URLs extracted by backend (view raw JSON for details).</p>`;

    let geoHtml;
    if (record.geo.available) {
      geoHtml = `<div class="geo-card">
        <div class="geo-card-row"><span>Sender IP</span><span>${escapeHtml(record.ip)} (${escapeHtml(record.ipClass)})</span></div>
        <div class="geo-card-row"><span>Location</span><span>${escapeHtml(record.geo.name)}, ${escapeHtml(record.geo.country)}</span></div>
        <div class="geo-card-row"><span>Source</span><span>${escapeHtml(record.geo.source)}</span></div>
      </div>`;
      if (record.impossibleTravel) {
        geoHtml += record.impossibleTravel.impossible
          ? `<div class="travel-alert">⚠ Impossible travel: ~${Math.round(record.impossibleTravel.distanceKm).toLocaleString()} km in ${record.impossibleTravel.hours.toFixed(2)} h from the previous sender location (~${Math.round(record.impossibleTravel.speedKmh).toLocaleString()} km/h).</div>`
          : `<div class="travel-ok">✓ Travel from the previous sender location is physically plausible (~${Math.round(record.impossibleTravel.speedKmh).toLocaleString()} km/h).</div>`;
      }
    } else {
      geoHtml = `<p class="panel-copy">${escapeHtml(record.geo.reason)}</p>`;
    }

    panel.innerHTML = `
      <div class="result-head">
        <div class="gauge-wrap">${gaugeSvg(record.score)}<div class="gauge-score">ensemble score<b>${record.score}%</b></div></div>
        ${verdictBadgeHtml(record.verdict)}
      </div>
      <h4>Why this score — ${record.signals.length} signal${record.signals.length === 1 ? "" : "s"}</h4>
      ${signalsHtml}
      <h4>Indicators</h4>
      ${urlsHtml}
      <h4>Geo attribution</h4>
      ${geoHtml}
      <div class="hash-block">
        <p class="hash-label">Evidence hash (SHA-256)</p><p class="hash">${record.evidenceHash}</p>
        <p class="hash-label" style="margin-top:10px">Chain hash</p><p class="hash">${record.chainHash}</p>
      </div>
      <div class="result-actions">
        <button class="btn btn-secondary" data-goto-report="${record.id}">Generate forensic report</button>
        <button class="btn btn-ghost" data-jump="evidence">View in evidence vault</button>
      </div>`;

    panel.querySelector("[data-goto-report]")?.addEventListener("click", () => {
      switchView("reports");
      document.getElementById("reportSelect").value = record.id;
      generateReport(record.id);
    });
    panel.querySelector("[data-jump]")?.addEventListener("click", (e) => switchView(e.currentTarget.dataset.jump));
  }

  // ---------------- vault ----------------
  function wireVault() {
    document.getElementById("verifyChainBtn").addEventListener("click", () => runVerify("chainVerifyResult", false));
    document.getElementById("verifyChainBtnOverview").addEventListener("click", () => runVerify("chainVerifyResult", true));
    document.getElementById("clearVaultBtn").addEventListener("click", clearVault);
  }
  async function runVerify(targetId, jump) {
    if (jump) switchView("evidence");
    const el = document.getElementById(targetId);
    if (!state.records.length) { el.innerHTML = `<div class="chain-result">No records to verify yet.</div>`; return; }
    const v = await verifyChain(state.records);
    el.innerHTML = v.ok
      ? `<div class="chain-result pass">✓ Chain intact — ${v.total} of ${v.total} links verified.</div>`
      : `<div class="chain-result fail">✗ Integrity issue detected at record ${v.brokenAt + 1} of ${v.total}.</div>`;
  }
  async function clearVault() {
    if (!confirm("Clear all evidence in this vault? This cannot be undone.")) return;
    state.records = [];
    saveLocal(state.records);
    if (state.backendAvailable) fetch("/api/investigations", { method: "DELETE" }).catch(() => {});
    document.getElementById("chainVerifyResult").innerHTML = "";
    const rp = document.getElementById("resultPanel");
    rp.classList.add("empty");
    rp.innerHTML = `<div class="empty-state">Analysis results will appear here.<br><small>Load a sample on the left to see the full pipeline run.</small></div>`;
    document.getElementById("reportOutput").innerHTML = "";
    renderAll();
  }
  function renderEvidenceTable() {
    const el = document.getElementById("evidenceTable");
    if (!state.records.length) { el.innerHTML = `<div class="empty-state">No evidence yet. Analyze an email to create the first record.</div>`; return; }
    const rows = [...state.records].reverse().map((r) => `
      <div class="evidence-row">
        <span class="badge ${r.verdict.toLowerCase()}">${r.verdict}</span>
        <span>${r.score}%</span>
        <span class="chain-ok">${shortHash(r.evidenceHash)}</span>
        <span class="chain-ok">${shortHash(r.chainHash)}</span>
        <span>${formatTime(r.createdAt)}</span>
      </div>`).join("");
    el.innerHTML = `<div class="evidence-row header"><span>Verdict</span><span>Score</span><span>Evidence hash</span><span>Chain hash</span><span>Time</span></div>${rows}`;
  }

  // ---------------- geo view ----------------
  function renderGeoView() {
    const geoRecords = state.records.filter((r) => r.geo && r.geo.available);
    const instrument = document.getElementById("geoInstrument");
    if (!geoRecords.length) {
      instrument.innerHTML = `<div class="empty-state">No geo-tagged analysis yet. <button class="link-btn" data-jump="analyze">Run one →</button></div>`;
    } else {
      const curr = geoRecords[geoRecords.length - 1];
      const prev = geoRecords.length > 1 ? geoRecords[geoRecords.length - 2] : null;
      let readout, needleDeg = 0;
      if (prev) {
        const isImpossible = curr.impossibleTravel && curr.impossibleTravel.impossible;
        readout = `<div class="instrument-readout">
            <div><span>From</span><strong>${escapeHtml(prev.geo.name)}, ${escapeHtml(prev.geo.country)}</strong></div>
            <div><span>To</span><strong>${escapeHtml(curr.geo.name)}, ${escapeHtml(curr.geo.country)}</strong></div>
          </div>
          ${isImpossible ? `<div class="travel-alert">⚠ Impossible travel detected by backend.</div>` : `<div class="travel-ok">✓ Physically plausible.</div>`}`;
      } else {
        readout = `<div class="instrument-readout">
            <div><span>Location</span><strong>${escapeHtml(curr.geo.name)}, ${escapeHtml(curr.geo.country)}</strong></div>
            <div><span>Source</span><strong>${escapeHtml(curr.geo.source)}</strong></div>
          </div>
          <p class="panel-copy" style="margin-top:12px">First geo-tagged analysis — nothing to compare it against yet.</p>`;
      }
      instrument.innerHTML = `<div class="instrument">
          <div class="compass"><div class="compass-needle" style="transform:translate(-50%,-100%) rotate(${needleDeg}deg)"></div><div class="compass-center"></div></div>
          <div>${readout}</div>
        </div>`;
      instrument.querySelectorAll("[data-jump]").forEach((b) => b.addEventListener("click", (e) => switchView(e.currentTarget.dataset.jump)));
    }

    const historyEl = document.getElementById("geoHistoryTable");
    setText("geoHistoryCount", `${geoRecords.length} record${geoRecords.length === 1 ? "" : "s"}`);
    if (!geoRecords.length) {
      historyEl.innerHTML = `<div class="empty-state">Nothing traced yet.</div>`;
    } else {
      const rows = [...geoRecords].reverse().map((r) => `
        <div class="geo-row">
          <span>${escapeHtml(r.ip)}</span><span>${escapeHtml(r.ipClass)}</span>
          <span>${escapeHtml(r.geo.name)}, ${escapeHtml(r.geo.country)}</span>
          <span>${formatTime(r.createdAt)}</span>
        </div>`).join("");
      historyEl.innerHTML = `<div class="geo-row header"><span>IP</span><span>Class</span><span>Location</span><span>Time</span></div>${rows}`;
    }
  }

  // ---------------- reports ----------------
  function renderReportOptions() {
    const sel = document.getElementById("reportSelect");
    const current = sel.value;
    sel.innerHTML = `<option value="">— select an evidence record —</option>` +
      [...state.records].reverse().map((r) => `<option value="${r.id}">${r.verdict} · ${r.score}% · ${shortId(r.id)} · ${formatTime(r.createdAt)}</option>`).join("");
    if (current) sel.value = current;
  }
  function wireReports() {
    document.getElementById("reportBtn").addEventListener("click", () => {
      const id = document.getElementById("reportSelect").value;
      if (id) generateReport(id);
    });
  }
  function generateReport(id) {
    const record = state.records.find((r) => r.id === id);
    const out = document.getElementById("reportOutput");
    if (!record) { out.innerHTML = ""; return; }
    const idx = state.records.findIndex((r) => r.id === id);
    const signalRows = record.signals.length ? record.signals.map((s) => `<tr><td>${escapeHtml(s.title)}</td><td>${escapeHtml(s.detail)}</td><td>${s.points > 0 ? "+" : ""}${s.points}</td></tr>`).join("") : `<tr><td colspan="3">No individual risk signals were triggered.</td></tr>`;
    const urlRows = record.urls.length ? record.urls.map((u) => `<tr><td colspan="3">${escapeHtml(u)}</td></tr>`).join("") : `<tr><td colspan="3">No URLs present.</td></tr>`;
    const geoRow = record.geo.available ? `${escapeHtml(record.geo.name)}, ${escapeHtml(record.geo.country)} — ${escapeHtml(record.geo.source)}` : escapeHtml(record.geo.reason);
    const travelRow = record.impossibleTravel ? (record.impossibleTravel.impossible ? `Flagged — ~${Math.round(record.impossibleTravel.speedKmh).toLocaleString()} km/h implied` : "Not flagged — plausible") : "No prior location to compare";

    out.innerHTML = `
      <div class="report-doc" id="printArea">
        <div class="wordmark"><span class="wordmark-mark">M</span>MailTrail</div>
        <h2 style="margin-top:14px">Forensic Investigation Report</h2>
        <p class="report-meta">Case ${record.id} · generated ${formatTime(new Date().toISOString())} · record ${idx + 1} of ${state.records.length}</p>
        <hr>
        <h4>Verdict</h4>
        <p style="margin-bottom:18px">${verdictBadgeHtml(record.verdict)} &nbsp; ensemble score <strong>${record.score}%</strong> &nbsp; analyzed ${formatTime(record.createdAt)}</p>
        <h4>Signal breakdown</h4>
        <table><thead><tr><th>Signal</th><th>Detail</th><th>Points</th></tr></thead><tbody>${signalRows}</tbody></table>
        <h4>Indicators of compromise</h4>
        <table><tbody>${urlRows}</tbody></table>
        <h4>Geo attribution</h4>
        <table><tbody>
          <tr><td>Sender IP</td><td colspan="2">${record.ip ? escapeHtml(record.ip) : "not found"} (${escapeHtml(record.ipClass || "n/a")})</td></tr>
          <tr><td>Location</td><td colspan="2">${geoRow}</td></tr>
          <tr><td>Impossible travel</td><td colspan="2">${travelRow}</td></tr>
        </tbody></table>
        <h4>Evidence custody</h4>
        <table><tbody>
          <tr><td>Evidence hash (SHA-256)</td></tr><tr><td colspan="3" class="hash" style="display:block">${record.evidenceHash}</td></tr>
          <tr><td>Chain hash</td></tr><tr><td colspan="3" class="hash" style="display:block">${record.chainHash}</td></tr>
          <tr><td>Chain position</td><td colspan="2">Record ${idx + 1} of ${state.records.length}</td></tr>
        </tbody></table>
        <h4>Investigator notes</h4>
        <textarea id="reportNotes" placeholder="Add any notes for this case file…"></textarea>
        <p class="report-disclaimer">Generated by MailTrail's heuristic ensemble engine (v1) for Smart India Hackathon problem statement SIH26106. This is an MVP demonstration, not a certified forensic tool — scores come from transparent rules, not a trained model.</p>
      </div>
      <div class="report-actions">
        <button class="btn btn-primary" id="printReportBtn">Print / save as PDF</button>
        <button class="btn btn-secondary" id="downloadJsonBtn">Download JSON</button>
      </div>`;

    document.getElementById("printReportBtn").addEventListener("click", () => window.print());
    document.getElementById("downloadJsonBtn").addEventListener("click", () => {
      const notes = document.getElementById("reportNotes").value;
      const blob = new Blob([JSON.stringify({ ...record, investigatorNotes: notes }, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `mailtrail-case-${shortId(record.id)}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
    });
  }

  // ---------------- render all ----------------
  async function renderAll() {
    const records = state.records;

    setText("heroAnalyzed", records.length);
    setText("heroSealed", records.length);
    const heroChain = document.getElementById("heroChain");
    if (heroChain) {
      if (!records.length) heroChain.textContent = "—";
      else { const v = await verifyChain(records); heroChain.textContent = v.ok ? "verified" : "flagged"; }
    }

    const high = records.filter((r) => r.verdict === "HIGH").length;
    const avg = records.length ? Math.round(records.reduce((a, r) => a + r.score, 0) / records.length) : 0;
    setText("statAnalyzed", records.length);
    setText("statHigh", high);
    setText("statAvg", avg + "%");
    setText("statSealed", records.length);

    const hasAny = records.length > 0;
    const hasGeo = records.some((r) => r.geo && r.geo.available);
    const pipeline = document.getElementById("pipelinePanel");
    const steps = [hasAny, hasAny, hasGeo, hasAny, hasAny];
    [...pipeline.children].forEach((row, i) => {
      const iEl = row.querySelector("i");
      iEl.textContent = steps[i] ? "done" : "pending";
      iEl.className = steps[i] ? "done" : "";
    });
    const pl = document.getElementById("pipelineLive");
    pl.textContent = hasAny ? "live" : "idle";
    pl.className = hasAny ? "live" : "";

    const chainBadge = document.getElementById("chainBadge");
    const chainSummary = document.getElementById("chainSummary");
    if (!records.length) {
      chainBadge.textContent = "no records yet";
      chainSummary.textContent = "Run your first analysis to open the evidence vault and start the custody chain.";
    } else {
      const v = await verifyChain(records);
      chainBadge.textContent = v.ok ? `${records.length} record${records.length === 1 ? "" : "s"} · intact` : "integrity issue";
      chainSummary.textContent = v.ok ? "Every evidence hash since record 1 links correctly to the one before it." : `Chain check failed at record ${v.brokenAt + 1}. Clear the vault to reset the demo.`;
    }

    const activityEl = document.getElementById("recentActivity");
    if (!records.length) {
      activityEl.innerHTML = `<div class="empty-state">Nothing analyzed yet. <button class="link-btn" data-jump="analyze">Run your first analysis →</button></div>`;
    } else {
      activityEl.innerHTML = [...records].reverse().slice(0, 5).map((r) => `
        <div class="activity-row">
          <span class="badge ${r.verdict.toLowerCase()}">${r.verdict}</span>
          <span>${r.score}% ensemble score · ${r.signals.length} signal${r.signals.length === 1 ? "" : "s"}${r.geo.available ? ` · ${escapeHtml(r.geo.name)}` : ""}</span>
          <span class="activity-time">${formatTime(r.createdAt)}</span>
        </div>`).join("");
    }
    activityEl.querySelectorAll("[data-jump]").forEach((b) => b.addEventListener("click", (e) => switchView(e.currentTarget.dataset.jump)));

    renderEvidenceTable();
    renderGeoView();
    renderReportOptions();
  }

  // ---------------- init ----------------
  async function init() {
    state.records = loadLocal();
    state.backendAvailable = await checkBackend();
    renderBackendStatus();
    if (state.backendAvailable) {
      await login();
    }
    wireNav();
    wireLaunch();
    wireAnalyze();
    wireVault();
    wireReports();
    await renderAll();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
