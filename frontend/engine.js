/**
 * MailTrail Heuristic Ensemble Engine (v1)
 * ------------------------------------------------------------
 * This is the rule-based, explainable multi-signal scoring engine
 * used by the MVP. It runs identically in the browser (public/app.js)
 * and on the server (server.js) — same module, two runtimes.
 *
 * NOTE ON HONESTY: the pitch deck describes a production model that
 * fuses a transformer NLP classifier (DistilBERT/BERT) with live
 * SPF/DKIM/DMARC DNS validation, MaxMind/IPinfo GeoIP and threat-intel
 * lookups (VirusTotal / AbuseIPDB). This build implements the same
 * *pipeline shape* with transparent, inspectable rules instead of a
 * trained model, and with client-side GeoIP lookups + a documented
 * fallback for offline/sandboxed use — see README "What's real".
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.MailTrailEngine = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const URGENCY_RE = /\b(urgent|immediately|act now|action required|verify now|account (will be |is )?suspend|final notice|within 24 hours|expires? (today|soon)|turant|khata band)\b/i;
  const LURE_RE = /\b(password|login|sign[- ]?in|verify|otp|one[- ]time pass|credential|bank account|card number|cvv|payment|invoice overdue|update your billing)\b/i;
  const RISKY_EXT_RE = /\.(exe|scr|js|vbs|bat|cmd|zip|rar|iso|lnk|docm|xlsm|pptm|jar)(\s|"|'|<|$)/i;
  const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "cutt.ly", "rebrand.ly"];
  const SUSPICIOUS_TLDS = [".zip", ".top", ".xyz", ".click", ".support", ".gq", ".work", ".mov", ".loan"];
  const BRANDS = ["sbi", "hdfc", "icici", "axis", "kotak", "paytm", "uidai", "incometax", "indiapost", "npci", "google", "microsoft", "paypal", "amazon", "apple", "netflix"];

  function extractUrls(text) {
    return (text.match(/https?:\/\/[^\s<>"')\]]+/gi) || []);
  }

  function domainOf(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch (e) {
      const m = url.match(/^https?:\/\/([^/]+)/i);
      return m ? m[1].toLowerCase() : "";
    }
  }

  function isIpLiteralHost(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  }

  // Cheap Levenshtein for short brand-name comparisons.
  function levenshtein(a, b) {
    const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
    for (let j = 0; j <= b.length; j++) dp[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] : 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
      }
    }
    return dp[a.length][b.length];
  }

  function brandLookalike(host) {
    const core = host.replace(/^www\./, "").split(".")[0];
    for (const brand of BRANDS) {
      if (core === brand) continue; // exact official-looking match isn't itself suspicious
      if (core.includes(brand) || levenshtein(core, brand) <= 1) {
        return brand;
      }
    }
    return null;
  }

  function classifyIp(ip) {
    const parts = ip.split(".").map(Number);
    if (parts[0] === 10) return "private";
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return "private";
    if (parts[0] === 192 && parts[1] === 168) return "private";
    if (parts[0] === 127) return "loopback";
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 2) return "reserved";
    if (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) return "reserved";
    if (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) return "reserved";
    return "public";
  }

  function extractIPs(text) {
    const found = [];
    const receivedRe = /Received:.*?\[(\d{1,3}(?:\.\d{1,3}){3})\]/gi;
    let m;
    while ((m = receivedRe.exec(text))) found.push(m[1]);
    const xoipRe = /X-Originating-IP:\s*\[?(\d{1,3}(?:\.\d{1,3}){3})\]?/gi;
    while ((m = xoipRe.exec(text))) found.push(m[1]);
    if (!found.length) {
      const generic = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [];
      found.push(...generic.filter((ip) => ip.split(".").every((n) => Number(n) <= 255)));
    }
    const unique = [...new Set(found)];
    const publicOne = unique.find((ip) => classifyIp(ip) === "public");
    const chosen = publicOne || unique[0] || null;
    return { all: unique, ip: chosen, ipClass: chosen ? classifyIp(chosen) : null };
  }

  function scoreEmail(text) {
    const lower = text.toLowerCase();
    const signals = [];
    let score = 6;
    const add = (points, title, detail) => {
      score += points;
      signals.push({ title, detail, points });
    };

    if (URGENCY_RE.test(lower)) add(15, "Urgency language", "The message uses pressure language designed to short-circuit careful review.");
    if (LURE_RE.test(lower)) add(18, "Credential or payment lure", "The message asks for, or references, a credential, OTP, or payment action.");

    const urls = extractUrls(text);
    const httpUrls = urls.filter((u) => /^http:\/\//i.test(u));
    if (httpUrls.length) add(10, "Insecure link", `${httpUrls.length} link(s) use unencrypted HTTP instead of HTTPS.`);
    if (urls.length === 1) add(10, "External link", "One external destination requires reputation and target-page verification.");
    if (urls.length >= 2) add(16, "Multiple external links", `${urls.length} distinct destinations widen the investigation surface.`);

    let sawShortener = false, sawIpLiteral = false, sawSuspiciousTld = false, lookalikeBrand = null;
    for (const u of urls) {
      const host = domainOf(u);
      if (!host) continue;
      if (SHORTENERS.some((s) => host.endsWith(s))) sawShortener = true;
      if (isIpLiteralHost(host)) sawIpLiteral = true;
      if (SUSPICIOUS_TLDS.some((t) => host.endsWith(t))) sawSuspiciousTld = true;
      const bl = brandLookalike(host);
      if (bl && !lookalikeBrand) lookalikeBrand = { brand: bl, host };
    }
    if (sawShortener) add(12, "Link shortener", "A shortening service hides the true destination until the link is clicked.");
    if (sawIpLiteral) add(16, "IP-literal destination", "A link points directly at a numeric address rather than a named domain.");
    if (sawSuspiciousTld) add(9, "Suspicious top-level domain", "One destination uses a low-cost TLD commonly abused in campaigns.");
    if (lookalikeBrand) add(20, "Brand look-alike domain", `"${lookalikeBrand.host}" reads as ${lookalikeBrand.brand.toUpperCase()} but doesn't match its official domain.`);

    if (RISKY_EXT_RE.test(text)) add(18, "High-risk attachment type", "A referenced file extension is commonly used to deliver malicious payloads.");

    const fromM = text.match(/^from:\s*.*?<?([\w.+-]+@[\w.-]+)>?/im);
    const replyM = text.match(/^reply-to:\s*.*?<?([\w.+-]+@[\w.-]+)>?/im);
    if (fromM && replyM) {
      const fromDomain = fromM[1].split("@")[1]?.toLowerCase();
      const replyDomain = replyM[1].split("@")[1]?.toLowerCase();
      if (fromDomain && replyDomain && fromDomain !== replyDomain) {
        add(9, "From / Reply-To mismatch", `Replies are redirected from ${fromDomain} to ${replyDomain}.`);
      }
    }

    const authResults = { spf: null, dkim: null, dmarc: null };
    for (const key of Object.keys(authResults)) {
      const re = new RegExp(`\\b${key}\\b\\s*[:=]\\s*(pass|fail|softfail|neutral|none)`, "i");
      const m = text.match(re);
      if (m) authResults[key] = m[1].toLowerCase();
    }
    if (authResults.spf === "fail") add(12, "SPF authentication failure", "The sending server is not authorized for this domain's SPF record.");
    if (authResults.dkim === "fail") add(12, "DKIM authentication failure", "The message's cryptographic signature failed verification.");
    if (authResults.dmarc === "fail") add(10, "DMARC alignment failure", "The message fails the domain's published DMARC policy.");
    const explicitlyChecked = Object.values(authResults).some((v) => v !== null);
    const allPass = explicitlyChecked && Object.values(authResults).every((v) => v === null || v === "pass");
    if (allPass && score <= 30) add(-8, "Clean authentication posture", "SPF, DKIM and DMARC all validated — lowers ensemble confidence in a threat.");

    score = Math.max(0, Math.min(100, Math.round(score)));
    const verdict = score >= 70 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW";
    return { score, verdict, signals, urls, authResults };
  }

  // ---- Geo helpers -------------------------------------------------

  const SIMULATED_CITIES = [
    { name: "Frankfurt", country: "DE", lat: 50.1109, lon: 8.6821 },
    { name: "Singapore", country: "SG", lat: 1.3521, lon: 103.8198 },
    { name: "Lagos", country: "NG", lat: 6.5244, lon: 3.3792 },
    { name: "São Paulo", country: "BR", lat: -23.5505, lon: -46.6333 },
    { name: "Moscow", country: "RU", lat: 55.7558, lon: 37.6173 },
    { name: "Bucharest", country: "RO", lat: 44.4268, lon: 26.1025 },
    { name: "Hanoi", country: "VN", lat: 21.0278, lon: 105.8342 },
    { name: "Johannesburg", country: "ZA", lat: -26.2041, lon: 28.0473 },
    { name: "Manila", country: "PH", lat: 14.5995, lon: 120.9842 },
    { name: "Kyiv", country: "UA", lat: 50.4501, lon: 30.5234 },
    { name: "Mumbai", country: "IN", lat: 19.076, lon: 72.8777 },
    { name: "Dublin", country: "IE", lat: 53.3498, lon: -6.2603 },
  ];

  function seededIndex(seed, mod) {
    let h = 0;
    for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
    return h % mod;
  }

  function pickSimulatedCity(seed) {
    return SIMULATED_CITIES[seededIndex(seed, SIMULATED_CITIES.length)];
  }

  function haversineKm(lat1, lon1, lat2, lon2) {
    const R = 6371;
    const toRad = (d) => (d * Math.PI) / 180;
    const dLat = toRad(lat2 - lat1);
    const dLon = toRad(lon2 - lon1);
    const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
    return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  }

  const IMPOSSIBLE_SPEED_KMH = 1000; // faster than sustained commercial air travel

  function evaluateImpossibleTravel(prev, curr) {
    if (!prev || !curr || prev.lat == null || curr.lat == null) return null;
    const distanceKm = haversineKm(prev.lat, prev.lon, curr.lat, curr.lon);
    const hours = Math.max((new Date(curr.timestamp) - new Date(prev.timestamp)) / 36e5, 1 / 3600);
    const speedKmh = distanceKm / hours;
    return { distanceKm, hours, speedKmh, impossible: distanceKm > 250 && speedKmh > IMPOSSIBLE_SPEED_KMH, from: prev, to: curr };
  }

  return {
    URGENCY_RE, LURE_RE, RISKY_EXT_RE, SHORTENERS, SUSPICIOUS_TLDS, BRANDS,
    extractUrls, extractIPs, classifyIp, brandLookalike, domainOf,
    scoreEmail, SIMULATED_CITIES, pickSimulatedCity, haversineKm,
    evaluateImpossibleTravel, IMPOSSIBLE_SPEED_KMH,
  };
});
