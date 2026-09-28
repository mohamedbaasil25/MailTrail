import { isAuthenticated, login } from "./auth.js";

/**
 * Splits a pasted email into its header block and body, unfolds
 * continuation lines (a line starting with whitespace is a continuation of
 * the previous header - standard RFC 5322 "folding"), and returns every
 * header as a {name, value} pair.
 *
 * This replaces the old logic, which only ever pulled out From/To/Subject
 * as top-level fields and sent `headers: []` to the backend no matter what
 * the user pasted. Since sender-IP extraction (services/geoip_service.py)
 * reads the "Received" header out of that array, the old code meant the
 * backend could never see a sender IP from this flow - Geo Intelligence
 * had nothing to work with even when the pasted email clearly had a
 * "Received: from ... ([1.2.3.4])" line right there in the textarea.
 */
function parseEmailText(rawText) {
  const normalized = rawText.replace(/\r\n/g, "\n");
  const blankLineIdx = normalized.indexOf("\n\n");
  const headerBlock = blankLineIdx === -1 ? normalized : normalized.slice(0, blankLineIdx);
  const bodyBlock = blankLineIdx === -1 ? "" : normalized.slice(blankLineIdx + 2);

  const headers = [];
  for (const rawLine of headerBlock.split("\n")) {
    if (/^[ \t]/.test(rawLine) && headers.length > 0) {
      // Folded continuation of the previous header.
      headers[headers.length - 1].value += " " + rawLine.trim();
      continue;
    }
    const match = rawLine.match(/^([A-Za-z0-9-]+):\s*(.*)$/);
    if (match) {
      headers.push({ name: match[1], value: match[2].trim() });
    }
  }

  const getHeader = (name) => headers.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value;

  return {
    headers,
    sender_email: getHeader("From") || "extracted@example.com",
    recipient_email: getHeader("To") || "user@example.com",
    subject: getHeader("Subject") || "Analysis subject",
    // If there was no blank-line separator at all (body-only paste, no
    // headers), analyze the whole thing as the body rather than losing it.
    body_text: blankLineIdx === -1 ? normalized : bodyBlock,
  };
}

export async function submitAnalysis(emailText) {
  const parsed = parseEmailText(emailText);
  const payload = {
    sender_email: parsed.sender_email,
    recipient_email: parsed.recipient_email,
    subject: parsed.subject,
    body_text: parsed.body_text,
    headers: parsed.headers,
    raw_source: emailText,
  };

  const reqHeaders = { "Content-Type": "application/json" };
  
  let res = await fetch("/api/v1/analyze", {
    method: "POST",
    headers: reqHeaders,
    body: JSON.stringify(payload)
  });

  if (res.status === 401) {
    // If unauthorized, the user may need to log in or token expired
    alert("Session expired, please login again.");
    return null;
  }

  if (!res.ok) throw new Error("Backend analysis failed (status " + res.status + ")");
  const data = await res.json();
  return data;
}
