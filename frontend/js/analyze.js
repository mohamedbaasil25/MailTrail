import { isAuthenticated, login } from "./auth.js";

export async function submitAnalysis(emailText) {
  const payload = {
    sender_email: "extracted@example.com", 
    recipient_email: "user@example.com",
    subject: "Analysis subject",
    body_text: emailText,
    headers: []
  };

  // Attempt to parse headers roughly for the demo
  const lines = emailText.split("\n");
  for (const line of lines) {
    if (line.toLowerCase().startsWith("from:")) payload.sender_email = line.substring(5).trim();
    if (line.toLowerCase().startsWith("to:")) payload.recipient_email = line.substring(3).trim();
    if (line.toLowerCase().startsWith("subject:")) payload.subject = line.substring(8).trim();
  }

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
