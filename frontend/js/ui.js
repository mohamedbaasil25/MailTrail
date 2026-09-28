export function switchView(name) {
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active-view"));
  const target = document.getElementById("view-" + name);
  if (target) target.classList.add("active-view");
  
  const eyebrows = {
    "overview": "security operations center",
    "analyze": "multi-signal analysis",
    "geo": "location & routing",
    "evidence": "tamper-evident storage",
    "reports": "cert-in compliance"
  };
  
  document.querySelectorAll(".sidebar .nav").forEach((b) => {
    const isActive = b.dataset.view === name;
    b.classList.toggle("active", isActive);
    
    if (isActive) {
      const titleEl = document.getElementById("pageTitle");
      if (titleEl) titleEl.textContent = b.textContent;
    }
  });

  const eyebrowEl = document.getElementById("pageEyebrow");
  if (eyebrowEl && eyebrows[name]) {
    eyebrowEl.textContent = eyebrows[name];
  }

  window.scrollTo(0, 0);
}

export function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function formatTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return `${d.toLocaleString("default", { month: "short" })} ${d.getDate()}, ${d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })}`;
}

export function shortHash(h) {
  if (!h || h.length < 16) return h;
  return `${h.slice(0, 10)}...${h.slice(-4)}`;
}

export function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}
