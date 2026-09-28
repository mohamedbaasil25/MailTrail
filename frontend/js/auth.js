import { switchView } from "./ui.js";

export let isAuthenticated = false;

export async function login(username, password) {
  try {
    const fd = new FormData();
    fd.append("username", username);
    fd.append("password", password);
    const res = await fetch("/api/v1/auth/token", { method: "POST", body: fd });
    if (res.ok) {
      isAuthenticated = true;
      return true;
    }
  } catch (e) {
    console.error(e);
  }
  return false;
}

export async function logout() {
  try {
    await fetch("/api/v1/auth/logout", { method: "POST" });
  } catch (e) {}
  isAuthenticated = false;
  document.getElementById("app").hidden = true;
  document.getElementById("site").hidden = false;
}
