const API_BASE = window.GREENTSTEP_API_BASE || window.GREENSTEP_API_BASE || "";
const USER_STORAGE_KEY = "greenstep_user";
const TOKEN_STORAGE_KEY = "greenstep_token";

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
}

function money(v) {
  return `${Number(v || 0)} баллов`;
}

function fmtDate(v) {
  return new Date(v).toLocaleString("ru-RU");
}

function statusClass(s) {
  return s === "approved" ? "approved" : s === "rejected" ? "rejected" : s === "paid" ? "paid" : "pending";
}

function statusLabel(s) {
  return s === "approved" ? "Подтверждено" : s === "rejected" ? "Отклонено" : s === "paid" ? "Баллы начислены" : "На проверке";
}

function getAuthToken() {
  return localStorage.getItem(TOKEN_STORAGE_KEY) || "";
}

function getCurrentUser() {
  try {
    return JSON.parse(localStorage.getItem(USER_STORAGE_KEY) || "null");
  } catch {
    return null;
  }
}

function setSession(payload) {
  localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(payload.user));
  localStorage.setItem(TOKEN_STORAGE_KEY, payload.token);
}

function updateCurrentUser(user) {
  localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user));
}

function clearSession() {
  localStorage.removeItem(USER_STORAGE_KEY);
  localStorage.removeItem(TOKEN_STORAGE_KEY);
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const token = getAuthToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};

  if (res.status === 401) {
    clearSession();
  }

  if (!res.ok) throw new Error(data.error || "API error");
  return data;
}

async function logout() {
  try {
    await api("/api/logout", { method: "POST" });
  } catch {}
  clearSession();
  location.href = "/auth";
}
