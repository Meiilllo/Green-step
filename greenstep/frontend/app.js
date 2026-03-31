const API_BASE = window.GREENTSTEP_API_BASE || window.GREENSTEP_API_BASE || "";

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
}

function money(v) {
  return `${Number(v || 0)} ₽`;
}

function fmtDate(v) {
  return new Date(v).toLocaleString("ru-RU");
}

function statusClass(s) {
  return s === "approved" ? "approved" : s === "rejected" ? "rejected" : s === "paid" ? "paid" : "pending";
}

function statusLabel(s) {
  return s === "approved" ? "Подтверждено" : s === "rejected" ? "Отклонено" : s === "paid" ? "Выплачено" : "На проверке";
}

async function api(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, options);
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) throw new Error(data.error || "API error");
  return data;
}

function getCurrentUser() {
  try {
    return JSON.parse(localStorage.getItem("greenstep_user") || "null");
  } catch {
    return null;
  }
}

function setCurrentUser(user) {
  localStorage.setItem("greenstep_user", JSON.stringify(user));
}

function logout() {
  localStorage.removeItem("greenstep_user");
  location.href = "index.html";
}
