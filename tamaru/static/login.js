"use strict";
let token = "";
const error = document.getElementById("login-error"),
  button = document.getElementById("submit");
async function init() {
  button.disabled = true;
  try {
    const r = await fetch("/api/login-token");
    if (!r.ok)
      throw Error("ログイン画面を準備できません。HTTPSで接続してください。");
    const d = await r.json();
    token = d.token;
    if (d.setup_needed)
      error.textContent =
        "初期管理者が未登録です。サーバー上で create-admin を実行してください。";
    button.disabled = d.setup_needed;
  } catch (e) {
    error.textContent = e.message;
  }
}
document.getElementById("login-form").onsubmit = async (e) => {
  e.preventDefault();
  button.disabled = true;
  error.textContent = "";
  try {
    const r = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
      body: JSON.stringify({
        username: document.getElementById("username").value,
        password: document.getElementById("password").value,
      }),
    });
    const d = await r.json();
    if (!r.ok) throw Error(d.error || "ログインできませんでした。");
    document.getElementById("password").value = "";
    location.replace("/");
  } catch (e) {
    error.textContent = e.message;
    button.disabled = false;
  }
};
init();
