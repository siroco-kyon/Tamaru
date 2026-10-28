"use strict";
let csrf = "",
  me = null,
  resetId = null;
const $ = (id) => document.getElementById(id);
let recursiveFolder = false;
let view = "files",
  page = 1,
  totalPages = 1,
  folder = "",
  requestId = 0,
  lastSignature = "",
  hadScan = false,
  busy = false,
  refreshing = false;
const nf = new Intl.NumberFormat("ja-JP");
const fmt = (n) => nf.format(n ?? 0);
const esc = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
function bytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  const i = Math.min(5, Math.floor(Math.log(n) / Math.log(1024)));
  return `${nf.format(Number((n / 1024 ** i).toFixed(i ? 1 : 0)))} ${u[i]}`;
}
function date(n) {
  return n == null
    ? "—"
    : new Date(n * 1000).toLocaleString("ja-JP", {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      });
}
function error(e) {
  $("error").textContent = e.message || String(e);
  $("error").classList.remove("hidden");
}
function toast(s) {
  $("toast").textContent = s;
  $("toast").classList.remove("hidden");
  setTimeout(() => $("toast").classList.add("hidden"), 3500);
}
async function api(path, body, method) {
  const r = await fetch(path, {
    method: method || (body === undefined ? "GET" : "POST"),
    headers: {
      ...(body === undefined
        ? {}
        : { "Content-Type": "application/json", "X-CSRF-Token": csrf }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const data = await r.json();
  if (r.status === 401) {
    location.replace("/login");
    throw Error("ログインしてください。");
  }
  if (!r.ok) throw Error(data.error || data.detail || "処理できませんでした");
  return data;
}

function params() {
  return new URLSearchParams({
    mode: view,
    page: String(page),
    limit: "100",
    q: $("search").value,
    root: $("root").value,
    age: $("age").value,
    sort: $("sort").value,
    folder,
    depth: $("depth").value,
    recursive: recursiveFolder ? "1" : "0",
  });
}
async function list() {
  const id = ++requestId;
  const d = await api("/api/list?" + params());
  if (id !== requestId) return;
  totalPages = Math.max(1, Math.ceil(d.count / d.limit));
  if (page > totalPages) {
    page = totalPages;
    return list();
  }
  $("result-count").textContent =
    `${fmt(d.count)}件${d.count ? "中 " + fmt((page - 1) * d.limit + 1) + "–" + fmt(Math.min(page * d.limit, d.count)) + "件を表示" : ""}`;
  $("page-label").textContent = `${page} / ${fmt(totalPages)}`;
  $("prev").disabled = page <= 1;
  $("next").disabled = page >= totalPages;
  $("thead").innerHTML =
    view === "files"
      ? '<tr><th>ファイル名 / フォルダ</th><th class="num">容量</th><th class="num">滞留日数</th><th>初回検出</th><th>最終確認 / 状態</th></tr>'
      : '<tr><th>フォルダ（直下のファイル）</th><th class="num">ファイル数</th><th class="num">合計容量</th><th class="num">最長滞留日数</th><th class="num">未確認</th></tr>';
  if (view === "folders" && d.recursive) {
    $("thead").querySelector("th").textContent =
      `フォルダ（${$("depth").value}階層目・配下を含む）`;
  }
  $("tbody").innerHTML = d.rows
    .map((r, i) =>
      view === "files"
        ? `<tr><td><div class="filename">${esc(r.name)}</div><div class="path" title="${esc(r.path)}">${esc(r.parent)}</div></td><td class="num" title="${fmt(r.size)} bytes">${bytes(r.size)}</td><td class="num"><span class="age ${r.age >= 30 ? "old" : ""}">${fmt(r.age)}日</span></td><td style="white-space:nowrap">${date(r.first_seen)}</td><td><div style="white-space:nowrap">${date(r.last_seen)}</div><span class="state ${r.status === "未確認" ? "unknown" : ""}">${esc(r.status)}</span></td></tr>`
        : `<tr><td><button class="folder-button" data-row="${i}">${esc(r.parent)}</button></td><td class="num">${fmt(r.count)}件</td><td class="num">${bytes(r.bytes)}</td><td class="num"><span class="age ${r.age >= 30 ? "old" : ""}">${fmt(r.age)}日</span></td><td class="num">${fmt(r.uncertain)}件</td></tr>`,
    )
    .join("");
  $("tbody")
    .querySelectorAll("[data-row]")
    .forEach(
      (b) =>
        (b.onclick = () => {
          const r = d.rows[Number(b.dataset.row)];
          folder = r.parent;
          recursiveFolder = !!d.recursive;
          $("root").value = String(r.root_id);
          setView("files", false);
        }),
    );
  $("empty").classList.toggle("hidden", d.count !== 0);
  if (!d.count) {
    $("empty").querySelector("strong").textContent = hadScan
      ? "該当するファイルがありません"
      : "まだ記録がありません";
    $("empty").querySelector("span").textContent = hadScan
      ? "検索条件を変えるか、収集結果を確認してください。"
      : "対象フォルダを設定し、「今すぐ収集」を押してください。";
  }
  $("breadcrumb").style.display = folder ? "block" : "none";
  $("breadcrumb").textContent = folder ? "絞り込み中: " + folder : "";
  if (folder) {
    const b = document.createElement("button");
    b.textContent = "解除";
    b.onclick = () => {
      folder = "";
      recursiveFolder = false;
      page = 1;
      list().catch(error);
    };
    $("breadcrumb").appendChild(b);
  }
}
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    const d = await api("/api/summary");
    hadScan = d.runs.length > 0;
    busy = d.progress.running;
    $("total-count").textContent = fmt(d.totals.count);
    const size = bytes(d.totals.bytes).split(" ");
    $("total-size").innerHTML =
      `${esc(size[0])} <small>${esc(size[1])}</small>`;
    $("aged-count").textContent = fmt(d.totals.aged);
    $("max-age").textContent = fmt(d.totals.max_age);
    $("uncertain").textContent =
      "未確認のファイル " + fmt(d.totals.uncertain) + "件";
    $("scan-status").textContent =
      d.progress.message +
      (busy ? " · " + fmt(d.progress.files) + "件検出" : "");
    $("status-dot").classList.toggle("busy", busy);
    $("scan").disabled = busy;
    $("settings").disabled = busy;
    $("scan").textContent = busy ? "収集中…" : "今すぐ収集";
    $("scan-path").textContent = d.progress.current;
    $("scan-path").classList.toggle("hidden", !busy);
    $("data-location").textContent = "Tamaru " + d.version + " · 調査専用";
    const s = d.progress.schedule;
    const j = d.progress.last_job;
    $("schedule-status").textContent =
      "自動収集: " +
      (s.enabled ? "毎日 " + s.time + "（" + s.timezone + "）" : "無効") +
      " / 最新の実行: " +
      (j ? date(j.started) + " · " + j.status + " · " + j.actor : "未実行");
    $("freshness").textContent = busy ? "前回の結果を表示しています" : "";
    const old = $("root").value;
    const rootHTML =
      '<option value="">すべての対象フォルダ</option>' +
      d.roots
        .map((r) => `<option value="${r.id}">${esc(r.path)}</option>`)
        .join("");
    if ($("root").innerHTML !== rootHTML) {
      $("root").innerHTML = rootHTML;
      $("root").value = old;
      if (!$("root").value) $("root").value = "";
    }
    $("runs").innerHTML =
      d.runs
        .map(
          (r) =>
            `<tr><td style="white-space:nowrap">${date(r.started)}</td><td class="path">${esc(r.path)}</td><td class="num">${fmt(r.files)}件</td><td><span class="run-status">${esc(r.status)}</span></td><td class="num">${fmt(r.errors)} / ${fmt(r.skipped)}</td></tr>`,
        )
        .join("") ||
      '<tr><td colspan="5" class="muted">まだ収集していません。</td></tr>';
    $("errors-detail").classList.toggle("hidden", d.errors.length === 0);
    $("errors-label").textContent = "最新の収集のエラー（最大100件を表示）";
    $("errors-list").innerHTML = d.errors
      .map(
        (e) =>
          `<div class="error-item"><strong>${esc(e.path)}</strong><br>${esc(e.message)}</div>`,
      )
      .join("");
    const signature = JSON.stringify([
      d.totals,
      d.roots.map((r) => [r.id, r.latest_run, r.status]),
      busy,
    ]);
    if (signature !== lastSignature) {
      lastSignature = signature;
      await list();
    }
  } catch (e) {
    error(e);
  } finally {
    refreshing = false;
  }
}
function setView(mode, clear = true) {
  view = mode;
  page = 1;
  if (clear) {
    folder = "";
    recursiveFolder = false;
  }
  $("files-tab").classList.toggle("active", mode === "files");
  $("folders-tab").classList.toggle("active", mode === "folders");
  $("depth").classList.toggle("hidden", mode !== "folders");
  list().catch(error);
}
$("files-tab").onclick = () => setView("files");
$("folders-tab").onclick = () => setView("folders");
let searchTimer;
$("search").oninput = () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    page = 1;
    list().catch(error);
  }, 250);
};
["root", "age", "sort", "depth"].forEach(
  (id) =>
    ($(id).onchange = () => {
      if (id === "root") {
        folder = "";
        recursiveFolder = false;
      }
      page = 1;
      list().catch(error);
    }),
);
$("prev").onclick = () => {
  page--;
  list().catch(error);
};
$("next").onclick = () => {
  page++;
  list().catch(error);
};
$("settings").onclick = async () => {
  try {
    const c = await api("/api/config");
    $("targets").value = c.targets.join("\n");
    $("daily-enabled").checked = c.enabled;
    $("daily-time").value = c.time;
    $("modal-error").textContent = "";
    $("modal").classList.remove("hidden");
    $("targets").focus();
  } catch (e) {
    error(e);
  }
};
$("cancel").onclick = () => {
  $("modal").classList.add("hidden");
  $("settings").focus();
};
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$("modal").classList.contains("hidden"))
    $("cancel").click();
});
$("save").onclick = async () => {
  try {
    await api("/api/config", {
      targets: $("targets").value.split(/\r?\n/),
      enabled: $("daily-enabled").checked,
      time: $("daily-time").value,
      timezone: "Asia/Tokyo",
    });
    $("modal").classList.add("hidden");
    folder = "";
    page = 1;
    lastSignature = "";
    await refresh();
    toast("対象フォルダを保存しました。収集で記録を開始できます。");
  } catch (e) {
    $("modal-error").textContent = e.message;
  }
};
$("scan").onclick = async () => {
  try {
    $("error").classList.add("hidden");
    $("scan").disabled = true;
    await api("/api/scan", {});
    await refresh();
  } catch (e) {
    error(e);
    $("scan").disabled = false;
  }
};
$("export").onclick = () => {
  const p = params();
  const a = document.createElement("a");
  a.href = "/api/export?" + p;
  a.download = "Tamaru-files.csv";
  document.body.appendChild(a);
  a.click();
  a.remove();
  toast("現在の絞り込み条件で、全件のファイル一覧をCSV出力します。");
};

$("logout").onclick = async () => {
  try {
    await api("/api/logout", {});
    location.replace("/login");
  } catch (e) {
    error(e);
  }
};
async function showAdmins() {
  const rows = await api("/api/admins");
  $("admins-list").innerHTML = rows
    .map(
      (a) =>
        `<div class="admin-row"><div><strong>${esc(a.display_name)}</strong><br><span class="muted">${esc(a.username)} · ${a.enabled ? "有効" : "無効"}${me && a.id === me.id ? " · ログイン中" : ""}</span></div><div><button data-reset="${a.id}">パスワード再設定</button> <button data-toggle="${a.id}" data-enabled="${a.enabled ? 0 : 1}">${a.enabled ? "無効化" : "有効化"}</button></div></div>`,
    )
    .join("");
  $("admins-list")
    .querySelectorAll("[data-reset]")
    .forEach(
      (b) =>
        (b.onclick = () => {
          resetId = Number(b.dataset.reset);
          $("password-target").textContent = rows.find(
            (a) => a.id === resetId,
          ).username;
          $("reset-password").value = "";
          $("password-error").textContent = "";
          $("password-modal").classList.remove("hidden");
        }),
    );
  $("admins-list")
    .querySelectorAll("[data-toggle]")
    .forEach(
      (b) =>
        (b.onclick = async () => {
          if (
            !confirm(
              "この管理者を" +
                (b.dataset.enabled === "1" ? "有効" : "無効") +
                "にしますか？",
            )
          )
            return;
          try {
            await api(
              "/api/admins/" + b.dataset.toggle,
              { enabled: b.dataset.enabled === "1" },
              "PATCH",
            );
            await showAdmins();
          } catch (e) {
            $("admin-error").textContent = e.message;
          }
        }),
    );
}
$("admin-settings").onclick = async () => {
  try {
    await showAdmins();
    $("admin-error").textContent = "";
    $("admins-modal").classList.remove("hidden");
  } catch (e) {
    error(e);
  }
};
$("close-admins").onclick = () => {
  $("admins-modal").classList.add("hidden");
  $("new-password").value = "";
};
$("add-admin").onclick = async () => {
  try {
    await api("/api/admins", {
      username: $("new-username").value,
      display_name: $("new-display").value,
      password: $("new-password").value,
    });
    $("new-password").value = "";
    $("new-username").value = "";
    $("new-display").value = "";
    $("admin-error").textContent = "";
    await showAdmins();
    toast("管理者を追加しました。");
  } catch (e) {
    $("admin-error").textContent = e.message;
  }
};
$("cancel-password").onclick = () => {
  $("password-modal").classList.add("hidden");
  $("reset-password").value = "";
};
$("save-password").onclick = async () => {
  try {
    await api(
      "/api/admins/" + resetId,
      { password: $("reset-password").value },
      "PATCH",
    );
    $("reset-password").value = "";
    $("password-modal").classList.add("hidden");
    toast("パスワードを再設定しました。対象者のログインは解除されます。");
    if (resetId === me.id) location.replace("/login");
  } catch (e) {
    $("password-error").textContent = e.message;
  }
};
const actions = {
  login: "ログイン",
  logout: "ログアウト",
  login_failed: "ログイン失敗",
  admin_created: "管理者追加",
  admin_changed: "管理者変更",
  config_changed: "収集設定変更",
  scan_requested: "収集実行",
  scan_finished: "収集終了",
  scan_failed: "収集失敗",
  csv_export: "CSV出力",
  folderage_import: "FolderAgeから取り込み",
};
$("audit-button").onclick = async () => {
  try {
    const rows = await api("/api/audit");
    $("audit-list").innerHTML = rows
      .map(
        (r) =>
          `<div class="error-item"><strong>${esc(actions[r.action] || r.action)}</strong> · ${esc(r.actor)} · ${date(r.at)}<br><span class="muted">${esc(r.detail)}</span></div>`,
      )
      .join("");
    $("audit-modal").classList.remove("hidden");
  } catch (e) {
    error(e);
  }
};
$("close-audit").onclick = () => $("audit-modal").classList.add("hidden");
async function init() {
  try {
    me = await api("/api/me");
    csrf = me.csrf;
    $("current-user").textContent = me.display_name;
    $("depth").classList.add("hidden");
    await refresh();
  } catch (e) {
    error(e);
  }
}
init();
const poll = setInterval(refresh, 5000);
