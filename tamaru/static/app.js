"use strict";
let csrf = "",
  me = null,
  resetId = null;
const $ = (id) => document.getElementById(id);
let recursiveFolder = false;
let view = "browse",
  page = 1,
  totalPages = 1,
  folder = "",
  requestId = 0,
  lastSignature = "",
  lastReportSignature = "",
  hadScan = false,
  busy = false,
  refreshing = false,
  trail = [],
  settingsTimezone = "Asia/Tokyo";
const nf = new Intl.NumberFormat("ja-JP");
const fmt = (n) => nf.format(n ?? 0);
const pathName = (path) => path.split(/[\\/]/).filter(Boolean).pop() || path;
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
    recursive: recursiveFolder ? "1" : "0",
  });
}
function navigate(rootId = "", path = "") {
  $("root").value = String(rootId);
  folder = path;
  recursiveFolder = true;
  view = "browse";
  page = 1;
  updateTabs();
  list().catch(error);
}
function updateTabs() {
  $("files-tab").classList.toggle("active", view === "files");
  $("folders-tab").classList.toggle("active", view === "browse");
}
function breadcrumbs(rootId) {
  const nav = $("breadcrumb");
  nav.replaceChildren();
  const add = (label, action, current = false) => {
    if (nav.childElementCount) {
      const separator = document.createElement("span");
      separator.textContent = "/";
      separator.setAttribute("aria-hidden", "true");
      nav.appendChild(separator);
    }
    const button = document.createElement("button");
    button.textContent = label;
    button.onclick = action;
    if (current) button.setAttribute("aria-current", "page");
    nav.appendChild(button);
  };
  add(
    "すべての対象フォルダ",
    () => navigate(),
    view === "browse" && !trail.length,
  );
  trail.forEach((part, index) =>
    add(
      part.name,
      () => navigate(rootId, part.path),
      view === "browse" && index === trail.length - 1,
    ),
  );
  if (view === "files") add("ファイル一覧", () => {}, true);
}
async function list() {
  const id = ++requestId;
  let d;
  try {
    d = await api(
      (view === "browse" ? "/api/browse?" : "/api/list?") + params(),
    );
  } catch (e) {
    lastSignature = "";
    throw e;
  }
  if (id !== requestId) return false;
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
      : '<tr><th>名前</th><th class="num">容量</th><th class="num">ファイル数</th><th class="num">最長滞留日数</th><th>最終確認 / 状態</th></tr>';
  $("tbody").innerHTML = d.rows
    .map((r, i) =>
      view === "files"
        ? `<tr><td><div class="filename">${esc(r.name)}</div><div class="path" title="${esc(r.path)}">${esc(r.parent)}</div></td><td class="num" title="${fmt(r.size)} bytes">${bytes(r.size)}</td><td class="num"><span class="age ${r.age >= 30 ? "old" : ""}">${fmt(r.age)}日</span></td><td style="white-space:nowrap">${date(r.first_seen)}</td><td><div style="white-space:nowrap">${date(r.last_seen)}</div><span class="state ${r.status === "未確認" ? "unknown" : ""}">${esc(r.status)}</span></td></tr>`
        : `<tr><td><div class="entry-name"><span class="entry-icon" aria-hidden="true">${r.kind === "folder" ? "📁" : "📄"}</span><div>${r.kind === "folder" ? `<button class="folder-button" data-row="${i}" title="${esc(r.path)}">${esc(r.name)}</button><div class="entry-detail">配下を含む${!d.root_id ? " · " + esc(r.path) : ""}</div>` : `<div class="filename" title="${esc(r.path)}">${esc(r.name)}</div><div class="entry-detail">このフォルダ直下のファイル</div>`}</div></div></td><td class="num">${bytes(r.bytes)}</td><td class="num">${r.kind === "folder" ? fmt(r.count) + "件" : "—"}</td><td class="num"><span class="age ${r.age >= 30 ? "old" : ""}">${fmt(r.age)}日</span></td><td>${date(r.last_seen)}<br><span class="state ${r.uncertain ? "unknown" : ""}">${r.uncertain ? "未確認 " + fmt(r.uncertain) + "件" : "確認済み"}</span></td></tr>`,
    )
    .join("");
  $("tbody")
    .querySelectorAll("[data-row]")
    .forEach(
      (b) =>
        (b.onclick = () => {
          const r = d.rows[Number(b.dataset.row)];
          navigate(r.root_id, r.path);
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
  if (view === "browse") {
    trail = d.breadcrumbs;
    folder = d.folder;
    recursiveFolder = true;
    $("location-title").textContent = trail.length
      ? trail[trail.length - 1].name
      : "対象フォルダ";
    $("location-path").textContent =
      folder || "登録した対象フォルダごとの配下合計";
    $("location-summary").textContent =
      `配下 ${fmt(d.totals.count)}ファイル · ${bytes(d.totals.bytes)}${d.totals.uncertain ? " · 未確認 " + fmt(d.totals.uncertain) + "件" : ""}（現在の検索・日数条件）`;
  } else {
    $("location-title").textContent = "ファイル一覧";
    $("location-path").textContent =
      folder ||
      ($("root").value
        ? $("root").selectedOptions[0].textContent
        : "すべての対象フォルダ");
    $("location-summary").textContent =
      `${fmt(d.count)}ファイル · 配下の階層をまとめて表示`;
  }
  $("subtree-files").classList.toggle(
    "hidden",
    view !== "browse" || !d.root_id,
  );
  breadcrumbs(view === "browse" ? d.root_id : $("root").value);
  $("error").classList.add("hidden");
  return true;
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
    const trendRoot = document.getElementById("trend-root");
    if (
      trendRoot.value &&
      !d.roots.some((r) => String(r.id) === trendRoot.value)
    ) {
      trendRoot.value = "";
    }
    const rootHTML =
      '<option value="">すべての対象フォルダ</option>' +
      d.roots
        .map((r) => {
          const name = pathName(r.path);
          const duplicate = d.roots.some(
            (other) => other.id !== r.id && pathName(other.path) === name,
          );
          return `<option value="${r.id}" title="${esc(r.path)}">${esc(duplicate ? r.path : name)}</option>`;
        })
        .join("");
    if ($("root").innerHTML !== rootHTML) {
      $("root").innerHTML = rootHTML;
      $("root").value = old;
      if (!$("root").value) {
        $("root").value = "";
        folder = "";
        trail = [];
      }
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
      if (await list()) lastSignature = signature;
    }
    if (signature !== lastReportSignature) {
      if (await refreshReports()) lastReportSignature = signature;
    }
  } catch (e) {
    error(e);
  } finally {
    refreshing = false;
  }
}
function setView(mode) {
  view = mode;
  page = 1;
  folder = "";
  trail = [];
  $("root").value = "";
  recursiveFolder = true;
  updateTabs();
  list().catch(error);
}
$("files-tab").onclick = () => setView("files");
$("folders-tab").onclick = () => setView("browse");
$("subtree-files").onclick = () => {
  view = "files";
  page = 1;
  recursiveFolder = true;
  updateTabs();
  list().catch(error);
};
let searchTimer;
$("search").oninput = () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    page = 1;
    list().catch(error);
  }, 250);
};
["root", "age", "sort"].forEach(
  (id) =>
    ($(id).onchange = () => {
      if (id === "root") {
        folder = "";
        trail = [];
        recursiveFolder = true;
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
    settingsTimezone = c.timezone;
    $("schedule-timezone").textContent = c.timezone;
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
      timezone: settingsTimezone,
    });
    $("modal").classList.add("hidden");
    folder = "";
    trail = [];
    $("root").value = "";
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
    await refresh();
  } catch (e) {
    error(e);
  }
}
init();
const poll = setInterval(refresh, 5000);
