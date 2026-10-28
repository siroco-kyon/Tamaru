"use strict";
const reportState = { request: 0, data: null };
const reportNode = (id) => document.getElementById(id);

function reportError(e) {
  lastReportSignature = "";
  reportNode("report-error").textContent = e.message || String(e);
  reportNode("report-error").classList.remove("hidden");
}

async function refreshTrends() {
  const id = ++reportState.request;
  const params = new URLSearchParams({ days: reportNode("trend-days").value });
  const root = reportNode("trend-root").value;
  if (root) params.set("root", root);
  const data = await api("/api/trends?" + params);
  if (id !== reportState.request) return false;
  const select = reportNode("trend-root");
  const options =
    '<option value="">すべての対象フォルダ</option>' +
    data.roots
      .map((r) => {
        const name = pathName(r.path);
        const duplicate = data.roots.some(
          (other) => other.id !== r.id && pathName(other.path) === name,
        );
        return `<option value="${r.id}" title="${esc(r.path)}">${esc(duplicate ? r.path : name)}</option>`;
      })
      .join("");
  if (select.innerHTML !== options) {
    select.innerHTML = options;
    select.value = data.root_id == null ? "" : String(data.root_id);
  }
  reportState.data = data;
  drawTrend();
  const signed = (value, format) =>
    value == null
      ? "—"
      : (value > 0 ? "+" : value < 0 ? "−" : "") + format(Math.abs(value));
  reportNode("trend-rows").innerHTML = [...data.rows]
    .reverse()
    .map(
      (r) =>
        `<tr><td>${esc(r.date)}</td><td class="num">${r.bytes == null ? "—" : bytes(r.bytes)}</td><td class="num">${r.count == null ? "—" : fmt(r.count)}</td><td class="num">${signed(r.delta_bytes, bytes)}</td><td class="num">${signed(r.delta_count, fmt)}</td><td>${r.comparison_days == null ? "" : `${fmt(r.comparison_days)}日前の正常結果比 · `}${esc(r.status)}${r.warning ? "（後続の収集に未確認等あり）" : ""}</td></tr>`,
    )
    .join("");
  return true;
}

function drawTrend() {
  const data = reportState.data;
  if (!data) return;
  const host = reportNode("trend-chart");
  host.replaceChildren();
  const metric = reportNode("trend-metric").value;
  const format = metric === "bytes" ? bytes : fmt;
  const values = data.rows.filter((r) => r[metric] != null);
  if (!values.length) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent =
      "この期間には正常な収集結果がありません。対象フォルダを選ぶか、収集を実行してください。";
    host.appendChild(empty);
    return;
  }
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 900 260");
  svg.setAttribute("role", "img");
  svg.setAttribute(
    "aria-label",
    `日別の${metric === "bytes" ? "合計容量" : "ファイル数"}。日本時間、${data.days}日間。詳細は下の日別表を参照してください。`,
  );
  const element = (tag, attrs, label) => {
    const node = document.createElementNS(ns, tag);
    for (const [key, value] of Object.entries(attrs))
      node.setAttribute(key, value);
    if (label != null) node.textContent = label;
    svg.appendChild(node);
    return node;
  };
  const rawMax = Math.max(4, ...values.map((r) => r[metric]));
  const max = metric === "count" ? Math.ceil(rawMax / 4) * 4 : rawMax * 1.1;
  const x = (i) => 80 + (i / Math.max(1, data.rows.length - 1)) * 790;
  const y = (value) => 215 - (value / max) * 190;
  for (let i = 0; i <= 4; i++) {
    const value = (max * i) / 4;
    element("line", {
      x1: 80,
      x2: 870,
      y1: y(value),
      y2: y(value),
      class: "chart-grid",
    });
    element(
      "text",
      { x: 70, y: y(value) + 4, "text-anchor": "end", class: "chart-label" },
      format(value),
    );
  }
  const positions = new Set([
    0,
    Math.floor((data.rows.length - 1) / 2),
    data.rows.length - 1,
  ]);
  for (const i of positions) {
    element(
      "text",
      { x: x(i), y: 244, "text-anchor": "middle", class: "chart-label" },
      data.rows[i].date.slice(5),
    );
  }
  let path = "";
  const flush = () => {
    if (path) element("path", { d: path, class: "chart-line" });
    path = "";
  };
  data.rows.forEach((row, i) => {
    if (row[metric] == null) {
      flush();
      return;
    }
    path += `${path ? " L" : "M"}${x(i)},${y(row[metric])}`;
  });
  flush();
  data.rows.forEach((row, i) => {
    if (row[metric] == null) return;
    const label = `${row.date}: ${format(row[metric])}${row.warning ? "（後続の収集に未確認等あり）" : ""}`;
    const point = element("circle", {
      cx: x(i),
      cy: y(row[metric]),
      r: 3.5,
      class: "chart-point",
      tabindex: "0",
      "aria-label": label,
    });
    const title = document.createElementNS(ns, "title");
    title.textContent = label;
    point.appendChild(title);
  });
  host.appendChild(svg);
  if (values.length === 1) {
    const note = document.createElement("p");
    note.className = "report-note";
    note.textContent =
      "正常な記録は1日分です。継続して収集すると日ごとの推移を表示できます。";
    host.appendChild(note);
  }
}

async function refreshReports() {
  try {
    const [fresh, storage] = await Promise.all([
      refreshTrends(),
      api("/api/storage"),
    ]);
    reportNode("storage-records").textContent =
      `記録 ${fmt(storage.file_records)}ファイル（消失記録を含む）`;
    reportNode("storage-summary").innerHTML = [
      ["管理DB", storage.database_bytes],
      ["収集用一時DB", storage.staging_bytes],
      ["SQLite作業ファイル", storage.journal_bytes],
      ["合計", storage.total_bytes],
    ]
      .map(
        ([label, value]) =>
          `<span>${label}<strong>${bytes(value)}</strong></span>`,
      )
      .join("");
    reportNode("storage-warning").textContent = storage.warning || "";
    if (fresh) reportNode("report-error").classList.add("hidden");
    return fresh;
  } catch (e) {
    reportError(e);
    return false;
  }
}
reportNode("trend-root").onchange = () =>
  refreshTrends()
    .then(() => reportNode("report-error").classList.add("hidden"))
    .catch(reportError);
reportNode("trend-days").onchange = reportNode("trend-root").onchange;
reportNode("trend-metric").onchange = drawTrend;
reportNode("reports-refresh").onclick = refreshReports;
