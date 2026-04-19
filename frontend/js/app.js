const token = localStorage.getItem("token");

const features = [
  { key: "wireguard", title: "WireGuard" },
  { key: "amneziawg", title: "AmneziaWG" },
  { key: "dns", title: "DNS" },
  { key: "zapret", title: "Zapret" },
  { key: "backups", title: "Backups" },
];

const WG_PARAMS_KEYS = [
  "SERVER_PUB_IP",
  "SERVER_PUB_NIC",
  "SERVER_WG_NIC",
  "SERVER_WG_IPV4",
  "SERVER_WG_IPV6",
  "SERVER_PORT",
  "SERVER_PRIV_KEY",
  "SERVER_PUB_KEY",
  "CLIENT_DNS_1",
  "CLIENT_DNS_2",
  "ALLOWED_IPS",
];

function wgParamsLabelRu(key) {
  const labels = {
    SERVER_PUB_IP: "Публичный IP или DNS (Endpoint)",
    SERVER_PUB_NIC: "Публичный NIC",
    SERVER_WG_NIC: "Интерфейс WG",
    SERVER_WG_IPV4: "IPv4 сети туннеля",
    SERVER_WG_IPV6: "IPv6 сети туннеля",
    SERVER_PORT: "Порт UDP",
    SERVER_PRIV_KEY: "Приватный ключ сервера",
    SERVER_PUB_KEY: "Публичный ключ сервера (Peer)",
    CLIENT_DNS_1: "DNS для клиентов (1)",
    CLIENT_DNS_2: "DNS для клиентов (2)",
    ALLOWED_IPS: "AllowedIPs (клиенты)",
  };
  return labels[key] || key;
}

const listEl = document.getElementById("feature-list");
const titleEl = document.getElementById("feature-title");
const formEl = document.getElementById("feature-form");
const outputEl = document.getElementById("result-panel");
const headActionsEl = document.getElementById("feature-head-actions");
const featurePanelHead = document.querySelector(".feature-panel-head");

function restoreFeatureTitleToPanelHead() {
  if (!featurePanelHead || !titleEl || !headActionsEl) return;
  if (headActionsEl.contains(titleEl)) {
    featurePanelHead.insertBefore(titleEl, headActionsEl);
  }
}

function clearHeadActions() {
  if (!headActionsEl) return;
  restoreFeatureTitleToPanelHead();
  headActionsEl.replaceChildren();
}

function clearFeatureTitleMobileHide() {
  titleEl.classList.remove("feature-title-hide-mobile");
}

const WG_MOBILE_MQ = window.matchMedia("(max-width: 900px)");
function wgIsMobileLayout() {
  return WG_MOBILE_MQ.matches;
}
let wgLayoutMqlCleanup = null;
function cleanupWgLayoutMql() {
  wgLayoutMqlCleanup?.();
  wgLayoutMqlCleanup = null;
}

const WG_VIEW_KEY = "wireguard_view";

function setWireGuardClientView(name) {
  sessionStorage.setItem(WG_VIEW_KEY, `client:${name}`);
}

function clearWireGuardClientView() {
  sessionStorage.removeItem(WG_VIEW_KEY);
}

/** Карточка клиента без #wireguard в URL — только sessionStorage */
function parseWireGuardView() {
  const v = sessionStorage.getItem(WG_VIEW_KEY);
  if (v && v.startsWith("client:")) {
    const name = v.slice(7);
    if (name) return { type: "client", name };
  }
  return { type: "list" };
}

/** Старые закладки #wireguard / #wireguard/client/… */
function migrateLegacyWireguardHash() {
  const h = location.hash || "";
  if (!h.startsWith("#wireguard")) return;
  const raw = h.replace(/^#/, "").replace(/^\/+/, "");
  if (raw.startsWith("wireguard/client/")) {
    const m = /^wireguard\/client\/(.+)$/.exec(raw);
    if (m) {
      try {
        setWireGuardClientView(decodeURIComponent(m[1]));
      } catch {
        /* ignore */
      }
    }
  } else {
    clearWireGuardClientView();
  }
  localStorage.setItem("activeFeatureKey", "wireguard");
  history.replaceState(null, "", "/dashboard");
  location.hash = "";
}

document.getElementById("logout-btn").onclick = () => {
  localStorage.removeItem("token");
  window.location.href = "/login";
};

const root = document.documentElement;
const THEME_STORAGE_KEY = "theme";

document.getElementById("theme-toggle").onclick = () => {
  const now = root.getAttribute("data-theme") === "light" ? "dark" : "light";
  root.setAttribute("data-theme", now);
  localStorage.setItem(THEME_STORAGE_KEY, now);
};

const storedTheme = localStorage.getItem(THEME_STORAGE_KEY);
const initialTheme =
  storedTheme === "light" || storedTheme === "dark" ? storedTheme : "dark";
root.setAttribute("data-theme", initialTheme);

/** Split user input by whitespace (spaces, tabs, newlines). */
function parseSpaceSeparated(raw) {
  return String(raw || "")
    .trim()
    .split(/\s+/)
    .filter(Boolean);
}

/** Runs async work with loading spinner + disabled state on a refresh-style button. */
async function withButtonLoading(btn, work) {
  if (!btn || btn.classList.contains("btn-loading")) return;
  btn.disabled = true;
  btn.classList.add("btn-loading");
  btn.setAttribute("aria-busy", "true");
  try {
    await work();
  } finally {
    btn.disabled = false;
    btn.classList.remove("btn-loading");
    btn.removeAttribute("aria-busy");
  }
}

/** Russian plural for 1 / 2–4 / 5+ (11–14 always many). */
function ruUnit(n, one, few, many) {
  const nAbs = Math.floor(Math.abs(n));
  const nn = nAbs % 100;
  const n1 = nAbs % 10;
  if (nn >= 11 && nn <= 14) return many;
  if (n1 === 1) return one;
  if (n1 >= 2 && n1 <= 4) return few;
  return many;
}

/**
 * @param {number|Date|string} input — unix sec/ms, Date, или строка для Date.parse
 * @returns {string}
 */
function formatRelativeTimeRu(input) {
  let ms;
  if (input instanceof Date) {
    ms = input.getTime();
  } else if (typeof input === "number" && Number.isFinite(input)) {
    ms = input < 1e12 ? input * 1000 : input;
  } else if (typeof input === "string") {
    const p = Date.parse(input.includes("T") ? input : input.replace(/^(\d{4}-\d{2}-\d{2}) /, "$1T"));
    ms = p;
  } else {
    return "";
  }
  if (!Number.isFinite(ms)) return "";
  const sec = Math.floor((Date.now() - ms) / 1000);
  if (sec < 0) return "только что";
  if (sec === 0) return "только что";
  if (sec < 60) {
    return `${sec} ${ruUnit(sec, "секунду", "секунды", "секунд")} назад`;
  }

  const min = Math.floor(sec / 60);
  if (min < 60) {
    return `${min} ${ruUnit(min, "минуту", "минуты", "минут")} назад`;
  }

  const h = Math.floor(min / 60);
  if (h < 24) {
    return `${h} ${ruUnit(h, "час", "часа", "часов")} назад`;
  }

  const d = Math.floor(h / 24);
  if (d < 30) {
    return `${d} ${ruUnit(d, "день", "дня", "дней")} назад`;
  }

  const mo = Math.floor(d / 30);
  if (mo < 12) {
    return `${mo} ${ruUnit(mo, "месяц", "месяца", "месяцев")} назад`;
  }

  const y = Math.floor(d / 365);
  const yn = Math.max(1, y);
  return `${yn} ${ruUnit(yn, "год", "года", "лет")} назад`;
}

function formatBackupCountdown(seconds) {
  if (seconds == null || Number.isNaN(seconds)) return "—";
  const sec = Math.max(0, Math.floor(Number(seconds)));
  if (sec === 0) return "сейчас";
  const d = Math.floor(sec / 86400);
  let r = sec % 86400;
  const h = Math.floor(r / 3600);
  r %= 3600;
  const m = Math.floor(r / 60);
  const s = r % 60;
  const parts = [];
  if (d) parts.push(`${d} д.`);
  if (h || d) parts.push(`${h} ч.`);
  if (m || h || d) parts.push(`${m} мин`);
  parts.push(`${s} с`);
  return parts.join(" ");
}

let backupPanelTimers = { countdown: null, sync: null };

function cleanupBackupPanelTimers() {
  if (backupPanelTimers.countdown) {
    clearInterval(backupPanelTimers.countdown);
    backupPanelTimers.countdown = null;
  }
  if (backupPanelTimers.sync) {
    clearInterval(backupPanelTimers.sync);
    backupPanelTimers.sync = null;
  }
}

function bindPanelStatus(statusEl) {
  return function setStatus(text, isError) {
    if (!text) {
      statusEl.textContent = "";
      statusEl.hidden = true;
      return;
    }
    statusEl.hidden = false;
    statusEl.textContent = text;
    statusEl.classList.toggle("wg-status-error", Boolean(isError));
  };
}

function formatLastVisit(client) {
  const createdAbs = client.created_at
    ? new Date(client.created_at * 1000).toLocaleString()
    : "";
  const createdRel = client.created_at
    ? formatRelativeTimeRu(client.created_at)
    : "";
  const hs = client.last_handshake;
  if (hs === undefined || hs === null) {
    return {
      main: "нет данных",
      sub: createdRel ? `создан ${createdRel}` : "",
      titleMain: "",
      titleSub: createdAbs || "",
    };
  }
  if (hs === 0) {
    return {
      main: "ещё не подключался",
      sub: createdRel ? `создан ${createdRel}` : "",
      titleMain: "",
      titleSub: createdAbs || "",
    };
  }
  const hsAbs = new Date(hs * 1000).toLocaleString();
  return {
    main: formatRelativeTimeRu(hs),
    sub: "",
    titleMain: hsAbs,
    titleSub: "",
  };
}

function wgDetailTimeToMs(raw) {
  const s = String(raw || "").trim();
  if (!s || s === "unknown") return null;
  const iso = s.includes("T") ? s : s.replace(/^(\d{4}-\d{2}-\d{2}) (\d)/, "$1T$2");
  const p = Date.parse(iso);
  return Number.isNaN(p) ? null : p;
}

/** Скачать конфиг клиента; onErr(message) при ошибке */
async function downloadWgConfigFile(clientName, onErr) {
  const resp = await fetch(
    `/api/wireguard/clients/${encodeURIComponent(clientName)}/config`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  let body;
  try {
    body = await resp.json();
  } catch {
    onErr("Не удалось разобрать ответ сервера");
    return;
  }
  if (!resp.ok) {
    onErr(
      typeof body.detail === "string"
        ? body.detail
        : JSON.stringify(body.detail || body),
    );
    return;
  }
  const cfg = body.config;
  if (typeof cfg !== "string") {
    onErr("Неожиданный формат конфига");
    return;
  }
  const blob = new Blob([cfg], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `wg-${clientName}.conf`;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function downloadAwgConfigFile(clientName, onErr) {
  const resp = await fetch(
    `/api/amneziawg/clients/${encodeURIComponent(clientName)}/config`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  let body;
  try {
    body = await resp.json();
  } catch {
    onErr("Не удалось разобрать ответ сервера");
    return;
  }
  if (!resp.ok) {
    onErr(
      typeof body.detail === "string"
        ? body.detail
        : JSON.stringify(body.detail || body),
    );
    return;
  }
  const cfg = body.config;
  if (typeof cfg !== "string") {
    onErr("Неожиданный формат конфига");
    return;
  }
  const blob = new Blob([cfg], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `awg-${clientName}.conf`;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function renderAmneziaWGPanel() {
  cleanupWgLayoutMql();
  cleanupBackupPanelTimers();
  formEl.innerHTML = "";
  outputEl.textContent = "";
  clearHeadActions();
  titleEl.textContent = "Клиенты AmneziaWG";
  titleEl.classList.add("feature-title-hide-mobile");

  const panel = document.createElement("div");
  panel.className = "wg-panel";

  const status = document.createElement("p");
  status.className = "wg-status muted";

  const wrap = document.createElement("div");
  wrap.className = "wg-table-wrap";
  const table = document.createElement("table");
  table.className = "data-table";
  const thead = document.createElement("thead");
  const tbody = document.createElement("tbody");
  table.append(thead, tbody);
  thead.innerHTML =
    "<tr><th>Клиент</th><th>IP</th><th>Последний визит</th></tr>";

  const toolbar = document.createElement("div");
  toolbar.className = "wg-toolbar";

  const sortSelect = document.createElement("select");
  sortSelect.setAttribute("aria-label", "Сортировка клиентов AmneziaWG");
  const optName = document.createElement("option");
  optName.value = "name";
  optName.textContent = "По имени (А–Я)";
  const optVisit = document.createElement("option");
  optVisit.value = "visit";
  optVisit.textContent = "По последнему визиту";
  optVisit.selected = true;
  sortSelect.append(optName, optVisit);

  const sortHeadLabel = document.createElement("span");
  sortHeadLabel.className = "muted wg-sort-head-label";

  const refreshBtn = document.createElement("button");
  refreshBtn.type = "button";
  refreshBtn.className = "btn-secondary";
  refreshBtn.textContent = "Обновить";

  if (headActionsEl) {
    const headRow = document.createElement("div");
    headRow.className = "feature-head-wg";
    headRow.append(titleEl, sortHeadLabel, sortSelect, refreshBtn);
    headActionsEl.appendChild(headRow);
  } else {
    const headRow = document.createElement("div");
    headRow.className = "feature-head-wg";
    headRow.append(titleEl, sortHeadLabel, sortSelect, refreshBtn);
    toolbar.prepend(headRow);
  }

  const addLabel = document.createElement("label");
  addLabel.className = "wg-add-field";
  const addSpan = document.createElement("span");
  addSpan.className = "muted";
  addSpan.textContent = "Новый клиент";
  const nameInput = document.createElement("input");
  nameInput.type = "text";
  nameInput.maxLength = 15;
  nameInput.placeholder = "имя (латиница, цифры, _-)";
  nameInput.autocomplete = "off";
  addLabel.append(addSpan, nameInput);
  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.textContent = "Добавить";
  toolbar.append(addLabel, addBtn);

  panel.append(status, wrap, toolbar);
  wrap.appendChild(table);
  formEl.appendChild(panel);

  let clientsCache = [];

  function sortAmneziaWGClients(list, mode) {
    const copy = [...list];
    if (mode === "visit") {
      copy.sort((a, b) => {
        const ha =
          typeof a.last_handshake === "number" && a.last_handshake > 0
            ? a.last_handshake
            : 0;
        const hb =
          typeof b.last_handshake === "number" && b.last_handshake > 0
            ? b.last_handshake
            : 0;
        if (ha !== hb) return hb - ha;
        return a.name.localeCompare(b.name, "ru");
      });
    } else {
      copy.sort((a, b) => a.name.localeCompare(b.name, "ru"));
    }
    return copy;
  }

  function setStatus(text, isError) {
    if (!text) {
      status.textContent = "";
      status.hidden = true;
      return;
    }
    status.hidden = false;
    status.textContent = text;
    status.classList.toggle("wg-status-error", Boolean(isError));
  }

  function rowForClient(c) {
    const tr = document.createElement("tr");
    const tdName = document.createElement("td");
    tdName.textContent = c.name;
    const tdIp = document.createElement("td");
    const ipCode = document.createElement("code");
    ipCode.className = "muted";
    ipCode.textContent = c.ipv4 || "";
    tdIp.appendChild(ipCode);
    const tdVisit = document.createElement("td");
    const visit = formatLastVisit(c);
    const main = document.createElement("div");
    main.textContent = visit.main;
    if (visit.titleMain) main.title = visit.titleMain;
    tdVisit.appendChild(main);
    if (visit.sub) {
      const sub = document.createElement("div");
      sub.className = "muted wg-sub";
      sub.textContent = visit.sub;
      if (visit.titleSub) sub.title = visit.titleSub;
      tdVisit.appendChild(sub);
    }
    tr.append(tdName, tdIp, tdVisit);
    return tr;
  }

  function renderClientRows() {
    tbody.replaceChildren();
    const colspan = 3;
    if (!clientsCache.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = colspan;
      td.className = "muted";
      td.textContent = "Клиентов пока нет";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    const sorted = sortAmneziaWGClients(clientsCache, sortSelect.value);
    for (const c of sorted) tbody.appendChild(rowForClient(c));
  }

  async function loadClients() {
    setStatus("");
    const resp = await fetch("/api/amneziawg/clients", {
      headers: { Authorization: `Bearer ${token}` },
    });
    let body;
    try {
      body = await resp.json();
    } catch {
      setStatus("Не удалось разобрать ответ сервера", true);
      clientsCache = [];
      renderClientRows();
      return;
    }
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string"
          ? body.detail
          : JSON.stringify(body.detail || body),
        true,
      );
      clientsCache = [];
      renderClientRows();
      return;
    }
    clientsCache = body.clients || [];
    renderClientRows();
  }

  async function addClient() {
    const name = String(nameInput.value || "").trim();
    if (!name) {
      setStatus("Введите имя клиента", true);
      return;
    }
    setStatus("");
    const resp = await fetch("/api/amneziawg/clients", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ client_name: name }),
    });
    const body = await resp.json();
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string" ? body.detail : JSON.stringify(body),
        true,
      );
      return;
    }
    nameInput.value = "";
    outputEl.textContent = JSON.stringify(body, null, 2);
    await loadClients();
  }

  sortSelect.addEventListener("change", () => renderClientRows());
  addBtn.onclick = () => addClient();
  refreshBtn.onclick = () => withButtonLoading(refreshBtn, loadClients);
  formEl.onsubmit = async (e) => {
    e.preventDefault();
    await addClient();
  };

  loadClients();
}

function renderWireGuardClientDetail(clientName) {
  titleEl.textContent = "Клиент WireGuard";
  titleEl.classList.add("feature-title-hide-mobile");

  const panel = document.createElement("div");
  panel.className = "wg-panel wg-client-detail";

  const status = document.createElement("p");
  status.className = "wg-status muted";

  const headBar = document.createElement("div");
  headBar.className = "wg-toolbar wg-client-detail-head";
  const backBtn = document.createElement("button");
  backBtn.type = "button";
  backBtn.className = "btn-secondary";
  backBtn.textContent = "← К списку клиентов";
  backBtn.onclick = () => {
    clearWireGuardClientView();
    history.pushState(null, "", "/dashboard");
    renderWireGuardPanel();
  };
  headBar.appendChild(backBtn);

  const metaCard = document.createElement("div");
  metaCard.className = "wg-client-meta";

  const actionsRow = document.createElement("div");
  actionsRow.className = "wg-toolbar wg-client-actions";

  const renameLabel = document.createElement("label");
  renameLabel.className = "wg-add-field";
  const renameSpan = document.createElement("span");
  renameSpan.className = "muted";
  renameSpan.textContent = "Новое имя";
  const renameInput = document.createElement("input");
  renameInput.type = "text";
  renameInput.maxLength = 15;
  renameInput.autocomplete = "off";
  renameLabel.append(renameSpan, renameInput);

  const renameBtn = document.createElement("button");
  renameBtn.type = "button";
  renameBtn.textContent = "Переименовать";
  const dlBtn = document.createElement("button");
  dlBtn.type = "button";
  dlBtn.className = "btn-secondary";
  dlBtn.textContent = "Скачать файл";
  const delBtn = document.createElement("button");
  delBtn.type = "button";
  delBtn.className = "btn-danger";
  delBtn.textContent = "Удалить";
  actionsRow.append(renameLabel, renameBtn, dlBtn, delBtn);

  const dnsTitle = document.createElement("h3");
  dnsTitle.className = "panel-section-title";
  dnsTitle.textContent = "DNS по ключевым словам";
  const dnsHint = document.createElement("p");
  dnsHint.className = "muted wg-dns-hint";
  dnsHint.textContent =
    "Те же ключевые слова, что в разделе «DNS». Показываются запросы AdGuard Home с IP туннеля этого клиента.";

  const chartsWrap = document.createElement("div");
  chartsWrap.className = "wg-dns-charts";

  const dnsToolbar = document.createElement("div");
  dnsToolbar.className = "wg-toolbar";
  const dnsRefresh = document.createElement("button");
  dnsRefresh.type = "button";
  dnsRefresh.className = "btn-secondary";
  dnsRefresh.textContent = "Обновить DNS";
  dnsToolbar.appendChild(dnsRefresh);

  const qWrap = document.createElement("div");
  qWrap.className = "wg-table-wrap";
  const qTable = document.createElement("table");
  qTable.className = "data-table";
  const qThead = document.createElement("thead");
  qThead.innerHTML =
    "<tr><th>Время</th><th>Домен</th><th>Ключевые слова</th></tr>";
  const qTbody = document.createElement("tbody");
  qTable.append(qThead, qTbody);

  panel.append(
    status,
    headBar,
    metaCard,
    actionsRow,
    dnsTitle,
    dnsHint,
    chartsWrap,
    dnsToolbar,
    qWrap,
  );
  qWrap.appendChild(qTable);
  formEl.appendChild(panel);

  if (headActionsEl) {
    const headRow = document.createElement("div");
    headRow.className = "feature-head-wg";
    headRow.appendChild(titleEl);
    headActionsEl.appendChild(headRow);
  }

  let currentName = clientName;
  let dnsQueriesCache = [];

  function setStatus(text, isError) {
    if (!text) {
      status.textContent = "";
      status.hidden = true;
      return;
    }
    status.hidden = false;
    status.textContent = text;
    status.classList.toggle("wg-status-error", Boolean(isError));
  }

  function renderDnsCharts(stats) {
    chartsWrap.replaceChildren();
    if (!stats || !stats.total_queries) {
      const p = document.createElement("p");
      p.className = "muted";
      p.textContent =
        "Нет совпадений по ключевым словам или лог AdGuard недоступен.";
      chartsWrap.appendChild(p);
      return;
    }

    const kw = stats.by_keyword || {};
    const kwEntries = Object.entries(kw).sort((a, b) => b[1] - a[1]);
    const maxKw = Math.max(...kwEntries.map((x) => x[1]), 1);

    const kwBlock = document.createElement("div");
    kwBlock.className = "wg-chart-block";
    const kwH = document.createElement("h4");
    kwH.className = "wg-chart-title";
    kwH.textContent = "Совпадения по словам";
    const kwBars = document.createElement("div");
    kwBars.className = "wg-bar-list";
    for (const [k, v] of kwEntries) {
      const row = document.createElement("div");
      row.className = "wg-bar-row";
      const lab = document.createElement("span");
      lab.className = "wg-bar-label";
      lab.textContent = k;
      const track = document.createElement("div");
      track.className = "wg-bar-track";
      const fill = document.createElement("div");
      fill.className = "wg-bar-fill";
      fill.style.width = `${(v / maxKw) * 100}%`;
      const num = document.createElement("span");
      num.className = "wg-bar-num";
      num.textContent = String(v);
      track.appendChild(fill);
      row.append(lab, track, num);
      kwBars.appendChild(row);
    }
    kwBlock.append(kwH, kwBars);

    const domBlock = document.createElement("div");
    domBlock.className = "wg-chart-block";
    const domH = document.createElement("h4");
    domH.className = "wg-chart-title";
    domH.textContent = "Частые домены";
    const topD = stats.top_domains || [];
    const maxD = Math.max(...topD.map((d) => d.count), 1);
    const domBars = document.createElement("div");
    domBars.className = "wg-bar-list";
    for (const { domain: d, count: v } of topD) {
      const row = document.createElement("div");
      row.className = "wg-bar-row";
      const lab = document.createElement("span");
      lab.className = "wg-bar-label wg-bar-label-domain";
      lab.textContent = d;
      lab.title = d;
      const track = document.createElement("div");
      track.className = "wg-bar-track";
      const fill = document.createElement("div");
      fill.className = "wg-bar-fill wg-bar-fill-alt";
      fill.style.width = `${(v / maxD) * 100}%`;
      const num = document.createElement("span");
      num.className = "wg-bar-num";
      num.textContent = String(v);
      track.appendChild(fill);
      row.append(lab, track, num);
      domBars.appendChild(row);
    }
    domBlock.append(domH, domBars);

    chartsWrap.append(kwBlock, domBlock);
  }

  function renderDnsRows() {
    qTbody.replaceChildren();
    const entries = dnsQueriesCache || [];
    if (!entries.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 3;
      td.className = "muted";
      td.textContent = "Нет записей";
      tr.appendChild(td);
      qTbody.appendChild(tr);
      return;
    }
    const sorted = [...entries].sort((a, b) => {
      const ta = wgDetailTimeToMs(a.time);
      const tb = wgDetailTimeToMs(b.time);
      const va = ta == null ? Number.NEGATIVE_INFINITY : ta;
      const vb = tb == null ? Number.NEGATIVE_INFINITY : tb;
      if (va !== vb) return vb - va;
      return (a.domain || "").localeCompare(b.domain || "", "ru");
    });
    for (const e of sorted) {
      const tr = document.createElement("tr");
      const tdT = document.createElement("td");
      const raw = e.time ?? "";
      if (raw === "unknown" || !raw) {
        tdT.textContent = raw || "—";
      } else {
        const p = wgDetailTimeToMs(raw);
        if (p == null) {
          tdT.textContent = raw;
        } else {
          tdT.textContent = formatRelativeTimeRu(p);
          tdT.title = raw;
        }
      }
      const tdD = document.createElement("td");
      tdD.textContent = e.domain ?? "";
      const tdK = document.createElement("td");
      const kws = e.matched_keywords || [];
      tdK.textContent = kws.join(", ");
      tr.append(tdT, tdD, tdK);
      qTbody.appendChild(tr);
    }
  }

  async function loadDns() {
    setStatus("");
    const resp = await fetch(
      `/api/wireguard/clients/${encodeURIComponent(currentName)}/dns-history`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    let body;
    try {
      body = await resp.json();
    } catch {
      setStatus("Не удалось разобрать ответ DNS", true);
      dnsQueriesCache = [];
      renderDnsRows();
      renderDnsCharts(null);
      return;
    }
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string"
          ? body.detail
          : JSON.stringify(body.detail || body),
        true,
      );
      dnsQueriesCache = [];
      renderDnsRows();
      renderDnsCharts(null);
      return;
    }
    dnsQueriesCache = body.entries || [];
    renderDnsCharts(body.stats || null);
    renderDnsRows();
  }

  async function loadClient() {
    setStatus("");
    const resp = await fetch(
      `/api/wireguard/clients/${encodeURIComponent(clientName)}`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    let body;
    try {
      body = await resp.json();
    } catch {
      metaCard.innerHTML = "";
      const err = document.createElement("p");
      err.className = "wg-status-error";
      err.textContent = "Не удалось разобрать ответ сервера";
      metaCard.appendChild(err);
      return;
    }
    if (!resp.ok) {
      metaCard.replaceChildren();
      const err = document.createElement("p");
      err.className = "wg-status-error";
      err.textContent =
        typeof body.detail === "string"
          ? body.detail
          : "Клиент не найден";
      metaCard.appendChild(err);
      return;
    }
    const c = body.client || {};
    currentName = c.name || clientName;
    renameInput.value = currentName;
    metaCard.replaceChildren();
    const grid = document.createElement("dl");
    grid.className = "wg-meta-dl";
    const rows = [
      ["Имя", currentName],
      ["IPv4", c.ipv4 || "—"],
      ["IPv6", c.ipv6 || "—"],
      ["Публичный ключ", c.public_key || "—"],
      [
        "Создан",
        c.created_at
          ? `${new Date(c.created_at * 1000).toLocaleString()} (${formatRelativeTimeRu(c.created_at)})`
          : "—",
      ],
    ];
    const visit = formatLastVisit(c);
    rows.push(["Последний визит", `${visit.main}${visit.sub ? ` · ${visit.sub}` : ""}`]);
    for (const [dt, dd] of rows) {
      const dtEl = document.createElement("dt");
      dtEl.textContent = dt;
      const ddEl = document.createElement("dd");
      if (dt === "Публичный ключ") {
        const code = document.createElement("code");
        code.className = "wg-pubkey";
        code.textContent = dd;
        ddEl.appendChild(code);
      } else {
        ddEl.textContent = dd;
      }
      grid.append(dtEl, ddEl);
    }
    metaCard.appendChild(grid);
  }

  renameBtn.onclick = async () => {
    const trimmed = String(renameInput.value || "").trim();
    if (!trimmed || trimmed === currentName) {
      setStatus("Введите другое имя", true);
      return;
    }
    setStatus("");
    const resp = await fetch("/api/wireguard/clients/rename", {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ old_name: currentName, new_name: trimmed }),
    });
    const body = await resp.json();
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string" ? body.detail : JSON.stringify(body),
        true,
      );
      return;
    }
    setWireGuardClientView(trimmed);
    history.replaceState(null, "", "/dashboard");
    renderWireGuardPanel();
  };

  dlBtn.onclick = async () => {
    await downloadWgConfigFile(currentName, (msg) => setStatus(msg, true));
  };

  delBtn.onclick = async () => {
    if (!confirm(`Удалить клиента «${currentName}»?`)) return;
    setStatus("");
    const resp = await fetch(
      `/api/wireguard/clients/${encodeURIComponent(currentName)}`,
      { method: "DELETE", headers: { Authorization: `Bearer ${token}` } },
    );
    const body = await resp.json();
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string" ? body.detail : JSON.stringify(body),
        true,
      );
      return;
    }
    clearWireGuardClientView();
    history.pushState(null, "", "/dashboard");
    renderWireGuardPanel();
  };

  dnsRefresh.onclick = () => withButtonLoading(dnsRefresh, loadDns);

  loadClient();
  loadDns();
}

function renderWireGuardPanel() {
  cleanupWgLayoutMql();
  cleanupBackupPanelTimers();
  formEl.innerHTML = "";
  outputEl.textContent = "";
  clearHeadActions();

  const route = parseWireGuardView();
  if (route.type === "client" && route.name) {
    renderWireGuardClientDetail(route.name);
    return;
  }

  titleEl.textContent = "Клиенты WireGuard";
  titleEl.classList.add("feature-title-hide-mobile");

  const panel = document.createElement("div");
  panel.className = "wg-panel";

  const paramsSection = document.createElement("section");
  paramsSection.className = "wg-params-block";
  const paramsTitle = document.createElement("h3");
  paramsTitle.className = "panel-section-title";
  paramsTitle.textContent = "Параметры сервера (params)";
  const paramsPathHint = document.createElement("p");
  paramsPathHint.className = "muted wg-params-path";
  const paramsFieldsWrap = document.createElement("div");
  paramsFieldsWrap.className = "wg-params-grid";
  const paramsToolbar = document.createElement("div");
  paramsToolbar.className = "wg-toolbar";
  const applyLabel = document.createElement("label");
  applyLabel.className = "wg-add-field wg-params-apply";
  const applyCb = document.createElement("input");
  applyCb.type = "checkbox";
  applyCb.id = "wg-params-apply-clients";
  const applySpan = document.createElement("span");
  applySpan.className = "muted";
  applySpan.textContent = "Перезаписать клиентов";
  applyLabel.append(applyCb, applySpan);
  const paramsSaveBtn = document.createElement("button");
  paramsSaveBtn.type = "button";
  paramsSaveBtn.textContent = "Сохранить";
  paramsToolbar.append(applyLabel, paramsSaveBtn);
  const paramsStatus = document.createElement("p");
  paramsStatus.className = "wg-status muted";
  paramsStatus.hidden = true;
  paramsSection.append(
    paramsTitle,
    paramsPathHint,
    paramsFieldsWrap,
    paramsToolbar,
    paramsStatus,
  );

  const status = document.createElement("p");
  status.className = "wg-status muted";

  const wrap = document.createElement("div");
  wrap.className = "wg-table-wrap";

  const table = document.createElement("table");
  table.className = "data-table";
  const thead = document.createElement("thead");
  const tbody = document.createElement("tbody");
  table.append(thead, tbody);

  function syncWgTableHead() {
    thead.innerHTML =
      "<tr><th>Клиент</th><th>IP</th><th>Последний визит</th></tr>";
  }
  syncWgTableHead();

  const toolbar = document.createElement("div");
  toolbar.className = "wg-toolbar";

  const sortSelect = document.createElement("select");
  sortSelect.setAttribute("aria-label", "Сортировка клиентов WireGuard");
  const optName = document.createElement("option");
  optName.value = "name";
  optName.textContent = "По имени (А–Я)";
  const optVisit = document.createElement("option");
  optVisit.value = "visit";
  optVisit.textContent = "По последнему визиту";
  optVisit.selected = true;
  sortSelect.append(optName, optVisit);

  const sortHeadLabel = document.createElement("span");
  sortHeadLabel.className = "muted wg-sort-head-label";

  const refreshBtn = document.createElement("button");
  refreshBtn.type = "button";
  refreshBtn.id = "wg-refresh-btn";
  refreshBtn.textContent = "Обновить";

  if (headActionsEl) {
    const headRow = document.createElement("div");
    headRow.className = "feature-head-wg";
    headRow.append(titleEl, sortHeadLabel, sortSelect, refreshBtn);
    headActionsEl.appendChild(headRow);
  } else {
    const headRow = document.createElement("div");
    headRow.className = "feature-head-wg";
    headRow.append(titleEl, sortHeadLabel, sortSelect, refreshBtn);
    toolbar.prepend(headRow);
  }

  const addLabel = document.createElement("label");
  addLabel.className = "wg-add-field";
  const addSpan = document.createElement("span");
  addSpan.className = "muted";
  addSpan.textContent = "Новый клиент";
  const nameInput = document.createElement("input");
  nameInput.type = "text";
  nameInput.id = "wg-new-name";
  nameInput.name = "client_name";
  nameInput.maxLength = 15;
  nameInput.placeholder = "имя (латиница, цифры, _-)";
  nameInput.autocomplete = "off";
  addLabel.append(addSpan, nameInput);
  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.id = "wg-add-btn";
  addBtn.textContent = "Добавить";
  toolbar.append(addLabel, addBtn);

  let clientsCache = [];

  function sortWireGuardClients(list, mode) {
    const copy = [...list];
    if (mode === "visit") {
      copy.sort((a, b) => {
        const ha =
          typeof a.last_handshake === "number" && a.last_handshake > 0
            ? a.last_handshake
            : 0;
        const hb =
          typeof b.last_handshake === "number" && b.last_handshake > 0
            ? b.last_handshake
            : 0;
        if (ha !== hb) return hb - ha;
        return a.name.localeCompare(b.name, "ru");
      });
    } else {
      copy.sort((a, b) => a.name.localeCompare(b.name, "ru"));
    }
    return copy;
  }

  function renderClientRows() {
    tbody.replaceChildren();
    const colspan = 3;
    if (!clientsCache.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = colspan;
      td.className = "muted";
      td.textContent = "Клиентов пока нет";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    const sorted = sortWireGuardClients(clientsCache, sortSelect.value);
    for (const c of sorted) tbody.appendChild(rowForClient(c));
  }

  panel.append(status, wrap, toolbar, paramsSection);
  wrap.appendChild(table);
  formEl.appendChild(panel);

  async function loadWgParams() {
    paramsStatus.hidden = true;
    paramsFieldsWrap.replaceChildren();
    paramsPathHint.textContent = "Загрузка…";
    const resp = await fetch("/api/wireguard/params", {
      headers: { Authorization: `Bearer ${token}` },
    });
    let body;
    try {
      body = await resp.json();
    } catch {
      paramsPathHint.textContent = "";
      paramsStatus.textContent = "Не удалось разобрать ответ сервера";
      paramsStatus.hidden = false;
      paramsStatus.classList.add("wg-status-error");
      return;
    }
    if (!resp.ok) {
      paramsPathHint.textContent = "";
      paramsStatus.textContent =
        typeof body.detail === "string"
          ? body.detail
          : JSON.stringify(body.detail || body);
      paramsStatus.hidden = false;
      paramsStatus.classList.add("wg-status-error");
      return;
    }
    paramsStatus.classList.remove("wg-status-error");
    paramsPathHint.textContent = `${body.path}${body.exists ? "" : " (файл ещё не создан)"}`;
    const vals = body.params || {};
    for (const key of WG_PARAMS_KEYS) {
      const label = document.createElement("label");
      label.className = "wg-param-field";
      const span = document.createElement("span");
      span.className = "muted";
      span.textContent = wgParamsLabelRu(key);
      const isLong =
        key.includes("KEY") || key === "ALLOWED_IPS" || key.includes("IPV");
      const input = isLong
        ? document.createElement("textarea")
        : document.createElement("input");
      if (input.tagName === "INPUT") input.type = "text";
      if (input.tagName === "TEXTAREA") input.rows = 2;
      input.dataset.paramKey = key;
      input.value = vals[key] ?? "";
      input.autocomplete = "off";
      label.append(span, input);
      paramsFieldsWrap.appendChild(label);
    }
  }

  paramsSaveBtn.onclick = async () => {
    paramsStatus.hidden = true;
    const payload = {};
    paramsFieldsWrap.querySelectorAll("[data-param-key]").forEach((el) => {
      payload[el.dataset.paramKey] = el.value;
    });
    const resp = await fetch("/api/wireguard/params", {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        params: payload,
        apply_to_clients: applyCb.checked,
      }),
    });
    let body;
    try {
      body = await resp.json();
    } catch {
      paramsStatus.textContent = "Не удалось разобрать ответ сервера";
      paramsStatus.hidden = false;
      paramsStatus.classList.add("wg-status-error");
      return;
    }
    if (!resp.ok) {
      paramsStatus.textContent =
        typeof body.detail === "string"
          ? body.detail
          : JSON.stringify(body.detail || body);
      paramsStatus.hidden = false;
      paramsStatus.classList.add("wg-status-error");
      return;
    }
    paramsStatus.classList.remove("wg-status-error");
    let msg = "Сохранено.";
    if (body.clients_updated != null) {
      msg += ` Обновлено клиентских конфигов: ${body.clients_updated}.`;
    }
    paramsStatus.textContent = msg;
    paramsStatus.hidden = false;
    applyCb.checked = false;
  };

  function setStatus(text, isError) {
    if (!text) {
      status.textContent = "";
      status.hidden = true;
      return;
    }
    status.hidden = false;
    status.textContent = text;
    status.classList.toggle("wg-status-error", Boolean(isError));
  }

  function rowForClient(c) {
    const tr = document.createElement("tr");
    const tdName = document.createElement("td");
    const nameLink = document.createElement("a");
    nameLink.href = "/dashboard";
    nameLink.dataset.wgClient = c.name;
    nameLink.className = "wg-client-open-link";
    nameLink.textContent = c.name;
    nameLink.title = "Подробнее";
    nameLink.setAttribute("aria-label", `Открыть клиента ${c.name}`);
    tdName.appendChild(nameLink);

    const tdIp = document.createElement("td");
    const ipCode = document.createElement("code");
    ipCode.className = "muted";
    ipCode.textContent = c.ipv4 || "";
    tdIp.appendChild(ipCode);

    const tdVisit = document.createElement("td");
    const visit = formatLastVisit(c);
    const main = document.createElement("div");
    main.textContent = visit.main;
    if (visit.titleMain) main.title = visit.titleMain;
    tdVisit.appendChild(main);
    if (visit.sub) {
      const sub = document.createElement("div");
      sub.className = "muted wg-sub";
      sub.textContent = visit.sub;
      if (visit.titleSub) sub.title = visit.titleSub;
      tdVisit.appendChild(sub);
    }

    tr.append(tdName, tdIp, tdVisit);
    return tr;
  }

  async function loadClients() {
    setStatus("");
    const resp = await fetch("/api/wireguard/clients", {
      headers: { Authorization: `Bearer ${token}` },
    });
    let body;
    try {
      body = await resp.json();
    } catch {
      clientsCache = [];
      setStatus("Не удалось разобрать ответ сервера", true);
      tbody.replaceChildren();
      return;
    }
    if (!resp.ok) {
      clientsCache = [];
      const msg =
        typeof body.detail === "string"
          ? body.detail
          : JSON.stringify(body.detail || body);
      setStatus(msg, true);
      tbody.replaceChildren();
      return;
    }
    clientsCache = body.clients || [];
    renderClientRows();
  }

  sortSelect.addEventListener("change", () => renderClientRows());

  async function addClient() {
    const name = String(nameInput.value || "").trim();
    if (!name) {
      setStatus("Введите имя клиента", true);
      return;
    }
    setStatus("");
    const resp = await fetch("/api/wireguard/clients", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ client_name: name }),
    });
    const body = await resp.json();
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string" ? body.detail : JSON.stringify(body),
        true,
      );
      return;
    }
    nameInput.value = "";
    outputEl.textContent = JSON.stringify(body, null, 2);
    await loadClients();
  }

  formEl.onsubmit = async (e) => {
    e.preventDefault();
    await addClient();
  };

  addBtn.onclick = () => addClient();
  refreshBtn.onclick = () => withButtonLoading(refreshBtn, loadClients);

  const onWgLayout = () => {
    if (!thead.isConnected) {
      cleanupWgLayoutMql();
      return;
    }
    syncWgTableHead();
    renderClientRows();
  };
  WG_MOBILE_MQ.addEventListener("change", onWgLayout);
  wgLayoutMqlCleanup = () => WG_MOBILE_MQ.removeEventListener("change", onWgLayout);

  loadWgParams();
  loadClients();
}

function renderZapretPanel() {
  cleanupWgLayoutMql();
  cleanupBackupPanelTimers();
  clearHeadActions();
  clearFeatureTitleMobileHide();
  titleEl.textContent = "Zapret";
  formEl.innerHTML = "";
  outputEl.textContent = "";

  const panel = document.createElement("div");
  panel.className = "wg-panel";

  const status = document.createElement("p");
  status.className = "wg-status muted";
  const setStatus = bindPanelStatus(status);

  let listsCache = [];

  const row1 = document.createElement("div");
  row1.className = "zapret-row";
  const listLabel = document.createElement("label");
  listLabel.className = "wg-add-field";
  const listSpan = document.createElement("span");
  listSpan.className = "muted";
  listSpan.textContent = "Файл списка (.txt)";
  const listSelect = document.createElement("select");
  listSelect.id = "zapret-list-select";
  listLabel.append(listSpan, listSelect);

  const sitesLabel = document.createElement("label");
  sitesLabel.className = "wg-add-field zapret-sites-field";
  const sitesSpan = document.createElement("span");
  sitesSpan.className = "muted";
  sitesSpan.textContent = "Сайты (через пробел)";
  const sitesInput = document.createElement("textarea");
  sitesInput.id = "zapret-sites";
  sitesInput.rows = 3;
  sitesInput.placeholder = "example.com foo.org …";
  sitesLabel.append(sitesSpan, sitesInput);

  row1.append(listLabel, sitesLabel);

  const toolbar = document.createElement("div");
  toolbar.className = "wg-toolbar";
  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.textContent = "Добавить в список";
  const refreshListsBtn = document.createElement("button");
  refreshListsBtn.type = "button";
  refreshListsBtn.className = "btn-secondary";
  refreshListsBtn.textContent = "Обновить списки";
  toolbar.append(addBtn, refreshListsBtn);

  const checkTitle = document.createElement("h3");
  checkTitle.className = "panel-section-title";
  checkTitle.textContent = "Проверить сайт";
  const checkRow = document.createElement("div");
  checkRow.className = "wg-toolbar";
  const checkInput = document.createElement("input");
  checkInput.type = "text";
  checkInput.placeholder = "домен или URL";
  checkInput.className = "zapret-check-input";
  const checkBtn = document.createElement("button");
  checkBtn.type = "button";
  checkBtn.textContent = "Проверить";
  checkRow.append(checkInput, checkBtn);

  const removeTitle = document.createElement("h3");
  removeTitle.className = "panel-section-title";
  removeTitle.textContent = "Удалить адрес из списка";
  const removeHint = document.createElement("p");
  removeHint.className = "muted zapret-hint";
  removeHint.textContent =
    "Тот же файл, что и для добавления. Адреса — через пробел; сравнение построчно (как в файле).";
  const removeLabel = document.createElement("label");
  removeLabel.className = "wg-add-field zapret-sites-field";
  const removeSpan = document.createElement("span");
  removeSpan.className = "muted";
  removeSpan.textContent = "Адреса для удаления (через пробел)";
  const removeInput = document.createElement("textarea");
  removeInput.rows = 2;
  removeInput.placeholder = "example.com …";
  removeLabel.append(removeSpan, removeInput);
  const removeToolbar = document.createElement("div");
  removeToolbar.className = "wg-toolbar";
  const removeBtn = document.createElement("button");
  removeBtn.type = "button";
  removeBtn.className = "btn-danger";
  removeBtn.textContent = "Удалить из списка";
  removeToolbar.appendChild(removeBtn);

  panel.append(
    status,
    row1,
    toolbar,
    checkTitle,
    checkRow,
    removeTitle,
    removeHint,
    removeLabel,
    removeToolbar,
  );
  formEl.appendChild(panel);

  async function loadLists() {
    setStatus("");
    const resp = await fetch("/api/zapret/lists", {
      headers: { Authorization: `Bearer ${token}` },
    });
    let body;
    try {
      body = await resp.json();
    } catch {
      setStatus("Не удалось разобрать ответ сервера", true);
      return;
    }
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail || body),
        true,
      );
      return;
    }
    listsCache = body.lists || [];
    listSelect.replaceChildren();
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = listsCache.length
      ? "— выберите файл —"
      : "Списков пока нет";
    listSelect.appendChild(placeholder);
    listsCache.forEach((item, i) => {
      const opt = document.createElement("option");
      opt.value = String(i);
      const zone = item.scope === "domains" ? "domains" : "ipset";
      opt.textContent = `${item.filename} (${zone})`;
      listSelect.appendChild(opt);
    });
  }

  async function addSites() {
    const idx = listSelect.value;
    if (idx === "" || listsCache[Number(idx)] == null) {
      setStatus("Выберите файл списка", true);
      return;
    }
    const sites = parseSpaceSeparated(sitesInput.value);
    if (!sites.length) {
      setStatus("Укажите хотя бы один сайт", true);
      return;
    }
    const item = listsCache[Number(idx)];
    setStatus("");
    const resp = await fetch("/api/zapret/sites", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        list_name: item.list_name,
        scope: item.scope,
        sites,
      }),
    });
    const body = await resp.json();
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string" ? body.detail : JSON.stringify(body),
        true,
      );
      return;
    }
    outputEl.textContent = JSON.stringify(body, null, 2);
    sitesInput.value = "";
  }

  async function checkSite() {
    const site = String(checkInput.value || "").trim();
    if (!site) {
      setStatus("Введите сайт для проверки", true);
      return;
    }
    setStatus("");
    const resp = await fetch("/api/zapret/check", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ site }),
    });
    const body = await resp.json();
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string" ? body.detail : JSON.stringify(body),
        true,
      );
      return;
    }
    const lines = [];
    lines.push(`Домен: ${body.domain}`);
    if (body.found && Array.isArray(body.matches)) {
      lines.push(`Найдено в ${body.matches.length} файле(ах):`);
      for (const m of body.matches) {
        lines.push(
          `  • ${m.filename} (${m.scope}) — ${m.path}`,
        );
      }
    } else {
      lines.push("Ни в одном списке не найдено.");
    }
    outputEl.textContent = `${lines.join("\n")}\n\n${JSON.stringify(body, null, 2)}`;
  }

  async function removeSites() {
    const idx = listSelect.value;
    if (idx === "" || listsCache[Number(idx)] == null) {
      setStatus("Выберите файл списка", true);
      return;
    }
    const sites = parseSpaceSeparated(removeInput.value);
    if (!sites.length) {
      setStatus("Укажите хотя бы один адрес для удаления", true);
      return;
    }
    const item = listsCache[Number(idx)];
    if (
      !confirm(
        `Удалить из «${item.filename}» (${item.scope}): ${sites.join(", ")}?`,
      )
    ) {
      return;
    }
    setStatus("");
    const resp = await fetch("/api/zapret/sites/remove", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        list_name: item.list_name,
        scope: item.scope,
        sites,
      }),
    });
    const body = await resp.json();
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string" ? body.detail : JSON.stringify(body),
        true,
      );
      return;
    }
    outputEl.textContent = JSON.stringify(body, null, 2);
    removeInput.value = "";
    await loadLists();
  }

  formEl.onsubmit = async (e) => {
    e.preventDefault();
    await addSites();
  };

  addBtn.onclick = () => addSites();
  refreshListsBtn.onclick = () => withButtonLoading(refreshListsBtn, loadLists);
  checkBtn.onclick = () => checkSite();
  removeBtn.onclick = () => removeSites();

  loadLists();
}

function renderDnsPanel() {
  cleanupWgLayoutMql();
  cleanupBackupPanelTimers();
  clearHeadActions();
  clearFeatureTitleMobileHide();
  titleEl.textContent = "DNS";
  formEl.innerHTML = "";
  outputEl.textContent = "";

  const panel = document.createElement("div");
  panel.className = "wg-panel";

  const status = document.createElement("p");
  status.className = "wg-status muted";
  const setStatus = bindPanelStatus(status);

  const kwTitle = document.createElement("h3");
  kwTitle.className = "panel-section-title";
  kwTitle.textContent = "Ключевые слова";

  const kwWrap = document.createElement("div");
  kwWrap.className = "wg-table-wrap";
  const kwTable = document.createElement("table");
  kwTable.className = "data-table";
  const kwThead = document.createElement("thead");
  kwThead.innerHTML = "<tr><th>Слово</th><th></th></tr>";
  const kwTbody = document.createElement("tbody");
  kwTable.append(kwThead, kwTbody);
  kwWrap.appendChild(kwTable);

  const kwToolbar = document.createElement("div");
  kwToolbar.className = "wg-toolbar";
  const kwAddLabel = document.createElement("label");
  kwAddLabel.className = "wg-add-field dns-kw-bulk-field";
  const kwAddSpan = document.createElement("span");
  kwAddSpan.className = "muted";
  kwAddSpan.textContent = "Новые слова (через пробел)";
  const kwBulkInput = document.createElement("textarea");
  kwBulkInput.rows = 2;
  kwBulkInput.placeholder = "tracker ads …";
  kwAddLabel.append(kwAddSpan, kwBulkInput);
  const kwAddBtn = document.createElement("button");
  kwAddBtn.type = "button";
  kwAddBtn.textContent = "Добавить";
  const kwRefreshBtn = document.createElement("button");
  kwRefreshBtn.type = "button";
  kwRefreshBtn.className = "btn-secondary";
  kwRefreshBtn.textContent = "Обновить список";
  kwToolbar.append(kwAddLabel, kwAddBtn, kwRefreshBtn);

  const qTitle = document.createElement("h3");
  qTitle.className = "panel-section-title dns-mobile-hide-label";
  qTitle.textContent = "Запросы по ключевым словам";

  const qHead = document.createElement("div");
  qHead.className = "panel-section-head";

  const qSortLabel = document.createElement("label");
  qSortLabel.className = "wg-add-field wg-sort-field";
  const qSortSpan = document.createElement("span");
  qSortSpan.className = "muted dns-mobile-hide-label";
  qSortSpan.textContent = "";
  const qSortSelect = document.createElement("select");
  qSortSelect.setAttribute("aria-label", "Сортировка запросов DNS");
  const optTimeDesc = document.createElement("option");
  optTimeDesc.value = "time_desc";
  optTimeDesc.textContent = "По времени (сначала новые)";
  const optTimeAsc = document.createElement("option");
  optTimeAsc.value = "time_asc";
  optTimeAsc.textContent = "По времени (сначала старые)";
  const optDomain = document.createElement("option");
  optDomain.value = "domain_asc";
  optDomain.textContent = "По домену (А–Я)";
  qSortSelect.append(optTimeDesc, optTimeAsc, optDomain);
  qSortLabel.append(qSortSpan, qSortSelect);

  const qRefreshBtn = document.createElement("button");
  qRefreshBtn.type = "button";
  qRefreshBtn.className = "btn-secondary";
  qRefreshBtn.textContent = "Обновить запросы";
  qHead.append(qTitle, qSortLabel, qRefreshBtn);

  const qWrap = document.createElement("div");
  qWrap.className = "wg-table-wrap";
  const qTable = document.createElement("table");
  qTable.className = "data-table";
  const qThead = document.createElement("thead");
  qThead.innerHTML =
    "<tr><th>Время</th><th>Домен</th><th>Клиент</th></tr>";
  const qTbody = document.createElement("tbody");
  qTable.append(qThead, qTbody);
  qWrap.appendChild(qTable);

  panel.append(
    status,
    qHead,
    qWrap,
    kwTitle,
    kwWrap,
    kwToolbar,
  );
  formEl.appendChild(panel);

  let queriesCache = [];

  function timeToMs(raw) {
    const s = String(raw || "").trim();
    if (!s || s === "unknown") return null;
    const iso = s.includes("T") ? s : s.replace(/^(\d{4}-\d{2}-\d{2}) (\d)/, "$1T$2");
    const p = Date.parse(iso);
    return Number.isNaN(p) ? null : p;
  }

  function appendQueryRow(e) {
    const tr = document.createElement("tr");
    for (const key of ["time", "domain", "client"]) {
      const td = document.createElement("td");
      if (key === "time") {
        const raw = e[key] ?? "";
        if (raw === "unknown" || !raw) {
          td.textContent = raw || "—";
        } else {
          const p = timeToMs(raw);
          if (p == null) {
            td.textContent = raw;
          } else {
            td.textContent = formatRelativeTimeRu(p);
            td.title = raw;
          }
        }
      } else {
        td.textContent = e[key] ?? "";
        if (key === "client" && e.client_ip && td.textContent !== e.client_ip) {
          td.title = e.client_ip;
        }
      }
      tr.appendChild(td);
    }
    return tr;
  }

  function renderQueries() {
    qTbody.replaceChildren();
    const entries = queriesCache || [];
    if (!entries.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 3;
      td.className = "muted";
      td.textContent = "Нет совпадений или лог недоступен";
      tr.appendChild(td);
      qTbody.appendChild(tr);
      return;
    }

    const mode = qSortSelect.value;
    const sorted = [...entries];
    if (mode === "time_asc") {
      sorted.sort((a, b) => {
        const ta = timeToMs(a.time);
        const tb = timeToMs(b.time);
        const va = ta == null ? Number.POSITIVE_INFINITY : ta;
        const vb = tb == null ? Number.POSITIVE_INFINITY : tb;
        if (va !== vb) return va - vb;
        return (a.domain || "").localeCompare(b.domain || "", "ru");
      });
    } else if (mode === "domain_asc") {
      sorted.sort((a, b) => (a.domain || "").localeCompare(b.domain || "", "ru"));
    } else {
      // time_desc (default)
      sorted.sort((a, b) => {
        const ta = timeToMs(a.time);
        const tb = timeToMs(b.time);
        const va = ta == null ? Number.NEGATIVE_INFINITY : ta;
        const vb = tb == null ? Number.NEGATIVE_INFINITY : tb;
        if (va !== vb) return vb - va;
        return (a.domain || "").localeCompare(b.domain || "", "ru");
      });
    }

    for (const e of sorted) qTbody.appendChild(appendQueryRow(e));
  }

  qSortSelect.addEventListener("change", () => renderQueries());

  function rowKeyword(word) {
    const tr = document.createElement("tr");
    const tdW = document.createElement("td");
    const code = document.createElement("code");
    code.textContent = word;
    tdW.appendChild(code);
    const tdA = document.createElement("td");
    tdA.className = "wg-actions";
    const del = document.createElement("button");
    del.type = "button";
    del.className = "btn-danger";
    del.textContent = "Удалить";
    del.dataset.keyword = word;
    tdA.appendChild(del);
    tr.append(tdW, tdA);
    return tr;
  }

  async function loadKeywords() {
    setStatus("");
    const resp = await fetch("/api/dns/keywords", {
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = await resp.json();
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail || body),
        true,
      );
      kwTbody.replaceChildren();
      return;
    }
    const kws = body.keywords || [];
    kwTbody.replaceChildren();
    if (!kws.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 2;
      td.className = "muted";
      td.textContent = "Ключевых слов нет";
      tr.appendChild(td);
      kwTbody.appendChild(tr);
      return;
    }
    for (const w of kws) kwTbody.appendChild(rowKeyword(w));
  }

  async function addKeywordsBulk() {
    const text = String(kwBulkInput.value || "").trim();
    if (!text) {
      setStatus("Введите слова через пробел", true);
      return;
    }
    setStatus("");
    const resp = await fetch("/api/dns/keywords/bulk", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ text }),
    });
    const body = await resp.json();
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string" ? body.detail : JSON.stringify(body),
        true,
      );
      return;
    }
    outputEl.textContent = JSON.stringify(body, null, 2);
    kwBulkInput.value = "";
    await loadKeywords();
  }

  async function loadQueries() {
    setStatus("");
    const resp = await fetch("/api/dns/queries", {
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = await resp.json();
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail || body),
        true,
      );
      qTbody.replaceChildren();
      return;
    }
    queriesCache = body.entries || [];
    renderQueries();
  }

  formEl.onsubmit = async (e) => {
    e.preventDefault();
    await addKeywordsBulk();
  };

  kwTbody.addEventListener("click", async (e) => {
    const btn = e.target.closest("button[data-keyword]");
    if (!btn) return;
    const kw = btn.dataset.keyword;
    if (!kw) return;
    if (!confirm(`Удалить ключевое слово «${kw}»?`)) return;
    setStatus("");
    const resp = await fetch("/api/dns/keywords", {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ keyword: kw }),
    });
    const body = await resp.json();
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string" ? body.detail : JSON.stringify(body),
        true,
      );
      return;
    }
    await loadKeywords();
  });

  kwAddBtn.onclick = () => addKeywordsBulk();
  kwRefreshBtn.onclick = () => withButtonLoading(kwRefreshBtn, loadKeywords);
  qRefreshBtn.onclick = () => withButtonLoading(qRefreshBtn, loadQueries);

  loadKeywords();
  loadQueries();
}

function renderBackupsPanel() {
  cleanupWgLayoutMql();
  cleanupBackupPanelTimers();
  clearHeadActions();
  clearFeatureTitleMobileHide();

  titleEl.textContent = "Резервные копии";
  formEl.innerHTML = "";
  outputEl.textContent = "";

  const panel = document.createElement("div");
  panel.className = "wg-panel backups-panel";

  const status = document.createElement("p");
  status.className = "wg-status muted";
  const setStatus = bindPanelStatus(status);

  const headRow = document.createElement("div");
  headRow.className = "wg-toolbar";
  const refreshBtn = document.createElement("button");
  refreshBtn.type = "button";
  refreshBtn.className = "btn-secondary";
  refreshBtn.textContent = "Обновить";
  const runNowBtn = document.createElement("button");
  runNowBtn.type = "button";
  runNowBtn.textContent = "Создать бэкап сейчас";
  headRow.append(refreshBtn, runNowBtn);

  const nextBlock = document.createElement("div");
  nextBlock.className = "backups-next-block";
  const nextLabel = document.createElement("p");
  nextLabel.className = "backups-countdown muted";
  const nextAbs = document.createElement("p");
  nextAbs.className = "muted backups-next-abs";
  nextAbs.style.fontSize = "0.88rem";
  nextBlock.append(nextLabel, nextAbs);

  const setTitle = document.createElement("h3");
  setTitle.className = "panel-section-title";
  setTitle.textContent = "Настройки";
  const setRow = document.createElement("div");
  setRow.className = "wg-toolbar backups-settings-row";
  const maxLabel = document.createElement("label");
  maxLabel.className = "wg-add-field";
  const maxSpan = document.createElement("span");
  maxSpan.className = "muted";
  maxSpan.textContent = "Хранить архивов";
  const maxInput = document.createElement("input");
  maxInput.type = "number";
  maxInput.min = "1";
  maxInput.max = "100000";
  maxInput.step = "1";
  maxLabel.append(maxSpan, maxInput);

  const intLabel = document.createElement("label");
  intLabel.className = "wg-add-field";
  const intSpan = document.createElement("span");
  intSpan.className = "muted";
  intSpan.textContent = "Интервал (часов)";
  const intInput = document.createElement("input");
  intInput.type = "number";
  intInput.min = "1";
  intInput.max = "8760";
  intInput.step = "1";
  intLabel.append(intSpan, intInput);

  const saveSetBtn = document.createElement("button");
  saveSetBtn.type = "button";
  saveSetBtn.textContent = "Сохранить настройки";
  setRow.append(maxLabel, intLabel, saveSetBtn);

  const archTitle = document.createElement("h3");
  archTitle.className = "panel-section-title";
  archTitle.textContent = "Архивы";
  const archSummary = document.createElement("p");
  archSummary.className = "muted backups-arch-summary";
  archSummary.textContent = "Загрузка…";
  const archWrap = document.createElement("div");
  archWrap.className = "wg-table-wrap backups-archive-wrap";
  const archTable = document.createElement("table");
  archTable.className = "data-table backups-archive-table";
  const archThead = document.createElement("thead");
  archThead.innerHTML =
    "<tr><th>Файл</th><th>Размер</th><th>Изменён</th><th colspan=\"2\">Действия</th></tr>";
  const archTbody = document.createElement("tbody");
  archTable.append(archThead, archTbody);

  const pathsTitle = document.createElement("h3");
  pathsTitle.className = "panel-section-title";
  pathsTitle.textContent = "Пути для копирования";
  const pathToolbar = document.createElement("div");
  pathToolbar.className = "wg-toolbar";
  const pathLabel = document.createElement("label");
  pathLabel.className = "wg-add-field backups-path-field dns-kw-bulk-field";
  const pathSpan = document.createElement("span");
  pathSpan.className = "muted";
  pathSpan.textContent = "Пути (несколько через пробел или с новой строки)";
  const pathInput = document.createElement("textarea");
  pathInput.rows = 4;
  pathInput.placeholder =
    "/var/www/site";
  pathInput.autocomplete = "off";
  pathLabel.append(pathSpan, pathInput);
  const addPathBtn = document.createElement("button");
  addPathBtn.type = "button";
  addPathBtn.textContent = "Добавить пути";
  pathToolbar.append(pathLabel, addPathBtn);

  const pathsWrap = document.createElement("div");
  pathsWrap.className = "wg-table-wrap";
  const pathsTable = document.createElement("table");
  pathsTable.className = "data-table";
  const pathsThead = document.createElement("thead");
  pathsThead.innerHTML = "<tr><th>Путь</th><th></th></tr>";
  const pathsTbody = document.createElement("tbody");
  pathsTable.append(pathsThead, pathsTbody);

  panel.append(
    status,
    headRow,
    nextBlock,
    setTitle,
    setRow,
    archTitle,
    archSummary,
    archWrap,
    pathsTitle,
    pathToolbar,
    pathsWrap,
  );
  pathsWrap.appendChild(pathsTable);
  archWrap.appendChild(archTable);
  formEl.appendChild(panel);

  let countdownSec = null;

  function updateCountdownDisplay() {
    if (countdownSec == null) {
      nextLabel.textContent = "До следующего бэкапа: —";
      nextAbs.textContent = "";
      return;
    }
    nextLabel.textContent = `До следующего бэкапа: ${formatBackupCountdown(countdownSec)}`;
  }

  function renderPaths(rows) {
    pathsTbody.replaceChildren();
    if (!rows || !rows.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 2;
      td.className = "muted";
      td.textContent = "Пути не заданы";
      tr.appendChild(td);
      pathsTbody.appendChild(tr);
      return;
    }
    for (const r of rows) {
      const tr = document.createElement("tr");
      const tdP = document.createElement("td");
      const code = document.createElement("code");
      code.textContent = r.path;
      code.className = "muted";
      tdP.appendChild(code);
      const tdA = document.createElement("td");
      tdA.className = "wg-actions";
      const del = document.createElement("button");
      del.type = "button";
      del.className = "btn-danger";
      del.textContent = "Удалить";
      del.dataset.pathId = String(r.id);
      tdA.appendChild(del);
      tr.append(tdP, tdA);
      pathsTbody.appendChild(tr);
    }
  }

  function formatBytes(n) {
    if (typeof n !== "number" || n < 0) return "—";
    if (n < 1024) return `${n} Б`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} КБ`;
    if (n < 1024 * 1024 * 1024)
      return `${(n / (1024 * 1024)).toFixed(1)} МБ`;
    return `${(n / (1024 * 1024 * 1024)).toFixed(2)} ГБ`;
  }

  function renderArchives(rows, totalBytes, count) {
    const n = typeof count === "number" ? count : rows?.length ?? 0;
    const tb =
      typeof totalBytes === "number" ? totalBytes : 0;
    if (n === 0) {
      archSummary.textContent = "Архивов нет — занято 0 Б.";
    } else {
      archSummary.textContent = `Всего архивов: ${n}, суммарный размер: ${formatBytes(tb)}`;
    }
    archTbody.replaceChildren();
    if (!rows || !rows.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 5;
      td.className = "muted";
      td.textContent = "Архивов пока нет";
      tr.appendChild(td);
      archTbody.appendChild(tr);
      return;
    }
    for (const r of rows) {
      const tr = document.createElement("tr");
      const tdN = document.createElement("td");
      const c = document.createElement("code");
      c.textContent = r.name;
      tdN.appendChild(c);
      const tdS = document.createElement("td");
      tdS.textContent = formatBytes(r.size_bytes);
      const tdT = document.createElement("td");
      const mod = r.modified_at
        ? new Date(r.modified_at * 1000).toLocaleString()
        : "—";
      tdT.textContent = mod;
      const tdAct = document.createElement("td");
      tdAct.colSpan = 2;
      tdAct.className = "backups-archive-actions";
      const actInner = document.createElement("div");
      actInner.className = "backups-archive-actions-inner";
      const dl = document.createElement("button");
      dl.type = "button";
      dl.className = "btn-secondary";
      dl.textContent = "Скачать";
      dl.dataset.file = r.name;
      dl.dataset.archiveAction = "download";
      const del = document.createElement("button");
      del.type = "button";
      del.className = "btn-danger";
      del.textContent = "Удалить";
      del.dataset.file = r.name;
      del.dataset.archiveAction = "delete";
      actInner.append(dl, del);
      tdAct.appendChild(actInner);
      tr.append(tdN, tdS, tdT, tdAct);
      archTbody.appendChild(tr);
    }
  }

  async function loadStatus() {
    setStatus("");
    const resp = await fetch("/api/backups", {
      headers: { Authorization: `Bearer ${token}` },
    });
    let body;
    try {
      body = await resp.json();
    } catch {
      setStatus("Не удалось разобрать ответ сервера", true);
      return;
    }
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string"
          ? body.detail
          : JSON.stringify(body.detail || body),
        true,
      );
      return;
    }
    const st = body.settings || {};
    maxInput.value = String(st.max_archives ?? 200);
    intInput.value = String(st.interval_hours ?? 24);

    countdownSec =
      typeof body.seconds_until_next === "number"
        ? body.seconds_until_next
        : null;
    updateCountdownDisplay();
    if (!body.paths || !body.paths.length) {
      nextAbs.textContent =
        "Добавьте хотя бы один путь — тогда появится расписание.";
    } else if (typeof body.next_backup_at === "number") {
      nextAbs.textContent = `Ориентировочно: ${new Date(body.next_backup_at * 1000).toLocaleString()}`;
    } else {
      nextAbs.textContent = "";
    }

    renderPaths(body.paths);
    renderArchives(
      body.archives,
      body.archives_total_bytes,
      body.archives_count,
    );
  }

  pathsTbody.addEventListener("click", async (e) => {
    const btn = e.target.closest("button[data-path-id]");
    if (!btn) return;
    const id = btn.dataset.pathId;
    if (!id) return;
    if (!confirm("Удалить этот путь из списка?")) return;
    setStatus("");
    const resp = await fetch(`/api/backups/paths/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = await resp.json();
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string" ? body.detail : JSON.stringify(body),
        true,
      );
      return;
    }
    await loadStatus();
  });

  archTbody.addEventListener("click", async (e) => {
    const btn = e.target.closest("button[data-archive-action][data-file]");
    if (!btn) return;
    const name = btn.dataset.file;
    if (!name) return;
    const action = btn.dataset.archiveAction;

    if (action === "delete") {
      if (!confirm(`Удалить архив «${name}»?`)) return;
      setStatus("");
      const resp = await fetch(
        `/api/backups/archives/${encodeURIComponent(name)}`,
        { method: "DELETE", headers: { Authorization: `Bearer ${token}` } },
      );
      let body;
      try {
        body = await resp.json();
      } catch {
        body = {};
      }
      if (!resp.ok) {
        setStatus(
          typeof body.detail === "string"
            ? body.detail
            : "Не удалось удалить архив",
          true,
        );
        return;
      }
      await loadStatus();
      return;
    }

    if (action !== "download") return;
    setStatus("");
    const resp = await fetch(
      `/api/backups/download/${encodeURIComponent(name)}`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    if (!resp.ok) {
      let err;
      try {
        err = await resp.json();
      } catch {
        err = {};
      }
      setStatus(
        typeof err.detail === "string"
          ? err.detail
          : "Не удалось скачать файл",
        true,
      );
      return;
    }
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });

  addPathBtn.onclick = async () => {
    const raw = String(pathInput.value || "").trim();
    if (!raw) {
      setStatus("Введите хотя бы один путь", true);
      return;
    }
    setStatus("");
    const resp = await fetch("/api/backups/paths/bulk", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ text: raw }),
    });
    const body = await resp.json();
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string" ? body.detail : JSON.stringify(body),
        true,
      );
      return;
    }
    const added = body.added?.length ?? 0;
    const skipped = body.skipped?.length ?? 0;
    const errList = body.errors || [];
    let msg = `Добавлено: ${added}`;
    if (skipped) msg += `, уже были: ${skipped}`;
    if (errList.length) {
      msg += `. Ошибки: ${errList.map((e) => `${e.path} (${e.error})`).join("; ")}`;
    }
    const hardFail = errList.length > 0 && added === 0;
    setStatus(msg, hardFail);
    outputEl.textContent = JSON.stringify(body, null, 2);
    pathInput.value = "";
    await loadStatus();
  };

  saveSetBtn.onclick = async () => {
    const max_archives = parseInt(maxInput.value, 10);
    const interval_hours = parseInt(intInput.value, 10);
    if (!Number.isFinite(max_archives) || max_archives < 1) {
      setStatus("Укажите число архивов от 1", true);
      return;
    }
    if (!Number.isFinite(interval_hours) || interval_hours < 1) {
      setStatus("Укажите интервал в часах от 1", true);
      return;
    }
    setStatus("");
    const resp = await fetch("/api/backups/settings", {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ max_archives, interval_hours }),
    });
    const body = await resp.json();
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string" ? body.detail : JSON.stringify(body),
        true,
      );
      return;
    }
    await loadStatus();
  };

  runNowBtn.onclick = async () => {
    setStatus("");
    const resp = await fetch("/api/backups/run", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    let body;
    try {
      body = await resp.json();
    } catch {
      setStatus("Не удалось разобрать ответ сервера", true);
      return;
    }
    if (!resp.ok) {
      setStatus(
        typeof body.detail === "string" ? body.detail : JSON.stringify(body),
        true,
      );
      return;
    }
    outputEl.textContent = JSON.stringify(body, null, 2);
    await loadStatus();
  };

  refreshBtn.onclick = () => withButtonLoading(refreshBtn, loadStatus);

  backupPanelTimers.countdown = setInterval(() => {
    if (countdownSec == null) return;
    if (countdownSec > 0) countdownSec -= 1;
    updateCountdownDisplay();
  }, 1000);

  backupPanelTimers.sync = setInterval(() => {
    loadStatus();
  }, 30000);

  loadStatus();
}

function renderFeature(feature) {
  if (feature.key === "wireguard") {
    renderWireGuardPanel();
    return;
  }
  if (feature.key === "amneziawg") {
    renderAmneziaWGPanel();
    return;
  }
  if (feature.key === "zapret") {
    renderZapretPanel();
    return;
  }
  if (feature.key === "dns") {
    renderDnsPanel();
    return;
  }
  if (feature.key === "backups") {
    renderBackupsPanel();
    return;
  }

  cleanupWgLayoutMql();
  cleanupBackupPanelTimers();
  clearHeadActions();
  clearFeatureTitleMobileHide();
  titleEl.textContent = feature.title;
  formEl.innerHTML = "";
  feature.fields.forEach((field) => {
    const label = document.createElement("label");
    label.textContent = field.name;
    const input = document.createElement("input");
    input.name = field.name;
    input.required = true;
    label.appendChild(input);
    formEl.appendChild(label);
  });
  const submit = document.createElement("button");
  submit.type = "submit";
  submit.textContent = "Run";
  formEl.appendChild(submit);

  formEl.onsubmit = async (event) => {
    event.preventDefault();
    const data = new FormData(formEl);
    let path = feature.path;
    const payload = {};

    feature.fields.forEach((f) => {
      const value = String(data.get(f.name) || "");
      if (path.includes(`{${f.name}}`)) {
        path = path.replace(`{${f.name}}`, encodeURIComponent(value));
      } else if (f.name === "sites_csv") {
        payload.sites = parseSpaceSeparated(value);
      } else if (f.name === "enabled") {
        payload.enabled = value === "1" || value.toLowerCase() === "true";
      } else {
        payload[f.name] = value;
      }
    });

    const options = {
      method: feature.method,
      headers: { Authorization: `Bearer ${token}` },
    };
    if (feature.method !== "GET") {
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(payload);
    }

    const resp = await fetch(path, options);
    const body = await resp.json();
    outputEl.textContent = JSON.stringify(body, null, 2);
  };
}

const featureButtonByKey = {};

function setActiveFeatureKey(key) {
  Object.entries(featureButtonByKey).forEach(([k, btn]) => {
    const active = k === key;
    btn.classList.toggle("active", active);
    btn.setAttribute("aria-selected", active ? "true" : "false");
    btn.tabIndex = active ? 0 : -1;
  });
}

listEl.setAttribute("role", "tablist");
listEl.setAttribute("aria-label", "Функции");

features.forEach((feature) => {
  const li = document.createElement("li");
  li.setAttribute("role", "presentation");
  const btn = document.createElement("button");
  btn.type = "button";
  btn.setAttribute("role", "tab");
  btn.id = `feature-tab-${feature.key}`;
  btn.setAttribute("aria-selected", "false");
  btn.tabIndex = -1;
  btn.textContent = feature.title;
  btn.onclick = () => {
    localStorage.setItem("activeFeatureKey", feature.key);
    setActiveFeatureKey(feature.key);
    if (feature.key === "wireguard") {
      clearWireGuardClientView();
      history.replaceState(null, "", "/dashboard");
      if (location.hash) location.hash = "";
    }
    renderFeature(feature);
  };
  li.appendChild(btn);
  listEl.appendChild(li);
  featureButtonByKey[feature.key] = btn;
});

listEl.addEventListener("keydown", (e) => {
  const order = features.map((f) => f.key);
  const tabs = order.map((k) => featureButtonByKey[k]).filter(Boolean);
  const i = tabs.indexOf(document.activeElement);
  if (i < 0) return;
  let next = i;
  if (e.key === "ArrowDown" || e.key === "ArrowRight") {
    e.preventDefault();
    next = (i + 1) % tabs.length;
  } else if (e.key === "ArrowUp" || e.key === "ArrowLeft") {
    e.preventDefault();
    next = (i - 1 + tabs.length) % tabs.length;
  } else if (e.key === "Home") {
    e.preventDefault();
    next = 0;
  } else if (e.key === "End") {
    e.preventDefault();
    next = tabs.length - 1;
  } else {
    return;
  }
  const t = tabs[next];
  t.focus();
  t.click();
});

migrateLegacyWireguardHash();

const lastKey = localStorage.getItem("activeFeatureKey");
const selected =
  (lastKey && features.find((f) => f.key === lastKey)) || features[0];
if (selected) {
  localStorage.setItem("activeFeatureKey", selected.key);
  setActiveFeatureKey(selected.key);
  renderFeature(selected);
}

document.body.addEventListener("click", (e) => {
  const a = e.target.closest("a.wg-client-open-link[data-wg-client]");
  if (!a) return;
  if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return;
  const name = a.dataset.wgClient;
  if (!name) return;
  e.preventDefault();
  setWireGuardClientView(name);
  history.replaceState(null, "", "/dashboard");
  localStorage.setItem("activeFeatureKey", "wireguard");
  setActiveFeatureKey("wireguard");
  renderWireGuardPanel();
});
