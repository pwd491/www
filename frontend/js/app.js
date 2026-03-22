const token = localStorage.getItem("token");
if (!token) window.location.href = "/login";

const features = [
  // { key: "help", title: "Помощь", method: "GET", path: "/api/help", fields: [] },
  { key: "wireguard", title: "WireGuard" },
  { key: "dns", title: "DNS" },
  { key: "zapret", title: "Zapret" },
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
  if (sec < 45) return "только что";

  const min = Math.floor(sec / 60);
  if (min < 1) return "меньше минуты назад";
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

function renderWireGuardPanel() {
  cleanupWgLayoutMql();
  formEl.innerHTML = "";
  outputEl.textContent = "";
  clearHeadActions();

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
  applySpan.textContent = "Перезаписать все клиентские .conf";
  applyLabel.append(applyCb, applySpan);
  const paramsSaveBtn = document.createElement("button");
  paramsSaveBtn.type = "button";
  paramsSaveBtn.textContent = "Сохранить params";
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
    thead.innerHTML = wgIsMobileLayout()
      ? "<tr><th>Клиент</th><th>IP</th><th>Последний визит</th></tr>"
      : "<tr><th>Клиент</th><th>IP</th><th>Последний визит</th><th></th></tr>";
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
    const colspan = wgIsMobileLayout() ? 3 : 4;
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

  async function downloadWgConfig(clientName) {
    setStatus("");
    const resp = await fetch(
      `/api/wireguard/clients/${encodeURIComponent(clientName)}/config`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
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
    const cfg = body.config;
    if (typeof cfg !== "string") {
      setStatus("Неожиданный формат конфига", true);
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

  function rowForClient(c) {
    const tr = document.createElement("tr");
    const tdName = document.createElement("td");
    if (wgIsMobileLayout()) {
      const nameLink = document.createElement("a");
      nameLink.href = "#";
      nameLink.className = "wg-client-download-link";
      nameLink.dataset.action = "download";
      nameLink.dataset.name = c.name;
      nameLink.textContent = c.name;
      nameLink.title = "Скачать конфиг";
      nameLink.setAttribute("aria-label", `Скачать конфиг: ${c.name}`);
      tdName.appendChild(nameLink);
    } else {
      const nameCode = document.createElement("code");
      nameCode.textContent = c.name;
      tdName.appendChild(nameCode);
    }

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
    if (!wgIsMobileLayout()) {
      const tdAct = document.createElement("td");
      tdAct.className = "wg-actions";
      const mk = (label, className, action) => {
        const b = document.createElement("button");
        b.type = "button";
        b.className = `${className} wg-row-action`;
        b.dataset.action = action;
        b.dataset.name = c.name;
        b.setAttribute("aria-label", label);
        b.title = label;
        b.textContent = label;
        return b;
      };
      tdAct.append(
        mk("Скачать конфиг", "btn-secondary", "download"),
        mk("Переименовать", "btn-secondary", "rename"),
        mk("Удалить", "btn-danger", "delete"),
      );
      tr.appendChild(tdAct);
    }
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

  tbody.addEventListener("click", async (e) => {
    const ctrl = e.target.closest("button[data-action], a[data-action]");
    if (!ctrl) return;
    if (ctrl.tagName === "A") e.preventDefault();
    const clientName = ctrl.dataset.name;
    if (!clientName) return;

    if (ctrl.dataset.action === "download") {
      await downloadWgConfig(clientName);
      return;
    }

    if (ctrl.dataset.action === "delete") {
      if (!confirm(`Удалить клиента «${clientName}»?`)) return;
      setStatus("");
      const resp = await fetch(
        `/api/wireguard/clients/${encodeURIComponent(clientName)}`,
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
      await loadClients();
      return;
    }

    if (ctrl.dataset.action === "rename") {
      const newName = prompt("Новое имя клиента:", clientName);
      if (newName == null) return;
      const trimmed = String(newName).trim();
      if (!trimmed || trimmed === clientName) return;
      setStatus("");
      const resp = await fetch("/api/wireguard/clients/rename", {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ old_name: clientName, new_name: trimmed }),
      });
      const body = await resp.json();
      if (!resp.ok) {
        setStatus(
          typeof body.detail === "string" ? body.detail : JSON.stringify(body),
          true,
        );
        return;
      }
      await loadClients();
    }
  });

  addBtn.onclick = () => addClient();
  refreshBtn.onclick = () => loadClients();

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
  refreshListsBtn.onclick = () => loadLists();
  checkBtn.onclick = () => checkSite();
  removeBtn.onclick = () => removeSites();

  loadLists();
}

function renderDnsPanel() {
  cleanupWgLayoutMql();
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
  kwRefreshBtn.onclick = () => loadKeywords();
  qRefreshBtn.onclick = () => loadQueries();

  loadKeywords();
  loadQueries();
}

function renderFeature(feature) {
  if (feature.key === "wireguard") {
    renderWireGuardPanel();
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

  cleanupWgLayoutMql();
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
  Object.values(featureButtonByKey).forEach((btn) =>
    btn.classList.remove("active")
  );
  const btn = featureButtonByKey[key];
  if (btn) btn.classList.add("active");
}

features.forEach((feature) => {
  const li = document.createElement("li");
  const btn = document.createElement("button");
  btn.textContent = feature.title;
  btn.onclick = () => {
    localStorage.setItem("activeFeatureKey", feature.key);
    setActiveFeatureKey(feature.key);
    renderFeature(feature);
  };
  li.appendChild(btn);
  listEl.appendChild(li);
  featureButtonByKey[feature.key] = btn;
});

const lastKey = localStorage.getItem("activeFeatureKey");
const selected =
  (lastKey && features.find((f) => f.key === lastKey)) || features[0];
if (selected) {
  setActiveFeatureKey(selected.key);
  renderFeature(selected);
}
