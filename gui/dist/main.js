// scredmanager GUI frontend. Talks only to the whitelisted Rust commands,
// which only spawn `scredmanager … --json`. No secret ever reaches this
// process: the CLI's get/run paths are not exposed here at all.
"use strict";

const invoke = window.__TAURI__.core.invoke;

const $ = (id) => document.getElementById(id);
const log = (msg) => {
  $("log").textContent = `${new Date().toLocaleTimeString()}  ${msg}\n` + $("log").textContent;
};

// Unwrap the schemaVersion-1 envelope; throw the CLI's error string.
async function cli(cmd, args = {}) {
  const env = await invoke(cmd, args);
  if (!env.ok) throw new Error(env.error || "unknown CLI error");
  return env.data;
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function stateOf(entry) {
  if (!entry) return "missing";
  return entry.state || "no-expiry";
}

function expiryText(entry) {
  if (!entry) return "no token stored";
  if (!entry.expiresAt) return "no expiry";
  const days = entry.daysLeft;
  const date = entry.expiresAt.slice(0, 10);
  if (days < 0) return `EXPIRED ${date}`;
  return `expires ${date} (${days}d)`;
}

async function doLogin(svc, btn) {
  btn.disabled = true;
  const useClipboard = !svc.deviceFlow;
  btn.textContent = useClipboard ? "copy token…" : "approve in browser…";
  log(
    useClipboard
      ? `login ${svc.id}: browser opening — mint a token and copy it (clipboard is cleared after storing)`
      : `login ${svc.id}: device flow — enter the code shown in your browser`
  );
  try {
    const data = await cli("gui_login", { id: svc.id, clipboard: useClipboard });
    log(`login ${svc.id}: stored (${data.mode} flow${data.expiresAt ? ", expires " + data.expiresAt.slice(0, 10) : ""})`);
  } catch (e) {
    log(`login ${svc.id}: ${e.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Login";
    refresh();
  }
}

async function doCheck(id, btn) {
  btn.disabled = true;
  try {
    await cli("gui_check", { id });
    log(`check ${id}: token valid`);
  } catch (e) {
    log(`check ${id}: ${e.message}`);
  } finally {
    btn.disabled = false;
  }
}

async function doRemove(id, btn) {
  if (!confirm(`Remove ${id} from the keychain?`)) return;
  btn.disabled = true;
  try {
    await cli("gui_rm", { id });
    log(`removed ${id}`);
  } catch (e) {
    log(`rm ${id}: ${e.message}`);
  } finally {
    refresh();
  }
}

function serviceRow(svc, entry) {
  const row = el("div", "row");
  row.appendChild(el("span", `badge ${stateOf(entry)}`));
  row.appendChild(el("span", "name", svc.id));
  const detail = [expiryText(entry), svc.envVar, svc.deviceFlow ? "device flow" : null]
    .filter(Boolean)
    .join(" · ");
  row.appendChild(el("span", "detail", detail));

  if (entry) {
    const check = el("button", null, "Check");
    check.onclick = () => doCheck(svc.id, check);
    row.appendChild(check);
  }
  const login = el("button", "primary", "Login");
  login.onclick = () => doLogin(svc, login);
  row.appendChild(login);
  return row;
}

function entryRow(entry) {
  const row = el("div", "row");
  row.appendChild(el("span", `badge ${stateOf(entry)}`));
  row.appendChild(el("span", "name", entry.id));
  row.appendChild(el("span", "detail", [expiryText(entry), entry.envVar].filter(Boolean).join(" · ")));
  const rm = el("button", "danger", "Remove");
  rm.onclick = () => doRemove(entry.id, rm);
  row.appendChild(rm);
  return row;
}

async function refresh() {
  try {
    const [services, status] = await Promise.all([cli("gui_services"), cli("gui_status")]);
    const entries = (status && status.entries) || [];
    const byId = Object.fromEntries(entries.map((e) => [e.id, e]));
    const svcIds = new Set((services || []).map((s) => s.id));

    const svcList = $("services");
    svcList.replaceChildren();
    if (!services || services.length === 0) {
      svcList.appendChild(el("div", "empty", "No services — edit ~/.scredmanager/services.json"));
    } else {
      for (const svc of services) svcList.appendChild(serviceRow(svc, byId[svc.id]));
    }

    const other = entries.filter((e) => !svcIds.has(e.id));
    const entryList = $("entries");
    entryList.replaceChildren();
    if (other.length === 0) {
      entryList.appendChild(el("div", "empty", "No ad-hoc entries"));
    } else {
      for (const e of other) entryList.appendChild(entryRow(e));
    }

    const warnings = (status && status.warnings) || 0;
    const banner = $("banner");
    if (warnings > 0) {
      banner.textContent = `${warnings} token${warnings > 1 ? "s" : ""} expiring or expired`;
      banner.classList.remove("hidden");
    } else {
      banner.classList.add("hidden");
    }
  } catch (e) {
    log(`refresh: ${e.message}`);
  }
}

async function doImport() {
  const path = $("import-path").value.trim();
  if (!path) return log("import: enter a path");
  const btn = $("import-btn");
  btn.disabled = true;
  try {
    const data = await cli("gui_import", { path });
    const n = (data.imported || []).length;
    log(`imported ${n} entr${n === 1 ? "y" : "ies"} from ${data.source} — shred the source file`);
  } catch (e) {
    log(`import: ${e.message}`);
  } finally {
    btn.disabled = false;
    refresh();
  }
}

// Settings: notification preference persists in localStorage.
const notifyBox = $("notify-on-launch");
notifyBox.checked = localStorage.getItem("notifyOnLaunch") === "1";
notifyBox.onchange = () => localStorage.setItem("notifyOnLaunch", notifyBox.checked ? "1" : "0");

$("refresh").onclick = refresh;
$("import-btn").onclick = doImport;

refresh().then(() => {
  if (notifyBox.checked) invoke("gui_notify").catch(() => {});
});
