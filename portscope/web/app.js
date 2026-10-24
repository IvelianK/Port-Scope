"use strict";

const LEVELS = ["critical", "high", "medium", "low", "info"];
const EXPOSURES = ["all", "internet", "network", "local"];
const $ = (sel) => document.querySelector(sel);

const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode: not persisted */ } },
};

const state = {
  lang: store.get("ps-lang") || ((navigator.language || "en").startsWith("es") ? "es" : "en"),
  dict: {},
  report: null,
  sev: new Set(["critical", "high", "medium", "low"]),
  exp: "all",
  q: "",
};

let token = null;

// The fragment carries either the token (link printed in the terminal) or a single-use
// launch code (link given to the browser, whose command line other local users can read).
// Either way it is kept for this tab only and stripped from the address bar.
async function initToken() {
  const m = location.hash.match(/^#([tc])=([\w-]+)$/);
  history.replaceState(null, "", location.pathname);
  if (m?.[1] === "t") token = m[2];
  else if (m?.[1] === "c") {
    const res = await fetch("/api/session", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code: m[2] }) });
    token = res.ok ? (await res.json()).token : null;
  } else {
    try { token = sessionStorage.getItem("ps-token"); } catch { /* storage blocked */ }
  }
  if (token) try { sessionStorage.setItem("ps-token", token); } catch { /* storage blocked */ }
}

/* ---------- helpers ---------- */

// All untrusted text (process names, router-provided strings) goes through textContent, never innerHTML.
function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "style") Object.assign(el.style, v); // CSSOM: allowed by the CSP, style="" is not
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid);
  return el;
}

function t(key, vars = {}) {
  const s = state.dict[key] ?? key;
  return s.replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? "");
}

function setStatus(msg, isError = false) {
  const el = $("#status");
  el.textContent = msg;
  el.classList.toggle("error", isError);
}

async function api(path, body = {}) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-PortScope-Token": token || "" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function external(href, text, cls) {
  return h("a", { href, target: "_blank", rel: "noopener noreferrer", class: cls }, text);
}

/* ---------- i18n ---------- */

async function setLang(lang) {
  const res = await fetch(`/i18n/${lang}.json`);
  state.dict = await res.json();
  state.lang = lang;
  store.set("ps-lang", lang);
  document.documentElement.lang = lang;
  for (const el of document.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
  for (const el of document.querySelectorAll("[data-i18n-placeholder]")) el.placeholder = t(el.dataset.i18nPlaceholder);
  for (const el of document.querySelectorAll("[data-i18n-aria]")) el.setAttribute("aria-label", t(el.dataset.i18nAria));
  for (const b of document.querySelectorAll("[data-lang]")) b.setAttribute("aria-pressed", String(b.dataset.lang === lang));
  if (state.report) render();
}

/* ---------- scan ---------- */

async function scan() {
  const btn = $("#scan");
  const withUpnp = $("#opt-upnp").checked;
  btn.disabled = true;
  btn.classList.add("busy");
  document.body.classList.add("scanning");
  setStatus(t(withUpnp ? "scanning_upnp" : "scanning"));
  try {
    state.report = await api("/api/scan", { upnp: withUpnp });
    render();
    const c = state.report.score.counts;
    setStatus(t("scan_done", { n: state.report.findings.length, crit: c.critical + c.high }));
  } catch (e) {
    setStatus(token ? `${t("error")}: ${e.message}` : t("no_token"), true);
  } finally {
    btn.disabled = false;
    btn.classList.remove("busy");
    document.body.classList.remove("scanning");
  }
}

/* ---------- render ---------- */

function render() {
  const r = state.report;
  $("#intro").hidden = true;
  for (const id of ["#overview", "#findings-wrap", "#foot"]) $(id).hidden = false;
  $("#version").textContent = `v${r.version}`;
  renderScore(r.score);
  renderFirewall(r.firewall);
  renderGateway(r.upnp);
  renderDiff(r.diff);
  renderChips();
  renderFindings();
  renderDevices(r.upnp);
  $("#generated").textContent = `${t("generated")} ${new Date(r.generated_at).toLocaleString(state.lang)} · ${r.platform}`;
}

function renderScore(s) {
  const circumference = 326.7;
  const dial = $("#dial");
  dial.style.strokeDashoffset = String(circumference * (1 - s.value / 100));
  dial.style.stroke = { A: "var(--accent)", B: "var(--accent)", C: "var(--medium)", D: "var(--high)", F: "var(--critical)" }[s.grade];
  $("#grade").textContent = s.grade;
  $("#score-num").textContent = `${s.value}/100`;
  const total = LEVELS.reduce((n, l) => n + s.counts[l], 0) || 1;
  $("#sevbar").replaceChildren(...LEVELS.map((l) => h("i", { class: `bg-${l}`, style: { width: `${(s.counts[l] / total) * 100}%` } })));
  $("#legend").replaceChildren(...LEVELS.map((l) => h("li", {}, h("i", { class: `bg-${l}` }), `${t("sev_" + l)} `, h("b", {}, String(s.counts[l])))));
}

function renderFirewall(fw) {
  const color = { on: "var(--low)", off: "var(--critical)", partial: "var(--medium)" }[fw.state] || "var(--muted)";
  const el = $("#fw-state");
  el.textContent = t("fw_" + fw.state);
  el.style.color = color;
  $("#fw-detail").textContent = fw.detail;
  $("#fw-note").textContent = t("fw_note_" + fw.state);
}

function renderGateway(upnp) {
  const box = $("#gw");
  if (!upnp) return box.replaceChildren(h("p", { class: "muted" }, t("upnp_skipped")));
  if (!upnp.gateways.length) {
    return box.replaceChildren(
      h("p", { class: "big c-low" }, t("upnp_none_title")),
      h("p", { class: "muted" }, t("upnp_none")),
      ...upnp.errors.map((e) => h("p", { class: "muted mono" }, e)),
    );
  }
  box.replaceChildren(...upnp.gateways.map((gw) => {
    const n = gw.mappings.length;
    return h("div", { class: "gw" },
      h("p", { class: "gw-name" }, gw.name || gw.ip),
      h("dl", { class: "kv" },
        h("dt", {}, t("gw_ip")), h("dd", {}, external(`http://${gw.ip}/`, gw.ip)),
        h("dt", {}, t("gw_external")), h("dd", {}, h("button", {
          type: "button", class: "reveal masked mono", title: t("reveal"),
          onclick: (e) => e.currentTarget.classList.toggle("masked"),
        }, gw.external_ip || "?")),
        h("dt", {}, t("gw_mappings")), h("dd", {}, h("span", { class: `pill c-${n ? "critical" : "low"}` }, gw.error ? `${n}+` : String(n))),
      ),
      gw.double_nat && h("p", { class: "muted" }, t("double_nat")),
      gw.error && h("p", { class: "status error" }, gw.error),
      h("p", { class: "muted" }, t(n ? "upnp_open_note" : "upnp_on_note")),
    );
  }));
}

function renderDiff(diff) {
  const el = $("#diff");
  if (!diff || (!diff.new.length && !diff.gone.length)) { el.hidden = true; return; }
  el.hidden = false;
  el.replaceChildren(
    h("strong", {}, t("diff_title")),
    diff.new.length > 0 && h("span", {}, `${t("diff_new")}: `, h("code", { class: "c-medium" }, diff.new.join(", "))),
    diff.gone.length > 0 && h("span", {}, `${t("diff_gone")}: `, h("code", { class: "c-low" }, diff.gone.join(", "))),
  );
}

function renderChips() {
  const counts = state.report.score.counts;
  $("#sev-chips").replaceChildren(...LEVELS.map((l) => h("button", {
    type: "button", class: "chip", "aria-pressed": String(state.sev.has(l)),
    onclick: () => { state.sev.has(l) ? state.sev.delete(l) : state.sev.add(l); renderChips(); renderFindings(); },
  }, h("i", { class: `bg-${l}` }), t("sev_" + l), h("b", {}, String(counts[l])))));
  $("#exp-chips").replaceChildren(...EXPOSURES.map((e) => h("button", {
    type: "button", class: "chip", "aria-pressed": String(state.exp === e),
    onclick: () => { state.exp = e; renderChips(); renderFindings(); },
  }, t("exp_" + e))));
}

function matches(f) {
  if (!state.sev.has(f.severity)) return false;
  if (state.exp !== "all" && f.exposure !== state.exp) return false;
  if (!state.q) return true;
  const hay = `${f.port} ${f.proto} ${f.service} ${f.process || ""} ${f.host || ""} ${f.attack.join(" ")}`.toLowerCase();
  return hay.includes(state.q);
}

function card(f) {
  const text = f.text[state.lang] || f.text.en;
  const who = f.host
    ? h("span", {}, `${t("device")} `, h("span", { class: "mono" }, f.host))
    : h("span", {}, `${t("process")} `, h("span", { class: "mono" }, f.process || t("unknown_proc")), f.pid != null ? ` · PID ${f.pid}` : "");
  return h("article", { class: "card", "data-sev": f.severity },
    h("div", { class: "card-head" },
      h("span", { class: "port" }, String(f.port)),
      h("span", { class: "proto" }, f.proto),
      h("span", { class: "sev" }, t("sev_" + f.severity)),
    ),
    h("h3", { class: "svc" }, f.service),
    h("div", { class: "meta" },
      h("span", { class: `exp ${f.exposure}`, title: t(`exp_${f.exposure}_hint`) }, t("exp_" + f.exposure)),
      who,
      h("span", {}, `${t("bound")} `, h("span", { class: "mono" }, f.addresses.join(", "))),
    ),
    text
      ? h("p", { class: "why" }, h("b", {}, text.what), " ", text.why)
      : h("p", { class: "why" }, t("unknown_why")),
    ...f.upnp.map((m) => h("p", { class: "upnp-note" }, t("upnp_forward", { ext: m.external_port, gw: m.gateway, desc: m.description || "-" }))),
    f.attack.length > 0 && h("div", { class: "attack", "aria-label": "MITRE ATT&CK" },
      ...f.attack.map((id) => external(`https://attack.mitre.org/techniques/${id.replace(".", "/")}/`, id))),
    h("div", { class: "card-actions" },
      h("button", { type: "button", class: "btn small primary", onclick: () => openGuide(f) }, t("how_to_close")),
      external(`https://www.speedguide.net/port.php?port=${f.port}`, t("port_ref"), "btn small ghost"),
    ),
  );
}

function renderFindings() {
  const list = state.report.findings.filter(matches);
  $("#findings").replaceChildren(...list.map(card));
  $("#empty").hidden = list.length > 0;
}

function renderDevices(upnp) {
  const devices = upnp?.devices || [];
  $("#devices-wrap").hidden = devices.length === 0;
  $("#devices").replaceChildren(...devices.map((d) => h("li", {},
    h("strong", {}, d.friendly_name || d.ip),
    h("span", {}, [d.manufacturer, d.model].filter(Boolean).join(" · ") || d.server),
    h("span", { class: "mono" }, `${d.ip}${d.igd ? " · IGD" : ""}${d.error ? " · " + d.error : ""}`),
  )));
}

/* ---------- how-to-close guide ---------- */

const SMB1 = ["tip_smb1", "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\nGet-SmbShare"];
const NETBIOS = ["tip_netbios", 'Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true" |\n  Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=[uint32]2}'];
const WINRM = ["tip_winrm", "Stop-Service WinRM\nSet-Service WinRM -StartupType Disabled"];
const WIN_TIPS = {
  139: SMB1,
  445: SMB1,
  137: NETBIOS,
  138: NETBIOS,
  3389: ["tip_rdp", "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1"],
  5355: ["tip_llmnr", "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force | Out-Null\nSet-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0 -Type DWord"],
  // upnphost depends on SSDPSRV: stop it first or Stop-Service refuses.
  1900: ["tip_ssdp", "Stop-Service upnphost, SSDPSRV -Force\nSet-Service SSDPSRV -StartupType Disabled"],
  5985: WINRM,
  5986: WINRM,
  7680: ["tip_do"],
};

const LINUX_TIPS = {
  22: ["tip_ssh", "sudo sshd -T | grep -Ei '^(passwordauthentication|permitrootlogin)'"],
  111: ["tip_rpcbind", "sudo systemctl disable --now rpcbind.service rpcbind.socket"],
  2375: ["tip_docker", "sudo systemctl cat docker | grep -- '-H'\ngrep -s hosts /etc/docker/daemon.json"],
  3306: ["tip_mysql", "grep -Rs bind-address /etc/mysql/"],
  5432: ["tip_pg", "sudo -u postgres psql -c 'SHOW listen_addresses;'"],
  6379: ["tip_redis", "redis-cli CONFIG GET bind\nredis-cli CONFIG GET protected-mode"],
  27017: ["tip_mongo", "grep -A3 -E '^(net|security):' /etc/mongod.conf"],
};

function codeBlock(code) {
  const btn = h("button", { type: "button", class: "btn small ghost" }, t("copy"));
  btn.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(code); btn.textContent = t("copied"); }
    catch { btn.textContent = t("copy_failed"); }
    setTimeout(() => { btn.textContent = t("copy"); }, 1500);
  });
  return h("div", { class: "code" }, h("pre", {}, h("code", {}, code)), btn);
}

function step(title, text, ...codes) {
  return h("section", { class: "step" }, h("h3", {}, title), text && h("p", {}, text), ...codes.flatMap((c) => (c ? [codeBlock(c)] : [])));
}

// Stopping these breaks Windows itself (RPC, kernel, auth): steer to the firewall instead.
const WIN_CORE_PROCS = new Set(["system", "lsass.exe", "wininit.exe", "services.exe", "csrss.exe", "smss.exe"]);
const WIN_CORE_PORTS = new Set([135]);

function windowsSteps(f) {
  const P = f.proto.toUpperCase();
  const rule = `PortScope: block ${P} ${f.port}`;
  let identify;
  if (f.pid != null) {
    identify = `Get-Process -Id ${f.pid} | Select-Object Id, ProcessName, Path\nGet-CimInstance Win32_Service -Filter "ProcessId=${f.pid}" | Select-Object Name, DisplayName, StartMode`;
  } else if (f.proto === "udp") {
    identify = `Get-NetUDPEndpoint -LocalPort ${f.port}`;
  } else {
    identify = `Get-NetTCPConnection -LocalPort ${f.port} -State Listen`;
  }
  const tip = WIN_TIPS[f.port];
  return [
    h("p", { class: "muted" }, t("g_win_admin")),
    step(t("g_identify"), t("g_identify_win"), identify),
    tip && step(t("g_specific"), t(tip[0]), tip[1]),
    WIN_CORE_PORTS.has(f.port) || WIN_CORE_PROCS.has((f.process || "").toLowerCase())
      ? step(t("g_stop"), t("g_stop_core"))
      : step(t("g_stop"), t("g_stop_win"), "Stop-Service -Name 'SERVICE_NAME'\nSet-Service -Name 'SERVICE_NAME' -StartupType Disabled"),
    step(t("g_block"), t("g_block_win"),
      `New-NetFirewallRule -DisplayName "${rule}" -Direction Inbound -Protocol ${P} -LocalPort ${f.port} -Action Block`),
    step(t("g_undo"), null, `Remove-NetFirewallRule -DisplayName "${rule}"`),
    step(t("g_verify"), t("g_verify_text")),
  ];
}

function linuxSteps(f) {
  const tip = LINUX_TIPS[f.port];
  const rich = `rule port port="${f.port}" protocol="${f.proto}" reject`;
  return [
    step(t("g_identify"), t("g_identify_linux"),
      `sudo ss -${f.proto === "udp" ? "u" : "t"}lpn 'sport = :${f.port}'${f.pid != null ? `\nsystemctl status ${f.pid} --no-pager | head -n 3` : ""}`),
    tip && step(t("g_specific"), t(tip[0]), tip[1]),
    step(t("g_stop"), t("g_stop_linux"), "sudo systemctl disable --now UNIT_NAME"),
    step(t("g_bind"), t("g_bind_text")),
    // ufw applies the first matching rule: insert at the top or an earlier "allow" wins.
    step(t("g_block"), t("g_block_ufw"), `sudo ufw insert 1 deny ${f.port}/${f.proto}`),
    step(t("g_undo"), null, `sudo ufw delete deny ${f.port}/${f.proto}`),
    step(t("g_block") + " (firewalld)", null,
      `sudo firewall-cmd --permanent --add-rich-rule='${rich}' && sudo firewall-cmd --reload`,
      `# ${t("g_undo")}\nsudo firewall-cmd --permanent --remove-rich-rule='${rich}' && sudo firewall-cmd --reload`),
    step(t("g_verify"), t("g_verify_text")),
  ];
}

function routerSteps(f) {
  const gw = state.report.upnp?.gateways?.[0];
  const dev = gw && state.report.upnp.devices.find((d) => d.ip === gw.ip);
  const model = dev ? [dev.manufacturer, dev.model].filter(Boolean).join(" ") : "";
  const items = [
    t("r_open", { ip: gw?.ip || "192.168.1.1 / 192.168.0.1" }),
    t("r_login"),
    t("r_find"),
    f.upnp.length ? t("r_delete", { ext: f.upnp[0].external_port, client: f.upnp[0].internal_client, port: f.upnp[0].internal_port }) : t("r_forward", { port: f.port }),
    t("r_disable"),
    t("r_save"),
  ];
  return [
    step(t("r_model_title"), model ? t("r_model_known", { model, name: gw.name }) : t("r_model_unknown")),
    model && step(t("r_manual_title"), t("r_manual", { model })),
    h("section", { class: "step" }, h("h3", {}, t("r_steps_title")), h("ol", {}, ...items.map((i) => h("li", {}, i)))),
    step(t("g_verify"), t("r_verify")),
  ];
}

function openGuide(f) {
  const dlg = $("#guide");
  $("#guide-title").textContent = t("guide_title", { port: f.port, proto: f.proto.toUpperCase(), service: f.service });
  $("#guide-lead").textContent = f.host ? t("guide_lead_remote", { host: f.host }) : t("guide_lead_local");
  const tabs = [
    ["windows", "Windows", windowsSteps],
    ["linux", "Linux", linuxSteps],
    ["router", t("router"), routerSteps],
  ];
  const os = (state.report.platform || "").toLowerCase();
  let current = f.exposure === "internet" ? "router" : os === "linux" ? "linux" : "windows";
  // Defence in depth: the backend already allow-lists these, and they are pasted into admin shells.
  const safe = ["tcp", "udp"].includes(f.proto) && Number.isInteger(f.port) && (f.pid == null || Number.isInteger(f.pid));
  const show = (id) => {
    current = id;
    $("#guide-tabs").replaceChildren(...tabs.map(([tid, label]) => h("button", {
      type: "button", "aria-pressed": String(tid === current), onclick: () => show(tid),
    }, label)));
    $("#guide-body").replaceChildren(...(safe
      ? tabs.find(([tid]) => tid === current)[2](f).filter(Boolean)
      : [h("p", { class: "status error" }, t("bad_finding"))]));
  };
  show(current);
  dlg.showModal();
}

/* ---------- export ---------- */

function exportJson() {
  // Exports end up attached to public bug reports: drop the public IP (the CLI --json keeps it).
  const report = structuredClone(state.report);
  for (const gw of report.upnp?.gateways || []) gw.external_ip = "(redacted)";
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const a = h("a", { href: URL.createObjectURL(blob), download: `portscope-${state.report.generated_at.slice(0, 10)}.json` });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

/* ---------- wiring ---------- */

document.addEventListener("DOMContentLoaded", async () => {
  $("#opt-upnp").checked = store.get("ps-upnp") !== "0";
  $("#opt-upnp").addEventListener("change", (e) => store.set("ps-upnp", e.target.checked ? "1" : "0"));
  $("#scan").addEventListener("click", scan);
  $("#export").addEventListener("click", exportJson);
  $("#print").addEventListener("click", () => window.print());
  $("#q").addEventListener("input", (e) => { state.q = e.target.value.trim().toLowerCase(); renderFindings(); });
  for (const b of document.querySelectorAll("[data-lang]")) b.addEventListener("click", () => setLang(b.dataset.lang));
  $("#quit").addEventListener("click", async () => {
    try { await api("/api/quit"); } catch { /* already gone */ }
    document.body.replaceChildren(h("main", {}, h("section", { class: "intro" }, h("h1", {}, t("bye")))));
  });
  await Promise.all([setLang(state.lang === "es" ? "es" : "en"), initToken()]);
  if (!token) return setStatus(t("no_token"), true);
  scan();
});
