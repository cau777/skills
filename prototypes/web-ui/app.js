const initialState = {
  activeView: "logs",
  selectedLogId: 1048,
  selectedRuleId: 2,
  editorRuleId: null,
  showEditor: false,
  credentials: [
    { id: 1, name: "GitHub host login", command: "gh auth token", status: "cached", cachedAt: "14:31:04", expiresIn: "42m", lastResult: "exit 0 · 40 chars" },
    { id: 2, name: "Codex subscription", command: "python3 ~/.local/share/proxy/refresh_codex.py", status: "cached", cachedAt: "14:18:51", expiresIn: "36m", lastResult: "exit 0 · 1837 chars" },
    { id: 3, name: "Claude subscription", command: "python3 ~/.local/share/proxy/refresh_claude.py", status: "stale", cachedAt: "12:02:10", expiresIn: "expired", lastResult: "exit 1 · refresh needed" },
  ],
  vms: [
    { id: 1, name: "orca-skills", ip: "10.14.105.22", status: "online", rules: 4, lastSeen: "now" },
    { id: 2, name: "orca-api", ip: "10.14.105.31", status: "online", rules: 3, lastSeen: "8s ago" },
    { id: 3, name: "scratch-pad", ip: "10.14.105.44", status: "offline", rules: 1, lastSeen: "2h ago" },
  ],
  rules: [
    { id: 1, priority: 10, vms: ["orca-skills", "orca-api"], host: "api.github.com", action: "Allow-with-credential", path: "/repos/cau777", scheme: "Bearer", credential: "GitHub host login" },
    { id: 2, priority: 20, vms: ["orca-skills"], host: "github.com", action: "Allow-with-credential", path: "/cau777/skills", scheme: "Basic x-access-token", credential: "GitHub host login" },
    { id: 3, priority: 30, vms: ["*"], host: "api.openai.com", action: "Allow-with-credential", path: "/v1", scheme: "Bearer", credential: "Codex subscription" },
    { id: 4, priority: 40, vms: ["scratch-pad"], host: "api.github.com", action: "Block", path: "", scheme: "", credential: "" },
    { id: 5, priority: 1000, vms: ["*"], host: "telemetry.example.com", action: "Block", path: "", scheme: "", credential: "" },
  ],
  logs: [
    { id: 1048, time: "14:32:11", vm: "orca-skills", method: "POST", host: "api.github.com", path: "/repos/cau777/skills/issues", decision: "Allow + credential", status: 201, ruleId: 1, latency: "184ms", reason: "Exact host and segment-boundary path matched priority 10.", headers: { "user-agent": "GitHub CLI 2.74.0", authorization: "[REDACTED · injected by GitHub host login]", accept: "application/vnd.github+json" }, trace: ["Identified VM orca-skills from source 10.14.105.22", "Priority 10 matched VM selector and api.github.com", "Path /repos/cau777/skills/issues is below /repos/cau777", "Injected Bearer credential; upstream returned 201"] },
    { id: 1047, time: "14:31:58", vm: "orca-skills", method: "GET", host: "telemetry.example.com", path: "/collect", decision: "Block", status: 403, ruleId: 5, latency: "2ms", reason: "Priority 1000 blocks this exact hostname for every VM.", headers: { "user-agent": "codex-cli/0.72", authorization: "absent", accept: "*/*" }, trace: ["Identified VM orca-skills from source 10.14.105.22", "No earlier exact-host rule matched", "Priority 1000 matched wildcard VM selector and hostname", "Blocked before TLS interception"] },
    { id: 1046, time: "14:31:44", vm: "orca-api", method: "GET", host: "pypi.org", path: "/simple/aiohttp/", decision: "Allow default", status: 200, ruleId: null, latency: "91ms", reason: "No Rule matched; unmatched traffic defaults to Allow.", headers: { "user-agent": "pip/25.1", authorization: "absent", accept: "text/html" }, trace: ["Identified VM orca-api from source 10.14.105.31", "No exact-host Rule matched pypi.org", "Applied default Allow without TLS interception"] },
    { id: 1045, time: "14:31:09", vm: "orca-skills", method: "GET", host: "github.com", path: "/cau777/other-repo.git/info/refs", decision: "Allow default", status: 401, ruleId: null, latency: "126ms", reason: "Credential Rule path did not match; continued credential-free to default Allow.", headers: { "user-agent": "git/2.43", authorization: "[REDACTED · client placeholder]", accept: "*/*" }, trace: ["Priority 20 matched VM selector and github.com", "Path /cau777/other-repo.git is outside /cau777/skills", "Continued without credential", "No later Rule matched; applied default Allow"] },
    { id: 1044, time: "14:30:47", vm: "scratch-pad", method: "GET", host: "api.github.com", path: "/user", decision: "Block", status: 403, ruleId: 4, latency: "1ms", reason: "Priority 40 blocks api.github.com for scratch-pad.", headers: { "user-agent": "curl/8.5", authorization: "absent", accept: "*/*" }, trace: ["Identified VM scratch-pad from source 10.14.105.44", "Prior Rules did not select scratch-pad", "Priority 40 matched VM and hostname", "Blocked before TLS interception"] },
  ],
};

let state = structuredClone(initialState);
const variants = [
  { key: "A", name: "Entity console" },
  { key: "B", name: "Policy workspace" },
  { key: "C", name: "Activity debugger" },
];

function currentVariant() {
  const key = new URLSearchParams(location.search).get("variant")?.toUpperCase();
  return variants.some((item) => item.key === key) ? key : "A";
}

function setVariant(key) {
  const url = new URL(location.href);
  url.searchParams.set("variant", key);
  history.replaceState({}, "", url);
  render();
}

function cycleVariant(direction) {
  const index = variants.findIndex((item) => item.key === currentVariant());
  setVariant(variants[(index + direction + variants.length) % variants.length].key);
}

function setView(view) {
  state.activeView = view;
  render();
}

function selectLog(id) {
  state.selectedLogId = Number(id);
  render();
}

function selectRule(id) {
  state.selectedRuleId = Number(id);
  render();
}

function openRuleEditor(id = null) {
  state.editorRuleId = id === null ? null : Number(id);
  state.showEditor = true;
  render();
}

function closeRuleEditor() {
  state.showEditor = false;
  render();
}

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function actionClass(action) {
  if (action === "Block") return "action-block";
  if (action === "Allow-with-credential" || action.includes("credential")) return "action-credential";
  return "action-allow";
}

function statusBadge(status) {
  const tone = status === "online" || status === "cached" ? "ok" : status === "offline" ? "danger" : "warn";
  return `<span class="badge ${tone}"><span class="dot"></span>${esc(status)}</span>`;
}

function navButton(view, label, count, variantClass) {
  const active = state.activeView === view ? "active" : "";
  return `<button class="${active}" data-view="${view}"><span>${label}</span>${count !== undefined ? `<span class="count">${count}</span>` : ""}</button>`;
}

function rulesTable() {
  return `<table><thead><tr><th>Priority</th><th>VM selector</th><th>Exact host</th><th>Action</th><th>Path / credential</th></tr></thead><tbody>${state.rules.sort((a,b) => a.priority - b.priority).map(rule => `
    <tr data-rule="${rule.id}" data-select class="${state.selectedRuleId === rule.id ? "selected" : ""}">
      <td class="mono">${rule.priority}</td><td>${esc(rule.vms.join(", "))}</td><td class="mono">${esc(rule.host)}</td>
      <td class="${actionClass(rule.action)}">${esc(rule.action)}</td><td>${rule.path ? `<span class="mono">${esc(rule.path)}</span><br><span class="tiny muted">${esc(rule.scheme)} · ${esc(rule.credential)}</span>` : `<span class="muted">hostname-level</span>`}</td>
    </tr>`).join("")}</tbody></table>`;
}

function credentialsTable() {
  return `<table><thead><tr><th>Name</th><th>Live cache status</th><th>Command</th><th>Last result</th></tr></thead><tbody>${state.credentials.map(item => `
    <tr><td><strong>${esc(item.name)}</strong></td><td>${statusBadge(item.status)}<div class="tiny muted" style="margin-top:5px">${esc(item.cachedAt)} · ${esc(item.expiresIn)}</div></td><td><code class="mono">${esc(item.command)}</code></td><td class="muted">${esc(item.lastResult)}</td></tr>`).join("")}</tbody></table>`;
}

function vmsTable() {
  return `<table><thead><tr><th>VM</th><th>Status</th><th>Source IP</th><th>Rules</th><th>Last seen</th></tr></thead><tbody>${state.vms.map(vm => `
    <tr><td><strong>${esc(vm.name)}</strong></td><td>${statusBadge(vm.status)}</td><td class="mono">${esc(vm.ip)}</td><td>${vm.rules}</td><td class="muted">${esc(vm.lastSeen)}</td></tr>`).join("")}</tbody></table>`;
}

function logsTable() {
  return `<table><thead><tr><th>Time</th><th>VM</th><th>Request</th><th>Decision</th><th>Status</th></tr></thead><tbody>${state.logs.map(log => `
    <tr data-log="${log.id}" data-select class="${state.selectedLogId === log.id ? "selected" : ""}"><td class="mono">${log.time}</td><td>${esc(log.vm)}</td><td><span class="mono">${esc(log.method)}</span> ${esc(log.host)}<div class="tiny muted mono">${esc(log.path)}</div></td><td class="${actionClass(log.decision)}">${esc(log.decision)}</td><td>${log.status} <span class="tiny muted">· ${log.latency}</span></td></tr>`).join("")}</tbody></table>`;
}

function viewTitle() {
  return {
    rules: ["Rules", "Unique priority is the entire ordering. Lower numbers run first."],
    credentials: ["Credentials", "Commands run on the host; only cached output is injected."],
    vms: ["Virtual machines", "Registered sources subject to transparent outbound enforcement."],
    logs: ["Request logs", "Every decision, including passthrough and default Allow."],
  }[state.activeView];
}

function currentViewTable() {
  return { rules: rulesTable, credentials: credentialsTable, vms: vmsTable, logs: logsTable }[state.activeView]();
}

function selectedLog() {
  return state.logs.find((log) => log.id === state.selectedLogId) || state.logs[0];
}

function selectedRule() {
  return state.rules.find((rule) => rule.id === state.selectedRuleId) || state.rules[0];
}

function logInspector(log, compact = false) {
  return `<div class="inspector-header"><div><div class="eyebrow">Decision ${log.id}</div><h2 style="margin:6px 0 3px">${esc(log.decision)}</h2><div class="muted tiny mono">${esc(log.time)} · ${esc(log.latency)}</div></div><span class="badge ${log.status >= 400 ? "danger" : "ok"}"><span class="dot"></span>HTTP ${log.status}</span></div>
    <dl class="kv"><dt>VM</dt><dd>${esc(log.vm)}</dd><dt>Request</dt><dd class="mono">${esc(log.method)} https://${esc(log.host)}${esc(log.path)}</dd><dt>Matched Rule</dt><dd>${log.ruleId ? `Priority ${state.rules.find(r => r.id === log.ruleId)?.priority ?? "?"}` : "None — default policy"}</dd></dl>
    <div class="inspector-section"><div class="eyebrow">Why</div><p style="font-size:13px;line-height:1.55">${esc(log.reason)}</p><ol class="decision-trace">${log.trace.map((step, i) => `<li><span class="trace-index">${i + 1}</span><span>${esc(step)}</span></li>`).join("")}</ol></div>
    <div class="inspector-section"><div class="eyebrow">Headers · redacted</div><div class="code" style="margin-top:10px">${Object.entries(log.headers).map(([key, value]) => `${esc(key)}: ${esc(value)}`).join("\n")}</div></div>`;
}

function ruleInspector(rule) {
  return `<div class="inspector-header"><div><div class="eyebrow">Rule priority</div><h2 style="margin:5px 0">${rule.priority}</h2></div><button class="button" data-edit-rule="${rule.id}">Edit</button></div>
    <dl class="kv"><dt>VM selector</dt><dd>${esc(rule.vms.join(", "))}</dd><dt>Exact host</dt><dd class="mono">${esc(rule.host)}</dd><dt>Action</dt><dd class="${actionClass(rule.action)}">${esc(rule.action)}</dd>${rule.path ? `<dt>Path prefix</dt><dd class="mono">${esc(rule.path)}</dd><dt>Auth scheme</dt><dd>${esc(rule.scheme)}</dd><dt>Credential</dt><dd>${esc(rule.credential)}</dd>` : ""}</dl>
    <div class="inspector-section"><div class="eyebrow">Evaluation preview</div><p class="tiny muted" style="line-height:1.6">First match wins. Host is exact. ${rule.action === "Allow-with-credential" ? "TLS is intercepted only to test the normalized path; similar path segments do not match." : "This hostname-level action is terminal before TLS interception."}</p></div>`;
}

function renderA() {
  const title = viewTitle();
  const count = state[state.activeView].length;
  const inspector = state.activeView === "logs" ? logInspector(selectedLog()) : state.activeView === "rules" ? ruleInspector(selectedRule()) : `<div class="eyebrow">Selection inspector</div><p class="muted" style="line-height:1.6">Select an item to inspect it without leaving the table. This variant optimizes for fast inventory work.</p>`;
  return `<div class="prototype-ribbon">THROWAWAY PROTOTYPE · VARIANT A · ENTITY CONSOLE</div><div class="a-shell">
    <aside class="a-sidebar"><div class="brand"><span class="brand-mark"></span>Outbound Gate</div><nav class="a-nav">${navButton("logs", "Logs", state.logs.length)}${navButton("rules", "Rules", state.rules.length)}${navButton("credentials", "Credentials", state.credentials.length)}${navButton("vms", "VMs", state.vms.length)}</nav><div style="position:fixed;bottom:92px" class="tiny muted"><span class="dot ok"></span> enforcement active</div></aside>
    <main class="a-main"><header class="a-main-header"><div><div class="eyebrow">Inventory</div><h1 class="section-title">${title[0]} <span class="count">${count}</span></h1><p class="section-subtitle">${title[1]}</p></div>${state.activeView === "rules" ? `<button class="button primary" data-new-rule>New Rule</button>` : ""}</header>
      <div class="a-toolbar"><input class="search" placeholder="Filter ${title[0].toLowerCase()}…"><button class="button">Filters</button></div><div class="a-table-wrap">${currentViewTable()}</div></main>
    <aside class="a-inspector">${inspector}</aside></div>`;
}

function renderB() {
  const tabs = ["rules", "credentials", "vms", "logs"].map(view => navButton(view, view[0].toUpperCase() + view.slice(1), undefined, "b")).join("");
  let content;
  if (state.activeView === "rules") {
    const rule = selectedRule();
    content = `<div style="display:flex;justify-content:space-between;align-items:end;gap:12px"><div><div class="eyebrow">Policy sequence</div><h1 style="margin:6px 0 0">What happens first?</h1><p class="section-subtitle">Drag is deliberately absent: priorities are explicit, unique values.</p></div><button class="button primary" data-new-rule>Add Rule</button></div>
      <div class="b-rule-layout"><div class="b-stack">${state.rules.sort((a,b) => a.priority - b.priority).map(item => `<div class="b-rule ${item.id === rule.id ? "selected" : ""}" data-rule="${item.id}"><div class="b-priority">${item.priority}</div><div><strong class="mono">${esc(item.host)}</strong><div class="tiny muted">${esc(item.path || "whole hostname")}</div></div><div class="b-action ${actionClass(item.action)}">${esc(item.action)}</div><div class="tiny">${esc(item.vms.join(", "))}</div><span>›</span></div>`).join("")}</div>
      <aside class="b-aside"><div class="eyebrow">Rule builder</div><h2 style="margin:7px 0 18px">Priority ${rule.priority}</h2><dl class="kv"><dt>When VM is</dt><dd>${esc(rule.vms.join(", "))}</dd><dt>And host is</dt><dd class="mono">${esc(rule.host)}</dd><dt>Then</dt><dd class="${actionClass(rule.action)}">${esc(rule.action)}</dd>${rule.path ? `<dt>Only below</dt><dd class="mono">${esc(rule.path)}</dd><dt>Using</dt><dd>${esc(rule.scheme)} · ${esc(rule.credential)}</dd>` : ""}</dl><button class="button" style="width:100%;margin-top:18px" data-edit-rule="${rule.id}">Edit this Rule</button><div class="code" style="margin-top:14px">Evaluation order\n${state.rules.sort((a,b) => a.priority-b.priority).map(r => `${r.priority}  ${r.host}`).join("\n")}\ndefault  Allow</div></aside></div>`;
  } else if (state.activeView === "credentials") {
    content = `<div class="eyebrow">Command-backed secrets</div><h1 style="margin:6px 0">Credentials</h1><p class="section-subtitle">Status is the live in-memory cache, not a claim about the command itself.</p><div class="b-entity-grid">${state.credentials.map(item => `<article class="b-card"><div style="display:flex;justify-content:space-between;gap:10px"><strong>${esc(item.name)}</strong>${statusBadge(item.status)}</div><div class="code" style="margin:16px 0 10px">$ ${esc(item.command)}</div><div class="tiny muted">Cached ${esc(item.cachedAt)} · ${esc(item.expiresIn)} remaining<br>${esc(item.lastResult)}</div></article>`).join("")}</div>`;
  } else if (state.activeView === "vms") {
    content = `<div class="eyebrow">Enforced sources</div><h1 style="margin:6px 0">Virtual machines</h1><div class="b-entity-grid">${state.vms.map(vm => `<article class="b-card"><div style="display:flex;justify-content:space-between"><strong>${esc(vm.name)}</strong>${statusBadge(vm.status)}</div><p class="mono">${esc(vm.ip)}</p><span class="tiny muted">${vm.rules} Rules · last seen ${esc(vm.lastSeen)}</span></article>`).join("")}</div>`;
  } else {
    content = `<div class="eyebrow">Decision ledger</div><h1 style="margin:6px 0">Logs</h1><p class="section-subtitle">Select a request for a reproducible explanation.</p><div class="b-rule-layout"><div>${logsTable()}</div><aside class="b-aside">${logInspector(selectedLog())}</aside></div>`;
  }
  return `<div class="prototype-ribbon">THROWAWAY PROTOTYPE · VARIANT B · POLICY WORKSPACE</div><div class="b-shell"><header class="b-header"><div class="brand"><span class="brand-mark"></span>Outbound Gate</div><nav class="b-tabs">${tabs}</nav><div class="b-status">● policy active</div></header><main class="b-main">${content}</main></div>`;
}

function cLogFeed() {
  return state.logs.map(log => `<div class="c-log ${state.selectedLogId === log.id ? "selected" : ""}" data-log="${log.id}"><span class="mono muted">${esc(log.time)}</span><span>${esc(log.vm)}</span><span class="host"><span class="mono">${esc(log.method)}</span> ${esc(log.host)}<br><span class="tiny muted mono">${esc(log.path)}</span></span><span class="${actionClass(log.decision)}">${esc(log.decision)}</span><span>${log.status} <span class="muted">${esc(log.latency)}</span></span></div>`).join("");
}

function renderC() {
  const nav = ["logs", "rules", "credentials", "vms"].map(view => navButton(view, view[0].toUpperCase() + view.slice(1))).join("");
  let main;
  if (state.activeView === "logs") {
    const log = selectedLog();
    main = `<main class="c-main"><section class="c-feed"><header class="c-feed-header"><div><div class="eyebrow">Live decision stream</div><h1 style="font-size:20px;margin:5px 0">Requests</h1></div><input class="search" style="max-width:300px" placeholder="Filter VM, host, decision…"></header>${cLogFeed()}</section><aside class="c-explain">${logInspector(log)}</aside></main>`;
  } else {
    const title = viewTitle();
    main = `<main class="c-main"><section class="c-config"><div style="display:flex;justify-content:space-between;align-items:end"><div><div class="eyebrow">Configuration</div><h1 class="section-title">${title[0]}</h1><p class="section-subtitle">${title[1]}</p></div>${state.activeView === "rules" ? `<button class="button primary" data-new-rule>New Rule</button>` : ""}</div>
      <div class="c-summary-grid"><div class="c-summary"><span class="muted tiny">ACTIVE RULES</span><strong>${state.rules.length}</strong></div><div class="c-summary"><span class="muted tiny">HEALTHY CREDENTIALS</span><strong>2 / 3</strong></div><div class="c-summary"><span class="muted tiny">ONLINE VMS</span><strong>2 / 3</strong></div></div><div class="a-table-wrap">${currentViewTable()}</div></section></main>`;
  }
  return `<div class="prototype-ribbon">THROWAWAY PROTOTYPE · VARIANT C · ACTIVITY DEBUGGER</div><div class="c-shell"><header class="c-top"><div class="brand"><span class="brand-mark"></span>Outbound Gate</div><nav class="c-nav">${nav}</nav><div class="c-live">● LIVE</div></header>${main}</div>`;
}

function ruleEditor() {
  if (!state.showEditor) return "";
  const existing = state.rules.find(rule => rule.id === state.editorRuleId);
  const rule = existing || { priority: Math.max(...state.rules.map(item => item.priority)) + 10, vms: [], host: "", action: "Allow-with-credential", path: "/", scheme: "Bearer", credential: state.credentials[0].name };
  const credentialFields = rule.action === "Allow-with-credential";
  return `<div class="scrim"><form class="drawer" id="rule-form"><div class="drawer-head"><div><div class="eyebrow">${existing ? "Edit Rule" : "New Rule"}</div><h2 style="margin:6px 0">${existing ? `Priority ${rule.priority}` : "Add to policy"}</h2><p class="section-subtitle">First matching priority wins. Hostnames are exact in v1.</p></div><button type="button" class="icon-button" data-close-editor>✕</button></div>
    <input type="hidden" name="id" value="${existing?.id ?? ""}"><div class="form-grid">
      <div class="field"><label for="priority">Unique priority · lowest first</label><input id="priority" name="priority" type="number" required value="${rule.priority}"><small>Priority is the sole ordering mechanism; duplicate values are rejected.</small></div>
      <div class="field"><label>VM selector</label><div class="checkboxes"><label><input type="checkbox" name="vm" value="*" ${rule.vms.includes("*") ? "checked" : ""}> * all current + future</label>${state.vms.map(vm => `<label><input type="checkbox" name="vm" value="${esc(vm.name)}" ${rule.vms.includes(vm.name) ? "checked" : ""}> ${esc(vm.name)}</label>`).join("")}</div><small>Wildcard is exclusive with named VMs.</small></div>
      <div class="field"><label for="host">Exact host</label><input id="host" name="host" required placeholder="api.github.com" value="${esc(rule.host)}"><small>Port and trailing dot are removed; matching is case-insensitive. No wildcards or subdomains.</small></div>
      <div class="field"><label for="action">Terminal action</label><select id="action" name="action"><option ${rule.action === "Allow" ? "selected" : ""}>Allow</option><option ${rule.action === "Block" ? "selected" : ""}>Block</option><option ${rule.action === "Allow-with-credential" ? "selected" : ""}>Allow-with-credential</option></select></div>
      <div id="credential-fields" style="display:${credentialFields ? "grid" : "none"};gap:15px"><div class="field"><label for="path">Normalized path prefix</label><input id="path" name="path" value="${esc(rule.path)}" placeholder="/repos/cau777"><small>Matches the identical path or descendants at a `/` boundary; query strings are ignored.</small></div><div class="field"><label for="scheme">Authentication scheme</label><input id="scheme" name="scheme" value="${esc(rule.scheme)}" placeholder="Bearer"><small>Examples: Bearer, token, Basic x-access-token.</small></div><div class="field"><label for="credential">Credential</label><select id="credential" name="credential">${state.credentials.map(item => `<option ${item.name === rule.credential ? "selected" : ""}>${esc(item.name)}</option>`).join("")}</select></div></div>
    </div><div class="form-actions"><button type="button" class="button" data-close-editor>Cancel</button><button type="submit" class="button primary">Save in memory</button></div></form></div>`;
}

function statePanel() {
  const visible = { variant: currentVariant(), activeView: state.activeView, selectedLogId: state.selectedLogId, selectedRuleId: state.selectedRuleId, rules: state.rules, credentials: state.credentials, vms: state.vms };
  return `<details class="state-panel"><summary>PROTOTYPE STATE · inspect</summary><pre>${esc(JSON.stringify(visible, null, 2))}</pre></details>`;
}

function switcher() {
  const variant = variants.find((item) => item.key === currentVariant());
  return `<div class="switcher" aria-label="Prototype variant switcher"><button data-cycle="-1" aria-label="Previous variant">←</button><div class="switcher-label">${variant.key} — ${variant.name}</div><button data-cycle="1" aria-label="Next variant">→</button></div>`;
}

function render() {
  const root = document.querySelector("#app");
  const variant = currentVariant();
  root.innerHTML = (variant === "A" ? renderA() : variant === "B" ? renderB() : renderC()) + ruleEditor() + statePanel() + switcher();
  bind();
}

function bind() {
  document.querySelectorAll("[data-view]").forEach(button => button.addEventListener("click", () => setView(button.dataset.view)));
  document.querySelectorAll("[data-log]").forEach(row => row.addEventListener("click", () => selectLog(row.dataset.log)));
  document.querySelectorAll("[data-rule]").forEach(row => row.addEventListener("click", () => selectRule(row.dataset.rule)));
  document.querySelectorAll("[data-edit-rule]").forEach(button => button.addEventListener("click", () => openRuleEditor(button.dataset.editRule)));
  document.querySelectorAll("[data-new-rule]").forEach(button => button.addEventListener("click", () => openRuleEditor()));
  document.querySelectorAll("[data-close-editor]").forEach(button => button.addEventListener("click", closeRuleEditor));
  document.querySelectorAll("[data-cycle]").forEach(button => button.addEventListener("click", () => cycleVariant(Number(button.dataset.cycle))));

  const action = document.querySelector("#action");
  action?.addEventListener("change", () => {
    document.querySelector("#credential-fields").style.display = action.value === "Allow-with-credential" ? "grid" : "none";
  });

  document.querySelector("#rule-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const id = data.get("id") ? Number(data.get("id")) : Math.max(...state.rules.map(rule => rule.id)) + 1;
    let vms = data.getAll("vm");
    if (vms.includes("*")) vms = ["*"];
    if (!vms.length) vms = [state.vms[0].name];
    const next = {
      id,
      priority: Number(data.get("priority")),
      vms,
      host: String(data.get("host")).trim().toLowerCase().replace(/\.$/, ""),
      action: data.get("action"),
      path: data.get("action") === "Allow-with-credential" ? data.get("path") : "",
      scheme: data.get("action") === "Allow-with-credential" ? data.get("scheme") : "",
      credential: data.get("action") === "Allow-with-credential" ? data.get("credential") : "",
    };
    const duplicate = state.rules.find(rule => rule.priority === next.priority && rule.id !== id);
    if (duplicate) {
      alert(`Priority ${next.priority} is already used by ${duplicate.host}.`);
      return;
    }
    const index = state.rules.findIndex(rule => rule.id === id);
    if (index >= 0) state.rules[index] = next; else state.rules.push(next);
    state.selectedRuleId = id;
    state.activeView = "rules";
    state.showEditor = false;
    render();
  });
}

document.addEventListener("keydown", (event) => {
  if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
  const target = event.target;
  if (target.matches("input, textarea, select, [contenteditable]")) return;
  cycleVariant(event.key === "ArrowRight" ? 1 : -1);
});

window.addEventListener("popstate", render);
render();
