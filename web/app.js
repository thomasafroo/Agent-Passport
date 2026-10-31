"use strict";
let state, session, selected, busy = false, filter = "all";
let seen = null; // what the last render showed, so only new changes animate
let pendingFocus = false;
const $ = id => document.getElementById(id);
const SVG = "http://www.w3.org/2000/svg";
const el = (tag, cls, text) => { const node = document.createElement(tag); if (cls) node.className = cls; if (text !== undefined) node.textContent = text; return node; };
const svg = (tag, attrs = {}) => { const node = document.createElementNS(SVG, tag); for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v); return node; };

async function api(path, method = "GET", payload) {
  const headers = { "X-Passport-Console": session || "" };
  if (payload !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(path, { method, headers, body: payload === undefined ? undefined : JSON.stringify(payload) });
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail || "The gateway could not complete this request.");
  return body;
}

function showError(message) { $("error").textContent = message; $("error").hidden = false; }

async function action(path) {
  if (busy) return;
  busy = true; $("error").hidden = true; renderControls();
  try { state = await api(path, "POST"); pendingFocus = true; render(); }
  catch (error) { showError(error.message); }
  finally { busy = false; renderControls(); if (state) renderInspector(); loadApprovals(); }
}

/* ---------- Guilloche: hypotrochoid rosettes and wave bands, the linework of security printing ---------- */
function rosette(R, r, d, steps = 1400) {
  const turns = r / gcd(Math.round(R), Math.round(r));
  let path = "";
  for (let i = 0; i <= steps; i++) {
    const t = (i / steps) * Math.PI * 2 * turns;
    const x = (R - r) * Math.cos(t) + d * Math.cos(((R - r) / r) * t);
    const y = (R - r) * Math.sin(t) - d * Math.sin(((R - r) / r) * t);
    path += `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`;
  }
  return path;
}
function gcd(a, b) { return b ? gcd(b, a % b) : a; }
function waves(width, height, lines) {
  const paths = [];
  for (let k = 0; k < lines; k++) {
    let path = ""; const base = (height / lines) * k + 6, phase = k * 0.32;
    for (let x = 0; x <= width; x += 4) {
      const y = base + Math.sin(x / 26 + phase) * 7 + Math.sin(x / 61 - phase * 1.7) * 9;
      path += `${x ? "L" : "M"}${x} ${y.toFixed(1)}`;
    }
    paths.push(path);
  }
  return paths;
}
function drawCover() {
  const host = $("cover-rosette");
  [[180, 48, 150], [150, 54, 120], [110, 30, 88]].forEach(([R, r, d]) => host.append(svg("path", { d: rosette(R, r, d, 3000) })));
}
const passportWaves = waves(420, 520, 34);
const photoRosette = rosette(70, 13, 42, 900);

/* ---------- Derived story data ---------- */
const PHASES = ["ready", "delegated", "attacked", "contained", "finished"];
function stage() {
  if (!state) return 0;
  const index = PHASES.indexOf(state.phase);
  return state.phase === "finished" && state.metrics.fork ? 5 : index;
}
const grantById = id => state.grants.find(g => g.id === id);
const isFork = g => g.subject.startsWith("Fork ");
const rootGrant = () => state.grants.find(g => !g.parent);
function topBranch(g) { let node = g; while (node?.parent && grantById(node.parent)?.parent) node = grantById(node.parent); return node; }
function branchColor(g) {
  if (!g) return "var(--ink)";
  if (isFork(g)) return "var(--branch-d)";
  if (!g.parent) return "var(--ink)";
  const tops = state.grants.filter(x => x.parent === rootGrant().id);
  return ["var(--branch-a)", "var(--branch-b)", "var(--branch-c)"][tops.indexOf(topBranch(g)) % 3];
}
function abbreviate(subject) { return subject.startsWith("Fork ") ? subject.slice(5) : subject.split(/\s+/).map(w => w.replace(/[^A-Za-z0-9]/g, "")[0] || "").join("").slice(0, 2).toUpperCase(); }
const denialsFor = id => state.events.filter(e => e.kind === "denied" && e.grant_id === id);
function available() { const r = state.run; return r.budget - r.spent - r.reserved; }
function relTime(t) { return `+${(t - state.run.created).toFixed(3)}s`; }
function humanRule(rule) { const s = rule.toLowerCase().replace(/_/g, " "); return s[0].toUpperCase() + s.slice(1); }

/* ---------- Controls ---------- */
const STEP_COPY = [
  { label: "Ready", button: "Start investigation", hint: () => "The coordinator holds one passport and a 24-unit budget. Start to issue four narrower passports." },
  { label: "Authority delegated", button: "Inject malicious output", hint: () => "Select any worker to inspect its passport. Each holds a strict subset of its parent's permissions and the same expiry or earlier." },
  { label: "Attack blocked", button: "Contain branch", alert: true, hint: () => "The model never decided this: the gateway checked the exact resource/action pair, and the stolen token failed without its holder key. Next, revoke the compromised branch." },
  { label: "Branch contained", button: "Complete investigation", hint: () => "Revocation reached the trace analyst through its ancestor chain, with no cache to expire. The other branches are untouched." },
  { label: "Investigation complete", button: "Fork 32 workers", hint: () => `Next, 32 workers race for the ${available()} units left. The pool should fill exactly to its limit and no further.` },
  { label: "Fork race complete", button: "Download evidence", hint: () => "The evidence file holds every decision and signed receipt. Verify it offline, or reset to replay." },
];

function renderControls() {
  const s = stage(), copy = STEP_COPY[s];
  $("step-text").textContent = copy.button;
  $("step").disabled = busy || !state;
  $("step").classList.toggle("busy", busy);
  $("reset").disabled = busy;
  $("export").disabled = busy || !state;
  $("request-config").disabled = busy || !state;
  if (state) { renderLive(); renderOwners(); }
}

function primary() {
  const s = stage();
  if (s <= 3) action("/api/demo/step");
  else if (s === 4) action("/api/demo/fork");
  else exportEvidence();
}

/* ---------- Tree ---------- */
function renderGraph() {
  const graph = $("graph"); graph.replaceChildren();
  const byParent = new Map();
  for (const g of state.grants) { const key = g.parent || "root"; if (!byParent.has(key)) byParent.set(key, []); byParent.get(key).push(g); }
  let order = 0;
  function branch(g) {
    const li = el("li");
    if (g.state !== "active") li.classList.add("void-branch");
    const button = el("button", `node ${g.state}${g.parent ? "" : " root"}${selected === g.id ? " selected" : ""}`);
    button.type = "button";
    button.setAttribute("aria-pressed", String(selected === g.id));
    button.setAttribute("aria-label", `${g.subject}, ${g.state === "active" ? "valid" : g.state}. Inspect passport`);
    const title = el("span", "node-title"); title.append(el("span", "dot"), document.createTextNode(g.subject));
    const scope = el("span", "node-scope");
    if (g.scopes.length > 1) scope.append(el("b", "", `${g.scopes.length} permissions`), document.createTextNode(" + full budget"));
    else scope.append(el("b", "", g.scopes[0].action), document.createTextNode(` on ${g.scopes[0].resource.split("/")[0]}`));
    button.append(title, scope, el("span", "node-id", g.id));
    const denials = denialsFor(g.id).length;
    if (denials) { const badge = el("span", "denials", String(denials)); badge.title = `${denials} denied request${denials === 1 ? "" : "s"}`; button.append(badge); }
    if (g.state === "revoked" || g.state === "deprovisioned") button.append(el("span", "void", "VOID"));
    else if (g.id === state.live_grant) { button.classList.add("live-node"); button.append(el("span", "live-chip", "LIVE")); }
    if (seen && !seen.grants.has(g.id)) { button.classList.add("appear"); button.style.setProperty("--i", String(order++)); }
    else if (seen && denials > (seen.denials.get(g.id) || 0)) button.classList.add("just-denied");
    button.onclick = () => { selected = g.id; renderGraph(); renderInspector(true); };
    li.append(button);
    const children = byParent.get(g.id) || [];
    const forks = children.filter(isFork), regular = children.filter(c => !isFork(c));
    if (regular.length || forks.length) {
      const ul = el("ul");
      regular.forEach(c => ul.append(branch(c)));
      if (forks.length) ul.append(forkCluster(forks));
      li.append(ul);
    }
    return li;
  }
  (byParent.get("root") || []).forEach(g => graph.append(branch(g)));
  const n = state.grants.length;
  $("agent-count").textContent = `${n} passport${n === 1 ? "" : "s"} issued`;
}

function forkOutcome(g) {
  const e = state.events.find(x => x.grant_id === g.id && (x.kind === "completed" || x.kind === "denied"));
  return e ? e.kind : "pending";
}

function forkCluster(forks) {
  const li = el("li");
  const button = el("button", "fork-cluster"); button.type = "button";
  const dots = el("span", "fork-dots");
  forks.forEach(f => dots.append(el("i", forkOutcome(f))));
  const admitted = forks.filter(f => forkOutcome(f) === "completed").length;
  button.append(el("strong", "", `${forks.length} forked workers`), dots, el("small", "", `${admitted} admitted, ${forks.length - admitted} denied by the pool`));
  button.setAttribute("aria-label", `${forks.length} forked workers. Open list`);
  button.onclick = () => showForks(forks);
  li.append(button);
  return li;
}

function showForks(forks) {
  $("dialog-title").textContent = "Forked workers";
  const detail = $("event-detail");
  const list = el("div", "fork-list");
  for (const g of forks) {
    const outcome = forkOutcome(g);
    const b = el("button"); b.type = "button";
    b.append(el("span", "", g.subject), el("span", `tag ${outcome}`, outcome === "completed" ? "Admitted" : outcome === "denied" ? "Denied" : "Pending"));
    b.onclick = () => { selected = g.id; $("event-dialog").close(); renderGraph(); renderInspector(true); };
    list.append(b);
  }
  detail.replaceChildren(el("h3", "", `${forks.length} workers. One shared pool.`), el("p", "", "Each fork holds its own signed passport but draws from the coordinator's budget. Select one to inspect it."), list);
  $("event-dialog").showModal();
}

/* ---------- Incident callout ---------- */
function renderIncident() {
  const box = $("incident");
  const injected = state.events.find(e => e.kind === "injected");
  if (!injected) { box.hidden = true; box.replaceChildren(); return; }
  const fresh = box.hidden;
  box.hidden = false;
  const victim = grantById(injected.grant_id);
  const quote = el("div", "incident-quote");
  quote.append(el("h3", "", "Untrusted tool output"), el("blockquote", "", injected.detail.replace(/^Fixture:\s*/, "").replace(/^[‘'"]|[’'"]$/g, "")), el("cite", "", `Delivered to ${victim?.subject || "a worker"}. A scripted fixture, not a model.`));
  const response = el("div", "incident-response");
  response.append(el("h3", "", "What the gateway did"));
  const attempts = state.events.filter(e => e.grant_id === injected.grant_id && e.kind === "denied" && e.seq > injected.seq);
  const revoked = state.events.find(e => e.kind === "revoked" && e.grant_id === injected.grant_id);
  const label = e => e.rule.startsWith("PROOF_") ? "replay stolen token, no holder key" : e.action ? `${e.action} → ${e.resource}` : "delegate → production deployer";
  const rows = attempts.map(e => ({ event: e, code: label(e), text: e.detail, stamp: "Denied" }));
  if (revoked) rows.push({ event: revoked, code: "revoke branch", text: revoked.detail, stamp: "Void" });
  rows.forEach((row, i) => {
    const b = el("button", "attempt"); b.type = "button";
    const left = el("span"); left.append(el("code", "", row.code), el("small", "", row.text));
    const stamp = el("span", "stamp", row.stamp);
    if (seen && !seen.events.has(row.event.seq)) { stamp.classList.add("thud"); stamp.style.setProperty("--i", String(i)); }
    b.append(left, stamp);
    b.onclick = () => showEvent(row.event);
    response.append(b);
  });
  box.replaceChildren(quote, response);
  if (fresh && seen) { box.classList.remove("reveal"); void box.offsetWidth; box.classList.add("reveal"); }
}

/* ---------- Passport ---------- */
function checkDigit(text) {
  const weights = [7, 3, 1];
  let sum = 0;
  [...text].forEach((c, i) => { const v = /\d/.test(c) ? +c : /[A-Z]/.test(c) ? c.charCodeAt(0) - 55 : 0; sum += v * weights[i % 3]; });
  return String(sum % 10);
}
function mrz(g) {
  const name = g.subject.toUpperCase().replace(/[^A-Z0-9]+/g, "<");
  const line1 = `PA<LCL${name}<<AGENT<DEPTH<${g.depth}`.padEnd(44, "<").slice(0, 44);
  const number = g.id.replace(/^g_/, "").toUpperCase().slice(0, 9).padEnd(9, "<");
  const d = new Date(g.expires * 1000);
  const yymmdd = [d.getUTCFullYear() % 100, d.getUTCMonth() + 1, d.getUTCDate()].map(n => String(n).padStart(2, "0")).join("");
  const scope = g.scopes.map(s => s.action.replace(/\./g, "")).join("<").toUpperCase();
  let line2 = `${number}${checkDigit(number)}LCL${yymmdd}${checkDigit(yymmdd)}${scope}`.padEnd(43, "<").slice(0, 43);
  line2 += checkDigit(line2);
  return `${line1}\n${line2}`;
}

function field(label, value, cls = "") {
  const f = el("div", `pp-field ${cls}`.trim());
  f.append(el("span", "", label));
  if (value instanceof Node) f.append(value); else f.append(el("strong", "", value));
  return f;
}

function renderInspector(flip = false) {
  const g = grantById(selected) || state.grants[0]; selected = g.id;
  const panel = $("inspector");
  const wasVoid = seen?.states.get(g.id) === "active" && g.state !== "active";
  const page = el("article", `passport${g.state !== "active" ? " void" : ""}${flip ? " flip" : ""}${wasVoid ? " just-voided" : ""}`);
  page.setAttribute("aria-label", `Passport for ${g.subject}`);
  const bg = svg("svg", { class: "passport-guilloche", viewBox: "0 0 420 520", preserveAspectRatio: "none", "aria-hidden": "true" });
  passportWaves.forEach(d => bg.append(svg("path", { d })));
  page.append(bg);

  const head = el("div", "pp-head");
  head.append(el("strong", "", "Agent passport"), el("span", "", g.parent ? `Delegated, depth ${g.depth}` : "Root authority"));

  const photo = el("div", "pp-photo");
  const ps = svg("svg", { viewBox: "-80 -80 160 160", "aria-hidden": "true" }); ps.append(svg("path", { d: photoRosette })); photo.append(ps);
  photo.append(el("b", "", abbreviate(g.subject)));

  const parent = grantById(g.parent);
  const expiry = new Date(g.expires * 1000);
  const fields = el("div", "pp-fields");
  fields.append(
    field("Holder", g.subject, "full"),
    field("Passport no.", el("code", "", g.id), "full"),
    field("Issued by", parent?.subject || "Local operator"),
    field("Owner", state.owner ? `${state.owner.display_name}${state.owner.active ? "" : " (deprovisioned)"}` : "None: issued before owners", "full"),
    field("Expires", expiry.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })),
    field("Budget", `Shared pool, ${state.run.budget} units`, "full"),
    field("Holder key", g.cnf ? el("code", "", `${g.cnf.slice(0, 12)}…`) : "None: bearer passport", "full"),
  );
  const body = el("div", "pp-body"); body.append(photo, fields);

  const visas = el("div", "pp-visas");
  visas.append(el("span", "", g.scopes.length === 1 ? "Permitted operation" : "Permitted operations"));
  for (const s of g.scopes) { const v = el("div", "visa"); v.append(el("b", "", s.action), el("span", "", s.resource)); visas.append(v); }

  const zone = el("div", "mrz", mrz(g)); zone.setAttribute("aria-hidden", "true");
  page.append(head, body, visas, zone);

  if (g.state === "active") {
    const seal = el("div", "seal"); seal.append(el("span", "", g.parent ? "Chain valid" : "Root valid")); seal.setAttribute("aria-hidden", "true"); page.append(seal);
  } else {
    const stamp = el("div", `big-stamp${g.state === "expired" ? " expired" : ""}`);
    stamp.append(document.createTextNode(g.state === "expired" ? "EXPIRED" : "VOID"), el("small", "", g.state === "deprovisioned" ? "Owner deprovisioned" : g.directly_revoked ? "Branch revoked" : g.state === "revoked" ? "Ancestor revoked" : "Past expiry"));
    page.append(stamp);
    if (g.state === "revoked" || g.state === "deprovisioned") { const punch = el("div", "punch"); punch.setAttribute("aria-hidden", "true"); for (let i = 0; i < 6; i++) punch.append(el("i")); page.append(punch); }
  }

  const chain = el("div", "ancestry");
  chain.append(el("h3", "", "Chain checked on every request"));
  const list = el("ol");
  const lineage = []; for (let node = g; node; node = grantById(node.parent)) lineage.unshift(node);
  const operator = el("li", state.owner && state.owner.active === false ? "deprovisioned" : "operator");
  operator.append(el("span", "dot"), el("span", "", state.owner ? `Owner: ${state.owner.display_name}` : "Local operator"));
  if (state.owner && !state.owner.active) operator.append(el("small", "", "deprovisioned"));
  list.append(operator);
  for (const node of lineage) {
    const li = el("li", node.directly_revoked ? "cut" : node.state);
    if (node.id === g.id) li.classList.add("self");
    li.append(el("span", "dot"), el("span", "", node.subject), el("small", "", node.directly_revoked ? "revoked here" : node.state === "active" ? "valid" : node.state));
    list.append(li);
  }
  chain.append(list);

  const actions = el("div", "inspector-actions");
  const denials = denialsFor(g.id).length;
  let note;
  if (!g.parent) note = "The root passport holds the run's whole budget. Every delegation below it can only narrow its permissions.";
  else if (g.state === "active") note = "Revoking this passport voids it and every descendant. Unrelated branches keep their authority.";
  else if (g.state === "deprovisioned") note = "Its owner was deprovisioned. Every passport issued on their behalf is void, and reactivating the owner does not restore it.";
  else note = `This passport can no longer reserve budget or dispatch work.${denials ? ` The gateway has denied ${denials} of its requests.` : ""}`;
  actions.append(el("p", "inspector-note", note));
  if (g.parent) {
    const revoke = el("button", "revoke", g.state === "active" ? "Revoke this branch" : "Branch revoked"); revoke.type = "button";
    revoke.disabled = g.state !== "active" || busy;
    revoke.onclick = () => action(`/api/grants/${encodeURIComponent(g.id)}/revoke`);
    actions.append(revoke);
  }
  panel.replaceChildren(page, chain, actions);
}

/* ---------- Budget ---------- */
function renderBudget() {
  const run = state.run;
  $("spent").textContent = run.spent;
  $("budget-limit").textContent = run.budget;
  const free = available();
  $("budget-description").textContent = `${free} available${run.reserved ? `, ${run.reserved} reserved` : ""}. Every descendant draws from this one pool.`;
  const spenders = state.events.filter(e => e.kind === "completed").map(e => grantById(e.grant_id));
  const track = $("budget-track"); track.replaceChildren();
  let fresh = 0;
  for (let i = 0; i < run.budget; i++) {
    const slot = el("span", "slot");
    if (i < run.spent) {
      const who = spenders[i];
      slot.classList.add("used");
      slot.style.setProperty("--slot", branchColor(who));
      slot.textContent = who ? abbreviate(who.subject) : "";
      slot.title = who ? `Unit ${i + 1}: ${who.subject}` : `Unit ${i + 1}: used`;
      if (seen && i >= seen.spent) { slot.classList.add("fresh"); slot.style.setProperty("--i", String(fresh++)); }
    } else if (i < run.spent + run.reserved) { slot.classList.add("reserved"); slot.title = `Unit ${i + 1}: reserved`; }
    else slot.title = `Unit ${i + 1}: available`;
    track.append(slot);
  }
  track.setAttribute("role", "meter"); track.setAttribute("aria-label", "Shared operation units used or reserved");
  track.setAttribute("aria-valuemin", "0"); track.setAttribute("aria-valuemax", String(run.budget)); track.setAttribute("aria-valuenow", String(run.spent + run.reserved));
  const counts = new Map();
  spenders.forEach(g => { if (!g) return; const key = isFork(g) ? "Forked workers" : g.subject; const c = counts.get(key) || { n: 0, color: branchColor(g) }; c.n++; counts.set(key, c); });
  const key = $("budget-key"); key.replaceChildren();
  if (!counts.size) key.append(el("span", "", "No units spent yet."));
  for (const [name, c] of counts) { const s = el("span"); const i = el("i"); i.style.setProperty("--slot", c.color); s.append(i, document.createTextNode(`${name}, ${c.n}`)); key.append(s); }
}

/* ---------- Fork race ---------- */
function renderRace() {
  const fork = state.metrics.fork;
  $("race").hidden = !fork;
  if (!fork) return;
  $("race-available").textContent = fork.available_before;
  $("race-summary").textContent = `Each worker requested one unit at the same moment. ${fork.completed} were admitted and ${fork.denied} were denied by the shared pool. Measured locally in ${Math.round(fork.elapsed_ms)} ms; a local timing, not a distributed guarantee.`;
  const forks = state.grants.filter(isFork);
  const outcomes = state.events.filter(e => (e.kind === "completed" || e.kind === "denied") && forks.some(f => f.id === e.grant_id));
  const board = $("race-board"); board.replaceChildren();
  outcomes.forEach((e, i) => {
    const g = grantById(e.grant_id);
    const tile = el("span", `racer ${e.kind}`, g.subject.slice(5));
    tile.title = `${g.subject}: ${e.kind === "completed" ? "admitted" : "denied, budget exhausted"}`;
    tile.style.setProperty("--i", String(i));
    board.append(tile);
  });
  board.classList.toggle("reveal", Boolean(seen && !seen.fork));
  const stats = $("race-stats"); stats.replaceChildren();
  [["Workers", fork.workers, ""], ["Admitted", fork.completed, "ok"], ["Denied", fork.denied, "no"], ["Total spend", `${fork.spent_after}/${fork.budget}`, ""]].forEach(([t, v, c]) => {
    const d = el("div"); d.append(el("dt", "", t), el("dd", c, String(v))); stats.append(d);
  });
}

/* ---------- Ledger ---------- */
const KIND_LABEL = { issued: "Issued", delegated: "Delegated", reserved: "Reserved", completed: "Allowed", denied: "Denied", revoked: "Revoked", injected: "Untrusted input", unknown: "Outcome unknown", reconciled: "Reconciled",
  awaiting_approval: "Awaiting approval", approved: "Approved", approval_denied: "Approval denied", approval_lapsed: "Approval lapsed", deprovisioned: "Owner deprovisioned", reactivated: "Owner reactivated" };
function renderEvents() {
  const container = $("events"); container.replaceChildren();
  const wanted = e => filter === "all" || (filter === "denied" ? e.kind === "denied" : ["denied", "revoked", "injected", "awaiting_approval", "approved", "approval_denied", "deprovisioned"].includes(e.kind));
  const events = state.events.filter(wanted).slice().reverse();
  if (!events.length) container.append(el("p", "empty", filter === "all" ? "No decisions yet. Start the investigation to issue passports." : "Nothing denied yet. Inject the malicious output to test the boundary."));
  for (const e of events) {
    const row = el("button", "event-row"); row.type = "button";
    if (e.kind === "injected") row.classList.add("highlight");
    const name = grantById(e.grant_id)?.subject || "Gateway";
    const main = el("span", "event-main"); main.append(el("strong", "", name), el("small", "", e.detail));
    const time = el("span", "event-time", relTime(e.time)); time.title = new Date(e.time * 1000).toLocaleString();
    row.append(time, el("span", `event-kind ${e.kind}`), main, el("span", `tag ${e.kind}`, KIND_LABEL[e.kind] || e.kind));
    row.onclick = () => showEvent(e);
    container.append(row);
  }
}

function showEvent(e) {
  $("dialog-title").textContent = `Decision record #${e.seq}`;
  const g = grantById(e.grant_id);
  const record = el("dl", "record");
  const rows = [["Decision", KIND_LABEL[e.kind] || e.kind], ["Rule", e.rule], ["Agent", g ? `${g.subject} (${g.id})` : e.grant_id || "Gateway"]];
  if (e.action) rows.push(["Requested", `${e.action} on ${e.resource}`]);
  if (e.operation_id) rows.push(["Operation", e.operation_id]);
  rows.push(["Recorded", new Date(e.time * 1000).toISOString()]);
  rows.forEach(([k, v]) => record.append(el("dt", "", k), el("dd", "", v)));
  const chain = el("div", "chain");
  chain.append(el("span", "", `prev ${e.previous.slice(0, 16)}…`), el("span", "", "→"), el("b", "", `hash ${e.hash.slice(0, 16)}…`));
  chain.title = "Each record commits to the previous record's hash. The chain is local and unanchored, so it cannot prove completeness.";
  const raw = el("details"); raw.append(el("summary", "", "Raw record"), el("pre", "", JSON.stringify(e, null, 2)));
  $("event-detail").replaceChildren(el("h3", "", humanRule(e.rule)), el("p", "", e.detail), record, chain, raw);
  $("event-dialog").showModal();
}

/* ---------- Approvals ---------- */
let approvals = [], approvalsShown = null;
const seconds = s => s >= 90 ? `${Math.round(s / 60)} min` : `${Math.max(0, Math.round(s))} s`;
async function loadApprovals() {
  if (!session) return;
  try { approvals = (await api("/api/approvals")).approvals; renderApprovals(); }
  catch { /* Keep the last list; explicit decisions report failures. */ }
}
function approvalMeta(a) {
  return a.state === "approved" ? `Approved. Runs once when the agent retries; lapses in ${seconds(a.lapses_in)}.`
    : `Waiting ${seconds(a.age_seconds)}. One unit held. Lapses undecided in ${seconds(a.lapses_in)}.`;
}
function renderApprovals() {
  const scripted = approvals.some(a => a.subject === "Config worker");
  $("request-config").textContent = scripted ? "Retry as the config worker" : "Script a config change request";
  $("request-config").disabled = busy || !state;
  const list = $("approval-list");
  const signature = approvals.map(a => `${a.id}:${a.state}`).join(",");
  if (signature === approvalsShown) {
    // Same requests: refresh timers only, so a reason being typed is not lost.
    approvals.forEach(a => { const meta = list.querySelector(`[data-op="${a.id}"] .approval-meta`); if (meta) meta.textContent = approvalMeta(a); });
    return;
  }
  approvalsShown = signature;
  list.replaceChildren();
  if (!approvals.length) { list.append(el("p", "empty", "Nothing is waiting. A config write from the live agent or the scripted worker appears here.")); return; }
  for (const a of approvals) {
    const card = el("article", `approval ${a.state}`); card.dataset.op = a.id;
    const head = el("div", "approval-head");
    const what = el("span"); what.append(el("strong", "", a.subject), document.createTextNode(` asks for ${a.action} on ${a.resource}`));
    head.append(what, el("code", "", a.id.slice(0, 15) + "…"));
    head.lastChild.title = a.id;
    card.append(head, el("p", "approval-meta", approvalMeta(a)));
    if (a.state === "awaiting_approval") {
      const form = el("form", "approval-form");
      const reason = el("input"); reason.name = "reason"; reason.required = true; reason.minLength = 10; reason.maxLength = 500;
      reason.placeholder = "Reason, 10 to 500 characters"; reason.setAttribute("aria-label", `Reason for the decision on ${a.id}`);
      const approve = el("button", "primary small", "Approve"); approve.type = "submit"; approve.value = "approve";
      const deny = el("button", "ghost", "Deny"); deny.type = "submit"; deny.value = "deny";
      form.append(reason, approve, deny);
      form.onsubmit = event => { event.preventDefault(); decide(a.id, event.submitter?.value || "approve", reason.value); };
      card.append(form);
    } else {
      card.append(el("p", "approval-note", "The approval is signed and bound to this exact operation. A revoked branch still cannot run it."));
    }
    list.append(card);
  }
}
async function decide(oid, decision, reason) {
  if (busy) return;
  if (reason.trim().length < 10) { showError("Record a reason of at least 10 characters for the decision."); return; }
  busy = true; $("error").hidden = true; renderControls();
  try {
    await api(`/api/approvals/${encodeURIComponent(oid)}`, "POST", { decision, reason });
    state = await api("/api/state"); render();
  } catch (error) { showError(error.message); }
  finally { busy = false; renderControls(); approvalsShown = null; await loadApprovals(); }
}

/* ---------- Owners ---------- */
function renderOwners() {
  const list = $("owner-list"); list.replaceChildren();
  for (const o of state.owners || []) {
    const li = el("li", o.active ? "" : "inactive");
    const who = el("span"); who.append(el("strong", "", o.display_name), el("small", "", `${o.user_name} · ${o.runs} run${o.runs === 1 ? "" : "s"}${o.id === state.owner?.id ? " · owns this run" : ""}`));
    const button = el("button", "revoke", o.active ? "Deactivate" : "Deprovisioned"); button.type = "button";
    button.disabled = busy || !o.active;
    button.title = o.active ? "Deprovision this owner. Every grant issued for them stops working." : "Reactivate with scripts/owners.py; old grants stay void.";
    button.onclick = () => action(`/api/owners/${encodeURIComponent(o.id)}/deactivate`);
    li.append(who, el("span", `tag ${o.active ? "active" : "inactive"}`, o.active ? "Active" : "Inactive"), button);
    list.append(li);
  }
}

/* ---------- Render ---------- */
const FOCUS_BY_STAGE = { 1: "Log reader", 2: "Log reader", 3: "Log reader", 4: "Patch worker" };
function renderLive() {
  const g = state.live_grant && grantById(state.live_grant);
  const button = $("issue-live");
  const free = available();
  button.disabled = busy || (g && g.state === "active") || free < 1;
  button.title = free < 1 ? "The shared budget is spent. Reset to give the live agent units to work with." : "";
  const status = $("live-status");
  if (!g) { status.textContent = free < 1 ? "The shared budget is spent. Reset first so the live agent has units to work with." : `The live agent will share the ${free} units left in this run's pool.`; return; }
  const events = state.events.filter(e => e.grant_id === g.id || state.grants.some(w => w.id === e.grant_id && w.parent === g.id));
  const done = events.filter(e => e.kind === "completed").length, denied = events.filter(e => e.kind === "denied").length;
  const workers = state.grants.filter(w => w.parent === g.id).length;
  status.textContent = g.state !== "active" ? `Claude (live) is void. Its next call will be denied. ${done} completed and ${denied} denied before revocation.`
    : !events.length ? "Passport issued to Claude (live). Waiting for its first tool call."
    : `Claude (live): ${done} completed, ${denied} denied${workers ? `, ${workers} worker${workers === 1 ? "" : "s"} delegated` : ""}.`;
}

function render() {
  if (seen && seen.run !== state.run.id) seen = null;
  if (pendingFocus) {
    const live = state.live_grant && stage() === 0 ? grantById(state.live_grant) : null;
    const focus = live || state.grants.find(g => g.subject === FOCUS_BY_STAGE[stage()]);
    if (focus && stage() !== seen?.stage) selected = focus.id;
  }
  if (!state.grants.some(g => g.id === selected)) selected = state.grants[0].id;
  const s = stage(), copy = STEP_COPY[s];
  $("run-id").textContent = state.run.id;
  $("provider").textContent = state.credential_mode === "synthetic" ? "Synthetic credentials" : "1Password CLI, fixture service";
  $("step-label").textContent = copy.label;
  $("step-label").classList.toggle("alert", Boolean(copy.alert));
  $("narrative").textContent = state.message;
  $("hint").textContent = copy.hint();
  document.querySelectorAll("#stepper li").forEach(li => {
    const n = +li.dataset.step;
    li.classList.toggle("done", n < s);
    li.classList.toggle("current", n === s);
    if (n === s) li.setAttribute("aria-current", "step"); else li.removeAttribute("aria-current");
  });
  renderGraph(); renderIncident(); renderInspector(pendingFocus && selected !== seen?.selected); renderBudget(); renderRace(); renderLive(); renderOwners(); renderEvents(); renderControls();
  seen = {
    run: state.run.id, stage: s, spent: state.run.spent, fork: Boolean(state.metrics.fork), selected,
    grants: new Set(state.grants.map(g => g.id)),
    states: new Map(state.grants.map(g => [g.id, g.state])),
    denials: new Map(state.grants.map(g => [g.id, denialsFor(g.id).length])),
    events: new Set(state.events.map(e => e.seq)),
  };
  pendingFocus = false;
}

async function exportEvidence() {
  try {
    // Preserve the server's UTF-8 bytes and numeric representation for verification.
    const response = await fetch("/api/evidence", { headers: { "X-Passport-Console": session } });
    if (!response.ok) throw new Error("Evidence export failed. Reload the console and try again.");
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = el("a"); link.href = url; link.download = `${state.run.id}-evidence.json`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) { showError(error.message); }
}

$("step").onclick = primary;
$("reset").onclick = () => action("/api/demo/reset");
$("export").onclick = exportEvidence;
$("request-config").onclick = () => action("/api/demo/config");
$("issue-live").onclick = async () => { await action("/api/live/issue"); if (state?.live_grant) { selected = state.live_grant; render(); } };
$("close-dialog").onclick = () => $("event-dialog").close();
$("event-dialog").onclick = event => { if (event.target === $("event-dialog")) { const r = event.target.getBoundingClientRect(); if (event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom) event.target.close(); } };
document.querySelectorAll("[data-filter]").forEach(button => button.onclick = () => { filter = button.dataset.filter; document.querySelectorAll("[data-filter]").forEach(b => { b.classList.toggle("selected", b === button); b.setAttribute("aria-pressed", String(b === button)); }); renderEvents(); });
document.addEventListener("keydown", event => {
  if (event.key !== "ArrowRight" || event.altKey || event.ctrlKey || event.metaKey || $("event-dialog").open) return;
  if (event.target.closest?.("input, textarea, select, [contenteditable]")) return;
  event.preventDefault(); if (!$("step").disabled) primary();
});
const director = document.querySelector(".director");
addEventListener("scroll", () => director.classList.toggle("stuck", director.getBoundingClientRect().top <= 0), { passive: true });

drawCover();
(async () => {
  try { session = (await api("/api/session")).console_token; state = await api("/api/state"); pendingFocus = true; render(); loadApprovals(); }
  catch (error) { document.querySelector(".pulse").classList.add("offline"); $("narrative").textContent = "The local gateway is not reachable."; showError(`Gateway unavailable: ${error.message}. Start it with python -m agent_passport.`); }
})();
let polling = false;
setInterval(async () => {
  if (!session || !state || busy || polling || document.hidden) return;
  polling = true;
  try {
    const next = await api("/api/state");
    if (!busy && (next.run.id !== state.run.id || next.events.at(-1)?.seq !== state.events.at(-1)?.seq || next.grants.some((g, i) => g.state !== state.grants[i]?.state))) {
      state = next; render();
    }
    await loadApprovals();
  } catch { /* Keep the last verified state; explicit actions report connection failures. */ }
  finally { polling = false; }
}, 2000);
