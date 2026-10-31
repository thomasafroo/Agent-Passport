"use strict";
let state, session, selected, busy = false, filter = "all";
const $ = id => document.getElementById(id);
const el = (tag, cls, text) => { const node = document.createElement(tag); if (cls) node.className = cls; if (text !== undefined) node.textContent = text; return node; };

async function api(path, method = "GET") {
  const response = await fetch(path, { method, headers: { "X-Passport-Console": session || "" } });
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail || "The gateway could not complete this request.");
  return body;
}

async function action(path) {
  if (busy) return;
  busy = true; $("error").hidden = true; renderControls();
  try { state = await api(path, "POST"); render(); }
  catch (error) { $("error").textContent = error.message; $("error").hidden = false; }
  finally { busy = false; renderControls(); if (state) renderInspector(); }
}

function renderControls() {
  const phase = state?.phase || "ready";
  const labels = { ready: "Start investigation", delegated: "Inject malicious output", attacked: "Contain branch", contained: "Complete investigation", finished: "Investigation complete" };
  $("step").replaceChildren(document.createTextNode(labels[phase]), el("span", "", "→"));
  $("step").disabled = busy || !state || phase === "finished";
  $("fork").disabled = busy || !state || phase !== "finished" || Boolean(state.metrics.fork);
  $("fork").title = phase !== "finished" ? "Complete the incident story before the concurrent fork test." : "Race 32 workers against the remaining shared budget.";
  $("reset").disabled = busy;
  $("export").disabled = busy || !state;
}

function renderGraph() {
  const graph = $("graph"); graph.replaceChildren();
  const byParent = new Map();
  for (const grant of state.grants) { const key = grant.parent || "root"; if (!byParent.has(key)) byParent.set(key, []); byParent.get(key).push(grant); }
  function branch(grant) {
    const wrapper = el("div", "tree-branch");
    const button = el("button", `node ${grant.state}${selected === grant.id ? " selected" : ""}`);
    button.setAttribute("aria-label", `${grant.subject}, ${grant.state}. Inspect passport`);
    button.setAttribute("aria-pressed", String(selected === grant.id));
    const title = el("span", "node-title"); title.append(el("span", "status-dot"), document.createTextNode(grant.subject));
    button.append(title, el("span", "node-sub", grant.state === "active" ? grant.scopes.length > 1 ? "3 exact permissions" : grant.scopes[0].action : `${grant.state} · access denied`), el("span", "node-id", grant.id));
    button.onclick = () => { selected = grant.id; renderGraph(); renderInspector(); };
    wrapper.append(button);
    const children = byParent.get(grant.id) || [];
    const forks = children.filter(g => g.subject.startsWith("Fork "));
    const regular = children.filter(g => !g.subject.startsWith("Fork "));
    if (regular.length) { const list = el("div", "tree-children"); regular.forEach(g => list.append(branch(g))); wrapper.append(list); }
    if (forks.length) { const cluster = el("button", "fork-cluster", `+ ${forks.length} forked workers ↗`); cluster.onclick = () => { showForks(forks); }; wrapper.append(cluster); }
    return wrapper;
  }
  (byParent.get("root") || []).forEach(g => graph.append(branch(g)));
  $("agent-count").textContent = `${state.grants.length} passport${state.grants.length === 1 ? "" : "s"} issued`;
}

function showForks(forks) {
  const detail = $("event-detail"); detail.replaceChildren(el("h2", "", `${forks.length} workers. One shared pool.`), el("p", "", "Select a worker to inspect its signed passport and inherited permissions."));
  for (const grant of forks) { const button = el("button", "event-row", `${grant.subject} · ${grant.state}`); button.onclick = () => { selected = grant.id; $("event-dialog").close(); renderGraph(); renderInspector(); }; detail.append(button); }
  $("event-dialog").showModal();
}

function renderInspector() {
  const g = state.grants.find(g => g.id === selected) || state.grants[0]; selected = g.id;
  const panel = $("inspector"); panel.replaceChildren(el("div", "passport-avatar", g.subject.split(" ").map(x => x[0]).slice(0,2).join("")), el("h2", "", g.subject), el("span", "passport-id", g.id), el("span", `state-badge ${g.state}`, g.state === "active" ? "● Verified / active" : `● ${g.state}`));
  const scope = el("div", "inspector-field"); scope.append(el("span", "", "PERMITTED OPERATIONS"));
  for (const s of g.scopes) { const line = el("code", "scope"); line.append(el("b", "", s.action), document.createTextNode(` · ${s.resource}`)); scope.append(line); }
  const parent = state.grants.find(x => x.id === g.parent);
  const fields = [["AUTHORIZED BY", parent?.subject || "Local operator"], ["EXPIRY", new Date(g.expires * 1000).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit", second:"2-digit"})], ["BUDGET AUTHORITY", "Shared root pool · 24 units"]];
  panel.append(scope);
  for (const [label, value] of fields) { const field = el("div", "inspector-field"); field.append(el("span", "", label), el("strong", "", value)); panel.append(field); }
  if (g.parent) { const revoke = el("button", "revoke-button", g.state === "active" ? "Revoke this branch" : "Branch has no authority"); revoke.disabled = g.state !== "active" || busy; revoke.onclick = () => action(`/api/grants/${encodeURIComponent(g.id)}/revoke`); panel.append(revoke); }
}

function renderEvents() {
  const container = $("events"); container.replaceChildren();
  const events = state.events.filter(e => filter === "all" || e.kind === "denied").slice().reverse();
  if (!events.length) container.append(el("div", "empty-state", "No denied requests. Start the incident to test a boundary."));
  for (const event of events) {
    const row = el("button", "event-row");
    const name = state.grants.find(g => g.id === event.grant_id)?.subject || "Gateway";
    const main = el("span", "event-main"); main.append(el("strong", "", name), el("small", "", event.rule));
    row.append(el("span", "event-time", new Date(event.time * 1000).toLocaleTimeString([], {hour12:false})), main, el("span", `result-tag ${event.kind}`, event.kind === "completed" ? "allowed ↗" : event.kind));
    row.onclick = () => { const detail = $("event-detail"); detail.replaceChildren(el("h2", "", event.rule), el("p", "", event.detail), el("pre", "", JSON.stringify(event, null, 2))); $("event-dialog").showModal(); };
    container.append(row);
  }
}

function render() {
  if (!state.grants.some(g => g.id === selected)) selected = state.grants[0].id;
  $("run-id").textContent = state.run.id;
  $("provider").textContent = state.credential_mode === "synthetic" ? "SYNTHETIC CREDENTIALS" : "1PASSWORD CLI · FIXTURE SERVICE";
  $("spent").textContent = state.run.spent;
  $("budget-description").textContent = `${state.run.budget - state.run.spent - state.run.reserved} available · ${state.run.reserved} reserved`;
  const track = $("budget-track"); track.replaceChildren();
  for (let i = 0; i < state.run.budget; i++) track.append(el("i", i < state.run.spent ? "used" : i < state.run.spent + state.run.reserved ? "reserved" : ""));
  track.setAttribute("role", "meter"); track.setAttribute("aria-label", "Shared operation units used or reserved"); track.setAttribute("aria-valuemin", "0"); track.setAttribute("aria-valuemax", String(state.run.budget)); track.setAttribute("aria-valuenow", String(state.run.spent + state.run.reserved));
  $("narrative").textContent = state.message;
  $("step-label").textContent = {ready:"READY TO INVESTIGATE",delegated:"01 / AUTHORITY DELEGATED",attacked:"02 / ATTACK BLOCKED",contained:"03 / BRANCH CONTAINED",finished:"04 / INVESTIGATION COMPLETE"}[state.phase];
  const fork = state.metrics.fork; $("fork-result").hidden = !fork;
  if (fork) $("fork-result").textContent = `${fork.workers} concurrent workers → ${fork.completed} completed / ${fork.denied} budget denials. Total spent: ${fork.spent_after}/${fork.budget}. Measured run: ${fork.elapsed_ms} ms.`;
  renderGraph(); renderInspector(); renderEvents(); renderControls();
}

$("step").onclick = () => action("/api/demo/step");
$("reset").onclick = () => action("/api/demo/reset");
$("fork").onclick = () => action("/api/demo/fork");
$("close-dialog").onclick = () => $("event-dialog").close();
$("event-dialog").onclick = event => { if (event.target === $("event-dialog")) { const r = event.target.getBoundingClientRect(); if (event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom) event.target.close(); } };
document.querySelectorAll("[data-filter]").forEach(button => button.onclick = () => { filter = button.dataset.filter; document.querySelectorAll("[data-filter]").forEach(b => { b.classList.toggle("selected", b === button); b.setAttribute("aria-pressed", String(b === button)); }); renderEvents(); });
$("export").onclick = async () => {
  try {
    // Preserve the server's UTF-8 bytes and numeric representation for verification.
    const response = await fetch("/api/evidence", {headers:{"X-Passport-Console":session}});
    if (!response.ok) throw new Error("Evidence export failed. Reload the console and try again.");
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = el("a"); link.href = url; link.download = `${state.run.id}-evidence.json`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) { $("error").textContent = error.message; $("error").hidden = false; }
};
(async () => { try { session = (await api("/api/session")).console_token; state = await api("/api/state"); render(); } catch (error) { $("error").textContent = `Gateway unavailable: ${error.message}. Start it with python -m agent_passport.`; $("error").hidden = false; } })();
let polling = false;
setInterval(async () => {
  if (!session || !state || busy || polling || document.hidden) return;
  polling = true;
  try {
    const next = await api("/api/state");
    if (!busy && (next.run.id !== state.run.id || next.events.at(-1)?.seq !== state.events.at(-1)?.seq || next.grants.some((g, i) => g.state !== state.grants[i]?.state))) {
      state = next; render();
    }
  } catch { /* Keep the last verified state; explicit actions report connection failures. */ }
  finally { polling = false; }
}, 2000);
