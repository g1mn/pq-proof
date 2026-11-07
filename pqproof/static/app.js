// PQ-Proof run viewer: plain JavaScript, no build step, nothing from another origin.
// Every value from a receipt goes into the page as text (textContent), never as HTML.
"use strict";

(function () {
  const $ = (id) => document.getElementById(id);
  const root = document.documentElement;
  const params = new URLSearchParams(location.search);

  // theme: dark by default; ?theme=light or a saved choice (saved only when the button is pressed)
  function setTheme(t) { root.setAttribute("data-theme", t); $("theme").textContent = t === "dark" ? "Light" : "Dark"; }
  let theme = "dark";
  try { theme = localStorage.getItem("pqproof-theme") || "dark"; } catch (e) { /* storage blocked */ }
  if (params.get("theme") === "light" || params.get("theme") === "dark") theme = params.get("theme");
  setTheme(theme);
  $("theme").addEventListener("click", () => {
    const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    setTheme(next);
    try { localStorage.setItem("pqproof-theme", next); } catch (e) { /* storage blocked */ }
  });

  function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") e.className = v; else if (k === "style") Object.assign(e.style, v); else e.setAttribute(k, v);
    }
    for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) e.append(c instanceof Node ? c : String(c));
    return e;
  }
  const t = (iso) => Date.parse(iso);
  const secs = (a, b) => ((t(b) - t(a)) / 1000).toFixed(1) + " s";
  const short = (h, n = 12) => (h ? String(h).slice(0, n) : "");
  const hash = (h) => el("span", { class: "hash", title: h || "" }, h || "none");
  const yes = (ok) => el("span", { class: ok ? "ok" : "bad" }, ok ? "yes" : "no");
  function table(head, rows, wide) {
    const tb = el("tbody");
    for (const r of rows) tb.append(r.tagName === "TR" ? r : el("tr", null, r.map((c) => el("td", null, c))));
    if (!rows.length) tb.append(el("tr", null, el("td", { colspan: String(head.length), class: "muted" }, "none")));
    return el("div", { class: "wrap" }, el("table", { class: wide ? "wide" : null }, el("thead", null, el("tr", null, head.map((h) => el("th", null, h)))), tb));
  }
  function fill(id, ...nodes) { const n = $(id); n.replaceChildren(...nodes.flat()); }

  async function getJSON(url) {
    const r = await fetch(url, { headers: { Accept: "application/json" } });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.error || r.status + " " + r.statusText);
    return body;
  }

  // a receipt whose hashes or counts do not check out: its content is shown, but never as a result
  const distrust = () => el("div", { class: "distrust", role: "alert" },
    el("b", null, "UNVERIFIED: "), "this receipt fails its hash check, so nothing in it can be trusted (see Hashed receipt below).");

  function summary(d) {
    const r = d.receipt, m = r.model, v = d.verification;
    fill("summary",
      v.ok ? null : distrust(),
      el("div", { class: "headline" },
        el("span", { class: "badge " + (v.ok ? r.verdict : "unverified") }, v.ok ? r.verdict.toUpperCase() : "UNVERIFIED"),
        el("span", null, !v.ok ? `the receipt says ${r.verdict}, but its hashes do not match` :
          r.verdict === "pass" ? "hybrid key exchange proved, classical clients still connect" : "migration not proved")),
      el("div", { class: "facts" },
        el("div", null, el("div", { class: "k" }, "Repository"), el("code", null, r.repo.url || "no public URL"),
          el("div", { class: "muted" }, "cloned from ", el("code", null, r.repo.path))),
        el("div", null, el("div", { class: "k" }, "Commit, tree"), el("span", { class: "hash" }, r.repo.commit),
          el("br"), el("span", { class: "hash" }, r.repo.tree)),
        el("div", null, el("div", { class: "k" }, "Started (UTC)"), el("span", { class: "nowrap" }, r.started_at)),
        el("div", null, el("div", { class: "k" }, "Duration"), el("span", { class: "nowrap" }, secs(r.started_at, r.finished_at))),
        el("div", null, el("div", { class: "k" }, "Model"), m.provider + (m.models.length ? " " + m.models.join(", ") : "")
          + (m.tokens ? ` (${m.requests_sent} requests, $${m.cost_usd})` : "")),
        el("div", null, el("div", { class: "k" }, "Receipt hashes"),
          el("span", { class: v.ok ? "ok" : "bad" }, v.ok ? `all ${v.checks} checks match` : `${v.failed.length} of ${v.checks} checks failed`))));
  }

  // job timeline: one bar per phase and per microVM; with now (seconds after the start) bars stop there
  function timeline(r, now) {
    const spans = r.timeline.map((p) => ({ label: p.name, a: p.started_at, b: p.ended_at, kind: "phase" }))
      .concat(r.sandboxes.map((s) => ({ label: s.step, a: s.started_at, b: s.destroyed_at || r.finished_at, kind: "vm", id: s.id,
        failed: s.execs.some((e) => e.exit_code !== 0 && !/^tls_probe$/.test(e.argv[0])) })));
    const t0 = Math.min(...spans.map((s) => t(s.a)));
    const t1 = Math.max(...spans.map((s) => t(s.b)), t0 + 1);
    const cut = now === undefined ? t1 : t0 + now * 1000;
    const row = (s) => {
      const end = Math.min(t(s.b), cut), shown = t(s.a) <= cut, done = t(s.b) <= cut;
      return el("div", { class: "tl-row" + (shown ? "" : " pending") },
        el("div", { class: "tl-label", title: s.id || "" }, s.label, s.failed && done ? el("span", { class: "bad" }, " (failed)") : null),
        el("div", { class: "tl-track" }, shown ? el("div", {
          class: "tl-bar" + (s.kind === "vm" ? " vm" : "") + (s.failed && done ? " failed" : "") + (done ? "" : " running"),
          style: { left: ((t(s.a) - t0) / (t1 - t0) * 100).toFixed(2) + "%", width: Math.max((end - t(s.a)) / (t1 - t0) * 100, 0.3).toFixed(2) + "%" },
        }) : null),
        el("div", { class: "tl-dur" }, shown ? ((end - t(s.a)) / 1000).toFixed(1) + " s" : ""));
    };
    fill("timeline",
      el("div", { class: "tl-group" }, "Control plane phases"), spans.filter((s) => s.kind === "phase").map(row),
      el("div", { class: "tl-group" }, "MicroVMs (one per step, each destroyed afterwards)"), spans.filter((s) => s.kind === "vm").map(row),
      el("div", { class: "legend" },
        el("span", null, el("i", { style: { background: "var(--phase)" } }), "phase"),
        el("span", null, el("i", { style: { background: "var(--vm)" } }), "microVM"),
        el("span", null, el("i", { class: "failed-swatch" }), "microVM where a build or check failed (striped, marked failed)"),
        el("span", null, `0 s = ${r.started_at}, total ${((t1 - t0) / 1000).toFixed(1)} s`)));
  }

  // replay: the recorded events (GET /api/runs/ID/replay, built from the receipt) played back faster
  const player = { timer: null, now: 0, shown: 0, events: [], duration: 0, speed: 1, r: null };
  const kindClass = { exfil: "ev-alarm", refused: "ev-alarm", "vm-failed": "ev-bad", verdict: "ev-verdict" };
  function feedItem(e) {
    const cls = kindClass[e.kind] || (e.kind === "proof" || e.kind === "attempt" ? (e.ok ? "ev-ok" : "ev-bad") : null);
    return el("li", { class: cls }, el("span", { class: "ev-t nowrap" }, "+" + e.t.toFixed(1) + " s"), el("span", null, e.text));
  }
  function draw() {
    const p = player, feed = $("rp-feed");
    while (p.shown < p.events.length && p.events[p.shown].t <= p.now) feed.append(feedItem(p.events[p.shown++]));
    timeline(p.r, p.now);
    $("rp-clock").textContent = Math.min(p.now, p.duration).toFixed(1) + " s / " + p.duration.toFixed(1) + " s";
    $("rp-bar").style.width = (p.duration ? Math.min(p.now / p.duration, 1) * 100 : 100).toFixed(1) + "%";
    $("rp-play").textContent = p.timer ? "Pause" : p.now >= p.duration ? "Replay" : "Play";
  }
  function stop() { if (player.timer) { clearInterval(player.timer); player.timer = null; } }
  function play() {
    stop();
    if (player.now >= player.duration) { player.now = 0; player.shown = 0; $("rp-feed").replaceChildren(); }
    let last = performance.now();
    player.timer = setInterval(() => {
      const tick = performance.now();
      player.now += (tick - last) / 1000 * player.speed;
      last = tick;
      if (player.now >= player.duration) { player.now = player.duration; stop(); }
      draw();
    }, 100);
    draw();
  }
  function toEnd() { stop(); player.now = player.duration; draw(); }
  $("rp-play").addEventListener("click", () => { if (player.timer) { stop(); draw(); } else play(); });
  $("rp-restart").addEventListener("click", () => { player.now = player.duration; play(); });
  $("rp-end").addEventListener("click", toEnd);

  async function replay(d) {
    stop();
    const rp = await getJSON("/api/runs/" + encodeURIComponent(d.id) + "/replay");
    Object.assign(player, { r: d.receipt, events: rp.events, duration: rp.duration_s, now: 0, shown: 0,
      speed: Math.max(1, Math.round(rp.duration_s / 25)) });
    $("rp-feed").replaceChildren();
    $("rp-note").textContent = player.speed + "x speed; nothing runs again: these are the receipt's own times and results";
    const still = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (still) toEnd(); else play();
  }

  function containment(r) {
    const c = r.containment;
    const caught = [];
    for (const s of r.sandboxes) for (const ev of s.egress.reached_sinkhole) {
      if (!ev.canaries.length) continue;
      caught.push(el("div", { class: "alarm" },
        el("b", null, "EXFIL CAUGHT: " + ev.canaries.join(", ")),
        ` sent to ${ev.dest} (${ev.kind}, ${ev.bytes} bytes) during ${s.step}; it stopped at the sinkhole.`,
        el("pre", null, ev.preview)));
    }
    const weak = r.attempts.filter((a) => a.tls_weakening.length);
    fill("containment",
      caught.length ? caught : el("p", { class: "muted" }, "No canary reached the sinkhole in this run."),
      weak.map((a) => el("div", { class: "alarm" }, el("b", null, `Patch refused (attempt ${a.number}): it weakens TLS`),
        el("ul", { class: "policy" }, a.tls_weakening.map((w) => el("li", null, w))))),
      el("div", { class: "counts" },
        el("div", null, el("div", { class: "n" }, String(c.reached_sinkhole)), el("div", { class: "muted" }, "egress attempts reached the sinkhole (recorded)")),
        el("div", null, el("div", { class: "n" }, String(c.reached_sinkhole_not_kept)), el("div", { class: "muted" }, "more reached it over its caps (counted, not kept)")),
        el("div", null, el("div", { class: "n" }, c.dropped_by_policy), el("div", { class: "muted" }, "dropped by policy: Microsandbox drops them before the sinkhole")),
        el("div", null, el("div", { class: "n" }, String(c.host_build_commands)), el("div", { class: "muted" }, `build commands on the host (${c.guest_build_commands} in microVMs)`)),
        el("div", null, el("div", { class: "n" }, `${c.sandboxes_destroyed} / ${c.sandboxes}`), el("div", { class: "muted" }, "microVMs destroyed")),
        el("div", null, el("div", { class: "n" }, c.canaries_caught.join(", ") || "none"), el("div", { class: "muted" }, "canary ids caught (fake credentials only)"))),
      el("h3", null, "What is blocked"),
      el("ul", { class: "policy" }, c.policy.map((p) => el("li", null, p))),
      el("h3", { style: { marginTop: "12px" } }, "Network flags of each microVM"),
      table(["Step", "msb create flags"], r.sandboxes.map((s) => [s.step, el("code", null, s.network.join(" "))]), true));
  }

  function cbom(id, rows, file, sha, base, ok) {
    if (rows === null) { fill(id, el("p", { class: "muted" }, "No CBOM after: no attempt passed.")); return; }
    const blocking = rows.filter((x) => x.blocks_hybrid).length;
    const trs = rows.map((x) => el("tr", { class: x.blocks_hybrid ? "blocks" : null },
      el("td", null, el("code", null, `${x.path}:${x.line}`)), el("td", null, x.kind), el("td", null, x.algorithm),
      el("td", null, x.blocks_hybrid === null ? el("span", { class: "muted" }, "unknown") : x.blocks_hybrid ? el("span", { class: "bad" }, "yes") : "no"),
      el("td", null, x.auto_fix ? "fixed automatically" : "reported only")));
    fill(id, ok ? null : distrust(), el("p", null, el("span", { class: blocking ? "bad" : "ok" }, blocking ? `${blocking} row(s) keep the service off X25519MLKEM768` : "no row keeps the service off X25519MLKEM768"),
      " ", el("a", { href: base + file }, file.split("/").pop()), " ", el("span", { class: "hash" }, short(sha, 16))),
      table(["Where", "Kind", "Algorithm", "Blocks hybrid", "Fix"], trs));
  }

  function proofs(r, base) {
    fill("proofs", el("p", { class: "muted" }, "Each check is a command in a microVM; its log and SHA-256 are in the receipt."),
      table(["Step", "Check", "Expected", "Actual", "Matches", "Log"], r.proofs.map((p) => [
        el("span", { class: "nowrap" }, p.step), p.name, p.expected, p.actual, yes(p.ok),
        el("span", null, el("a", { href: base + p.log }, p.log.split("/").pop()), " ", el("span", { class: "hash" }, short(p.log_sha256)))]), true));
  }

  async function patch(r, base, ok) {
    const parts = [table(["Attempt", "Outcome", "Diff", "Error fed back"], r.attempts.map((a) => [
      String(a.number), a.outcome, a.diff ? el("a", { href: base + a.diff }, a.diff.split("/").pop()) : "none",
      a.error ? el("a", { href: base + a.error }, a.error.split("/").pop()) : "none"]))];
    fill("patch", parts);
    if (!r.patch) return;
    const pre = el("pre", { class: "diff" });
    try {
      const res = await fetch(base + r.patch.diff);
      const text = res.ok ? await res.text() : "";
      for (const line of text.replace(/\n$/, "").split("\n")) {
        const cls = line.startsWith("@@") ? "hunk" : line.startsWith("+") && !line.startsWith("+++") ? "add" : line.startsWith("-") && !line.startsWith("---") ? "del" : "ctx";
        pre.append(el("span", { class: cls }, line || " "));  // one block per line
      }
    } catch (e) { pre.textContent = "diff not available: " + e.message; }
    $("patch").append(ok ? el("h3", { style: { marginTop: "12px" } }, `Patch that passed (attempt ${r.patch.attempt}): ${r.patch.files.join(", ")}`)
      : el("div", null, distrust(), el("h3", { style: { marginTop: "12px" } }, `Patch the receipt names (attempt ${r.patch.attempt}), unverified`)), pre);
  }

  function receiptPanel(d) {
    const r = d.receipt, v = d.verification;
    fill("receipt",
      el("p", null, el("a", { href: d.links.receipt_html }, "receipt.html"), " · ", el("a", { href: d.links.receipt_json }, "receipt.json"),
        ` · ${r.artifacts.length} artifacts`),
      el("div", { class: "facts" }, el("div", null, el("div", { class: "k" }, "receipt_id (SHA-256)"), hash(r.receipt_id))),
      el("p", { class: v.ok ? "ok" : "bad" }, v.ok ? `The server recomputed every hash just now: all ${v.checks} checks match.` : "Hash check failed:"),
      v.ok ? null : el("ul", null, v.failed.map((f) => el("li", null, f))),
      el("p", { class: "muted" }, r.note),
      el("pre", null, "python3 -m pqproof verify-receipt RECEIPT_DIR"));
  }

  async function show(id) {
    $("status").textContent = "Loading " + id + "...";
    try {
      const d = await getJSON("/api/runs/" + encodeURIComponent(id));
      const r = d.receipt, base = d.links.base;
      summary(d); timeline(r); containment(r);
      cbom("cbom-before", r.cbom.before, r.cbom.before_file, r.cbom.before_file_sha256, base, d.verification.ok);
      cbom("cbom-after", r.cbom.after, r.cbom.after_file, r.cbom.after_file_sha256, base, d.verification.ok);
      proofs(r, base); receiptPanel(d);
      await patch(r, base, d.verification.ok);
      $("status").hidden = true; $("view").hidden = false;
      await replay(d).catch((e) => { $("rp-note").textContent = "Replay unavailable: " + e.message; });
    } catch (e) { $("status").hidden = false; $("view").hidden = true; $("status").textContent = "Could not load run " + id + ": " + e.message; }
  }

  async function start() {
    try {
      const list = await getJSON("/api/runs");
      $("footer").textContent = "Live runs: " + list.live_runs + ". Served by the PQ-Proof control plane; this page loads nothing from other sites.";
      if (!list.runs.length) { $("status").textContent = "No runs with a receipt yet."; return; }
      const sel = $("run");
      sel.replaceChildren(...list.runs.map((r) => el("option", { value: r.id }, `${r.id} (${r.verified ? r.verdict : "UNVERIFIED"}, ${r.model})`)));
      const want = params.get("run");
      if (want && list.runs.some((r) => r.id === want)) sel.value = want;
      sel.addEventListener("change", () => show(sel.value));
      await show(sel.value);
    } catch (e) { $("status").textContent = "Could not load runs: " + e.message; }
  }
  start();
})();
