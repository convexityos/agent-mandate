/**
 * The principal console, as one static page.
 *
 * No build step and no dependencies, served as a string from `ConsoleService`.
 * The page is the whole client: it fetches one overview, renders it, and signs
 * decisions locally.
 *
 * ## The key never leaves this page
 *
 * A decision is only worth anything because the agent cannot forge it, so the
 * console has to hold the principal's key to sign one. It is imported through
 * WebCrypto as **non-extractable** and kept in a module-scoped variable: not in
 * `localStorage`, not in a cookie, not in the DOM, and gone on reload.
 *
 * That is the best a browser can do, and it is worth being plain that it is not
 * nothing to worry about: this page asks a human to paste a spending key into a
 * web form, which is precisely the gesture a phishing page wants to teach. The
 * CSP is tight, the page makes no outbound requests except to its own origin,
 * and the key is unexportable once imported — but a principal who will not paste
 * a key here is being sensible, and should sign decisions offline instead. The
 * approval and control endpoints accept a JWS from anywhere.
 *
 * Note this file contains no backticks and no dollar-brace: it lives inside a
 * template literal.
 */
export const CONSOLE_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent Mandate — principal console</title>
<style>
  :root {
    --ground: #0a0c10;
    --panel: #12151c;
    --line: #1e232e;
    --ink: #e6e9ef;
    --muted: #8b94a7;
    --cobalt: #3b6ef5;
    --warn: #d8a13a;
    --bad: #d8564a;
    --good: #4ba573;
    --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 2rem 1.5rem 4rem;
    background: var(--ground); color: var(--ink);
    font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  main { max-width: 1100px; margin: 0 auto; }
  h1 { font-size: 1.15rem; font-weight: 600; letter-spacing: -0.01em; margin: 0; }
  h2 { font-size: 0.8rem; font-weight: 600; text-transform: uppercase;
       letter-spacing: 0.07em; color: var(--muted); margin: 0 0 0.75rem; }
  header { display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;
           padding-bottom: 1.25rem; border-bottom: 1px solid var(--line); margin-bottom: 1.5rem; }
  .spacer { flex: 1; }
  section { background: var(--panel); border: 1px solid var(--line);
            border-radius: 10px; padding: 1.1rem 1.25rem; margin-bottom: 1rem; }
  input, button, textarea {
    font: inherit; color: inherit; border-radius: 7px;
    border: 1px solid var(--line); background: #171b24; padding: 0.45rem 0.7rem;
  }
  textarea { width: 100%; font-family: var(--mono); font-size: 12px; min-height: 5.5rem; resize: vertical; }
  button { cursor: pointer; border-color: #2a3040; }
  button:hover:not(:disabled) { border-color: var(--cobalt); }
  button:disabled { opacity: 0.4; cursor: not-allowed; }
  button.primary { background: var(--cobalt); border-color: var(--cobalt); color: #fff; }
  button.danger { background: var(--bad); border-color: var(--bad); color: #fff; }
  button.ghost { background: transparent; }
  table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
  th { text-align: left; font-weight: 500; color: var(--muted); padding: 0.3rem 0.6rem 0.5rem 0;
       border-bottom: 1px solid var(--line); font-size: 12px; }
  td { padding: 0.5rem 0.6rem 0.5rem 0; border-bottom: 1px solid #171b23; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  .mono { font-family: var(--mono); font-size: 12px; }
  .muted { color: var(--muted); }
  .num { font-family: var(--mono); font-variant-numeric: tabular-nums; }
  .pill { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 999px;
          font-size: 11px; font-weight: 600; letter-spacing: 0.03em; text-transform: uppercase; }
  .pill.ok { background: rgba(75,165,115,0.15); color: var(--good); }
  .pill.warn { background: rgba(216,161,58,0.15); color: var(--warn); }
  .pill.bad { background: rgba(216,86,74,0.15); color: var(--bad); }
  .pill.idle { background: #1b202b; color: var(--muted); }
  .bar { height: 5px; background: #1b202b; border-radius: 3px; overflow: hidden; margin-top: 0.3rem; }
  .bar > i { display: block; height: 100%; background: var(--cobalt); }
  .bar > i.high { background: var(--warn); }
  .bar > i.full { background: var(--bad); }
  .indent { display: inline-block; color: var(--muted); }
  .row { display: flex; gap: 0.6rem; align-items: center; flex-wrap: wrap; }
  .note { font-size: 12.5px; color: var(--muted); margin-top: 0.6rem; }
  .empty { color: var(--muted); font-size: 13px; padding: 0.4rem 0; }
  #toast { position: fixed; right: 1.25rem; bottom: 1.25rem; max-width: 30rem;
           background: var(--panel); border: 1px solid var(--line); border-left: 3px solid var(--cobalt);
           border-radius: 8px; padding: 0.7rem 0.9rem; font-size: 13px; display: none; }
  #toast.bad { border-left-color: var(--bad); }
</style>
</head>
<body>
<main>
  <header>
    <h1>Principal console</h1>
    <span id="killBadge" class="pill idle">unknown</span>
    <span class="spacer"></span>
    <input id="root" placeholder="root mandate jti" size="26" class="mono">
    <button id="load" class="primary">Load</button>
    <button id="kill" class="danger" disabled>Halt everything</button>
    <button id="release" class="ghost" disabled>Release</button>
  </header>

  <section>
    <h2>Signing key</h2>
    <div class="row">
      <textarea id="jwk" placeholder='Principal private JWK: {"kty":"OKP","crv":"Ed25519","x":"...","d":"..."}'></textarea>
    </div>
    <div class="row" style="margin-top:0.6rem">
      <button id="arm" class="primary">Import key</button>
      <button id="disarm" class="ghost" disabled>Forget key</button>
      <span id="keyState" class="muted">No key. Reads work; nothing can be decided.</span>
    </div>
    <p class="note">
      Imported non-extractable and held in memory only — never stored, never sent, gone on reload.
      If you would rather not paste a spending key into a browser, that is a reasonable
      position: sign decisions offline and POST the JWS to the same endpoints.
    </p>
  </section>

  <section>
    <h2>Budget tree</h2>
    <div id="tree"><p class="empty">Load a root to begin.</p></div>
  </section>

  <section>
    <h2>Awaiting approval</h2>
    <div id="stepups"><p class="empty">Nothing waiting.</p></div>
  </section>

  <section>
    <h2>Settlement</h2>
    <div id="settling"><p class="empty">—</p></div>
  </section>

  <section>
    <h2>Spend feed</h2>
    <div id="feed"><p class="empty">—</p></div>
  </section>
</main>
<div id="toast"></div>

<script>
(function () {
  'use strict';

  var API = location.pathname.replace(/\\/$/, '');
  var signingKey = null;   // CryptoKey, non-extractable. Never persisted.
  var state = null;        // last overview payload

  var $ = function (id) { return document.getElementById(id); };

  function toast(message, bad) {
    var el = $('toast');
    el.textContent = message;
    el.className = bad ? 'bad' : '';
    el.style.display = 'block';
    clearTimeout(el._t);
    el._t = setTimeout(function () { el.style.display = 'none'; }, 6000);
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  function money(m) { return m ? esc(m.amt) + ' ' + esc(m.cur) : '—'; }

  function ago(seconds) {
    if (seconds == null) return '—';
    if (seconds < 60) return seconds + 's';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm';
    if (seconds < 86400) return Math.floor(seconds / 3600) + 'h';
    return Math.floor(seconds / 86400) + 'd';
  }

  // ---- signing -------------------------------------------------------------

  function b64u(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  }
  function b64uText(text) { return b64u(new TextEncoder().encode(text)); }

  async function signJws(typ, claims) {
    if (!signingKey) throw new Error('no key imported');
    var header = { alg: 'EdDSA', typ: typ, kid: claims.iss };
    var input = b64uText(JSON.stringify(header)) + '.' + b64uText(JSON.stringify(claims));
    var sig = await crypto.subtle.sign(
      { name: 'Ed25519' }, signingKey, new TextEncoder().encode(input)
    );
    return input + '.' + b64u(new Uint8Array(sig));
  }

  $('arm').onclick = async function () {
    try {
      var jwk = JSON.parse($('jwk').value);
      // extractable: false — once it is in here it cannot be read back out,
      // not by this page and not by anything that later injects into it.
      signingKey = await crypto.subtle.importKey(
        'jwk', jwk, { name: 'Ed25519' }, false, ['sign']
      );
      $('jwk').value = '';
      $('keyState').textContent = 'Key armed. Held in memory only.';
      $('disarm').disabled = false;
      $('arm').disabled = true;
      render();
      toast('Key imported. It is not stored anywhere.');
    } catch (err) {
      toast('Could not import key: ' + err.message, true);
    }
  };

  $('disarm').onclick = function () {
    signingKey = null;
    $('keyState').textContent = 'No key. Reads work; nothing can be decided.';
    $('disarm').disabled = true;
    $('arm').disabled = false;
    render();
    toast('Key forgotten.');
  };

  // ---- data ----------------------------------------------------------------

  async function load() {
    var root = $('root').value.trim();
    if (!root) { toast('Enter a root mandate jti.', true); return; }
    try {
      var res = await fetch(API + '/api/overview?root=' + encodeURIComponent(root));
      if (!res.ok) throw new Error('HTTP ' + res.status);
      state = await res.json();
      render();
    } catch (err) {
      toast('Load failed: ' + err.message, true);
    }
  }

  async function postDecision(path, jws) {
    var res = await fetch(API + path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ decision: jws })
    });
    var body = await res.json().catch(function () { return {}; });
    if (!res.ok) throw new Error(body.detail || body.error || ('HTTP ' + res.status));
    return body;
  }

  function principal() {
    // The console does not derive a DID from the key — it uses the issuer the
    // ledger recorded for this root. A key that does not match simply fails to
    // verify server-side, which is the correct place to find out.
    return state && state.tree.length ? state.tree[0].issuer : null;
  }

  // The ledger's clock, carried in the overview. Not Date.now(): the ledger's
  // clock is authoritative, and subtracting the reader's would render ages that
  // disagree with the ledger and can go negative outright.
  function ledgerNow() { return state ? state.now : Math.floor(Date.now() / 1000); }

  async function control(action, target) {
    var iss = principal();
    if (!iss) { toast('Load a root first.', true); return; }
    var now = ledgerNow();
    var claims = {
      v: 'am/1', typ: 'control',
      jti: 'ctl_' + crypto.randomUUID().replace(/-/g, ''),
      iss: iss, action: action, root: state.root,
      iat: now, exp: now + 300
    };
    if (target) claims.target = target;
    try {
      await postDecision('/api/control', await signJws('application/agent-control+jwt', claims));
      toast(action === 'kill' ? 'Spending halted for this principal.' : 'Done: ' + action);
      await load();
    } catch (err) {
      toast(action + ' refused: ' + err.message, true);
    }
  }

  async function decideStepUp(handle, verdict) {
    var s = state.stepUps.filter(function (x) { return x.handle === handle; })[0];
    if (!s) return;
    var now = ledgerNow();
    try {
      var jws = await signJws('application/agent-approval+jwt', {
        v: 'am/1', typ: 'approval',
        handle: handle, iss: principal(), verdict: verdict,
        // Restated so the signature covers the terms, not just the handle.
        root: s.root, res: s.resource, amt: s.amount,
        iat: now, exp: now + 900
      });
      await postDecision('/api/step-up/' + encodeURIComponent(handle), jws);
      toast(verdict === 'approve' ? 'Approved.' : 'Denied.');
      await load();
    } catch (err) {
      toast('Decision refused: ' + err.message, true);
    }
  }

  $('load').onclick = load;
  $('root').addEventListener('keydown', function (e) { if (e.key === 'Enter') load(); });
  $('kill').onclick = function () { control('kill'); };
  $('release').onclick = function () { control('release'); };

  // ---- rendering -----------------------------------------------------------

  function renderTree() {
    if (!state.tree.length) return '<p class="empty">No spending recorded under this root yet.</p>';
    var byParent = {};
    state.tree.forEach(function (n) {
      var k = n.parent || '';
      (byParent[k] = byParent[k] || []).push(n);
    });
    var rows = [];
    (function walk(parent, depth) {
      (byParent[parent] || []).forEach(function (n) {
        var pct = n.budget && Number(n.budget.amt) > 0
          ? Math.min(100, (Number(n.spent.amt) / Number(n.budget.amt)) * 100) : 0;
        var cls = pct >= 100 ? 'full' : pct >= 80 ? 'high' : '';
        rows.push(
          '<tr><td class="mono">' +
            '<span class="indent">' + '&nbsp;&nbsp;'.repeat(depth) + (depth ? '└ ' : '') + '</span>' +
            esc(n.jti) +
            (n.revoked ? ' <span class="pill bad">revoked</span>' : '') +
          '</td>' +
          '<td class="num">' + money(n.budget) + '</td>' +
          '<td class="num">' + money(n.spent) +
            '<div class="bar"><i class="' + cls + '" style="width:' + pct.toFixed(1) + '%"></i></div>' +
          '</td>' +
          '<td class="num">' + money(n.remaining) + '</td>' +
          '<td class="muted">' + (n.rate ? esc(n.rate.n + '/' + n.rate.per) : '—') + '</td>' +
          '<td><button class="ghost" data-revoke="' + esc(n.jti) + '">Revoke</button></td></tr>'
        );
        walk(n.jti, depth + 1);
      });
    })('', 0);
    return '<table><thead><tr><th>Mandate</th><th>Budget</th><th>Spent</th>' +
      '<th>Remaining</th><th>Rate</th><th></th></tr></thead><tbody>' +
      rows.join('') + '</tbody></table>';
  }

  function renderStepUps() {
    if (!state.stepUps.length) return '<p class="empty">Nothing waiting.</p>';
    var armed = !!signingKey;
    return '<table><thead><tr><th>Requested</th><th>Amount</th><th>Resource</th>' +
      '<th>Agent</th><th>Task</th><th></th></tr></thead><tbody>' +
      state.stepUps.map(function (s) {
        return '<tr>' +
          '<td class="muted">' + ago(ledgerNow() - s.requestedAt) + ' ago</td>' +
          '<td class="num"><strong>' + money(s.amount) + '</strong></td>' +
          '<td class="mono">' + esc(s.resource) + '</td>' +
          '<td class="mono muted">' + esc(s.agent) + '</td>' +
          '<td class="muted">' + esc(s.taskId || '—') + '</td>' +
          '<td class="row">' +
            '<button class="primary" data-approve="' + esc(s.handle) + '"' + (armed ? '' : ' disabled') + '>Approve</button>' +
            '<button class="ghost" data-deny="' + esc(s.handle) + '"' + (armed ? '' : ' disabled') + '>Deny</button>' +
          '</td></tr>';
      }).join('') + '</tbody></table>' +
      (armed ? '' : '<p class="note">Import a key to decide these.</p>');
  }

  function renderSettling() {
    var s = state.settling;
    var pill = s.count === 0 ? '<span class="pill ok">clear</span>'
      : '<span class="pill warn">' + s.count + ' in flight</span>';
    var body = '<div class="row">' + pill +
      '<span class="muted">oldest ' + ago(s.oldestSeconds) + '</span></div>';
    if (state.escalations.length) {
      body += '<table style="margin-top:0.8rem"><thead><tr><th>Escalated</th><th>Amount</th>' +
        '<th>Merchant</th><th>Why</th></tr></thead><tbody>' +
        state.escalations.map(function (e) {
          return '<tr><td class="mono">' + esc(e.spendId) + '</td>' +
            '<td class="num">' + money(e.amount) + '</td>' +
            '<td>' + esc(e.merchant) + '</td>' +
            '<td class="muted">' + esc(e.escalated ? e.escalated.reason : '') + '</td></tr>';
        }).join('') + '</tbody></table>';
    }
    return body;
  }

  function renderFeed() {
    if (!state.spends.length) return '<p class="empty">No spending recorded.</p>';
    var pillFor = {
      settled: 'ok', reserved: 'idle', settling: 'warn', refunded: 'idle', expired: 'idle'
    };
    return '<table><thead><tr><th>When</th><th>Status</th><th>Amount</th><th>Merchant</th>' +
      '<th>Agent</th><th>Rail ref</th></tr></thead><tbody>' +
      state.spends.map(function (r) {
        return '<tr>' +
          '<td class="muted">' + ago(ledgerNow() - r.createdAt) + ' ago</td>' +
          '<td><span class="pill ' + (pillFor[r.status] || 'idle') + '">' + esc(r.status) + '</span></td>' +
          '<td class="num">' + money(r.amount) + '</td>' +
          '<td>' + esc(r.merchant) + '</td>' +
          '<td class="mono muted">' + esc(r.agent) + '</td>' +
          '<td class="mono muted">' + esc(r.railRef || '—') + '</td></tr>';
      }).join('') + '</tbody></table>';
  }

  function render() {
    if (!state) return;
    var badge = $('killBadge');
    badge.textContent = state.killed ? 'halted' : 'spending';
    badge.className = 'pill ' + (state.killed ? 'bad' : 'ok');

    var armed = !!signingKey;
    $('kill').disabled = !armed || state.killed;
    $('release').disabled = !armed || !state.killed;

    $('tree').innerHTML = renderTree();
    $('stepups').innerHTML = renderStepUps();
    $('settling').innerHTML = renderSettling();
    $('feed').innerHTML = renderFeed();

    document.querySelectorAll('[data-approve]').forEach(function (b) {
      b.onclick = function () { decideStepUp(b.getAttribute('data-approve'), 'approve'); };
    });
    document.querySelectorAll('[data-deny]').forEach(function (b) {
      b.onclick = function () { decideStepUp(b.getAttribute('data-deny'), 'deny'); };
    });
    document.querySelectorAll('[data-revoke]').forEach(function (b) {
      b.onclick = function () {
        if (!signingKey) { toast('Import a key first.', true); return; }
        control('revoke', b.getAttribute('data-revoke'));
      };
    });
  }

  if (!(crypto.subtle && crypto.subtle.importKey)) {
    toast('This browser has no WebCrypto; the console is read-only here.', true);
  }
})();
</script>
</body>
</html>
`;
