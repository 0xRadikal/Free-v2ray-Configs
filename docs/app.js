/* ─────────────────────────────────────────────────────────────────────────────
 * Free V2Ray Configs — status dashboard
 *
 * Design rule, deliberately strict: **this file contains no counts.** Every
 * number rendered on the page comes from index.json / health.json fetched at
 * runtime. If the pipeline's output changes, the dashboard follows without an
 * edit here — and it can never advertise a figure the repository isn't
 * currently publishing.
 *
 * Why absolute raw URLs instead of a relative "../index.json": GitHub Pages
 * serves the /docs folder AS the site root, so the repository root is not
 * reachable from the published site at all. The mirror is used only as a
 * fallback, because jsDelivr can lag a branch ref by up to 12 hours.
 * ───────────────────────────────────────────────────────────────────────────── */

'use strict';

const REPO = '0xRadikal/Free-v2ray-Configs';
const BRANCH = 'main';
const PRIMARY = `https://raw.githubusercontent.com/${REPO}/${BRANCH}`;
const MIRROR = `https://cdn.jsdelivr.net/gh/${REPO}@${BRANCH}`;

const $ = (id) => document.getElementById(id);

/* ── helpers ─────────────────────────────────────────────────────────────── */

const nf = new Intl.NumberFormat('en-US');
const num = (v) => (typeof v === 'number' && isFinite(v) ? nf.format(v) : '—');

/* Numeric fields from index.json / health.json are exactly as untrusted as the
 * URLs handled by safeHref() below — they arrive from a CDN. Untyped use of them
 * fails silently and in ways that corrupt *unrelated* output:
 *
 *   • `total += s.count` switches from addition to string concatenation the
 *     moment one count is published as "250", producing "10025050", which then
 *     renders as "—": one bad field destroys a whole aggregate.
 *   • `Math.max(m, v)` over one non-numeric value yields NaN, so `max > 0` is
 *     false and *every* bar on the page collapses to 0% width.
 *   • a bare `if (count)` treats the string "0" as truthy, so a zero is reported
 *     as a real count that renders "—" and is left out of the zero tally.
 *
 * So numbers are narrowed once, here. `fin` answers "is this a usable number?"
 * and returns null when it is not — deliberately distinct from 0, because
 * "missing" and "zero" are different claims. `n0` is for arithmetic that must
 * not propagate the difference. */
function fin(v) { return typeof v === 'number' && isFinite(v) ? v : null; }
function n0(v) { const x = fin(v); return x === null ? 0 : x; }

/* Same argument for strings: a published field that is not a string would
 * otherwise be interpolated as "[object Object]". */
function str(v, dflt = '—') { return typeof v === 'string' && v ? v : dflt; }

/* A "record" is what both published files are supposed to be: a plain JSON
 * object. Note that Array.isArray is checked explicitly, because typeof [] is
 * "object" and an array would otherwise pass for a document. */
function isRecord(v) { return typeof v === 'object' && v !== null && !Array.isArray(v); }

/* An upstream failure message can be an entire HTML error page, so per-source
 * errors are clipped for layout — visibly, never silently. */
const ERROR_MAX_CHARS = 160;

/* Upper bound on how many per-round figures are printed inline. The array comes
 * from published JSON, so its length is not this page's to assume. */
const MAX_RUNS_SHOWN = 24;

function pct(part, whole) {
  if (typeof part !== 'number' || typeof whole !== 'number' || whole <= 0) return null;
  return (part / whole) * 100;
}

function fmtPct(v) {
  return v === null || !isFinite(v) ? '—' : `${v.toFixed(1)}%`;
}

/* Only ever put a vetted absolute http(s) URL into an href. index.json and
 * health.json are fetched from a CDN, so as far as this page is concerned their
 * contents are untrusted input: a `javascript:` string arriving in a `url`
 * field must not become a clickable link. */
function safeHref(url) {
  if (typeof url !== 'string') return null;
  try {
    const u = new URL(url, location.href);
    return (u.protocol === 'https:' || u.protocol === 'http:') ? u.href : null;
  } catch {
    return null;
  }
}

function relativeAge(ms) {
  if (!isFinite(ms)) return 'unknown';
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  if (h < 24) return rm ? `${h}h ${rm}m ago` : `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ${h % 24}h ago`;
}

function fmtSeconds(v) {
  if (typeof v !== 'number' || !isFinite(v)) return '—';
  if (v < 60) return `${v.toFixed(v < 10 ? 2 : 1)}s`;
  const m = Math.floor(v / 60);
  return `${m}m ${Math.round(v % 60)}s`;
}

function text(el, v) { if (el) el.textContent = v; }

function el(tag, cls, txt) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (txt !== undefined) n.textContent = txt;
  return n;
}

/* Cache-buster: raw.githubusercontent.com sends max-age=300, and this page is
 * about freshness, so a stale 5-minute copy would be actively misleading. */
/* Per-attempt timeout. Without one, a request that is throttled rather than
 * refused never settles: the primary attempt hangs forever, the mirror fallback
 * below is never reached, and the page sits on "Fetching live metadata…"
 * indefinitely with no error shown. That failure mode is likely for this
 * audience, whose networks are more often slowed than cleanly blocked.
 *
 * AbortSignal.timeout() is the standard expression of this and replaces the
 * older AbortController + setTimeout dance. It reached Baseline "widely
 * available" on 11 June 2026, so it is the current idiom rather than a bet on a
 * new API — but it is still feature-detected, because this page's audience is
 * disproportionately on old and locked-down devices, and the fallback costs four
 * lines. A missing implementation degrades to "no timeout" rather than throwing
 * and breaking loading altogether.
 *
 * Considered and rejected: racing primary and mirror with Promise.any(). It
 * would hide a slow primary behind the mirror, but the mirror can lag the branch
 * by up to 12 hours, so a race would sometimes win with *stale* data on a page
 * whose entire purpose is reporting freshness. Sequential-with-timeout is the
 * correct trade here, not the lazy one. */
const FETCH_TIMEOUT_MS = 12000;

function timeoutSignal(ms) {
  try {
    if (typeof AbortSignal !== 'undefined' &&
        typeof AbortSignal.timeout === 'function') {
      return AbortSignal.timeout(ms);
    }
    if (typeof AbortController === 'function') {
      const ac = new AbortController();
      setTimeout(() => ac.abort(), ms);
      return ac.signal;
    }
  } catch { /* fall through to no signal */ }
  return undefined;
}

async function getJSON(path) {
  const bust = `?_=${Date.now()}`;
  const attempts = [`${PRIMARY}/${path}${bust}`, `${MIRROR}/${path}${bust}`];
  let lastErr;
  for (const url of attempts) {
    try {
      const signal = timeoutSignal(FETCH_TIMEOUT_MS);
      const opts = { cache: 'no-store' };
      if (signal) opts.signal = signal;
      const res = await fetch(url, opts);
      if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
      const data = await res.json();
      return { data, url, mirrored: url.startsWith(MIRROR) };
    } catch (e) {
      lastErr = (e && e.name === 'TimeoutError')
        ? new Error(`timed out after ${FETCH_TIMEOUT_MS} ms: ${url}`)
        : e;
    }
  }
  throw lastErr || new Error(`could not load ${path}`);
}

/* ── renderers ───────────────────────────────────────────────────────────── */

function renderFreshness(idx) {
  const box = $('freshness');
  const updated = Date.parse(idx.updated_at);
  const known = isFinite(updated);
  const age = known ? Date.now() - updated : NaN;
  const ivMin = fin(idx.update_interval_minutes);
  const interval = n0(ivMin) * 60 * 1000;
  const judgeable = known && interval > 0;

  // "stale" is defined against the repository's own advertised interval rather
  // than a number invented here — which means freshness is only *judgeable* when
  // BOTH the timestamp and the interval are usable. Two separate traps live here,
  // and both end at the same wrong answer:
  //
  //   1. `updated_at` missing or unparseable ⇒ `age` is NaN, and every comparison
  //      against NaN is false.
  //   2. `update_interval_minutes` missing, 0, or non-numeric ⇒ `interval` is 0
  //      or NaN, so both interval guards are false.
  //
  // In either case a naive chain falls through to the final `else` and paints a
  // green dot — measured here at 1096 days old, still reported as "fresh". A
  // dashboard whose whole job is freshness must never assert it by default, so
  // anything not judgeable gets its own neutral state instead of inheriting the
  // good one.
  let cls;
  if (!judgeable) cls = 'unknown';
  else if (age > interval * 3) cls = 'broken';
  else if (age > interval * 1.5) cls = 'stale';
  else cls = 'fresh';
  box.className = cls;

  // A <time> element is only correct when there is a machine-readable value to
  // put in it. Per the HTML Standard (§4.5.14 The time element): "The datetime
  // attribute may be present. If present, its value must be a representation of
  // the element's contents in a machine-readable format", and "The datetime value
  // of a time element is the value of the element's datetime content attribute,
  // if it has one, otherwise the child text content of the time element. The
  // datetime value of a time element must match one of the following syntaxes."
  //
  // So datetime="" is invalid — and, less obviously, merely *removing* the
  // attribute does not fix it: the datetime value then falls through to the child
  // text, and a placeholder like "—" matches none of the listed syntaxes either.
  // The only conformant answer for an unknown timestamp is to emit no <time> at
  // all, so the element is built here instead of sitting empty in the HTML.
  const wrap = $('updated-at-wrap');
  if (wrap) {
    wrap.replaceChildren();
    if (known) {
      const iso = new Date(updated).toISOString();
      const t = el('time', null, str(idx.updated_at, iso));
      t.id = 'updated-at';
      t.dateTime = iso;
      wrap.appendChild(t);
    } else {
      wrap.textContent = 'update time unknown';
    }
  }

  let verdict;
  if (!known) {
    verdict = 'update time unknown (index.json carried no usable updated_at)';
  } else if (ivMin === null || ivMin <= 0) {
    // Say which half is missing. "unknown" with no reason is a dead end for
    // whoever has to debug it.
    verdict = `updated ${relativeAge(age)}, but index.json published no usable ` +
              `update_interval_minutes, so staleness cannot be judged`;
  } else {
    verdict = `updated ${relativeAge(age)} · target interval ${num(ivMin)} min`;
  }
  text($('freshness-text'), verdict);

  text($('updated-age'), relativeAge(age));
  text($('next-eta'), str(idx.next_update_eta));
  text($('run-seconds'), fmtSeconds(idx.elapsed_seconds));
  text($('branch'), str(idx.publish_branch));
}

function renderCategories(idx) {
  const tbody = $('category-rows');
  tbody.replaceChildren();
  const cats = idx.categories || {};
  for (const [name, c] of Object.entries(cats)) {
    const tr = el('tr');
    tr.appendChild(el('td', 'name', name));
    tr.appendChild(el('td', 'num', num(c.unique)));
    tr.appendChild(el('td', 'num', num(c.duplicates)));
    tr.appendChild(el('td', 'num', num(c.broken)));
    tr.appendChild(el('td', 'num', num(c.total_fetched)));
    tr.appendChild(el('td', 'num', num(c.active_sources)));
    const dedup = pct(c.duplicates, c.total_fetched);
    tr.appendChild(el('td', 'num', fmtPct(dedup)));
    tbody.appendChild(tr);
  }

  const all = cats.all || {};
  text($('total-unique'), num(all.unique));
  text($('total-unique-sub'),
    all.total_fetched ? `from ${num(all.total_fetched)} fetched` : '');
}

function renderProtocols(idx) {
  const host = $('protocol-list');
  host.replaceChildren();
  const protos = Object.entries(idx.protocols || {})
    .sort((a, b) => n0(b[1]) - n0(a[1]));
  const max = protos.reduce((m, [, v]) => Math.max(m, n0(v)), 0);
  const published = new Set(Object.keys(idx.protocol_files || {}));

  // Three outcomes, not two. A count of 0 and a count that cannot be read are
  // different facts, and collapsing them would make the summary sentence below
  // claim "yielded nothing" about a protocol whose result is simply unknown.
  let zero = 0, unusable = 0;
  for (const [name, rawCount] of protos) {
    const count = fin(rawCount);
    const isZero = count !== null && count <= 0;
    const row = el('div', 'proto' + (isZero ? ' is-zero' : ''));
    row.appendChild(el('span', 'pname', name));

    const bar = el('div', 'bar');
    const fill = el('i');
    fill.style.width = max > 0 ? `${(n0(count) / max) * 100}%` : '0%';
    bar.appendChild(fill);
    row.appendChild(bar);

    const p = el('span', 'pcount');
    if (count === null) {
      unusable++;
      p.appendChild(el('span', 'pill unknown', 'unreadable'));
    } else if (count > 0) {
      p.textContent = num(count);
    } else {
      zero++;
      p.appendChild(el('span', 'pill zero', 'none'));
    }
    row.appendChild(p);
    // A file link only if the repository is actually publishing that file.
    const pf = str(idx.protocol_files && idx.protocol_files[name], '');
    if (published.has(name) && pf) row.title = `published: ${pf}`;
    host.appendChild(row);
  }

  const notes = [];
  if (zero > 0) {
    notes.push(`${zero} supported protocol${zero === 1 ? '' : 's'} yielded nothing this round — ` +
               `no file is published for those, because an empty subscription file is worse than a 404.`);
  }
  if (unusable > 0) {
    notes.push(`${unusable} protocol count${unusable === 1 ? '' : 's'} in index.json could not be read ` +
               `as a number and ${unusable === 1 ? 'is' : 'are'} shown as unreadable rather than as zero.`);
  }
  if (!notes.length) notes.push('Every supported protocol yielded at least one config this round.');
  text($('protocol-note'), notes.join(' '));
}

function renderSources(health) {
  const list = Array.isArray(health.sources) ? health.sources : [];
  const tbody = $('source-rows');
  tbody.replaceChildren();

  // Counted from the source list itself, NOT from health.summary: summary
  // reports ok/empty/fail, but a source can also be "unknown", which belongs
  // to none of those three. Deriving the tally here keeps the page honest even
  // when the buckets don't add up to the total.
  const tally = new Map();
  let yielded = 0;

  // Object.create(null): the keys come from published JSON, and a plain object
  // literal would resolve inherited names (a status of "constructor" would look
  // up to a function instead of falling through to the default rank).
  const order = Object.assign(Object.create(null),
    { fail: 0, empty: 1, unknown: 2, ok: 3 });
  list.slice()
    .sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9) ||
                    (b.count || 0) - (a.count || 0))
    .forEach((s) => {
      const st = str(s.status, 'unknown');
      tally.set(st, (tally.get(st) || 0) + 1);
      yielded += n0(s.count);

      const tr = el('tr');
      const nameTd = el('td', 'name');
      const href = safeHref(s.url);
      if (href) {
        const a = el('a', null, str(s.name, href));
        a.href = href;
        a.rel = 'noopener noreferrer';
        a.target = '_blank';
        nameTd.appendChild(a);
      } else {
        nameTd.textContent = str(s.name);
      }
      tr.appendChild(nameTd);
      tr.appendChild(el('td', null, str(s.tier)));
      const stTd = el('td');
      stTd.appendChild(el('span', `pill ${['ok', 'empty', 'fail'].includes(st) ? st : 'unknown'}`, st));
      tr.appendChild(stTd);
      tr.appendChild(el('td', 'num', num(s.count)));

      // Diagnostics actually published per source. The issue templates tell
      // reporters to consult the HTTP code, latency and last error before
      // filing, so a dashboard that fetched health.json and then dropped those
      // fields would be sending people to read raw JSON for data it already
      // had in hand.
      const diagTd = el('td', 'diag');
      const bits = [];
      if (typeof s.http_code === 'number') bits.push(`HTTP ${s.http_code}`);
      if (typeof s.latency_ms === 'number') bits.push(`${num(Math.round(s.latency_ms))} ms`);
      if (typeof s.attempts === 'number' && s.attempts > 1) bits.push(`${s.attempts} attempts`);
      if (bits.length) diagTd.appendChild(el('span', null, bits.join(' · ')));
      if (s.error) {
        // Truncating is necessary — an upstream error can be a whole HTML page —
        // but truncating *silently* is not acceptable: a cut-off error reads as a
        // complete one, and the reader draws a conclusion from half a sentence.
        // So the cut is marked with an ellipsis and the full text is kept on the
        // element, reachable by hover/inspection rather than thrown away.
        const full = String(s.error);
        const clipped = full.length > ERROR_MAX_CHARS;
        const err = el('span', 'diag-error',
          clipped ? `${full.slice(0, ERROR_MAX_CHARS - 1)}\u2026` : full);
        if (clipped) err.title = full;
        if (bits.length) diagTd.appendChild(document.createTextNode(' · '));
        diagTd.appendChild(err);
      }
      if (!bits.length && !s.error) {
        // No diagnostics at all is itself information: this source was never
        // contacted in the run that produced health.json.
        diagTd.appendChild(el('span', 'diag-none', 'not contacted'));
      }
      tr.appendChild(diagTd);
      tbody.appendChild(tr);
    });

  text($('sources-total'), num(list.length));
  const parts = [...tally.entries()]
    .sort((a, b) => (order[a[0]] ?? 9) - (order[b[0]] ?? 9))
    .map(([k, v]) => `${v} ${k}`);
  text($('sources-breakdown'), parts.join(' · ') || '—');
  text($('sources-yield'), num(yielded));
  text($('checked-at'), str(health.checked_at));
}

function renderCascade(health) {
  const c = health.cascade;
  const section = $('cascade-section');
  if (!c || !c.layers) { section.hidden = true; return; }
  section.hidden = false;

  const l = c.layers;
  const l01 = l.l0_l1 || {}, l2 = l.l2 || {}, l3 = l.l3 || {};
  const b = c.buckets || {};
  const raw = l01.in;

  const ec = (c.exit_country && typeof c.exit_country === 'object') ? c.exit_country : {};
  const ecLoc = str(ec.loc, ''), ecColo = str(ec.colo, '');
  text($('exit-country'), ecLoc ? `${ecLoc}${ecColo ? ` (${ecColo})` : ''}` : 'unknown');
  const src = $('exit-country-source');
  const ecHref = safeHref(ec.source);
  if (ecHref) { src.href = ecHref; src.hidden = false; } else { src.hidden = true; }

  // Every note below goes through fin()/num() like the numeric cells beside it.
  // Interpolating a raw field would print "[object Object] rounds" or "lots%" in
  // a row whose other five cells correctly say "—" — an inconsistency that reads
  // as a real measurement.
  const uniq = fin(l01.endpoints_unique);
  const dnsF = fin(l2.dns_failed);
  const rounds = fin(l3.rounds);
  const flaky = fin(l3.flaky_pct);
  const rows = [
    ['L0/L1 — parsable & unique endpoint', l01.in, l01.out, l01.seconds,
     uniq !== null ? `${num(uniq)} unique endpoints` : ''],
    ['L2 — TCP port accepts', l2.in, l2.out, l2.seconds,
     dnsF !== null ? `${num(dnsF)} DNS failures` : ''],
    ['L3 — real HTTP request through proxy', l3.in, l3.ever_ok, l3.seconds,
     rounds !== null ? `${num(rounds)} round${rounds === 1 ? '' : 's'}, worked at least once` : ''],
    ['L3 — passed EVERY round → verified/', l3.in, l3.stable, null,
     flaky !== null ? `${num(flaky)}% of ever-ok were flaky` : ''],
  ];

  const tbody = $('cascade-rows');
  tbody.replaceChildren();
  for (const [label, inn, out, secs, note] of rows) {
    const tr = el('tr');
    tr.appendChild(el('td', null, label));
    tr.appendChild(el('td', 'num', num(inn)));
    tr.appendChild(el('td', 'num', num(out)));
    tr.appendChild(el('td', 'num', fmtPct(pct(out, raw))));
    tr.appendChild(el('td', 'num', secs === null ? '—' : fmtSeconds(secs)));
    tr.appendChild(el('td', null, note || ''));
    tbody.appendChild(tr);
  }

  text($('verified-count'), num(b.verified));
  text($('verified-sub'), fmtPct(pct(b.verified, raw)) + ' of the pool');
  text($('fast-count'), num(b.fast));
  const fastMs = fin(b.fast_threshold_ms);
  text($('fast-sub'), fastMs !== null && fastMs > 0 ? `< ${num(fastMs)} ms` : '');
  text($('secure-count'), num(b.secure));
  text($('cascade-seconds'), fmtSeconds(c.total_seconds));

  // per-round detail, stated explicitly because the spread is the whole point.
  //
  // Math.min(...arr) is NOT used here. Spreading an array into a call passes one
  // argument per element, so the array's length becomes an argument count — and
  // this array arrives from a CDN. Measured: 100,000 elements still works, but
  // 200,000 throws "RangeError: Maximum call stack size exceeded", which would
  // abort the whole render. reduce() has no such ceiling. The printed list is
  // capped for the same reason: joining 200,000 numbers would freeze the tab.
  const runsRaw = Array.isArray(l3.per_run_ok) ? l3.per_run_ok : [];
  const runs = runsRaw.map(fin).filter((v) => v !== null);
  if (runsRaw.length) {
    const shown = runsRaw.slice(0, MAX_RUNS_SHOWN);
    text($('per-round'),
      shown.map(num).join(' · ') +
      (runsRaw.length > MAX_RUNS_SHOWN ? ` … (+${num(runsRaw.length - MAX_RUNS_SHOWN)} more)` : ''));
    if (runs.length) {
      const lo = runs.reduce((m, v) => Math.min(m, v), Infinity);
      const hi = runs.reduce((m, v) => Math.max(m, v), -Infinity);
      text($('per-round-note'),
        `Per-round success ranged ${num(lo)}–${num(hi)}, while only ${num(fin(l3.stable))} passed ` +
        `every round. Publishing the best round would have overstated the result.`);
    } else {
      text($('per-round-note'),
        'health.json published per-round figures that could not be read as numbers, ' +
        'so no range is stated here.');
    }
  } else {
    text($('per-round'), '—');
    text($('per-round-note'), '');
  }
}

function renderLinks(idx) {
  const tbody = $('link-rows');
  tbody.replaceChildren();
  const cats = idx.categories || {};
  for (const [cat, c] of Object.entries(cats)) {
    const files = c.files || {};
    for (const [kind, url] of Object.entries(files)) {
      if (typeof url !== 'string' || !url.startsWith('http')) continue;
      if (url.startsWith(MIRROR)) continue;           // primary links only
      const tr = el('tr');
      tr.appendChild(el('td', 'name', cat));
      tr.appendChild(el('td', null, kind));
      const td = el('td', 'name');
      // Degrade to plain text, not to href="#". A '#' link is not inert: it
      // navigates to the top of the page, so a reader who clicks what looks like
      // a download link gets a silent scroll instead. Showing the URL as text
      // says "here is what was published, and it is not usable as a link" — and
      // it matches how the source table above handles a rejected URL.
      const safe = safeHref(url);
      if (safe) {
        const a = el('a', null, url);
        a.href = safe;
        a.rel = 'noopener noreferrer';
        td.appendChild(a);
      } else {
        td.textContent = url;
      }
      tr.appendChild(td);
      tbody.appendChild(tr);
    }
  }
  // Two-way, not one-way: every hide in this file has a matching un-hide so the
  // renderers stay idempotent. Nothing re-renders today, but a one-way hide is a
  // trap for whoever adds a refresh button later.
  $('links-section').hidden = !tbody.children.length;
}

function showError(e, which) {
  $('loading-state').hidden = true;
  // Fail closed. A render that threw part-way leaves the dashboard holding some
  // real numbers, some stale placeholders and no marker separating them; shown
  // next to an error banner it invites the reader to trust the half that looks
  // populated. Hiding it is the only honest state, and it also makes showError
  // safe to call from anywhere rather than only before the reveal.
  const dash = $('dashboard');
  if (dash) dash.hidden = true;
  const box = $('error-state');
  box.hidden = false;
  text($('error-detail'), `${which}: ${e && e.message ? e.message : String(e)}`);
}

/* ── boot ────────────────────────────────────────────────────────────────── */

async function main() {
  let idx, health;
  try {
    idx = await getJSON('index.json');
  } catch (e) {
    return showError(e, 'index.json');
  }
  // `JSON.parse` accepts "null", "42" and "[]" as complete documents, so a
  // successful fetch does not mean a usable payload. Without this guard,
  // index.json === null reaches renderFreshness and throws
  // "Cannot read properties of null (reading 'updated_at')" — an internal
  // TypeError shown to a visitor in place of the plain fact that the published
  // file is not an object. Arrays are rejected too: typeof [] is "object", and an
  // array would silently render as a dashboard of empty tables.
  if (!isRecord(idx.data)) {
    return showError(new Error('index.json did not contain a JSON object'), 'index.json');
  }

  try {
    health = await getJSON('health.json');
  } catch (e) {
    // The page is still useful without health.json, so degrade instead of dying.
    health = { data: {}, mirrored: false };
    $('health-warning').hidden = false;
  }
  // Same guard, softer consequence: health.json is optional, so a payload that is
  // not an object is treated as an absent one instead of aborting the page. It
  // must not be left as-is — Object.keys("ab").length is 2, so a bare JSON string
  // would pass the "have health?" test below and produce an empty source table
  // presenting itself as a real measurement of zero sources.
  if (!isRecord(health.data)) {
    health = { data: {}, mirrored: health.mirrored };
    $('health-warning').hidden = false;
  }

  $('loading-state').hidden = true;

  if (idx.mirrored || health.mirrored) $('mirror-warning').hidden = false;

  // index.json and health.json are two separate requests against a CDN that
  // caches them independently, so they can legitimately arrive from different
  // pipeline runs. Detect that and say so rather than presenting a blended set
  // of numbers as if it were one measurement.
  const iAt = idx.data && idx.data.updated_at;
  const hAt = health.data && health.data.checked_at;
  if (iAt && hAt) {
    const di = Date.parse(iAt), dh = Date.parse(hAt);
    if (isFinite(di) && isFinite(dh) && Math.abs(di - dh) > 120000) {
      text($('mismatch-index-at'), iAt);
      text($('mismatch-health-at'), hAt);
      $('run-mismatch-warning').hidden = false;
    }
  }

  try {
    renderFreshness(idx.data);
    renderCategories(idx.data);
    renderProtocols(idx.data);
    renderLinks(idx.data);
    const haveHealth = !!(health.data && Object.keys(health.data).length);
    $('sources-section').hidden = !haveHealth;
    if (haveHealth) {
      renderSources(health.data);
      renderCascade(health.data);
    } else {
      $('cascade-section').hidden = true;
    }
    text($('brand'), str(idx.data.brand, ''));
  } catch (e) {
    return showError(e, 'render');
  }

  // Revealed only after every renderer has completed. Doing this earlier meant a
  // throw half-way through left a partly-filled dashboard on screen *beside* the
  // error banner, with nothing to tell the reader which figures had actually been
  // written. The page now shows either a complete dashboard or an error, never
  // both.
  $('dashboard').hidden = false;
}

document.addEventListener('DOMContentLoaded', main);
