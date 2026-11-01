/* Raydikalx — Free V2Ray Configs landing page runtime.
 *
 * Hand-written, no framework, no build step. Shared by / and /fa/; every
 * user-visible string comes from the <script id="i18n"> block the page was
 * generated with (docs-src/i18n/*.json).
 *
 * Rules this file keeps (inherited from the previous dashboard):
 *   - Published JSON/text is UNTRUSTED input. Every value passes a guard; a
 *     missing number renders as "—", never as NaN, undefined or a fake 0.
 *   - Nothing from the network is inserted as HTML. Text goes through
 *     textContent; the only innerHTML is the QR <svg> built locally from a
 *     module matrix by the vendored qrcode-generator.
 *   - Subscription URLs are NOT taken from the JSON. They are built from the
 *     repository's fixed layout (locked by scripts/test_pipeline.py), so a
 *     malformed index.json can never turn a button into a hostile link.
 *   - raw.githubusercontent.com first, the jsDelivr mirror only as fallback.
 */
(function () {
  'use strict';

  var RAW = 'https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main';
  var CDN = 'https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main';
  var TIMEOUT_MS = 12000;
  var PAGE_SIZE = 40;
  var AUTO_REFRESH_MS = 120000;

  var T = {};
  try { T = JSON.parse(document.getElementById('i18n').textContent); } catch (e) { T = {}; }
  var LANG = T.lang === 'fa' ? 'fa' : 'en';

  /* ── tiny helpers ─────────────────────────────────────────────────── */
  function $(id) { return document.getElementById(id); }
  function t(key, vars) {
    var s = typeof T[key] === 'string' ? T[key] : key;
    if (vars) {
      Object.keys(vars).forEach(function (k) { s = s.split('{' + k + '}').join(String(vars[k])); });
    }
    return s;
  }
  function h(tag, attrs, kids) {
    var el = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === null || v === undefined || v === false) return;
        if (k === 'text') el.textContent = v;
        else if (k === 'class') el.className = v;
        else if (k.slice(0, 2) === 'on' && typeof v === 'function') el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? '' : String(v));
      });
    }
    (kids || []).forEach(function (c) {
      if (c === null || c === undefined || c === false) return;
      el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return el;
  }
  function clear(el) { while (el && el.firstChild) el.removeChild(el.firstChild); }
  function fin(x) { return typeof x === 'number' && isFinite(x) ? x : null; }
  function obj(x) { return x && typeof x === 'object' && !Array.isArray(x) ? x : null; }
  function str(x) { return typeof x === 'string' ? x : null; }
  function dig(o, path) {
    var cur = o;
    for (var i = 0; i < path.length; i++) {
      if (!cur || typeof cur !== 'object') return undefined;
      cur = cur[path[i]];
    }
    return cur;
  }
  var NF = (function () { try { return new Intl.NumberFormat(LANG); } catch (e) { return null; } })();
  function num(x) {
    var n = fin(x);
    if (n === null) return '—';
    return NF ? NF.format(n) : String(n);
  }
  function pct(x, digits) {
    var n = fin(x);
    if (n === null) return '—';
    try { return new Intl.NumberFormat(LANG, { maximumFractionDigits: digits || 0 }).format(n); } catch (e) { return n.toFixed(digits || 0); }
  }
  function isHttpUrl(u) {
    if (typeof u !== 'string') return false;
    try { var p = new URL(u); return p.protocol === 'https:' || p.protocol === 'http:'; } catch (e) { return false; }
  }
  var DN = (function () {
    try { return new Intl.DisplayNames([LANG], { type: 'region' }); } catch (e) { return null; }
  })();
  function countryName(code, fallback) {
    if (DN && /^[A-Z]{2}$/.test(code || '')) {
      try { var n = DN.of(code); if (n && n !== code) return n; } catch (e) { /* ignore */ }
    }
    return fallback || code || '—';
  }
  function flagOf(code) {
    if (!/^[A-Z]{2}$/.test(code || '')) return '🌐';
    return String.fromCodePoint(0x1F1E6 + code.charCodeAt(0) - 65, 0x1F1E6 + code.charCodeAt(1) - 65);
  }
  function store(key, val) {
    try {
      if (val === undefined) return window.localStorage.getItem('rdx-v2-' + key);
      window.localStorage.setItem('rdx-v2-' + key, val);
    } catch (e) { /* storage blocked (private mode) — preferences just aren't kept */ }
    return null;
  }

  /* ── toast + clipboard ────────────────────────────────────────────── */
  var toastTimer = null;
  function toast(msg, isError) {
    var el = $('toast');
    if (!el) return;
    el.textContent = msg;
    el.className = 'toast' + (isError ? ' error' : '');
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.hidden = true; }, 2600);
  }
  function copyText(text) {
    function legacy() {
      return new Promise(function (resolve, reject) {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.setAttribute('aria-hidden', 'true');
        ta.style.position = 'fixed'; ta.style.top = '-1000px'; ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        var ok = false;
        try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
        document.body.removeChild(ta);
        if (ok) resolve(); else reject(new Error('copy failed'));
      });
    }
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).catch(legacy);
    }
    return legacy();
  }
  function copyWithFeedback(text, btn, okMsg) {
    return copyText(text).then(function () {
      toast(okMsg || t('copied'));
      if (btn) {
        btn.classList.add('done');
        setTimeout(function () { btn.classList.remove('done'); }, 1400);
      }
    }, function () { toast(t('copyFail'), true); });
  }

  /* ── QR ───────────────────────────────────────────────────────────── */
  function renderQr(el, text) {
    clear(el);
    if (typeof window.qrcode !== 'function') {
      el.appendChild(h('span', { class: 'qr-msg', text: t('noData') }));
      return false;
    }
    try {
      window.qrcode.stringToBytes = window.qrcode.stringToBytesFuncs['UTF-8'];
      var qr = window.qrcode(0, text.length > 600 ? 'L' : 'M');
      qr.addData(text, 'Byte');
      qr.make();
      // createSvgTag only emits rect/path data derived from the module matrix.
      el.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
      return true;
    } catch (e) {
      el.appendChild(h('span', { class: 'qr-msg', text: t('qrTooLong') }));
      return false;
    }
  }
  function openQrDialog(text, label) {
    var dlg = $('qrDialog');
    renderQr($('qrDialogCode'), text);
    $('qrDialogName').textContent = label || '';
    if (dlg && typeof dlg.showModal === 'function') dlg.showModal();
    else if (dlg) dlg.setAttribute('open', '');
  }

  /* ── network ──────────────────────────────────────────────────────── */
  function fetchWithTimeout(url) {
    var ctrl = typeof AbortController === 'function' ? new AbortController() : null;
    var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, TIMEOUT_MS) : null;
    var opts = { cache: 'no-store' };
    if (ctrl) opts.signal = ctrl.signal;
    return fetch(url, opts).then(function (res) {
      if (timer) clearTimeout(timer);
      if (!res.ok) throw new Error('HTTP ' + res.status + ' for ' + url);
      return res;
    }, function (err) {
      if (timer) clearTimeout(timer);
      throw err;
    });
  }
  /** Fetch `path` from raw, then from the mirror. Resolves {body, mirrored}. */
  function getFile(path, asJson) {
    var bases = [RAW, CDN];
    var i = 0;
    function attempt() {
      var base = bases[i];
      return fetchWithTimeout(base + '/' + path + '?_=' + Date.now())
        .then(function (res) { return asJson ? res.json() : res.text(); })
        .then(function (body) { return { body: body, mirrored: base === CDN }; })
        .catch(function (err) {
          i += 1;
          if (i < bases.length) return attempt();
          throw err;
        });
    }
    return attempt();
  }

  /* ── subscription model (fixed repository layout) ─────────────────── */
  var FULL = ['base64', 'txt', 'clash', 'singbox'];
  var FILE_OF = { base64: 'configs_base64.txt', txt: 'configs.txt', clash: 'clash.yaml', singbox: 'singbox.json' };
  var TIERS = {
    verified: { group: 'rec', label: 'tVerified', desc: 'verifiedDesc', tested: true },
    fast: { group: 'rec', label: 'tFast', desc: 'fastDesc', tested: true },
    secure: { group: 'rec', label: 'tSecure', desc: 'secureDesc', tested: true },
    top100: { group: 'rec', label: 'tTop100', desc: 'top100Desc', tested: true },
    all: { group: 'pool', label: 'tAll', desc: 'allDesc', tested: false },
    heavy: { group: 'pool', label: 'tHeavy', desc: 'heavyDesc', tested: false },
    light: { group: 'pool', label: 'tLight', desc: 'lightDesc', tested: false }
  };
  var FORMATS = [
    { id: 'base64', label: 'fBase64', desc: 'fBase64d' },
    { id: 'txt', label: 'fTxt', desc: 'fTxtd' },
    { id: 'clash', label: 'fClash', desc: 'fClashd' },
    { id: 'singbox', label: 'fSingbox', desc: 'fSingboxd' }
  ];
  var COUNTRY_FILE = /^Countries\/[A-Za-z0-9_.-]+\.txt$/;
  var PROTO_KEY = /^[a-z0-9]{2,20}$/;

  /** Selection -> {format: repo path}. Only formats the pipeline writes appear. */
  function filesFor(sel) {
    var out = {};
    if (sel.kind === 'tier' && TIERS[sel.id]) {
      if (sel.id === 'top100') { out.txt = 'top100.txt'; return out; }
      FULL.forEach(function (f) { out[f] = sel.id + '/' + FILE_OF[f]; });
    } else if (sel.kind === 'country' && COUNTRY_FILE.test(sel.file || '')) {
      out.txt = sel.file;
    } else if (sel.kind === 'protocol' && PROTO_KEY.test(sel.id || '')) {
      out.base64 = 'protocols/' + sel.id + '_base64.txt';
      out.txt = 'protocols/' + sel.id + '.txt';
    }
    return out;
  }
  function urlOf(path, mirror) { return (mirror ? CDN : RAW) + '/' + path; }

  /* ── state ────────────────────────────────────────────────────────── */
  var S = {
    idx: null, health: null, countries: null, countriesFailed: false, countriesMethod: 'GeoIP',
    mirrored: false,
    sel: { kind: 'tier', id: 'verified' },
    format: 'base64', pref: 'base64',
    mirror: false,
    configs: null, configsFailed: false,
    filtered: [], shown: PAGE_SIZE
  };
  (function restore() {
    var tier = store('tier');
    if (tier && TIERS[tier]) S.sel = { kind: 'tier', id: tier };
    var fmt = store('format');
    if (fmt && FILE_OF[fmt]) { S.pref = fmt; S.format = fmt; }
    S.mirror = store('mirror') === '1';
  })();

  /* ── hub ──────────────────────────────────────────────────────────── */
  function tierCount(id) {
    var idx = S.idx;
    if (!idx) return null;
    if (id === 'top100') return fin(dig(idx, ['top100', 'count']));
    if (TIERS[id] && TIERS[id].group === 'rec') return fin(dig(idx, ['cascade_categories', id, 'unique']));
    return fin(dig(idx, ['categories', id, 'unique']));
  }
  function selectionCount(sel) {
    if (sel.kind === 'tier') return tierCount(sel.id);
    if (sel.kind === 'country') return fin(sel.count);
    if (sel.kind === 'protocol') return fin(dig(S.idx, ['protocols', sel.id]));
    return null;
  }
  function selectionName(sel) {
    if (sel.kind === 'tier') return t(TIERS[sel.id].label);
    if (sel.kind === 'country') return sel.flag + ' ' + sel.name;
    if (sel.kind === 'protocol') return sel.id.toUpperCase();
    return '—';
  }
  function profileName(sel) {
    if (sel.kind === 'tier') return 'Raydikalx ' + sel.id.toUpperCase();
    if (sel.kind === 'country') return 'Raydikalx ' + sel.code;
    if (sel.kind === 'protocol') return 'Raydikalx ' + sel.id.toUpperCase();
    return 'Raydikalx';
  }
  function selectionDesc(sel) {
    if (sel.kind === 'tier') {
      var ms = fin(dig(S.health, ['cascade', 'buckets', 'fast_threshold_ms']));
      return t(TIERS[sel.id].desc, { ms: ms === null ? '—' : num(ms) });
    }
    if (sel.kind === 'country') return t('countryDesc', { name: sel.name });
    if (sel.kind === 'protocol') return t('protocolDesc', { name: sel.id.toUpperCase() });
    return '';
  }
  function selectTier(id) {
    S.sel = { kind: 'tier', id: id };
    store('tier', id);
    $('hubCountry').value = '';
    $('hubProtocol').value = '';
    updateHub();
  }
  function renderTierChips() {
    var rec = $('tiersRecommended'), pool = $('tiersPools');
    clear(rec); clear(pool);
    Object.keys(TIERS).forEach(function (id) {
      var tier = TIERS[id];
      var count = tierCount(id);
      var chip = h('button', {
        type: 'button',
        class: 'chip' + (tier.tested ? '' : ' untested'),
        'aria-pressed': S.sel.kind === 'tier' && S.sel.id === id ? 'true' : 'false',
        onclick: function () { selectTier(id); }
      }, [t(tier.label), count === null ? null : h('span', { class: 'chip-n', text: num(count) })]);
      (tier.group === 'rec' ? rec : pool).appendChild(chip);
    });
  }
  function renderFormats(available) {
    var box = $('formats');
    clear(box);
    FORMATS.forEach(function (f) {
      box.appendChild(h('button', {
        type: 'button',
        class: 'fmt',
        'aria-pressed': S.format === f.id ? 'true' : 'false',
        disabled: available[f.id] ? null : true,
        onclick: function () { S.pref = f.id; store('format', f.id); updateHub(); }
      }, [h('strong', { text: t(f.label) }), h('small', { text: t(f.desc) })]));
    });
  }
  function appLink(code, name, plat, href) {
    return h('a', { class: 'app-link', href: href, rel: 'noopener' }, [
      h('span', { class: 'app-ic', 'aria-hidden': 'true', text: code }),
      h('span', null, [name, h('small', { text: plat })])
    ]);
  }
  /* Deep-link formats — each one checked against the app's own source code:
   *   v2rayNG    v2rayng://install-sub?url=<enc>#<name>            UrlSchemeActivity.kt
   *   Hiddify    hiddify://import/<url>#<name>                     test/utils/link_parsers_test.dart
   *   Clash Meta clash://install-config?url=<enc>&name=<enc>       ExternalControlActivity.kt
   *   sing-box   sing-box://import-remote-profile?url=<enc>#<name> experimental/libbox/remote_profile.go */
  function renderApps(files, profile) {
    var box = $('appLinks');
    clear(box);
    var enc = encodeURIComponent;
    var sub = files.base64 || files.txt;
    if (sub) {
      var su = urlOf(sub, S.mirror);
      box.appendChild(appLink('NG', 'v2rayNG', t('platAndroid'), 'v2rayng://install-sub?url=' + enc(su) + '#' + enc(profile)));
      box.appendChild(appLink('HI', 'Hiddify', t('platMulti'), 'hiddify://import/' + su + '#' + enc(profile)));
    }
    if (files.clash) {
      box.appendChild(appLink('CM', 'Clash Meta', t('platAndroid'), 'clash://install-config?url=' + enc(urlOf(files.clash, S.mirror)) + '&name=' + enc(profile)));
    }
    if (files.singbox) {
      box.appendChild(appLink('SB', 'sing-box', t('platMulti'), 'sing-box://import-remote-profile?url=' + enc(urlOf(files.singbox, S.mirror)) + '#' + enc(profile)));
    }
  }
  function updateHub() {
    var files = filesFor(S.sel);
    // S.pref is what the user picked; S.format is what this list can serve.
    S.format = files[S.pref] ? S.pref : (files.base64 ? 'base64' : 'txt');
    renderTierChips();
    renderFormats(files);
    $('hubCountry').classList.toggle('active', S.sel.kind === 'country');
    $('hubProtocol').classList.toggle('active', S.sel.kind === 'protocol');

    var path = files[S.format];
    var url = path ? urlOf(path, S.mirror) : '';
    var count = selectionCount(S.sel);
    $('resName').textContent = selectionName(S.sel);
    $('resCount').textContent = count === null ? '' : t('configs', { n: num(count) });
    $('tierDesc').textContent = selectionDesc(S.sel);
    $('subUrl').textContent = url || '—';
    var open = $('openSub');
    if (url) { open.setAttribute('href', url); open.removeAttribute('aria-disabled'); }
    else { open.setAttribute('href', '#hub'); open.setAttribute('aria-disabled', 'true'); }
    $('copySub').disabled = !url;
    if (url) renderQr($('subQr'), url); else clear($('subQr'));
    renderApps(files, profileName(S.sel));
  }
  function wireHub() {
    $('copySub').addEventListener('click', function () {
      var url = $('subUrl').textContent;
      if (isHttpUrl(url)) copyWithFeedback(url);
    });
    var mt = $('mirrorToggle');
    mt.checked = S.mirror;
    mt.addEventListener('change', function () {
      S.mirror = mt.checked;
      store('mirror', S.mirror ? '1' : '0');
      updateHub();
      renderCountries();
    });
    $('hubCountry').addEventListener('change', function (ev) {
      var c = findCountry(ev.target.value);
      if (c) { pickCountry(c); } else { selectTier('verified'); }
    });
    $('hubProtocol').addEventListener('change', function (ev) {
      var id = ev.target.value;
      if (PROTO_KEY.test(id)) { S.sel = { kind: 'protocol', id: id }; $('hubCountry').value = ''; updateHub(); }
      else selectTier('verified');
    });
  }
  function findCountry(code) {
    var list = S.countries || [];
    for (var i = 0; i < list.length; i++) if (list[i].code === code) return list[i];
    return null;
  }
  function pickCountry(c) {
    S.sel = { kind: 'country', code: c.code, name: c.name, flag: c.flag, file: c.file, count: c.count };
    $('hubCountry').value = c.code;
    $('hubProtocol').value = '';
    updateHub();
  }
  function fillHubSelects() {
    var hc = $('hubCountry'), hp = $('hubProtocol');
    while (hc.options.length > 1) hc.remove(1);
    (S.countries || []).forEach(function (c) {
      hc.appendChild(h('option', { value: c.code, text: c.flag + ' ' + c.name + ' · ' + num(c.count) }));
    });
    // Only protocols the pipeline actually published a file for.
    while (hp.options.length > 1) hp.remove(1);
    var pf = obj(dig(S.idx, ['protocol_files'])) || {};
    var counts = obj(dig(S.idx, ['protocols'])) || {};
    Object.keys(pf).filter(function (k) { return PROTO_KEY.test(k); })
      .sort(function (a, b) { return (fin(counts[b]) || 0) - (fin(counts[a]) || 0); })
      .forEach(function (k) {
        hp.appendChild(h('option', { value: k, text: k.toUpperCase() + ' · ' + num(counts[k]) }));
      });
    if (S.sel.kind === 'country') hc.value = S.sel.code;
    if (S.sel.kind === 'protocol') hp.value = S.sel.id;
  }

  /* ── overview + freshness ─────────────────────────────────────────── */
  function relAge(ms) {
    var m = Math.max(1, Math.round(ms / 60000));
    if (m < 60) return t('min', { n: num(m) });
    var hrs = Math.floor(m / 60), rem = m % 60;
    return rem ? t('hr', { n: num(hrs) }) + ' ' + t('min', { n: num(rem) }) : t('hr', { n: num(hrs) });
  }
  function fmtTime(ms) {
    try {
      return new Intl.DateTimeFormat(LANG, { hour: '2-digit', minute: '2-digit', day: 'numeric', month: 'short' }).format(new Date(ms));
    } catch (e) { return new Date(ms).toISOString(); }
  }
  /* "stale" is judged against the repository's own advertised interval, the
     same thresholds the previous dashboard used: >1.5x late, >3x broken. */
  function renderFreshness() {
    var idx = S.idx;
    if (!idx) return;
    var box = $('freshStatus');
    var upd = fin(idx.updated_at_unix);
    var iv = fin(idx.update_interval_minutes);
    var now = Date.now();
    var state = 'fresh', msg;
    if (upd !== null && upd > 0) {
      var age = now - upd * 1000;
      var ageText = age < 45000 ? t('now') : t('ago', { n: relAge(age) });
      if (iv !== null && iv > 0) {
        var ivMs = iv * 60000;
        state = age > ivMs * 3 ? 'broken' : (age > ivMs * 1.5 ? 'stale' : 'fresh');
      }
      // A late copy fetched from jsDelivr is the mirror's cache, not a stalled
      // pipeline — say so instead of blaming the build.
      msg = S.mirrored && state !== 'fresh' ? t('mirrorStale', { age: ageText }) : t(state, { age: ageText });
      $('updatedAt').textContent = fmtTime(upd * 1000);
      $('updatedAt').setAttribute('datetime', new Date(upd * 1000).toISOString());
    } else {
      msg = t('unknownAge');
    }
    var eta = str(idx.next_update_eta);
    var etaMs = eta ? Date.parse(eta) : NaN;
    if (isFinite(etaMs)) {
      $('nextAt').textContent = etaMs > now ? t('inT', { n: relAge(etaMs - now) }) : t('overdue');
      $('nextAt').setAttribute('datetime', new Date(etaMs).toISOString());
    }
    if (S.mirrored && state === 'fresh') msg += t('mirrored');
    box.setAttribute('data-state', state);
    $('freshText').textContent = msg;
  }
  function renderOverview() {
    var idx = S.idx, health = S.health;
    $('sVerified').textContent = num(dig(idx, ['cascade_categories', 'verified', 'unique']));
    $('sFast').textContent = num(dig(idx, ['cascade_categories', 'fast', 'unique']));
    $('sSecure').textContent = num(dig(idx, ['cascade_categories', 'secure', 'unique']));
    $('sCountries').textContent = num(dig(idx, ['countries', 'count']));
    $('sPool').textContent = num(dig(idx, ['categories', 'all', 'unique']));
    var ms = fin(dig(health, ['cascade', 'buckets', 'fast_threshold_ms']));
    if (ms !== null) $('sFastFoot').textContent = t('fastFoot', { ms: num(ms) });
    var loc = str(dig(health, ['cascade', 'exit_country', 'loc']));
    var colo = str(dig(health, ['cascade', 'exit_country', 'colo']));
    if (loc && /^[A-Z]{2}$/.test(loc)) {
      var label = flagOf(loc) + ' ' + countryName(loc, loc) + (colo && /^[A-Z]{3}$/.test(colo) ? ' · ' + colo : '');
      $('runnerLoc').textContent = t('runner', { loc: label });
    }
    renderFreshness();
  }

  /* ── config parsing (explorer) ────────────────────────────────────── */
  var SCHEMES = { vless: 'vless', vmess: 'vmess', trojan: 'trojan', ss: 'ss', hysteria2: 'hysteria2', hy2: 'hysteria2', socks: 'socks', tuic: 'tuic', ssr: 'ssr' };
  var PROTO_LABEL = { vless: 'VLESS', vmess: 'VMess', trojan: 'Trojan', ss: 'SS', hysteria2: 'HY2', socks: 'SOCKS', tuic: 'TUIC', ssr: 'SSR' };
  function b64decode(s) {
    var clean = String(s).replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
    while (clean.length % 4) clean += '=';
    var bin = atob(clean);
    try {
      var bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return new TextDecoder('utf-8').decode(bytes);
    } catch (e) { return bin; }
  }
  function safeDecode(s) { try { return decodeURIComponent(s); } catch (e) { return s; } }
  function splitHostPort(hp) {
    var m = /^\[([0-9a-fA-F:.]+)\]:(\d{1,5})$/.exec(hp);
    if (m) return { host: m[1], port: m[2], v6: true };
    m = /^([^:@/?#\s[\]]+):(\d{1,5})$/.exec(hp);
    return m ? { host: m[1], port: m[2], v6: false } : null;
  }
  function parseQuery(q) {
    var out = {};
    (q || '').split('&').forEach(function (kv) {
      if (!kv) return;
      var i = kv.indexOf('=');
      out[safeDecode(i < 0 ? kv : kv.slice(0, i)).toLowerCase()] = safeDecode(i < 0 ? '' : kv.slice(i + 1));
    });
    return out;
  }
  function parseConfig(line) {
    var m = /^([a-z0-9]+):\/\//i.exec(line);
    if (!m) return null;
    var scheme = SCHEMES[m[1].toLowerCase()];
    if (!scheme) return null;
    var rest = line.slice(m[0].length);
    var hashAt = rest.indexOf('#');
    var remark = hashAt >= 0 ? safeDecode(rest.slice(hashAt + 1)) : '';
    if (hashAt >= 0) rest = rest.slice(0, hashAt);
    var c = { line: line, proto: scheme, host: null, port: null, v6: false, sec: 'unset', net: 'tcp', sni: '', cc: '', remark: remark, cipher: '' };
    try {
      if (scheme === 'vmess') {
        var j = JSON.parse(b64decode(rest));
        c.host = str(j.add) || null;
        c.port = (typeof j.port === 'number' || typeof j.port === 'string') ? String(j.port) : null;
        c.sec = str(j.tls) === 'tls' ? 'tls' : 'none';
        c.net = str(j.net) || 'tcp';
        c.sni = str(j.sni) || str(j.host) || '';
        if (str(j.ps)) c.remark = j.ps;
      } else {
        var qAt = rest.indexOf('?');
        var q = qAt >= 0 ? parseQuery(rest.slice(qAt + 1)) : {};
        var auth = (qAt >= 0 ? rest.slice(0, qAt) : rest).replace(/\/+$/, '');
        var at = auth.lastIndexOf('@');
        var userinfo = at >= 0 ? auth.slice(0, at) : '';
        var hp = splitHostPort(at >= 0 ? auth.slice(at + 1) : auth);
        if (!hp && scheme === 'ss' && at < 0) {
          var dec = b64decode(auth);           // legacy ss://base64(method:pass@host:port)
          var at2 = dec.lastIndexOf('@');
          userinfo = dec.slice(0, at2);
          hp = splitHostPort(dec.slice(at2 + 1));
          c.cipher = userinfo.split(':')[0];
        }
        if (hp) { c.host = hp.host; c.port = hp.port; c.v6 = hp.v6; }
        c.sni = q.sni || q.peer || q.host || '';
        if (scheme === 'ss') {
          if (!c.cipher && userinfo) {
            var u = safeDecode(userinfo);
            if (u.indexOf(':') > 0) c.cipher = u.split(':')[0];
            else { try { c.cipher = b64decode(u).split(':')[0]; } catch (e) { c.cipher = ''; } }
          }
          c.sec = 'cipher';
          c.net = q.plugin ? 'plugin' : 'tcp';
        } else if (scheme === 'hysteria2' || scheme === 'tuic') {
          c.sec = 'tls'; c.net = 'quic';
        } else {
          var s = (q.security || '').toLowerCase();
          if (s === 'reality' || s === 'tls' || s === 'none') c.sec = s;
          else if (s === 'xtls') c.sec = 'tls';
          else c.sec = scheme === 'trojan' ? 'unset' : 'none';
          c.net = (q.type || 'tcp').toLowerCase();
        }
      }
    } catch (e) { /* keep whatever parsed; the raw line is still copyable */ }
    var cc = /^([A-Z]{2})\s/.exec(c.remark || '');
    c.cc = cc ? cc[1] : '';
    if (!/^[a-z0-9-]{1,16}$/.test(c.net)) c.net = '—';
    if (c.cipher && !/^[A-Za-z0-9_.-]{1,40}$/.test(c.cipher)) c.cipher = '';
    c.search = [c.proto, PROTO_LABEL[c.proto], c.host, c.port, c.sni, c.remark, c.net, c.sec, c.cipher, c.cc].join(' ').toLowerCase();
    return c;
  }
  function secLabel(c) {
    if (c.sec === 'cipher') return c.cipher || t('secCipher');
    if (c.sec === 'unset') return t('secUnset');
    if (c.sec === 'none') return t('noTls');
    if (c.sec === 'reality') return 'Reality';
    return c.net === 'quic' ? 'QUIC · TLS' : 'TLS';
  }
  function secFilterLabel(k) {
    return { reality: 'Reality', tls: 'TLS', none: t('noTls'), cipher: t('secCipher'), unset: t('secUnset') }[k] || k;
  }

  /* ── explorer ─────────────────────────────────────────────────────── */
  function loadConfigs() {
    S.configsFailed = false;
    $('exState').textContent = t('waitingJs');
    renderSkeleton();
    return getFile('verified/configs.txt', false).then(function (r) {
      var lines = String(r.body).split(/\r?\n/);
      var list = [];
      for (var i = 0; i < lines.length; i++) {
        var L = lines[i].trim();
        if (!L || L.charAt(0) === '#' || L.slice(0, 2) === '//') continue;
        var c = parseConfig(L);
        if (c) { c.rank = list.length + 1; list.push(c); }
      }
      S.configs = list;
      $('exState').textContent = t(r.mirrored ? 'readyMirror' : 'ready');
      fillExplorerFilters();
      applyFilters();
    }).catch(function () {
      S.configs = null;
      S.configsFailed = true;
      $('exState').textContent = t('unavailable');
      renderExplorer();
    });
  }
  function renderSkeleton() {
    var list = $('exList');
    clear(list);
    $('exEmpty').hidden = true;
    for (var i = 0; i < 6; i++) {
      list.appendChild(h('li', { class: 'cfg-row', 'aria-hidden': 'true' }, [
        h('span', { class: 'skeleton', style: 'width:22px' }),
        h('span', { class: 'skeleton', style: 'width:60px' }),
        h('span', { class: 'skeleton', style: 'width:80%' }),
        h('span', { class: 'cfg-meta' }, [h('span', { class: 'skeleton', style: 'width:90px' })]),
        h('span')
      ]));
    }
  }
  function fillSelect(sel, entries) {
    var keep = sel.value;
    while (sel.options.length > 1) sel.remove(1);
    entries.forEach(function (e) { sel.appendChild(h('option', { value: e.value, text: e.text })); });
    sel.value = keep;
    if (sel.value !== keep) sel.value = '';
  }
  function countBy(list, key) {
    var m = {};
    list.forEach(function (c) { var k = key(c); if (k) m[k] = (m[k] || 0) + 1; });
    return Object.keys(m).sort(function (a, b) { return m[b] - m[a]; }).map(function (k) { return { k: k, n: m[k] }; });
  }
  function fillExplorerFilters() {
    var list = S.configs || [];
    fillSelect($('exProtocol'), countBy(list, function (c) { return c.proto; }).map(function (e) {
      return { value: e.k, text: (PROTO_LABEL[e.k] || e.k) + ' · ' + num(e.n) };
    }));
    fillSelect($('exCountry'), countBy(list, function (c) { return c.cc; }).map(function (e) {
      return { value: e.k, text: flagOf(e.k) + ' ' + countryName(e.k, e.k) + ' · ' + num(e.n) };
    }));
    fillSelect($('exSecurity'), countBy(list, function (c) { return c.sec; }).map(function (e) {
      return { value: e.k, text: secFilterLabel(e.k) + ' · ' + num(e.n) };
    }));
  }
  function applyFilters() {
    var list = S.configs || [];
    var q = ($('exSearch').value || '').trim().toLowerCase();
    var p = $('exProtocol').value, cc = $('exCountry').value, sec = $('exSecurity').value;
    var terms = q ? q.split(/\s+/) : [];
    S.filtered = list.filter(function (c) {
      if (p && c.proto !== p) return false;
      if (cc && c.cc !== cc) return false;
      if (sec && c.sec !== sec) return false;
      for (var i = 0; i < terms.length; i++) if (c.search.indexOf(terms[i]) < 0) return false;
      return true;
    });
    S.shown = PAGE_SIZE;
    renderExplorer();
  }
  function hostLabel(c) {
    if (!c.host) return '—';
    return (c.v6 ? '[' + c.host + ']' : c.host) + (c.port ? ':' + c.port : '');
  }
  function configRow(c) {
    var name = (PROTO_LABEL[c.proto] || c.proto) + ' · ' + hostLabel(c);
    var copyBtn = h('button', { type: 'button', class: 'mini', 'aria-label': t('copy') + ' — ' + name }, [h('span', { 'aria-hidden': 'true', text: '⧉' }), t('copy')]);
    copyBtn.addEventListener('click', function () { copyWithFeedback(c.line, copyBtn); });
    var qrBtn = h('button', { type: 'button', class: 'mini', 'aria-label': t('qr') + ' — ' + name, text: t('qr') });
    qrBtn.addEventListener('click', function () { openQrDialog(c.line, name); });
    var subline = c.sni && c.sni !== c.host ? 'SNI ' + c.sni : '';
    return h('li', { class: 'cfg-row' }, [
      h('span', { class: 'cfg-rank', text: num(c.rank) }),
      h('span', { class: 'proto p-' + c.proto, text: PROTO_LABEL[c.proto] || c.proto }),
      h('div', { class: 'cfg-server' }, [h('code', { dir: 'ltr', text: hostLabel(c) }), subline ? h('small', { dir: 'ltr', text: subline }) : null]),
      h('div', { class: 'cfg-meta' }, [
        h('span', { class: 'cfg-loc' }, [h('span', { class: 'flag', 'aria-hidden': 'true', text: flagOf(c.cc) }), c.cc ? countryName(c.cc, c.cc) : '—']),
        h('span', { class: 'sec s-' + c.sec, text: secLabel(c) }),
        h('span', { class: 'cfg-net', dir: 'ltr', text: c.net })
      ]),
      h('div', { class: 'cfg-actions' }, [copyBtn, qrBtn])
    ]);
  }
  function renderExplorer() {
    var list = $('exList'), empty = $('exEmpty'), more = $('exMore'), retry = $('exRetry');
    clear(list);
    if (S.configsFailed) {
      empty.hidden = false;
      $('exEmptyTitle').textContent = t('failedList');
      $('exEmptyDesc').textContent = t('failed');
      retry.textContent = t('retry');
      retry.setAttribute('data-mode', 'retry');
      more.hidden = true;
      $('exCount').textContent = num(0);
      $('exPage').textContent = '—';
      $('exCopy').disabled = true;
      return;
    }
    retry.setAttribute('data-mode', 'clear');
    retry.textContent = t('clearJs');
    $('exEmptyTitle').textContent = t('emptyTitleJs');
    $('exEmptyDesc').textContent = t('emptyDescJs');
    var rows = S.filtered;
    $('exCount').textContent = num(rows.length);
    $('exCopy').disabled = rows.length === 0;
    empty.hidden = rows.length !== 0;
    var n = Math.min(S.shown, rows.length);
    var frag = document.createDocumentFragment();
    for (var i = 0; i < n; i++) frag.appendChild(configRow(rows[i]));
    list.appendChild(frag);
    more.hidden = n >= rows.length;
    $('exPage').textContent = t('showing', { a: num(n), b: num(rows.length) });
  }
  function wireExplorer() {
    var timer = null;
    $('exSearch').addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(applyFilters, 140); });
    ['exProtocol', 'exCountry', 'exSecurity'].forEach(function (id) { $(id).addEventListener('change', applyFilters); });
    function clearAll() {
      $('exSearch').value = ''; $('exProtocol').value = ''; $('exCountry').value = ''; $('exSecurity').value = '';
      applyFilters();
    }
    $('exClear').addEventListener('click', clearAll);
    $('exRetry').addEventListener('click', function () {
      if ($('exRetry').getAttribute('data-mode') === 'retry') loadConfigs(); else clearAll();
    });
    $('exMore').addEventListener('click', function () { S.shown += PAGE_SIZE * 2; renderExplorer(); });
    $('exCopy').addEventListener('click', function () {
      if (!S.filtered.length) return;
      var text = S.filtered.map(function (c) { return c.line; }).join('\n') + '\n';
      copyWithFeedback(text, null, t('copiedN', { n: num(S.filtered.length) }));
    });
  }

  /* ── countries ────────────────────────────────────────────────────── */
  function normaliseCountries(raw) {
    var arr = Array.isArray(dig(raw, ['countries'])) ? raw.countries : [];
    var out = [];
    arr.forEach(function (c) {
      if (!obj(c)) return;
      var code = str(c.code), file = str(c.file), count = fin(c.count);
      if (!code || !/^[A-Z]{2}$/.test(code) || !file || !COUNTRY_FILE.test(file) || count === null || count < 1) return;
      out.push({ code: code, file: file, count: count, flag: flagOf(code), name: countryName(code, str(c.name) || code) });
    });
    out.sort(function (a, b) { return b.count - a.count; });
    return out;
  }
  function renderCountries() {
    var grid = $('ctGrid');
    clear(grid);
    var list = S.countries;
    if (!list) { $('ctNote').textContent = S.countriesFailed ? t('failed') : ''; return; }
    var q = ($('ctSearch').value || '').trim().toLowerCase();
    var max = list.length ? list[0].count : 1;
    list.filter(function (c) {
      return !q || c.name.toLowerCase().indexOf(q) >= 0 || c.code.toLowerCase().indexOf(q) >= 0;
    }).forEach(function (c) {
      var url = urlOf(c.file, S.mirror);
      var copyBtn = h('button', { type: 'button', class: 'mini', 'aria-label': t('copyCountry') + ' — ' + c.name }, [h('span', { 'aria-hidden': 'true', text: '⧉' }), t('copyCountry')]);
      copyBtn.addEventListener('click', function () { copyWithFeedback(url, copyBtn); });
      var qrBtn = h('button', { type: 'button', class: 'mini', 'aria-label': t('qr') + ' — ' + c.name, text: t('qr') });
      qrBtn.addEventListener('click', function () { openQrDialog(url, c.flag + ' ' + c.name); });
      var useBtn = h('button', { type: 'button', class: 'mini', 'aria-label': t('use') + ' — ' + c.name, text: t('use') });
      useBtn.addEventListener('click', function () {
        pickCountry(c);
        var hub = $('hub');
        if (hub && hub.scrollIntoView) hub.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
      grid.appendChild(h('article', { class: 'country' }, [
        h('div', { class: 'country-top' }, [
          h('span', { class: 'flag', 'aria-hidden': 'true', text: c.flag }),
          h('div', null, [h('h3', { class: 'country-name', text: c.name }), h('div', { class: 'country-n', text: t('configs', { n: num(c.count) }) })])
        ]),
        h('div', { class: 'country-bar', 'aria-hidden': 'true' }, [h('span', { style: 'width:' + Math.max(3, Math.round(c.count / max * 100)) + '%' })]),
        h('div', { class: 'country-actions' }, [copyBtn, qrBtn, useBtn])
      ]));
    });
    var total = list.reduce(function (a, c) { return a + c.count; }, 0);
    $('ctNote').textContent = t('countryNote', { n: num(list.length), c: num(total), m: S.countriesMethod });
  }

  /* ── proof ────────────────────────────────────────────────────────── */
  function renderFunnel() {
    var box = $('funnel');
    clear(box);
    var idx = S.idx, L = dig(S.health, ['cascade', 'layers']);
    var steps = [
      { k: 'fRaw', v: fin(dig(idx, ['categories', 'all', 'total_fetched'])) },
      { k: 'fUnique', v: fin(dig(idx, ['categories', 'all', 'unique'])) },
      { k: 'fParse', v: fin(dig(L, ['l0_l1', 'out'])) },
      { k: 'fTcp', v: fin(dig(L, ['l2', 'out'])) },
      { k: 'fEver', v: fin(dig(L, ['l3', 'ever_ok'])) },
      { k: 'fStable', v: fin(dig(L, ['l3', 'stable'])) }
    ];
    var top = steps[0].v || 0;
    steps.forEach(function (s, i) {
      var w = top > 0 && s.v !== null ? Math.max(0.6, Math.min(100, s.v / top * 100)) : 0;
      box.appendChild(h('div', { class: 'f-row' + (i === steps.length - 1 ? ' final' : '') }, [
        h('span', { class: 'f-label', text: t(s.k) }),
        h('span', { class: 'f-track', 'aria-hidden': 'true' }, [h('span', { class: 'f-fill', style: 'width:' + w.toFixed(2) + '%' })]),
        h('span', { class: 'f-num', text: num(s.v) })
      ]));
    });
    var stable = steps[5].v;
    $('funnelTag').textContent = stable !== null && top > 0 ? t('ofPool', { p: pct(stable / top * 100, 1) + '%' }) : '—';
    var flaky = fin(dig(L, ['l3', 'flaky_pct']));
    $('funnelNote').textContent = flaky !== null ? t('funnelNote', { f: pct(flaky, 1) }) : '';
  }
  function renderProtocols() {
    var box = $('protoBars');
    clear(box);
    var p = obj(dig(S.idx, ['protocols'])) || {};
    var rows = Object.keys(p).filter(function (k) { return PROTO_KEY.test(k) && (fin(p[k]) || 0) > 0; })
      .sort(function (a, b) { return p[b] - p[a]; });
    var max = rows.length ? p[rows[0]] : 1;
    rows.forEach(function (k) {
      box.appendChild(h('div', { class: 'b-row' }, [
        h('span', { class: 'b-name', dir: 'ltr', text: k }),
        h('span', { class: 'b-track', 'aria-hidden': 'true' }, [h('span', { class: 'b-fill', style: 'width:' + Math.max(1, p[k] / max * 100).toFixed(2) + '%' })]),
        h('span', { class: 'b-num', text: num(p[k]) })
      ]));
    });
    if (!rows.length) box.appendChild(h('p', { class: 'panel-note', text: t('noData') }));
  }
  function renderSources() {
    var body = $('srcBody');
    clear(body);
    var list = Array.isArray(dig(S.health, ['sources'])) ? S.health.sources : [];
    var order = { ok: 0, empty: 1, fail: 2, disabled: 3 };
    list = list.filter(obj).slice().sort(function (a, b) {
      var oa = order[a.status] !== undefined ? order[a.status] : 9;
      var ob = order[b.status] !== undefined ? order[b.status] : 9;
      return oa - ob || (fin(b.count) || 0) - (fin(a.count) || 0);
    });
    list.forEach(function (s) {
      var name = str(s.name) || '—';
      var status = /^(ok|disabled|empty|fail)$/.test(s.status) ? s.status : 'fail';
      var nameCell = isHttpUrl(s.url)
        ? h('a', { href: s.url, target: '_blank', rel: 'noopener noreferrer', dir: 'ltr', title: s.url, text: name })
        : h('span', { dir: 'ltr', text: name });
      var lat = fin(s.latency_ms);
      body.appendChild(h('tr', { class: status === 'disabled' ? 'disabled' : null }, [
        h('td', null, [nameCell]),
        h('td', { text: str(s.tier) || '—' }),
        h('td', null, [h('span', { class: 'badge ' + status, text: t('st' + status.charAt(0).toUpperCase() + status.slice(1)) })]),
        h('td', { class: 'num', text: num(s.count) }),
        h('td', { class: 'num', text: lat === null ? '—' : num(lat) + ' ms' })
      ]));
    });
    var sum = obj(dig(S.health, ['summary']));
    $('srcTag').textContent = sum ? t('srcTag', { ok: num(sum.ok), d: num(sum.disabled), n: num(sum.total) }) : '—';
  }

  /* ── load orchestration ───────────────────────────────────────────── */
  var loading = null;
  function loadAll() {
    if (loading) return loading;
    var btn = $('refreshBtn');
    btn.setAttribute('aria-busy', 'true');
    if (!S.idx) { $('freshStatus').setAttribute('data-state', 'loading'); $('freshText').textContent = t('loading'); }

    var pIdx = getFile('index.json', true).then(function (r) {
      if (!obj(r.body)) throw new Error('index.json is not an object');
      S.idx = r.body; S.mirrored = r.mirrored;
      return true;
    }).catch(function () { return false; });
    var pHealth = getFile('health.json', true).then(function (r) {
      if (obj(r.body)) S.health = r.body;
    }).catch(function () { /* optional: panels fall back to "—" */ });
    var pCountries = getFile('Countries/index.json', true).then(function (r) {
      S.countries = normaliseCountries(r.body);
      S.countriesMethod = /DB-IP/i.test(str(dig(r.body, ['location_method'])) || '') ? 'GeoIP (DB-IP)' : 'GeoIP';
      S.countriesFailed = false;
    }).catch(function () { S.countriesFailed = !S.countries; });

    loading = Promise.all([pIdx, pHealth, pCountries]).then(function (res) {
      loading = null;
      btn.removeAttribute('aria-busy');
      if (!res[0] && !S.idx) {
        $('freshStatus').setAttribute('data-state', 'error');
        $('freshText').textContent = t('failed');
      } else {
        renderOverview();
      }
      fillHubSelects();
      updateHub();
      renderCountries();
      renderFunnel();
      renderProtocols();
      renderSources();
    });
    return loading;
  }

  function init() {
    wireHub();
    wireExplorer();
    var dlg = $('qrDialog');
    if (dlg) dlg.addEventListener('click', function (ev) { if (ev.target === dlg && dlg.close) dlg.close(); });
    $('ctSearch').addEventListener('input', renderCountries);
    $('refreshBtn').addEventListener('click', function () {
      var before = S.idx && S.idx.updated_at_unix;
      loadAll().then(function () {
        if (!S.configs || (S.idx && S.idx.updated_at_unix !== before)) loadConfigs();
      });
    });
    updateHub();
    loadAll();
    loadConfigs();
    setInterval(renderFreshness, 30000);
    setInterval(function () {
      if (document.hidden) return;
      var before = S.idx && S.idx.updated_at_unix;
      loadAll().then(function () {
        if (S.idx && before && S.idx.updated_at_unix !== before) loadConfigs();
      });
    }, AUTO_REFRESH_MS);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();

})();
