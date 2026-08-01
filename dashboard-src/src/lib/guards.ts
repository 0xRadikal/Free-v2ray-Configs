/* ─────────────────────────────────────────────────────────────────────────────
 * Untrusted-input narrowing layer.
 *
 * Ported 1:1 from the previous vanilla docs/app.js. The reasoning is preserved
 * because it was earned, not assumed: index.json and health.json arrive from a
 * CDN, so every field in them is untrusted input.
 *
 *   • `total += s.count` becomes string concatenation the moment one count is
 *     published as "250", producing "10025050", which renders as "—":
 *     one bad field destroys a whole aggregate.
 *   • `Math.max(m, v)` over one non-numeric value yields NaN, so `max > 0` is
 *     false and every bar on the page collapses to 0% width.
 *   • a bare `if (count)` treats the string "0" as truthy.
 *
 * So numbers are narrowed once, here. `fin` answers "is this a usable number?"
 * and returns null when it is not — deliberately distinct from 0, because
 * "missing" and "zero" are different claims. `n0` is for arithmetic that must
 * not propagate the difference.
 * ───────────────────────────────────────────────────────────────────────────── */

const nf = new Intl.NumberFormat('en-US');

/** Format a number, or "—" when it is not a usable one. */
export function num(v: unknown): string {
  return typeof v === 'number' && isFinite(v) ? nf.format(v) : '—';
}

/** null when not a usable number — deliberately distinct from 0. */
export function fin(v: unknown): number | null {
  return typeof v === 'number' && isFinite(v) ? v : null;
}

/** 0 when not a usable number. For arithmetic only. */
export function n0(v: unknown): number {
  const x = fin(v);
  return x === null ? 0 : x;
}

/** A published field that is not a string would interpolate as "[object Object]". */
export function str(v: unknown, dflt = '—'): string {
  return typeof v === 'string' && v ? v : dflt;
}

/**
 * A "record" is what both published files are supposed to be: a plain JSON
 * object. Array.isArray is checked explicitly, because typeof [] is "object"
 * and an array would otherwise pass for a document.
 */
export function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function pct(part: unknown, whole: unknown): number | null {
  if (typeof part !== 'number' || typeof whole !== 'number' || whole <= 0) return null;
  return (part / whole) * 100;
}

export function fmtPct(v: number | null): string {
  return v === null || !isFinite(v) ? '—' : `${v.toFixed(1)}%`;
}

/**
 * Only ever put a vetted absolute http(s) URL into an href. A `javascript:`
 * string arriving in a `url` field must not become a clickable link.
 */
export function safeHref(url: unknown): string | null {
  if (typeof url !== 'string') return null;
  try {
    const u = new URL(url, location.href);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : null;
  } catch {
    return null;
  }
}

export function relativeAge(ms: number): string {
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

export function fmtSeconds(v: unknown): string {
  if (typeof v !== 'number' || !isFinite(v)) return '—';
  if (v < 60) return `${v.toFixed(v < 10 ? 2 : 1)}s`;
  const m = Math.floor(v / 60);
  return `${m}m ${Math.round(v % 60)}s`;
}

/** Countdown to an ISO instant. Returns null when unparseable or already past. */
export function countdownTo(iso: unknown): string | null {
  if (typeof iso !== 'string') return null;
  const t = Date.parse(iso);
  if (!isFinite(t)) return null;
  const left = t - Date.now();
  if (left <= 0) return null;
  const s = Math.floor(left / 1000);
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, '0')}`;
}

/** An upstream failure message can be an entire HTML error page. */
export const ERROR_MAX_CHARS = 160;

/** The per_run_ok array arrives from a CDN; its length is not ours to assume. */
export const MAX_RUNS_SHOWN = 24;

/**
 * Truncating is necessary — an upstream error can be a whole HTML page — but
 * truncating *silently* is not acceptable: a cut-off error reads as a complete
 * one. So the cut is marked and the full text is returned alongside it.
 */
export function clipError(v: unknown): { shown: string; full: string; clipped: boolean } | null {
  if (v === undefined || v === null || v === '') return null;
  const full = String(v);
  const clipped = full.length > ERROR_MAX_CHARS;
  return { shown: clipped ? `${full.slice(0, ERROR_MAX_CHARS - 1)}\u2026` : full, full, clipped };
}

/**
 * Min/max without spreading. Spreading an array into a call passes one argument
 * per element, so the array's length becomes an argument count — and this array
 * arrives from a CDN. Measured previously: 100,000 elements works, 200,000
 * throws "RangeError: Maximum call stack size exceeded", aborting the render.
 * reduce() has no such ceiling.
 */
export function minMax(arr: number[]): { lo: number; hi: number } | null {
  if (!arr.length) return null;
  const lo = arr.reduce((m, v) => Math.min(m, v), Infinity);
  const hi = arr.reduce((m, v) => Math.max(m, v), -Infinity);
  return { lo, hi };
}
