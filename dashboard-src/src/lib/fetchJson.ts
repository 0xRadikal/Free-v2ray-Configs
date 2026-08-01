/* ─────────────────────────────────────────────────────────────────────────────
 * Runtime data access. Ported 1:1 from the previous docs/app.js.
 *
 * Why absolute raw URLs instead of a relative "../index.json": GitHub Pages
 * serves the /docs folder AS the site root, so the repository root is not
 * reachable from the published site at all. The mirror is used only as a
 * fallback, because jsDelivr can lag a branch ref by up to 12 hours.
 * ───────────────────────────────────────────────────────────────────────────── */

export const REPO = '0xRadikal/Free-v2ray-Configs';
export const BRANCH = 'main';
export const PRIMARY = `https://raw.githubusercontent.com/${REPO}/${BRANCH}`;
export const MIRROR = `https://cdn.jsdelivr.net/gh/${REPO}@${BRANCH}`;

/**
 * Per-attempt timeout. Without one, a request that is throttled rather than
 * refused never settles: the primary attempt hangs forever, the mirror fallback
 * is never reached, and the page sits on "Fetching live metadata…" indefinitely
 * with no error shown. That failure mode is likely for this audience, whose
 * networks are more often slowed than cleanly blocked.
 */
export const FETCH_TIMEOUT_MS = 12000;

/**
 * AbortSignal.timeout() is the standard expression of this, but it is still
 * feature-detected: this page's audience is disproportionately on old and
 * locked-down devices, and the fallback costs four lines. A missing
 * implementation degrades to "no timeout" rather than throwing.
 */
function timeoutSignal(ms: number): AbortSignal | undefined {
  try {
    if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
      return AbortSignal.timeout(ms);
    }
    if (typeof AbortController === 'function') {
      const ac = new AbortController();
      setTimeout(() => ac.abort(), ms);
      return ac.signal;
    }
  } catch {
    /* fall through to no signal */
  }
  return undefined;
}

export interface Fetched<T = unknown> {
  data: T;
  url: string;
  mirrored: boolean;
}

/**
 * Sequential primary → mirror, deliberately NOT Promise.any().
 *
 * Racing them would hide a slow primary behind the mirror, but the mirror can
 * lag the branch by up to 12 hours, so a race would sometimes win with *stale*
 * data on a page whose entire purpose is reporting freshness.
 * Sequential-with-timeout is the correct trade here, not the lazy one.
 *
 * `bases` is injectable purely so the scenario harness can point the same code
 * at a local stub server; production always uses the defaults.
 */
export async function getJSON(
  path: string,
  bases: readonly string[] = [PRIMARY, MIRROR],
): Promise<Fetched> {
  // Cache-buster: raw.githubusercontent.com sends max-age=300, and this page is
  // about freshness, so a stale 5-minute copy would be actively misleading.
  const bust = `?_=${Date.now()}`;
  const mirrorBase = bases[1];
  let lastErr: unknown;
  for (const base of bases) {
    const url = `${base}/${path}${bust}`;
    try {
      const signal = timeoutSignal(FETCH_TIMEOUT_MS);
      const opts: RequestInit = { cache: 'no-store' };
      if (signal) opts.signal = signal;
      const res = await fetch(url, opts);
      if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
      const data = await res.json();
      return { data, url, mirrored: !!mirrorBase && url.startsWith(mirrorBase) };
    } catch (e) {
      lastErr =
        e && (e as Error).name === 'TimeoutError'
          ? new Error(`timed out after ${FETCH_TIMEOUT_MS} ms: ${url}`)
          : e;
    }
  }
  throw lastErr || new Error(`could not load ${path}`);
}

/**
 * Test hook. The scenario harness sets window.__DASH_BASES__ to redirect both
 * primary and mirror at a local stub. Absent in production, where the constants
 * above are used unchanged.
 */
export function resolveBases(): readonly string[] {
  const w = window as unknown as { __DASH_BASES__?: string[] };
  return Array.isArray(w.__DASH_BASES__) && w.__DASH_BASES__.length
    ? w.__DASH_BASES__
    : [PRIMARY, MIRROR];
}
