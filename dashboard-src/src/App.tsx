import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, GitBranch, RefreshCw, Send, ShieldCheck } from 'lucide-react';
import { getJSON, resolveBases, type Fetched } from '@/lib/fetchJson';
import { countdownTo, fin, isRecord, n0, num, relativeAge, str } from '@/lib/guards';
import type { HealthDoc, IndexDoc } from '@/lib/types';
import {
  CascadeSection,
  CategoriesSection,
  ConvertersSection,
  GeoSection,
  LinksSection,
  ProtocolsSection,
  ReleaseSection,
  SourcesSection,
  hasCascade,
  hasConverters,
  hasGeo,
  hasSources,
} from '@/sections';

type Freshness = 'fresh' | 'stale' | 'broken' | 'unknown';

interface Loaded {
  idx: IndexDoc;
  health: HealthDoc;
  mirrored: boolean;
  healthMissing: boolean;
  fetchedAt: number;
}

const NAV = [
  ['release', 'This release'],
  ['categories', 'Categories'],
  ['protocols', 'Protocols'],
  ['cascade', 'Verification'],
  ['converters', 'Conversion losses'],
  ['geo', 'Server locations'],
  ['sources', 'Source health'],
  ['links', 'Subscription links'],
] as const;

export default function App() {
  const [state, setState] = useState<Loaded | null>(null);
  /* `kind` separates "could not reach the file" from "reached it, but the bytes
     were not a usable document". Without it the banner blames the reader's
     network for what is actually a publishing fault — a claim the page is in no
     position to make, and one that sends people to debug the wrong thing. */
  const [error, setError] = useState<{
    which: string;
    message: string;
    kind: 'network' | 'payload';
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [now, setNow] = useState(() => Date.now());
  const [auto, setAuto] = useState(true);
  const busy = useRef(false);

  /* One ticker drives every relative time on the page. Separate intervals per
     component would drift apart and show two different "ages" at once. */
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const load = useCallback(async () => {
    if (busy.current) return;
    busy.current = true;
    setLoading(true);
    const bases = resolveBases();
    let idxRes: Fetched;
    try {
      idxRes = await getJSON('index.json', bases);
    } catch (e) {
      setError({
        which: 'index.json',
        message: e instanceof Error ? e.message : String(e),
        kind: 'network',
      });
      setState(null);
      setLoading(false);
      busy.current = false;
      return;
    }

    /* JSON.parse accepts "null", "42" and "[]" as complete documents, so a
       successful fetch does not mean a usable payload. Arrays are rejected too:
       typeof [] is "object", and an array would silently render as a dashboard
       of empty tables. */
    if (!isRecord(idxRes.data)) {
      setError({
        which: 'index.json',
        message: 'index.json did not contain a JSON object',
        kind: 'payload',
      });
      setState(null);
      setLoading(false);
      busy.current = false;
      return;
    }

    /* health.json is optional: the page is still useful without it, so a failure
       degrades with a warning instead of killing the render. */
    let health: HealthDoc = {};
    let healthMissing = false;
    let healthMirrored = false;
    try {
      const h = await getJSON('health.json', bases);
      healthMirrored = h.mirrored;
      if (isRecord(h.data)) health = h.data as HealthDoc;
      else healthMissing = true;
    } catch {
      healthMissing = true;
    }

    setError(null);
    setState({
      idx: idxRes.data as IndexDoc,
      health,
      mirrored: idxRes.mirrored || healthMirrored,
      healthMissing,
      fetchedAt: Date.now(),
    });
    setLoading(false);
    busy.current = false;
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  /* Auto-refresh. The page's whole subject is freshness, so leaving a stale copy
     on screen for an hour is the one thing it must not do. The poll is slower
     than the publish interval on purpose — polling faster would not make the
     data newer, it would only add load. */
  useEffect(() => {
    if (!auto) return;
    const t = setInterval(() => void load(), 60_000);
    return () => clearInterval(t);
  }, [auto, load]);

  const idx = state?.idx;
  const updatedMs = idx ? Date.parse(str(idx.updated_at, '')) : NaN;
  const known = isFinite(updatedMs);
  const ageMs = known ? now - updatedMs : NaN;
  const ivMin = idx ? fin(idx.update_interval_minutes) : null;
  const interval = n0(ivMin) * 60 * 1000;

  /* "stale" is defined against the repository's own advertised interval rather
     than a number invented here — which means freshness is only *judgeable*
     when BOTH the timestamp and the interval are usable. A naive chain falls
     through to "fresh" and paints a green dot on data 1096 days old. A
     dashboard whose whole job is freshness must never assert it by default. */
  let fresh: Freshness = 'unknown';
  if (known && interval > 0) {
    if (ageMs > interval * 3) fresh = 'broken';
    else if (ageMs > interval * 1.5) fresh = 'stale';
    else fresh = 'fresh';
  }

  /* `idx` is null both before the first response AND after a failed load, so a
     bare "loading…" here leaves the rail asserting work that has already stopped
     — the one place on the page a reader looks for a verdict, permanently
     claiming it is about to have one. Distinguish the two. */
  let verdict: string;
  if (!idx && error) verdict = 'no data — the last load attempt failed';
  else if (!idx) verdict = loading ? 'loading…' : 'no data';
  else if (!known) verdict = 'update time unknown (index.json carried no usable updated_at)';
  else if (ivMin === null || ivMin <= 0)
    verdict = `updated ${relativeAge(ageMs)}, but index.json published no usable update_interval_minutes, so staleness cannot be judged`;
  else verdict = `updated ${relativeAge(ageMs)} · target interval ${num(ivMin)} min`;

  /* index.json and health.json are two separate requests against a CDN that
     caches them independently, so they can legitimately arrive from different
     pipeline runs. Detect that and say so rather than presenting a blended set
     of numbers as if it were one measurement. */
  const mismatch = useMemo(() => {
    if (!state) return null;
    const iAt = str(state.idx.updated_at, '');
    const hAt = str(state.health.checked_at, '');
    if (!iAt || !hAt) return null;
    const di = Date.parse(iAt);
    const dh = Date.parse(hAt);
    if (isFinite(di) && isFinite(dh) && Math.abs(di - dh) > 120000) return { iAt, hAt };
    return null;
  }, [state]);

  const eta = idx ? countdownTo(idx.next_update_eta) : null;

  /* The rail must advertise only sections that are actually on the page. When
     health.json is missing, four of the eight suppress themselves; leaving their
     links in place would give the reader anchors that scroll nowhere and imply
     the page is reporting things it is not. Uses the same predicates the
     sections themselves use, so the two can never disagree. */
  const navItems = useMemo(() => {
    if (!state) return NAV;
    const h = state.health;
    return NAV.filter(([id]) => {
      if (id === 'cascade') return hasCascade(h);
      if (id === 'converters') return hasConverters(h);
      if (id === 'geo') return hasGeo(h);
      if (id === 'sources') return hasSources(h);
      return true;
    });
  }, [state]);

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[15rem_minmax(0,1fr)]">
      <Rail
        fresh={fresh}
        verdict={verdict}
        eta={eta}
        auto={auto}
        setAuto={setAuto}
        onRefresh={() => void load()}
        loading={loading}
        brand={str(idx?.brand, '')}
        hasData={!!state}
        nav={navItems}
      />

      <main className="min-w-0 px-4 pb-16 pt-6 lg:px-8">
        <div className="mx-0 max-w-[74rem]">
          <header className="mb-6 border-b pb-5">
            <h1 className="text-[26px] font-semibold leading-tight tracking-tight lg:text-[30px]">
              Free V2Ray Configs{' '}
              <span className="ml-1.5 align-middle text-[13px] font-normal text-muted-foreground">
                live status
              </span>
            </h1>
            <p className="mt-2 max-w-2xl text-[13.5px] leading-relaxed text-muted-foreground">
              Every figure on this page is read at runtime from{' '}
              <a
                className="text-primary underline-offset-2 hover:underline"
                href="https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/index.json"
              >
                <code className="fig">index.json</code>
              </a>{' '}
              and{' '}
              <a
                className="text-primary underline-offset-2 hover:underline"
                href="https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/health.json"
              >
                <code className="fig">health.json</code>
              </a>
              . No number here is written by hand — if the pipeline stops publishing something, this
              page stops claiming it.
            </p>
          </header>

          {loading && !state && !error ? <Skeleton /> : null}

          {error ? (
            <section role="alert" aria-live="assertive" className="callout callout-bad">
              <h2 className="mb-1.5 flex items-center gap-2 text-base font-semibold">
                <AlertTriangle size={16} /> Could not load live data
              </h2>
              <p className="text-[13.5px] leading-relaxed">
                {error.kind === 'network' ? (
                  <>
                    Both the primary source (<code className="fig">raw.githubusercontent.com</code>)
                    and the jsDelivr mirror failed. That usually means a network or CORS problem on
                    your side rather than a broken release — the files themselves are plain static
                    JSON in the repository.
                  </>
                ) : (
                  <>
                    The file was reachable, but what it returned is not a usable JSON object. That
                    points at the publishing pipeline rather than at your network, so retrying is
                    unlikely to help until a new release is published.
                  </>
                )}
              </p>
              <p className="fig mt-2 break-all text-[12px] text-muted-foreground">
                {error.which}: {error.message}
              </p>
            </section>
          ) : null}

          {/* Rendered only when a full payload is in hand. A render that threw
              part-way would otherwise leave real numbers, stale placeholders and
              no marker separating them — shown beside an error banner, that
              invites the reader to trust the half that looks populated. */}
          {state && !error ? (
            <div className="space-y-8">
              {state.mirrored ? (
                <p className="callout">
                  ⚠️ <strong>Serving from the jsDelivr mirror.</strong> The primary raw source could
                  not be reached, so these figures may be up to <strong>12 hours</strong> old —
                  jsDelivr caches branch references far longer than the update interval.
                </p>
              ) : null}

              {state.healthMissing ? (
                <p className="callout">
                  ⚠️ <strong><code className="fig">health.json</code> could not be loaded.</strong>{' '}
                  Source health, conversion losses, server locations and the verification cascade
                  are therefore not shown below.
                </p>
              ) : null}

              {mismatch ? (
                <p className="callout">
                  ⚠️ <strong>These figures come from two different pipeline runs.</strong> The counts
                  are from the run at <code className="fig">{mismatch.iAt}</code>, while source
                  health and the cascade are from <code className="fig">{mismatch.hAt}</code>. The
                  two files are cached separately by the CDN, so one can lag the other. Reload in a
                  minute to get a matched pair.
                </p>
              ) : null}

              <ReleaseSection idx={state.idx} ageMs={ageMs} />
              <CategoriesSection idx={state.idx} />
              <ProtocolsSection idx={state.idx} />
              <CascadeSection health={state.health} />
              <ConvertersSection health={state.health} />
              <GeoSection health={state.health} />
              <SourcesSection health={state.health} />
              <LinksSection idx={state.idx} />

              <footer className="border-t pt-5 text-[12.5px] leading-relaxed text-muted-foreground">
                <p>
                  <span className="fig">{str(state.idx.brand, '')}</span> ·{' '}
                  <a className="text-primary hover:underline" href="https://github.com/0xRadikal/Free-v2ray-Configs">source</a> ·{' '}
                  <a className="text-primary hover:underline" href="https://github.com/0xRadikal/Free-v2ray-Configs/blob/main/SECURITY.md">security</a> ·{' '}
                  <a className="text-primary hover:underline" href="https://t.me/Raydikalx">@Raydikalx</a>
                </p>
                <p className="mt-1.5 max-w-2xl">
                  For educational &amp; research purposes. No uptime or quality guarantee. This
                  project aggregates publicly-available configs; it does not operate, own, or vet
                  the servers they point at.
                </p>
              </footer>
            </div>
          ) : null}
        </div>
      </main>
    </div>
  );
}

/* ── left instrument rail ────────────────────────────────────────────────── */

function Rail({
  fresh,
  verdict,
  eta,
  auto,
  setAuto,
  onRefresh,
  loading,
  brand,
  hasData,
  nav,
}: {
  fresh: Freshness;
  verdict: string;
  eta: string | null;
  auto: boolean;
  setAuto: (v: boolean) => void;
  onRefresh: () => void;
  loading: boolean;
  brand: string;
  hasData: boolean;
  nav: readonly (readonly [string, string])[];
}) {
  const dot =
    fresh === 'fresh'
      ? 'bg-[hsl(var(--sig-ok))] shadow-[0_0_8px_hsl(var(--sig-ok))]'
      : fresh === 'stale'
        ? 'bg-[hsl(var(--sig-warn))]'
        : fresh === 'broken'
          ? 'bg-[hsl(var(--sig-bad))]'
          : 'bg-[hsl(var(--sig-unknown))]';

  return (
    <aside className="border-b bg-card/40 px-4 py-4 lg:sticky lg:top-0 lg:h-screen lg:overflow-y-auto lg:border-b-0 lg:border-r lg:px-5 lg:py-6">
      <div className="flex items-center gap-2">
        <span className="inline-flex h-7 w-7 items-center justify-center rounded-[3px] bg-primary/15 text-primary">
          <ShieldCheck size={15} />
        </span>
        <span className="fig text-[13px] font-semibold tracking-tight">v2ray-configs</span>
      </div>

      {/* The freshness verdict is the single most important thing on the page,
          so a screen reader must be told when it changes rather than silently
          keeping "loading…". role=status keeps the announcement polite. */}
      <div className="mt-4 border p-2.5" style={{ borderRadius: 'var(--radius)' }}>
        <div className="flex items-center gap-2">
          <span className={`inline-block h-2 w-2 flex-none rounded-full ${dot}`} />
          <span className="eyebrow">{fresh === 'unknown' ? 'not judgeable' : fresh}</span>
        </div>
        <p role="status" aria-live="polite" className="mt-1.5 text-[12px] leading-snug text-muted-foreground">
          {verdict}
        </p>
        {eta ? (
          <p className="mt-1.5 text-[12px] text-muted-foreground">
            next run in <span className="fig text-foreground">{eta}</span>
          </p>
        ) : null}
      </div>

      <div className="mt-2.5 flex items-center gap-1.5">
        <button
          type="button"
          onClick={onRefresh}
          disabled={loading}
          className="inline-flex flex-1 items-center justify-center gap-1.5 border px-2 py-1.5 text-[12px]
                     transition-colors hover:bg-secondary disabled:opacity-50"
          style={{ borderRadius: 'var(--radius)' }}
        >
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
          {loading ? 'fetching' : 'refresh'}
        </button>
        <button
          type="button"
          onClick={() => setAuto(!auto)}
          aria-pressed={auto}
          title="Re-fetch automatically every 60 seconds"
          className={`border px-2 py-1.5 text-[12px] transition-colors hover:bg-secondary ${
            auto ? 'text-primary' : 'text-muted-foreground'
          }`}
          style={{ borderRadius: 'var(--radius)' }}
        >
          auto
        </button>
      </div>

      {hasData ? (
        <nav aria-label="Sections" className="mt-5 hidden lg:block">
          <div className="eyebrow mb-2">Sections</div>
          <ul className="space-y-0.5">
            {nav.map(([id, label]) => (
              <li key={id}>
                <a
                  href={`#${id}`}
                  className="block border-l px-2.5 py-1 text-[12.5px] text-muted-foreground
                             transition-colors hover:border-primary hover:text-foreground"
                >
                  {label}
                </a>
              </li>
            ))}
          </ul>
        </nav>
      ) : null}

      <div className="mt-5 hidden space-y-1 text-[12px] text-muted-foreground lg:block">
        <a className="flex items-center gap-1.5 hover:text-foreground" href="https://github.com/0xRadikal/Free-v2ray-Configs">
          <GitBranch size={12} /> repository
        </a>
        <a className="flex items-center gap-1.5 hover:text-foreground" href="https://t.me/Raydikalx">
          <Send size={12} /> {brand || '@Raydikalx'}
        </a>
      </div>
    </aside>
  );
}

function Skeleton() {
  return (
    <div role="status" aria-live="polite" className="space-y-3">
      <span className="sr-only">Fetching live metadata…</span>
      <div className="grid grid-cols-2 gap-2.5 lg:grid-cols-4">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="skel h-[74px]" />
        ))}
      </div>
      <div className="skel h-44" />
      <div className="skel h-64" />
    </div>
  );
}
