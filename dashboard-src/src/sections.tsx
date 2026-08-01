import { useMemo, useState } from 'react';
import { ArrowDown, ArrowUp, Search } from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Input } from '@/components/ui/input';
import { CopyButton, Distribution, Kpi, Meter, Pill, SafeLink, Section } from '@/components/bits';
import {
  MAX_RUNS_SHOWN,
  clipError,
  fin,
  fmtPct,
  fmtSeconds,
  minMax,
  n0,
  num,
  pct,
  str,
} from '@/lib/guards';
import { MIRROR } from '@/lib/fetchJson';
import type { Category, HealthDoc, IndexDoc, SourceRow } from '@/lib/types';

/* ── section availability ─────────────────────────────────────────────────────
 * Single source of truth for "did the publisher actually report this?".
 *
 * Both the section components AND the rail's navigation consult these, so it is
 * structurally impossible for a section to suppress itself while the rail still
 * advertises a link down to it. Written as shared predicates rather than as two
 * copies of the same boolean precisely because the two copies would drift.
 * ─────────────────────────────────────────────────────────────────────────── */
export const hasCascade = (h: HealthDoc): boolean => !!(h.cascade && h.cascade.layers);
export const hasConverters = (h: HealthDoc): boolean =>
  !!h.converters && Object.keys(h.converters).length > 0;
export const hasGeo = (h: HealthDoc): boolean => !!h.geo && Object.keys(h.geo).length > 0;
/* Array.isArray, not length: a published-but-empty list is a real measured zero
   and must still render. Only an absent/non-array list means "not measured". */
export const hasSources = (h: HealthDoc): boolean => Array.isArray(h.sources);

/* ── 1. this release ─────────────────────────────────────────────────────── */

export function ReleaseSection({ idx, ageMs }: { idx: IndexDoc; ageMs: number }) {
  const all = (idx.categories?.all ?? {}) as Category;
  const ivMin = fin(idx.update_interval_minutes);
  const updated = Date.parse(str(idx.updated_at, ''));
  const known = isFinite(updated);

  return (
    <Section
      id="release"
      title="This release"
      lede="Read at runtime from index.json — no figure below is written by hand."
    >
      <div className="grid grid-cols-2 gap-2.5 lg:grid-cols-4">
        <Kpi
          label="Unique configs (all)"
          value={num(all.unique)}
          sub={all.total_fetched ? `from ${num(all.total_fetched)} fetched` : undefined}
        />
        <Kpi
          label="Last updated"
          value={
            <span className="text-xl">
              {known ? relativeShort(ageMs) : 'unknown'}
            </span>
          }
          sub={
            /* A <time> element is only correct when there is a machine-readable
               value to put in it. Per the HTML Standard §4.5.14 the datetime
               value falls through to the child text when the attribute is
               absent, and a "—" placeholder matches none of the permitted
               syntaxes — so when the timestamp is unparseable no <time> is
               emitted at all. */
            known ? (
              <time dateTime={new Date(updated).toISOString()}>{str(idx.updated_at)}</time>
            ) : (
              'update time unknown'
            )
          }
        />
        <Kpi
          label="Next update ETA"
          value={<span className="text-sm leading-snug">{str(idx.next_update_eta)}</span>}
          sub={
            <>
              branch <span className="fig">{str(idx.publish_branch)}</span>
              {ivMin !== null && ivMin > 0 ? ` · every ${num(ivMin)} min` : ''}
            </>
          }
        />
        <Kpi
          label="Aggregation took"
          value={fmtSeconds(idx.elapsed_seconds)}
          sub="fetch → clean → dedup → convert → validate"
        />
      </div>
    </Section>
  );
}

function relativeShort(ms: number): string {
  if (!isFinite(ms)) return 'unknown';
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

/* ── 2. categories ───────────────────────────────────────────────────────── */

export function CategoriesSection({ idx }: { idx: IndexDoc }) {
  const cats = Object.entries(idx.categories ?? {});
  if (!cats.length) return null;

  return (
    <Section
      id="categories"
      title="Categories"
      lede="all = every source · heavy = bulk feeds · light = curated feeds"
    >
      <div className="tscroll">
        <table className="dtable">
          <thead>
            <tr>
              <th scope="col">category</th>
              <th scope="col" className="num">unique</th>
              <th scope="col" className="num">duplicates</th>
              <th scope="col" className="num">broken</th>
              <th scope="col" className="num">fetched</th>
              <th scope="col" className="num">active sources</th>
              <th scope="col" className="num">dedup saving</th>
            </tr>
          </thead>
          <tbody>
            {cats.map(([name, c]) => (
              <tr key={name}>
                <td className="fig">{name}</td>
                <td className="num">{num(c.unique)}</td>
                <td className="num">{num(c.duplicates)}</td>
                <td className="num">{num(c.broken)}</td>
                <td className="num">{num(c.total_fetched)}</td>
                <td className="num">{num(c.active_sources)}</td>
                <td className="num">{fmtPct(pct(c.duplicates, c.total_fetched))}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Per-category protocol split. index.json has always published this and
          the previous dashboard never rendered it — only the global split. */}
      <div className="panel mt-3 p-3.5">
        <div className="eyebrow mb-2.5">Protocol split per category</div>
        <Tabs defaultValue={cats[0][0]}>
          <TabsList className="h-auto rounded-[2px] bg-secondary p-0.5">
            {cats.map(([name]) => (
              <TabsTrigger key={name} value={name} className="fig rounded-[1px] text-xs">
                {name}
              </TabsTrigger>
            ))}
          </TabsList>
          {cats.map(([name, c]) => {
            const entries = Object.entries(c.protocols ?? {})
              .map(([k, v]) => [k, n0(v)] as [string, number])
              .sort((a, b) => b[1] - a[1]);
            return (
              <TabsContent key={name} value={name} className="mt-3">
                <Distribution entries={entries} emptyText="no protocol breakdown published for this category" />
              </TabsContent>
            );
          })}
        </Tabs>
      </div>
    </Section>
  );
}

/* ── 3. protocols ────────────────────────────────────────────────────────── */

export function ProtocolsSection({ idx }: { idx: IndexDoc }) {
  const protos = Object.entries(idx.protocols ?? {}).sort((a, b) => n0(b[1]) - n0(a[1]));
  const max = protos.reduce((m, [, v]) => Math.max(m, n0(v)), 0);
  const published = new Set(Object.keys(idx.protocol_files ?? {}));

  /* Three outcomes, not two. A count of 0 and a count that cannot be read are
     different facts, and collapsing them would make the note below claim
     "yielded nothing" about a protocol whose result is simply unknown. */
  let zero = 0;
  let unusable = 0;
  for (const [, raw] of protos) {
    const c = fin(raw);
    if (c === null) unusable++;
    else if (c <= 0) zero++;
  }

  const notes: string[] = [];
  if (zero > 0) {
    notes.push(
      `${zero} supported protocol${zero === 1 ? '' : 's'} yielded nothing this round — no file is published for those, because an empty subscription file is worse than a 404.`,
    );
  }
  if (unusable > 0) {
    notes.push(
      `${unusable} protocol count${unusable === 1 ? '' : 's'} in index.json could not be read as a number and ${unusable === 1 ? 'is' : 'are'} shown as unreadable rather than as zero.`,
    );
  }
  if (!notes.length) notes.push('Every supported protocol yielded at least one config this round.');

  return (
    <Section id="protocols" title="Protocol breakdown" lede="Across the whole pool.">
      <div className="panel divide-y">
        {protos.map(([name, raw]) => {
          const count = fin(raw);
          const isZero = count !== null && count <= 0;
          const file = str(idx.protocol_files?.[name], '');
          return (
            <div
              key={name}
              className="grid grid-cols-[minmax(6rem,9rem)_1fr_auto] items-center gap-3 px-3.5 py-2"
              title={published.has(name) && file ? `published: ${file}` : undefined}
            >
              <span className={`fig text-[13px] ${isZero ? 'text-muted-foreground' : ''}`}>{name}</span>
              <Meter frac={max > 0 ? n0(count) / max : 0} zero={isZero} />
              <span className="w-20 text-right">
                {count === null ? (
                  <Pill kind="unknown">unreadable</Pill>
                ) : count > 0 ? (
                  <span className="fig text-[13px]">{num(count)}</span>
                ) : (
                  <Pill kind="unknown">none</Pill>
                )}
              </span>
            </div>
          );
        })}
      </div>
      <p className="mt-2.5 text-[12.5px] leading-relaxed text-muted-foreground">{notes.join(' ')}</p>
    </Section>
  );
}

/* ── 4. verification cascade ─────────────────────────────────────────────── */

export function CascadeSection({ health }: { health: HealthDoc }) {
  const c = health.cascade;
  /* hasCascade() is the shared availability rule, but a function call is opaque
     to the compiler's narrowing, so `!c.layers` is repeated here to actually
     prove `c.layers` is defined below rather than asserting it away with `!`. */
  if (!hasCascade(health) || !c || !c.layers) return null;

  const l = c.layers;
  const l01 = l.l0_l1 ?? {};
  const l2 = l.l2 ?? {};
  const l3 = l.l3 ?? {};
  const b = c.buckets ?? {};
  const raw = l01.in;

  const ec = c.exit_country && typeof c.exit_country === 'object' ? c.exit_country : {};
  const ecLoc = str(ec.loc, '');
  const ecColo = str(ec.colo, '');

  const uniq = fin(l01.endpoints_unique);
  const dnsF = fin(l2.dns_failed);
  const rounds = fin(l3.rounds);
  const flaky = fin(l3.flaky_pct);

  const rows: Array<[string, unknown, unknown, unknown, string]> = [
    ['L0/L1 — parsable & unique endpoint', l01.in, l01.out, l01.seconds,
      uniq !== null ? `${num(uniq)} unique endpoints` : ''],
    ['L2 — TCP port accepts', l2.in, l2.out, l2.seconds,
      dnsF !== null ? `${num(dnsF)} DNS failures` : ''],
    ['L3 — real HTTP request through proxy', l3.in, l3.ever_ok, l3.seconds,
      rounds !== null ? `${num(rounds)} round${rounds === 1 ? '' : 's'}, worked at least once` : ''],
    ['L3 — passed EVERY round → verified/', l3.in, l3.stable, null,
      flaky !== null ? `${num(flaky)}% of ever-ok were flaky` : ''],
  ];

  const runsRaw = Array.isArray(l3.per_run_ok) ? (l3.per_run_ok as unknown[]) : [];
  const runs = runsRaw.map(fin).filter((v): v is number => v !== null);
  const range = minMax(runs);
  const fastMs = fin(b.fast_threshold_ms);

  return (
    <Section
      id="cascade"
      title="Does it actually work? — measured, not estimated"
      lede="A config reaches verified/ only if it passed every round of a real HTTP request."
    >
      <p className="callout mb-3">
        <strong>The large majority of any free config pool is dead at any moment.</strong> That is a
        property of free configs, not of this repository, so it is measured rather than hidden.
      </p>

      <div className="grid grid-cols-2 gap-2.5 lg:grid-cols-4">
        <Kpi
          label="verified/ (passed every round)"
          value={num(b.verified)}
          sub={`${fmtPct(pct(b.verified, raw))} of the pool`}
          tone="ok"
        />
        <Kpi label="fast/" value={num(b.fast)} sub={fastMs !== null && fastMs > 0 ? `< ${num(fastMs)} ms` : undefined} />
        <Kpi label="secure/" value={num(b.secure)} sub="stricter transport/TLS requirements" />
        <Kpi
          label="Tested from"
          value={ecLoc ? `${ecLoc}${ecColo ? ` (${ecColo})` : ''}` : 'unknown'}
          sub={<SafeLink url={ec.source}>detection source</SafeLink>}
        />
      </div>

      <div className="tscroll mt-3">
        <table className="dtable">
          <thead>
            <tr>
              <th scope="col">stage</th>
              <th scope="col" className="num">in</th>
              <th scope="col" className="num">out</th>
              <th scope="col" className="num">of pool</th>
              <th scope="col" className="num">took</th>
              <th scope="col">note</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(([label, inn, out, secs, note]) => (
              <tr key={label}>
                <td>
                  <div className="text-[13px]">{label}</div>
                  <div className="mt-1 max-w-[16rem]">
                    <Meter frac={(n0(out) || 0) / Math.max(1, n0(raw))} />
                  </div>
                </td>
                <td className="num">{num(inn)}</td>
                <td className="num">{num(out)}</td>
                <td className="num">{fmtPct(pct(out, raw))}</td>
                <td className="num">{secs === null ? '—' : fmtSeconds(secs)}</td>
                <td className="text-[12.5px] text-muted-foreground">{note}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="mt-3 grid gap-2.5 lg:grid-cols-2">
        <div className="panel px-3.5 py-3">
          <div className="eyebrow">Per-round successes</div>
          <div className="fig mt-1.5 text-base">
            {runsRaw.length
              ? runsRaw.slice(0, MAX_RUNS_SHOWN).map((v) => num(v)).join(' · ') +
                (runsRaw.length > MAX_RUNS_SHOWN
                  ? ` … (+${num(runsRaw.length - MAX_RUNS_SHOWN)} more)`
                  : '')
              : '—'}
          </div>
          <div className="mt-1.5 text-[12px] leading-snug text-muted-foreground">
            {!runsRaw.length
              ? ''
              : range
                ? `Per-round success ranged ${num(range.lo)}–${num(range.hi)}, while only ${num(fin(l3.stable))} passed every round. Publishing the best round would have overstated the result.`
                : 'health.json published per-round figures that could not be read as numbers, so no range is stated here.'}
          </div>
        </div>
        <Kpi label="Cascade total time" value={fmtSeconds(c.total_seconds)} sub="L0/L1 + L2 + L3" />
      </div>

      <p className="callout mt-3">
        ⚠️ <strong>Read this before quoting any percentage above.</strong> These numbers were
        measured from <em>one</em> host, on <em>one</em> day, on <em>one</em> link. A config that
        fails from a datacentre in one country may work perfectly from another, and the reverse is
        just as true. So <code className="fig">verified/</code> means “this config answered a real
        request from the machine that ran the test” — <em>not</em> “this config will work for you”.
      </p>
    </Section>
  );
}

/* ── 5. converter losses (new — health.converters was never rendered) ────── */

export function ConvertersSection({ health }: { health: HealthDoc }) {
  const conv = health.converters;
  if (!hasConverters(health) || !conv) return null;
  const names = Object.keys(conv);

  return (
    <Section
      id="converters"
      title="Conversion losses"
      lede="Configs that survived dedup but could not be expressed in a client format."
    >
      <p className="callout callout-info mb-3">
        A subscription file is only useful in the client that reads it. These are the configs the
        pipeline <strong>declined to emit</strong> rather than emit incorrectly — reported here
        because a silent drop is indistinguishable from a bug.
      </p>
      <div className="grid gap-2.5 lg:grid-cols-2">
        {names.map((k) => {
          const s = conv[k] ?? {};
          const reasons = Object.entries(s.by_reason ?? {})
            .map(([r, v]) => [r, n0(v)] as [string, number])
            .sort((a, b) => b[1] - a[1]);
          const protos = Object.entries(s.by_protocol ?? {})
            .map(([r, v]) => [r, n0(v)] as [string, number])
            .sort((a, b) => b[1] - a[1]);
          return (
            <div key={k} className="panel p-3.5">
              <div className="flex items-baseline justify-between gap-2 border-b pb-2">
                <span className="fig text-sm font-semibold">{k}</span>
                <span className="fig text-lg">{num(s.total)}</span>
              </div>
              <div className="mt-3">
                <div className="eyebrow mb-2">by reason</div>
                <Distribution entries={reasons} />
              </div>
              <div className="mt-3.5">
                <div className="eyebrow mb-2">by protocol</div>
                <Distribution entries={protos} />
              </div>
            </div>
          );
        })}
      </div>
    </Section>
  );
}

/* ── 6. geo resolution (new — health.geo was never rendered) ─────────────── */

export function GeoSection({ health }: { health: HealthDoc }) {
  const g = health.geo;
  if (!hasGeo(health) || !g) return null;

  const resolved = fin(g.hosts_resolved);
  const unknownHosts = fin(g.hosts_unknown);
  const totalHosts = n0(resolved) + n0(unknownHosts);

  const rows: Array<[string, unknown]> = [
    ['located from an IP literal', g.by_ip_literal],
    ['located after a DNS lookup', g.by_dns],
    ['DNS lookup failed', g.dns_failed],
    ['IP literal, no country match', g.unknown_ip_literal],
    ['resolved, no country match', g.unknown_after_dns],
    ['skipped (no database)', g.skipped_no_db],
  ];

  return (
    <Section
      id="geo"
      title="Where the servers are"
      lede="How each config's host was turned into a country — including the failures."
    >
      <div className="grid gap-2.5 lg:grid-cols-[minmax(0,18rem)_1fr]">
        <div className="grid grid-cols-2 gap-2.5 lg:grid-cols-1">
          <Kpi
            label="Hosts located"
            value={num(resolved)}
            sub={totalHosts > 0 ? `${fmtPct(pct(n0(resolved), totalHosts))} of ${num(totalHosts)} hosts` : undefined}
          />
          <Kpi
            label="Hosts unresolved"
            value={num(unknownHosts)}
            tone={n0(unknownHosts) > 0 ? 'warn' : 'default'}
            sub="counted, not hidden"
          />
        </div>
        <div className="panel p-3.5">
          <div className="eyebrow mb-2.5">Resolution path</div>
          <Distribution
            entries={rows
              .filter(([, v]) => fin(v) !== null)
              .map(([k, v]) => [k, n0(v)] as [string, number])
              .sort((a, b) => b[1] - a[1])}
          />
          <p className="mt-3 text-[12px] leading-snug text-muted-foreground">
            A country label is a property of the <em>address</em>, not of the operator. Hosts behind
            a CDN resolve to the CDN's edge, so these labels move between runs without any server
            moving.
          </p>
        </div>
      </div>
    </Section>
  );
}

/* ── 7. source health ────────────────────────────────────────────────────── */

type SortKey = 'status' | 'count' | 'name';

/**
 * An ABSENT source list is not a measured zero.
 *
 * When health.json is missing or unusable this section must disappear rather
 * than render "Sources 0" beside a live-looking empty table: that is a fabricated
 * measurement, and it is the single most misleading thing this page could print,
 * because "we checked 0 sources" and "we could not check" look identical to a
 * reader while meaning opposite things. The three sibling health sections
 * already suppress themselves on absent data; this one did not, which is the
 * inconsistency being closed here.
 *
 * A list that IS published but empty stays rendered — that genuinely is a
 * measured zero, and hiding it would suppress a real and alarming fact.
 *
 * The guard lives in this wrapper instead of as an early return inside the body
 * because the body holds hooks (useState/useMemo). Returning null before them
 * would call zero hooks on one render and several on the next as soon as
 * health.json succeeds on a later auto-refresh — "rendered more hooks than
 * during the previous render", i.e. trading a wrong number for a crash.
 */
export function SourcesSection({ health }: { health: HealthDoc }) {
  if (!hasSources(health)) return null;
  return <SourcesBody health={health} />;
}

function SourcesBody({ health }: { health: HealthDoc }) {
  const list: SourceRow[] = Array.isArray(health.sources) ? (health.sources as SourceRow[]) : [];
  const [q, setQ] = useState('');
  const [sort, setSort] = useState<SortKey>('status');
  const [desc, setDesc] = useState(false);

  /* Object.create(null): the keys come from published JSON, and a plain object
     literal would resolve inherited names (a status of "constructor" would look
     up to a function instead of falling through to the default rank). */
  const order: Record<string, number> = Object.assign(Object.create(null), {
    fail: 0,
    empty: 1,
    unknown: 2,
    ok: 3,
  });

  /* Counted from the source list itself, NOT from health.summary: summary
     reports ok/empty/fail, but a source can also be "unknown", which belongs to
     none of those three. */
  const { tally, yielded } = useMemo(() => {
    const t = new Map<string, number>();
    let y = 0;
    for (const s of list) {
      const st = str(s.status, 'unknown');
      t.set(st, (t.get(st) ?? 0) + 1);
      y += n0(s.count);
    }
    return { tally: t, yielded: y };
  }, [list]);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const filtered = needle
      ? list.filter((s) =>
          [s.name, s.url, s.tier, s.status]
            .map((v) => (typeof v === 'string' ? v.toLowerCase() : ''))
            .some((v) => v.includes(needle)),
        )
      : list.slice();
    const dir = desc ? -1 : 1;
    return filtered.sort((a, b) => {
      if (sort === 'count') return dir * (n0(a.count) - n0(b.count));
      if (sort === 'name') return dir * str(a.name, '').localeCompare(str(b.name, ''));
      return (
        dir *
        (((order[str(a.status, 'unknown')] ?? 9) - (order[str(b.status, 'unknown')] ?? 9)) ||
          n0(b.count) - n0(a.count))
      );
    });
  }, [list, q, sort, desc]);

  function th(key: SortKey, label: string, cls = '') {
    const active = sort === key;
    return (
      <th scope="col" className={cls}>
        <button
          type="button"
          /* min-h-6 = 24px: measured at a real 375px viewport these sort headers
             were 20px tall, under the WCAG 2.2 SC 2.5.8 minimum target size.
             They might well have qualified for the spacing exception, but four
             pixels is cheaper than the argument, and costs nothing in a header row. */
          className={`inline-flex min-h-6 items-center gap-1 uppercase tracking-wider ${active ? 'text-foreground' : ''}`}
          onClick={() => {
            if (active) setDesc(!desc);
            else {
              setSort(key);
              setDesc(false);
            }
          }}
        >
          {label}
          {active ? (desc ? <ArrowDown size={11} /> : <ArrowUp size={11} />) : null}
        </button>
      </th>
    );
  }

  const breakdown = [...tally.entries()]
    .sort((a, b) => (order[a[0]] ?? 9) - (order[b[0]] ?? 9))
    .map(([k, v]) => `${v} ${k}`)
    .join(' · ');

  return (
    <Section id="sources" title="Source health" lede="One row per configured upstream feed.">
      <div className="grid grid-cols-2 gap-2.5 lg:grid-cols-3">
        <Kpi label="Sources" value={num(list.length)} sub={breakdown || '—'} />
        <Kpi label="Configs yielded" value={num(yielded)} sub="before dedup" />
        <Kpi
          label="Health checked at"
          value={<span className="text-sm leading-snug">{str(health.checked_at)}</span>}
          sub="regenerated every run"
        />
      </div>

      <div className="mt-3 flex items-center gap-2">
        <div className="relative w-full max-w-xs">
          <Search
            size={13}
            className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground"
          />
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="filter sources…"
            aria-label="Filter sources"
            className="h-8 rounded-[2px] pl-7 text-[13px]"
          />
        </div>
        <span className="fig text-[12px] text-muted-foreground">
          {rows.length === list.length ? `${list.length} shown` : `${rows.length} / ${list.length}`}
        </span>
      </div>

      <div className="tscroll mt-2">
        <table className="dtable">
          <thead>
            <tr>
              {th('name', 'source')}
              <th scope="col">tier</th>
              {th('status', 'status')}
              {th('count', 'configs', 'num')}
              <th scope="col">diagnostics</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s, i) => {
              const st = str(s.status, 'unknown');
              const bits: string[] = [];
              if (typeof s.http_code === 'number') bits.push(`HTTP ${s.http_code}`);
              if (typeof s.latency_ms === 'number') bits.push(`${num(Math.round(s.latency_ms))} ms`);
              if (typeof s.attempts === 'number' && s.attempts > 1) bits.push(`${s.attempts} attempts`);
              const err = clipError(s.error);
              return (
                <tr key={`${str(s.url, String(i))}-${i}`}>
                  <td className="max-w-[18rem]">
                    <SafeLink url={s.url} className="fig break-all text-[12.5px]">
                      {str(s.name, str(s.url, '—'))}
                    </SafeLink>
                  </td>
                  <td className="text-[12.5px]">{str(s.tier)}</td>
                  <td>
                    <Pill kind={st}>{st}</Pill>
                  </td>
                  <td className="num">{num(s.count)}</td>
                  <td className="max-w-[22rem] text-[12px] text-muted-foreground">
                    {bits.length ? <span className="fig">{bits.join(' · ')}</span> : null}
                    {err ? (
                      <>
                        {bits.length ? ' · ' : null}
                        <span
                          className="break-words text-[hsl(var(--sig-bad))]"
                          title={err.clipped ? err.full : undefined}
                        >
                          {err.shown}
                        </span>
                      </>
                    ) : null}
                    {!bits.length && !err ? (
                      <span className="italic">not contacted</span>
                    ) : null}
                  </td>
                </tr>
              );
            })}
            {!rows.length ? (
              <tr>
                <td colSpan={5} className="py-6 text-center text-[13px] text-muted-foreground">
                  No source matches “{q}”.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      <p className="callout callout-info mt-3">
        A status of <code className="fig">unknown</code> means the source produced no result in the
        run that wrote <code className="fig">health.json</code>, so it is counted separately from{' '}
        <code className="fig">ok</code>, <code className="fig">empty</code> and{' '}
        <code className="fig">fail</code> rather than being folded into any of them.
        <br />
        In practice this is usually <strong>not</strong> a missed request: the pipeline keeps
        cross-run memory in <code className="fig">state.json</code> and deliberately{' '}
        <strong>skips sources it has quarantined</strong> for repeatedly returning nothing, so they
        are never fetched at all and therefore never get a status. A source can also show{' '}
        <code className="fig">unknown</code> simply because it was added after the last run.
      </p>
    </Section>
  );
}

/* ── 8. subscription links ───────────────────────────────────────────────── */

type LinkFlavour = 'primary' | 'mirror' | 'base64';

export function LinksSection({ idx }: { idx: IndexDoc }) {
  const [flavour, setFlavour] = useState<LinkFlavour>('primary');

  const rows = useMemo(() => {
    const out: Array<{ cat: string; kind: string; url: string }> = [];
    for (const [cat, c] of Object.entries(idx.categories ?? {})) {
      for (const [kind, url] of Object.entries(c.files ?? {})) {
        if (typeof url !== 'string' || !url.startsWith('http')) continue;
        const isMirror = url.startsWith(MIRROR);
        const isB64 = kind.includes('base64');
        if (flavour === 'primary' && (isMirror || isB64)) continue;
        if (flavour === 'mirror' && !isMirror) continue;
        if (flavour === 'base64' && !isB64) continue;
        out.push({ cat, kind, url });
      }
    }
    if (flavour === 'base64') {
      for (const [proto, url] of Object.entries(idx.protocol_files_base64 ?? {})) {
        if (typeof url === 'string' && url.startsWith('http')) {
          out.push({ cat: proto, kind: 'protocol_base64', url });
        }
      }
    }
    if (flavour === 'primary') {
      for (const [proto, url] of Object.entries(idx.protocol_files ?? {})) {
        if (typeof url === 'string' && url.startsWith('http')) {
          out.push({ cat: proto, kind: 'protocol_txt', url });
        }
      }
    }
    return out;
  }, [idx, flavour]);

  const policy = idx.link_policy ?? {};
  const pCache = fin(policy.primary_cache_seconds);
  const mCache = fin(policy.mirror_cache_seconds);

  if (!rows.length && flavour === 'primary') return null;

  return (
    <Section
      id="links"
      title="Subscription links"
      lede="Taken from index.json — exactly what the repository is publishing right now."
    >
      {pCache !== null && mCache !== null && pCache > 0 ? (
        <p className="callout callout-info mb-3">
          <strong>Prefer the primary.</strong>{' '}
          <code className="fig">{str(policy.primary, 'raw')}</code> is cached for{' '}
          <span className="fig">{num(pCache)}s</span>, while{' '}
          <code className="fig">{str(policy.mirror, 'the mirror')}</code> is cached for{' '}
          <span className="fig">{num(mCache)}s</span> — about{' '}
          <strong>{Math.round(mCache / pCache)}× staler</strong>. Use the mirror only where the
          primary is unreachable.
        </p>
      ) : null}

      <Tabs value={flavour} onValueChange={(v) => setFlavour(v as LinkFlavour)}>
        <TabsList className="h-auto rounded-[2px] bg-secondary p-0.5">
          <TabsTrigger value="primary" className="fig rounded-[1px] text-xs">primary (raw)</TabsTrigger>
          <TabsTrigger value="mirror" className="fig rounded-[1px] text-xs">mirror (jsDelivr)</TabsTrigger>
          <TabsTrigger value="base64" className="fig rounded-[1px] text-xs">base64</TabsTrigger>
        </TabsList>
      </Tabs>

      <div className="tscroll mt-2">
        <table className="dtable">
          <thead>
            <tr>
              <th scope="col">group</th>
              <th scope="col">format</th>
              <th scope="col">URL</th>
              <th scope="col" className="w-0" />
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={`${r.cat}-${r.kind}-${r.url}`}>
                <td className="fig text-[12.5px]">{r.cat}</td>
                <td className="text-[12.5px] text-muted-foreground">{r.kind}</td>
                <td>
                  <SafeLink url={r.url} className="fig break-all text-[12px]" />
                </td>
                <td className="whitespace-nowrap pl-1">
                  <CopyButton text={r.url} label={`Copy ${r.cat} ${r.kind} URL`} />
                </td>
              </tr>
            ))}
            {!rows.length ? (
              <tr>
                <td colSpan={4} className="py-6 text-center text-[13px] text-muted-foreground">
                  index.json is not publishing any link of this kind right now.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </Section>
  );
}
