# dashboard-src — source for `docs/index.html`

`docs/index.html` is **generated**. This directory is the source it is generated
from. Edit here, rebuild, copy the result over — never hand-edit the published
file, because the next rebuild will silently discard the edit.

## Why the published page is one 300 KB file

The page makes **zero external requests to render itself**: script, styles and
favicon are all inlined. No CDN, no web fonts, no analytics, no tracker.

That is not a stylistic preference. A large share of this project's readers
arrive from networks where a third-party CDN request is the component most
likely to be slow, blocked, or logged. A single self-contained file removes that
class of failure entirely: if the HTML arrives, the page works.

The only network traffic the page generates is the data it reports on:

| request | purpose |
|---|---|
| `raw.githubusercontent.com/.../main/index.json` | release contents, counts, links |
| `raw.githubusercontent.com/.../main/health.json` | source health, verification cascade, geo |
| `cdn.jsdelivr.net/gh/...` | **fallback only**, used when raw is unreachable |

## Build

Requires Node 20+ and pnpm.

```bash
cd dashboard-src
pnpm install
pnpm run typecheck        # tsc --noEmit, must exit 0
pnpm run bundle           # parcel build + html-inline -> bundle.html
cp bundle.html ../docs/index.html
```

Then re-add the generated-file banner at the top of `docs/index.html` (the
comment immediately after `<!DOCTYPE html>`), which the build does not emit.

`pnpm run dev` starts a Vite dev server for iteration; note that the dev server
is only for editing convenience — the artifact that ships is the Parcel bundle.

## Things that will bite you

- **`@radix-ui/primitive/is-development` fails to resolve under Parcel.** That
  package exposes the subpath only through the `development`/`production` export
  conditions, which Parcel's default resolver does not apply, so the build aborts.
  `src/shims/is-development.mjs` plus the `alias` block in `package.json` is the
  fix. Do not delete either.
- **`pnpm-workspace.yaml` carries `strictDepBuilds: false` and `allowBuilds`.**
  On pnpm 11 the equivalent `onlyBuiltDependencies` key in `package.json` is
  ignored; the native deps (`@swc/core`, `lmdb`, `msgpackr-extract`) will refuse
  to build without this file.
- **`baseUrl` is deprecated in TypeScript 6**, which is why the tsconfigs carry
  `"ignoreDeprecations": "6.0"`. Removing it reintroduces error TS5101.
- The build peaks around 800 MB RSS. On a small machine, cap it:
  `NODE_OPTIONS="--max-old-space-size=420" pnpm run bundle`.

## Layout

```
src/
  App.tsx            shell: fetch + freshness state machine + rail + warnings
  sections.tsx       the eight content sections, and their availability predicates
  components/bits.tsx  shared presentational pieces (Kpi, Pill, Meter, CopyButton…)
  lib/fetchJson.ts   primary -> mirror fetch with per-attempt timeout
  lib/guards.ts      every number/string/URL coercion used by the page
  lib/types.ts       deliberately loose `unknown`-based shapes for published JSON
  index.css          design tokens and component classes
```

### The rule the whole page is built around

Published JSON is treated as **untrusted input**. Every value goes through a
guard in `lib/guards.ts` before it reaches the DOM. A missing field renders as
`—`, never as `undefined`, `NaN` or `0`; an absent measurement is never printed
as a measured zero; a URL that is not `http(s)` is never turned into a link.

The reason is that this page's only job is to tell the reader whether the data
is trustworthy. A dashboard that renders `NaN`, or that shows a confident green
"fresh" on a payload it failed to parse, has actively lied about the one thing it
exists to report.
