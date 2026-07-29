# 🚀 Free V2Ray Configs — by [@Raydikalx](https://t.me/Raydikalx)

[![Aggregate](https://github.com/0xRadikal/Free-v2ray-Configs/actions/workflows/aggregate.yml/badge.svg)](https://github.com/0xRadikal/Free-v2ray-Configs/actions/workflows/aggregate.yml)
![Update](https://img.shields.io/badge/update-every%2015%20min-blue)
![Validated](https://img.shields.io/badge/validated-sing--box%20%2B%20mihomo-success)
![License](https://img.shields.io/github/license/0xRadikal/Free-v2ray-Configs)

> 🇮🇷 [نسخهٔ فارسی](README_FA.md)

Automatically aggregated, **deduplicated**, **branded**, and **client-validated** free
V2Ray / Xray configs. Collected from **21 sources** (7 light + 14 heavy), cleaned with a
CDN-aware deduplication engine, and updated **every ~15 minutes** via GitHub Actions.

All remarks are rebranded to: `{CC} {flag} | @Raydikalx | {id}` — where `{id}` is a
short **content-derived** fingerprint, not a counter. The same server always gets the
same tag, so your client's entry names stay stable between updates.

### ✅ Every release is verified by the real clients

A single malformed entry makes a client reject the **entire file** — so "mostly valid"
output is worth nothing. Before anything is published, every `clash.yaml` and
`singbox.json` is checked with the same binaries you run:

```
sing-box check -c <file>      # sing-box 1.13.14
mihomo -t -f <file>           # mihomo v1.19.29
```

If any file fails, **the run aborts and nothing is committed**. The previous good
release stays in place.

> ⚠️ No TCP health-checking is performed — configs are validated for *correctness*,
> not *reachability*. Structurally broken entries (dummy UUID, `App not supported`,
> unsupported ciphers, malformed REALITY keys) are dropped; a syntactically perfect
> config may still be offline.

---

## 📥 Quick Subscribe (copy a link into your client)

> **Use the `raw.githubusercontent.com` links below.** They are the primary,
> freshest source. A jsDelivr mirror is listed further down for anyone who
> cannot reach GitHub directly.
>
> **Why raw and not the CDN?** Measured on this repository:
>
> | | cache directive | effective staleness |
> |---|---|---|
> | `raw.githubusercontent.com` | `max-age=300` | up to **5 minutes** |
> | `cdn.jsdelivr.net` (branch ref) | `s-maxage=43200` | up to **12 hours** |
>
> jsDelivr's own documentation states that branch references are cached for
> 12 hours. In one live check the CDN was serving a snapshot **12 h 45 min**
> old (4,353 configs) while raw served the current one (8,168 configs) — that
> is **51×** the 15-minute update interval. The CDN cache is now purged on
> every run, but purging clears only the edge; jsDelivr's own origin can still
> lag while it re-resolves the branch name. Raw has no such layer.
>
> 📌 **Everything is on the default branch (`main`).** Open the repository and
> the config files are right there — no branch switching, no hidden location.
> Links you copied months ago keep working. See
> [How publishing stays cheap](#-how-publishing-stays-cheap).

### 🌐 ALL configs (light + heavy)
| Format | URL (primary — raw) |
|---|---|
| Plain (v2ray) | `https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt` |
| **Base64** (sub) | `https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs_base64.txt` |
| Clash YAML | `https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/clash.yaml` |
| Sing-box JSON | `https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/singbox.json` |

### ⭐ LIGHT (curated — sourced from speed-tested upstreams)
- Plain: `…/main/light/configs.txt`
- Base64: `…/main/light/configs_base64.txt`
- Clash: `…/main/light/clash.yaml` · Sing-box: `…/main/light/singbox.json`

### 📦 HEAVY (large, diverse)
- Plain: `…/main/heavy/configs.txt`
- Base64: `…/main/heavy/configs_base64.txt`
- Clash: `…/main/heavy/clash.yaml` · Sing-box: `…/main/heavy/singbox.json`

### 🎯 Per-protocol (from ALL)

Regularly populated: `vless` · `vmess` · `shadowsocks` · `trojan` · `hysteria2` ·
`shadowsocksr` · `tuic`

Also supported (a file appears only when upstreams actually publish that
protocol — empty files are never published, so a missing file means "none this
round"): `hysteria` · `wireguard` · `juicity` · `anytls` · `snell` · `mieru` · `socks`

```
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vless.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vless_base64.txt
…and so on for each protocol
```

`index.json` lists exactly which protocol files exist right now, so you never
have to guess.

### 🪞 Mirror (jsDelivr) — only if raw is unreachable

Replace the prefix with
`https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/…`

The mirror is purged on every run, but may still trail the primary. If you need
a guaranteed-exact copy through the CDN, pin a commit instead of the branch
(`@<commit-sha>/…`) — verified bit-identical to raw.

---

## 🗂️ Repository structure

**One branch — `main`.** Source code and published output live side by side on the
default branch, which is exactly what a visitor sees when they open the repo.

Machine-generated output, refreshed every run:

```
all/        configs.txt · configs_base64.txt · clash.yaml · singbox.json   (light + heavy)
heavy/      configs.txt · configs_base64.txt · clash.yaml · singbox.json   (14 heavy sources)
light/      configs.txt · configs_base64.txt · clash.yaml · singbox.json   (7 light sources)
protocols/  vless.txt · vmess.txt · trojan.txt · … (+ *_base64.txt)         (split from ALL)
archive/    <cat>_broken.txt (+ _base64)                                   (rejected configs)
index.json  full metadata: counts, timestamps, protocol breakdown, all URLs
health.json per-source health report: ok/empty/fail, http code, latency, errors
```

Human-authored source, with normal git history and blame:

```
scripts/    the pipeline (core.py · converters.py · sources.py · aggregate.py · validate.py)
.github/    the scheduled workflow
README.md · README_FA.md · LICENSE
```

Notes:

- Files in `protocols/` and `archive/` appear **only when non-empty**. A missing
  file means "nothing in this category this round" — an empty file would be
  worse than a 404, because a client subscribed to it would replace its working
  list with nothing, whereas a 404 makes clients keep the previous list.
- `index.json` advertises exactly the files that exist, so its URL list is never
  a promise the repository cannot keep.

<a name="-how-publishing-stays-cheap"></a>
## 🌿 How publishing stays cheap (and why the files are on `main`)

Git never forgets a blob. Every scheduled run regenerates the same set of large
files, and appending them to a branch in the normal way adds a **new** copy of
each changed file to history forever. Publishing then costs
**O(number of commits)**, with no upper bound.

That is not hypothetical here. This repository reached **≈ 3.55 GB across ~5,649
commits**. Measured on two consecutive real bot commits, each output commit added
**604 KB** of permanent history — **≈ 56.6 MB/day** at ~96 runs/day, i.e.
**≈ 20 GB/year**.

### The wrong fix (and why it was reverted)

The first attempt moved the output to an **orphan branch** that was force-pushed
as a single commit. Publishing cost did drop to O(1) — and the project quietly
broke:

- **Every previously copied subscription link returned HTTP 404.** A user whose
  client points at `…/main/all/configs.txt` did not get an error dialog; the
  subscription just silently went empty.
- **A visitor opening the repository saw no configs at all** — only code. Most
  people looking for a config have no idea what a git branch is, let alone that
  they should switch to a second one and look again.
- **Discoverability collapsed.** GitHub search, the repo landing page, and search
  engines all index the default branch. Hiding the product off-default made the
  most valuable content invisible.
- **Not one successful repository in this space does it.** Checked directly:
  Epodonios/v2ray-configs (⭐ 3,166 — 24.7 GB, output on `main`),
  mahdibland/V2RayAggregator (⭐ 4,003 — output on `master`),
  Pawdroid/Free-servers (⭐ 18,420 — output on `main`).

Cheap history is worth nothing if nobody can find the files.

### The right fix — rolling squash on `main`

Output is published **to the default branch**, but the branch is kept at
**source history + exactly one output commit**:

1. Find the newest commit that is *not* marked `[auto-output]` — the **anchor**
   (the last human/source commit).
2. Build a tree = *anchor's tree* + *this run's fresh output*.
3. `git commit-tree <tree> -p <anchor>` and force-push **with a lease**.

The previous output commit becomes unreachable and is garbage-collected, so the
history never accumulates snapshots. Publishing cost is **O(1)** — while every
file stays exactly where users (and crawlers) already look for it.

Measured over 25 consecutive rounds, each from a fresh shallow clone: repository
size stayed **constant at 172 KB**, growth **0 KB/round**.

Safety properties, each verified by an executable test:

- **`--force-with-lease`, never a bare `--force`.** Because publishing now
  targets the same branch humans commit to, a naive force-push would delete their
  work. Run as a negative control: with a plain `--force`, the owner's commit
  count on the remote dropped to **0**. With the lease, a genuinely contested
  push is rejected, the step re-anchors, and both the owner's commit and the new
  output survive.
- **Source-regression guard.** Every path that differs between anchor and tip is
  classified; if anything outside the output set changed, the step refuses to
  publish rather than reverting someone's code.
- **Shallow-checkout aware.** `actions/checkout` fetches depth 1 by default, so
  the only visible commit is normally an output commit and the anchor search
  would find nothing — permanently halting publishing. The step progressively
  deepens (2 → 4 → 8 → 32) until the anchor appears. (`fetch-depth: 0` was
  rejected: cloning 3.55 GB 96 times a day.)
- **Fail-closed everywhere.** Missing output, a suspiciously small config file, or
  an empty tree aborts the publish and leaves the previous good release in place.
- **No recursion.** Pushes made with `GITHUB_TOKEN` do not trigger new workflow
  runs (documented GitHub behaviour), and the `push` trigger is additionally
  filtered to `scripts/**`, which the bot never writes.

### Output is deterministic on purpose

Rolling squash bounds history; determinism keeps each round's diff genuinely
small. Three sources of pointless churn were found by measurement and removed:

| Was | Now |
|---|---|
| Country label read from whichever upstream was fetched first — the same server flipped `RU 🇷🇺` ⇄ `US 🇺🇸` between runs | Label locked to the **endpoint**; first decisive detection wins and is frozen |
| Remark tag was a **positional counter** — inserting one config renamed every line after it | Tag is `sha256(dedup-key)[:6]` — derived from content, immune to position |
| Line order followed network response order | Sorted by dedup key — same set of configs ⇒ same file, byte for byte |

Effect: two back-to-back runs now produce **32 of 34 files byte-identical**; the
only differences are the timestamps in `index.json` / `health.json`.

### One honest caveat

The ~3.55 GB already in history was **not** rewritten. Because GitHub shares
objects across a fork network, a rewrite would reclaim close to nothing while
breaking every existing clone and all 3 forks. The bleeding is stopped going
forward; the old scar is left alone deliberately.

## 📊 Live metadata — `index.json`

`https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/index.json`

Contains per-category counts (unique / duplicates / broken), protocol breakdown,
last-update timestamp, next-update ETA, and every file URL (raw primary + CDN
mirror), plus a `link_policy` block stating which one to prefer and why.

## 🩺 Source health — `health.json`

`https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/health.json`

A per-source health report regenerated on every run: for each of the 21 sources it
records `status` (`ok` / `empty` / `fail`), HTTP code, attempt count, latency, the
yielded config count, and the last error (if any). Makes dead/changed upstreams
immediately visible. A summary (`healthy` / `unhealthy`) is also embedded in `index.json`.

---

## ⚙️ How it works

1. **Fetch** — 21 sources downloaded concurrently (auto base64/direct detection).
   Retries on transient errors, but fails fast on 4xx so a dead URL is reported, not retried.
2. **Clean** — drop dummy/broken (zero-UUID, `App not supported`, empty proxies).
3. **Dedup** — CDN-aware server-identity fingerprint (rotating CDN IPs collapse to one).
4. **Brand** — every remark rewritten to `{CC} {flag} | @Raydikalx | {id}`, where `{id}`
   is `sha256(dedup-key)[:6]`. It is derived from the config itself, so it never shifts
   when the list grows. The country label is locked to the **endpoint**, not to whichever
   upstream happened to be fetched first, so it does not flip between runs either.
5. **Convert** — per-client schema translation with strict field validation:
   cipher whitelists, SS-2022 key lengths, uTLS for REALITY, `short-id`/public-key
   format checks, and full transport emission (`ws` / `grpc` / `h2` / `http` /
   `httpupgrade` / `xhttp`). Entries a client cannot express are dropped rather than
   silently downgraded — a downgraded config looks valid but never connects.
6. **Validate** — `sing-box check` + `mihomo -t` on all six generated files. **Any
   failure aborts the run**, so a broken release can never overwrite a good one.
7. **Publish** — GitHub Actions commits results every ~15 min; served via jsDelivr CDN.

### ⏱️ Reliable ~15-minute scheduling

GitHub's `schedule:` cron is best-effort and is frequently delayed or skipped during
busy periods. To guarantee a steady cadence this repo uses a **three-layer** approach:

1. **High-frequency cron** (`*/5 * * * *`) — more chances to actually fire.
2. **Freshness gate** — each tick exits early if `index.json` was updated < 13 min ago,
   so heavy work runs only ~every 15 min (no wasted runs, no double updates).
3. **`repository_dispatch` fallback** — the always-on bot server sends an
   `aggregate-now` event every 15 min, guaranteeing a run even if cron is dropped.
   Manual `workflow_dispatch` (with optional `force`) is also supported.

## 🙌 Sources

Thanks to all upstream maintainers (mahdibland, peasoft, mahsanet, barry-far,
roosterkid, 4n0nymou3, ALIILAPRO, Epodonios, V2RAYCONFIGSPOOL, ShadowException,
w1770946466 and others). This repo only aggregates, validates & cleans
publicly-available configs.

## 📜 Disclaimer

For educational & research purposes. No uptime/quality guarantee. Use responsibly.

---

**Channel:** [@Raydikalx](https://t.me/Raydikalx) · **Bot:** [@RaydikalxBot](https://t.me/RaydikalxBot)
