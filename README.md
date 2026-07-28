# 🚀 Free V2Ray Configs — by [@Raydikalx](https://t.me/Raydikalx)

[![Aggregate](https://github.com/0xRadikal/Free-v2ray-Configs/actions/workflows/aggregate.yml/badge.svg)](https://github.com/0xRadikal/Free-v2ray-Configs/actions/workflows/aggregate.yml)
![Update](https://img.shields.io/badge/update-every%2015%20min-blue)
![Validated](https://img.shields.io/badge/validated-sing--box%20%2B%20mihomo-success)
![License](https://img.shields.io/github/license/0xRadikal/Free-v2ray-Configs)

> 🇮🇷 [نسخهٔ فارسی](README_FA.md)

Automatically aggregated, **deduplicated**, **branded**, and **client-validated** free
V2Ray / Xray configs. Collected from **21 sources** (7 light + 14 heavy), cleaned with a
CDN-aware deduplication engine, and updated **every ~15 minutes** via GitHub Actions.

All remarks are rebranded to: `{CC} {flag} | @Raydikalx | {index}`

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
> 📌 **Note on the branch:** outputs live on the **`data`** branch, not `main`.
> `main` holds only code and documentation. See
> [Why a separate `data` branch](#-why-a-separate-data-branch).

### 🌐 ALL configs (light + heavy)
| Format | URL (primary — raw) |
|---|---|
| Plain (v2ray) | `https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/data/all/configs.txt` |
| **Base64** (sub) | `https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/data/all/configs_base64.txt` |
| Clash YAML | `https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/data/all/clash.yaml` |
| Sing-box JSON | `https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/data/all/singbox.json` |

### ⭐ LIGHT (curated — sourced from speed-tested upstreams)
- Plain: `…/data/light/configs.txt`
- Base64: `…/data/light/configs_base64.txt`
- Clash: `…/data/light/clash.yaml` · Sing-box: `…/data/light/singbox.json`

### 📦 HEAVY (large, diverse)
- Plain: `…/data/heavy/configs.txt`
- Base64: `…/data/heavy/configs_base64.txt`
- Clash: `…/data/heavy/clash.yaml` · Sing-box: `…/data/heavy/singbox.json`

### 🎯 Per-protocol (from ALL)

Regularly populated: `vless` · `vmess` · `shadowsocks` · `trojan` · `hysteria2` ·
`shadowsocksr` · `tuic`

Also supported (a file appears only when upstreams actually publish that
protocol — empty files are never published, so a missing file means "none this
round"): `hysteria` · `wireguard` · `juicity` · `anytls` · `snell` · `mieru` · `socks`

```
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/data/protocols/vless.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/data/protocols/vless_base64.txt
…and so on for each protocol
```

`index.json` lists exactly which protocol files exist right now, so you never
have to guess.

### 🪞 Mirror (jsDelivr) — only if raw is unreachable

Replace the prefix with
`https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@data/…`

The mirror is purged on every run, but may still trail the primary. If you need
a guaranteed-exact copy through the CDN, pin a commit instead of the branch
(`@<commit-sha>/…`) — verified bit-identical to raw.

---

## 🗂️ Repository structure

Two branches with two different jobs.

**Branch `data`** — machine-generated output only, rewritten every run:

```
all/        configs.txt · configs_base64.txt · clash.yaml · singbox.json   (light + heavy)
heavy/      configs.txt · configs_base64.txt · clash.yaml · singbox.json   (14 heavy sources)
light/      configs.txt · configs_base64.txt · clash.yaml · singbox.json   (7 light sources)
protocols/  vless.txt · vmess.txt · trojan.txt · … (+ *_base64.txt)         (split from ALL)
archive/    <cat>_broken.txt (+ _base64)                                   (rejected configs)
index.json  full metadata: counts, timestamps, protocol breakdown, all URLs
health.json per-source health report: ok/empty/fail, http code, latency, errors
```

**Branch `main`** — human-authored source, normal git history:

```
scripts/    the pipeline (core.py · converters.py · sources.py · aggregate.py · validate.py)
.github/    the scheduled workflow
README.md · README_FA.md · LICENSE
```

Notes on `data`:

- Files in `protocols/` and `archive/` appear **only when non-empty**. A missing
  file means "nothing in this category this round" — an empty file would be
  worse than a 404, because a client subscribed to it would replace its working
  list with nothing, whereas a 404 makes clients keep the previous list.
- `index.json` advertises exactly the files that exist, so its URL list is never
  a promise the repository cannot keep.

<a name="-why-a-separate-data-branch"></a>
## 🌿 Why a separate `data` branch

Git never forgets a blob. Every scheduled run regenerates the same set of large
files, and committing them to a normal branch appends a **new** copy of each
changed file to history forever. The cost of publishing is therefore
**O(number of commits)** and has no upper bound.

That is not hypothetical here. Before this change the repository had grown to
**≈ 3.54 GB across ~5,649 commits** — roughly **69 MB of new history per day** at
~98 commits/day — heading for GitHub's **5 GB** recommended-maximum ceiling in a
matter of weeks, while the *useful* content at any moment is only a few tens of
megabytes.

Reducing the payload alone does not fix this. Trimming the generated output
(dropping the duplicate archives and never publishing empty files) measurably cut
the per-commit cost by **~23 %** and the tracked working tree by **~35 %** — but
because the growth is linear in commit count, that only bought a few extra days.

So outputs are published to an **orphan branch** (`data`) that is rewritten as a
**single commit and force-pushed** on every run. The branch has no parent, so the
previous snapshot becomes unreachable and is garbage-collected instead of
accumulating. Publishing cost becomes **O(1)** — bounded by the size of one
snapshot, not by how long the project has been running.

Consequences you should know about:

- `data` has **no usable history** — that is the entire point. Use `main` for
  code history and blame.
- Both `raw.githubusercontent.com` and `cdn.jsdelivr.net` serve non-default
  branches, so subscription links work exactly as before; only the branch
  segment of the URL changed (`/main/…` → `/data/…`).
- Because the branch ref is force-moved, a CDN that caches by branch name is the
  worst possible consumer of it — another reason raw links are the primary.

## 📊 Live metadata — `index.json`

`https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/data/index.json`

Contains per-category counts (unique / duplicates / broken), protocol breakdown,
last-update timestamp, next-update ETA, and every file URL (raw primary + CDN
mirror), plus a `link_policy` block stating which one to prefer and why.

## 🩺 Source health — `health.json`

`https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/data/health.json`

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
4. **Brand** — every remark rewritten to `{CC} {flag} | @Raydikalx | {index}`.
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
