<div align="center">

<h1>🛰️ Free V2Ray Configs</h1>

<p><b>Auto-aggregated · CDN-aware deduplicated · client-validated · reachability-tested</b><br>
Fresh subscriptions every <b>~15 minutes</b>, published on the default branch — by <a href="https://t.me/Raydikalx">@Raydikalx</a></p>

<p>
<a href="https://github.com/0xRadikal/Free-v2ray-Configs/actions/workflows/aggregate.yml"><img alt="pipeline" src="https://img.shields.io/github/actions/workflow/status/0xRadikal/Free-v2ray-Configs/aggregate.yml?style=for-the-badge&label=pipeline&logo=githubactions&logoColor=white"></a>
<img alt="auto-update" src="https://img.shields.io/badge/auto--update-every%2015%20min-0ea5e9?style=for-the-badge">
<a href="https://0xradikal.github.io/Free-v2ray-Configs/"><img alt="dashboard" src="https://img.shields.io/badge/live-dashboard-ec4899?style=for-the-badge&logo=githubpages&logoColor=white"></a>
<a href="https://t.me/Raydikalx"><img alt="telegram" src="https://img.shields.io/badge/Telegram-%40Raydikalx-229ED9?style=for-the-badge&logo=telegram&logoColor=white"></a>
</p>

<p><i>Live counters — these read the repository's own <code>index.json</code> / <code>health.json</code>, so they are never stale:</i></p>

<p>
<img alt="configs" src="https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2F0xRadikal%2FFree-v2ray-Configs%2Fmain%2Findex.json&query=%24.categories.all.unique&label=configs&color=2563eb&style=for-the-badge">
<img alt="verified" src="https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2F0xRadikal%2FFree-v2ray-Configs%2Fmain%2Fhealth.json&query=%24.cascade.buckets.verified&label=verified&color=16a34a&style=for-the-badge&logo=checkmarx">
<img alt="fast" src="https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2F0xRadikal%2FFree-v2ray-Configs%2Fmain%2Fhealth.json&query=%24.cascade.buckets.fast&label=fast&color=f59e0b&style=for-the-badge">
<img alt="secure" src="https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2F0xRadikal%2FFree-v2ray-Configs%2Fmain%2Fhealth.json&query=%24.cascade.buckets.secure&label=secure&color=7c3aed&style=for-the-badge">
<img alt="sources live" src="https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2F0xRadikal%2FFree-v2ray-Configs%2Fmain%2Fhealth.json&query=%24.summary.ok&label=sources%20live&color=0891b2&style=for-the-badge">
<img alt="license" src="https://img.shields.io/github/license/0xRadikal/Free-v2ray-Configs?style=for-the-badge&color=334155">
</p>

<p>
🇮🇷 <a href="README_FA.md">نسخهٔ فارسی</a> · 🇨🇳 <a href="README_ZH.md">中文版</a> · 🇷🇺 <a href="README_RU.md">Русская версия</a>
</p>

</div>

---

# ⚡ Subscription links

> **In a hurry? Copy this one line into your client.** It is the most reliable list this
> repository produces — every entry answered a real HTTP request through the proxy in
> **all three** independent test rounds:
>
> ```
> https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs_base64.txt
> ```
>
> Want the largest possible list instead of the most reliable one? Swap `verified` for `all`.

## 🎛️ Choose a tier

Six tiers are published every run. They are not different sources — they are the **same
pool, filtered by how much evidence there is that a config actually works**.

| Tier | What gets in | Plain | Base64 | Clash | Sing-box |
|:--|:--|:--:|:--:|:--:|:--:|
| 🏆 **`verified`** | passed a real proxied request in **all 3** rounds — *recommended* | [txt](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt) | [b64](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs_base64.txt) | [yaml](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/clash.yaml) | [json](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/singbox.json) |
| ⚡ **`fast`** | `verified` **and** median delay `< 800 ms` | [txt](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs.txt) | [b64](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs_base64.txt) | [yaml](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/clash.yaml) | [json](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/singbox.json) |
| 🔐 **`secure`** | `verified` **and** forward secrecy, **and** the link does not disable cert validation | [txt](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/configs.txt) | [b64](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/configs_base64.txt) | [yaml](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/clash.yaml) | [json](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/singbox.json) |
| 🌐 **`all`** | everything, deduplicated — largest list, mostly untested | [txt](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt) | [b64](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs_base64.txt) | [yaml](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/clash.yaml) | [json](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/singbox.json) |
| 📦 **`heavy`** | the 14 high-volume upstreams only | [txt](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/heavy/configs.txt) | [b64](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/heavy/configs_base64.txt) | [yaml](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/heavy/clash.yaml) | [json](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/heavy/singbox.json) |
| ⭐ **`light`** | the 7 curated / speed-tested upstreams only | [txt](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/light/configs.txt) | [b64](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/light/configs_base64.txt) | [yaml](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/light/clash.yaml) | [json](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/light/singbox.json) |

**Which format?** `configs_base64.txt` is the classic subscription format and the safest
default. `configs.txt` is the same list unencoded. `clash.yaml` is a full mihomo/Clash
profile; `singbox.json` is a full sing-box config — both are validated by the real
binaries before publishing (see [below](#-every-release-is-checked-by-the-real-clients)).

## 📋 Copy-paste: every tier URL

```text
# ── verified — passed all 3 rounds (recommended) ───────────────────────────────
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs_base64.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/clash.yaml
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/singbox.json

# ── fast — verified and median delay < 800 ms ──────────────────────────────────
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs_base64.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/clash.yaml
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/singbox.json

# ── secure — verified and forward secrecy ──────────────────────────────────────
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/configs.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/configs_base64.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/clash.yaml
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/singbox.json

# ── all — light + heavy, deduplicated ──────────────────────────────────────────
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs_base64.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/clash.yaml
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/singbox.json

# ── heavy — high-volume upstreams ──────────────────────────────────────────────
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/heavy/configs.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/heavy/configs_base64.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/heavy/clash.yaml
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/heavy/singbox.json

# ── light — curated upstreams ──────────────────────────────────────────────────
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/light/configs.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/light/configs_base64.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/light/clash.yaml
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/light/singbox.json

# ── top 100 — the verified list, sorted by median delay ────────────────────────
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt
```

## 🎯 Per-protocol links

Split out of `all/`. A file is published **only when it is non-empty**, so a 404 means
"nothing of this protocol this round" — never an empty subscription that would wipe your
client's list.

| Protocol | Plain | Base64 |
|:--|:--|:--|
| VLESS | `…/main/protocols/vless.txt` | `…/main/protocols/vless_base64.txt` |
| VMess | `…/main/protocols/vmess.txt` | `…/main/protocols/vmess_base64.txt` |
| Trojan | `…/main/protocols/trojan.txt` | `…/main/protocols/trojan_base64.txt` |
| Shadowsocks | `…/main/protocols/shadowsocks.txt` | `…/main/protocols/shadowsocks_base64.txt` |
| ShadowsocksR | `…/main/protocols/shadowsocksr.txt` | `…/main/protocols/shadowsocksr_base64.txt` |
| Hysteria2 | `…/main/protocols/hysteria2.txt` | `…/main/protocols/hysteria2_base64.txt` |
| TUIC | `…/main/protocols/tuic.txt` | `…/main/protocols/tuic_base64.txt` |
| SOCKS | `…/main/protocols/socks.txt` | `…/main/protocols/socks_base64.txt` |

<details>
<summary><b>📎 Full per-protocol URLs (copy-paste)</b></summary>

```text
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vless.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vless_base64.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vmess.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vmess_base64.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/trojan.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/trojan_base64.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/shadowsocks.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/shadowsocks_base64.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/shadowsocksr.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/shadowsocksr_base64.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/hysteria2.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/hysteria2_base64.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/tuic.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/tuic_base64.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/socks.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/socks_base64.txt
```

`hysteria` · `wireguard` · `juicity` · `anytls` · `snell` · `mieru` are recognised by the
parser too, but were **empty in the snapshot below** — no upstream published any. The
authoritative, always-current list of protocol files that exist right now is the
`protocol_files` block of [`index.json`](#-machine-readable-metadata).

</details>

<a name="-machine-readable-metadata"></a>

## 🧭 Machine-readable metadata

| File | What it is |
|:--|:--|
| [`index.json`](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/index.json) | every counter, timestamp, next-update ETA and **every file URL** (raw + mirror) |
| [`health.json`](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/health.json) | per-source health, converter drops, geo stats, and the full `cascade` test report |
| [`state.json`](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/state.json) | rolling per-source yield history and auto-disable decisions |
| [`top100.txt`](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt) | the 100 lowest-latency verified configs |
| [`archive/all_broken.txt`](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/archive/all_broken.txt) | what was rejected, and kept visible on purpose (+ `_base64`, + `heavy_broken*`) |

## 🪞 Mirror (jsDelivr) — only if `raw.githubusercontent.com` is blocked

Replace the prefix `https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main`
with `https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main` — every path above
exists on the mirror unchanged.

```
https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/verified/configs_base64.txt
```

**Prefer raw when you can.** This is the repository's own `link_policy`, not an opinion:

| | cache directive | worst-case staleness |
|:--|:--|:--|
| `raw.githubusercontent.com` | `max-age=300` | **5 minutes** |
| `cdn.jsdelivr.net` (branch ref) | `s-maxage=43200` | **12 hours** — 144× longer |

The CDN is purged on every run, but purging clears only the edge; jsDelivr's origin can
still lag while it re-resolves the branch name. If you need a guaranteed-exact copy
through the CDN, pin a commit instead of the branch: `@<commit-sha>/…`.

> 📌 **Everything is on the default branch (`main`).** No branch switching, no hidden
> location — a link you copied months ago still works. Why that is not as obvious as it
> sounds: [How publishing stays cheap](#-how-publishing-stays-cheap-and-why-the-files-live-on-main).

---

<a name="-does-it-actually-work"></a>

# 🧪 Does it actually work?

Most free-config repositories publish a big number and let you guess. Here is the
uncomfortable answer, **measured rather than estimated**: the large majority of any free
config pool is dead at any given moment. That is a property of free configs, not of this
repository — so instead of hiding it, every run measures it and sorts by it.

Each config is pushed through four stages. Every stage is cheap enough to run on the
whole pool, and each one throws away work the next stage would have wasted:

| Stage | The question it asks | Cost |
|:--|:--|:--|
| **L0 / L1** | Is it parsable, is the endpoint unique, is it routable? | no network |
| **L2** | Does the TCP port actually accept a connection? | one connect per unique endpoint |
| **L3** | Does a **real HTTP request through the proxy** succeed? | full handshake, repeated **3×** |
| **buckets** | Which ones passed *every* L3 round? | sorting only |

A config reaches `verified/` only if it passed **every** round — never just its best one.

## 📉 The funnel, on a real release

<div align="center">

**Snapshot: `2026-08-02 07:38:41 UTC` · run took 216 s · test ran from a 🇺🇸 US runner (Cloudflare colo `SJC`)**

</div>

| Stage | Configs | Share of pool |
|:--|--:|--:|
| fetched from 17 live sources | 14,225 | — |
| **unique after CDN-aware dedup** | **10,116** | **100 %** |
| structurally valid (L0/L1) | 10,066 | 99.5 % |
| TCP port open (L2) | 5,231 | 51.7 % |
| worked **at least once** (L3) | 1,280 | 12.7 % |
| worked in **all 3** rounds → `verified/` | **844** | **8.3 %** |

The three L3 rounds individually returned **1,125 / 1,053 / 1,042** successes — but only
**844** configs are in all three sets. **34.06 %** of everything that ever worked is
flaky. Publishing "everything that worked once" would have overstated the result by
**1.52×**; publishing the best single round, by **1.33×**. That gap is the entire reason
the L3 stage runs more than once.

> ### ⚠️ Read this before quoting the percentage
>
> **8.3 % is not a constant, and it is not a claim about your connection.** It was
> measured from **one host, in the United States, on one day**. A config that fails from
> a GitHub runner in San José may work perfectly from Tehran — and the reverse is just
> as true.
>
> So: **`verified/` means "this config answered a real request from the machine that ran
> the test" — not "this config will work for you."** The numbers for the exact release
> you are downloading, plus the country the test ran from, are recorded in the `cascade`
> block of [`health.json`](#-source-health--healthjson). **Trust that file over any
> number written in this README**, which is a dated snapshot by construction.

<details>
<summary><b>📊 Everything else that snapshot measured</b></summary>

| | |
|:--|:--|
| **Tier sizes** | `all` 10,116 · `heavy` 8,462 · `light` 2,472 · `verified` 844 · `fast` 460 · `secure` 474 · `top100` 100 |
| **Protocols** | vless 3,668 · vmess 3,215 · shadowsocks 2,117 · trojan 961 · hysteria2 120 · shadowsocksr 28 · socks 5 · tuic 2 |
| **Dedup** | 4,108 duplicates removed; 10,116 configs collapse to 8,574 unique endpoints (**14.82 %** of L2 work saved) |
| **Dropped at L0/L1** | 50 total — unparsable 21 · unroutable server 16 · invalid server 10 · invalid UUID 2 · invalid port 1 |
| **DNS** | 324 endpoints failed to resolve at L2; 6,268 hosts geolocated, 303 unknown |
| **Converter drops** | Clash 50 · sing-box 379 (331 of them simply *not expressible* in the sing-box schema) |
| **Sources** | 21 configured (7 light + 14 heavy) · 17 returned configs · 0 empty · 0 failed |
| **Stage timings** | L0/L1 0.4 s · L2 36.4 s · L3 178.3 s · total 215.6 s |

</details>

---

<a name="-every-release-is-checked-by-the-real-clients"></a>

# ✅ Every release is checked by the real clients

A **single** malformed entry makes a client reject the **entire file** — so "mostly
valid" output is worth nothing. Before anything is published, every generated
`clash.yaml` and `singbox.json` is parsed by the same binaries you run:

```bash
sing-box check -c <file>      # sing-box 1.13.14
mihomo -t -f <file>           # mihomo   v1.19.29
```

Both binaries are **version-pinned and SHA256-verified** at download time in the
workflow. If any file fails validation, **the run aborts and nothing is committed** —
the previous good release stays exactly where it is.

> ⚠️ **Structural validity is not the same as working.** Structurally broken entries
> (zero UUIDs, `App not supported`, unsupported ciphers, malformed REALITY keys) are
> dropped — but a syntactically perfect config can still be dead. That is a different
> question, and it is answered separately by the [L3 cascade above](#-does-it-actually-work).

## 🏷️ Stable, content-derived names

Every remark is rewritten to `{CC} {flag} | @Raydikalx | {id}`, where `{id}` is
`sha256(dedup-key)[:6]` — **derived from the config itself, not from its position in the
list**. The same server therefore always gets the same tag, so your client's entry names
stay stable between updates instead of being reshuffled every 15 minutes.

---

# 🗂️ Repository layout

**One branch — `main`.** Source code and published output live side by side on the
default branch, which is exactly what a visitor sees when they open the repository.

Machine-generated, refreshed every run (**48 files**):

```
verified/   configs.txt · configs_base64.txt · clash.yaml · singbox.json   passed all 3 L3 rounds
fast/       configs.txt · configs_base64.txt · clash.yaml · singbox.json   verified + median < 800ms
secure/     configs.txt · configs_base64.txt · clash.yaml · singbox.json   verified + forward secrecy
all/        configs.txt · configs_base64.txt · clash.yaml · singbox.json   light + heavy, deduplicated
heavy/      configs.txt · configs_base64.txt · clash.yaml · singbox.json   14 high-volume upstreams
light/      configs.txt · configs_base64.txt · clash.yaml · singbox.json   7 curated upstreams
protocols/  vless.txt · vmess.txt · trojan.txt · … (+ *_base64.txt)        split out of all/
archive/    all_broken.txt · heavy_broken.txt (+ _base64)                  what was rejected
top100.txt  the 100 lowest-latency verified configs
index.json  counts · timestamps · protocol breakdown · every file URL
health.json per-source health · converter drops · geo · the full cascade report
state.json  rolling per-source yield history and auto-disable decisions
```

Human-authored, with normal git history and blame:

```
scripts/    the pipeline — core · sources · filters · converters · geo · reachability
            realtest · pipeline · aggregate · validate · state (+ test_pipeline.py)
.github/    the scheduled workflow · Dependabot config · issue templates
docs/       the live status dashboard (reads index.json / health.json in the browser)
README.md · README_FA.md · README_ZH.md · README_RU.md
SECURITY.md · CONTRIBUTING.md · LICENSE
```

Two rules that are easy to miss and matter a lot:

- **Empty files are never published.** A file in `protocols/` or `archive/` appears only
  when it has content. An empty file would be *worse* than a 404: a client subscribed to
  it would replace its working list with nothing, whereas a 404 makes clients keep what
  they already have.
- **`index.json` advertises exactly the files that exist** — its URL list is never a
  promise the repository cannot keep.

<a name="-how-publishing-stays-cheap-and-why-the-files-live-on-main"></a>

# 🌿 How publishing stays cheap (and why the files live on `main`)

Git never forgets a blob. Every scheduled run regenerates the same set of large files,
and appending them to a branch the normal way adds a **new permanent copy** of each
changed file to history — forever. Publishing then costs **O(number of runs)**, with no
upper bound. At ~96 runs a day that is not a theoretical concern: this repository's
history had already grown to **≈ 3.6 GiB** before the fix.

### ❌ The wrong fix (tried, and reverted)

Move the output to an **orphan branch**, force-pushed as a single commit. Publishing cost
did drop to O(1) — and the project quietly broke:

- **Every previously copied subscription link returned HTTP 404.** A user whose client
  pointed at `…/main/all/configs.txt` did not get an error dialog; the subscription just
  silently went empty.
- **A visitor opening the repository saw no configs at all** — only code. Most people
  looking for a config have no idea what a git branch is, let alone that they should
  switch to a second one and look again.
- **Discoverability collapsed.** GitHub search, the landing page and search engines all
  index the default branch.
- **Not one successful repository in this space does it.** Checked directly:
  `Epodonios/v2ray-configs`, `mahdibland/V2RayAggregator`, `Pawdroid/Free-servers` —
  all publish on their default branch.

Cheap history is worth nothing if nobody can find the files.

### ✅ The right fix — rolling squash on `main`

Output is published **to the default branch**, but the branch is kept at
*source history + exactly one output commit*:

1. Find the newest commit **not** marked `[auto-output]` — the **anchor**.
2. Build a tree = *anchor's tree* + *this run's fresh output*.
3. `git commit-tree <tree> -p <anchor>` and push **with a lease**.

The previous output commit becomes unreachable and is garbage-collected. You can read
this straight off the log — it strictly alternates, one output commit per human commit,
no matter how many runs happened in between:

```
94a939f23  bot     chore: update configs — 07:42 UTC — 10116 configs   ← the only live output
e5a0e7dbf  human   docs: rebuild the status dashboard …
a72b66717  bot     chore: update configs — 22:12 UTC — 10146 configs
19b8d6cca  human   docs(security): document the branch and tag rulesets …
```

Publishing cost is **O(1)** — while every file stays exactly where users and crawlers
already look for it.

Each safety property below is backed by an executable test:

- **`--force-with-lease`, never a bare `--force`.** Publishing targets the same branch
  humans commit to, so a naive force-push would delete their work. Run as a negative
  control, a plain `--force` dropped the owner's commit count on the remote to **0**.
  With the lease, a genuinely contested push is rejected, the step re-anchors, and both
  the owner's commit and the new output survive.
- **Source-regression guard.** Every path that differs between anchor and tip is
  classified; if anything outside the output set changed, the step refuses to publish
  rather than reverting someone's code.
- **Shallow-checkout aware.** `actions/checkout` fetches depth 1, so the only visible
  commit is normally an output commit and the anchor search would find nothing —
  permanently halting publishing. The step progressively deepens (2 → 4 → 8 → 32) until
  the anchor appears. (`fetch-depth: 0` was rejected: cloning gigabytes 96 times a day.)
- **Fail-closed everywhere.** Missing output, a suspiciously small config file, or an
  empty tree aborts the publish and leaves the previous good release in place.
- **No recursion.** Pushes made with `GITHUB_TOKEN` do not trigger new workflow runs, and
  the `push` trigger is additionally filtered to `scripts/**`, which the bot never writes.

### 🧊 Output is deterministic on purpose

Rolling squash bounds history; determinism keeps each round's diff genuinely small. Three
sources of pointless churn were found by measurement and removed:

| Was | Now |
|:--|:--|
| Country label taken from whichever upstream was fetched first — the same server flipped `RU 🇷🇺` ⇄ `US 🇺🇸` between runs | Label locked to the **endpoint**; the first decisive detection wins and is frozen |
| Remark tag was a **positional counter** — inserting one config renamed every line after it | Tag is `sha256(dedup-key)[:6]`, derived from content and immune to position |
| Line order followed network response order | Sorted by dedup key — the same set of configs produces the same file, byte for byte |

Determinism does **not** mean the files stop changing; it means they change *only when
the data changes* — and the churn that used to happen *without* a data change is gone.

### 🩹 One honest caveat

The ≈ 3.6 GiB already in history was **not** rewritten. Because GitHub shares objects
across a fork network, a rewrite would reclaim close to nothing while breaking every
existing clone and both forks. The bleeding is stopped going forward; the old scar is
left alone deliberately.

---

# 📊 Live metadata — `index.json`

```
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/index.json
```

Per-category counts (unique / duplicates / broken / active sources), the protocol
breakdown, the last-update timestamp, the next-update ETA, **every file URL** (raw
primary + CDN mirror), and a `link_policy` block stating which one to prefer and why.

If you are building anything on top of this repository, read `index.json` instead of
hardcoding paths — it is the contract, and it can never advertise a file that does not
exist.

<a name="-source-health--healthjson"></a>

# 🩺 Source health & test report — `health.json`

```
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/health.json
```

Regenerated every run. For each of the 21 sources it records `status`
(`ok` / `empty` / `fail`), HTTP code, attempt count, latency, the yielded config count and
the last error — so a dead or changed upstream is visible immediately instead of silently
shrinking the output.

The same file carries the **`cascade`** block: the numbers come from the machine that
produced the release, not from this README. This is the block from the snapshot above,
abridged:

```jsonc
"cascade": {
  "exit_country": { "colo": "SJC", "loc": "US",          // where the test ran from
                    "source": "https://cp.cloudflare.com/cdn-cgi/trace" },
  "layers": {
    "l0_l1": { "in": 10116, "out": 10066, "seconds": 0.42,
               "endpoints_unique": 8574, "dedup_saving_pct": 14.82,
               "dropped": { "unparsable": 21, "invalid_port": 1, "invalid_uuid": 2,
                            "unroutable_server": 16, "invalid_server": 10 } },
    "l2":    { "in": 10066, "out": 5231, "open_pct": 51.97,
               "open_pct_of_raw_input": 51.71, "dns_failed": 324,
               "dns_seconds": 20.41, "tcp_seconds": 15.59, "seconds": 36.44 },
    "l3":    { "in": 5231, "rounds": 3, "per_run_ok": [1125, 1053, 1042],
               "ever_ok": 1280, "stable": 844, "flaky_pct": 34.06,
               "seconds": 178.26 }
  },
  "buckets": { "verified": 844, "fast": 460, "secure": 474, "top": 100,
               "top_short_by": 0, "fast_threshold_ms": 800 },
  "total_seconds": 215.59
}
```

Three details worth knowing:

- **`exit_country`** is the country the *test* ran from — the single most important
  caveat when reading any success rate. Only `loc` and `colo` are recorded; the runner's
  IP address is deliberately never published.
- **`dropped`** names the reason each config was rejected, so a source that starts
  emitting garbage becomes visible instead of just quietly shrinking the output.
- **`per_run_ok` vs `stable`** shows flakiness directly. `stable` counts only configs
  that passed *every* round — and that is what `verified/` is built from.

## 📈 Live dashboard

**<https://0xradikal.github.io/Free-v2ray-Configs/>**

A single self-contained page that fetches `index.json` and `health.json` in your browser
and renders the cascade, the buckets, per-source health, the geo breakdown and the
converter drops. It makes **zero** external requests — no CDN, no tracker, no fonts —
and falls back to the jsDelivr mirror automatically if raw is unreachable.

---

# ⚙️ How it works

1. **Fetch** — 21 sources downloaded concurrently, with automatic base64/plain detection.
   Retries on transient errors, but fails fast on 4xx so a dead URL is *reported*, not
   silently retried forever.
2. **Clean** — drop dummy and structurally broken entries (zero UUID,
   `App not supported`, empty proxies, unroutable servers).
3. **Dedup** — a CDN-aware server-identity fingerprint, so a host behind rotating CDN IPs
   collapses to a single entry instead of appearing dozens of times.
4. **Brand** — every remark rewritten to `{CC} {flag} | @Raydikalx | {id}` with a
   content-derived `{id}` and an endpoint-locked country label.
5. **Convert** — per-client schema translation with strict field validation: cipher
   whitelists, SS-2022 key lengths, uTLS for REALITY, `short-id` / public-key format
   checks, and full transport emission (`ws` / `grpc` / `h2` / `http` / `httpupgrade` /
   `xhttp`). Entries a client cannot express are **dropped, not silently downgraded** —
   a downgraded config looks valid and never connects.
6. **Verify** — `sing-box check` + `mihomo -t` on every generated file. **Any failure
   aborts the run.**
7. **Test** — the L0→L3 cascade actually connects through the proxies, three times, and
   builds `verified/`, `fast/`, `secure/` and `top100.txt`.
8. **Publish** — rolling-squash commit to `main`, plus a jsDelivr purge.

## ⏱️ Reliable ~15-minute scheduling

GitHub's `schedule:` cron is best-effort and is frequently delayed or skipped during busy
periods. To hold a steady cadence anyway, this repository uses **three layers**:

1. **High-frequency cron** (`*/5 * * * *`) — more chances to actually fire.
2. **Freshness gate** — each tick exits immediately if `index.json` was updated less than
   13 minutes ago, so the heavy work runs only about every 15 minutes: no wasted runs, no
   double updates.
3. **`repository_dispatch` fallback** — an always-on bot sends an `aggregate-now` event
   every 15 minutes, guaranteeing a run even if cron is dropped entirely. Manual
   `workflow_dispatch` (with an optional `force`) is supported too.

---

# 🤝 Contributing, security, license

| | |
|:--|:--|
| 🐛 **Found a broken source or a bad config?** | Open an issue — the templates are in `.github/` |
| 🔐 **Security policy** | [`SECURITY.md`](SECURITY.md) |
| 📐 **Contribution guide** | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| 📜 **License** | [MIT](LICENSE) |

## 🙌 Sources

Thanks to every upstream maintainer — mahdibland, peasoft, mahsanet, barry-far,
roosterkid, 4n0nymou3, ALIILAPRO, Epodonios, V2RAYCONFIGSPOOL, ShadowException,
w1770946466 and others. This repository only aggregates, deduplicates, validates and
tests publicly available configs. The full, current list with per-source health lives in
[`health.json`](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/health.json).

## 📜 Disclaimer

For educational and research purposes. No uptime or quality guarantee — see the
[measured reality](#-does-it-actually-work) above, which is published precisely so that
nothing here has to be taken on faith. Use responsibly and in accordance with your local
laws.

---

<div align="center">

**Channel:** [@Raydikalx](https://t.me/Raydikalx) · **Bot:** [@RaydikalxBot](https://t.me/RaydikalxBot)

<sub>Every number in this README is a dated snapshot. The live numbers are always in
<a href="https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/index.json"><code>index.json</code></a> and
<a href="https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/health.json"><code>health.json</code></a>.</sub>

</div>
