# 🚀 Free V2Ray Configs — by [@Raydikalx](https://t.me/Raydikalx)

[![Aggregate](https://github.com/0xRadikal/Free-v2ray-Configs/actions/workflows/aggregate.yml/badge.svg)](https://github.com/0xRadikal/Free-v2ray-Configs/actions/workflows/aggregate.yml)
![Update](https://img.shields.io/badge/update-every%2031%20min-blue)
![License](https://img.shields.io/github/license/0xRadikal/Free-v2ray-Configs)

> 🇮🇷 [نسخهٔ فارسی](README_FA.md)

Automatically aggregated, **deduplicated**, and **branded** free V2Ray / Xray configs.
Collected from **22 sources** (9 light + 13 heavy), cleaned with a CDN-aware
deduplication engine, and updated **every ~31 minutes** via GitHub Actions.

All remarks are rebranded to: `{CC} {flag} | @Raydikalx | {index}`

> ⚠️ No TCP health-checking is performed (configs are not connection-tested).
> Dead/broken configs are filtered only via structural rules (dummy UUID / app-not-supported).

---

## 📥 Quick Subscribe (copy a link into your client)

> Served via **jsDelivr CDN** for speed & reliability (recommended).

### 🌐 ALL configs (light + heavy)
| Format | jsDelivr CDN URL |
|---|---|
| Plain (v2ray) | `https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/all/configs.txt` |
| **Base64** (sub) | `https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/all/configs_base64.txt` |
| Clash YAML | `https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/all/clash.yaml` |
| Sing-box JSON | `https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/all/singbox.json` |

### ⭐ LIGHT (high-quality, smaller)
- Plain: `…@main/light/configs.txt`
- Base64: `…@main/light/configs_base64.txt`
- Clash: `…@main/light/clash.yaml` · Sing-box: `…@main/light/singbox.json`

### 📦 HEAVY (large, diverse)
- Plain: `…@main/heavy/configs.txt`
- Base64: `…@main/heavy/configs_base64.txt`
- Clash: `…@main/heavy/clash.yaml` · Sing-box: `…@main/heavy/singbox.json`

### 🎯 Per-protocol (from ALL)
`vless` · `vmess` · `trojan` · `shadowsocks` · `hysteria2` · `hysteria` · `tuic` · `wireguard`

```
https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/protocols/vless.txt
https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/protocols/vless_base64.txt
…and so on for each protocol
```

> Prefer GitHub raw? Replace the prefix with
> `https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/…`

---

## 🗂️ Repository structure

```
all/        configs.txt · configs_base64.txt · clash.yaml · singbox.json   (light + heavy)
heavy/      configs.txt · configs_base64.txt · clash.yaml · singbox.json   (13 heavy sources)
light/      configs.txt · configs_base64.txt · clash.yaml · singbox.json   (9 light sources)
protocols/  vless.txt · vmess.txt · trojan.txt · … (+ *_base64.txt)         (split from ALL)
archive/    <cat>_broken.txt · <cat>_duplicates.txt (+ base64)             (removed configs)
index.json  full metadata: counts, timestamps, protocol breakdown, all URLs
health.json per-source health report: ok/empty/fail, http code, latency, errors
scripts/    the aggregation pipeline (core.py · converters.py · sources.py · aggregate.py)
```

## 📊 Live metadata — `index.json`

`https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/index.json`

Contains per-category counts (unique / duplicates / broken), protocol breakdown,
last-update timestamp, next-update ETA, and every file URL (raw + CDN).

## 🩺 Source health — `health.json`

`https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/health.json`

A per-source health report regenerated on every run: for each of the 22 sources it
records `status` (`ok` / `empty` / `fail`), HTTP code, attempt count, latency, the
yielded config count, and the last error (if any). Makes dead/changed upstreams
immediately visible. A summary (`healthy` / `unhealthy`) is also embedded in `index.json`.

---

## ⚙️ How it works

1. **Fetch** — 22 sources downloaded concurrently (auto base64/direct detection).
2. **Clean** — drop dummy/broken (zero-UUID, `App not supported`, empty proxies).
3. **Dedup** — CDN-aware server-identity fingerprint (rotating CDN IPs collapse to one).
4. **Brand** — every remark rewritten to `{CC} {flag} | @Raydikalx | {index}`.
5. **Emit** — txt + base64 + Clash YAML + Sing-box JSON, per-protocol splits, archives, `index.json`.
6. **Publish** — GitHub Actions commits results every ~31 min; served via jsDelivr CDN.

### ⏱️ Reliable ~31-minute scheduling

GitHub's `schedule:` cron is best-effort and is frequently delayed or skipped during
busy periods. To guarantee a steady cadence this repo uses a **three-layer** approach:

1. **High-frequency cron** (`*/5 * * * *`) — more chances to actually fire.
2. **Freshness gate** — each tick exits early if `index.json` was updated < 28 min ago,
   so heavy work runs only ~every 31 min (no wasted runs, no double updates).
3. **`repository_dispatch` fallback** — the always-on bot server sends an
   `aggregate-now` event every 31 min, guaranteeing a run even if cron is dropped.
   Manual `workflow_dispatch` (with optional `force`) is also supported.

## 🙌 Sources

Thanks to all upstream maintainers (mahsanet, barry-far, roosterkid, 4n0nymou3,
V2RAYCONFIGSPOOL, MahsaNetConfigTopic, ShadowException and others). This repo only
aggregates & cleans publicly-available configs.

## 📜 Disclaimer

For educational & research purposes. No uptime/quality guarantee. Use responsibly.

---

**Channel:** [@Raydikalx](https://t.me/Raydikalx) · **Bot:** [@RaydikalxBot](https://t.me/RaydikalxBot)
