#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aggregate.py — خط‌لولهٔ اصلیِ تجمیع کانفیگ‌های @Raydikalx.

جریان کار (هیچ TCP-connect ای انجام نمی‌شود — مطابق تصمیم کاربر):
  ۱) واکشیِ هم‌زمانِ ۲۲ منبع (۹ سبک + ۱۳ انبوه) با ThreadPool
  ۲) استخراجِ کانفیگ‌های معتبر از هر منبع (direct یا base64)
  ۳) برای سه دستهٔ ALL / HEAVY / LIGHT:
       • حذف خراب‌ها (dummy)  → بایگانیِ broken
       • حذف تکراری‌ها (CDN-aware dedup) → بایگانیِ duplicates
       • برندینگِ یکتاها  «{CC} {flag} | @Raydikalx | {idx}»
  ۴) نوشتنِ خروجی‌ها:
       all|heavy|light/  : configs.txt , configs_base64.txt , clash.yaml , singbox.json
       protocols/        : vless.txt , vmess.txt , ... (روی دستهٔ ALL)
       archive/          : <cat>_broken.txt , <cat>_duplicates.txt  (+ base64)
       index.json        : متادیتای کامل (شمارش‌ها، زمان، پروتکل‌ها، CDN URLها)

اجرا:
    python scripts/aggregate.py --out <output_dir>
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

import requests

# اجازهٔ import وقتی از ریشهٔ ریپو یا از scripts/ اجرا شود
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import core  # noqa: E402
import converters  # noqa: E402
from sources import LIGHT_SOURCES, HEAVY_SOURCES  # noqa: E402

# CDN/raw base — برای درج در index.json
GH_USER = "0xRadikal"
GH_REPO = "Free-v2ray-Configs"
GH_BRANCH = "main"
RAW_BASE = f"https://raw.githubusercontent.com/{GH_USER}/{GH_REPO}/{GH_BRANCH}"
CDN_BASE = f"https://cdn.jsdelivr.net/gh/{GH_USER}/{GH_REPO}@{GH_BRANCH}"

USER_AGENT = "v2rayNG/1.8.36"
FETCH_TIMEOUT = 15
MAX_WORKERS = 12


def log(msg: str) -> None:
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


# ──────────────────────────────────────────────────────────────────────────────
# واکشی منابع
# ──────────────────────────────────────────────────────────────────────────────

def fetch_source(url: str) -> Tuple[str, List[str]]:
    """یک منبع → (url, لیست کانفیگ‌های معتبر). خطا → لیست خالی."""
    try:
        resp = requests.get(url, timeout=FETCH_TIMEOUT, headers={"User-Agent": USER_AGENT})
        if resp.status_code != 200 or not resp.text.strip():
            return url, []
        return url, core.extract_valid_lines(resp.text.strip())
    except Exception as e:
        log(f"  ⚠️ fetch fail {url.split('/')[-1]}: {e}")
        return url, []


def fetch_all(urls: List[str]) -> Dict[str, List[str]]:
    """واکشیِ هم‌زمانِ همهٔ URLها → نگاشت url→configs."""
    results: Dict[str, List[str]] = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(fetch_source, u): u for u in urls}
        for fut in as_completed(futs):
            url, cfgs = fut.result()
            results[url] = cfgs
            log(f"  ✓ {len(cfgs):>5} configs ← {url.split('/')[-1]}")
    return results


# ──────────────────────────────────────────────────────────────────────────────
# پردازش یک دسته (dedup + brand)
# ──────────────────────────────────────────────────────────────────────────────

class CategoryResult:
    def __init__(self) -> None:
        self.unique: List[str] = []        # برند‌شده، یکتا
        self.broken: List[str] = []        # خراب/جعلی
        self.duplicates: List[str] = []    # تکراریِ حذف‌شده
        self.total_seen = 0
        self.active_sources = 0
        self.protocol_counts: Dict[str, int] = {}


def process_category(per_source: Dict[str, List[str]], source_urls: List[str]) -> CategoryResult:
    """dedup سراسری + برندینگ روی کانفیگ‌های یک دسته."""
    r = CategoryResult()
    seen_cores: set = set()
    raw_unique: List[str] = []

    for url in source_urls:
        cfgs = per_source.get(url, [])
        if not cfgs:
            continue
        r.active_sources += 1
        for line in cfgs:
            r.total_seen += 1
            if core.is_dummy_config(line):
                r.broken.append(line)
                continue
            key = core.dedup_key(line)
            if key not in seen_cores:
                seen_cores.add(key)
                raw_unique.append(line)
            else:
                r.duplicates.append(line)

    # برندینگ یکتاها + شمارش پروتکل‌ها
    for idx, line in enumerate(raw_unique, start=1):
        branded = core.brand_remark(line, idx)
        r.unique.append(branded)
        proto = core.protocol_of(branded)
        if proto:
            r.protocol_counts[proto] = r.protocol_counts.get(proto, 0) + 1
    return r


# ──────────────────────────────────────────────────────────────────────────────
# نوشتن فایل‌ها
# ──────────────────────────────────────────────────────────────────────────────

def _write_text(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def write_category(out_dir: str, cat: str, r: CategoryResult) -> None:
    """فایل‌های یک دسته (configs.txt / base64 / clash / singbox)."""
    base = os.path.join(out_dir, cat)
    header = f"# @Raydikalx — {cat.upper()} — {len(r.unique)} unique configs\n"
    _write_text(os.path.join(base, "configs.txt"), header + "\n".join(r.unique) + "\n")
    _write_text(os.path.join(base, "configs_base64.txt"),
                core.encode_base64_subscription(r.unique))
    try:
        _write_text(os.path.join(base, "clash.yaml"), converters.build_clash_yaml(r.unique))
    except Exception as e:
        log(f"  ⚠️ clash {cat}: {e}")
    try:
        _write_text(os.path.join(base, "singbox.json"), converters.build_singbox_json(r.unique))
    except Exception as e:
        log(f"  ⚠️ singbox {cat}: {e}")


def write_archive(out_dir: str, cat: str, r: CategoryResult) -> None:
    """بایگانیِ خراب‌ها و تکراری‌های یک دسته (txt + base64)."""
    base = os.path.join(out_dir, "archive")
    bh = f"# @Raydikalx — {cat.upper()} BROKEN/dummy — {len(r.broken)} configs\n"
    dh = f"# @Raydikalx — {cat.upper()} DUPLICATES — {len(r.duplicates)} configs\n"
    _write_text(os.path.join(base, f"{cat}_broken.txt"), bh + "\n".join(r.broken) + "\n")
    _write_text(os.path.join(base, f"{cat}_duplicates.txt"), dh + "\n".join(r.duplicates) + "\n")
    if r.broken:
        _write_text(os.path.join(base, f"{cat}_broken_base64.txt"),
                    core.encode_base64_subscription(r.broken))
    if r.duplicates:
        _write_text(os.path.join(base, f"{cat}_duplicates_base64.txt"),
                    core.encode_base64_subscription(r.duplicates))


def write_protocols(out_dir: str, all_unique: List[str]) -> Dict[str, int]:
    """فایل‌های per-protocol (روی دستهٔ ALL)."""
    base = os.path.join(out_dir, "protocols")
    buckets: Dict[str, List[str]] = {}
    for line in all_unique:
        proto = core.protocol_of(line)
        if proto:
            buckets.setdefault(proto, []).append(line)
    counts: Dict[str, int] = {}
    for proto in core.PROTOCOL_ORDER:
        lines = buckets.get(proto, [])
        counts[proto] = len(lines)
        h = f"# @Raydikalx — {proto} — {len(lines)} configs\n"
        _write_text(os.path.join(base, f"{proto}.txt"), h + "\n".join(lines) + "\n")
        if lines:
            _write_text(os.path.join(base, f"{proto}_base64.txt"),
                        core.encode_base64_subscription(lines))
    # 🧠 پروتکل‌های ناشناخته/جدید (خارج از ترتیبِ شناخته‌شده) — خودکار فایل می‌سازند
    for proto, lines in sorted(buckets.items(), key=lambda x: -len(x[1])):
        if proto not in counts:
            counts[proto] = len(lines)
            h = f"# @Raydikalx — {proto} — {len(lines)} configs\n"
            _write_text(os.path.join(base, f"{proto}.txt"), h + "\n".join(lines) + "\n")
            if lines:
                _write_text(os.path.join(base, f"{proto}_base64.txt"),
                            core.encode_base64_subscription(lines))
    return counts


def build_index(results: Dict[str, CategoryResult], proto_counts: Dict[str, int],
                elapsed: float) -> dict:
    now = _dt.datetime.now(_dt.timezone.utc)
    next_run = now + _dt.timedelta(minutes=31)

    def cat_block(cat: str, r: CategoryResult) -> dict:
        return {
            "unique": len(r.unique),
            "broken": len(r.broken),
            "duplicates": len(r.duplicates),
            "total_fetched": r.total_seen,
            "active_sources": r.active_sources,
            "protocols": dict(sorted(r.protocol_counts.items(), key=lambda x: -x[1])),
            "files": {
                "configs_txt": f"{CDN_BASE}/{cat}/configs.txt",
                "configs_base64": f"{CDN_BASE}/{cat}/configs_base64.txt",
                "clash_yaml": f"{CDN_BASE}/{cat}/clash.yaml",
                "singbox_json": f"{CDN_BASE}/{cat}/singbox.json",
            },
        }

    return {
        "brand": core.BRAND_CHANNEL,
        "generator": "RaydikalxBot aggregator",
        "updated_at": now.isoformat(),
        "updated_at_unix": int(now.timestamp()),
        "next_update_eta": next_run.isoformat(),
        "update_interval_minutes": 31,
        "elapsed_seconds": round(elapsed, 1),
        "raw_base": RAW_BASE,
        "cdn_base": CDN_BASE,
        "categories": {
            "all": cat_block("all", results["all"]),
            "heavy": cat_block("heavy", results["heavy"]),
            "light": cat_block("light", results["light"]),
        },
        "protocols": dict(sorted(proto_counts.items(), key=lambda x: -x[1])),
        "protocol_files": {
            p: f"{CDN_BASE}/protocols/{p}.txt" for p in core.PROTOCOL_ORDER
        },
        "archive": {
            "all_broken": f"{CDN_BASE}/archive/all_broken.txt",
            "all_duplicates": f"{CDN_BASE}/archive/all_duplicates.txt",
            "heavy_broken": f"{CDN_BASE}/archive/heavy_broken.txt",
            "heavy_duplicates": f"{CDN_BASE}/archive/heavy_duplicates.txt",
            "light_broken": f"{CDN_BASE}/archive/light_broken.txt",
            "light_duplicates": f"{CDN_BASE}/archive/light_duplicates.txt",
        },
        "sources": {
            "light_count": len(LIGHT_SOURCES),
            "heavy_count": len(HEAVY_SOURCES),
            "total_count": len(LIGHT_SOURCES) + len(HEAVY_SOURCES),
        },
    }


# ──────────────────────────────────────────────────────────────────────────────
# main
# ──────────────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="Raydikalx config aggregator")
    ap.add_argument("--out", default=os.getcwd(), help="output directory (repo root)")
    args = ap.parse_args()
    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    t0 = time.time()
    log(f"🚀 Aggregator start → out={out_dir}")
    log(f"📡 Fetching {len(LIGHT_SOURCES)} light + {len(HEAVY_SOURCES)} heavy sources …")

    all_urls = LIGHT_SOURCES + HEAVY_SOURCES
    per_source = fetch_all(all_urls)

    log("🧮 Processing categories (dedup + brand) …")
    res_all = process_category(per_source, all_urls)
    res_heavy = process_category(per_source, HEAVY_SOURCES)
    res_light = process_category(per_source, LIGHT_SOURCES)
    results = {"all": res_all, "heavy": res_heavy, "light": res_light}

    for cat, r in results.items():
        log(f"  • {cat:<5}: {len(r.unique):>6} unique | "
            f"{len(r.duplicates):>6} dup | {len(r.broken):>5} broken | "
            f"{r.active_sources}/{len(HEAVY_SOURCES if cat=='heavy' else LIGHT_SOURCES if cat=='light' else all_urls)} src")

    log("💾 Writing output files …")
    for cat, r in results.items():
        write_category(out_dir, cat, r)
        write_archive(out_dir, cat, r)

    proto_counts = write_protocols(out_dir, res_all.unique)
    log(f"  • protocols: " + ", ".join(f"{k}={v}" for k, v in proto_counts.items() if v))

    elapsed = time.time() - t0
    index = build_index(results, proto_counts, elapsed)
    _write_text(os.path.join(out_dir, "index.json"),
                json.dumps(index, ensure_ascii=False, indent=2))

    # خروجی برای GitHub Actions summary
    log(f"✅ Done in {elapsed:.1f}s — "
        f"ALL={len(res_all.unique)} HEAVY={len(res_heavy.unique)} LIGHT={len(res_light.unique)} unique")

    if res_all.unique == []:
        log("❌ No configs produced — aborting (will not commit empty output)")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
