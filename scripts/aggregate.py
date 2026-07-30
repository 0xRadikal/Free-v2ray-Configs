#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aggregate.py — خط‌لولهٔ اصلیِ تجمیع کانفیگ‌های @Raydikalx.

جریان کار (هیچ TCP-connect ای انجام نمی‌شود — مطابق تصمیم کاربر):
  ۱) واکشیِ هم‌زمانِ ۲۱ منبع (۷ سبک + ۱۴ انبوه) با ThreadPool
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
from typing import Dict, List, Optional, Tuple

import requests

# اجازهٔ import وقتی از ریشهٔ ریپو یا از scripts/ اجرا شود
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import core  # noqa: E402
import converters  # noqa: E402
import state as memory  # noqa: E402
from sources import LIGHT_SOURCES, HEAVY_SOURCES  # noqa: E402

# geo اختیاری است: اگر پایگاه‌دادهٔ GeoIP یا کتابخانه‌اش در دسترس نباشد، خط‌لوله
# باید همان‌طور که پیش از این کار می‌کرد کار کند، فقط با برچسب‌های ضعیف‌تر.
# پس ایمپورتِ آن هرگز نباید اجرا را متوقف کند.
try:
    import geo  # noqa: E402
except Exception:  # pragma: no cover - محیطِ بدونِ geo
    geo = None  # type: ignore

# ──────────────────────────────────────────────────────────────────────────────
# پایهٔ لینک‌ها — برای درج در index.json
#
# چرا raw شد لینکِ «اصلی» و jsDelivr شد «آینه»؟
#   این یک سلیقه نیست؛ اندازه‌گیریِ زندهٔ همین مخزن است:
#     raw.githubusercontent →  cache-control: max-age=300            (۵ دقیقه)
#     cdn.jsdelivr.net      →  cache-control: ... s-maxage=43200     (۱۲ ساعت)
#   و مستنداتِ رسمیِ jsDelivr هم صریح می‌گوید کشِ «Branches» دوازده ساعت است.
#   در یک سنجشِ زنده، jsDelivr نسخه‌ای ۱۲ساعت‌و‌۴۵دقیقه‌ای را سرو می‌کرد
#   (۴٬۳۵۳ کانفیگ) در حالی که raw نسخهٔ تازه را می‌داد (۸٬۱۶۸ کانفیگ) —
#   یعنی ۵۱ برابرِ بازهٔ هدفِ ۱۵ دقیقه‌ای. پس تلاش برای رسیدن به آپدیتِ
#   ۱۵ دقیقه‌ای، برای هر کسی که لینکِ jsDelivr را subscribe کرده بود، بی‌اثر بود.
#   حالا: لینکِ اصلی = raw (۱۴۴ برابر تازه‌تر)، و jsDelivr به‌عنوان mirror
#   می‌ماند (برای کاربرانی که raw برایشان فیلتر است) و در هر دور با
#   Purge API پاک می‌شود (مرحلهٔ پاک‌سازیِ کش در ورک‌فلو).
#
# خروجی‌ها روی همان برنچِ پیش‌فرض (`main`) منتشر می‌شوند.
#
#   یک نسخهٔ میانی خروجی‌ها را به شاخهٔ جداگانهٔ `data` برد تا تاریخِ `main`
#   متورم نشود. آن تصمیم از نظرِ حجمِ گیت درست بود ولی از نظرِ محصول اشتباه:
#
#     • کاربری که دنبالِ کانفیگ است لازم نیست بداند «برنچ» چیست؛ او صفحهٔ
#       اصلیِ ریپو را باز می‌کند و روی فایل کلیک می‌کند. با انتقال به `data`
#       صفحهٔ اصلی خالی می‌شد و کانفیگ‌ها عملاً پنهان می‌شدند.
#     • هر لینکی که کاربران قبلاً کپی کرده بودند (`.../main/all/configs.txt`)
#       ۴۰۴ می‌شد — سنجیده و تأییدشده. یعنی subscriptionِ کارِ مردم می‌شکست.
#     • موتورهای جست‌وجو و ویترینِ ریپو هم فقط برنچِ پیش‌فرض را نشان می‌دهند،
#       پس کشف‌پذیری و ستاره‌گرفتن آسیب می‌دید.
#
#   بررسیِ ریپوهای شاخصِ همین حوزه هم همین را می‌گوید: هیچ‌کدام خروجی را روی
#   برنچِ جدا نمی‌گذارند (Epodonios روی main، mahdibland روی master،
#   Pawdroid روی main).
#
#   مسئلهٔ حجم به‌جای «برنچِ جدا» با دو کار حل می‌شود:
#     ۱) پایدارسازیِ خروجی (برچسبِ کشور و شناسهٔ ریمارک دیگر بین اجراها
#        نمی‌رقصند و خطوط مرتب‌اند) ⇒ diffِ هر انتشار کوچک می‌شود.
#     ۲) «rolling squash» در ورک‌فلو: کامیتِ خروجی همیشه روی آخرین کامیتِ
#        سورس بسته می‌شود، پس در هر لحظه فقط یک کامیتِ خروجی روی `main`
#        وجود دارد و تاریخ انباشته نمی‌شود (هزینهٔ O(1) به‌جای O(commits)).
#
#   برنچ hard-code نیست تا تست‌ها و ورک‌فلو بتوانند مقدارش را بدهند.
# ──────────────────────────────────────────────────────────────────────────────
GH_USER = os.environ.get("AGG_GH_USER", "0xRadikal")
GH_REPO = os.environ.get("AGG_GH_REPO", "Free-v2ray-Configs")

# نامِ برنچِ انتشار از محیط خوانده می‌شود. `PUBLISH_BRANCH` نامِ صریحِ امروزی
# است؛ دو نامِ قدیمی (`AGG_DATA_BRANCH` / `DATA_BRANCH`) برای سازگاریِ عقب‌رو
# پذیرفته می‌شوند تا اگر جایی مانده باشد بی‌صدا خراب نشود. اگر هیچ‌کدام ست
# نشده باشند، پیش‌فرض همان برنچِ پیش‌فرضِ ریپو است.
GH_BRANCH = (os.environ.get("AGG_PUBLISH_BRANCH")
             or os.environ.get("PUBLISH_BRANCH")
             or os.environ.get("AGG_DATA_BRANCH")
             or os.environ.get("DATA_BRANCH")
             or "main")
RAW_BASE = f"https://raw.githubusercontent.com/{GH_USER}/{GH_REPO}/{GH_BRANCH}"
CDN_BASE = f"https://cdn.jsdelivr.net/gh/{GH_USER}/{GH_REPO}@{GH_BRANCH}"
# از این پس هرجا یک لینکِ «اصلی» لازم است از PRIMARY_BASE استفاده می‌شود.
PRIMARY_BASE = RAW_BASE
MIRROR_BASE = CDN_BASE

# چند User-Agent متفاوت — برخی منابع به UAِ خاصی پاسخِ بهتر می‌دهند
USER_AGENTS = (
    "v2rayNG/1.8.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "ClashforWindows/0.20.39",
)
FETCH_TIMEOUT = int(os.getenv("AGG_FETCH_TIMEOUT", "15"))
MAX_WORKERS = int(os.getenv("AGG_MAX_WORKERS", "16"))
FETCH_RETRIES = int(os.getenv("AGG_FETCH_RETRIES", "3"))  # تعدادِ تلاشِ مجدد در صورتِ خطا/خالی‌بودن
RETRY_BACKOFF = 1.5        # ثانیه × شمارهٔ تلاش

#: بازهٔ به‌روزرسانی (دقیقه) — باید با raydikalx/repo_trigger.py و
#: UPDATE_INTERVAL_MINUTES در aggregate.yml هماهنگ باشد (پیش‌فرض ۱۵).
#: قابلِ override با متغیرِ محیطی AGG_UPDATE_INTERVAL_MIN.
UPDATE_INTERVAL_MIN = int(os.getenv("AGG_UPDATE_INTERVAL_MIN", "15"))

#: گزارشِ سلامتِ منابع (پر می‌شود در fetch_all) — برای index.json و health.json
SOURCE_HEALTH: Dict[str, dict] = {}


def log(msg: str) -> None:
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


# ──────────────────────────────────────────────────────────────────────────────
# واکشی منابع (با retry + backoff + گزارشِ سلامت)
# ──────────────────────────────────────────────────────────────────────────────

def fetch_source(url: str) -> Tuple[str, List[str]]:
    """یک منبع → (url, لیست کانفیگ‌های معتبر) + ثبتِ سلامت در SOURCE_HEALTH.

    رفتارِ مقاوم: تا FETCH_RETRIES بار تلاش می‌کند؛ بینِ تلاش‌ها UA را می‌چرخاند
    و backoff اعمال می‌کند. اگر همهٔ تلاش‌ها ناموفق/خالی بودند، لیستِ خالی برمی‌گرداند
    (مطابقِ رفتارِ قبلی) اما دلیلِ آن در گزارشِ سلامت ثبت می‌شود.
    """
    name = url.rsplit("/", 1)[-1] or url
    last_err = ""
    last_code = 0
    t_start = time.time()
    for attempt in range(1, FETCH_RETRIES + 1):
        ua = USER_AGENTS[(attempt - 1) % len(USER_AGENTS)]
        try:
            resp = requests.get(url, timeout=FETCH_TIMEOUT, headers={"User-Agent": ua})
            last_code = resp.status_code
            body = resp.text.strip() if resp.text else ""
            if resp.status_code == 200 and body:
                cfgs = core.extract_valid_lines(body)
                if cfgs:
                    SOURCE_HEALTH[url] = {
                        "name": name, "status": "ok", "count": len(cfgs),
                        "http_code": resp.status_code, "attempts": attempt,
                        "latency_ms": int((time.time() - t_start) * 1000),
                    }
                    return url, cfgs
                # ۲۰۰ ولی صفر کانفیگِ معتبر → ممکن است فرمتِ ناشناخته باشد
                last_err = "200 but 0 valid configs"
            else:
                last_err = f"HTTP {resp.status_code}" if resp.status_code != 200 else "empty body"
                # fail-fast روی خطاهای دائمیِ کلاینت: 404/410/451 با تلاش مجدد
                # هرگز درست نمی‌شوند. تلاش مجدد فقط ۴.۵ ثانیه از بودجهٔ زمانی
                # ورک‌فلو را هدر می‌دهد (۳ تلاش × backoff) بدون هیچ فایده‌ای.
                if resp.status_code in (400, 401, 403, 404, 410, 451):
                    break
        except Exception as e:  # noqa: BLE001
            last_err = f"{type(e).__name__}: {str(e)[:80]}"
        if attempt < FETCH_RETRIES:
            time.sleep(RETRY_BACKOFF * attempt)
    # شکستِ نهایی
    SOURCE_HEALTH[url] = {
        "name": name, "status": "empty" if "0 valid" in last_err else "fail",
        "count": 0, "http_code": last_code, "attempts": attempt,
        "latency_ms": int((time.time() - t_start) * 1000), "error": last_err,
    }
    log(f"  ⚠️ fetch fail {name}: {last_err} (after {attempt} tries)")
    return url, []


def fetch_all(urls: List[str]) -> Dict[str, List[str]]:
    """واکشیِ هم‌زمانِ همهٔ URLها → نگاشت url→configs."""
    results: Dict[str, List[str]] = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(fetch_source, u): u for u in urls}
        for fut in as_completed(futs):
            url, cfgs = fut.result()
            results[url] = cfgs
            log(f"  ✓ {len(cfgs):>5} configs ← {url.rsplit('/', 1)[-1]}")
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
        # ── دروازهٔ برندینگ (E-6) ────────────────────────────────────────────
        # خطوطی که حتی بعد از تلاشِ دوباره برند نخوردند و **منتشر نشدند**.
        # امروز اندازه‌گیری‌شده = ۰ (روی ۸٬۱۳۶ خطِ زندهٔ منتشرشده). نگه‌داشتنِ
        # شمارنده برای وقتی است که صفر نماند: بی‌شمارنده، نقضِ ناوردا بی‌صدا
        # می‌شد و کسی نمی‌فهمید.
        self.unbranded_dropped = 0
        self.unbranded_rebranded = 0
        self.unbranded_samples: List[str] = []


def process_category(
    per_source: Dict[str, List[str]],
    source_urls: List[str],
    _cache: Optional[Dict[str, Tuple[bool, str]]] = None,
) -> CategoryResult:
    """dedup سراسری + برندینگ روی کانفیگ‌های یک دسته.

    این تابع سه بار صدا زده می‌شود (all / heavy / light) و منابعِ HEAVY و LIGHT
    هر دو داخلِ ALL هم هستند، پس `is_dummy_config` و `dedup_key` روی هر خط
    **دو بار** محاسبه می‌شد. با `_cache` مشترک، هر خط فقط یک بار تحلیل می‌شود.
    هر دو تابع خالص‌اند (ورودی یکسان ← خروجی یکسان)، پس caching بی‌خطر است.
    """
    if _cache is None:
        _cache = {}
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
            cached = _cache.get(line)
            if cached is None:
                cached = (core.is_dummy_config(line), "")
                if not cached[0]:
                    cached = (False, core.dedup_key(line))
                _cache[line] = cached
            is_dummy, key = cached
            if is_dummy:
                r.broken.append(line)
                continue
            if key not in seen_cores:
                seen_cores.add(key)
                raw_unique.append(line)
            else:
                r.duplicates.append(line)

    # برندینگ یکتاها + شمارش پروتکل‌ها
    #
    # ترتیبِ خروجی: پیش از این، خطوط به ترتیبِ واکشیِ منابع نوشته می‌شدند. آن
    # ترتیب به سرعتِ پاسخِ شبکه بستگی دارد، پس در هر اجرا عوض می‌شد و فایل
    # ظاهراً «کلاً تغییر کرده» به نظر می‌رسید. مرتب‌سازی بر اساسِ کلیدِ یکتاسازی
    # ترتیب را به محتوا گره می‌زند: تا وقتی مجموعهٔ کانفیگ‌ها ثابت باشد، ترتیب
    # هم ثابت است.
    ordered = sorted(raw_unique, key=lambda ln: (core.dedup_key(ln) or ln))

    # ── گرم‌کردنِ کشِ کشور، پیش از حلقهٔ برندینگ ─────────────────────────────
    #
    # `core.brand_remark` برای هر خط `country_for_endpoint` را صدا می‌زند و آن هم
    # در صورتِ نیاز DNS حل می‌کند. اگر این کار داخلِ حلقه و *تک‌تک* انجام شود،
    # هر میزبانِ نامی یک رفت‌وبرگشتِ سریِ DNS می‌شود.
    #
    # اندازه‌گیریِ واقعی روی همین دادهٔ زنده:
    #   ۵٬۰۸۵ میزبانِ یکتا  →  ۳٬۷۲۰ (۷۳٫۲٪) از قبل IP خام‌اند و DNS نمی‌خواهند
    #                          ۱٬۳۶۵ میزبانِ نامی باقی می‌ماند
    #   ۱٬۳۶۵ میزبان به‌صورتِ هم‌زمان با ۶۴ کارگر  →  ۴٫۹ ثانیه
    #   (۱۲۸ کارگر *بدتر* بود: ۸٫۴ ثانیه — گلوگاه، خودِ resolver بالادستی است،
    #    نه پهنای‌باند، پس افزودنِ کارگر بیشتر فقط صف‌بندی ایجاد می‌کند.)
    #
    # کلِ خط‌لوله الان ۴٫۸ ثانیه طول می‌کشد، پس بدترین حالت تقریباً دو برابر
    # می‌شود و همچنان بسیار کمتر از بازهٔ ۱۵ دقیقه‌ای است.
    #
    # این تابع سه بار صدا زده می‌شود (all/heavy/light) ولی کشِ `geo` سراسری است،
    # پس دورهای دوم و سوم عملاً هزینه‌ای ندارند.
    if geo is not None:
        try:
            hosts = []
            for ln in ordered:
                ep = core.endpoint_of(ln)
                if ep:
                    hosts.append(ep)
            geo.warm_up(hosts)
        except Exception as e:  # هرگز نباید تجمیع را متوقف کند
            log(f"  ⚠️ geo warm-up skipped: {e}")

    for idx, line in enumerate(ordered, start=1):
        branded = core.brand_remark(line, idx)

        # ══════════════════════════════════════════════════════════════════════
        # 🔒 دروازهٔ ایمن‌ازکارِ برندینگ (E-6)
        # ══════════════════════════════════════════════════════════════════════
        # سیاستِ مالکِ مخزن (بالای `core.py`): «همیشه» باید آیدیِ کانال روی
        # کانفیگ‌ها باشد. `brand_remark` امروز روی ۱۰۰٫۰۰٪ خطوط موفق است
        # (اندازه‌گیری‌شده)، ولی «امروز موفق است» ضمانت نیست: یک قالبِ تازهٔ
        # بالادست می‌تواند مسیری بسازد که برندینگ خاموشانه ردش کند و کانفیگِ
        # بی‌برند — یا بدتر، با تبلیغِ کانالِ رقیب — منتشر شود.
        #
        # سه تصمیمِ عمدی، هر کدام با دلیل:
        #
        #  ۱) **یک بار تلاشِ دوباره.** `brand_remark` خودتوان است (اندازه‌گیری‌شده
        #     روی پیکرهٔ خصمانه: ۵۶ نمونه × ۵ اعمالِ متوالی)، پس اعمالِ دوباره
        #     روی خطِ سالم بی‌اثر است و فقط حالتِ گذرا را نجات می‌دهد.
        #
        #  ۲) **حذفِ همان یک خط، نه توقفِ اجرا.** وسوسه‌ی «abort» غلط است:
        #     یک خطِ بدشکل نباید کلِ اشتراکِ کاربران را خالی کند. دروازهٔ
        #     `if not res_all.unique` پایین‌تر، حالتِ فروپاشیِ کامل را جدا
        #     پوشش می‌دهد.
        #
        #  ۳) **حذف، نه انتشارِ بی‌برند.** چون ناوردا، الزامِ محصول است. سکوت
        #     هم ممنوع: شمارش و نمونه در `health.json` می‌رود تا دیده شود.
        # ══════════════════════════════════════════════════════════════════════
        if not core.is_branded(branded):
            retry = core.brand_remark(branded, idx)
            if core.is_branded(retry):
                branded = retry
                r.unbranded_rebranded += 1
            else:
                r.unbranded_dropped += 1
                # نمونه‌ها سقف دارند: `health.json` را مصرف‌کنندگان دانلود
                # می‌کنند و نباید با هزاران رشته باد کند. سه نمونه برای
                # ریشه‌یابیِ الگو کافی است.
                if len(r.unbranded_samples) < 3:
                    r.unbranded_samples.append(branded[:160])
                continue

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


def _remove_if_exists(path: str) -> bool:
    """حذفِ فایلِ منتشرشدهٔ قبلی (اگر هست). برمی‌گرداند: آیا حذف شد؟

    چرا «حذف» و نه «نوشتنِ فایلِ خالی»؟ اگر فایل را خالی بنویسیم، مشترکی که
    آن لینک را subscribe کرده هر بار یک پاسخِ ۲۰۰ با بدنهٔ خالی می‌گیرد و
    کلاینت لیستِ قبلی‌اش را با «هیچ» جانشین می‌کند. اگر فایل را حذف کنیم،
    لینک ۴۰۴ می‌دهد و کلاینت‌ها لیستِ قبلی را نگه می‌دارند — رفتارِ درست‌تر.
    مهم‌تر: هر فایلِ نوشته‌شده در هر دور یک blob جدید در تاریخِ git می‌سازد.
    """
    if os.path.exists(path):
        try:
            os.remove(path)
            return True
        except OSError as e:
            log(f"  ⚠️ could not remove {path}: {e}")
    return False


def write_archive(out_dir: str, cat: str, r: CategoryResult) -> None:
    """بایگانیِ خراب‌های یک دسته (txt + base64).

    حذفِ تولیدِ archive/*_duplicates* ★
    اندازه‌گیریِ واقعی روی همین مخزن:
        archive/all_duplicates_base64.txt    4,286,344 B
        archive/heavy_duplicates_base64.txt  3,720,596 B
        archive/all_duplicates.txt           3,214,809 B
        archive/heavy_duplicates.txt         2,790,499 B
        archive/light_duplicates_base64.txt    274,408 B
        archive/light_duplicates.txt           205,857 B
        ─────────────────────────────────────────────────
        جمع                                 14,492,513 B ≈ 13.82 MiB
    این ۱۳.۸ مگابایت در «هر» دور (۹۸ دور در روز) از نو نوشته می‌شود و چون
    محتوایش با هر دور عوض می‌شود، هر بار blobهای تازه به تاریخِ git اضافه
    می‌کند. آزمایشِ کنترل‌شده (۳ کامیتِ بازتولید + ۱۰٪ جابه‌جاییِ خطوط، سپس
    gc) نشان داد حذفِ همین پوشه هزینهٔ هر کامیت را از ۱۶۸۰ به ۱۳۲۸ کیلوبایت
    می‌رساند (−۲۱٪).
    ارزشِ کاربردی این فایل‌ها صفر است: «تکراری‌ها» به تعریف، کانفیگ‌هایی
    هستند که نسخهٔ یکتای‌شان همین حالا در all/ منتشر شده — هیچ کاربری به
    نسخهٔ دومِ همان سرور نیاز ندارد.
    فایل‌های broken نگه داشته می‌شوند: کوچک‌اند (۱۶۸ و ۱۷۰ بایت) و برای
    عیب‌یابیِ منابع مفیدند.
    """
    base = os.path.join(out_dir, "archive")
    btxt = os.path.join(base, f"{cat}_broken.txt")
    bb64 = os.path.join(base, f"{cat}_broken_base64.txt")
    if r.broken:
        bh = f"# @Raydikalx — {cat.upper()} BROKEN/dummy — {len(r.broken)} configs\n"
        _write_text(btxt, bh + "\n".join(r.broken) + "\n")
        _write_text(bb64, core.encode_base64_subscription(r.broken))
    else:
        # همان سیاستِ «فایلِ خالی منتشر نمی‌شود»: وقتی این دور هیچ کانفیگِ خرابی نبود،
        # فایلِ توخالی منتشر نمی‌کنیم (در تستِ واقعی light_broken.txt با ۵۱
        # بایتِ سرآیندِ تنها و light_broken_base64.txt با ۰ بایت تولید می‌شد).
        gone_txt = _remove_if_exists(btxt)
        gone_b64 = _remove_if_exists(bb64)
        if gone_txt or gone_b64:
            log(f"  🗑️ pruned empty archive/{cat}_broken*")
    # ── پاک‌سازیِ فایل‌های duplicates که در دورهای قبل منتشر شده‌اند ──
    for stale in (f"{cat}_duplicates.txt", f"{cat}_duplicates_base64.txt"):
        if _remove_if_exists(os.path.join(base, stale)):
            log(f"  🗑️ removed obsolete archive/{stale}")


def write_protocols(out_dir: str, all_unique: List[str]) -> Dict[str, int]:
    """فایل‌های per-protocol (روی دستهٔ ALL).

    ننوشتنِ فایلِ پروتکلِ خالی ★
    وضعیتِ اندازه‌گیری‌شدهٔ مخزن پیش از این تغییر: از ۲۸ فایلِ پوشهٔ
    protocols/، ۱۴ فایل هیچ کانفیگی نداشتند —
      ۷ فایلِ ‎*_base64.txt‎ با اندازهٔ دقیقاً ۰ بایت:
        anytls, hysteria, juicity, mieru, snell, socks, wireguard
      ۷ فایلِ ‎*.txt‎ فقط شاملِ خطِ سرآیند (۳۸ تا ۴۲ بایت، «۰ configs»):
        mieru(38) snell(38) socks(38) anytls(39) juicity(40) hysteria(41)
        wireguard(42)
    این فایل‌ها سه ضررِ هم‌زمان داشتند:
      ۱) کاربر لینک را باز می‌کند، پاسخِ ۲۰۰ با بدنهٔ خالی می‌گیرد و
         تصور می‌کند مخزن خراب است (نه اینکه آن پروتکل موجود نیست).
      ۲) کلاینتی که این لینک را subscribe کرده، لیستش را با «هیچ» جانشین
         می‌کند — یعنی فایلِ خالی از نبودِ فایل بدتر است.
      ۳) هر کدام یک ورودیِ درختِ git در هر یک از ۹۸ دورِ روزانه است.

    سیاستِ جدید: فایل فقط وقتی نوشته می‌شود که حداقل یک کانفیگ داشته باشد؛
    در غیر این صورت فایلِ منتشرشدهٔ قبلی حذف می‌شود تا لینک ۴۰۴ بدهد
    (سیگنالِ صادق) و دادهٔ بایات هم در مخزن نماند.
    مقادیرِ شمارش برای همهٔ پروتکل‌ها — حتی صفرها — در index.json می‌مانند،
    پس هیچ اطلاعاتی از دست نمی‌رود؛ فقط فایلِ توخالی منتشر نمی‌شود.
    """
    base = os.path.join(out_dir, "protocols")
    buckets: Dict[str, List[str]] = {}
    for line in all_unique:
        proto = core.protocol_of(line)
        if proto:
            buckets.setdefault(proto, []).append(line)

    counts: Dict[str, int] = {}
    written = 0
    pruned = 0

    def emit(proto: str, lines: List[str]) -> None:
        """نوشتن (یا حذفِ) جفت‌فایلِ یک پروتکل."""
        nonlocal written, pruned
        txt = os.path.join(base, f"{proto}.txt")
        b64 = os.path.join(base, f"{proto}_base64.txt")
        if lines:
            h = f"# @Raydikalx — {proto} — {len(lines)} configs\n"
            _write_text(txt, h + "\n".join(lines) + "\n")
            _write_text(b64, core.encode_base64_subscription(lines))
            written += 1
        else:
            # فایلِ توخالی منتشر نمی‌شود و نسخهٔ قبلی پاک می‌شود.
            # ⚠️ هر دو حذف باید «مستقل» ارزیابی شوند. نوشتنِ
            #    `if _remove_if_exists(txt) or _remove_if_exists(b64)`
            #    باگ می‌سازد: عملگر `or` کوتاه‌مدار است، پس وقتی فایلِ txt
            #    حذف شود، تابعِ دومی هرگز صدا زده نمی‌شود و فایلِ base64
            #    برای همیشه در مخزن باقی می‌ماند (در تستِ واقعی دقیقاً همین
            #    رخ داد: ۷ فایلِ ‎*_base64.txt‎ صفر-بایتی باقی مانده بودند).
            gone_txt = _remove_if_exists(txt)
            gone_b64 = _remove_if_exists(b64)
            if gone_txt or gone_b64:
                pruned += 1

    for proto in core.PROTOCOL_ORDER:
        lines = buckets.get(proto, [])
        counts[proto] = len(lines)
        emit(proto, lines)

    # 🧠 پروتکل‌های ناشناخته/جدید (خارج از ترتیبِ شناخته‌شده) — خودکار فایل می‌سازند
    for proto, lines in sorted(buckets.items(), key=lambda x: -len(x[1])):
        if proto not in counts:
            counts[proto] = len(lines)
            emit(proto, lines)

    log(f"  📁 protocols: {written} file-pairs written, {pruned} empty pruned")
    return counts


def build_index(results: Dict[str, CategoryResult], proto_counts: Dict[str, int],
                elapsed: float) -> dict:
    now = _dt.datetime.now(_dt.timezone.utc)
    next_run = now + _dt.timedelta(minutes=UPDATE_INTERVAL_MIN)

    def cat_block(cat: str, r: CategoryResult) -> dict:
        return {
            "unique": len(r.unique),
            "broken": len(r.broken),
            "duplicates": len(r.duplicates),
            "total_fetched": r.total_seen,
            "active_sources": r.active_sources,
            "protocols": dict(sorted(r.protocol_counts.items(), key=lambda x: -x[1])),
            # لینکِ اصلی raw است (کشِ ۵ دقیقه‌ای)، jsDelivr آینه
            #   (کشِ ۱۲ ساعته). کلیدهای قدیمی حذف نشدند تا هیچ مصرف‌کننده‌ای
            #   نشکند؛ فقط مقدارشان به raw تغییر کرد و آینه در کلیدهای
            #   جداگانهٔ *_mirror در دسترس است.
            "files": {
                "configs_txt": f"{PRIMARY_BASE}/{cat}/configs.txt",
                "configs_base64": f"{PRIMARY_BASE}/{cat}/configs_base64.txt",
                "clash_yaml": f"{PRIMARY_BASE}/{cat}/clash.yaml",
                "singbox_json": f"{PRIMARY_BASE}/{cat}/singbox.json",
                "configs_txt_mirror": f"{MIRROR_BASE}/{cat}/configs.txt",
                "configs_base64_mirror": f"{MIRROR_BASE}/{cat}/configs_base64.txt",
                "clash_yaml_mirror": f"{MIRROR_BASE}/{cat}/clash.yaml",
                "singbox_json_mirror": f"{MIRROR_BASE}/{cat}/singbox.json",
            },
        }

    return {
        "brand": core.BRAND_CHANNEL,
        "generator": "RaydikalxBot aggregator",
        "updated_at": now.isoformat(),
        "updated_at_unix": int(now.timestamp()),
        "next_update_eta": next_run.isoformat(),
        "update_interval_minutes": UPDATE_INTERVAL_MIN,
        "elapsed_seconds": round(elapsed, 1),
        # اولویتِ لینک‌ها به‌صورتِ ماشین‌خوان اعلام می‌شود تا هر
        #   مصرف‌کننده‌ای (ربات، اپ، اسکریپت) بداند کدام تازه‌تر است.
        "raw_base": RAW_BASE,
        "cdn_base": CDN_BASE,
        "primary_base": PRIMARY_BASE,
        "mirror_base": MIRROR_BASE,
        # نامِ برنچی که فایل‌ها از آن سرو می‌شوند. کلیدِ `data_branch` هم با
        # همان مقدار می‌ماند: مصرف‌کننده‌هایی که آن را می‌خوانند نباید بشکنند.
        "publish_branch": GH_BRANCH,
        "data_branch": GH_BRANCH,
        # index.json آدرسِ خودش را هم منتشر می‌کند.
        #   چرا: یک بازبینیِ کاملِ «هر فایلِ منتشرشده باید تبلیغ شود» نشان داد
        #   تنها فایلِ منتشرشده‌ای که در index.json آدرسی نداشت، خودِ index.json
        #   بود. این یعنی مصرف‌کننده‌ای که فقط همین سند را در دست دارد (مثل یک
        #   ربات یا آینه‌ساز) نمی‌تواند بفهمد از کجا باید آن را دوباره بگیرد و
        #   ناچار است آدرس را hard-code کند — همان چیزی که این تغییر حذفش کرد.
        "self_url": f"{PRIMARY_BASE}/index.json",
        "self_url_mirror": f"{MIRROR_BASE}/index.json",
        "link_policy": {
            "primary": "raw.githubusercontent.com",
            "primary_cache_seconds": 300,
            "mirror": "cdn.jsdelivr.net",
            "mirror_cache_seconds": 43200,
            "note": ("raw is ~144x fresher (300s vs 43200s cache). The jsDelivr "
                     "mirror is purged on every run, but use raw when possible."),
        },
        "categories": {
            "all": cat_block("all", results["all"]),
            "heavy": cat_block("heavy", results["heavy"]),
            "light": cat_block("light", results["light"]),
        },
        "protocols": dict(sorted(proto_counts.items(), key=lambda x: -x[1])),
        # فقط پروتکل‌هایی که واقعاً فایل دارند اینجا فهرست می‌شوند.
        #   پیش‌تر همهٔ ۱۴ پروتکلِ PROTOCOL_ORDER بی‌قید فهرست می‌شدند، حتی
        #   ۷ موردی که صفر کانفیگ داشتند → index.json لینکی را تبلیغ می‌کرد
        #   که بدنهٔ خالی برمی‌گرداند. حالا که فایلِ خالی حذف می‌شود، فهرست‌کردنِ
        #   بی‌قید به تبلیغِ ۴۰۴ تبدیل می‌شد؛ پس فهرست هم شرطی شد.
        #   شمارشِ همهٔ پروتکل‌ها (شاملِ صفرها) در کلیدِ "protocols" باقی است،
        #   پس هیچ اطلاعاتی از دست نمی‌رود.
        "protocol_files": {
            p: f"{PRIMARY_BASE}/protocols/{p}.txt"
            for p in core.PROTOCOL_ORDER if proto_counts.get(p, 0) > 0
        },
        "protocol_files_base64": {
            p: f"{PRIMARY_BASE}/protocols/{p}_base64.txt"
            for p in core.PROTOCOL_ORDER if proto_counts.get(p, 0) > 0
        },
        "protocol_files_mirror": {
            p: f"{MIRROR_BASE}/protocols/{p}.txt"
            for p in core.PROTOCOL_ORDER if proto_counts.get(p, 0) > 0
        },
        # کلیدهای *_duplicates حذف شدند چون فایل‌شان دیگر تولید نمی‌شود.
        #   نگه‌داشتنِ کلید بدونِ فایل = تبلیغِ لینکِ ۴۰۴ در index.json.
        #   کلیدهای broken هم شرطی شدند: اگر یک دسته این دور صفر کانفیگِ خراب
        #   داشته باشد، فایلش نوشته نمی‌شود، پس نباید تبلیغ شود. (در تستِ واقعی
        #   light صفر خراب داشت و index.json لینکِ ۴۰۴ تبلیغ می‌کرد.)
        "archive": {
            **{f"{cat}_broken": f"{PRIMARY_BASE}/archive/{cat}_broken.txt"
               for cat in ("all", "heavy", "light") if results[cat].broken},
            # فایل base64 پیش‌تر تولید می‌شد ولی هیچ‌جا فهرست نشده بود
            # (منتشرشده اما کشف‌ناپذیر). حالا فهرست می‌شود.
            **{f"{cat}_broken_base64": f"{PRIMARY_BASE}/archive/{cat}_broken_base64.txt"
               for cat in ("all", "heavy", "light") if results[cat].broken},
        },
        "sources": {
            "light_count": len(LIGHT_SOURCES),
            "heavy_count": len(HEAVY_SOURCES),
            "total_count": len(LIGHT_SOURCES) + len(HEAVY_SOURCES),
            # ── گزارشِ سلامتِ منابع (حرفه‌ای): چند منبع زنده/مرده‌اند ──────────
            "healthy": sum(1 for h in SOURCE_HEALTH.values() if h.get("status") == "ok"),
            "unhealthy": sum(1 for h in SOURCE_HEALTH.values() if h.get("status") != "ok"),
            "health_url": f"{PRIMARY_BASE}/health.json",
            "health_url_mirror": f"{MIRROR_BASE}/health.json",
        },
    }


def build_health_report(
    elapsed: float,
    conv_by_category: Optional[Dict[str, dict]] = None,
    results: Optional[Dict[str, "CategoryResult"]] = None,
) -> dict:
    """گزارشِ کاملِ سلامتِ هر منبع — برای مانیتورینگ و دیباگِ منابعِ مرده.

    از این نسخه، گزارش سه بخشِ تازه هم دارد:

      `converters` — چند کانفیگ در تبدیل به Clash/Sing-box حذف شد و چرا.
                     تا پیش از این، حذف بی‌صدا بود؛ حالا اگر یک تغییر باعث شود
                     ناگهان هزاران کانفیگ حذف شوند، در همین فایل دیده می‌شود.

      `geo`        — چند برچسبِ کشور از GeoIP آمد، چند تا از DNS، چند DNS شکست
                     خورد و آیا پایگاه‌داده اصلاً بارگذاری شد یا نه. بدونِ این،
                     اگر دانلودِ mmdb در ورک‌فلو خراب شود، خط‌لوله بی‌صدا به
                     برچسب‌گذاریِ ضعیفِ قدیمی برمی‌گشت و کسی نمی‌فهمید.

    هر دو بخش «بهترین تلاش»اند: اگر ماژول در دسترس نباشد، مقدارشان None می‌شود و
    گزارش همان ساختارِ قبلی را حفظ می‌کند (سازگاریِ عقب‌رو برای هر مصرف‌کننده‌ای
    که health.json را پارس می‌کند).
    """
    now = _dt.datetime.now(_dt.timezone.utc)
    items = []
    for url in (LIGHT_SOURCES + HEAVY_SOURCES):
        h = SOURCE_HEALTH.get(url, {"name": url.rsplit("/", 1)[-1], "status": "unknown", "count": 0})
        tier = "light" if url in LIGHT_SOURCES else "heavy"
        items.append({"url": url, "tier": tier, **h})

    # ═════════════════════════════════════════════════════════════════════════
    # آمارِ حذفِ مبدل‌ها — اصلاحِ یک عددِ غلطِ منتشرشده (E-11)
    # ═════════════════════════════════════════════════════════════════════════
    # `converters._drops` یک شمارشگرِ **سراسری** است و `build_clash_yaml` /
    # `build_singbox_json` در شروعِ کار `clear_target()` می‌زنند. فایل‌ها به
    # ترتیبِ all → heavy → light نوشته می‌شوند، و این گزارش **بعد** از همهٔ
    # آن نوشتن‌ها ساخته می‌شود — پس تا پیش از این، عددِ منتشرشده فقط به
    # دستهٔ **light** تعلق داشت در حالی که مانندِ آمارِ کل خوانده می‌شد.
    # اندازه‌گیریِ زنده (فاز E): light = ۲۱ حذف، در حالی که all = ۹۳.
    #
    # راه‌حل: خط‌لوله پس از نوشتنِ هر دسته، یک snapshot می‌گیرد و همه را
    # اینجا می‌دهد. کلیدِ `converters` عمداً به دستهٔ `all` می‌ماند (همانی که
    # لینکِ پیش‌فرضِ کاربران است) تا مصرف‌کننده‌های فعلی نشکنند؛ تفکیکِ
    # کامل در کلیدِ تازهٔ `converters_by_category` می‌آید.
    #
    # اگر خط‌لوله snapshot نداد (مسیرِ قدیمی/آزمونی)، رفتارِ قبلی حفظ
    # می‌شود تا امضای تابع سازگارِ عقب‌رو بماند.
    conv_by_cat = dict(conv_by_category or {})
    try:
        conv_stats = conv_by_cat.get("all") or converters.drop_stats()
    except Exception:
        conv_stats = None

    # ── دروازهٔ برندینگ (E-6) — رصدپذیری ──────────────────────────────
    # این اعداد باید همیشه صفر باشند. هر عددِ غیرِصفر یعنی قالبی از
    # بالادست آمده که `brand_remark` بلد نیست — یعنی کارِ توسعهٔ فوری.
    brand_gate = None
    if results:
        brand_gate = {
            cat: {"dropped": r.unbranded_dropped,
                  "rebranded": r.unbranded_rebranded,
                  "samples": list(r.unbranded_samples)}
            for cat, r in results.items()
        }

    geo_stats = None
    if geo is not None:
        try:
            geo_stats = geo.stats()
        except Exception:
            geo_stats = None

    return {
        "brand": core.BRAND_CHANNEL,
        "checked_at": now.isoformat(),
        "checked_at_unix": int(now.timestamp()),
        "elapsed_seconds": round(elapsed, 1),
        "summary": {
            "total": len(items),
            "ok": sum(1 for i in items if i.get("status") == "ok"),
            "empty": sum(1 for i in items if i.get("status") == "empty"),
            "fail": sum(1 for i in items if i.get("status") == "fail"),
        },
        "sources": items,
        "converters": conv_stats,
        "converters_by_category": conv_by_cat or None,
        "brand_gate": brand_gate,
        "geo": geo_stats,
    }


# ──────────────────────────────────────────────────────────────────────────────
# حافظهٔ بین‌دوره‌ای (فاز D)
# ──────────────────────────────────────────────────────────────────────────────

def unique_yield(per_source: Dict[str, List[str]]) -> Tuple[Dict[str, int], Dict[str, int], int]:
    """بازدهِ **یکتا**ی هر منبع → (total, unique, union_size).

    «یکتا» یعنی کلیدی که *هیچ منبعِ دیگری* در همین دور نداشته است. این سنجه —
    نه «تعدادِ کانفیگ» و نه «HTTP 200» — تنها چیزی است که افزونگی را می‌بیند.

    چرا لازم است، با عددِ سنجیده: `mahdibland/Eternity.txt` امروز ۱۹۸ کانفیگ و
    `status: ok` دارد، ولی **زیرمجموعهٔ محضِ ۱۰۰.۰۰٪** از
    `mahdibland/sub/sub_merge.txt` است (هر دو از یک مخزنِ بالادست). با معیارِ
    «کانفیگ» یا «سلامت» نامرئی است؛ با معیارِ «یکتا» عددش صفر می‌شود.

    از `core.dedup_key` — همان تابعِ هویتی که خطِ لوله برای تکراری‌زدایی به‌کار
    می‌برد — استفاده می‌شود، تا این سنجه با خروجیِ واقعی هم‌داستان باشد.
    """
    keys: Dict[str, set] = {}
    for url, cfgs in per_source.items():
        ks = set()
        for line in cfgs:
            try:
                if not core.is_dummy_config(line):
                    ks.add(core.dedup_key(line))
            except Exception:
                continue
        keys[url] = ks

    owners: Dict[str, int] = {}
    for ks in keys.values():
        for k in ks:
            owners[k] = owners.get(k, 0) + 1

    totals = {u: len(ks) for u, ks in keys.items()}
    uniq = {u: sum(1 for k in ks if owners.get(k) == 1) for u, ks in keys.items()}
    return totals, uniq, len(owners)


def advance_memory(state: dict, per_source: Dict[str, List[str]],
                   live_urls: List[str], state_path: str) -> dict:
    """یک دور را در حافظه ثبت کن، تصمیمِ auto-disable بگیر، و ذخیره کن.

    کلِ این تابع «بهترین تلاش» است: هیچ خرابی‌ای در حافظه نباید دورِ سالمی را
    بشکند، چون خروجیِ منتشرشده به حافظه وابسته نیست — حافظه فقط دورِ *بعد* را
    بهتر می‌کند.
    """
    try:
        totals, uniq, union = unique_yield(per_source)
        obs = {u: {"tier": "light" if u in LIGHT_SOURCES else "heavy",
                   "total": totals.get(u, 0), "unique": uniq.get(u, 0)}
               for u in per_source}
        state = memory.record_round(state, obs, live_urls)

        cand = memory.disable_candidates(state, uniq, union)
        if cand:
            state = memory.mark_disabled(state, cand)
            for url, why in cand.items():
                log(f"  🚫 auto-disabling {url.rsplit('/', 1)[-1]} — {why}")
        memory.save_state(state, state_path)

        top = sorted(uniq.items(), key=lambda kv: -kv[1])[:3]
        zero = [u.rsplit("/", 1)[-1] for u, n in uniq.items() if n == 0]
        log(memory.summary(state))
        log(f"  📊 union={union} · top unique: "
            + ", ".join(f"{u.rsplit('/', 1)[-1]}={n}" for u, n in top))
        if zero:
            log(f"  ⚠️ zero unique yield this round ({len(zero)}): {', '.join(zero)}")
    except Exception as exc:  # noqa: BLE001 — حافظه هرگز دور را نمی‌شکند
        log(f"  ⚠️ memory step failed ({type(exc).__name__}) — round continues")
    return state


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

    # ── حافظهٔ بین‌دوره‌ای (فاز D) ───────────────────────────────────────────
    # پیش از واکشی خوانده می‌شود تا منابعی که حافظه غیرفعال کرده رد شوند.
    # `load_state` هرگز استثنا نمی‌دهد؛ نبودِ فایل = حافظهٔ خالی = رفتارِ قبلی.
    state_path = os.path.join(out_dir, memory.STATE_PATH)
    mem = memory.load_state(state_path)
    skipped = [u for u in memory.disabled_urls(mem)
               if u in (LIGHT_SOURCES + HEAVY_SOURCES)]

    all_urls = [u for u in (LIGHT_SOURCES + HEAVY_SOURCES) if u not in set(skipped)]
    if skipped:
        log(f"🧠 memory disabled {len(skipped)} source(s) → fetching "
            f"{len(all_urls)} of {len(LIGHT_SOURCES) + len(HEAVY_SOURCES)}")
        for u in skipped:
            log(f"     ⏭️ {u.rsplit('/', 1)[-1]}")
    per_source = fetch_all(all_urls)

    log("🧮 Processing categories (dedup + brand) …")
    # cache مشترک بین سه دسته — هر خط فقط یک بار تحلیل می‌شود
    analysis_cache: Dict[str, Tuple[bool, str]] = {}
    res_all = process_category(per_source, all_urls, analysis_cache)
    res_heavy = process_category(per_source, HEAVY_SOURCES, analysis_cache)
    res_light = process_category(per_source, LIGHT_SOURCES, analysis_cache)
    results = {"all": res_all, "heavy": res_heavy, "light": res_light}

    for cat, r in results.items():
        log(f"  • {cat:<5}: {len(r.unique):>6} unique | "
            f"{len(r.duplicates):>6} dup | {len(r.broken):>5} broken | "
            f"{r.active_sources}/{len(HEAVY_SOURCES if cat=='heavy' else LIGHT_SOURCES if cat=='light' else all_urls)} src")

    # ── دروازهٔ ایمنی: پیش از **هر** نوشتنی بررسی کن ────────────────────────────
    # قبلاً این بررسی بعد از نوشتن همهٔ فایل‌ها انجام می‌شد؛ یعنی اگر همهٔ منابع
    # از کار می‌افتادند، فایل‌های خوبِ موجود در ریپو با فایل‌های خالی بازنویسی
    # می‌شدند و بعد کد ۲ برمی‌گشت — دادهٔ سالم قبلی از دست می‌رفت.
    if not res_all.unique:
        log("❌ No configs produced — aborting BEFORE writing (existing files preserved)")
        return 2

    # ── ثبتِ دور در حافظه (فاز D) ─────────────────────────────────────────────
    # عمداً **بعدِ** دروازهٔ ایمنی: دوری که هیچ کانفیگی نساخته، شاهدِ معتبری از
    # بازدهِ منابع نیست و نباید تاریخچه را آلوده کند یا کسی را غیرفعال کند.
    # `live_urls` فهرستِ کاملِ `sources.py` است — نه `all_urls`ِ فیلترشده —
    # وگرنه منبعی که خودمان رد کردیم، در همان دور GC می‌شد و حافظه‌اش (و دلیلِ
    # غیرفعال‌شدنش) پاک می‌شد؛ یعنی دورِ بعد دوباره واکشی می‌شد.
    mem = advance_memory(mem, per_source, LIGHT_SOURCES + HEAVY_SOURCES, state_path)

    log("💾 Writing output files …")
    # snapshot ِآمارِ حذف **بلافاصله پس از هر دسته** گرفته می‌شود، وگرنه
    # `clear_target()`ِ دستهٔ بعدی آن را پاک می‌کند (ریشهٔ باگِ E-11).
    conv_by_cat: Dict[str, dict] = {}
    for cat, r in results.items():
        write_category(out_dir, cat, r)
        try:
            conv_by_cat[cat] = converters.drop_stats()
        except Exception:
            pass
        write_archive(out_dir, cat, r)

    # گزارشِ دروازهٔ برندینگ (E-6) — در لاگ هم دیده شود، نه فقط در فایل
    for cat, r in results.items():
        if r.unbranded_dropped or r.unbranded_rebranded:
            log(f"  ⚠️ brand gate [{cat}]: dropped={r.unbranded_dropped} "
                f"rebranded={r.unbranded_rebranded}")
            for s in r.unbranded_samples:
                log(f"       ↳ {s}")

    proto_counts = write_protocols(out_dir, res_all.unique)
    log(f"  • protocols: " + ", ".join(f"{k}={v}" for k, v in proto_counts.items() if v))

    elapsed = time.time() - t0
    index = build_index(results, proto_counts, elapsed)
    _write_text(os.path.join(out_dir, "index.json"),
                json.dumps(index, ensure_ascii=False, indent=2))

    # ── گزارشِ سلامتِ منابع (حرفه‌ای) ─────────────────────────────────────────
    health = build_health_report(elapsed, conv_by_cat, results)
    _write_text(os.path.join(out_dir, "health.json"),
                json.dumps(health, ensure_ascii=False, indent=2))
    hs = health["summary"]
    log(f"  • source health: {hs['ok']} ok / {hs['empty']} empty / {hs['fail']} fail")

    cs = health.get("converters") or {}
    for target in ("clash", "singbox"):
        t = cs.get(target)
        if t:
            reasons = ", ".join(f"{k}={v}" for k, v in (t.get("by_reason") or {}).items())
            log(f"  • {target} drops: {t.get('total', 0)}" + (f" ({reasons})" if reasons else ""))

    gs = health.get("geo")
    if gs:
        log("  • geo: db=" + ("yes" if gs.get("db_loaded") else "no")
            + f" ip={gs.get('by_ip_literal', 0)}"
            + f" dns={gs.get('by_dns', 0)}"
            + f" dns_failed={gs.get('dns_failed', 0)}"
            + f" unknown={gs.get('unknown_ip_literal', 0) + gs.get('unknown_after_dns', 0)}")

    # خروجی برای GitHub Actions summary
    log(f"✅ Done in {elapsed:.1f}s — "
        f"ALL={len(res_all.unique)} HEAVY={len(res_heavy.unique)} LIGHT={len(res_light.unique)} unique")
    return 0


if __name__ == "__main__":
    sys.exit(main())
