# -*- coding: utf-8 -*-
"""
validate.py — دروازهٔ اعتبارسنجی خروجی‌ها با **کلاینت واقعی**.

مسئلهٔ بنیادینی که این ماژول حل می‌کند
────────────────────────────────────────
یک کانفیگ نامعتبر در وسط `clash.yaml` یا `singbox.json` باعث می‌شود کلاینت
**کل فایل** را رد کند، نه فقط همان یک نود. یعنی یک خط خراب = صفر کانفیگ برای
کاربر. تولید فایل «تقریباً درست» بی‌معنی است.

پس پیش از انتشار، همان باینری‌هایی که کاربر استفاده می‌کند خروجی را
اعتبارسنجی می‌کنند:
  • `sing-box check -c <file>`
  • `mihomo -t -f <file>`

اگر باینری در دسترس نباشد (توسعهٔ محلی)، اعتبارسنجی ساختاری انجام می‌شود
(JSON/YAML قابل تجزیه + وجود کلیدهای الزامی) و نتیجه «skipped» علامت
می‌خورد — هرگز به‌دروغ «pass» گزارش نمی‌شود.

دو گونهٔ دسته، با دو قاعدهٔ متفاوت
──────────────────────────────────
`all/ heavy/ light/` همیشه تولید می‌شوند، پس نبودنشان خطاست.

`verified/ fast/ secure/` (فاز B) تنها وقتی تولید می‌شوند که آزمونِ واقعیِ
پروکسی در آن اجرا فعال باشد. قاعدهٔ آن‌ها «الزامی به‌شرطِ حضور» است: اگر
دایرکتوری نبود، از بررسی رد می‌شود؛ ولی اگر بود و فایلش خراب یا ناقص بود،
**شکست** است — نه «skipped» و نه نادیده‌گرفتن.

چرا این تفکیک لازم بود؟ `report["ok"]` شرطِ `missing == 0` دارد. افزودنِ
سادهٔ سه دستهٔ تازه به همان تاپل، دروازه را بی‌درنگ می‌شکست: سنجیده شد که
پیش از این تغییر ۶ بررسی و rc=0 بود، و با افزودنِ ساده ۶ موردِ `missing`
و rc=1 می‌شد — یعنی انتشار می‌ایستاد پیش از آنکه اصلاً کدِ تولیدکنندهٔ
آن دسته‌ها نوشته شود.

اجرا به‌صورت مستقل:
    python scripts/validate.py --out .            # اعتبارسنجی خروجی‌های موجود
    python scripts/validate.py --out . --strict   # کد خروج ≠۰ در صورت شکست
"""
from __future__ import annotations

import argparse
import base64
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

#: دسته‌هایی که خط‌لوله **همیشه** تولید می‌کند. نبودنشان خطاست.
CORE_CATEGORIES = ("all", "heavy", "light")

#: دسته‌های فاز B (آبشارِ اعتبارسنجی). این‌ها تنها وقتی تولید می‌شوند که
#: لایهٔ L3 در آن اجرا فعال باشد، و «فعال‌بودن» به محیطِ اجرا بسته است.
#:
#: چرا جدا؟ چون `report["ok"]` شرطِ `missing == 0` دارد. اگر این سه به
#: `CORE_CATEGORIES` اضافه می‌شدند، همان لحظه دروازه با `--strict` کدِ ۱
#: می‌داد و انتشار را می‌بست — پیش از آنکه اصلاً کدِ تولیدکننده‌شان نوشته
#: شود. سنجیده شد: پیش از این تغییر ۶ بررسی و rc=0؛ با افزودنِ ساده به
#: همان تاپل، ۶ موردِ `missing` و rc=1.
#:
#: قاعدهٔ درست «الزامی به‌شرطِ حضور» است: اگر دایرکتوری نباشد، رد می‌شود؛
#: ولی اگر باشد و فایلش خراب یا ناقص باشد، **شکست** است. یعنی حذفِ خودکارِ
#: یک دسته هرگز به‌شکلِ «موفق» ظاهر نمی‌شود.
OPTIONAL_CATEGORIES = ("verified", "fast", "secure")

#: سازگاریِ عقب‌رو: هر مصرف‌کنندهٔ بیرونیِ `CATEGORIES` باید کار کند.
CATEGORIES = CORE_CATEGORIES + OPTIONAL_CATEGORIES

# نرم‌شدنِ قاعده هرگز نباید به دسته‌های اصلی سرایت کند. اگر روزی کسی نامی را
# جابه‌جا کند، `all/` می‌توانست بی‌صدا «تولیدنشده» به حساب بیاید و دروازه با
# صفر کانفیگ سبز بماند — بدترین شکستِ خاموشِ ممکن برای این پروژه. پس این‌جا
# در زمانِ import می‌شکند، نه در زمانِ انتشار.
assert not (set(CORE_CATEGORIES) & set(OPTIONAL_CATEGORIES)), \
    "a core category must never be optional"
assert len(set(CATEGORIES)) == len(CATEGORIES), "duplicate category name"

#: زمان بیشینهٔ اجرای هر باینری اعتبارسنج (ثانیه).
CHECK_TIMEOUT = 180

#: ★ فهرستِ سفیدِ دروازه (F-5). تنها وضعیت‌هایی که اجازهٔ عبور دارند؛ هر
#: وضعیتِ دیگر — از جمله هر وضعیتِ **ناشناختهٔ** آینده — دروازه را می‌بندد.
#:
#: ⚠️ چرا این نام در **سطحِ ماژول** است و نه داخلِ `validate_outputs`:
#:    تا ۲۰۲۶-۰۸-۰۴ این تاپل یک متغیرِ محلی بود. با اجرا (نه با خواندنِ کد)
#:    اندازه‌گیری شد که آزمونِ ناوردا
#:    (`test_zzz_f5_the_fix_changes_no_verdict_for_real_statuses`) با
#:    `hasattr(validate, "ACCEPTABLE_STATUSES")` سراغش می‌آمد و چون نامِ
#:    محلی از بیرون دیده نمی‌شود، آن شرط **همیشه** False بود و آزمون به
#:    نسخهٔ رونویسی‌شدهٔ `{"pass", "skipped"}` داخلِ خودش تکیه می‌کرد.
#:    نتیجهٔ سنجیده‌شدهٔ آن جداافتادگی: با گشاد‌کردنِ همین تاپل به
#:    `("pass", "skipped", "fail", "missing")` — یعنی دروازهٔ کاملاً
#:    fail-open — هر ۵ آزمونِ F-5 **سبز ماندند**. پس فهرستِ سفید باید تنها
#:    یک منبعِ حقیقت داشته باشد و آزمون همان را بخواند، نه رونوشتش را.
ACCEPTABLE_STATUSES = ("pass", "skipped")

#: sing-box/mihomo پیام‌ها را رنگی چاپ می‌کنند؛ در لاگ CI به بایت‌های زائد
#: تبدیل می‌شود و مقایسهٔ رشته‌ای را می‌شکند، پس پاک می‌شود.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _clean(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _find_binary(*names: str) -> Optional[str]:
    """مسیر باینری در PATH یا محل‌های متعارف نصب در CI."""
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    for n in names:
        for cand in (f"/usr/local/bin/{n}", f"/usr/bin/{n}", f"./{n}"):
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
    return None


def _run(cmd: List[str]) -> Tuple[int, str]:
    try:
        pr = subprocess.run(cmd, capture_output=True, text=True, timeout=CHECK_TIMEOUT)
        return pr.returncode, _clean((pr.stdout or "") + (pr.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {CHECK_TIMEOUT}s"
    except Exception as e:  # noqa: BLE001
        return 125, f"{type(e).__name__}: {e}"


# ──────────────────────────────────────────────────────────────────────────────
# اعتبارسنجی ساختاری (وقتی باینری نیست)
# ──────────────────────────────────────────────────────────────────────────────

def _total_check(fn):
    """یک بررسیِ ساختاری را به تابعی **کل** بدل می‌کند: هرگز استثنا نمی‌دهد.

    ── چرا این لایه لازم است (F-4) ───────────────────────────────────────────
    دو بررسیِ زیر شکلِ سندِ خوانده‌شده را «مفروض» می‌گرفتند. با اجرا (نه با
    خواندنِ کد) روی سندهای بدشکل، **۲۳** شکلِ متمایز پیدا شد که استثنا
    می‌دادند — گزارشِ اولیه فقط ۱۲ موردِ «سطحِ بالا dict نیست» را دیده بود.
    نمونه‌های تازه‌کشف‌شده:

        route یک رشته باشد        → AttributeError ('str' has no 'get')
        tag یک لیست باشد          → TypeError: unhashable type: 'list'
        selector.outbounds عدد    → TypeError: 'int' object is not iterable
        proxy-groups رشته/dict    → AttributeError
        group.proxies عدد         → TypeError

    و این استثناها گزارش نمی‌شدند، بلکه **می‌کشتند**: هر دو فراخوانی
    (`check_singbox:170` و `check_clash:183`) هیچ `try` ندارند، پس با اجرا
    ثابت شد که `check_singbox(path, None)` خودش استثنا بیرون می‌دهد و
    `validate.py` می‌میرد — یعنی به‌جای «یک فایلِ خراب = یک `fail`» کلِ
    دروازهٔ اعتبارسنجی از کار می‌افتاد.

    ── چرا یک لفافِ کل، و نه فقط شمردنِ شکل‌ها ────────────────────────────────
    گاردهای دقیق (پایین‌تر) پیامِ خوانا می‌دهند و باید باشند. ولی شمارشِ
    دستیِ شکل‌ها شمارشی است که هر بار یک شکلِ نو جا می‌ماند — همان‌طور که
    گزارشِ اولیه ۱۱ شکل را جا انداخت. پس این لفاف پشتوانهٔ نهایی است:

      • این توابع **اعتبارسنج** اند؛ کارشان همین است که بگویند «این فایل
        قابل‌قبول است یا نه». هر شکلِ غیرمنتظره، به تعریف، «قابل‌قبول نیست».
        پس تبدیلِ استثنا به `(False, …)` نه پنهان‌کاری است، نه نرم‌کردنِ
        دروازه — دقیقاً همان معناست.
      • fail-closed می‌ماند: `check_*` مقدارِ `False` را به وضعیتِ `"fail"`
        نگاشت می‌کند، `fail` در `summary` شمرده می‌شود و `report["ok"]` را
        `False` می‌کند (سطرِ ~۲۶۲)، پس با `--strict` انتشار می‌ایستد.
        یعنی خروجیِ خراب هرگز بی‌صدا منتشر نمی‌شود.
      • نامِ استثنا در پیام می‌آید تا عیب‌یابی کور نشود.
    """
    def wrapper(path: str) -> Tuple[bool, str]:
        try:
            return fn(path)
        except Exception as e:  # noqa: BLE001
            # یک شکلِ پیش‌بینی‌نشده. «نمی‌دانم» در یک اعتبارسنج یعنی «رد».
            return False, (f"unexpected document shape "
                           f"({type(e).__name__}: {str(e)[:120]})")
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    wrapper.__wrapped__ = fn
    return wrapper


@_total_check
def _structural_singbox(path: str) -> Tuple[bool, str]:
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except Exception as e:  # noqa: BLE001
        return False, f"JSON parse error: {e}"
    # JSONِ معتبر لازم نیست یک شیء باشد: `[]`، `"x"`، `42`، `null`، `true`
    # همه سندِ معتبرند و همه پیش از این `AttributeError` می‌دادند.
    if not isinstance(doc, dict):
        return False, (f"top-level JSON must be an object, "
                       f"got {type(doc).__name__}")
    if not isinstance(doc.get("outbounds"), list) or not doc["outbounds"]:
        return False, "missing/empty outbounds"
    tags = set()
    for o in doc["outbounds"]:
        if not isinstance(o, dict):
            return False, "non-object outbound"
        tag = o.get("tag")
        # `tag` باید هش‌شدنی باشد وگرنه ساختنِ همین مجموعه می‌شکست
        # (`TypeError: unhashable type: 'list'`).
        if isinstance(tag, (dict, list, set)):
            return False, f"outbound tag must be a scalar, got {type(tag).__name__}"
        tags.add(tag)
    # هر ارجاعی در selector/urltest باید به یک tag موجود اشاره کند،
    # وگرنه sing-box با «outbound not found» کل فایل را رد می‌کند.
    for o in doc["outbounds"]:
        if o.get("type") in ("selector", "urltest"):
            refs = o.get("outbounds", [])
            # فقط لیست پیمایش می‌شود: عدد `TypeError` می‌داد، و رشته/dict
            # کاراکتر‌به‌کاراکتر یا کلید‌به‌کلید پیمایش می‌شد و پیامِ
            # گمراه‌کنندهٔ «dangling reference: 'a'» می‌ساخت.
            if not isinstance(refs, list):
                return False, (f"{o.get('tag')!r}: selector/urltest outbounds "
                               f"must be a list, got {type(refs).__name__}")
            for ref in refs:
                if ref not in tags:
                    return False, f"dangling reference: {ref!r}"
    route = doc.get("route")
    # `route` تُنُک ولی غیرشیء (`"oops"`, `[…]`, `7`) → پیش از این
    # `(doc.get("route") or {}).get(...)` استثنا می‌داد.
    if route is not None and not isinstance(route, dict):
        return False, f"route must be an object, got {type(route).__name__}"
    final = (route or {}).get("final")
    if final and final not in tags:
        return False, f"route.final points to unknown tag: {final!r}"
    return True, f"structural ok ({len(doc['outbounds'])} outbounds)"


@_total_check
def _structural_clash(path: str) -> Tuple[bool, str]:
    try:
        import yaml
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except Exception as e:  # noqa: BLE001
        return False, f"YAML parse error: {e}"
    # `safe_load` روی فایلِ خالی یا فقط-توضیح `None` می‌دهد، و روی سندِ
    # لیستی/اسکالر یک non-dict. همه پیش از این `AttributeError` می‌دادند.
    if not isinstance(doc, dict):
        got = "empty document" if doc is None else type(doc).__name__
        return False, f"top-level YAML must be a mapping, got {got}"
    proxies = doc.get("proxies")
    if not isinstance(proxies, list) or not proxies:
        return False, "missing/empty proxies"
    names = set()
    for p in proxies:
        # پیش از این، ورودیِ غیر-dict فقط از `names` می‌افتاد و بعد با
        # پیامِ گمراه‌کنندهٔ «duplicate proxy names» گزارش می‌شد. آینهٔ
        # همان قاعدهٔ «non-object outbound» در sing-box است.
        if not isinstance(p, dict):
            return False, "non-object proxy entry"
        nm = p.get("name")
        if isinstance(nm, (dict, list, set)):
            return False, f"proxy name must be a scalar, got {type(nm).__name__}"
        names.add(nm)
    if len(names) != len(proxies):
        return False, "duplicate proxy names (mihomo rejects the file)"
    groups = doc.get("proxy-groups") or []
    if not isinstance(groups, list):
        return False, f"proxy-groups must be a list, got {type(groups).__name__}"
    group_names = {g.get("name") for g in groups if isinstance(g, dict)}
    for g in groups:
        if not isinstance(g, dict):
            return False, "non-object proxy-group entry"
        refs = g.get("proxies", [])
        if not isinstance(refs, list):
            return False, (f"group {g.get('name')!r}: proxies must be a list, "
                           f"got {type(refs).__name__}")
        for ref in refs:
            if ref not in names and ref not in group_names:
                return False, f"group {g.get('name')!r} references unknown proxy {ref!r}"
    return True, f"structural ok ({len(proxies)} proxies)"


# ──────────────────────────────────────────────────────────────────────────────
# اعتبارسنجی با کلاینت واقعی
# ──────────────────────────────────────────────────────────────────────────────

def check_singbox(path: str, binary: Optional[str]) -> Dict[str, Any]:
    if not os.path.isfile(path):
        return {"status": "missing", "detail": "file not found"}
    if not binary:
        ok, detail = _structural_singbox(path)
        return {"status": "skipped" if ok else "fail", "detail": detail,
                "note": "sing-box binary unavailable; structural check only"}
    code, out = _run([binary, "check", "-c", path])
    if code == 0:
        return {"status": "pass", "detail": "sing-box check OK"}
    return {"status": "fail", "detail": out.splitlines()[0][:300] if out else f"exit {code}"}


def check_clash(path: str, binary: Optional[str]) -> Dict[str, Any]:
    if not os.path.isfile(path):
        return {"status": "missing", "detail": "file not found"}
    if not binary:
        ok, detail = _structural_clash(path)
        return {"status": "skipped" if ok else "fail", "detail": detail,
                "note": "mihomo binary unavailable; structural check only"}
    # mihomo برای -t به یک دایرکتوری کاری قابل‌نوشتن نیاز دارد.
    with tempfile.TemporaryDirectory() as d:
        code, out = _run([binary, "-t", "-d", d, "-f", path])
    bad = [ln for ln in out.splitlines() if "level=error" in ln or "level=fatal" in ln]
    if code == 0 and not bad:
        return {"status": "pass", "detail": "mihomo -t OK"}
    detail = (bad[0] if bad else out.splitlines()[0] if out else f"exit {code}")
    return {"status": "fail", "detail": detail[:300]}


# ──────────────────────────────────────────────────────────────────────────────
# بارگذاریِ واقعیِ اشتراک‌های متنی در mihomo (provider load)
# ──────────────────────────────────────────────────────────────────────────────
#
# ── نقصی که این بخش می‌بندد (سنجیده‌شده، نه فرضی) ──────────────────────────
# `check_clash` فقط `mihomo -t` را روی `clash.yaml` اجرا می‌کند. `mihomo -t`
# provider بارگذاری نمی‌کند، پس `configs.txt`/`configs_base64.txt` — همان
# لینک‌هایی که کاربرانِ Clash Meta / FlClash / Clash Verge در برنامه می‌گذارند —
# هیچ‌گاه سنجیده نمی‌شدند. در mihomo یک سطرِ مردود در `ParseProxy` کلِ
# provider را صفر می‌کند (`adapter/provider/provider.go`). روی خروجیِ زندهٔ
# ۲۰۲۶-۱۰-۱۵ ۲۰:۱۲ UTC با باینریِ pin‌شدهٔ v1.19.29:
#     all/configs.txt   12103 خط → 0 بارگذاری   (unknown method: chacha20-poly1305)
#     heavy/configs.txt  9454 خط → 0
#     light/configs.txt  3356 خط → 0           (REALITY requires TLS)
#     protocols/vless.txt, protocols/shadowsocks.txt (+ base64) → 0
# یعنی ۱۴ فایلِ اشتراک خراب بود و همهٔ ۱۲ بررسیِ این دروازه «pass» بودند.
#
# ── چرا تشخیصِ «تمام شد» حدس نیست ──────────────────────────────────────────
# `hub/executor/executor.go::ApplyConfig` (v1.19.29) به این ترتیب است:
#     loadProvider(cfg.Providers)      // همهٔ proxy-providerها + wg.Wait()
#     updateProfile(cfg)
#     loadProvider(cfg.RuleProviders)  // ← لاگِ «Start initial provider …»
# پس دیده‌شدنِ لاگِ شروعِ یک rule-providerِ نگهبان یعنی همهٔ proxy-providerها
# تمام شده‌اند (موفق یا ناموفق). بدونِ `sleep`ِ حدسی.
#
# ── چرا پیش‌فرض «گزارش» است نه «بستنِ انتشار» ─────────────────────────────
# دروازهٔ `mihomo_compat` در aggregate.py سطرهای مهلکِ شناخته‌شده را پیش از
# انتشار حذف می‌کند. اگر اینجا شکستی دیده شود یعنی قاعده‌ای **تازه** در
# mihomo. بستنِ کلِ انتشار به‌خاطرِ آن، به‌روزرسانیِ کاربرانِ v2rayNG/Hiddify
# (که مشکلی ندارند) را هم متوقف می‌کرد و کانفیگ‌های رایگان در چند ساعت
# می‌میرند. پس پیش‌فرض: هشدارِ آشکار (annotation در CI + `validation.json`)؛
# و `--strict-subscriptions` برای کسی که بستن را می‌خواهد.

#: طرح‌هایی که مبدّلِ URI در mihomo می‌شناسد (`common/convert/converter.go`،
#: شاخه‌های `switch scheme` در v1.19.29). فایلی که هیچ سطری با این طرح‌ها
#: ندارد (مثلاً `protocols/happ.txt`) برای mihomo «نامربوط» است، نه «خراب».
MIHOMO_URI_SCHEMES = frozenset({
    "hysteria", "hysteria2", "hy2", "hysteria2+realm", "hy2+realm", "tuic",
    "trojan", "vless", "vmess", "ss", "ssr", "socks", "socks5", "socks5h",
    "http", "https", "anytls", "mierus",
})

#: سقفِ انتظار برای بارگذاریِ همهٔ providerها (ثانیه). سنجیده: ۶۶ فایل با
#: ~۷۰هزار سطر در ۵.۷ ثانیه؛ ۱۲۰ ثانیه ~۲۰ برابر حاشیه است.
SUBSCRIPTION_TIMEOUT = 120

_SENTINEL = "zz_load_sentinel"
_PROVIDER_ERR_RE = re.compile(
    r'initial proxy provider (p\d{3}) error: (.*?)"?\s*$', re.M)


def _subscription_files(out_dir: str, categories: List[str]) -> List[str]:
    """مسیرِ نسبیِ همهٔ فایل‌های اشتراکِ متنیِ منتشرشده، مرتب و یکتا."""
    rels: List[str] = []
    for cat in categories:
        for name in ("configs.txt", "configs_base64.txt"):
            rels.append(f"{cat}/{name}")
    rels.append("top100.txt")
    for sub in ("protocols", "Countries"):
        for p in glob.glob(os.path.join(out_dir, sub, "*.txt")):
            rels.append(f"{sub}/{os.path.basename(p)}")
    seen = sorted(set(rels))
    return [r for r in seen if os.path.isfile(os.path.join(out_dir, r))]


def _supported_lines(text: str) -> int:
    n = 0
    for line in text.split("\n"):
        scheme, sep, _ = line.strip().partition("://")
        if sep and scheme.lower() in MIHOMO_URI_SCHEMES:
            n += 1
    return n


def _mihomo_relevant_lines(buf: bytes) -> int:
    """تعدادِ سطرهایی که mihomo به‌عنوانِ پروکسی می‌خواند — محافظه‌کارانه.

    mihomo کلِ بافر را اول base64 می‌خواند و اگر نشد متنِ ساده
    (`common/convert/base64.go::DecodeBase64`). بیشینهٔ هر دو تفسیر گرفته
    می‌شود تا فایلی هرگز به‌اشتباه «نامربوط» شمرده نشود.
    """
    text = buf.decode("utf-8", errors="replace")
    best = _supported_lines(text)
    compact = "".join(text.split())
    if compact:
        try:
            dec = base64.b64decode(compact + "=" * (-len(compact) % 4),
                                   validate=True)
            best = max(best, _supported_lines(dec.decode("utf-8", "replace")))
        except Exception:  # noqa: BLE001 — متنِ ساده است، نه base64
            pass
    return best


def _parse_provider_errors(log_text: str) -> Dict[str, str]:
    return {m.group(1): m.group(2).replace('\\"', '"')
            for m in _PROVIDER_ERR_RE.finditer(_clean(log_text))}


def _api_get(sock_path: str, path: str) -> Any:
    import http.client
    import socket

    class _Unix(http.client.HTTPConnection):
        def connect(self) -> None:  # noqa: D401
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(30)
            self.sock.connect(sock_path)

    conn = _Unix("mihomo")
    try:
        conn.request("GET", path)
        return json.loads(conn.getresponse().read())
    finally:
        conn.close()


def _classify_subscription(relevant: int, loaded: int,
                           error: Optional[str]) -> Dict[str, Any]:
    """حکمِ یک فایل از روی سه واقعیتِ سنجیده‌شده (تابعِ خالص).

    • `relevant == 0` → `n/a`: هیچ طرحی که mihomo بشناسد ندارد (مثلاً
      `happ://` یا `slipnet-enc://`). mihomo همیشه رَدَش می‌کند و این فایل
      از اساس برای کاربرانِ mihomo نیست — «نامربوط»، نه «خراب».
    • خطای provider → `fail` (همان چیزی که کاربر می‌بیند: صفر پروکسی).
    • بی‌خطا ولی صفر پروکسی → `fail` (هرگز «pass» با صفر).
    """
    entry: Dict[str, Any] = {"lines": relevant, "loaded": loaded}
    if relevant == 0:
        entry["status"] = "n/a"
        if error:
            entry["detail"] = error[:300]
    elif error:
        entry.update(status="fail", detail=error[:300])
    elif loaded == 0:
        entry.update(status="fail", detail="provider loaded 0 proxies")
    else:
        entry["status"] = "pass"
    return entry


def check_subscriptions(out_dir: str, binary: Optional[str],
                        categories: Optional[List[str]] = None,
                        timeout: Optional[float] = None) -> Dict[str, Any]:
    """هر فایلِ اشتراکِ متنی را با providerِ **واقعیِ** mihomo بارگذاری می‌کند.

    وضعیتِ هر فایل: `pass` (بارگذاری شد و دست‌کم یک پروکسی)، `fail` (خطای
    provider یا صفر پروکسی با وجودِ سطرِ پشتیبانی‌شده)، `n/a` (هیچ طرحی که
    mihomo بشناسد ندارد). هرگز استثنا بیرون نمی‌دهد.
    """
    cats = list(categories) if categories is not None else list(CORE_CATEGORIES)
    if not binary:
        return {"status": "skipped", "files": {},
                "detail": "mihomo binary unavailable; subscription load not run"}
    limit = float(timeout if timeout is not None else SUBSCRIPTION_TIMEOUT)
    files = _subscription_files(out_dir, cats)
    if not files:
        return {"status": "fail", "files": {}, "detail": "no subscription files"}
    work = tempfile.mkdtemp(prefix="mh_sub_")
    proc = None
    try:
        names: Dict[str, str] = {}
        relevant: Dict[str, int] = {}
        cfg = ["mixed-port: 0", "log-level: info",
               f"external-controller-unix: {json.dumps(os.path.join(work, 'api.sock'))}",
               "proxy-providers:"]
        for i, rel in enumerate(files):
            name = f"p{i:03d}"
            names[name] = rel
            with open(os.path.join(out_dir, rel), "rb") as fh:
                buf = fh.read()
            relevant[name] = _mihomo_relevant_lines(buf)
            # mihomo فقط مسیرهای داخلِ home (`-d`) را می‌پذیرد (SAFE_PATHS).
            with open(os.path.join(work, f"{name}.txt"), "wb") as fh:
                fh.write(buf)
            cfg.append(f"  {name}: {{type: file, path: ./{name}.txt, "
                       f"health-check: {{enable: false}}}}")
        with open(os.path.join(work, "sentinel.txt"), "w", encoding="utf-8") as fh:
            fh.write("DOMAIN,sentinel.invalid\n")
        cfg += ["rule-providers:",
                f"  {_SENTINEL}: {{type: file, behavior: classical, "
                f"format: text, path: ./sentinel.txt}}",
                "proxy-groups:",
                "  - {name: g, type: select, use: [" + ", ".join(names) + "]}",
                f'rules: ["RULE-SET,{_SENTINEL},DIRECT", "MATCH,DIRECT"]']
        conf = os.path.join(work, "config.yaml")
        with open(conf, "w", encoding="utf-8") as fh:
            fh.write("\n".join(cfg) + "\n")

        log_path = os.path.join(work, "mihomo.log")
        marker = f"Start initial provider {_SENTINEL}"
        with open(log_path, "wb") as log:
            proc = subprocess.Popen([binary, "-d", work, "-f", conf],
                                    stdin=subprocess.DEVNULL, stdout=log,
                                    stderr=subprocess.STDOUT)
            started = time.time()
            while True:
                with open(log_path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
                if marker in text:
                    break
                if proc.poll() is not None:
                    last = _clean(text).strip().splitlines()[-1:] or [""]
                    return {"status": "fail", "files": {},
                            "detail": f"mihomo exited {proc.returncode} before "
                                      f"loading: {last[0][:300]}"}
                if time.time() - started > limit:
                    return {"status": "fail", "files": {},
                            "detail": f"providers not loaded within {limit:g}s"}
                time.sleep(0.2)
            elapsed = round(time.time() - started, 2)
            data = _api_get(os.path.join(work, "api.sock"),
                            "/providers/proxies").get("providers", {})
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            errors = _parse_provider_errors(fh.read())

        results: Dict[str, Any] = {}
        for name, rel in names.items():
            loaded = len((data.get(name) or {}).get("proxies") or [])
            results[rel] = _classify_subscription(relevant[name], loaded,
                                                  errors.get(name))
        failed = sorted(r for r, e in results.items() if e["status"] == "fail")
        return {"status": "fail" if failed else "pass", "files": results,
                "failed": failed, "seconds": elapsed,
                "detail": (f"{len(failed)} of {len(results)} subscription file(s) "
                           f"load 0 proxies in mihomo") if failed else
                          f"{len(results)} subscription file(s) loaded"}
    except Exception as e:  # noqa: BLE001 — یک اعتبارسنج هرگز نمی‌میرد
        return {"status": "fail", "files": {},
                "detail": f"subscription check error ({type(e).__name__}: "
                          f"{str(e)[:200]})"}
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        shutil.rmtree(work, ignore_errors=True)


def validate_outputs(out_dir: str) -> Dict[str, Any]:
    """همهٔ فایل‌های Clash/Sing-box را اعتبارسنجی می‌کند و گزارش برمی‌گرداند."""
    sb = _find_binary("sing-box")
    mh = _find_binary("mihomo", "clash-meta", "clash")
    report: Dict[str, Any] = {
        "tools": {
            "sing_box": sb or None,
            "mihomo": mh or None,
        },
        "results": {},
        "summary": {"pass": 0, "fail": 0, "skipped": 0, "missing": 0},
    }
    absent: List[str] = []
    for cat in CATEGORIES:
        cat_dir = os.path.join(out_dir, cat)
        # دستهٔ اختیاری که کلاً وجود ندارد: هنوز تولید نمی‌شود، پس بررسی‌ای
        # هم ندارد. ولی اگر دایرکتوری *باشد*، دقیقاً مثل دسته‌های اصلی
        # سنجیده می‌شود — نه نرم‌تر.
        if cat in OPTIONAL_CATEGORIES and not os.path.isdir(cat_dir):
            absent.append(cat)
            continue
        report["results"][cat] = {
            "singbox": check_singbox(os.path.join(cat_dir, "singbox.json"), sb),
            "clash": check_clash(os.path.join(cat_dir, "clash.yaml"), mh),
        }
    report["absent_optional"] = absent
    # ناوردا: دستهٔ اصلی هرگز از بررسی رد نمی‌شود، حتی اگر دایرکتوری‌اش نباشد
    # (در آن حالت فایل‌ها `missing` می‌شوند و دروازه همان‌جا می‌شکند).
    assert all(c in report["results"] for c in CORE_CATEGORIES), \
        "every core category must be checked"
    for cat_res in report["results"].values():
        for res in cat_res.values():
            report["summary"][res["status"]] = report["summary"].get(res["status"], 0) + 1

    # ── دروازه: فهرستِ سفید، نه فهرستِ سیاه (F-5) ─────────────────────────────
    #
    # شکلِ پیشین `fail == 0 and missing == 0` بود؛ یعنی یک **فهرستِ سیاه**.
    # با اجرا (نه با خواندنِ کد) ثابت شد که این fail-open است: اگر روزی یک
    # `check_*` وضعیتی تازه برگرداند — مثلاً `"error"` یا `"timeout"` — آن
    # وضعیت در `summary` شمرده می‌شود ولی در هیچ‌یک از دو شرط نمی‌آید، پس:
    #
    #     summary = {'pass': 0, 'fail': 0, 'skipped': 3, 'missing': 0, 'error': 3}
    #     ok      = True      ← دروازه سبز، با ۳ موردِ خطا!
    #
    # این «باگِ خاموش» است: امروز بی‌اثر است (هر چهار وضعیتِ تولیدشدنی
    # پوشش داده شده‌اند) ولی افزودنِ یک وضعیتِ تازه در آینده، دروازه را
    # بی‌صدا باز می‌کند. `_run` هم دو کدِ اختصاصیِ ۱۲۴/۱۲۵ دارد که وسوسهٔ
    # افزودنِ وضعیتِ `"timeout"` را واقعی می‌کند.
    #
    # درمان: فقط وضعیت‌هایی که **صریحاً** قابل‌قبول شمرده شده‌اند اجازهٔ
    # عبور دارند؛ هر چیزِ دیگر، از جمله وضعیتِ ناشناخته، دروازه را می‌بندد.
    #
    # ثابت شد که این تغییر **صفر رگرسیون** دارد: روی هر ۸۱ ترکیبِ شمارشِ
    # چهار وضعیتِ واقعی (`pass`/`fail`/`skipped`/`missing`، هر یک ۰..۲)،
    # فهرستِ سفید و شکلِ پیشین **در همهٔ موارد هم‌نظرند** (صفر اختلاف).
    # تفاوت تنها آن‌جا ظاهر می‌شود که وضعیتی ناشناخته وجود داشته باشد.
    #
    # چرا `skipped` قابل‌قبول است و «نرم‌کردن» نیست: طبقِ سندِ بالای همین
    # فایل، در توسعهٔ محلی که باینریِ کلاینت نیست، اعتبارسنجیِ ساختاری
    # جایگزین می‌شود و نتیجه `skipped` علامت می‌خورد — و همان بررسیِ
    # ساختاری هرچه خراب باشد `fail` می‌دهد نه `skipped`. در CI هم گامِ
    # نصبِ باینری‌ها fail-closed است (`set -euo pipefail` + چهار checksum و
    # بدونِ `continue-on-error`)، پس رسیدن به `skipped` در CI یعنی آن گام
    # پیش‌تر کلِ job را شکسته است.
    # فهرستِ سفید در سطحِ ماژول تعریف شده (بالای فایل) تا آزمونِ ناوردا
    # بتواند **همان** منبعِ حقیقت را بخواند، نه رونوشتی از آن.
    offending = {status: count
                 for status, count in report["summary"].items()
                 if count > 0 and status not in ACCEPTABLE_STATUSES}
    report["offending"] = offending
    report["ok"] = not offending

    # ── شفافیت: «چیزی اثبات نشد» باید دیده شود ────────────────────────────────
    #
    # سنجیده شد که با نبودِ هر دو باینری، خروجی `pass=0 skipped=6` و
    # `ok=True` و `rc=0` است. این طبقِ طراحی است (بالا) و **نباید** به
    # شکست تبدیل شود — سه تستِ موجود (`…optional_category_absence…`،
    # `…pipeline output gate…`، `…f7…`) درست به همین رفتار تکیه دارند و
    # سخت‌کردنِ دروازه، رگرسیون می‌ساخت نه بهبود.
    #
    # ولی «طبقِ طراحی» به‌معنای «نامرئی» نیست: تا امروز هیچ‌جا دیده نمی‌شد
    # که این اجرا با کلاینتِ واقعی سنجیده شده یا فقط ساختاری. این پرچمِ
    # صریح، تصمیم را از حدس‌زدن بیرون می‌آورد و در `validation.json` هم
    # ثبت می‌شود.
    report["real_validation"] = report["summary"]["pass"] > 0

    # بارگذاریِ واقعیِ اشتراک‌های متنی (بالا را ببینید). عمداً بیرونِ
    # `summary`/`ok` است تا حکمِ دروازهٔ موجود بیت‌به‌بیت همان بماند؛
    # بستنِ انتشار با آن، انتخابِ صریحِ `--strict-subscriptions` است.
    report["subscriptions"] = check_subscriptions(
        out_dir, mh, categories=list(report["results"]))
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate generated client configs")
    ap.add_argument("--out", default=os.getcwd(), help="repo root containing all/ heavy/ light/")
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero when any file fails validation")
    ap.add_argument("--strict-subscriptions", action="store_true",
                    help="also exit non-zero when a .txt subscription loads "
                         "0 proxies in mihomo (default: warn only)")
    ap.add_argument("--json", dest="json_path", default="",
                    help="also write the report to this path")
    args = ap.parse_args()

    rep = validate_outputs(os.path.abspath(args.out))
    print("🔍 Client validation")
    print(f"   sing-box: {rep['tools']['sing_box'] or 'NOT FOUND (structural fallback)'}")
    print(f"   mihomo  : {rep['tools']['mihomo'] or 'NOT FOUND (structural fallback)'}")
    icons = {"pass": "✅", "fail": "❌", "skipped": "⚠️", "missing": "🚫"}
    for cat, res in rep["results"].items():
        for kind, r in res.items():
            print(f"   {icons.get(r['status'], '?')} {cat:<5} {kind:<8} "
                  f"{r['status']:<8} {r['detail']}")
    for cat in rep.get("absent_optional", []):
        print(f"   ➖ {cat:<5} {'—':<8} not produced in this run")
    s = rep["summary"]
    print(f"   → pass={s['pass']} fail={s['fail']} "
          f"skipped={s['skipped']} missing={s['missing']}")
    # هر وضعیتِ ناشناخته‌ای که دروازه را بست، باید نامش چاپ شود وگرنه
    # عیب‌یابی کور می‌شود («چرا قرمز شد؟» بی‌پاسخ می‌ماند).
    extra = {k: v for k, v in s.items()
             if v > 0 and k not in ("pass", "fail", "skipped", "missing")}
    if extra:
        print(f"   ⚠️ unrecognised statuses (gate closed): {extra}")
    if not rep.get("real_validation", False):
        print("   ⚠️ structural fallback only — no real client validated this run")

    sub = rep.get("subscriptions") or {}
    sub_icon = {"pass": "✅", "fail": "❌", "skipped": "⚠️"}.get(sub.get("status"), "?")
    print(f"   {sub_icon} subscriptions (mihomo provider load): "
          f"{sub.get('status')} — {sub.get('detail', '')}")
    for rel in sub.get("failed", []):
        e = sub["files"][rel]
        print(f"      ❌ {rel}: lines={e['lines']} loaded={e['loaded']} "
              f"{e.get('detail', '')}")
        if os.environ.get("GITHUB_ACTIONS") == "true":
            # annotation: در صفحهٔ اجرای CI دیده می‌شود حتی وقتی job سبز است.
            print(f"::warning title=mihomo subscription broken::{rel} loads 0 "
                  f"proxies in mihomo — {e.get('detail', '')[:200]}")

    if args.json_path:
        os.makedirs(os.path.dirname(os.path.abspath(args.json_path)) or ".", exist_ok=True)
        with open(args.json_path, "w", encoding="utf-8") as f:
            json.dump(rep, f, ensure_ascii=False, indent=2)

    if args.strict and not rep["ok"]:
        print("❌ Validation gate FAILED — outputs must not be published.")
        return 1
    if args.strict_subscriptions and sub.get("status") == "fail":
        print("❌ Subscription gate FAILED — a .txt subscription loads 0 "
              "proxies in mihomo.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
