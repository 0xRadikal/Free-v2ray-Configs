#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
آبشارِ چهارلایه — هماهنگ‌کننده (بندهای B5/B6/B7/B8 فاز B).

این ماژول لایه‌های موجود را **می‌چیند**، نه آن‌که منطقشان را تکرار کند:

    L0/L1  filters.py       حذفِ ساختاریِ بی‌شبکه + یکتاسازیِ نقطهٔ پایانی
    L2     reachability.py  دست‌دادنِ TCP
    L3     realtest.py      آزمونِ واقعیِ پروکسی با xray-knife
    ↓
    verified/ · fast/ · secure/ · top100.txt

چهار تصمیمِ **سنجیده** که این فایل را شکل می‌دهند:

۱) «پایدار» = موفق در **همهٔ** اجراهای یک دور، با **۳** اجرا.
   سنجش (B4b، ۵ اجرای کامل، **در سندباکس**): موفق‌ها ۵۰۱/۴۷۳/۳۶۳/۴۴۲/۴۷۳ —
   میانگین ۴۵۰٫۴، انحرافِ معیار ۵۳٫۱، دامنه ۱۳۸ (۳۰٫۶٪). از ۶۲۶ کانفیگی که
   **دست‌کم یک بار** کار کرد، تنها ۲۲۴ **همیشه** کار کرد ⇒ ۶۴٫۲۲٪ لرزان.
   اعتبارسنجیِ leave-one-out (آموزش روی ۴ اجرا، آزمون روی پنجمی):
       ۱-از-۴ → ۶۱۱ کانفیگ · دقت ۷۱٫۳٪ · بازخوانی ۹۶٫۸٪
       ۲-از-۴ → ۵۲۰ کانفیگ · دقت ۷۷٫۸٪ · بازخوانی ۸۹٫۹٪
       ۳-از-۴ → ۴۱۶ کانفیگ · دقت ۸۳٫۷٪ · بازخوانی ۷۷٫۵٪
       ۴-از-۴ → ۲۵۵ کانفیگ · دقت ۸۸٫۵٪ · بازخوانی ۵۰٫۴٪
       یک اجرا (مبنا) → ۴۵۰ کانفیگ · دقت ۷۸٫۶٪

   ⚠️ **آن ۶۴٫۲۲٪ عددِ محیط است، نه ثابتِ قاعده.** همان کد روی یک سرورِ
   اختصاصی (۸۱۵۸ کانفیگِ یکسان، ۳ اجرا) سنجیده شد: موفق‌ها ۵۴۲/۵۳۱/۵۳۲
   (انحرافِ معیار ≈۶ در برابر ۵۳)، پایدار ۴۵۸ در برابر ۲۲۴، لرزان
   **۲۴٫۹۲٪** در برابر ۶۴٫۲۲٪. یعنی بخشِ بزرگی از آن لرزش، شبکهٔ سندباکس
   بود و نه کانفیگ‌ها. **قاعده** («موفق در همهٔ اجراها») از هر دو سنجش
   سالم بیرون آمد؛ فقط *درصد* را نباید مطلق خواند. هر خروجی درصدِ
   **همان اجرا** را در سرآیندِ خود می‌نویسد (`stats['flaky_pct']`).

   هزینه: سنجشِ اجراشده روی سرور ⇒ L3 سه اجرا **۱۰۶٫۹۲s** و کلِ آبشار
   (L0/L1 + L2 + سه اجرای L3) **۱۴۹٫۳۴s** از بودجهٔ ۹۰۰ ثانیه‌ایِ CI،
   کندترین اجرا ۳۶٫۲۱s ⇒ جا می‌شود. (ادعای پیشینِ «۳×۴۴s ≈ ۱۳۲s» در همین
   docstring **غلط** بود: آن ۴۴s از سریع‌ترین اجرای سندباکس برداشته شده
   بود، در حالی که فاصلهٔ واقعیِ اجراهای B4b ۵۴/۳۴۵/۶۱۵/۴۰۴ ثانیه بود.)
   روی اجراهای ۱–۳ سندباکس عدداً **۲۸۱** کانفیگ می‌داد و روی سرور ۴۵۸ —
   هر دو بیش از ۱۰۰ موردِ لازم برای `top100.txt`.

۲) پذیرشِ یک ردیف **چهار** شرط دارد، نه یکی. `success == total` تنها **سوراخ**
   است: برای همهٔ ۸۷ ردیفِ `broken` هم درست است (۰ == ۰). قاعده در
   `realtest.is_row_genuinely_ok` است و این‌جا **بازنویسی نمی‌شود**.

۳) `fast` با **میانهٔ چند اجرا** سنجیده می‌شود، نه یک اجرا. سنجش: میانهٔ هر
   اجرا ۷۶۱/۷۲۰/۷۶۸/۷۵۶/۷۶۵ms (میانگین ۷۵۴، انحرافِ معیار فقط ۲۰) — یعنی
   *توزیع* پایدار است. ولی **۷۷ کانفیگ (۳۴٫۴٪) خطِ ۸۰۰ms را بینِ اجراها رد و
   بدل می‌کنند** (میانهٔ دامنهٔ درون‌لینکی ۳۷۳ms = ۵۷٫۲٪). پس برچسبِ تک‌اجرا
   بی‌اعتبار است.

۴) `secure` = **محرمانگیِ پیشرو**، نه «هر رمزنگاری». مستندِ کاملِ استدلال و سه
   اثباتِ اجراشده در `PHASE_B_PLAN.md` بندِ B7؛ خلاصه در `has_forward_secrecy`.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import realtest  # noqa: E402
import reachability  # noqa: E402
import converters  # noqa: E402
import core  # noqa: E402

# ──────────────────────────────────────────────────────────────────────────────
# ثابت‌ها
# ──────────────────────────────────────────────────────────────────────────────

#: تعدادِ اجراهای L3 در هر دور. «پایدار» = موفق در *همهٔ* این اجراها.
#: سنجش (B4b): ۳ اجرا ⇒ ۲۸۱ کانفیگ روی اجراهای ۱–۳ و ~۱۳۲ ثانیه هزینه.
L3_ROUNDS = int(os.environ.get("L3_ROUNDS", "3"))

#: آستانهٔ `fast` بر پایهٔ **میانهٔ** چند اجرا (میلی‌ثانیه).
#: سنجش روی مجموعهٔ پایدار: ۳۰۰ms→۱۴ کانفیگ (۶٫۲٪، بی‌فایده) · ۵۰۰→۸۶ ·
#: ۶۰۰→۱۱۱ · **۸۰۰→۱۴۹ (۶۶٫۵٪)** · ۱۰۰۰→۱۶۸ · ۱۲۰۰→۱۸۲.
FAST_THRESHOLD_MS = int(os.environ.get("L3_FAST_MS", "800"))

#: سقفِ `top100.txt`. اگر کمتر از این تعداد پایدار بود، فایل با تعدادِ
#: **واقعی** منتشر می‌شود؛ پرکردنِ مصنوعی با کانفیگِ نیازموده ممنوع است.
TOP_N = int(os.environ.get("L3_TOP_N", "100"))

#: مقادیرِ `tls` که دست‌دادنِ (EC)DHE و در نتیجه محرمانگیِ پیشرو را می‌رسانند.
FS_TLS_VALUES = frozenset({"tls", "reality", "xtls"})

#: پروتکل‌هایی که روی QUIC سوارند ⇒ TLS 1.3 اجباری (RFC 9001 §4.2:
#: «Clients MUST NOT offer TLS versions older than 1.3»).
FS_SCHEMES = frozenset({"hysteria2", "hy2", "tuic"})

#: پارامترهایی که با آن‌ها خودِ لینک اعتبارسنجیِ گواهی را کنار می‌گذارد.
#: چنین لینکی هرچند TLS دارد، در برابرِ MITM محافظت ندارد.
INSECURE_KEYS = frozenset({
    "insecure", "allowinsecure", "allow_insecure",
    "skip-cert-verify", "skipcertverify", "allowinsecureciphers",
})
_TRUEISH = frozenset({"1", "true", "yes", "on"})

CATEGORIES = ("verified", "fast", "secure")


class StabilityError(RuntimeError):
    """دورِ آزمون نتوانست هیچ اجرای معتبری تولید کند — خطای محیط، نه داده."""


# ──────────────────────────────────────────────────────────────────────────────
# داوریِ امنیت
# ──────────────────────────────────────────────────────────────────────────────

def scheme_of(link: str) -> str:
    return link.split("://", 1)[0].strip().lower() if "://" in link else ""


def _query(link: str) -> Dict[str, str]:
    try:
        raw = parse_qs(urlsplit(link).query)
    except ValueError:
        return {}
    return {k.strip().lower(): (v[0] if v else "") for k, v in raw.items()}


def declares_insecure(link: str) -> bool:
    """آیا خودِ لینک اعتبارسنجیِ گواهی را غیرفعال می‌کند؟"""
    q = _query(link)
    for key in INSECURE_KEYS:
        if unquote(q.get(key, "")).strip().lower() in _TRUEISH:
            return True
    return False


def has_forward_secrecy(link: str, tls_value: str) -> bool:
    """
    آیا کلیدِ نشست از (EC)DHE می‌آید؟

    چرا این معیار و نه «هر رمزنگاری»؟ چون این مخزن **عمومی** است. سه اثباتِ
    اجراشده (`/home/user/exp/b7_proof.py` و `b7_final.py`):

      * `ss` با رمزِ AEAD: `salt` روی سیم بازمتن است و کلیدِ اصلی از رمزِ
        داخلِ همان لینکِ منتشرشده مشتق می‌شود ⇒ ناظری که فقط لینک را دارد
        متنِ اصلی را باز کرد (۳/۳ رمز). SIP022 هم صریح است:
        «Shadowsocks 2022 does not provide forward secrecy».
      * `vmess` بی‌TLS: کلیدِ بخشِ فرمان `MD5(UUID ‖ ثابتِ عمومی)` است و آن
        بخش خودش کلیدِ دادهٔ نشست را دارد ⇒ با UUIDِ منتشرشده و ۶۱ بار MD5
        (پنجرهٔ ±۳۰ ثانیه) کلیدِ نشست بازیافت شد.
      * `vless` با `tls=none`: مشخصهٔ VLESS `encryption` را «تنها `none`»
        می‌پذیرد ⇒ واقعاً بی‌رمز.

    این کانفیگ‌ها «خراب» نیستند و در `verified/` می‌مانند؛ فقط برچسبِ «امن»
    برایشان در یک مخزنِ عمومی نادرست است.
    """
    if (tls_value or "").strip().lower() in FS_TLS_VALUES:
        return True
    return scheme_of(link) in FS_SCHEMES


def is_secure(link: str, tls_value: str) -> bool:
    return has_forward_secrecy(link, tls_value) and not declares_insecure(link)


# ──────────────────────────────────────────────────────────────────────────────
# دورِ چندباره‌ی L3
# ──────────────────────────────────────────────────────────────────────────────

def _median_int(values: Sequence[int]) -> int:
    return int(round(statistics.median(values)))


def _rows_of(result: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    ردیف‌های یک اجرای L3 را برمی‌گرداند.

    `realtest.run_test` کلیدِ `rows` را **نقشهٔ لینک→ردیف** می‌دهد. اتکا به
    پیمایشِ مستقیمِ آن، کلیدهای رشته‌ای می‌دهد و در اجرای واقعی می‌شکند؛ این
    تابع قرارداد را در **یک نقطه** متمرکز می‌کند و شکلِ ناشناخته را خاموش رد
    نمی‌کند، بلکه بلند می‌شکند.
    """
    rows = result.get("rows")
    if isinstance(rows, dict):
        return list(rows.values())
    if isinstance(rows, list):
        return rows
    raise StabilityError(
        f"unexpected shape for the L3 'rows' field: {type(rows).__name__}")


def run_l3_round(lines: Sequence[str], rounds: int = None,
                 **kwargs: Any) -> Dict[str, Any]:
    """
    L3 را `rounds` بار روی همان ورودی اجرا می‌کند و پایداری را می‌سنجد.

    خروجی:
        rounds       : تعدادِ اجراهای انجام‌شده
        per_run_ok   : تعدادِ موفقِ هر اجرا (برای تلمتری و کشفِ رگرسیون)
        stable       : لینک‌هایی که در **همهٔ** اجراها پذیرفته شدند
        ever_ok      : لینک‌هایی که دست‌کم یک بار پذیرفته شدند
        delays       : لینکِ پایدار → میانهٔ تأخیر در اجراها
        tls          : لینک → مقدارِ `tls` (ایستا؛ در ۰ از ۳٬۸۴۵ ردیف تغییر کرد)
        flaky_pct    : درصدِ لرزان از میانِ هرچه کار کرد
    """
    if rounds is None:
        rounds = L3_ROUNDS
    if rounds < 1:
        raise ValueError(f"rounds must be >= 1, got {rounds!r}")

    lines = [ln.strip() for ln in lines if (ln or "").strip()]
    if not lines:
        # همان درسِ لایهٔ L3: ورودیِ تهی باید **بلند** بشکند، نه خاموش.
        raise realtest.EmptyInput("no configs to test at L3")

    ok_sets: List[set] = []
    per_run_ok: List[int] = []
    delays: Dict[str, List[int]] = {}
    tls_of: Dict[str, str] = {}

    for _ in range(rounds):
        res = realtest.test_lines(lines, **kwargs)
        # قرارداد سنجیده‌شده: `realtest` مقدارِ `rows` را **نقشهٔ لینک→ردیف**
        # می‌دهد (خطِ ۳۹۳: `"rows": by_link`). پیمایشِ مستقیمِ یک dict کلیدها را
        # می‌دهد که رشته‌اند، نه ردیف. این اشتباه در اجرای واقعی با
        # `'str' object has no attribute 'get'` شکست — در حالی که آزمون‌ها سبز
        # بودند، چون شیمِ آزمون شکلِ نادرستی می‌داد. `.values()` صریح است و
        # `_rows_of` هر دو شکل را می‌پذیرد تا قرارداد یک‌جا کنترل شود.
        ok_now = set()
        for row in _rows_of(res):
            link = (row.get("link") or "").strip()
            if not link:
                continue
            tls_of.setdefault(link, realtest.row_tls(row))
            if realtest.is_row_genuinely_ok(row):
                ok_now.add(link)
                d = realtest.row_delay_ms(row)
                if d is not None:
                    delays.setdefault(link, []).append(d)
        ok_sets.append(ok_now)
        per_run_ok.append(len(ok_now))

    if not ok_sets:
        raise StabilityError("no L3 run produced a result set")

    stable = set.intersection(*ok_sets)
    ever_ok = set.union(*ok_sets)
    flaky_pct = (round(100.0 * (len(ever_ok) - len(stable)) / len(ever_ok), 2)
                 if ever_ok else 0.0)

    return {
        "rounds": rounds,
        "per_run_ok": per_run_ok,
        "stable": stable,
        "ever_ok": ever_ok,
        # تنها میانهٔ لینک‌های پایدار معنا دارد؛ بقیه نمونهٔ کامل ندارند.
        "delays": {L: _median_int(delays[L]) for L in stable if L in delays},
        "tls": tls_of,
        "flaky_pct": flaky_pct,
    }


def build_buckets(round_result: Dict[str, Any],
                  fast_ms: int = None,
                  top_n: int = None) -> Dict[str, Any]:
    """
    از نتیجهٔ دور، سه سبد + `top100` را می‌سازد.

    مرتب‌سازی همه‌جا بر **میانهٔ تأخیر** است و برای تأخیرهای مساوی بر خودِ
    لینک — تا خروجی **بازتولیدپذیر** باشد و در git تفاوتِ کاذب نسازد.
    """
    if fast_ms is None:
        fast_ms = FAST_THRESHOLD_MS
    if top_n is None:
        top_n = TOP_N

    delays = round_result["delays"]
    tls_of = round_result["tls"]
    stable = round_result["stable"]

    # کانفیگِ پایدارِ بی‌تأخیر نداریم، ولی اگر پیش آمد نباید خاموش گم شود.
    ranked = sorted(stable, key=lambda L: (delays.get(L, 10 ** 9), L))

    verified = ranked
    fast = [L for L in ranked if delays.get(L, 10 ** 9) < fast_ms]
    secure = [L for L in ranked if is_secure(L, tls_of.get(L, ""))]
    top = ranked[:top_n]

    return {
        "verified": verified,
        "fast": fast,
        "secure": secure,
        "top": top,
        "delays": delays,
        "stats": {
            "rounds": round_result["rounds"],
            "per_run_ok": round_result["per_run_ok"],
            "ever_ok": len(round_result["ever_ok"]),
            "stable": len(stable),
            "flaky_pct": round_result["flaky_pct"],
            "fast_threshold_ms": fast_ms,
            "verified": len(verified),
            "fast": len(fast),
            "secure": len(secure),
            "top": len(top),
            "top_short_by": max(0, top_n - len(top)),
            "median_delay_ms": (_median_int(sorted(delays.values()))
                                if delays else None),
        },
    }


# ──────────────────────────────────────────────────────────────────────────────
# نوشتنِ خروجی
# ──────────────────────────────────────────────────────────────────────────────

def _write_lines(path: str, header: str, lines: Sequence[str]) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(header)
        for line in lines:
            fh.write(line + "\n")


def write_buckets(out_dir: str, buckets: Dict[str, Any]) -> Dict[str, str]:
    """
    سه سبد + `top100.txt` را می‌نویسد و مسیرها را برمی‌گرداند.

    هر فایل سرآیندی دارد که **معیارِ سنجیده** را می‌گوید، نه شعار — تا کاربر
    بداند «امن» یا «سریع» بر چه پایه‌ای ادعا شده.
    """
    st = buckets["stats"]
    rounds = st["rounds"]
    written: Dict[str, str] = {}

    heads = {
        "verified": (
            f"# @Raydikalx — VERIFIED — {st['verified']} configs\n"
            f"# criterion: a real proxied request to {realtest.TEST_URL} succeeded\n"
            f"# in ALL {rounds} independent runs of this round.\n"
            f"# measured: {st['flaky_pct']}% of everything that ever worked is "
            f"flaky, so a single run is not enough.\n"),
        "fast": (
            f"# @Raydikalx — FAST — {st['fast']} configs\n"
            f"# criterion: verified AND median delay across {rounds} runs "
            f"< {st['fast_threshold_ms']}ms.\n"
            f"# the median (not one sample) is used because configs cross this "
            f"line between runs: measured 34.4% of them in a 5-run experiment.\n"
            f"# that share depends on the network the test ran on, so treat it "
            f"as the reason for using a median, not as a constant.\n"),
        "secure": (
            f"# @Raydikalx — SECURE — {st['secure']} configs\n"
            f"# criterion: verified AND forward secrecy — the session key comes\n"
            f"# from an (EC)DHE handshake (TLS/REALITY, or QUIC which mandates\n"
            f"# TLS 1.3 per RFC 9001 §4.2) AND the link does not disable\n"
            f"# certificate validation.\n"
            f"# note: this repo is PUBLIC. A pre-shared-key protocol such as\n"
            f"# shadowsocks is decryptable by anyone who reads the link, so it\n"
            f"# is NOT listed here even though it is encrypted on the wire.\n"),
    }

    for cat in CATEGORIES:
        path = os.path.join(out_dir, cat, "configs.txt")
        _write_lines(path, heads[cat], buckets[cat])
        written[cat] = path
        # ── چرا سه فایلِ دیگر هم لازم است ────────────────────────────────
        # سنجیده شد، حدس نیست: `validate.py` هر دایرکتوریِ دسته را که
        # **وجود داشته باشد** با همان سختیِ دسته‌های اصلی می‌سنجد و
        # `singbox.json`/`clash.yaml`ِ نبوده را `missing` می‌شمارد. با تنها
        # `configs.txt` نتیجه اندازه‌گیری شد: ok=False، missing=2 ⇒ دروازهٔ
        # انتشار با `--strict` کدِ ۱ می‌داد و کلِ انتشار می‌شکست. پس یا باید
        # هر چهار فایل نوشته شود، یا دسته اصلاً ساخته نشود.
        for name, build in (
            ("configs_base64.txt",
             lambda L: core.encode_base64_subscription(L)),
            ("clash.yaml", lambda L: converters.build_clash_yaml(L)),
            ("singbox.json", lambda L: converters.build_singbox_json(L)),
        ):
            try:
                body = build(buckets[cat])
            except Exception as exc:  # noqa: BLE001
                # تبدیل‌کننده‌ها ممکن است روی یک لینکِ خاص بشکنند؛ آن نباید
                # کلِ آبشار را از بین ببرد، ولی **باید دیده شود**.
                print(f"⚠️ {cat}/{name}: {exc}", file=sys.stderr)
                continue
            sub = os.path.join(out_dir, cat, name)
            _write_lines(sub, "", [body.rstrip("\n")])
            written[f"{cat}/{name}"] = sub

    top_path = os.path.join(out_dir, "top100.txt")
    short = st["top_short_by"]
    top_head = (
        f"# @Raydikalx — TOP {len(buckets['top'])} — sorted by median delay\n"
        f"# every entry passed a real proxied request in all {rounds} runs.\n")
    if short:
        # اعلامِ صریح به‌جای پرکردنِ مصنوعی. کاربر باید بداند استخر کوچک بود.
        top_head += (f"# NOTE: only {len(buckets['top'])} configs met the bar "
                     f"this round ({short} short of {TOP_N}). The file is NOT "
                     f"padded with untested configs.\n")
    _write_lines(top_path, top_head, buckets["top"])
    written["top"] = top_path
    return written


def run_pipeline(lines: Iterable[str], out_dir: str,
                 rounds: int = None, fast_ms: int = None,
                 top_n: int = None, **kwargs: Any) -> Dict[str, Any]:
    """آبشارِ کامل: L0/L1 → L2 → L3×n → سبدها → فایل‌ها."""
    l2 = reachability.check_lines(lines)
    open_lines = l2["kept_open"]
    rr = run_l3_round(open_lines, rounds=rounds, **kwargs)
    buckets = build_buckets(rr, fast_ms=fast_ms, top_n=top_n)
    paths = write_buckets(out_dir, buckets)
    buckets["stats"]["l2"] = l2["stats"]
    buckets["paths"] = paths
    return buckets


def _main(argv: Sequence[str]) -> int:
    ap = argparse.ArgumentParser(description="four-layer verification cascade")
    ap.add_argument("input", help="file with one config per line")
    ap.add_argument("--out", default=".", help="output directory")
    ap.add_argument("--rounds", type=int, default=None)
    ap.add_argument("--fast-ms", type=int, default=None)
    ap.add_argument("--top-n", type=int, default=None)
    ap.add_argument("--json", default=None, help="write stats as JSON here")
    args = ap.parse_args(argv)

    with open(args.input, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()

    res = run_pipeline(lines, args.out, rounds=args.rounds,
                       fast_ms=args.fast_ms, top_n=args.top_n)
    st = res["stats"]
    print(f"→ rounds={st['rounds']} per_run_ok={st['per_run_ok']} "
          f"ever_ok={st['ever_ok']} stable={st['stable']} "
          f"flaky={st['flaky_pct']}%")
    print(f"→ verified={st['verified']} fast={st['fast']} "
          f"secure={st['secure']} top={st['top']}")
    if st["top_short_by"]:
        print(f"⚠️ top file is {st['top_short_by']} short of {TOP_N} — "
              f"published unpadded")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(st, fh, ensure_ascii=False, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
