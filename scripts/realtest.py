#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
لایهٔ L3 — آزمونِ *واقعیِ* پروکسی با xray-knife (فاز B، بندِ B4).

جایگاهِ این لایه در آبشار:

    L0  یکتاسازیِ نقطهٔ پایانی    ← filters.py
    L1  پالایشِ ارزانِ بی‌شبکه     ← filters.py
    L2  دست‌دادنِ TCP             ← reachability.py
    L3  آزمونِ واقعیِ پروکسی      ← همین ماژول

L2 فقط می‌گوید «سوکت باز شد». L3 می‌گوید «ترافیک واقعاً از این پروکسی
گذشت و به اینترنت رسید». فاصلهٔ این دو در سرشماریِ واقعی بزرگ است:

    خامِ ورودی            ۸٬۰۲۸ کانفیگ
    پس از L0/L1/L2        ۳٬۸۴۵ کانفیگ  (۴۷٫۹۱٪)
    پس از L3              ۵۰۴ کانفیگ    (۱۳٫۱۱٪ از L2، ۶٫۲۸٪ از خام)

──────────────────────────────────────────────────────────────────────────────
هفت تصمیمِ طراحی، هرکدام پشتِ یک اندازه‌گیریِ زنده — نه پشتِ شهود
──────────────────────────────────────────────────────────────────────────────

۱) `semi-passed` پذیرفته می‌شود، و این اصلاحِ پلنِ خودِ ما است.
   پلنِ اولیه (`PHASE_B_PLAN.md`) گفته بود `semi-passed` باید **رد** شود.
   آن حکم از متنِ راهنما استنباط شده بود، نه از داده. سنجشِ ۵۵ سطرِ
   `semi-passed` در سرشماریِ کاملِ ۳٬۸۴۵ سطری، با **صفر استثنا**:

       success == total  (۵۵ از ۵۵)
       code == 204       (۵۵ از ۵۵)
       endpoints         `...=ok(NNNms)`  ← نقطهٔ پایانی *موفق* بود
       reason            `ip_info_failed` ← تنها همین، هیچ چیزِ دیگر
       ip == "null"      (۵۵ از ۵۵)
       location == "null"(۵۵ از ۵۵)

   و اثباتِ هم‌ارزیِ مجموعه‌ها: مجموعهٔ `semi-passed` **بیت‌به‌بیت** برابرِ
   مجموعهٔ سطرهای موفق با `location == "null"` است (۵۵ == ۵۵، اختلافِ
   دوسویه = ۰). در مقابل، ۴۴۹ سطرِ `passed` **صفر** موردِ `ip == "null"`
   دارند. یعنی `semi-passed` هیچ ربطی به «شکستِ نیمهٔ پروکسی» ندارد؛
   یعنی «پروکسی کامل کار کرد، ولی جست‌وجویِ *اختیاریِ* اطلاعاتِ IP
   (`--rip`) شکست خورد». ردکردنش ۵۵ کانفیگِ سالم (۱۰٫۹٪ از خروجیِ نهایی)
   را خاموشانه دور می‌ریخت.

۲) `success == total` به‌تنهایی **کافی نیست** — یک سوراخِ واقعی.
   سطرهای `broken` مقدارِ `success=0, total=0` دارند، پس شرطِ
   `success == total` برای آن‌ها هم **درست** است (۰ == ۰). سنجش:

       passed       ۴۴۹ سطر  → success==total: ۴۴۹  (همه)
       semi-passed   ۵۵ سطر  → success==total:  ۵۵  (همه)
       failed     ۳٬۲۵۴ سطر  → success==total:   ۰
       broken        ۸۷ سطر  → success==total:  ۸۷  (همه!)  ← سوراخ

   قفلِ درست، که روی سرشماری آزموده شد و مجموعهٔ موفق را **دقیقاً**
   بازتولید کرد (۵۰۴ در هر دو سو، اختلافِ دوسویه = ۰):

       total >= 1  و  success == total  و  200 <= code < 400

۳) دو مسیرِ **قفل‌شدنِ کاملِ CI** — کشف‌شده و بسته‌شده.
   با ورودیِ **ناموجود** یا **تهی**، ابزار خطا چاپ می‌کند و سپس روی
   ورودیِ استاندارد **منتظر می‌ماند** («Please enter a config link»).
   بازتولید زیرِ شرطِ واقعیِ CI (stdin یک FIFO که بسته نمی‌شود):

       فایلِ تهی    + stdin باز        → rc=124  (قفل)
       فایلِ ناموجود + stdin باز        → rc=124  (قفل)
       فایلِ تهی    + `</dev/null`     → rc=1    (شکستِ پاک)
       فایلِ فقط‌فاصله + stdin باز       → rc=0    (بی‌خطر، CSV سرآیندی)

   در CI ورودیِ استاندارد هرگز بسته نمی‌شود، پس job تا سقفِ ۶ ساعتِ
   GitHub می‌سوزد و `concurrency: group: aggregate` هر اجرایِ بعدی را
   هم در صف نگه می‌دارد. حالتِ «فایلِ تهی» حالتِ واقع‌بینانه است: هر بار
   که L2 صفر نقطهٔ بازِ باقی بگذارد همین رخ می‌دهد.
   سه لایهٔ دفاع: (الف) بررسیِ وجود *و* ناتهی‌بودن پیش از فراخوانی،
   (ب) `stdin=DEVNULL`، (ج) مهلتِ سختِ پایتونی.

۴) خروجیِ کهنه **زنده می‌ماند** — و این خطرناک‌ترین موردِ سنجیده‌شده است.
   سنجش: یک CSV با سطرِ `STALE_MARKER,passed` ساختیم، سپس اجرایِ
   شکست‌خورده (فایلِ تهی) را با همان `-o` صدا زدیم. نتیجه: `rc=1` و
   **`STALE_MARKER` دست‌نخورده باقی ماند**. اگر پس از یک اجرای ناموفق
   خروجی خوانده شود، داده‌های *دفعهٔ قبل* به‌عنوانِ نتیجهٔ تازه خوانده
   می‌شوند. پس خروجی **پیش از** هر اجرا حذف می‌شود.

۵) `-o` پوشهٔ والد را نمی‌سازد، و در این حالت **دروغ می‌گوید**.
   سنجش با `-o .../nodir/deep/s3.csv`:

       rc = 0
       پیام: «🎉 Results have been saved to /.../nodir/deep/s3.csv»
       واقعیت: فایل **وجود ندارد**

   یعنی نبودِ پوشهٔ والد = ازدست‌رفتنِ کاملِ داده، با کدِ خروجِ ۰ و پیامِ
   موفقیت. پس والد خودمان ساخته می‌شود *و* وجودِ فایل پس از اجرا
   تأیید می‌شود (`OutputNotWritten`).

۶) کدِ خروج هرگز کیفیتِ نتیجه را نشان نمی‌دهد.
   سنجش: ورودیِ تک‌لینکیِ کاملاً مرده → `rc=0`. پس `rc` فقط «ابزار
   اجرا شد» را می‌گوید. داوریِ کیفیت تنها از CSV می‌آید.

۷) CSV باید با ماژولِ `csv` خوانده شود، نه با `split(",")`.
   سنجش روی سرشماریِ ۳٬۸۴۵ سطری: **۲۳۶ سطر** با `split(",")` تعدادِ
   ستونِ اشتباه می‌دادند (۳٬۳۲۱ سطر نویسهٔ گیومه دارند و ۱۸۲ لینک خودشان
   کاما دارند). یعنی تفکیکِ ساده حدودِ ۶٪ داده را خاموشانه خراب می‌کرد.

──────────────────────────────────────────────────────────────────────────────
چرا `--retries` و `--max-passed` استفاده نمی‌شوند؟
──────────────────────────────────────────────────────────────────────────────

`--retries` نااستواری را *داخلِ* یک اجرا پنهان می‌کند. نااستواریِ سنجیده‌شده
۳۲٫۷٪ اتحاد است (۱۷ از ۵۲ لینک در ۳ اجرا). اگر ابزار خودش تلاشِ دوباره کند،
دیگر نمی‌توان «پایدار» را از «خوش‌شانس» جدا کرد؛ و جداکردنِ همین دو کارِ
بندِ B4b است. پس چندبار‌اجرا در لایهٔ بالاتر انجام می‌شود، نه با این پرچم.

`--max-passed` خروجیِ **ناقص** می‌دهد: با `--max-passed 2 -t 5` پنج سطر
برگشت (۲ موفق + ۳ نیمه‌کارهٔ شکست‌خورده). یعنی نبودِ یک لینک در CSV را
هرگز نمی‌توان «شکست خورد» خواند. هر دو پرچم برای استفادهٔ دستی پشتیبانی
می‌شوند، ولی نتیجه با `partial=True` علامت می‌خورد.

خروجیِ `run_test` قراردادِ ورودیِ بندهای B5/B6/B7/B13 است:

    {ok: [...], failed: [...], broken: [...],
     rows: {link: row}, stats: {...}, partial: bool}
"""
from __future__ import annotations

import csv
import io
import os
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ──────────────────────────────────────────────────────────────────────────────
# پارامترها — همه از سنجش آمده‌اند و همه با محیط قابلِ تنظیم‌اند
# ──────────────────────────────────────────────────────────────────────────────

#: مسیرِ باینری. نصبش در CI با نسخهٔ سنجیده و دو checksum انجام می‌شود (بندِ B3).
XK_BIN = os.environ.get("L3_XK_BIN", "xray-knife")

#: نشانیِ آزمون. **صریح** است و به پیش‌فرضِ ابزار تکیه نمی‌کند: پیش‌فرضِ
#: v10.1.1 یعنی `https://cloudflare.com/cdn-cgi/trace` که HTTP 200 می‌دهد،
#: ولی اجراهای مرجعِ ما HTTP 204 ثبت کرده‌اند. بی‌تثبیتِ این نشانی نتایجِ
#: دو اجرا با هم قابلِ مقایسه نیستند.
TEST_URL = os.environ.get("L3_TEST_URL", "https://cp.cloudflare.com/generate_204")

#: رشته‌های آزمون. سنجشِ زنده روی همان ۳٬۸۴۵ کانفیگ: t=50 ← ۱۶۹ ثانیه،
#: t=150 ← ۶۱ ثانیه، t=200 ← **۴۳ ثانیه**، t=300 ← بی‌بهبودِ معنادار.
THREADS = int(os.environ.get("L3_THREADS", "200"))

#: بیشترین تأخیرِ پذیرفتنی (میلی‌ثانیه) — همان پیش‌فرضِ ابزار، صریح‌شده.
MDELAY_MS = int(os.environ.get("L3_MDELAY", "5000"))

#: مهلتِ هر درخواست (میلی‌ثانیه). پیش‌فرضِ ابزار ۰ (بی‌مهلت) است که در CI
#: خطرناک است، پس صریحاً بسته می‌شود.
TIMEOUT_MS = int(os.environ.get("L3_TIMEOUT", "5000"))

#: تورِ آخر. سرشماریِ کامل ۴۳ ثانیه بود؛ ۱۸۰۰ ثانیه ۴۲ برابرِ حاشیه دارد و
#: هم‌زمان خیلی کمتر از سقفِ ۶ ساعتِ GitHub است.
HARD_TIMEOUT = int(os.environ.get("L3_HARD_TIMEOUT", "1800"))

STATUS_PASSED = "passed"
STATUS_SEMI = "semi-passed"
STATUS_FAILED = "failed"
STATUS_BROKEN = "broken"

#: سطرهایی که «پروکسی کار کرد» را نشان می‌دهند. `semi-passed` عمداً این‌جاست
#: (بندِ ۱ سند). هر عضو باز هم از قفلِ عددیِ `is_row_genuinely_ok` می‌گذرد.
OK_STATUSES = (STATUS_PASSED, STATUS_SEMI)

#: هر چهار وضعیتِ سنجیده‌شده. تقسیمِ failed/broken معنادار است:
#: `failed` = پروکسی ساخته شد ولی درخواست رد شد (سرورِ مرده — طبیعی و گذرا).
#: `broken` = پروکسی هرگز ساخته نشد (دادهٔ بد — در سرچشمه قابلِ تعمیر).
ALL_STATUSES = (STATUS_PASSED, STATUS_SEMI, STATUS_FAILED, STATUS_BROKEN)

#: قراردادِ ستون‌ها. اگر بالادست شِما را عوض کند، باید **بلند** بشکند، نه
#: این‌که خاموشانه ستونِ اشتباه خوانده شود.
CSV_COLUMNS = (
    "link", "status", "reason", "tls", "ip", "delay", "code", "download",
    "upload", "location", "ttfb", "connect_time", "success", "total",
    "endpoints",
)

#: ابزار «نبودِ مقدار» را رشتهٔ تحت‌اللفظیِ `null` می‌نویسد، نه فیلدِ تهی.
#: سنجش: ستونِ `ip` در ۳٬۳۹۶ سطر دقیقاً `"null"` است و در **صفر** سطر تهی.
NULL_TOKEN = "null"

#: بازهٔ کدِ موفق. سنجش: تنها دو مقدار در سرشماری دیده شد — ۲۰۴ (۵۰۴ سطر،
#: همه موفق) و ‎-۱ (۳٬۳۴۱ سطر، همه ناموفق).
CODE_MIN_OK = 200
CODE_MAX_OK = 400


class XrayKnifeMissing(RuntimeError):
    """باینریِ xray-knife پیدا نشد — این خطای محیط است، نه خطای داده."""


class XrayKnifeFailed(RuntimeError):
    """ابزار اجرا شد ولی به‌درستی تمام نشد (کدِ خروجِ ناصفر یا مهلتِ سخت)."""


class EmptyInput(ValueError):
    """
    ورودی تهی یا ناموجود است.

    چرا استثنا و نه «صفر نتیجه»؟ چون سنجشِ زنده نشان داد همین دو حالت
    باعثِ **قفل‌شدنِ** ابزار روی ورودیِ استاندارد می‌شوند (rc=124 زیرِ
    stdin بازِ CI). این استثنا آن مسیر را پیش از فراخوانی می‌بندد.
    """


class OutputNotWritten(RuntimeError):
    """
    ابزار «ذخیره شد» گفت ولی فایل وجود ندارد.

    سنجش: با `-o` به پوشهٔ ناموجود، `rc=0` و پیامِ
    «🎉 Results have been saved to ...» آمد و فایل **ساخته نشد**. بی این
    بررسی، ازدست‌رفتنِ کاملِ داده به‌شکلِ «صفر کانفیگِ سالم» ظاهر می‌شود.
    """


class MalformedCsv(ValueError):
    """CSV با قراردادِ ۱۵ستونی نمی‌خواند — بالادست شِما را عوض کرده است."""


# ──────────────────────────────────────────────────────────────────────────────
# داوری روی یک سطر
# ──────────────────────────────────────────────────────────────────────────────

def _as_int(value: Optional[str]) -> Optional[int]:
    """عددِ صحیح، یا None اگر مقدار عدد نباشد (شاملِ `null` و تهی)."""
    if value is None:
        return None
    text = value.strip()
    if not text or text == NULL_TOKEN:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def is_row_genuinely_ok(row: Dict[str, str]) -> bool:
    """
    آیا این سطر یعنی «پروکسی واقعاً کار کرد»؟

    قفل چهار شرط دارد و هر چهار لازم‌اند:

        ۱) status ∈ OK_STATUSES        — شاملِ `semi-passed` (بندِ ۱ سند)
        ۲) total >= 1                  — سطرِ `broken` مقدارِ total=0 دارد
        ۳) success == total            — همهٔ نقاطِ پایانی موفق بوده‌اند
        ۴) 200 <= code < 400           — پاسخِ HTTP واقعاً موفق بوده

    شرطِ ۲ تنها به لطفِ سنجش این‌جاست: بی آن، `success == total` برای
    ۸۷ سطرِ `broken` هم درست بود (۰ == ۰) و آن‌ها را «موفق» می‌شمردیم.

    اعتبارسنجی روی سرشماریِ کاملِ ۳٬۸۴۵ سطری: این قفل دقیقاً ۵۰۴ سطر
    را می‌پذیرد و مجموعه‌اش با مجموعهٔ `status ∈ OK_STATUSES` **یکی**
    است (اختلافِ دوسویه = ۰) — یعنی نه سخت‌گیرتر است و نه سست‌تر، بلکه
    همان داوری را از دو راهِ مستقل تأیید می‌کند.
    """
    if (row.get("status") or "").strip() not in OK_STATUSES:
        return False
    total = _as_int(row.get("total"))
    success = _as_int(row.get("success"))
    code = _as_int(row.get("code"))
    if total is None or success is None or code is None:
        return False
    if total < 1 or success != total:
        return False
    return CODE_MIN_OK <= code < CODE_MAX_OK


def row_delay_ms(row: Dict[str, str]) -> Optional[int]:
    """تأخیر به میلی‌ثانیه، یا None. سنجش: بازهٔ سطرهای موفق ۵۴ تا ۴٬۷۷۶."""
    delay = _as_int(row.get("delay"))
    if delay is None or delay < 0:
        return None
    return delay


def row_location(row: Dict[str, str]) -> Optional[str]:
    """کدِ کشورِ گزارش‌شدهٔ ابزار، یا None اگر `null`/تهی باشد."""
    loc = (row.get("location") or "").strip()
    if not loc or loc == NULL_TOKEN:
        return None
    return loc


def row_tls(row: Dict[str, str]) -> str:
    """
    لایهٔ امنیت، خام. سنجشِ مقادیرِ دیده‌شده در سرشماری:
    `tls` ۲٬۰۳۲ · تهی ۸۲۸ · `none` ۵۶۵ · `reality` ۴۱۴ · `false` ۴ ·
    `…` ۱ · `auto` ۱. داوریِ «امن» کارِ بندِ B7 است، نه این‌جا.
    """
    return (row.get("tls") or "").strip()


# ──────────────────────────────────────────────────────────────────────────────
# خواندنِ CSV
# ──────────────────────────────────────────────────────────────────────────────

def parse_csv(text: str) -> List[Dict[str, str]]:
    """
    CSV ابزار را به سطرهای دیکشنری تبدیل می‌کند.

    عمداً از ماژولِ `csv` استفاده می‌شود، نه `split(",")`: سنجش روی
    سرشماریِ ۳٬۸۴۵ سطری نشان داد **۲۳۶ سطر** با تفکیکِ سادهٔ کاما تعدادِ
    ستونِ اشتباه می‌دهند، چون ۱۸۲ لینک خودشان کاما دارند و ۳٬۳۲۱ سطر
    گیومه‌گذاری‌شده‌اند.

    اگر سرآیند با `CSV_COLUMNS` نخواند، `MalformedCsv` پرتاب می‌شود —
    نه بازگشتِ خاموشِ فهرستِ تهی. بالادست ممکن است روزی ستونی اضافه کند و
    آن روز باید **بلند** بشکنیم.
    """
    if not text.strip():
        return []
    reader = csv.DictReader(io.StringIO(text))
    header = tuple(reader.fieldnames or ())
    if header != CSV_COLUMNS:
        raise MalformedCsv(
            f"the CSV header does not match the measured 15-column contract.\n"
            f"  expected: {CSV_COLUMNS}\n"
            f"  actual  : {header}\n"
            f"An upstream schema change must break loudly; reading the wrong "
            f"column silently would mis-grade every config."
        )
    rows: List[Dict[str, str]] = []
    for raw in reader:
        if raw.get(None) is not None:
            raise MalformedCsv(
                f"a CSV row carries more fields than the 15-column contract: "
                f"{raw.get(None)!r}"
            )
        if any(value is None for value in raw.values()):
            raise MalformedCsv(
                f"a CSV row is short of the 15-column contract: {raw!r}"
            )
        rows.append({key: (value or "") for key, value in raw.items()})
    return rows


def classify(rows: Sequence[Dict[str, str]]) -> Dict[str, Any]:
    """
    سطرها را به سه سبد می‌ریزد و آمار می‌سازد.

    تقسیمِ `failed` از `broken` عمدی است: `broken` یعنی کانفیگ هرگز ساخته
    نشد (دادهٔ بد — در سرچشمه قابلِ تعمیر)، `failed` یعنی سرور جواب نداد
    (طبیعی و گذرا). یک‌جا شمردنشان کیفیتِ سرچشمه‌ها را پنهان می‌کند.
    """
    ok: List[str] = []
    failed: List[str] = []
    broken: List[str] = []
    by_status: Dict[str, int] = {name: 0 for name in ALL_STATUSES}
    unknown_status: Dict[str, int] = {}
    by_link: Dict[str, Dict[str, str]] = {}

    for row in rows:
        link = row.get("link") or ""
        by_link[link] = row
        status = (row.get("status") or "").strip()
        if status in by_status:
            by_status[status] += 1
        else:
            unknown_status[status] = unknown_status.get(status, 0) + 1
        if is_row_genuinely_ok(row):
            ok.append(link)
        elif status == STATUS_BROKEN:
            broken.append(link)
        else:
            failed.append(link)

    delays = [row_delay_ms(by_link[link]) for link in ok]
    delays = sorted(d for d in delays if d is not None)
    stats: Dict[str, Any] = {
        "rows": len(rows),
        "ok": len(ok),
        "failed": len(failed),
        "broken": len(broken),
        "ok_pct": round(100.0 * len(ok) / len(rows), 2) if rows else 0.0,
        "by_status": by_status,
        "with_location": sum(1 for link in ok if row_location(by_link[link])),
        "delay_min": delays[0] if delays else None,
        "delay_median": delays[len(delays) // 2] if delays else None,
        "delay_max": delays[-1] if delays else None,
    }
    if unknown_status:
        # وضعیتِ ناشناخته خطا نیست، ولی باید دیده شود: سنجشِ ما فقط چهار
        # مقدار را ثبت کرده و پنجمی یعنی بالادست چیزی را عوض کرده است.
        stats["unknown_status"] = unknown_status
    return {"ok": ok, "failed": failed, "broken": broken,
            "rows": by_link, "stats": stats}


# ──────────────────────────────────────────────────────────────────────────────
# اجرا
# ──────────────────────────────────────────────────────────────────────────────

def resolve_binary(binary: Optional[str] = None) -> str:
    """مسیرِ اجراییِ ابزار، یا `XrayKnifeMissing`."""
    name = binary or XK_BIN
    if os.path.sep in name:
        if os.path.isfile(name) and os.access(name, os.X_OK):
            return os.path.abspath(name)
        raise XrayKnifeMissing(
            f"xray-knife is not an executable file at {name!r}")
    found = shutil.which(name)
    if not found:
        raise XrayKnifeMissing(
            f"xray-knife ({name!r}) is not on PATH. CI installs it pinned to "
            f"a checksum-verified release; locally, put the binary on PATH or "
            f"set L3_XK_BIN.")
    return found


def _non_blank_count(path: str) -> int:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return sum(1 for line in handle if line.strip())


def build_argv(in_path: str, out_path: str, *,
               binary: str,
               test_url: str = None,
               threads: int = None,
               mdelay_ms: int = None,
               timeout_ms: int = None,
               max_passed: int = 0,
               retries: int = 0) -> List[str]:
    """
    خطِ فرمانِ کامل. هیچ پرچمی به پیش‌فرض واگذار نمی‌شود مگر آن‌که
    پیش‌فرضش سنجیده و پذیرفته شده باشد.

    `--rip` عمداً دست‌کاری نمی‌شود: پیش‌فرضش `true` است و سنجشِ A/B نشان
    داد با `--rip=false` ستونِ `location` در **صفر** سطر پر می‌شود، که
    بندِ B6b (کشور از xray-knife) را ناممکن می‌کند.
    """
    argv = [
        binary, "http",
        "-f", in_path,
        "-x", "csv",
        "-o", out_path,
        "-t", str(int(threads if threads is not None else THREADS)),
        "-d", str(int(mdelay_ms if mdelay_ms is not None else MDELAY_MS)),
        "--timeout", str(int(timeout_ms if timeout_ms is not None
                             else TIMEOUT_MS)),
        "-u", test_url if test_url is not None else TEST_URL,
    ]
    if max_passed:
        argv += ["--max-passed", str(int(max_passed))]
    if retries:
        argv += ["--retries", str(int(retries))]
    return argv


def run_test(in_path: str, *,
             out_path: str = None,
             binary: str = None,
             test_url: str = None,
             threads: int = None,
             mdelay_ms: int = None,
             timeout_ms: int = None,
             max_passed: int = 0,
             retries: int = 0,
             hard_timeout: int = None) -> Dict[str, Any]:
    """
    L3 را روی یک فایلِ ورودی اجرا می‌کند و نتیجهٔ داوری‌شده را برمی‌گرداند.

    ترتیبِ گام‌ها هرکدام پشتِ یک سنجشِ زنده است:

      ۱) ورودی باید باشد *و* سطرِ ناتهی داشته باشد → EmptyInput
         (بی این گام: rc=124، قفل تا سقفِ ۶ ساعتِ GitHub)
      ۲) باینری حل می‌شود                        → XrayKnifeMissing
      ۳) پوشهٔ والدِ خروجی ساخته می‌شود
         (بی این گام: rc=0 با پیامِ موفقیت و **بی هیچ فایلی**)
      ۴) خروجیِ کهنه حذف می‌شود
         (بی این گام: دادهٔ اجرایِ قبلی «نتیجهٔ تازه» خوانده می‌شود)
      ۵) اجرا با `stdin=DEVNULL` و مهلتِ سختِ پایتونی
      ۶) وجودِ فایلِ خروجی تأیید می‌شود          → OutputNotWritten
      ۷) CSV با ماژولِ `csv` خوانده و داوری می‌شود

    کلیدِ `partial` یعنی «تعدادِ سطرها از تعدادِ لینک‌های یکتایِ ورودی کمتر
    است». هرگز نباید نبودِ یک لینک را «شکست خورد» خواند: سنجشِ
    `--max-passed 2 -t 5` پنج سطر داد (۲ موفق + ۳ نیمه‌کاره)، و خودِ ابزار
    هم تکراری‌ها را حذف می‌کند («Removed 2 duplicate config link(s)»).
    """
    # ترتیب مهم است: بررسیِ ورودی **پیش از** یافتنِ باینری می‌آید. بررسیِ
    # ورودی رایگان است و مسیرِ قفل‌شدن را می‌بندد؛ اگر جای این دو عوض شود،
    # روی ماشینی که ابزار را ندارد قفلِ ضدِ‌hang هرگز آزموده نمی‌شود — و
    # همین ترتیبِ اشتباه در نسخهٔ اولِ این تابع بود و آزمونِ واحد گرفتش.
    if not os.path.isfile(in_path):
        raise EmptyInput(
            f"input file does not exist: {in_path!r}. Measured: xray-knife "
            f"then falls back to reading stdin and blocks forever (rc=124 "
            f"under CI's open stdin).")
    n_lines = _non_blank_count(in_path)
    if n_lines == 0:
        raise EmptyInput(
            f"input file has no non-blank line: {in_path!r}. Measured: an "
            f"empty file makes xray-knife wait on stdin (rc=124 under CI's "
            f"open stdin). This is exactly what happens when L2 leaves zero "
            f"open endpoints, so it must be handled, not hoped away.")

    resolved = resolve_binary(binary)

    # مالکیتِ فایلِ خروجی (F-3)
    # ─────────────────────────
    # اگر فراخوان مسیر داده باشد، فایل **مالِ اوست** و ما حق نداریم پاکش
    # کنیم؛ اگر ما خودمان با `mkstemp` ساختیم، مالِ ماست و باید در هر مسیرِ
    # خروج — موفق یا استثنا — پاکش کنیم. تفکیکِ این دو حالت با همین پرچم
    # انجام می‌شود، نه با حدس‌زدن از رویِ نامِ فایل.
    #
    # اندازه‌گیریِ نشت (پیش از درمان، با باینریِ شبیه‌سازِ xray-knife):
    #   • هر `test_lines`/`run_test` بی‌`out_path`  → ۱ فایلِ `l3_*.csv` جا می‌ماند
    #   • `pipeline.run_l3_round` با L3_ROUNDS=3   → ۳ فایل در هر دور
    #   • مسیرهای استثنا هم نشت داشتند: rc≠۰ و CSVِ بدشکل هرکدام ۱ فایل
    #     (مسیرهای «فایل نوشته نشد» و «مهلت» و «باینریِ غایب» و «ورودیِ تهی»
    #      طبعاً چیزی جا نمی‌گذاشتند، ولی حالا همه یکسان پوشش دارند)
    # چون هر اجرایِ CI یک دورِ L3 دارد، این نشت خاموش و انباشتی بود.
    owned = out_path is None
    if owned:
        handle, out_path = tempfile.mkstemp(prefix="l3_", suffix=".csv")
        os.close(handle)
    parent = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(parent, exist_ok=True)
    if os.path.exists(out_path):
        os.remove(out_path)

    try:
        argv = build_argv(in_path, out_path, binary=resolved,
                          test_url=test_url, threads=threads,
                          mdelay_ms=mdelay_ms, timeout_ms=timeout_ms,
                          max_passed=max_passed, retries=retries)
        limit = int(hard_timeout if hard_timeout is not None else HARD_TIMEOUT)

        started = time.time()
        try:
            proc = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,   # لایهٔ دومِ دفاع در برابرِ قفل
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=limit,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise XrayKnifeFailed(
                f"xray-knife did not finish within {limit}s. The measured full "
                f"census of 3,845 configs took 43s, so this is not slowness — "
                f"it is a stuck run."
            ) from exc
        elapsed = round(time.time() - started, 2)
        output = (proc.stdout or b"").decode("utf-8", errors="replace")

        if proc.returncode != 0:
            raise XrayKnifeFailed(
                f"xray-knife exited {proc.returncode}.\n"
                f"--- last output ---\n{output[-2000:]}")

        if not os.path.isfile(out_path):
            raise OutputNotWritten(
                f"xray-knife exited 0 but wrote no file at {out_path!r}. "
                f"Measured: with a missing parent directory it prints 'Results "
                f"have been saved to ...' and creates nothing.\n"
                f"--- last output ---\n{output[-2000:]}")

        with open(out_path, encoding="utf-8", errors="replace") as handle:
            result = classify(parse_csv(handle.read()))

        unique_in = _unique_links(in_path)
        result["partial"] = len(result["rows"]) < len(unique_in)
        result["stats"]["elapsed_sec"] = elapsed
        result["stats"]["lines_in"] = n_lines
        result["stats"]["unique_in"] = len(unique_in)
        result["stats"]["test_url"] = (
            test_url if test_url is not None else TEST_URL)
        result["stats"]["threads"] = int(
            threads if threads is not None else THREADS)
        # `out_path` هم‌چنان گزارش می‌شود تا قرارداد نشکند، ولی اگر مالِ ما
        # بوده باشد دیگر روی دیسک نیست. هیچ مصرف‌کننده‌ای در پروژه این کلید
        # را نمی‌خواند (شمرده شد: ۰ مورد بیرونِ همین ماژول)، پس حذفِ فایل
        # چیزی را نمی‌شکند؛ نگه‌داشتنِ کلید فقط برای سازگاری است.
        result["out_path"] = out_path
        return result
    finally:
        # `finally` عمداً بیرونِ همهٔ شاخه‌هاست: هر استثنایی هم که رد شود،
        # فایلِ موقتِ خودمان می‌رود. `try/except OSError` لازم است چون پاک‌سازی
        # هرگز نباید علتِ اصلیِ خطا را بپوشاند.
        if owned:
            try:
                os.remove(out_path)
            except OSError:
                pass


def _unique_links(path: str) -> List[str]:
    seen: Dict[str, None] = {}
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            text = line.strip()
            if text:
                seen.setdefault(text, None)
    return list(seen)


def test_lines(lines: Iterable[str], **kwargs: Any) -> Dict[str, Any]:
    """L3 روی سطرهای در حافظه. ورودی به یک فایلِ موقت نوشته می‌شود."""
    handle, path = tempfile.mkstemp(prefix="l3_in_", suffix=".txt")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            for line in lines:
                text = line.strip()
                if text:
                    out.write(text + "\n")
        return run_test(path, **kwargs)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def test_file(path: str, **kwargs: Any) -> Dict[str, Any]:
    return run_test(path, **kwargs)


def _main(argv: Sequence[str]) -> int:
    import json
    if len(argv) < 2:
        print(f"usage: {os.path.basename(argv[0])} <configs.txt> [out.csv]",
              file=sys.stderr)
        return 64
    in_path = argv[1]
    out_path = argv[2] if len(argv) > 2 else None

    try:
        result = test_file(in_path, out_path=out_path)
    except (XrayKnifeMissing, EmptyInput) as exc:
        print(f"!! {exc}", file=sys.stderr)
        return 2
    except (XrayKnifeFailed, OutputNotWritten, MalformedCsv) as exc:
        print(f"!! {exc}", file=sys.stderr)
        return 3

    payload = {"stats": result["stats"], "partial": result["partial"]}
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
