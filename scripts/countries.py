#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تفکیکِ کانفیگ‌های **تأییدشده** بر پایهٔ کشور → `Countries/<Name>.txt`.

این ماژول یک لایهٔ آزمونِ تازه نیست و هیچ چیزی را از نو نمی‌سنجد؛ تنها
خروجیِ *همین‌حالا سنجیده‌شدهٔ* آبشار را بر پایهٔ برچسبی که `aggregate.py`
پیش‌تر نوشته است، به فایل‌های کشوری تقسیم می‌کند.

چهار تصمیمِ **سنجیده** که این فایل را شکل می‌دهند:

۱) منبع: `buckets["verified"]` — نه `all/`.
   «تأییدشده» یعنی کانفیگ در **همهٔ** اجراهای L3 یک درخواستِ واقعیِ
   پروکسی‌شده را رد کرد. سنجشِ اجراشده روی دادهٔ زندهٔ همین مخزن:
       all/       ۸۵۶۵ کانفیگ · ۷۳ برچسب · ۱٫۹۱ MiB · شاملِ «Global»
       verified/  ۱۲۴۶ کانفیگ · ۵۰ کشور · ۰٫۲۹ MiB · **صفر** «Global»
   آن «صفر Global» تصادفی نیست: کانفیگی که واقعاً وصل شده، نشانیِ
   شبکه‌ایِ قابلِ مکان‌یابی دارد، پس هرگز به شاخهٔ «کشورِ نامعلوم»
   نمی‌افتد. نتیجه: پرسشِ «با Global.txt چه کنیم؟» در این منبع
   **موضوعیت ندارد** و هیچ فایلِ زائدی ساخته نمی‌شود.

۲) مکان از **برچسبِ خودِ سطر** خوانده می‌شود، نه از شبکه.
   `aggregate.py` (که پیش از `pipeline.py` اجرا می‌شود — گامِ ۴۴۴ در
   برابرِ ۶۵۴ ورک‌فلو) هر سطر را با `core.country_for_endpoint` برچسب
   زده و نتیجه را در remark نوشته: `DE 🇩🇪 | @Raydikalx | tag`.
   خواندنِ همان برچسب سه چیز را تضمین می‌کند:
     · **صفر** پرس‌وجویِ DNS و صفر ثانیه هزینهٔ شبکه در این گام؛
     · سازگاریِ کاملِ نام‌گذاری با `all/` و بقیهٔ خروجی‌ها — اگر مکان
       را از نو می‌سنجیدیم، هر جابه‌جاییِ DNS بینِ دو گام می‌توانست
       کانفیگی را در `all/` آلمان و در `Countries/` فرانسه نشان دهد؛
     · تعیّن (determinism): دو اجرا روی یک ورودی، یک خروجی.
   سنجش روی ۲۰٬۷۵۵ سطرِ زندهٔ هر هفت فایلِ خروجی: **صفر** سطرِ
   تجزیه‌نشده. روی ۱۲۴۶ سطرِ `verified/`: ۱۲۴۶/۱۲۴۶ کدِ کشور.

۳) نامِ کشور از **خودِ پایگاه‌دادهٔ GeoIP** می‌آید، نه از جدولِ دستی.
   دلیل: جدولِ دستی هزینهٔ نگه‌داری دارد و در همین مخزن سابقهٔ خرابی
   دارد. سنجش روی هر ۱٬۳۷۲٬۲۴۸ شبکهٔ پایگاه‌داده: ۲۵۱ کدِ ISO،
   **صفر** تضادِ نام، **صفر** کدِ بی‌نامِ انگلیسی.
   راهِ رسیدن به نام، «اسکنِ کاملِ پایگاه‌داده» **نیست** (سنجیده شد:
   ۱۱٫۱۹s — برای خطِ لوله‌ای که روزی ۹۶ بار اجرا می‌شود پذیرفتنی
   نیست). به‌جایش: برای هر گروه، یک **IP صریحِ همان گروه** را در
   پایگاه‌داده می‌جوییم؛ آن IP به تعریف در همان کشور است، پس
   `country.names.en` رکوردش نامِ معتبر است. سنجش: ۰٫۰۰۱s.
   ⚠️ **گاردِ حیاتی** (با سنجش کشف شد، نه با حدس): تنها وقتی نام را
   می‌پذیریم که `iso_code`ِ رکورد **برابرِ همان کد** باشد. بی این
   گارد، دادهٔ زنده ۴ نامِ غلط می‌داد (`AE`→«United States»،
   `IR`→«Poland»، `PT`→«France»، `SC`→«Netherlands») — چون برچسب با
   پایگاه‌دادهٔ ماهِ قبلِ کش‌شدهٔ CI نوشته شده و نشانی در نسخهٔ تازه
   جابه‌جا شده است. با گارد: ۴۶/۵۰ در ۰٫۰۰۱s، و ۴ موردِ باقی‌مانده با
   اسکنِ **زودخروج** در ۰٫۰۹۳s ⇒ جمعاً ۵۰/۵۰ با **صفر** اختلاف با
   نامِ درستِ پایگاه‌داده.
   اسکنِ زودخروج بودجهٔ زمانی دارد: بدترین حالتِ سنجیده‌شده برای کدی
   که در پایگاه‌داده **نیست** ۱۰٫۷۰s و ۱٬۳۷۲٬۲۴۸ گام بود؛ سقفِ
   ۲ ثانیه‌ای سنجیده شد و واقعاً عمل می‌کند (۲٫۰۲s / ۲۸۰٬۰۰۰ گام).

۴) ★ **جاروی پیش از نوشتن** (`_sweep`) — بی این، قابلیت **معیوب** است.
   ماشینِ انتشارِ ورک‌فلو درخت را از ANCHOR می‌سازد و بعد `git add -A`
   می‌زند، و `actions/checkout` فایل‌های دورِ قبل را روی دیسک برگردانده
   است. پس هر فایلی که این دور نوشته نشود، **تا ابد** بازمنتشر می‌شود.
   این با استدلال ثابت نشده — با یک مخزنِ gitِ واقعی شبیه‌سازی شد و
   منطقِ ورک‌فلو مو‌به‌مو تکرار شد؛ نتیجه:
       بی جارو → درختِ منتشرشده `Countries/Kenya.txt` را داشت، در حالی
                 که تولیدکننده دیگر آن را نمی‌نوشت.
       با جارو → تنها `Countries/Germany.txt`، و فایل‌های منبع دست‌نخورده.
   و این خطر **واقعی** است نه نظری: سنجشِ چرخشِ مجموعهٔ کشورها نشان
   داد ۲۳ کد در `all/` هستند که در `verified/` نیستند ⇒ مجموعهٔ
   کشورها بینِ دورها **تغییر می‌کند**.
   جارو از الگویِ جاافتادهٔ همین مخزن پیروی می‌کند
   (`aggregate._remove_if_exists`): «حذف» بهتر از «نوشتنِ فایلِ خالی»
   است، چون پاسخِ ۲۰۰ با بدنهٔ خالی باعث می‌شود کلاینتِ اشتراک لیستش
   را با «هیچ» جانشین کند، ولی ۴۰۴ باعث می‌شود لیستِ قبلی را نگه دارد.

نکتهٔ ایمنی: این ماژول هرگز نباید خطِ لولهٔ اصلی را زمین بزند. هر
استثنا در `write_countries` گرفته و به هشدار تبدیل می‌شود (همان سیاستِ
`merge_index`/`merge_health`)، چون `Countries/` یک قابلیتِ **افزوده**
است و شکستنِ انتشارِ ۸۵۰۰ کانفیگ به‌خاطرِ آن، معامله‌ای زیان‌ده است.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import core  # noqa: E402
import geo  # noqa: E402

# ──────────────────────────────────────────────────────────────────────────────
# خواندنِ ایمنِ متغیرهای محیطی
# ──────────────────────────────────────────────────────────────────────────────
#
# چرا این دو کمکی لازم‌اند: مقادیرِ زیر در **سطحِ ماژول** خوانده می‌شوند و
# `pipeline.py` در خطِ ۷۵ `import countries` را **بیرونِ هر try/except**
# انجام می‌دهد. پس یک `COUNTRIES_MIN=abc` باعثِ `ValueError` در لحظهٔ
# import می‌شد و کلِ خطِ لوله را پیش از پردازشِ حتی یک کانفیگ می‌کُشت؛
# یعنی انتشارِ ~۸۵۰۰ کانفیگ صفر می‌شد. این با اجرا تأیید شد:
#     COUNTRIES_MIN=abc python -c "import countries"
#     ValueError: invalid literal for int() with base 10: 'abc'
#
# قاعده: ورودیِ بد **هرگز** raise نمی‌کند؛ هشدار می‌دهد و به پیش‌فرضِ
# سنجیده‌شده برمی‌گردد. یک قابلیتِ فرعی حق ندارد کلِ انتشار را زمین بزند.
#
# چرا `sys.stderr` و نه `log()`: خودِ `log()` پایین‌تر (خطِ ~۱۷۵) تعریف
# می‌شود و این‌جا هنوز وجود ندارد.


def _warn_env(name: str, raw: str, fallback: Any, why: str) -> None:
    """هشدارِ یکدست برای متغیرِ محیطیِ نامعتبر."""
    print(f"⚠️ {name}={raw!r} {why}; falling back to {fallback!r}",
          file=sys.stderr, flush=True)


def _int_env(name: str, default: int, minimum: int) -> int:
    """`int`ِ محیطی با کرانهٔ پایین. در هر خطا به `default` برمی‌گردد."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except (TypeError, ValueError):
        _warn_env(name, raw, default, "is not an integer")
        return default
    if value < minimum:
        _warn_env(name, raw, minimum, f"is below the minimum {minimum}")
        return minimum
    return value


def _float_env(name: str, default: float, minimum: float) -> float:
    """`float`ِ محیطی با کرانهٔ پایین، و ردِ `nan`/`inf`.

    ★ `nan` و `inf` عامدانه رد می‌شوند و این با اندازه‌گیری ثابت شد:
    گاردِ بودجه به‌شکلِ `(time.time() - started) > budget` است و در
    پایتون هر مقایسه با `nan` نتیجهٔ `False` می‌دهد، و هیچ عددی از
    `inf` بزرگ‌تر نیست. پس هر دو گارد را **کاملاً خاموش** می‌کنند.
    سنجشِ واقعی روی کدِ ناموجودِ `QQ` با پایگاه‌دادهٔ حاضر:
        budget=2.0 → ۲٫۰۳s (گارد شلیک کرد)
        budget=nan → ۱۱٫۰۶s (گارد هرگز شلیک نکرد؛ اسکنِ کامل)
    یعنی ۵٫۴ برابر کندتر — دقیقاً همان چیزی که این گارد برای جلوگیری
    از آن ساخته شده بود.
    """
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw.strip())
    except (TypeError, ValueError):
        _warn_env(name, raw, default, "is not a number")
        return default
    # `value != value` تشخیصِ nan بی وابستگی به math است.
    if value != value or value in (float("inf"), float("-inf")):
        _warn_env(name, raw, default, "is not finite")
        return default
    if value < minimum:
        _warn_env(name, raw, minimum, f"is below the minimum {minimum}")
        return minimum
    return value


# ──────────────────────────────────────────────────────────────────────────────
# ثابت‌ها
# ──────────────────────────────────────────────────────────────────────────────

#: نامِ پوشهٔ خروجی. با حرفِ بزرگ، دقیقاً همان‌که درخواست شده بود.
COUNTRIES_DIR = "Countries"

#: نامِ فایلِ فهرستِ ماشین‌خوان درونِ همان پوشه.
INDEX_NAME = "index.json"

#: برچسبِ مکان که `aggregate.py` در ابتدای remark می‌نویسد.
#:
#: دو شکلِ ممکن (از `core.py` خطوطِ ۱۲۷۳/۱۲۹۶):
#:     `DE 🇩🇪 | @Raydikalx | tag`      → کدِ کشور
#:     `Global 🌐 | @Raydikalx | tag`   → کشورِ نامعلوم
#: سنجش روی ۲۰٬۷۵۵ سطرِ زندهٔ همهٔ فایل‌های خروجی: صفر موردِ تجزیه‌نشده.
#: و روی ۱۱ ورودیِ خصمانه (پیمایشِ مسیر با `../`، جداکنندهٔ `/`، یونیکدِ
#: تمام‌عرض، حروفِ کوچک، کدِ سه‌حرفی، فرگمنتِ خالی، بی‌`|`): همه به‌درستی
#: `None` شدند، پس هیچ رشتهٔ خصمانه‌ای به نامِ فایل نمی‌رسد.
LABEL_RE = re.compile(r"^\s*(?:([A-Z]{2})\s+\S+|Global\s+\S+)\s*\|")

#: برچسبی که `core` برای «کشورِ نامعلوم» می‌گذارد.
GLOBAL_CODE = "Global"

#: بودجهٔ ثانیه‌ایِ اسکنِ پشتیبانِ پایگاه‌داده برای یافتنِ نام.
#:
#: چرا سقف لازم است: اگر کدی در پایگاه‌داده **نباشد**، اسکن تا آخر
#: می‌رود. سنجشِ بدترین حالت با کدِ ساختگیِ `QQ`: ۱۰٫۷۰s و
#: ۱٬۳۷۲٬۲۴۸ گام. سقفِ ۲ ثانیه سنجیده شد و واقعاً می‌بُرد
#: (۲٫۰۲s / ۲۸۰٬۰۰۰ گام). در حالتِ عادی اصلاً به این اسکن نمی‌رسیم یا
#: در ۰٫۰۹۳s تمام می‌شود.
#: کرانهٔ پایین `0.1` است نه `0`: بودجهٔ صفر گاردِ زمانی را در همان
#: اولین بررسیِ ساعت می‌بُراند و نامِ هیچ کشوری از پایگاه‌داده در نمی‌آید،
#: که یعنی خروجیِ بی‌صدا بدترِ از خطا. `0.1` کمینه‌ای‌ست که معنا دارد.
NAME_SCAN_BUDGET = _float_env("COUNTRIES_NAME_BUDGET", 2.0, 0.1)

#: هر چند گام یک‌بار ساعت را نگاه کنیم. `time.time()` در هر گام،
#: خودش هزینه‌ای‌ست که می‌خواهیم از آن پرهیز کنیم.
_CLOCK_EVERY = 20_000

#: کمینهٔ کانفیگ برای ساختنِ فایلِ یک کشور.
#:
#: چرا ۱ (یعنی «همه»): `verified/` پیش‌تر **سخت‌ترین** پالایش را خورده؛
#: تنها کانفیگی این‌جاست که در همهٔ اجراها واقعاً وصل شد. آستانه گذاشتن
#: یعنی دور انداختنِ کانفیگِ سالم. سنجش روی دادهٔ زنده: تنها ۹ کشور
#: یک‌کانفیگی‌اند و بزرگ‌ترین‌ها US=۲۶۳ · NL=۱۹۸ · CA=۱۶۱ · DE=۹۱.
#: کرانهٔ پایین `1` است: `MIN_PER_COUNTRY` در شرطِ `len(v) < MIN` به کار
#: می‌رود، پس `0` و مقادیرِ منفی خروجیِ یکسانی با `1` می‌دهند (سنجیده شد:
#: هر سه به `countries=2 · configs=3` رسیدند). نرمال‌سازی می‌کنیم تا
#: آمارِ `min_per_country` در `index.json` عددِ بی‌معنا گزارش نکند.
MIN_PER_COUNTRY = _int_env("COUNTRIES_MIN", 1, 1)

#: حداکثر طولِ مجازِ نامِ فایل (بی پسوند). سنجش: بلندترین نامِ
#: پایگاه‌داده پس از slug شدن خیلی کوتاه‌تر از این است؛ این فقط یک
#: کمربندِ ایمنی برابرِ نامِ غول‌آسا در نسخه‌های آیندهٔ پایگاه‌داده است.
MAX_SLUG_LEN = 96

#: الگویِ نامِ فایلِ **مجاز**. هر چیزِ دیگری رد می‌شود.
_SAFE_SLUG_RE = re.compile(r"\A[A-Za-z0-9_]{1,%d}\Z" % MAX_SLUG_LEN)

#: توضیحِ معیار که در سرآیندِ هر فایل نوشته می‌شود.
CRITERION_LINES: Tuple[str, ...] = (
    "# source: verified/ — every config passed a real proxied request "
    "in ALL L3 rounds",
    "# location: GeoIP (DB-IP Country Lite) on the real network address "
    "of the server",
    "# note: this is where the SERVER is, not necessarily where your "
    "traffic exits",
)


def log(msg: str) -> None:
    print(msg, flush=True)


# ──────────────────────────────────────────────────────────────────────────────
# خواندنِ کدِ کشور از یک سطر
# ──────────────────────────────────────────────────────────────────────────────

def country_code_of(line: str) -> Optional[str]:
    """کدِ دوحرفیِ کشورِ یک سطر، از **برچسبِ خودش**؛ یا `None`.

    هیچ پرس‌وجویِ شبکه‌ای انجام نمی‌شود — دلیلش در docstringِ ماژول
    (تصمیمِ ۲) با عدد آمده.

    `Global` هم یک مقدارِ برگشتیِ معتبر است (نه `None`)؛ تصمیمِ
    «فایل ساختن یا نساختن برایش» کارِ `group_by_country` است، نه این‌جا.
    """
    if not line:
        return None
    remark = core.remark_of(line)
    if not remark:
        return None
    m = LABEL_RE.match(remark)
    if m is None:
        return None
    return m.group(1) or GLOBAL_CODE


# ──────────────────────────────────────────────────────────────────────────────
# نامِ ایمنِ فایل
# ──────────────────────────────────────────────────────────────────────────────

def slug_for(name: str) -> str:
    """نامِ کشور → قطعهٔ نامِ فایلِ ایمن (تنها `A-Za-z0-9_`).

    چرا این‌قدر سخت‌گیرانه: این رشته مستقیم به `os.path.join` می‌رود.
    اگر روزی پایگاه‌داده نامی با `/` یا `..` بدهد، بی این پالایه یک
    نوشتنِ بیرون از پوشهٔ خروجی داریم. پس به‌جای «حذفِ کاراکترهای بد»
    (لیستِ سیاه، که همیشه سوراخ دارد) **لیستِ سفید** به‌کار می‌رود.

    گام‌ها: NFKD → دور انداختنِ نشانه‌های ترکیبی → تنها ASCII → هر چیزِ
    غیرِ حرف/رقم به «_» → فشرده‌سازیِ «_»های پیاپی.

    سنجش روی همهٔ ۲۵۱ نامِ انگلیسیِ پایگاه‌داده: **صفر** نامِ ناایمن و
    **صفر** برخوردِ نام. سه نام واقعاً تغییرِ شکل دادند و هر سه درست:
        `Bonaire, Saint Eustatius and Saba ` → `Bonaire_Saint_Eustatius_and_Saba`
        `Guinea-Bissau`                      → `Guinea_Bissau`
        `U.S. Virgin Islands`                → `U_S_Virgin_Islands`
    """
    s = unicodedata.normalize("NFKD", name or "")
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = s.encode("ascii", "ignore").decode("ascii")
    s = re.sub(r"[^A-Za-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s[:MAX_SLUG_LEN]


def is_safe_slug(slug: str) -> bool:
    """آیا این قطعه‌نام برای ساختنِ مسیر بی‌خطر است؟"""
    return bool(slug) and _SAFE_SLUG_RE.match(slug) is not None


# ──────────────────────────────────────────────────────────────────────────────
# گروه‌بندی
# ──────────────────────────────────────────────────────────────────────────────

def group_by_country(lines: Iterable[str]) -> Dict[str, List[str]]:
    """سطرها → `{کدِ کشور: [سطرها]}`.

    سه چیز عامدانه این‌جا **انجام نمی‌شود**:
      · مرتب‌سازیِ مجدد — ترتیبِ ورودی همان ترتیبِ رتبه‌بندیِ آبشار است
        (`build_buckets` بر پایهٔ تأخیر مرتب کرده). آن ترتیب ارزش دارد:
        کاربر سریع‌ترین سرورِ کشورش را در بالای فایل می‌بیند.
      · یکتاسازی — ورودی از `verified/` می‌آید که پیش‌تر در L0/L1
        یکتاسازیِ نقطهٔ پایانی خورده.
      · ساختنِ گروه برای `Global` — سنجش نشان داد `verified/` صفر موردِ
        Global دارد؛ ولی اگر روزی داشت، این‌جا کنار گذاشته می‌شود چون
        «Global» یک کشور نیست و فایلی به نامِ یک کشور نمی‌سازد.
    """
    groups: Dict[str, List[str]] = {}
    for line in lines:
        s = (line or "").strip()
        if not s or s.startswith("#"):
            continue
        code = country_code_of(s)
        if not code or code == GLOBAL_CODE:
            continue
        groups.setdefault(code, []).append(s)
    return groups


# ──────────────────────────────────────────────────────────────────────────────
# یافتنِ نامِ کشور
# ──────────────────────────────────────────────────────────────────────────────

def _host_of(line: str) -> str:
    """میزبانِ نقطهٔ پایانیِ یک سطر (بی درگاه، بی کروشهٔ IPv6)."""
    endpoint = core.endpoint_of(line) or ""
    if not endpoint:
        return ""
    host = endpoint.rsplit(":", 1)[0] if ":" in endpoint else endpoint
    return host.strip().strip("[]")


def _targeted_names(groups: Dict[str, List[str]], reader: Any) -> Dict[str, str]:
    """نامِ کشورها از رویِ **یک IP صریحِ همان گروه**.

    ★ گاردِ `iso_code == code` قلبِ این تابع است، نه یک بررسیِ تشریفاتی.
    روی دادهٔ زنده بی آن گارد ۴ نامِ غلط تولید می‌شد، چون برچسبِ سطر با
    پایگاه‌دادهٔ ماهِ قبل (کشِ CI) نوشته شده بود و نشانی در نسخهٔ تازه
    کشورش عوض شده. با گارد، رکوردِ ناهمخوان **رد** می‌شود و کار به
    اسکنِ پشتیبان می‌افتد — که همیشه نامِ درست را می‌دهد.
    """
    out: Dict[str, str] = {}
    for code, lines in groups.items():
        for line in lines:
            host = _host_of(line)
            if not host or not geo.is_ip_literal(host):
                continue
            try:
                record = reader.get(host)
            except Exception:
                continue
            country = (record or {}).get("country") or {}
            if country.get("iso_code") != code:
                continue
            name = (country.get("names") or {}).get("en")
            if name:
                out[code] = name
                break
    return out


def _scan_names(missing: Iterable[str], reader: Any,
                budget: float = NAME_SCAN_BUDGET) -> Dict[str, str]:
    """اسکنِ **زودخروجِ** پایگاه‌داده برای کدهایی که هدف‌گیری نیافت.

    دو محافظ:
      · زودخروج — به‌محضِ یافتنِ همهٔ کدهای خواسته‌شده `break`.
        سنجش روی ۴ کدِ واقعیِ باقی‌مانده: ۰٫۰۹۳s / ۱۳٬۰۵۹ گام (در
        برابرِ ۱۱٫۱۹s برای اسکنِ کامل).
      · بودجهٔ زمانی — برای کدی که در پایگاه‌داده **نیست** زودخروج هرگز
        رخ نمی‌دهد. سنجش با کدِ ساختگیِ `QQ`: ۱۰٫۷۰s تا ته.
    """
    need = {c for c in missing if c and c != GLOBAL_CODE}
    found: Dict[str, str] = {}
    if not need:
        return found
    started = time.time()
    steps = 0
    try:
        for _network, record in reader:
            steps += 1
            country = (record or {}).get("country") or {}
            iso = country.get("iso_code")
            if iso in need:
                name = (country.get("names") or {}).get("en")
                if name:
                    found[iso] = name
                need.discard(iso)
                if not need:
                    break
            if steps % _CLOCK_EVERY == 0 and (time.time() - started) > budget:
                log(f"  ⚠️ {COUNTRIES_DIR}: name scan hit the "
                    f"{budget:g}s budget after {steps} steps; "
                    f"{len(need)} code(s) will fall back to the ISO code")
                break
    except Exception as exc:  # pragma: no cover - خرابیِ پایگاه‌داده
        log(f"  ⚠️ {COUNTRIES_DIR}: name scan aborted: {exc}")
    return found


def resolve_names(groups: Dict[str, List[str]]) -> Dict[str, str]:
    """`{کد: نامِ کشور}` — سه‌مرحله‌ای، از ارزان به گران.

    ۱) هدف‌گیری با IP صریحِ همان گروه — ۰٫۰۰۱s، ۴۶/۵۰ روی دادهٔ زنده.
    ۲) اسکنِ زودخروجِ بودجه‌دار برای بقیه — ۰٫۰۹۳s، ۴/۴.
    ۳) اگر پایگاه‌داده نبود یا کد در آن نبود: **خودِ کدِ ISO**.
       این مرحله تشریفاتی نیست: گامِ «Verify GeoIP» ورک‌فلو
       *warn-only* است (هشدار می‌دهد و با `SystemExit(0)` رد می‌شود)،
       پس اجرا با پایگاه‌دادهٔ غایب یک حالتِ **واقعاً ممکن** است. در آن
       حالت `Countries/DE.txt` می‌سازیم — کم‌تر خوانا، ولی درست و
       بی‌خطر. سکوت هم نمی‌کنیم: هشدار در لاگ می‌آید.

    خروجی همیشه برای **همهٔ** کلیدهای `groups` مقدار دارد.
    """
    names: Dict[str, str] = {}
    reader = None
    if geo.database_available():
        try:
            reader = geo._get_reader()
        except Exception as exc:
            log(f"  ⚠️ {COUNTRIES_DIR}: GeoIP reader unavailable: {exc}")
            reader = None
    else:
        log(f"  ⚠️ {COUNTRIES_DIR}: GeoIP database missing — "
            f"falling back to ISO codes as filenames")

    if reader is not None:
        try:
            names.update(_targeted_names(groups, reader))
        except Exception as exc:
            log(f"  ⚠️ {COUNTRIES_DIR}: targeted lookup failed: {exc}")
        missing = [c for c in groups if c not in names]
        if missing:
            try:
                names.update(_scan_names(missing, reader))
            except Exception as exc:
                log(f"  ⚠️ {COUNTRIES_DIR}: name scan failed: {exc}")

    for code in groups:
        if code not in names:
            names[code] = code
    return names


# ──────────────────────────────────────────────────────────────────────────────
# سرآیندِ فایل
# ──────────────────────────────────────────────────────────────────────────────

def header_for(name: str, code: str, count: int) -> str:
    """سرآیندِ ۹ خطیِ یک فایلِ کشوری.

    پنج خطِ اولش بلوکِ پروفایلِ Hiddify است و **باید اول باشد**:
    Hiddify تنها ۲۹ خطِ نخستِ فایل را برای یافتنِ این کلیدها می‌خواند.
    ۵ + ۴ = ۹ خط، پس با فاصلهٔ زیاد درونِ آن پنجره است.
    """
    label = (f"{name.upper().replace('_', ' ')} ({code})"
             if name != code else code)
    out = [core.hiddify_profile_header(label).rstrip("\n")]
    out.append(f"# {core.BRAND_CHANNEL} — {label} — {count} configs")
    out.extend(CRITERION_LINES)
    return "\n".join(out) + "\n"


# ──────────────────────────────────────────────────────────────────────────────
# نوشتن و جارو
# ──────────────────────────────────────────────────────────────────────────────

def _remove_if_exists(path: str) -> bool:
    """حذفِ فایلِ منتشرشدهٔ دورِ قبل (اگر هست). برمی‌گرداند: حذف شد؟

    همان استدلالِ `aggregate._remove_if_exists`: «۴۰۴ بهتر از دادهٔ
    کهنه، و دادهٔ کهنه بهتر از فایلِ خالی» — پاسخِ ۲۰۰ با بدنهٔ خالی
    باعث می‌شود کلاینتِ اشتراک لیستش را با «هیچ» جانشین کند.

    ★ `os.path.lexists` و نه `os.path.exists`: دومی symlink را **دنبال
    می‌کند**، پس برای یک symlinkِ **معلق** (هدفش نیست) پاسخِ `False`
    می‌دهد و آن لینک پاک **نمی‌شود** — سنجیده شد:
    `exists(معلق)=False` ولی `lexists(معلق)=True`. `os.remove` روی
    خودِ لینک کار می‌کند و هدف را دست نمی‌زند (سنجیده شد: لینک رفت،
    هدف سالم ماند)، پس این تغییر تنها «دیدنِ» لینکِ معلق را اضافه
    می‌کند و رفتارِ فایلِ معمولی را عوض نمی‌کند.
    """
    if os.path.lexists(path):
        try:
            os.remove(path)
            return True
        except OSError as exc:
            log(f"  ⚠️ could not remove {path}: {exc}")
    return False


def _sweep(base: str, keep: Iterable[str]) -> List[str]:
    """★ هر `Countries/*.txt` که این دور ساخته **نمی‌شود** را حذف می‌کند.

    این تابع دلِ درستیِ این قابلیت است. دلیلِ سنجیده‌شده‌اش در
    docstringِ ماژول (تصمیمِ ۴) با شبیه‌سازیِ گیتِ واقعی آمده: بی این،
    کشوری که از `verified/` بیرون رفته تا ابد در `Countries/` باقی
    می‌ماند و کاربر یک فایلِ **کهنه** را به‌عنوان دادهٔ تازه می‌خواند.

    تنها `*.txt` و `*.tmp` را می‌بیند و تنها در همین پوشه — نه بازگشتی —
    تا هیچ‌وقت چیزی بیرون از قلمروِ خودش را نبیند. `index.json` عامدانه
    استثنا است چون خودش پس از جارو نوشته می‌شود.

    ★ `*.tmp` چرا: `_write_text` با الگویِ «بنویس در `.tmp` سپس
    `os.replace`» کار می‌کند. اگر دورِ قبل وسطِ کار کشته شود (تایم‌اوتِ
    ۱۵ دقیقه‌ایِ ورک‌فلو، ENOSPC، SIGKILL) یک `.tmp`ِ نیمه‌نوشته می‌ماند
    که خودِ `_write_text` دیگر فرصتِ پاک‌کردنش را ندارد. چون مرحلهٔ
    انتشار کلِ پوشه را stage می‌کند، آن فایلِ نیمه‌کاره **منتشر** می‌شود
    (با شبیه‌سازیِ گیتِ واقعی تأیید شد). این‌جا هر `.tmp` بی‌قید حذف
    می‌شود چون هیچ `.tmp`ِ معتبری نباید از یک دور به دورِ بعد برسد.

    ایمنیِ حذفِ بی‌قیدِ `.tmp` سنجیده شد و به دو تضمینِ مستقل تکیه دارد:
      ۱) `concurrency: {group: aggregate, cancel-in-progress: false}` در
         ورک‌فلو ⇒ دو دور هرگز هم‌زمان روی این پوشه نمی‌نویسند.
      ۲) `runs-on: ubuntu-latest` با checkoutِ تازه در هر دور ⇒ پوشه‌ای
         که می‌بینیم محصولِ همین دور است.
    در همین فرآیند، `_write_text` فایل‌های `.tmp`ِ خودش را **پس از**
    این جارو می‌سازد و بی‌درنگ با `os.replace` مصرف می‌کند، پس جارو
    هرگز `.tmp`ِ در حالِ استفادهٔ همین دور را نمی‌بیند.
    """
    if not os.path.isdir(base):
        return []
    keep_set = set(keep)
    pruned: List[str] = []
    try:
        entries = sorted(os.listdir(base))
    except OSError as exc:
        log(f"  ⚠️ {COUNTRIES_DIR}: cannot list {base}: {exc}")
        return []
    for entry in entries:
        # `.tmp` همیشه رفتنی است (یتیمِ دورِ کشته‌شده)؛ `.txt` تنها اگر
        # این دور ساخته نشود. هر چیزِ دیگری دست‌نخورده می‌ماند.
        if entry.endswith(".tmp"):
            pass
        elif entry.endswith(".txt") and entry not in keep_set:
            pass
        else:
            continue
        target = os.path.join(base, entry)
        # ★ `isfile` symlink را دنبال می‌کند، پس یک symlinkِ **معلق** را
        # «فایل نیست» می‌دید و از جارو جان سالم می‌برد؛ سپس
        # `open(f"{path}.tmp", "w")` دنبالش می‌رفت و خروجی **بیرون از
        # `Countries/`** نوشته می‌شد. شرطِ درست «فایلِ معمولی **یا** هر
        # symlink» است — پوشهٔ واقعی همچنان دست‌نخورده می‌ماند.
        if (os.path.islink(target)
                or os.path.isfile(target)) and _remove_if_exists(target):
            pruned.append(entry)
    return pruned


def _write_text(path: str, content: str) -> None:
    """نوشتنِ اتمیکِ متن، با همان گاردِ بایتِ کنترلیِ بقیهٔ خروجی‌ها."""
    core.assert_no_control_bytes(path, content)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = f"{path}.tmp"
    # اگر نوشتن یا `os.replace` شکست بخورد، فایلِ `.tmp` نباید رها شود.
    # چرا مهم است: مرحلهٔ انتشارِ ورک‌فلو با `git add -A -- $PATHS` کلِ
    # پوشه را stage می‌کند (خطِ ۱۰۸۶ در `aggregate.yml`)، پس یک `.tmp`ِ
    # یتیم عیناً منتشر می‌شود. جاروی این ماژول هم فقط `*.txt` را می‌دید
    # و `*.txt.tmp` را نمی‌گرفت — با شبیه‌سازیِ گیتِ واقعی دیده شد که
    # `Countries/Germany.txt.tmp` وارد درختِ منتشرشده می‌شود.
    try:
        # ★ `O_NOFOLLOW`: اگر روی مسیرِ `.tmp` یک symlink باشد، هسته با
        # `ELOOP` رد می‌کند و **هرگز** از آن عبور نمی‌کند. جارو هم همین
        # را می‌گیرد، ولی این لایه از جارو مستقل است: اگر لینک **پس از**
        # جارو ساخته شود (TOCTOU)، تنها همین لایه جلویش را می‌گیرد.
        # `O_TRUNC` هست تا رفتارِ `open(..., "w")` عیناً حفظ شود و
        # `0o666` با umask به همان `0o644`ِ قبلی می‌رسد (سنجیده شد).
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                     | os.O_NOFOLLOW, 0o666)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, path)
    except BaseException:
        # `BaseException` تا KeyboardInterrupt/SystemExit هم پاک‌سازی شود.
        # خطای پاک‌سازی، خطای اصلی را نمی‌پوشاند.
        try:
            # `lexists` تا اگر آن `.tmp` خودش یک symlinkِ معلق بود هم
            # پاک شود؛ `exists` آن را نمی‌دید و یتیم رهایش می‌کرد.
            if os.path.lexists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        raise


def write_countries(out_dir: str, lines: Sequence[str]) -> Dict[str, Any]:
    """`Countries/` را از سطرهای **تأییدشده** می‌سازد. آمار را برمی‌گرداند.

    هفت گام، به همین ترتیب — و ترتیب مهم است:
      ۱) گروه‌بندی بر پایهٔ برچسبِ خودِ سطر (بی شبکه)
      ۲) کنار گذاشتنِ گروه‌های کوچک‌تر از `MIN_PER_COUNTRY`
      ۳) یافتنِ نامِ کشورها (هدف‌گیری → اسکنِ بودجه‌دار → کدِ ISO)
      ۴) ساختنِ نامِ فایلِ ایمن + حلِ برخوردِ نام
      ۵) ★ **جارو** — پیش از نوشتن، تا فایلِ دورِ قبل نماند
      ۶) نوشتنِ فایل‌ها
      ۷) نوشتنِ `Countries/index.json`
    """
    base = os.path.join(out_dir, COUNTRIES_DIR)
    started = time.time()
    lines = list(lines or [])

    # ۱ + ۲
    groups = group_by_country(lines)
    skipped = {c: len(v) for c, v in groups.items()
               if len(v) < MIN_PER_COUNTRY}
    for code in skipped:
        groups.pop(code, None)

    # ۳
    names = resolve_names(groups) if groups else {}

    # ۴ — نامِ فایل. برخوردِ نام روی هر ۲۵۱ نامِ پایگاه‌داده سنجیده شد و
    # صفر بود؛ ولی «سنجیده‌شده صفر» با «ناممکن» یکی نیست: نسخهٔ آیندهٔ
    # پایگاه‌داده می‌تواند دو نام بدهد که به یک slug برسند. در آن حالت
    # به‌جای این‌که یک کشور فایلِ دیگری را بازنویسی کند، کدِ ISO به نام
    # چسبانده می‌شود.
    plan: Dict[str, Tuple[str, str]] = {}   # code → (filename, slug)
    used: Dict[str, str] = {}               # filename → code
    for code in sorted(groups):
        slug = slug_for(names.get(code, code))
        if not is_safe_slug(slug):
            log(f"  ⚠️ {COUNTRIES_DIR}: unsafe name for {code} "
                f"({names.get(code)!r}) — using the ISO code")
            slug = code if is_safe_slug(code) else ""
        if not slug:
            log(f"  ⚠️ {COUNTRIES_DIR}: skipping {code!r}: no safe filename")
            continue
        filename = f"{slug}.txt"
        if filename in used:
            slug = f"{slug}_{code}"
            filename = f"{slug}.txt"
            log(f"  ⚠️ {COUNTRIES_DIR}: filename collision — "
                f"{code} written as {filename}")
        if filename in used or not is_safe_slug(slug):
            log(f"  ⚠️ {COUNTRIES_DIR}: skipping {code}: cannot place safely")
            continue
        used[filename] = code
        plan[code] = (filename, slug)

    # ۵ ★
    pruned = _sweep(base, keep=set(used))
    if pruned:
        log(f"  🗑️ {COUNTRIES_DIR}: pruned {len(pruned)} stale file(s): "
            f"{', '.join(pruned[:8])}"
            f"{' …' if len(pruned) > 8 else ''}")

    # ۶
    written: Dict[str, Dict[str, Any]] = {}
    failed: Dict[str, str] = {}
    for code in sorted(plan):
        filename, slug = plan[code]
        group = groups[code]
        path = os.path.join(base, filename)
        try:
            body = core.shield_unsupported_runs(group)
            # شمارشِ سرآیند از `group` گرفته می‌شود، نه از `body`ِ سپرخورده.
            # این عیناً همان قراردادِ `aggregate.write_category` است:
            # «شمارشِ سرآیند عمداً از `r.unique` گرفته می‌شود، نه از لیستِ
            # سپرخورده — سپر «کانفیگ» نیست.» اگر `len(body)` می‌بود، سرآیند
            # به‌اندازهٔ تعدادِ خطوطِ سپر متورم می‌شد و با `count`ِ همین
            # کشور در `index.json` — که از `len(group)` می‌آید — تناقض
            # پیدا می‌کرد؛ یعنی دو خروجیِ رسمی دو عددِ مختلف می‌دادند.
            content = header_for(slug, code, len(group)) + "\n".join(body) + "\n"
            _write_text(path, content)
        except Exception as exc:
            # همان سیاستِ `write_buckets`: خرابیِ یک فایل، بقیه را زمین
            # نمی‌زند؛ و فایلِ نیمه‌نوشته منتشر نمی‌شود.
            log(f"  ⚠️ {COUNTRIES_DIR}/{filename}: {exc}")
            _remove_if_exists(path)
            failed[code] = str(exc)
            continue
        written[code] = {
            "file": f"{COUNTRIES_DIR}/{filename}",
            "name": slug.replace("_", " "),
            "code": code,
            "flag": geo.flag_of(code),
            "count": len(group),
        }

    stats: Dict[str, Any] = {
        "countries": len(written),
        "configs": sum(v["count"] for v in written.values()),
        # `ln` و نه `l`: قاعدهٔ E741 در `pyproject.toml` فعال است و
        # سیاستِ نوشتهٔ مخزن «در کد اصلاح شود، نه با ignore» است.
        "input": len([ln for ln in lines if (ln or "").strip()]),
        "pruned": pruned,
        "skipped_small": skipped,
        "failed": failed,
        "named_from_db": sum(1 for c in written if names.get(c) != c),
        "min_per_country": MIN_PER_COUNTRY,
        "seconds": round(time.time() - started, 3),
    }

    # ۷ — فهرست. عامدانه **درونِ همین پوشه** و نه در `index.json`ِ ریشه:
    # تستِ ۹۴۵۴ در `test_pipeline.py` صریحاً
    # `set(index["categories"]) == {"all","heavy","light"}` را قید
    # می‌کند؛ افزودنِ `Countries` به آن مجموعه، آن گاردِ «جهانِ بسته» را
    # می‌شکند. یک فهرستِ جدا همان کار را بی شکستنِ هیچ قراری می‌کند.
    if written:
        index = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": "verified",
            "criterion": "passed a real proxied request in ALL L3 rounds",
            "location_method": "GeoIP (DB-IP Country Lite) on the "
                               "server's network address",
            "countries": [written[c] for c in sorted(
                written, key=lambda c: (-written[c]["count"], c))],
            "stats": {k: stats[k] for k in
                      ("countries", "configs", "min_per_country")},
        }
        try:
            _write_text(os.path.join(base, INDEX_NAME),
                        json.dumps(index, ensure_ascii=False, indent=2) + "\n")
            stats["index"] = f"{COUNTRIES_DIR}/{INDEX_NAME}"
        except Exception as exc:
            log(f"  ⚠️ {COUNTRIES_DIR}/{INDEX_NAME}: {exc}")
    else:
        # هیچ کشوری نداریم ⇒ فهرستِ دورِ قبل هم باید برود، وگرنه فایلی را
        # تبلیغ می‌کند که همین حالا جارو شده.
        if _remove_if_exists(os.path.join(base, INDEX_NAME)):
            log(f"  🗑️ {COUNTRIES_DIR}: pruned stale {INDEX_NAME}")

    stats["files"] = {c: written[c]["file"] for c in written}
    log(f"  🌍 {COUNTRIES_DIR}: {stats['countries']} countries · "
        f"{stats['configs']} configs · {stats['seconds']}s")
    return stats
