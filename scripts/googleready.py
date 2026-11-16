#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
لایهٔ «Google Ready» — آزمونِ واقعیِ دسترسی به سرویس‌های گوگل، **پس از** آبشار.

جایگاه:

    L0/L1 → L2 → L3×n  ⇒  verified/        (pipeline.py — دست‌نخورده)
                              ↓
                     همین ماژول ⇒ google/

ورودی فقط `verified/configs.txt`ِ **همین اجرا** است؛ پس `google/` همیشه
زیرمجموعهٔ `verified/` است و منطقِ L3 هیچ تغییری نمی‌کند.

──────────────────────────────────────────────────────────────────────────────
چرا این دسته اطلاعاتِ تازه می‌دهد — سنجش، نه حدس (۲۰۲۶-۱۱-۱۶)
──────────────────────────────────────────────────────────────────────────────
همهٔ ۱٬۱۷۶ کانفیگِ `verified/`، سه دور، همین پنلِ پنج‌مقصدی با xray-knife
10.1.1 (همان باینری و checksumِ CI)، از یک سرورِ آلمان. از ۹۸۳ کانفیگی که
مقصدِ کنترل (Cloudflare) در **هر سه** دور برایشان موفق بود:

    gstatic   ۹۲۳ همیشه موفق ·   ۱ همیشه ناموفق
    youtube   ۸۹۰ همیشه موفق ·  ۲۶ همیشه ناموفق  (۱۱ تا خروجِ ایران)
    play      ۸۹۲ همیشه موفق ·  ۲۲ همیشه ناموفق
    maven     ۷۰۸ همیشه موفق · ۲۰۹ همیشه ناموفق  (۱۵۰ تا HTTP 404 در هر سه دور)
    همهٔ چهار سرویس در همهٔ دورها: ۶۴۴ (۶۵٫۵٪)

یعنی تقریباً یک‌سوم از کانفیگ‌هایی که «کار می‌کنند»، دست‌کم یک سرویسِ گوگل را
باز نمی‌کنند. 404ِ Maven با curl از همان تونل بازتولید شد: گواهیِ معتبرِ
`*.google.com`، هدرِ `server: downloads`، و گوگل همان IP را `GL=US` می‌داند —
پس پاسخِ واقعیِ گوگل است و نه مرزبندیِ کشوری. روی همان میزبان کلیدِ Chrome
200 می‌داد و Maven/SDK اندروید 404.

──────────────────────────────────────────────────────────────────────────────
تصمیم‌های طراحی
──────────────────────────────────────────────────────────────────────────────
۱) **مقصدِ کنترل در همان اجرای هر کانفیگ.** نخستین مقصدِ پنل
   `cp.cloudflare.com/generate_204` است (همان نشانیِ L3). اگر کنترل شکست
   بخورد، شکستِ گوگل قابلِ نسبت‌دادن به گوگل نیست ⇒ «نامعلوم»، نه «رد».
   سنجش: وقتی کنترل شکسته بود، gstatic در حدودِ نیمی از موارد هم شکسته بود.

۲) **دو دور، موفق در هر دو.** دقتِ پیش‌بینی روی دورِ کنارگذاشته
   (leave-one-out): یک دور ۰٫۹۲۲–۰٫۹۵۵، دو دور ۰٫۹۳۷–۰٫۹۷۳. هر دور
   ۸۴–۹۳ ثانیه با ۱۰۰ رشته. دورِ سوم بیش از ۹۰ ثانیه به jobی می‌افزود که
   سقفِ ۹۰۰ ثانیه دارد.

۳) **داوری از ستونِ `endpoints`، نه از `status`.** در حالتِ پنلی، اگر
   درخواستِ جانبیِ `--rip` به Cloudflare شکست بخورد، ابزار وضعیت را
   `semi-passed` می‌کند حتی وقتی همهٔ مقصدها موفق بوده‌اند (خوانده‌شده از
   `pkg/http/examiner.go`). پس تنها منبعِ معتبر، نتیجهٔ تک‌تکِ مقصدهاست.

۴) **دروازهٔ مرجع، fail-closed.** پیش از هر کار، خودِ رانر مستقیم همهٔ
   مقصدها را می‌زند (Maven با بررسیِ محتوای POM). اگر یکی خراب باشد، این دور
   `google/` منتشر **نمی‌شود** — انتشار نکردن بهتر از انتشارِ غلط است.

۵) **هیچ دادهٔ بایاتی.** `google/` نخستین کارِ این ماژول حذف می‌شود و
   خروجیِ تازه در پوشهٔ موقت نوشته و سپس اتمیک جابه‌جا می‌شود. سنجیده شد که
   گامِ انتشار درخت را از **پوشهٔ کاری** می‌سازد، و پوشهٔ کاری checkoutِ
   انتشارِ قبلی است؛ پس هر دوری که این گام کامل نشود، بدونِ حذفِ اولیه
   `google/`ِ کهنه را دوباره منتشر می‌کرد.

۶) **بودجهٔ زمانی.** گام‌های پس از این (validate ≤۹s، publish ≤۱۱s،
   purge ≤۶۵s در ۱۲ اجرای واقعی) باید در سقفِ ۹۰۰ ثانیهٔ job جا شوند. اگر
   پیش از یک دور زمانِ کافی نماند، آن دور اجرا نمی‌شود و دسته منتشر نمی‌شود.

۷) **کارِ ناامنی که سنجش رد کرد:** «یک کانفیگ برای هر IPِ خروجی» بار را نصف
   می‌کرد، ولی در هر دور ۶ تا ۸ IP هم 200 و هم 404 گرفتند ⇒ حکم صددرصد تابعِ
   IP نیست و این بهینه‌سازی نتیجه را خراب می‌کرد.

──────────────────────────────────────────────────────────────────────────────
Gemini — دو آزمونِ جدا، هر دو پس از سنجش (۲۰۲۶-۱۱-۱۶)
──────────────────────────────────────────────────────────────────────────────
الف) **انسدادِ IP** — مقصدِ پنلیِ `gemini.google.com/robots.txt` (۱۱۶ بایت).
     روی ۵۲۵ کانفیگی که کنترلشان موفق بود، هم‌زمان `/app` (۹۳۰ کیلوبایت) و
     `robots.txt` سنجیده شد:
         ۳۶۹  هر دو ok
          ۶۹  هر دو 403  («Your client does not have permission»)
          ۴۳  robots=404 و app = خطای حلقهٔ redirect یا 429؛ با curl دیده شد
              که `/app` با 302 به `www.google.com/sorry/index` (CAPTCHA) می‌رود
     همخوانی ۵۰۱/۵۲۵ (۹۵٫۴٪)؛ باقی تقریباً همه نویزِ انتقال بود (error/slow).
     یعنی ~۲۱٪ از کانفیگ‌های «کارکن» اصلاً Gemini را باز نمی‌کنند و هیچ‌یک از
     چهار آزمونِ قبلی این را نمی‌گرفت. robots کافی است و `/app` لازم نیست.

ب) **کشورِ پشتیبانی‌نشده** — گوگل Gemini را در هر کشوری ارائه نمی‌کند و
     مستنداتش می‌گوید مکان را از IP می‌گیرد. سنجش نشان داد:
       • کد/عنوان/اندازهٔ صفحه هیچ نشانهٔ کشوری ندارد (روسیه هم 200 و صفحهٔ
         کامل می‌گیرد). پرچمِ `ARR9x` در صفحه **رد شد**: بینِ دو اجرا عوض
         می‌شد و با کشورِ دیدِ گوگل نمی‌خواند.
       • API بی‌کلید یا با کلیدِ نامعتبر، کلید را **پیش از** مکان می‌سنجد.
       • AI Studio بی‌ورود برای روسیه و آمریکا همان redirect را می‌دهد.
       • کشورِ Cloudflare (`location`ِ xray-knife) از ۱۸ خروجی‌ای که گوگل
         «RU» می‌داند تنها ۲ را می‌شناخت — جانشینِ قابلِ‌اتکایی نیست.
     تنها منبعِ درست، دیدِ خودِ گوگل است: `www.youtube.com/sw.js_data`
     (۲٫۶ کیلوبایت) کدِ کشورِ IPِ درخواست‌کننده را برمی‌گرداند. چون xray-knife
     بدنه را نمی‌خواند، این آزمون با یک inboundِ محلیِ همان باینری برای هر
     کانفیگ و curl انجام می‌شود (`geo_phase`). سنجش روی ۳۶۹ کانفیگِ
     Gemini-ok: ۱۸ تا (۵٫۶٪) را گوگل در روسیه می‌دانست. ۴۸ پاسخ در هم‌روندیِ
     ۱۶ خالی ماند و ۴۳ تای آن‌ها در تلاشِ دوم با هم‌روندیِ ۴ پر شد ⇒ یک دورِ
     تکرار با هم‌روندیِ کمتر لازم است؛ آنچه باز هم نامعلوم بماند **حذف** می‌شود.
     راستی‌آزماییِ مستقلِ ۴۳۳ کانفیگِ منتشرشده یک کانفیگ را «RU» یافت: همان
     سرور از IPv4 «US» و از IPv6 «RU» دیده می‌شد و خانوادهٔ IP در هر اتصال
     عوض می‌شد ⇒ برای کاربر هم گاهی کار می‌کند و گاهی نه. پس از همان inbound
     سه بار خوانده می‌شود و **هر** خواندنِ ناپشتیبان کانفیگ را حذف می‌کند.
     خطرِ باقی‌مانده (سنجیده، نه برآورد): پس از این قاعده، دو خواندنِ مستقل روی
     هر ۴۱۱ کانفیگِ منتشرشده تنها **یک** کانفیگ را با یک خواندنِ «RU» یافت
     (IPv6 ⇒ RU در ۷ از ۱۰، IPv4 ⇒ UA در ۳ از ۱۰؛ سه خواندنِ کد هر سه IPv4
     افتاده بود: ۰٫۳³ ≈ ۲٫۷٪). راهِ «اجبارِ خانوادهٔ IP» با `ipv4.google.com` /
     `ipv6.google.com` آزموده و **رد** شد: `sw.js_data` آن‌جا 404 است و نشانِ
     کشور در صفحهٔ اصلی فقط در پیوندِ رضایتِ EU و در بایتِ ~۱۷۰٬۰۰۰ آمد.
     فهرستِ کشورها از صفحهٔ رسمی (`support.google.com/gemini/answer/13575153`،
     ۲۴۲ نام) با CLDR به ۲۴۱ کد نگاشت شد («Mainland China (Workspace only)»
     عمداً بیرون است چون برای کاربرِ عادی نیست).

حدِ ادعا: این دو آزمون نشان می‌دهند گوگل این IP را نه مسدود کرده، نه به
CAPTCHA فرستاده و نه در کشورِ ناپشتیبان می‌داند. استفادهٔ واقعی از Gemini
به حسابِ گوگل هم بستگی دارد (کشورِ حساب، سن) که بی ورود قابلِ سنجش نیست.

محدودیتِ ادعا (در سرآیندِ فایل هم نوشته می‌شود): «در زمانِ آزمون، از محلِ
رانر، این مقصدهای مشخص پاسخِ درست دادند» — نه «همهٔ سرویس‌های گوگل کار
می‌کنند» و نه «پخشِ ویدئو کار می‌کند».
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import converters  # noqa: E402
import core  # noqa: E402
import pipeline  # noqa: E402
import realtest  # noqa: E402

# ──────────────────────────────────────────────────────────────────────────────
# ثابت‌ها
# ──────────────────────────────────────────────────────────────────────────────

CATEGORY = "google"
SOURCE_CATEGORY = "verified"

#: فایلِ POMِ کوچک (۲٬۰۰۸ بایت، سنجیده شد) از مخزنِ رسمیِ Google Maven.
#: `maven.google.com` با 301 به همین نشانی می‌فرستد (سنجیده شد)، پس نشانیِ
#: نهایی مستقیم آمده تا یک رفت‌وبرگشتِ اضافه از هر پروکسی کم شود.
MAVEN_URL = ("https://dl.google.com/dl/android/maven2/androidx/annotation/"
             "annotation/1.9.1/annotation-1.9.1.pom")

#: (نام، نشانی، کدِ لازم). کنترل **باید** نخستین مقصد باشد.
CONTROL: Tuple[str, str, int] = (
    "control", "https://cp.cloudflare.com/generate_204", 204)
SERVICES: Tuple[Tuple[str, str, int], ...] = (
    ("gstatic", "https://www.gstatic.com/generate_204", 204),
    ("youtube", "https://www.youtube.com/generate_204", 204),
    ("play", "https://play.google.com/generate_204", 204),
    ("maven", MAVEN_URL, 200),
    # ۲۰۰ = باز؛ ۴۰۳ = IP مسدود؛ ۴۰۴ = IP در CAPTCHAی `google.com/sorry`
    # (سنجش و شرح در docstring، بخشِ «Gemini»).
    ("gemini", "https://gemini.google.com/robots.txt", 200),
)
PANEL: Tuple[Tuple[str, str, int], ...] = (CONTROL,) + SERVICES

ROUNDS = int(os.environ.get("GR_ROUNDS", "2"))

#: کمینهٔ زمانِ باقی‌مانده برای شروعِ یک دور (ثانیه). سنجش: ۸۴–۹۳ ثانیه برای
#: هر دور با ۱۰۰ رشته روی ۱٬۱۷۶ کانفیگ ⇒ ۱۲۰ یعنی «دستِ‌کم یک دورِ سنجیده +
#: حاشیه». کمتر از این، دور به احتمالِ زیاد وسطِ کار با مهلت قطع می‌شود.
MIN_ROUND_SECONDS = int(os.environ.get("GR_MIN_ROUND_SECONDS", "120"))

#: سرِ هر دور این مقدار از بودجه کم می‌شود تا نوشتنِ فایل‌ها هم جا شود.
WRITE_RESERVE_SECONDS = 15

REFERENCE_TIMEOUT = 10.0
REFERENCE_ATTEMPTS = 2

# ── کشور از دیدِ گوگل (برای Gemini) ────────────────────────────────────────────

#: پاسخی ۲٫۶ کیلوبایتی که با `["hl","GL",null,"<IP>",...]` کشورِ IPِ درخواست‌کننده
#: را از دیدِ گوگل می‌گوید (سنجیده: از سرورِ آلمان `"DE"`، از خروجی‌های روسی `"RU"`).
GEO_URL = "https://www.youtube.com/sw.js_data"
#: فیلدِ اول برچسبِ زبانِ BCP-47 است و **می‌تواند رقم داشته باشد**: بازبینیِ
#: پس از انتشار، از ۵۳۷ پاسخِ 200 دقیقاً یکی را تجزیه‌نشده یافت — `"es-419","MX"`
#: (اسپانیاییِ آمریکای لاتین، خروجِ مکزیک). الگوی پیشین `[A-Za-z-]` بود و آن
#: کانفیگِ سالم را در تقریباً هر دور «unparsed» و حذف می‌کرد. کدِ کشور همچنان
#: دقیقاً دو حرفِ بزرگ است.
_GEO_RE = re.compile(r'"yt\.sw\.adr",null,\[\[\["[A-Za-z0-9-]{0,35}","([A-Z]{2})"')

#: کشورهایی که Gemini در آن‌ها ارائه می‌شود — از
#: https://support.google.com/gemini/answer/13575153 (خوانده‌شده ۲۰۲۶-۱۱-۱۶،
#: ۲۴۲ نام). ۲۰۸ نام با نامِ CLDR دقیقاً یکی بود و رفت‌وبرگشت شد؛ ۳۳ نامِ
#: دیگر (مثلِ «Türkiye»→TR، «Czech Republic»→CZ، «Hong Kong»→HK) دستی و با
#: چاپِ نامِ CLDRِ هر کد تأیید شد. «Mainland China (Workspace only)» عمداً
#: نیست. فهرستِ سفید است: کشوری که بعداً اضافه شود تا به‌روزرسانی **حذف**
#: می‌شود (سمتِ امن)، نه برعکس.
GEMINI_COUNTRIES = frozenset("""
    AD AE AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF
    BG BH BI BJ BL BM BN BO BQ BR BS BT BW BZ CA CC CD CF CG CH
    CI CK CL CM CO CR CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG
    EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM
    GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN
    IO IQ IS IT JE JM JO JP KE KG KH KI KM KN KR KW KY KZ LA LB
    LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN
    MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO
    NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA
    RE RO RS RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS
    ST SV SX SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ
    UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM
    ZW
""".split())
assert len(GEMINI_COUNTRIES) == 241, len(GEMINI_COUNTRIES)

#: هم‌روندیِ دورِ اول و دورِ تکرار. سنجش: با ۱۶ هم‌روند ۴۸ از ۳۶۹ پاسخ خالی
#: ماند و ۴۳ تای آن‌ها با ۴ هم‌روند پر شد.
GEO_WORKERS = int(os.environ.get("GR_GEO_WORKERS", "12"))
GEO_RETRY_WORKERS = int(os.environ.get("GR_GEO_RETRY_WORKERS", "4"))
GEO_FETCH_TIMEOUT = 20
GEO_READY_TIMEOUT = 10.0
GEO_PORT_BASE = int(os.environ.get("GR_GEO_PORT_BASE", "23000"))

#: چند خواندن از **همان** inbound. سنجش: یک کانفیگ که از IPv4 (`185.236.8.132`)
#: «US» و از IPv6 (`2a0f:b240:18:115::1`) «RU» دیده می‌شد، در یک پروسه و ۶
#: خواندنِ پشتِ‌سرِ‌هم `RU RU RU US US RU` / `RU RU US US US US` / `RU US RU US US RU`
#: داد — یعنی خانوادهٔ IPِ خروج در هر اتصال عوض می‌شود و کاربر هم گاهی به
#: Gemini می‌رسد و گاهی نه. پس **هر** خواندنِ ناپشتیبان کانفیگ را حذف می‌کند.
#: با یک خواندن، از ۴۳۳ کانفیگِ منتشرشده یکی همین وضع را داشت.
GEO_READINGS = int(os.environ.get("GR_GEO_READINGS", "3"))
#: کمینهٔ خواندنِ موفق برای حکمِ «پشتیبانی‌شده».
GEO_MIN_READABLE = 2
if GEO_READINGS < GEO_MIN_READABLE:
    # با کمتر از این، هیچ کانفیگی هرگز «پشتیبانی‌شده» نمی‌شد و دسته بی‌صدا تهی
    # می‌ماند. استثنا هم راهِ درستی نیست: شکستِ import یعنی `remove_outputs`
    # اجرا نمی‌شود (گامِ ورک‌فلو برای همین خودش هم پیش‌اپیش `google/` را پاک می‌کند).
    print(f"⚠️ GR_GEO_READINGS={GEO_READINGS} < {GEO_MIN_READABLE}; using "
          f"{GEO_MIN_READABLE}", file=sys.stderr)
    GEO_READINGS = GEO_MIN_READABLE
#: زمانی که پیش از آغازِ هر کار باید باقی مانده باشد (راه‌اندازی + خواندن‌ها).
GEO_TASK_SECONDS = GEO_READY_TIMEOUT + GEO_FETCH_TIMEOUT * GEO_READINGS + 5


def xk_label(url: str) -> str:
    """
    برچسبی که xray-knife در ستونِ `endpoints` برای این نشانی می‌نویسد.

    همان قاعدهٔ `endpointLabel` در `pkg/http/examiner.go` (v10.1.1): نامِ
    میزبان، بی پیشوندِ `www.` و بی درگاه.
    """
    host = urlsplit(url).hostname or ""
    return host[4:] if host.startswith("www.") else host


LABELS: Dict[str, str] = {name: xk_label(url) for name, url, _ in PANEL}

# اگر دو مقصد یک برچسب بگیرند، ستونِ `endpoints` نمی‌تواند آن‌ها را از هم جدا
# کند و یک شکست می‌تواند زیرِ نامِ موفق پنهان شود. پس در زمانِ import می‌شکند.
assert len(set(LABELS.values())) == len(LABELS), f"ambiguous labels: {LABELS}"
assert PANEL[0] is CONTROL, "the control endpoint must be probed first"

#: شکلِ دقیقِ هر نشانه در ستونِ `endpoints` (از `summarizeEndpoints`).
_EP_RE = re.compile(
    r"^(?P<label>[^=;\s]+)="
    r"(?:ok\((?P<ok>\d+)ms\)|slow\((?P<slow>\d+)ms\)|status(?P<st>-?\d+)|(?P<err>error))$")

OK = "ok"


# ──────────────────────────────────────────────────────────────────────────────
# تجزیه و داوری
# ──────────────────────────────────────────────────────────────────────────────

class UnparsedEndpoints(ValueError):
    """ستونِ `endpoints` با شکلِ سنجیده نمی‌خواند — بالادست چیزی را عوض کرده."""


def parse_endpoints(text: str) -> Dict[str, str]:
    """
    `"gstatic.com=ok(408ms); dl.google.com=status404"` →
    `{"gstatic.com": "ok", "dl.google.com": "status404"}`.

    نشانهٔ ناشناخته **بلند** می‌شکند: خواندنِ خاموشِ آن یعنی شاید یک شکست
    «موفق» شمرده شود.
    """
    out: Dict[str, str] = {}
    if not (text or "").strip():
        return out
    for token in text.split(";"):
        token = token.strip()
        if not token:
            continue
        m = _EP_RE.match(token)
        if not m:
            raise UnparsedEndpoints(f"unrecognised endpoint token: {token!r}")
        if m["ok"] is not None:
            outcome = OK
        elif m["slow"] is not None:
            outcome = "slow"
        elif m["st"] is not None:
            outcome = f"status{m['st']}"
        else:
            outcome = "error"
        out[m["label"]] = outcome
    return out


def judge_row(row: Optional[Dict[str, str]]) -> Dict[str, str]:
    """
    نتیجهٔ هر مقصد برای یک سطر: `{نام: outcome}`.

    سطرِ غایب (خروجیِ ناقص) یا تجزیه‌ناپذیر ⇒ همهٔ مقصدها `missing` /
    `unparsed` — هیچ‌کدام هرگز `ok` شمرده نمی‌شوند.
    """
    if row is None:
        return {name: "missing" for name, _, _ in PANEL}
    try:
        eps = parse_endpoints(row.get("endpoints", ""))
    except UnparsedEndpoints:
        return {name: "unparsed" for name, _, _ in PANEL}
    return {name: eps.get(LABELS[name], "absent") for name, _, _ in PANEL}


def classify_rounds(links: Sequence[str],
                    rounds: Sequence[Dict[str, Dict[str, str]]]) -> Dict[str, Any]:
    """
    حکمِ نهایی از چند دور.

        ready    کنترل و هر چهار سرویس در **همهٔ** دورها ok
        fail     کنترل در همهٔ دورها ok، ولی سرویسی دست‌کم یک بار ناموفق
        unknown  کنترل دست‌کم یک بار ناموفق ⇒ شکستِ گوگل قابلِ نسبت‌دادن نیست

    ترتیبِ `ready` همان ترتیبِ ورودی است (یعنی ترتیبِ `verified/` که بر
    میانهٔ تأخیرِ L3 مرتب شده) تا خروجی بازتولیدپذیر بماند.
    """
    if not rounds:
        raise ValueError("at least one round is required")
    ready: List[str] = []
    fail: List[str] = []
    unknown: List[str] = []
    per_service: Dict[str, Dict[str, Any]] = {
        name: {"all_ok": 0, "all_fail": 0, "mixed": 0, "fail_outcomes": {}}
        for name, _, _ in SERVICES}

    for link in links:
        verdicts = [judge_row(r.get(link)) for r in rounds]
        if not all(v["control"] == OK for v in verdicts):
            unknown.append(link)
            continue
        all_good = True
        for name, _, _ in SERVICES:
            seq = [v[name] for v in verdicts]
            n_ok = sum(1 for s in seq if s == OK)
            bucket = per_service[name]
            if n_ok == len(seq):
                bucket["all_ok"] += 1
            else:
                all_good = False
                bucket["all_fail" if n_ok == 0 else "mixed"] += 1
                for s in seq:
                    if s != OK:
                        bucket["fail_outcomes"][s] = bucket["fail_outcomes"].get(s, 0) + 1
        (ready if all_good else fail).append(link)

    return {"ready": ready, "fail": fail, "unknown": unknown,
            "per_service": per_service}


# ──────────────────────────────────────────────────────────────────────────────
# دروازهٔ مرجع
# ──────────────────────────────────────────────────────────────────────────────

def _maven_body_ok(body: bytes) -> bool:
    text = body.decode("utf-8", "replace")
    return "<project" in text and "<artifactId>annotation</artifactId>" in text


def _gemini_robots_ok(body: bytes) -> bool:
    """محتوای سنجیدهٔ `gemini.google.com/robots.txt` (۱۱۶ بایت)."""
    text = body.decode("utf-8", "replace")
    return "User-agent:" in text and "Disallow: /app/" in text


#: مقصدهایی که در مرجع، افزون بر کد، **محتوا** هم باید درست باشد.
_BODY_CHECKS: Dict[str, Callable[[bytes], bool]] = {
    "maven": _maven_body_ok,
    "gemini": _gemini_robots_ok,
}


def parse_geo(body: bytes) -> Optional[str]:
    """کدِ کشورِ دیدِ گوگل از بدنهٔ `sw.js_data`، یا None."""
    m = _GEO_RE.search(body.decode("utf-8", "replace"))
    return m.group(1) if m else None


def _fetch(url: str, timeout: float) -> Tuple[int, bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(65536)
    except urllib.error.HTTPError as exc:
        return exc.code, b""


def reference_check(fetch: Callable[[str, float], Tuple[int, bytes]] = _fetch,
                    attempts: int = REFERENCE_ATTEMPTS,
                    timeout: float = REFERENCE_TIMEOUT) -> Dict[str, Any]:
    """
    خودِ رانر، **بی پروکسی**، همهٔ مقصدها را می‌زند.

    اگر مقصدی از خودِ رانر هم خراب باشد، شکستِ آن در پروکسی‌ها نشانهٔ محیط
    است، نه کانفیگ ⇒ این دور منتشر نمی‌شود.
    """
    results: Dict[str, Any] = {}
    for name, url, expect in PANEL:
        last = "not attempted"
        good = False
        for _ in range(max(1, attempts)):
            try:
                code, body = fetch(url, timeout)
            except Exception as exc:  # noqa: BLE001
                last = f"{type(exc).__name__}: {exc}"
                continue
            last = str(code)
            body_ok = _BODY_CHECKS.get(name, lambda _b: True)
            if code == expect and body_ok(body):
                good = True
                break
            if code == expect:
                last = f"{code} (unexpected body)"
        results[name] = {"ok": good, "result": last, "expect": expect}
    # کشورِ خودِ رانر از دیدِ گوگل: اگر این‌جا هم خوانده نشود، آزمونِ کشور در
    # پروکسی‌ها بی‌معناست (شکلِ پاسخ عوض شده یا میزبان در دسترس نیست).
    geo_last = "not attempted"
    geo_code: Optional[str] = None
    for _ in range(max(1, attempts)):
        try:
            code, body = fetch(GEO_URL, timeout)
        except Exception as exc:  # noqa: BLE001
            geo_last = f"{type(exc).__name__}: {exc}"
            continue
        geo_code = parse_geo(body) if code == 200 else None
        geo_last = f"{code} gl={geo_code}"
        if geo_code:
            break
    results["geo"] = {"ok": geo_code is not None, "result": geo_last,
                      "expect": "200 + a 2-letter country"}
    return {"ok": all(r["ok"] for r in results.values()), "endpoints": results}


# ──────────────────────────────────────────────────────────────────────────────
# اجرا
# ──────────────────────────────────────────────────────────────────────────────

def read_source_lines(path: str) -> List[str]:
    """خطوطِ کانفیگِ `verified/configs.txt` — بی سرآیند و بی سپرِ `#`."""
    if not os.path.isfile(path):
        return []
    out: List[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            text = line.strip()
            if not text or text.startswith("#") or text.startswith("//"):
                continue
            out.append(text)
    return list(dict.fromkeys(out))


def _rows_of(result: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    rows = result.get("rows")
    if not isinstance(rows, dict):
        raise TypeError(f"unexpected realtest rows shape: {type(rows).__name__}")
    return rows


def default_round(lines: Sequence[str], hard_timeout: int) -> Dict[str, Dict[str, str]]:
    """یک دورِ پنل با همان `realtest` (همان قفل‌های ضدِّ hang و دادهٔ کهنه)."""
    res = realtest.test_lines(
        lines,
        test_urls=[url for _, url, _ in PANEL],
        hard_timeout=hard_timeout,
        threads=int(os.environ.get("GR_THREADS", str(realtest.THREADS))),
    )
    return _rows_of(res)


def _port_free(port: int) -> bool:
    """آیا درگاهِ loopback آزاد است؟ (`SO_REUSEADDR` مثلِ شنوندهٔ Go، تا اتصال‌های
    TIME_WAITِ پروسهٔ قبلی همین اسلات «اشغال» خوانده نشوند)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _wait_port(port: int, proc: "subprocess.Popen[bytes]", timeout: float) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if proc.poll() is not None:
            return False                      # پروسه مُرد ⇒ کانفیگ ساخته نشد
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _curl_fetch(proxy_url: str, url: str, timeout: int) -> Optional[bytes]:
    """بدنه از راهِ SOCKS (پایتون SOCKS ندارد؛ curl روی رانرِ ubuntu هست و
    ورک‌فلو خودش هم از آن استفاده می‌کند). شکست ⇒ None."""
    try:
        proc = subprocess.run(
            ["curl", "-s", "--max-time", str(int(timeout)), "--max-filesize", "262144",
             "-x", proxy_url, url],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout + 5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout if proc.returncode == 0 else None


def judge_readings(readings: Sequence[Optional[str]]) -> Tuple[Optional[str], str]:
    """
    حکم از چند خواندنِ کشور: هر خواندنِ ناپشتیبان ⇒ همان کد (حذف)؛ وگرنه با
    دست‌کم `GEO_MIN_READABLE` خواندنِ موفق ⇒ پرتکرارترین کد؛ وگرنه نامعلوم.
    """
    readable = [r for r in readings if r]
    for r in readable:
        if r not in GEMINI_COUNTRIES:
            return r, "ok"
    if len(readable) < GEO_MIN_READABLE:
        return None, "too_few_readings"
    best = max(sorted(set(readable)), key=readable.count)
    return best, "ok"


def geo_probe(link: str, port: int, *, binary: str, password: str,
              fetch: Callable[[str, str, int], Optional[bytes]] = _curl_fetch,
              ready_timeout: float = GEO_READY_TIMEOUT,
              readings: int = GEO_READINGS) -> Tuple[Optional[str], str]:
    """
    کشورِ دیدِ گوگل برای خروجیِ **یک** کانفیگ: `(کد یا None, چرا)`.

    inbound با `-I socks://gr:<رمز>@127.0.0.1:<درگاه>` ساخته می‌شود (خوانده‌شده
    از `pkg/proxy/service.go::createInbound` و `pkg/core/xray/socks.go` در
    v10.1.1 و آزموده: رمزِ درست پاسخ داد، رمزِ غلط با کدِ ۹۷ رد شد) — پس نه
    متنِ لاگ تجزیه می‌شود و نه پروسهٔ دیگری روی loopback می‌تواند از آن استفاده کند.
    """
    if not _port_free(port):
        return None, "port_busy"
    inbound = f"socks://gr:{password}@127.0.0.1:{port}#gr"
    try:
        proc = subprocess.Popen(
            [binary, "proxy", "inbound", "-c", link, "-I", inbound, "--health-check", "0"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        return None, f"spawn: {exc}"
    try:
        if not _wait_port(port, proc, ready_timeout):
            return None, "inbound_not_ready"
        proxy_url = f"socks5h://gr:{password}@127.0.0.1:{port}"
        seen: List[Optional[str]] = []
        fails: List[str] = []
        for _ in range(max(1, int(readings))):
            body = fetch(proxy_url, GEO_URL, GEO_FETCH_TIMEOUT)
            code = parse_geo(body) if body is not None else None
            if body is None:
                fails.append("fetch_failed")
            elif code is None:
                fails.append("unparsed")
            seen.append(code)
            if code is not None and code not in GEMINI_COUNTRIES:
                break                       # یک خواندنِ ناپشتیبان کافی است
        gl, why = judge_readings(seen)
        if gl is None and why == "too_few_readings" and fails and not any(seen):
            why = fails[-1]                 # هیچ خواندنی نبود ⇒ علتِ واقعی
        return gl, why
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def geo_phase(links: Sequence[str], *,
              deadline_epoch: float = 0.0,
              clock: Callable[[], float] = time.time,
              probe: Optional[Callable[[str, int], Tuple[Optional[str], str]]] = None,
              workers: int = GEO_WORKERS,
              retry_workers: int = GEO_RETRY_WORKERS) -> Dict[str, Dict[str, Any]]:
    """
    کشورِ دیدِ گوگل برای همهٔ `links`: `{link: {"gl": کد|None, "why": ..., "tries": n}}`.

    یک دور با `workers` و سپس یک دورِ تکرار با `retry_workers` برای آن‌هایی که
    پاسخ نگرفتند (سنجش: ۴۳ از ۴۸ پاسخِ خالی در تکرار پر شد). هر کار پیش از
    آغاز، بودجهٔ زمانی را می‌سنجد؛ کاری که جا نشود `deadline` می‌شود و — مثلِ
    هر نامعلومِ دیگری — کانفیگش منتشر نمی‌شود.
    """
    if probe is None:
        binary = realtest.resolve_binary()
        password = secrets.token_hex(12)

        def probe(link: str, port: int) -> Tuple[Optional[str], str]:
            return geo_probe(link, port, binary=binary, password=password)

    results: Dict[str, Dict[str, Any]] = {
        L: {"gl": None, "why": "not_run", "tries": 0} for L in links}
    lock = threading.Lock()

    def run_pass(todo: Sequence[str], n: int) -> None:
        ports: "queue.Queue[int]" = queue.Queue()
        for i in range(n):
            ports.put(GEO_PORT_BASE + i)

        def task(link: str) -> None:
            if deadline_epoch and deadline_epoch - clock() < GEO_TASK_SECONDS:
                gl, why = None, "deadline"
            else:
                port = ports.get()
                try:
                    gl, why = probe(link, port)
                except Exception as exc:  # noqa: BLE001
                    gl, why = None, f"error: {type(exc).__name__}"
                finally:
                    ports.put(port)
            with lock:
                prev = results[link]["tries"]
                results[link] = {"gl": gl, "why": why,
                                 "tries": prev + (0 if why == "deadline" else 1)}

        with ThreadPoolExecutor(max_workers=n) as ex:
            list(ex.map(task, todo))

    run_pass(list(links), max(1, int(workers)))
    retry = [L for L in links if results[L]["gl"] is None and results[L]["why"] != "deadline"]
    if retry:
        run_pass(retry, max(1, int(retry_workers)))
    return results


def default_geo(links: Sequence[str], deadline_epoch: float,
                clock: Callable[[], float]) -> Dict[str, Dict[str, Any]]:
    return geo_phase(links, deadline_epoch=deadline_epoch, clock=clock)


def remove_outputs(out_dir: str) -> List[str]:
    removed: List[str] = []
    for name in (CATEGORY, CATEGORY + ".tmp"):
        path = os.path.join(out_dir, name)
        if os.path.lexists(path):
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            removed.append(name)
    return removed


def _header(count: int, rounds: int) -> str:
    services = ", ".join(f"{name} ({url})" for name, url, _ in SERVICES)
    return (
        core.hiddify_profile_header("GOOGLE READY") +
        f"# @Raydikalx — GOOGLE READY — {count} configs\n"
        f"# criterion: verified AND, in ALL {rounds} runs of this round, a real\n"
        f"# proxied request succeeded to each of: {services}.\n"
        f"# generate_204 must answer exactly 204; Maven and Gemini must answer 2xx\n"
        f"# (Gemini answers 403 to blocked IPs and 404 to CAPTCHA-flagged ones).\n"
        f"# Gemini region: Google itself places the exit IP in a country where the\n"
        f"# Gemini web app is offered (read from {GEO_URL}).\n"
        f"# limits: measured from the CI runner at test time. This does NOT\n"
        f"# promise every Google service, sign-in, account eligibility, or video\n"
        f"# playback.\n")


def write_category(out_dir: str, lines: Sequence[str], rounds: int) -> Dict[str, str]:
    """
    چهار فایلِ استاندارد را در پوشهٔ موقت می‌نویسد و سپس اتمیک جابه‌جا می‌کند.

    اگر حتی یکی از چهار فایل ساخته نشود، کلِ دسته رها می‌شود: `validate.py`
    دستهٔ موجودِ ناقص را `missing` می‌شمارد و با `--strict` **کلِ انتشار** را
    می‌شکست (همان سنجشی که در `pipeline.write_buckets` ثبت شده).
    """
    tmp = os.path.join(out_dir, CATEGORY + ".tmp")
    final = os.path.join(out_dir, CATEGORY)
    if os.path.lexists(tmp):
        shutil.rmtree(tmp)
    head = _header(len(lines), rounds)
    shielded = core.shield_unsupported_runs(list(lines))
    try:
        pipeline._write_lines(os.path.join(tmp, "configs.txt"), head, shielded)
        bodies = (
            ("configs_base64.txt", core.encode_base64_subscription(list(lines), header=head)),
            ("clash.yaml", head + converters.build_clash_yaml(list(lines))),
            ("singbox.json", converters.build_singbox_json(list(lines))),
        )
        for name, body in bodies:
            pipeline._write_lines(os.path.join(tmp, name), "", [body.rstrip("\n")])
        # همان بررسیِ `validate.py::check_singbox` (json.load) — پیش از جابه‌جایی.
        with open(os.path.join(tmp, "singbox.json"), encoding="utf-8") as fh:
            json.load(fh)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    if os.path.lexists(final):
        shutil.rmtree(final)
    os.replace(tmp, final)
    return {name: os.path.join(final, name)
            for name in ("configs.txt", "configs_base64.txt", "clash.yaml", "singbox.json")}


def _load_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        print(f"⚠️ {path} could not be read ({exc})", file=sys.stderr)
        return None
    return doc if isinstance(doc, dict) else None


def _dump_json(path: str, doc: Dict[str, Any]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


CRITERION = ("verified AND, in all rounds, a real proxied request succeeded to "
             "gstatic, YouTube and Play generate_204 (exactly 204), a Google Maven "
             "POM (2xx) and gemini.google.com (2xx: not blocked, not CAPTCHA-flagged) "
             "AND Google places the exit IP in a Gemini-supported country; "
             "measured from the CI runner")


def merge_health(out_dir: str, block: Dict[str, Any]) -> Optional[str]:
    path = os.path.join(out_dir, "health.json")
    doc = _load_json(path) if os.path.exists(path) else None
    if doc is None:
        return None
    doc[CATEGORY] = block
    _dump_json(path, doc)
    return path


def merge_index(out_dir: str, count: int) -> Optional[str]:
    """
    `google` را زیرِ `cascade_categories` تبلیغ می‌کند — **فقط** اگر هر چهار
    فایل روی دیسک باشند. کلیدِ بسته‌ی `categories` دست نمی‌خورد (همان
    قراردادِ `pipeline.merge_index` و تستِ مربوط به آن).
    """
    path = os.path.join(out_dir, "index.json")
    doc = _load_json(path) if os.path.exists(path) else None
    if doc is None:
        return None
    primary = doc.get("primary_base")
    mirror = doc.get("mirror_base") or ""
    cascade = doc.get("cascade_categories")
    if not isinstance(cascade, dict):
        cascade = {}
    cat_dir = os.path.join(out_dir, CATEGORY)
    files: Dict[str, str] = {}
    if isinstance(primary, str) and primary and count > 0:
        for fname, key in (("configs.txt", "configs_txt"),
                           ("configs_base64.txt", "configs_base64"),
                           ("clash.yaml", "clash_yaml"),
                           ("singbox.json", "singbox_json")):
            if not os.path.isfile(os.path.join(cat_dir, fname)):
                files = {}
                break
            files[key] = f"{primary}/{CATEGORY}/{fname}"
            if isinstance(mirror, str) and mirror:
                files[f"{key}_mirror"] = f"{mirror}/{CATEGORY}/{fname}"
    if files:
        cascade[CATEGORY] = {"unique": count, "criterion": CRITERION, "files": files}
    else:
        cascade.pop(CATEGORY, None)
    if cascade:
        doc["cascade_categories"] = cascade
    else:
        doc.pop("cascade_categories", None)
    _dump_json(path, doc)
    return path


def run(out_dir: str, *,
        rounds: Optional[int] = None,
        deadline_epoch: float = 0.0,
        cascade_outcome: str = "success",
        reference: Callable[[], Dict[str, Any]] = reference_check,
        round_fn: Callable[[Sequence[str], int], Dict[str, Dict[str, str]]] = default_round,
        geo_fn: Callable[[Sequence[str], float, Callable[[], float]],
                         Dict[str, Dict[str, Any]]] = default_geo,
        clock: Callable[[], float] = time.time) -> Dict[str, Any]:
    """
    کلِ لایه. همیشه یک بلوکِ گزارش برمی‌گرداند و در `health.json` می‌نویسد؛
    `google/` تنها وقتی وجود دارد که همهٔ شرط‌ها برقرار باشند.
    """
    rounds = ROUNDS if rounds is None else int(rounds)
    if rounds < 1:
        raise ValueError(f"rounds must be >= 1, got {rounds!r}")
    t0 = clock()
    removed = remove_outputs(out_dir)
    block: Dict[str, Any] = {
        "status": "skipped",
        "reason": "",
        "criterion": CRITERION,
        "rounds": rounds,
        "panel": {name: {"url": url, "expect": expect} for name, url, expect in PANEL},
        "removed_previous": removed,
    }

    def finish(status: str, reason: str = "") -> Dict[str, Any]:
        block["status"] = status
        block["reason"] = reason
        block["seconds"] = round(clock() - t0, 2)
        merge_health(out_dir, block)
        merge_index(out_dir, block.get("ready", 0) if status == "published" else 0)
        print(f"→ google: {status}" + (f" ({reason})" if reason else ""))
        return block

    if cascade_outcome != "success":
        # `verified/` ممکن است بایاتِ انتشارِ قبلی باشد ⇒ رویش آزمون نمی‌زنیم.
        return finish("skipped", f"cascade outcome is {cascade_outcome!r}")

    links = read_source_lines(os.path.join(out_dir, SOURCE_CATEGORY, "configs.txt"))
    block["input"] = len(links)
    if not links:
        return finish("skipped", "verified/configs.txt is missing or empty")

    ref = reference()
    block["reference"] = ref
    if not ref.get("ok"):
        return finish("skipped", "reference check failed from the runner itself")

    results: List[Dict[str, Dict[str, str]]] = []
    per_round_seconds: List[float] = []
    for i in range(rounds):
        limit = int(realtest.HARD_TIMEOUT)
        if deadline_epoch:
            remaining = int(deadline_epoch - clock()) - WRITE_RESERVE_SECONDS
            if remaining < MIN_ROUND_SECONDS:
                block["per_round_seconds"] = per_round_seconds
                return finish("skipped",
                              f"time budget: {remaining}s left before round {i + 1}, "
                              f"need >= {MIN_ROUND_SECONDS}s")
            limit = min(limit, remaining)
        t = clock()
        try:
            results.append(round_fn(links, limit))
        except Exception as exc:  # noqa: BLE001
            block["per_round_seconds"] = per_round_seconds
            return finish("failed", f"round {i + 1}: {type(exc).__name__}: {str(exc)[:300]}")
        per_round_seconds.append(round(clock() - t, 2))
    block["per_round_seconds"] = per_round_seconds

    verdict = classify_rounds(links, results)
    block.update({
        "panel_ready": len(verdict["ready"]),
        "fail": len(verdict["fail"]),
        "unknown": len(verdict["unknown"]),
        "judged": len(verdict["ready"]) + len(verdict["fail"]),
        "per_service": verdict["per_service"],
    })
    if not verdict["ready"]:
        block["ready"] = 0
        return finish("empty", "no config passed every endpoint in every round")

    # ── کشورِ Gemini از دیدِ گوگل — فقط روی آنچه پنل را در همهٔ دورها گذراند ──
    if deadline_epoch and deadline_epoch - clock() < GEO_TASK_SECONDS + WRITE_RESERVE_SECONDS:
        block["ready"] = 0
        return finish("skipped", "time budget: no room left for the Gemini region check")
    t = clock()
    try:
        geo = geo_fn(verdict["ready"], deadline_epoch, clock)
    except Exception as exc:  # noqa: BLE001
        block["ready"] = 0
        return finish("failed", f"geo phase: {type(exc).__name__}: {str(exc)[:300]}")
    ready: List[str] = []
    unsupported: Dict[str, int] = {}
    unknown_geo: Dict[str, int] = {}
    kept_countries: Dict[str, int] = {}
    for link in verdict["ready"]:
        entry = geo.get(link) or {}
        gl = entry.get("gl")
        if gl is None:
            why = str(entry.get("why") or "missing")
            unknown_geo[why] = unknown_geo.get(why, 0) + 1
        elif gl in GEMINI_COUNTRIES:
            ready.append(link)
            kept_countries[gl] = kept_countries.get(gl, 0) + 1
        else:
            unsupported[gl] = unsupported.get(gl, 0) + 1
    block["geo"] = {
        "source": GEO_URL,
        "kept_by_country": dict(sorted(kept_countries.items(), key=lambda kv: (-kv[1], kv[0]))),
        "dropped_unsupported_country": dict(sorted(unsupported.items(), key=lambda kv: (-kv[1], kv[0]))),
        "dropped_unknown": unknown_geo,
        "retried": sum(1 for v in geo.values() if (v or {}).get("tries", 0) > 1),
        "seconds": round(clock() - t, 2),
    }
    block["ready"] = len(ready)
    judged = block["judged"]
    block["ready_pct_of_judged"] = round(100.0 * block["ready"] / judged, 2) if judged else 0.0

    if not ready:
        return finish("empty", "no config passed the Gemini region check")
    try:
        write_category(out_dir, ready, rounds)
    except Exception as exc:  # noqa: BLE001
        return finish("failed", f"writing {CATEGORY}/: {type(exc).__name__}: {str(exc)[:300]}")
    return finish("published")


def _main(argv: Sequence[str]) -> int:
    ap = argparse.ArgumentParser(description="Google Ready layer (runs after the cascade)")
    ap.add_argument("--out", default=".", help="output directory (repo root)")
    ap.add_argument("--rounds", type=int, default=None)
    ap.add_argument("--deadline-epoch", type=float, default=0.0,
                    help="unix time by which this step must be done (0 = no deadline)")
    ap.add_argument("--cascade-outcome", default="success",
                    help="outcome of the cascade step; anything but 'success' skips")
    args = ap.parse_args(argv)
    block = run(args.out, rounds=args.rounds, deadline_epoch=args.deadline_epoch,
                cascade_outcome=args.cascade_outcome)
    summary = {k: block.get(k) for k in ("status", "reason", "input", "panel_ready", "ready",
                                         "fail", "unknown", "per_round_seconds", "seconds")}
    geo = block.get("geo") or {}
    summary["geo"] = {k: geo.get(k) for k in ("dropped_unsupported_country", "dropped_unknown",
                                              "retried", "seconds")}
    print(json.dumps(summary, ensure_ascii=False))
    return 1 if block["status"] == "failed" else 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
