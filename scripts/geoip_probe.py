#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""geoip_probe.py — «این فایلِ mmdb *واقعاً* مالِ کدام ماه است؟»

چرا این ابزار ساخته شد
──────────────────────
کلیدِ cache در گیت‌هاب فقط یک **نام** است و می‌تواند دروغ بگوید. نقصِ
اندازه‌گیری‌شده‌ای که این فایل برای بستنش نوشته شده، دقیقاً همین بود:

    ۱) اولِ ماه، فایلِ ماهِ جاری هنوز منتشر نشده و ۴۰۴ می‌دهد
       (اندازه‌گیریِ `Last-Modified`ِ سرور: انتشار حدودِ ۰۶:۳۰–۰۶:۴۵ UTC
        روزِ اول ⇒ ~۶٫۶ ساعت پنجرهٔ ۴۰۴؛ با `cron: */5` احتمالِ افتادنِ
        دستِ‌کم یک اجرا در آن پنجره عملاً ۱ است)
    ۲) `restore-keys` بایتِ **ماهِ پیش** را بازمی‌گرداند
    ۳) گامِ `actions/cache` در post-step همان بایت را زیرِ کلیدِ **ماهِ
       جاری** ذخیره می‌کند
    ۴) کلیدهای cache تغییرناپذیرند ⇒ از آن پس `cache-hit` صادق می‌شود،
       گامِ دانلود skip می‌شود و پایگاهِ داده **تا آخرِ ماه** کهنه می‌ماند

اثرِ این کهنگی حدس نیست، سنجیده شده: روی ۳۱۱۹ هاستِ واقعیِ همین مخزن،
پایگاهِ دادهٔ یک‌ماه‌کهنه ۱۴۳ برچسبِ کشور (۴٫۵۹٪) را متفاوت — یعنی
غلط — می‌داد. و برچسبِ غلط از نبودِ برچسب بدتر است.

چرا «محتوا» و نه «نامِ کلید»
────────────────────────────
خودِ فایلِ mmdb ماهش را در متادیتا حمل می‌کند (`build_epoch`). آزمونِ
زنده روی هر دو نسخهٔ موجود:

    2026-07 → build_epoch=1782869996 → 2026-07  ✓
    2026-08 → build_epoch=1785548229 → 2026-08  ✓

و همین با یک رمزگشای مستقلِ متادیتا (پایتونِ خالص، بی‌وابستگی) هم
راستی‌آزمایی شد: مقدارها **یکسان**. چون داوری بر پایهٔ محتواست،
cacheِ از قبل آلوده هم خودش را ترمیم می‌کند — چیزی که با تکیه بر نامِ
کلید **ناممکن** است، چون کلید دیگر قابلِ بازنویسی نیست.

چرا گاردِ اندازه به‌تنهایی کافی نیست
────────────────────────────────────
اندازه‌گیری شد: یک آرشیوِ نیمه‌تمام ۳٬۷۷۲٬۹۰۹ بایت mmdb تولید می‌کند —
یعنی از آستانهٔ یک‌مگابایتی رد می‌شود — ولی `maxminddb.open_database()`
رویش `InvalidDatabaseError` می‌دهد. پس «اندازه» با «اعتبار» یکی نیست.

قراردادِ خروجی
──────────────
دو خط روی stdout، به شکلِ `key=value` تا مستقیماً به `$GITHUB_OUTPUT`
اضافه شود:

    status=<absent|unverifiable|corrupt|wrongtype|badlookup|stale|current>
    ym=<YYYY-MM یا خالی>

★ این ابزار **همیشه** با کدِ ۰ خارج می‌شود. دلیلش رفتاری است، نه
سلیقه‌ای: گامِ فراخوان `set -euo pipefail` دارد، پس هر خروجِ ناصفر کلِ
گام را می‌کشت و همان «شکستِ پرصدا»یی می‌شد که این فایل قرار است از آن
جلوگیری کند. نبودِ یک پایگاهِ دادهٔ **کمکی** نباید انتشارِ کانفیگ‌ها را
متوقف کند.

چرا `unverifiable` جدا از `corrupt` است
───────────────────────────────────────
اگر `maxminddb` نصب نباشد، هیچ داوریِ محتوایی ممکن نیست. یکی‌کردنِ این
حالت با `corrupt` باعث می‌شد هر فایلی رد شود و خط‌لوله **بدتر از امروز**
عمل کند (هیچ‌وقت پایگاهِ داده‌ای نداشته باشد). با برچسبِ جداگانه،
فراخوان می‌تواند به رفتارِ امروز — گاردِ اندازه — عقب‌نشینی کند.

اجرا:
    python scripts/geoip_probe.py <mmdb-path> [YYYY-MM]
"""

from __future__ import annotations

import datetime
import os
import sys
from typing import Optional, Tuple

#: کمینهٔ اندازهٔ باورپذیر. نسخه‌های واقعی ۸٬۱۸۲٬۱۳۵ و ۸٬۲۸۴٬۲۰۷ بایت
#: اندازه‌گیری شدند، پس یک مگابایت با فاصلهٔ ایمنِ ~۸ برابری زیرِ آن است.
#: این عدد عمداً همان آستانهٔ گامِ قبلیِ ورک‌فلو است تا رفتار عقب نرود.
MIN_SIZE = 1_000_000

#: نامی که DB-IP در متادیتا می‌گذارد (از خودِ فایلِ واقعی خوانده شد،
#: نه از مستندات).
EXPECTED_TYPE = "DBIP-Country-Lite"

#: نشانی‌هایی با کشورِ پایدار و مستند، به‌عنوانِ آزمونِ سلامتِ محتوا.
#: همین جفت‌ها در گامِ «Verify GeoIP database»ِ ورک‌فلو هم استفاده
#: می‌شوند؛ عمداً یکسان‌اند تا دو سنجه با هم اختلاف پیدا نکنند.
SANITY = (("8.8.8.8", "US"), ("1.1.1.1", "AU"))


def month_of_epoch(epoch: int) -> str:
    """`build_epoch` را به `YYYY-MM`ِ UTC تبدیل می‌کند.

    چرا UTC صریح: بی‌آن، `fromtimestamp` منطقهٔ زمانیِ ماشین را می‌گیرد و
    نتیجه روی یک runnerِ غیرUTC می‌توانست یک ماه بلغزد — یعنی همان نقصی
    که این ابزار برای گرفتنش نوشته شده، از راهِ دیگری برمی‌گشت.
    """
    return datetime.datetime.fromtimestamp(
        epoch, datetime.timezone.utc).strftime("%Y-%m")


def inspect_database(path: str) -> Tuple[str, str]:
    """`(status, ym)` را برای یک فایلِ mmdb برمی‌گرداند.

    هیچ استثنایی از این تابع بیرون نمی‌زند: هر خطا به یک برچسبِ وضعیت
    ترجمه می‌شود، چون فراخوان زیرِ `set -e` است.
    """
    if not os.path.isfile(path):
        return "absent", ""
    try:
        if os.path.getsize(path) < MIN_SIZE:
            return "absent", ""
    except OSError:
        return "absent", ""

    try:
        import maxminddb  # noqa: PLC0415  (وارداتِ تنبل — عمدی، پایین)
    except Exception:  # noqa: BLE001
        # نه `corrupt`: نبودِ ابزار دربارهٔ فایل هیچ نمی‌گوید.
        return "unverifiable", ""

    try:
        with maxminddb.open_database(path) as reader:
            meta = reader.metadata()
            if meta.database_type != EXPECTED_TYPE:
                return "wrongtype", ""
            for ip, expected in SANITY:
                record = reader.get(ip)
                got = None
                if isinstance(record, dict):
                    country = record.get("country")
                    if isinstance(country, dict):
                        got = country.get("iso_code")
                if got != expected:
                    return "badlookup", ""
            return "ok", month_of_epoch(int(meta.build_epoch))
    except Exception:  # noqa: BLE001
        # هر چیزی که خواندنِ فایل را ناممکن کند: کوتاه‌شدگی، بایتِ
        # تصادفی، متادیتای ناقص. اندازه‌گیری: gzip خودش ۴۰/۴۰ خرابیِ
        # درون‌جریانی را می‌گیرد، و این لایه بازمانده‌ها را می‌گیرد.
        return "corrupt", ""


def probe(path: str, want: str = "") -> Tuple[str, str]:
    """داوریِ نهایی: آیا فایل همان ماهِ خواسته‌شده است؟"""
    status, ym = inspect_database(path)
    if status != "ok":
        return status, ym
    if want and ym == want:
        return "current", ym
    return "stale", ym


def main(argv: Optional[list] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        # بی‌مسیر هم نباید بشکند: فراخوان انتظارِ دو خطِ خروجی دارد.
        print("status=absent")
        print("ym=")
        return 0
    path = args[0]
    want = args[1] if len(args) > 1 else ""
    try:
        status, ym = probe(path, want)
    except Exception:  # noqa: BLE001
        # آخرین سنگر: حتی یک نقصِ پیش‌بینی‌نشده در همین فایل هم نباید
        # گامِ ورک‌فلو را بکشد.
        status, ym = "corrupt", ""
    print(f"status={status}")
    print(f"ym={ym}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
