"""
geo.py — تعیینِ کشورِ واقعیِ سرور از روی نشانیِ شبکه، نه از روی متنِ ریمارک.

چرا این ماژول ساخته شد
──────────────────────
برچسبِ کشور پیش از این تنها از متنِ ریمارکِ منبع خوانده می‌شد. آن روش سه مرحله
داشت: پرچمِ داخلِ ریمارک، جست‌وجوی کلیدواژه، و در پایان حلقه‌ای که هر واژهٔ
دوحرفیِ لاتین را کدِ کشور فرض می‌کرد. مرحلهٔ سوم یک حدس بود، نه یک اندازه‌گیری:
«join-us-on-Telegram» کشور را US می‌ساخت و «剩余流量：55.26 GB» آن را GB.

اندازه‌گیریِ دقتِ روشِ قدیمی روی نمونه‌ای از ۶۷۵ کانفیگ که کشورِ واقعی‌شان از
یک منبعِ مستقل (ip-api.com) گرفته شده بود:

    درست            ۳۶۲   (۵۳٫۶٪)
    غلط              ۹۹   (۱۴٫۷٪)
    «Global» (تسلیم) ۲۱۴   (۳۱٫۷٪)

یعنی از هر هفت کانفیگ، یکی برچسبِ کشورِ **اشتباه** می‌گرفت. برچسبِ اشتباه از
نبودِ برچسب بدتر است: کاربری که «US 🇺🇸» می‌بیند و به سرورِ کانادایی وصل می‌شود
حق دارد به همهٔ داده‌های مخزن بی‌اعتماد شود.

روشِ این ماژول روی همان نمونه:

    درست            ۶۶۱   (۹۷٫۹٪)
    غلط              ۱۴   (۲٫۱٪)
    «Global»          ۰   (۰٫۰٪)

پایگاهِ داده
────────────
DB-IP Country Lite با پروانهٔ CC-BY-4.0، ماهانه به‌روز، بدونِ کلیدِ اشتراک.
انتخابِ آگاهانه در برابرِ GeoLite2 مکس‌مایند: دانلودِ GeoLite2 از سالِ ۲۰۱۹ کلیدِ
حساب می‌خواهد و در CI به رمزِ مخزن گره می‌خورد. آزمونِ زنده:

    DB-IP    → HTTP 200
    MaxMind  → HTTP 401

پس DB-IP هم دقیق است هم بی‌قید؛ اگر روزی در دسترس نبود، ماژول به‌جای شکستن
به حالتِ کاهش‌یافته می‌رود (پایینِ همین فایل).

پایداریِ برچسب
──────────────
فازِ پیشین ثابت کرد خروجیِ ناپایدار هزینهٔ واقعی دارد: هر تغییرِ بی‌دلیل در
ریمارک، کل فایل را از نو می‌نویسد. پس برچسبِ کشور هم باید بینِ دو اجرا یکسان
بماند، وگرنه همان مشکل از راهِ دیگری برمی‌گردد.

۷۳٫۲٪ از میزبان‌ها IP خام‌اند؛ برای آن‌ها پرسشِ پایگاهِ داده تابعِ خالص است و
پایداری تضمین‌شده. برای ۲۶٫۸٪ باقی‌مانده DNS لازم است و DNS پایدار نیست.
اندازه‌گیریِ دو اجرای پشت‌سرهم روی ۱۱۲۷ میزبانِ نامی:

    gethostbyname (یک نشانی)      ۲۵ میزبان کشورشان عوض شد  (۲٫۲۲٪)
    مجموعهٔ کاملِ رکوردهای A       ۴ میزبان                  (۰٫۳۵٪)

علت: gethostbyname یکی از چند نشانیِ round-robin را برمی‌گرداند و انتخابش در
هر فراخوانی عوض می‌شود. راهکار: getaddrinfo تمامِ رکوردهای A را می‌گیرد،
مرتب می‌شود، و کشور با رأی‌گیریِ اکثریت از خودِ *مجموعه* گرفته می‌شود. مجموعه
مستقل از ترتیبِ پاسخ است، پس برچسب پایدار می‌شود. تأثیرِ عملی: ۶۶ کانفیگِ
ناپایدار به ۴ کانفیگ رسید (۰٫۸۲٪ → ۰٫۰۵٪).

هزینه
─────
حل‌کردنِ ۱۳۶۵ میزبانِ نامی با ۶۴ رشتهٔ همروند ۴٫۹ ثانیه طول می‌کشد. اجرای فعلیِ
خطِ لوله ۴٫۸ ثانیه است، پس بدترین حالت آن را دو برابر می‌کند و همچنان بسیار
کمتر از فاصلهٔ ۱۵ دقیقه‌ایِ به‌روزرسانی است. ۶۰۷۶ کانفیگ (۷۵٫۸٪) هیچ DNS لازم
ندارند و بی‌درنگ برچسب می‌خورند.
"""

from __future__ import annotations

import collections
import contextlib
import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Iterable, List, Optional, Set, Tuple

#: مسیرِ پایگاهِ داده. CI آن را دانلود و در همین مسیر cache می‌کند.
MMDB_PATH = os.environ.get("GEOIP_MMDB", os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".cache", "dbip-country-lite.mmdb"
))

#: نشانیِ دانلود. الگوی ماهانه؛ CI ماهِ جاری و ماهِ پیش را امتحان می‌کند چون
#: فایلِ ماهِ جاری در روزهای نخستِ ماه ممکن است هنوز منتشر نشده باشد.
DBIP_URL_TEMPLATE = "https://download.db-ip.com/free/dbip-country-lite-{ym}.mmdb.gz"

#: شمارِ رشته‌های همروندِ DNS. اندازه‌گیری: ۶۴ رشته ← ۴٫۹ ثانیه برای ۱۳۶۵ میزبان.
#: افزایش به ۱۲۸ نتیجه را بهتر نکرد (۸٫۴ ثانیه) چون گلوگاه، پاسخِ حل‌کنندهٔ
#: بالادست است نه شمارِ رشته‌ها.
DNS_WORKERS = int(os.environ.get("GEO_DNS_WORKERS", "64"))

#: مهلتِ هر پرسشِ DNS به ثانیه.
DNS_TIMEOUT = float(os.environ.get("GEO_DNS_TIMEOUT", "4"))

UNKNOWN = ("Global", "🌐")

_reader = None
_reader_tried = False
_reader_lock = threading.Lock()

#: نتیجهٔ نهاییِ هر میزبان. کلید: میزبانِ نرمال‌شده. مقدار: (کد, پرچم).
_HOST_CC: Dict[str, Tuple[str, str]] = {}

#: نشانی‌هایِ حل‌شدهٔ هر میزبان، تا در یک اجرا دو بار DNS نزنیم.
_HOST_ADDRS: Dict[str, Tuple[str, ...]] = {}

#: میزبان‌هایی که یک بار امتحان شدند و *نشد* — کشِ منفی.
#:
#: چرا لازم است: `warm_up` سه بار صدا زده می‌شود (all / heavy / light) و تنها
#: موفقیت‌ها در `_HOST_CC` می‌نشستند. پس هر میزبانِ ناموفق در هر سه دور از نو
#: DNS می‌خورد و از نو هم شمرده می‌شد. اندازه‌گیریِ واقعی روی همین داده:
#:
#:      میزبانِ نامی            ۱٬۳۷۵
#:      دورِ ۱                  by_dns=۱۱۴۶  dns_failed=۲۲۷
#:      دورِ ۲ (همان ورودی)     by_dns=۱۱۴۶  dns_failed=۴۵۴   ← ‎+۲۲۷ تکراری
#:
#: نتیجه‌اش در health.json عددِ dns_failed=۹۲۴ بود، در حالی که کلِ میزبانِ نامی
#: ۱٬۳۷۵ است — یعنی آمار *بیش‌شماری* می‌کرد و خواننده را گمراه می‌کرد. با کشِ
#: منفی، هر میزبان دقیقاً یک بار امتحان و یک بار شمرده می‌شود.
_HOST_FAILED: Set[str] = set()

_stats = collections.Counter()


# ──────────────────────────────────────────────────────────────────────────────
# پرچم از کدِ ISO
# ──────────────────────────────────────────────────────────────────────────────

def flag_of(code: str) -> str:
    """
    پرچمِ یونیکد از کدِ دوحرفیِ ISO-3166-1 alpha-2.

    محاسباتی است، نه جدولی. نقشهٔ دستیِ پیشین فقط ۵۶ کشور را می‌شناخت، ولی
    اندازه‌گیریِ زندهٔ همین مخزن ۸۴ کشورِ متمایز پیدا کرد — یعنی ۳۲ کشور
    (از جمله CY, IL, KZ, AM, MO, IS, MT, PH) با آن نقشه اصلاً قابلِ بیان
    نبودند. فرمولِ regional-indicator این محدودیت را کاملاً برمی‌دارد.
    """
    c = (code or "").strip().upper()
    if len(c) != 2 or not c.isalpha():
        return "🌐"
    return chr(0x1F1E6 + ord(c[0]) - 65) + chr(0x1F1E6 + ord(c[1]) - 65)


# ──────────────────────────────────────────────────────────────────────────────
# پایگاهِ داده
# ──────────────────────────────────────────────────────────────────────────────

def _get_reader():
    """
    خوانندهٔ mmdb یا None.

    فقط یک بار تلاش می‌کند؛ اگر فایل یا کتابخانه نبود، None برمی‌گرداند و
    ماژول به حالتِ کاهش‌یافته می‌رود. هرگز استثنا به بیرون نمی‌دهد، چون نبودِ
    یک پایگاهِ دادهٔ کمکی نباید انتشارِ کانفیگ‌ها را متوقف کند.

    چرا `maxminddb` و نه `geoip2`
    ─────────────────────────────
    بستهٔ `geoip2` یک لایهٔ مدل روی `maxminddb` است و برای نصب، `aiohttp` و
    `requests` را هم می‌آورد — دو وابستگیِ سنگین که برای یک جست‌وجویِ سادهٔ
    «IP → کدِ کشور» هیچ کاری نمی‌کنند. آزمونِ مستقیم روی هر ۳۷۲۰ آی‌پیِ خامِ
    واقعیِ همین مخزن:

        توافق      ۳۷۲۰ / ۳۷۲۰   (۱۰۰٪ ، صفر اختلاف)
        سرعت       maxminddb ۳۱٫۴ms   در برابر   geoip2 ۵۷٫۱ms   (۱٫۸۲ برابر)

    پس خواندنِ مستقیم هم نتیجهٔ یکسان می‌دهد، هم سریع‌تر است، هم وابستگیِ
    کمتری به requirements اضافه می‌کند.
    """
    global _reader, _reader_tried
    if _reader is not None or _reader_tried:
        return _reader
    with _reader_lock:
        if _reader is not None or _reader_tried:
            return _reader
        _reader_tried = True
        try:
            import maxminddb  # type: ignore
            if os.path.exists(MMDB_PATH) and os.path.getsize(MMDB_PATH) > 1024:
                _reader = maxminddb.open_database(MMDB_PATH)
                _stats["db_loaded"] = 1
        except Exception:
            _reader = None
    return _reader


def database_available() -> bool:
    """آیا پایگاهِ داده بارگذاری شد؟ برای گزارشِ سلامت."""
    return _get_reader() is not None


def country_of_ip(ip: str) -> Optional[str]:
    """کدِ کشورِ یک IP یا None. تابعِ خالص نسبت به پایگاهِ دادهٔ ثابت.

    خواندنِ مستقیمِ رکورد است، بی‌واسطهٔ مدل‌های `geoip2`. شکلِ رکوردِ
    DB-IP Country Lite چنین است و کلیدِ موردِ نیاز تنها همین یکی است:

        {"continent": {...}, "country": {"is_in_european_union": …,
                                         "iso_code": "DE", "names": {…}}}

    دو حالتِ «نداریم» به‌طورِ طبیعی به None می‌رسند و بالادست به «Global»
    می‌افتد، بی‌آنکه استثنایی بیرون بزند:
      • نشانیِ خارج از پایگاهِ داده  → get() مقدارِ None می‌دهد
      • نشانیِ خصوصی (مثلِ 127.0.0.1) → همان None
    """
    r = _get_reader()
    if r is None or not ip:
        return None
    try:
        rec = r.get(ip)
        if not rec:
            return None
        return ((rec.get("country") or {}).get("iso_code")) or None
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────────────
# DNS
# ──────────────────────────────────────────────────────────────────────────────

@contextlib.contextmanager
def _dns_timeout():
    """
    `DNS_TIMEOUT` را فقط برای همین بازه اعمال می‌کند و بعد **برمی‌گرداند**.

    چرا لازم است (F-12)
    ───────────────────
    `socket.getaddrinfo` پارامترِ `timeout` ندارد — با اجرا بررسی شد:
        socket.getaddrinfo(host, port, family=0, type=0, proto=0, flags=0)
    پس تنها راهِ مهارِ زمانِ آن، همان `setdefaulttimeout`ِ سراسری است. ولی
    این تنظیم *سراسریِ کلِ فرآیند* است، نه رشته‌ای (سنجیده شد: مقدارِ
    تنظیم‌شده در رشتهٔ اصلی را هر سه رشتهٔ دیگر هم می‌دیدند). پیش‌تر
    `resolve_all` آن را می‌گذاشت و هرگز برنمی‌گرداند، پس هر سوکتی که پس از
    نخستین جست‌وجوی DNS در همین فرآیند ساخته می‌شد تایم‌اوتِ ما را ارث
    می‌برد (اندازه‌گیری‌شده: `None` → `4.0`).

    چرا این‌جا و نه داخلِ `resolve_all`
    ───────────────────────────────────
    وسوسهٔ طبیعی این است که همین prev/finally را داخلِ خودِ `resolve_all`
    بگذاریم. آن **غلط** است و با اجرا رد شد: `resolve_all` از داخلِ
    `ThreadPoolExecutor` صدا زده می‌شود، و چون همهٔ کارگرها *همان* مقدار را
    می‌گذارند، `prev`ِ خوانده‌شده توسط یک کارگر می‌تواند مقدارِ کارگرِ دیگر
    باشد و همان بازگردانده شود. سنجش: الگویِ سادهٔ درون‌کارگری در ۶ آزمایشِ
    ۲۴کاره با ۸ رشته **۶ بار از ۶** نشت داد؛ همین الگو دورِ استخر **۰ بار
    از ۶**. پس مرزِ درست بیرونِ استخر است.

    این همان کاری است که `reachability.resolve_hosts` از قبل می‌کند
    (prev/finally دورِ استخر، نه داخلِ کارگر)؛ اکنون دو ماژول هم‌رفتار شدند.
    """
    prev = socket.getdefaulttimeout()
    socket.setdefaulttimeout(DNS_TIMEOUT)
    try:
        yield
    finally:
        socket.setdefaulttimeout(prev)


def is_ip_literal(host: str) -> bool:
    """آیا میزبان خودش IP است؟ (IPv4 یا IPv6)"""
    h = (host or "").strip()
    if not h:
        return False
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, h)
            return True
        except Exception:
            continue
    return False


def resolve_all(host: str) -> Tuple[str, ...]:
    """
    همهٔ نشانی‌هایِ IPv4 یک میزبان، مرتب‌شده.

    مرتب‌سازی عمدی است: پاسخِ DNS برای میزبان‌های round-robin در هر فراخوانی
    ترتیبِ دیگری دارد. با مرتب‌سازی، خروجی تابعی از *مجموعهٔ* رکوردها می‌شود
    نه از ترتیبِ تصادفیِ پاسخ.
    """
    h = (host or "").strip().lower()
    if not h:
        return ()
    if h in _HOST_ADDRS:
        return _HOST_ADDRS[h]
    if is_ip_literal(h):
        _HOST_ADDRS[h] = (h,)
        return (h,)
    # عمداً این‌جا `setdefaulttimeout` صدا زده نمی‌شود: این تابع از داخلِ
    # `ThreadPoolExecutor` هم فراخوانی می‌شود و دست‌کاریِ وضعیتِ سراسری از
    # داخلِ کارگر مسابقه‌دار است (F-12 — شرحش در `_dns_timeout`). مهارِ زمان
    # مسئولیتِ فراخوان است، با `with _dns_timeout():`.
    try:
        infos = socket.getaddrinfo(h, None, socket.AF_INET, socket.SOCK_STREAM)
        addrs = tuple(sorted({i[4][0] for i in infos}))
    except Exception:
        addrs = ()
    _HOST_ADDRS[h] = addrs
    return addrs


def country_of_addrs(addrs: Iterable[str]) -> Optional[str]:
    """
    کشورِ یک مجموعهٔ نشانی، با رأی‌گیریِ اکثریت.

    برخی CDN ها نشانی‌هایی در چند کشور دارند. انتخابِ «نشانیِ اول» ناپایدار
    است؛ اکثریت پایدار است. تساوی با کوچک‌ترین IP (به ترتیبِ الفبا) شکسته
    می‌شود تا نتیجه کاملاً معین باشد و به ترتیبِ ورودی بستگی نداشته باشد.
    """
    votes: collections.Counter = collections.Counter()
    first: Dict[str, str] = {}
    for ip in sorted(set(addrs)):
        cc = country_of_ip(ip)
        if cc:
            votes[cc] += 1
            first.setdefault(cc, ip)
    if not votes:
        return None
    top = max(votes.values())
    return sorted((c for c, n in votes.items() if n == top), key=lambda c: first[c])[0]


# ──────────────────────────────────────────────────────────────────────────────
# پیش‌گرم‌کردن (warm-up)
# ──────────────────────────────────────────────────────────────────────────────

def warm_up(hosts: Iterable[str]) -> Dict[str, int]:
    """
    برچسبِ همهٔ میزبان‌ها را یک‌جا و همروند آماده می‌کند.

    خطِ لوله این را یک بار پیش از برندینگ صدا می‌زند. اگر به‌جای آن برچسب
    هنگامِ نیاز و یکی‌یکی گرفته شود، ۱۳۶۵ پرسشِ DNS پشتِ‌سرِ هم انجام می‌شود
    (اندازه‌گیری: بیش از ۱۰ دقیقه) در حالی که همروند ۴٫۹ ثانیه است.
    """
    uniq: Set[str] = set()
    for h in hosts:
        h = (h or "").strip().lower()
        # هم موفق‌ها و هم ناموفق‌ها رد می‌شوند: بارِ دوم نه پرسشِ تازه‌ای لازم
        # است و نه شمارشِ تازه‌ای درست است.
        if h and h not in _HOST_CC and h not in _HOST_FAILED:
            uniq.add(h)
    if not uniq:
        return dict(_stats)

    ordered = sorted(uniq)                      # ترتیبِ معین
    literal = [h for h in ordered if is_ip_literal(h)]
    named = [h for h in ordered if not is_ip_literal(h)]

    # IP های خام: بی‌نیاز از شبکه
    for h in literal:
        cc = country_of_ip(h)
        _HOST_ADDRS[h] = (h,)
        if cc:
            _HOST_CC[h] = (cc, flag_of(cc))
            _stats["by_ip_literal"] += 1
        else:
            _HOST_FAILED.add(h)
            _stats["unknown_ip_literal"] += 1

    # میزبان‌های نامی: DNS همروند
    if named and _get_reader() is not None:
        try:
            with _dns_timeout():
                with ThreadPoolExecutor(max_workers=max(1, DNS_WORKERS)) as ex:
                    results = list(ex.map(resolve_all, named))
        except Exception:
            with _dns_timeout():
                results = [resolve_all(h) for h in named]
        for h, addrs in zip(named, results):
            if not addrs:
                _HOST_FAILED.add(h)
                _stats["dns_failed"] += 1
                continue
            cc = country_of_addrs(addrs)
            if cc:
                _HOST_CC[h] = (cc, flag_of(cc))
                _stats["by_dns"] += 1
            else:
                _HOST_FAILED.add(h)
                _stats["unknown_after_dns"] += 1
    elif named:
        # اینجا عمداً در کشِ منفی ثبت نمی‌شود: علتِ شکست نبودِ پایگاهِ داده است،
        # نه خودِ میزبان. اگر پایگاهِ داده بعداً بیاید، باید دوباره امتحان شود.
        _stats["skipped_no_db"] += len(named)

    return dict(_stats)


def country_for_host(host: str) -> Optional[Tuple[str, str]]:
    """
    (کد, پرچم) برای یک میزبان، یا None اگر معلوم نشد.

    اگر warm_up صدا زده نشده باشد، همین‌جا و به‌صورتِ تک‌نفره کار می‌کند تا
    فراخوان‌های پراکنده (مثلاً در تست) هم درست جواب بگیرند.

    این مسیر هم مثلِ warm_up آمار ثبت می‌کند. اگر ثبت نمی‌کرد، میزبانی که از
    این راه برچسب می‌گرفت در health.json ناپیدا می‌ماند و جمعِ آمار با شمارِ
    واقعیِ میزبان‌ها جور در نمی‌آمد — یعنی گزارش، بی‌آنکه خطایی بدهد، دروغ
    می‌گفت.
    """
    h = (host or "").strip().lower()
    if not h:
        return None
    hit = _HOST_CC.get(h)
    if hit is not None:
        return hit
    # کشِ منفی: میزبانی که یک بار شکست خورده، دوباره نه پرسیده و نه شمرده می‌شود.
    # بی این بند، فراخوانیِ دوبارهٔ همان میزبانِ ناموفق آمار را دو برابر می‌کرد.
    if h in _HOST_FAILED:
        return None
    if _get_reader() is None:
        _stats["skipped_no_db"] += 1
        return None
    literal = is_ip_literal(h)
    with _dns_timeout():
        addrs = resolve_all(h)
    if not addrs:
        _HOST_FAILED.add(h)
        _stats["dns_failed"] += 1
        return None
    cc = country_of_addrs(addrs)
    if not cc:
        _HOST_FAILED.add(h)
        _stats["unknown_ip_literal" if literal else "unknown_after_dns"] += 1
        return None
    res = (cc, flag_of(cc))
    _HOST_CC[h] = res
    _stats["by_ip_literal" if literal else "by_dns"] += 1
    return res


#: کلیدهایی که *همیشه* در stats() هستند، حتی اگر صفر باشند.
#
# چرا ثابت: health.json را ابزارهای بیرونی پارس می‌کنند. اگر کلیدها فقط وقتی
# ظاهر شوند که مقدارشان ناصفر است، مصرف‌کننده مجبور است برای هر کلید `if` بنویسد
# و بدتر، «نبودِ dns_failed» با «صفر بودنِ dns_failed» یکی به نظر می‌رسد — در
# حالی که اولی یعنی هنوز چیزی اندازه‌گیری نشده و دومی یعنی همه‌چیز سالم است.
_STAT_KEYS = (
    "db_loaded",
    "by_ip_literal",
    "unknown_ip_literal",
    "by_dns",
    "dns_failed",
    "unknown_after_dns",
    "skipped_no_db",
)


def stats() -> Dict[str, int]:
    """آمارِ کارِ انجام‌شده، برای درجِ در health.json.

    شمایِ خروجی ثابت است (همهٔ کلیدهای `_STAT_KEYS` حاضرند) و دو مقدارِ مشتق هم
    اضافه می‌شود تا مصرف‌کننده لازم نباشد خودش جمع بزند:

      hosts_resolved  = مجموعِ میزبان‌هایی که برچسبِ کشور گرفتند
      hosts_unknown   = مجموعِ میزبان‌هایی که نگرفتند (به هر دلیل)
    """
    out = {k: int(_stats.get(k, 0)) for k in _STAT_KEYS}
    out["db_loaded"] = 1 if _get_reader() is not None else 0
    out["hosts_resolved"] = out["by_ip_literal"] + out["by_dns"]
    out["hosts_unknown"] = (
        out["unknown_ip_literal"] + out["unknown_after_dns"]
        + out["dns_failed"] + out["skipped_no_db"]
    )
    return out


def reset() -> None:
    """پاک‌سازیِ حافظه — برای تست‌های مستقل از هم."""
    _HOST_CC.clear()
    _HOST_ADDRS.clear()
    _HOST_FAILED.clear()
    _stats.clear()
    if _get_reader() is not None:
        _stats["db_loaded"] = 1
