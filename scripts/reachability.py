#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
لایهٔ L2 — سنجشِ دسترسی‌پذیریِ TCP (فاز B، بندِ B2).

جایگاهِ این لایه در آبشار:

    L0  یکتاسازیِ نقطهٔ پایانی    ← filters.py
    L1  پالایشِ ارزانِ بی‌شبکه     ← filters.py
    L2  دست‌دادنِ TCP             ← همین ماژول
    L3  آزمونِ واقعیِ پروکسی      ← realtest.py

L2 برای این هست که L3 گران است. هر آزمونِ واقعیِ پروکسی یک هستهٔ کامل بالا
می‌آورد، پس هر نقطهٔ پایانی که سوکتش هم باز نمی‌شود، اتلافِ محض است.

──────────────────────────────────────────────────────────────────────────────
چهار تصمیمِ طراحی، هرکدام پشتِ یک اندازه‌گیری — نه پشتِ شهود
──────────────────────────────────────────────────────────────────────────────

۱) DNS از TCP جدا است.
   `asyncio.open_connection(host, port)` نام را با `getaddrinfo` در
   «executorِ پیش‌فرضِ» asyncio حل می‌کند و آن استخر فقط
   min(32, nproc + 4) رشته دارد؛ روی این runner با nproc=2 یعنی **۶ رشته**.
   نتیجه: هر عددی که برای conc بگذاریم بی‌معنا می‌شد، چون گلوگاهِ واقعی
   DNS بود نه سوکت. پس ابتدا همهٔ نام‌ها یک‌بار با استخرِ اختصاصیِ ۶۴ رشته
   حل می‌شوند و سپس TCP فقط روی IP کار می‌کند.

۲) هم‌روندی ۸۰۰، و این سقف است نه سلیقه.
   سنجشِ واقعی روی ۸٬۰۲۸ کانفیگ (۶٬۹۲۱ نقطهٔ پایانیِ یکتا):

       conc=200  → ۵۳٫۸۷ ثانیه
       conc=400  → ۳۰٫۶۳ ثانیه
       conc=800  → ۱۹٫۴۵ ثانیه، اوجِ fd = ۸۰۶، EMFILE = ۰
       conc=1200 → **فروپاشی**: ۵٬۷۰۰ خطای EMFILE، نرخِ سنجیده‌شده از
                   ۴۸٫۰٪ به ۱٫۱٪ سقوط کرد — و **کدِ خروج ۰ بود**

   `ulimit -n` نرم روی این ماشین ۱۰۲۴ است. conc=800 نزدیک‌ترین توانِ دو
   به آن سقف است که هنوز جا برای fdهای دیگرِ فرآیند می‌گذارد.

۳) EMFILE جداگانه شمرده می‌شود، و کمبودِ fd خطای مرگبار است.
   بندِ ۲ فقط به این دلیل کشف شد که errno 24 جدا از «رد شد» شمرده می‌شد.
   اگر همه‌ی OSError ها یک‌جا «ناموفق» حساب شوند، فروپاشیِ fd به شکلِ
   «۹۹٪ سرورها خراب‌اند» ظاهر می‌شود و کسی نمی‌فهمد ابزار خراب بوده.
   این‌جا هر EMFILE باعثِ استثنا در پایانِ اجرا می‌شود، نه یک خطِ لاگ.

   و ناوردای دومی هم هست: «هیچ سوکتی پس از سنجش باز نماند». این یکی با
   شمارشِ **سوکت‌ها** داوری می‌شود، نه با اختلافِ کلِ fdهای فرآیند — چون
   سنجهٔ کل با اجرا در هر دو جهت خطادار ثابت شد (F-13؛ شرح در
   `socket_fd_count`).

۴) تا سه نشانیِ هر میزبان آزموده می‌شود، نه فقط نشانیِ اول.
   سنجشِ واقعی روی همان مجموعه: ۴۳۹ میزبان بیش از یک نشانی دارند
   (۵۶۴ نقطهٔ پایانی، ۷۶۶ کانفیگ). روی همین زیرمجموعه:

       سقف ۱ نشانی → ۳۹۰ نقطه باز   (۶٬۷۰۴ کاوش)
       سقف ۲ نشانی → ۴۰۶ نقطه باز   (۷٬۲۶۸ کاوش)
       سقف ۳ نشانی → ۴۰۹ نقطه باز   (۷٬۶۳۸ کاوش)  ← انتخاب‌شده
       سقف ۴ نشانی → ۴۰۹ نقطه باز   (۷٬۹۸۰ کاوش)  — هیچ سودی
       بی‌سقف      → ۴۱۱ نقطه باز   (۸٬۵۶۰ کاوش)

   یعنی «فقط نشانیِ اول» ۲۱ نقطه از ۴۱۱ (۵٫۱٪) را از دست می‌داد، و سقفِ ۳
   با ۱۳٫۹٪ کاوشِ بیشتر ۹۹٫۵٪ آن‌ها را بازمی‌گرداند.

──────────────────────────────────────────────────────────────────────────────
چرا `geo.resolve_all` بازاستفاده نمی‌شود؟
──────────────────────────────────────────────────────────────────────────────
قاعدهٔ همین فاز «واگذار کن، بازنویسی نکن» است (و `filters.py` همین کار را با
`converters` می‌کند). ولی این‌جا سنجش خلافش را نشان داد: `geo.resolve_all`
عمداً `socket.AF_INET` است، چون برچسبِ کشور از پایگاهِ IPv4 خوانده می‌شود.
مقایسه روی ۱٬۳۵۴ میزبانِ نامیِ واقعی:

    geo.resolve_all  → ۱٬۱۶۵ حل‌شده
    این ماژول        → ۱٬۱۶۲ حل‌شده

اختلاف با تکرار داوری شد، نه با حدس: چهار موردِ «فقط geo» نوسانِ گذرای DNS
بود (یکی‌شان در تکرار جهت عوض کرد)، ولی `litev6.abalahrar.ir` در ۳ تکرار از
۳ تکرار **فقط IPv6** داشت و `AF_INET` هر سه بار `gaierror` داد. برای
برچسبِ کشور از‌دست‌رفتنش بی‌اهمیت است؛ برای «آیا وصل می‌شود؟» یک نتیجهٔ
نادرست است. پس این‌جا `AF_UNSPEC` لازم است و واگذاری ممکن نیست.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ──────────────────────────────────────────────────────────────────────────────
# پارامترها — همه از سنجش آمده‌اند و همه با محیط قابلِ تنظیم‌اند
# ──────────────────────────────────────────────────────────────────────────────

#: هم‌روندیِ TCP. ۸۰۰ سقفِ سنجیده‌شده روی ulimit نرمِ ۱۰۲۴ است (بندِ ۲ سند).
CONCURRENCY = int(os.environ.get("L2_CONCURRENCY", "800"))

#: مهلتِ دست‌دادنِ TCP. سنجشِ B0.4: بازیابی در ۱ و ۲ و ۳ و ۵ ثانیه یکسان بود،
#: پس کوچک‌ترین عددی که حاشیهٔ امن دارد انتخاب شد.
TCP_TIMEOUT = float(os.environ.get("L2_TCP_TIMEOUT", "3"))

#: رشته‌های استخرِ DNS. مقدارِ `geo.py` هم همین است؛ عمداً هم‌تراز.
DNS_WORKERS = int(os.environ.get("L2_DNS_WORKERS", "64"))

#: مهلتِ هر پرسشِ DNS.
DNS_TIMEOUT = float(os.environ.get("L2_DNS_TIMEOUT", "4"))

#: بیشترین نشانیِ آزمودنی برای هر میزبان (بندِ ۴ سند: ۳ → ۹۹٫۵٪ بازیابی).
ADDR_CAP = int(os.environ.get("L2_ADDR_CAP", "3"))

#: مرزِ ایمنِ fd. اگر conc از این بالاتر بزند، پیش از سوختن هشدار می‌دهیم.
_FD_HEADROOM = 200

ERR_TIMEOUT = "timeout"
ERR_REFUSED = "refused"
ERR_UNREACHABLE = "unreachable"
ERR_DNS = "dns_failed"
ERR_EMFILE = "emfile"
ERR_OTHER = "other"
ALL_ERRORS = (ERR_TIMEOUT, ERR_REFUSED, ERR_UNREACHABLE, ERR_DNS,
              ERR_EMFILE, ERR_OTHER)


class FileDescriptorExhaustion(RuntimeError):
    """
    کمبودِ fd رخ داده — نتیجه دورانداختنی است، نه گزارش‌کردنی.

    چرا استثنا و نه لاگ؟ چون در سنجشِ conc=1200 فرآیند با کدِ خروجِ ۰ تمام
    شد و «۱٫۱٪ کارکرد» گزارش داد، در حالی که واقعیت ۴۸٪ بود. یک شکستِ
    خاموشِ ۴۴ برابری. تنها راهِ جلوگیری این است که خطا صدا داشته باشد.
    """


# ──────────────────────────────────────────────────────────────────────────────
# مرحلهٔ DNS
# ──────────────────────────────────────────────────────────────────────────────

def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip().strip("[]"))
        return True
    except ValueError:
        return False


def _resolve_one(host: str) -> Tuple[str, Tuple[str, ...]]:
    """
    همهٔ نشانی‌های یک میزبان، مرتب‌شده و بی‌تکرار.

    `AF_UNSPEC` (پیش‌فرضِ getaddrinfo) عمدی است: میزبانِ فقط-IPv6 در دادهٔ
    واقعیِ همین مخزن وجود دارد و با `AF_INET` نامرئی می‌شد.

    مرتب‌سازی هم عمدی است: پاسخِ round-robin هر بار ترتیبِ دیگری دارد، و بی
    مرتب‌سازی «سه نشانیِ اول» در هر اجرا مجموعهٔ دیگری می‌شد — یعنی نتیجه
    غیرِقطعی و ناقابلِ بازتولید.
    """
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception:
        return host, ()
    return host, tuple(sorted({i[4][0] for i in infos}))


def resolve_hosts(hosts: Iterable[str]) -> Tuple[Dict[str, Tuple[str, ...]], float]:
    """نام → نشانی‌ها، همروند. IPِ خام بی‌درنگ برمی‌گردد (بی هیچ پرسشی)."""
    out: Dict[str, Tuple[str, ...]] = {}
    named: List[str] = []
    for h in hosts:
        h = (h or "").strip()
        if not h:
            continue
        if _is_ip(h):
            out[h] = (h.strip("[]"),)
        else:
            named.append(h)

    t0 = time.monotonic()
    if named:
        named = sorted(set(named))          # ترتیبِ معین برای بازتولیدپذیری
        prev = socket.getdefaulttimeout()
        socket.setdefaulttimeout(DNS_TIMEOUT)
        try:
            with ThreadPoolExecutor(max_workers=max(1, DNS_WORKERS)) as ex:
                for h, addrs in ex.map(_resolve_one, named):
                    out[h] = addrs
        finally:
            socket.setdefaulttimeout(prev)
    return out, time.monotonic() - t0


# ──────────────────────────────────────────────────────────────────────────────
# مرحلهٔ TCP
# ──────────────────────────────────────────────────────────────────────────────

def fd_count() -> int:
    """تعدادِ fdِ بازِ همین فرآیند؛ ‎-1 اگر /proc نبود."""
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return -1


def socket_fd_count() -> int:
    """
    شمارِ fdهایی که **سوکت** اند؛ ‎-1 اگر ‎/proc‏ نبود (همان قراردادِ
    `fd_count`).

    ── چرا این تابع لازم شد (F-13) ──────────────────────────────────────────
    ناوردای «نشتِ سوکت» پیش‌تر با *اختلافِ کلِ* fdهای فرآیند سنجیده می‌شد:

        if fd_before >= 0 and fd_after > fd_before:  raise ...

    آن سنجه، سنجهٔ چیزی نبود که ادعا می‌کرد. با اجرا (نه با حدس) هر دو
    جهتِ خطا ثابت شد:

    ۱) **مثبتِ کاذب** — یک `open(os.devnull)` بی‌آزار که در بازهٔ سنجش
       (سطرهای ۲۸۹..۳۰۱) باز شود و زنده بماند، اجرایی کاملاً سالم را باطل
       می‌کرد: «‎4 open before, 5 after‏». هیچ سوکتی نشت نکرده بود.
       بازهٔ سنجش شاملِ `resolve_hosts` و `asyncio.run` است، پس هر منبعِ
       تنبلِ درونِ آن — پروندهٔ نهانگاه، importِ درون‌تابعی، دستهٔ لاگ —
       همین را می‌ساخت.

    ۲) **منفیِ کاذب** (این نیمه در گزارشِ اولیه دیده نشده بود) — اختلافِ
       کل، الکی **دوسویه** است. با نشت دادنِ عمدیِ ۲ سوکتِ واقعی و بستنِ
       ۲ fdِ بی‌ربط در همان بازه، اختلاف صفر شد و محافظ **ساکت** ماند:
       یک نشتِ واقعی از کنارِ گاردی که برای دیدنش ساخته شده بود گذشت.

    ۳) و متنِ استثنا در حالتِ (۱) می‌گفت «Every probed socket must be
       closed» — یعنی تشخیص را به سمتِ کدی می‌بُرد که هیچ ایرادی نداشت.

    ── چرا `socket:` و چرا این سنجه دقیق است ────────────────────────────────
    `/proc/self/fd/N` یک پیوندِ نمادین است که برای سوکت‌ها با `socket:[…]`
    آغاز می‌شود (سنجیده شد: fd سوکتی از fdِ پرونده و از `pipe:[…]`ِ
    self-pipeِ حلقهٔ رویداد قابلِ تفکیک است). پس «سوکتِ بازمانده» را
    می‌توان **مستقیم** شمرد، نه از راهِ یک عددِ کلِ نیابتی.

    این سنجه هرگز *بدتر* از سنجهٔ قبلی نیست: هر سوکتِ نشت‌کرده‌ای که
    اختلافِ کل می‌دید، اختلافِ سوکتی هم می‌بیند (سوکت خودش جزوِ کل است).
    تنها چیزی که از دست می‌رود، همان دو دسته خطاست.

    ── سنجشِ درستیِ خودِ بازه ────────────────────────────────────────────────
    اجرای واقعی (DNS واقعی + TCP واقعی) ۲۵ بار تکرار شد:
        `resolve_hosts` (استخرِ رشته + getaddrinfo) → رانشِ سوکت ۰/۱۰
        `asyncio.run` + حلقهٔ رویداد                → رانشِ سوکت ۰/۱۰
        `check_endpoints` کامل                      → رانشِ سوکت ۰/۵
    یعنی «صفر سوکتِ بازمانده» ناوردای درست و دست‌یافتنیِ این ماژول است و
    سخت‌گیریِ `> 0` بی‌جا نیست — تنها موضوعش باید سوکت باشد، نه هر fd.

    نکتهٔ پیاده‌سازی: اگر fd بینِ `listdir` و `readlink` بسته شود، خطا
    نادیده گرفته می‌شود. چنین fdی *باز نمانده*، پس شمردنش دقیقاً همان
    «نشتِ کاذبی» بود که این تابع برای حذفش نوشته شده.
    """
    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        return -1
    n = 0
    for name in names:
        try:
            if os.readlink(f"/proc/self/fd/{name}").startswith("socket:"):
                n += 1
        except OSError:
            continue
    return n


async def _probe(ip: str, port: int, sem: asyncio.Semaphore,
                 timeout: float, tally: Dict[str, int]) -> Optional[int]:
    """
    یک دست‌دادنِ TCP. تأخیر به میلی‌ثانیه، یا None اگر باز نشد.

    سوکت بی‌درنگ بسته می‌شود: نگه‌داشتنِ ۸۰۰ سوکتِ باز تا پایانِ اجرا همان
    فروپاشیِ fd را می‌سازد که این ماژول برای دیدنش ساخته شده.
    """
    async with sem:
        t0 = time.monotonic()
        writer = None
        try:
            conn = asyncio.open_connection(ip, port)
            _, writer = await asyncio.wait_for(conn, timeout=timeout)
            return int((time.monotonic() - t0) * 1000)
        except asyncio.TimeoutError:
            tally[ERR_TIMEOUT] += 1
        except OSError as exc:
            errno = getattr(exc, "errno", None)
            if errno == 24:                       # EMFILE — ابزار خراب است
                tally[ERR_EMFILE] += 1
            elif errno == 111:                    # ECONNREFUSED — سرور هست
                tally[ERR_REFUSED] += 1
            elif errno in (101, 113):             # ENETUNREACH / EHOSTUNREACH
                tally[ERR_UNREACHABLE] += 1
            else:
                tally[ERR_OTHER] += 1
        except Exception:                         # noqa: BLE001
            tally[ERR_OTHER] += 1
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:                 # noqa: BLE001
                    pass
        return None


async def _probe_endpoint(addrs: Sequence[str], port: int,
                          sem: asyncio.Semaphore, timeout: float,
                          tally: Dict[str, int]) -> Optional[int]:
    """
    یک نقطهٔ پایانی روی حداکثر `ADDR_CAP` نشانی. کم‌ترین تأخیرِ موفق.

    «کم‌ترین» و نه «اولین»: میزبانِ چندنشانی معمولاً anycast/CDN است و
    نزدیک‌ترین نشانی نمایندهٔ واقعیِ تجربهٔ کاربر است.
    """
    results = await asyncio.gather(*[_probe(ip, port, sem, timeout, tally)
                                     for ip in addrs[:max(1, ADDR_CAP)]])
    ok = [r for r in results if r is not None]
    return min(ok) if ok else None


async def _run_tcp(targets: Sequence[Tuple[Tuple[str, int], Tuple[str, ...]]],
                   conc: int, timeout: float,
                   tally: Dict[str, int]) -> List[Optional[int]]:
    sem = asyncio.Semaphore(conc)
    return list(await asyncio.gather(*[
        _probe_endpoint(addrs, port, sem, timeout, tally)
        for (_host, port), addrs in targets
    ]))


# ──────────────────────────────────────────────────────────────────────────────
# API عمومی
# ──────────────────────────────────────────────────────────────────────────────

def check_endpoints(endpoints: Sequence[Tuple[str, int]],
                    concurrency: Optional[int] = None,
                    timeout: Optional[float] = None) -> Dict[str, Any]:
    """
    L2 روی فهرستی از `(host, port)`.

    خروجی — کلیدها قراردادِ `health.json` هستند:
        open        : {(host, port): delay_ms} — تنها نقاطِ باز
        closed      : [(host, port)] به‌ترتیبِ ورودی
        addrs       : {host: (ip, ...)} نتیجهٔ DNS، برای بازرسی
        errors      : {دلیل: تعداد} — همهٔ دلیل‌ها حاضرند، حتی صفرها
        stats       : شمارش‌ها و زمان‌ها

    استثنا: `FileDescriptorExhaustion` در دو حالت — (۱) حتی یک EMFILE، و
    (۲) بازماندنِ سوکت پس از سنجش. نتیجهٔ آلوده به کمبودِ fd بی‌معناست و
    نباید منتشر شود.

    `stats` چهار عددِ fd دارد: `fd_before`/`fd_after` (کلِ fdها، تنها برای
    گزارش و رصد) و `sock_before`/`sock_after` (تنها سوکت‌ها — سنجهٔ واقعیِ
    ناوردای نشت). چرا این تفکیک لازم بود، در `socket_fd_count` آمده.
    """
    conc = int(concurrency or CONCURRENCY)
    tmo = float(timeout or TCP_TIMEOUT)

    eps = [(str(h).strip().strip("[]"), int(p)) for h, p in endpoints]
    fd_before = fd_count()
    # ناوردای دقیق: تنها سوکت‌ها. `fd_before/fd_after` برای *گزارش* می‌مانند
    # (`pipeline.py` آن دو را در `cascade.layers.l2` منتشر می‌کند) ولی دیگر
    # پایهٔ داوریِ «نشت» نیستند — دلیلش در سندِ `socket_fd_count` آمده.
    sock_before = socket_fd_count()

    addrs, dns_s = resolve_hosts({h for h, _ in eps})

    targets = [(ep, addrs.get(ep[0], ())) for ep in eps]
    resolvable = [(ep, a) for ep, a in targets if a]
    tally = {k: 0 for k in ALL_ERRORS}
    tally[ERR_DNS] = sum(1 for _ep, a in targets if not a)

    t0 = time.monotonic()
    delays = asyncio.run(_run_tcp(resolvable, conc, tmo, tally))
    tcp_s = time.monotonic() - t0
    fd_after = fd_count()
    sock_after = socket_fd_count()

    open_map: Dict[Tuple[str, int], int] = {}
    for (ep, _a), d in zip(resolvable, delays):
        if d is not None:
            open_map[ep] = d
    closed = [ep for ep in eps if ep not in open_map]

    probes = sum(min(max(1, ADDR_CAP), len(a)) for _ep, a in resolvable)
    res: Dict[str, Any] = {
        "open": open_map,
        "closed": closed,
        "addrs": addrs,
        "errors": tally,
        "stats": {
            "endpoints": len(eps),
            "hosts": len({h for h, _ in eps}),
            "dns_failed": tally[ERR_DNS],
            "probes": probes,
            "open": len(open_map),
            "closed": len(closed),
            "open_pct": round(100.0 * len(open_map) / len(eps), 2) if eps else 0.0,
            "concurrency": conc,
            "tcp_timeout": tmo,
            "addr_cap": max(1, ADDR_CAP),
            "dns_s": round(dns_s, 2),
            "tcp_s": round(tcp_s, 2),
            "fd_before": fd_before,
            "fd_after": fd_after,
            # افزودنی و سازگارِ رو‌به‌عقب: کلیدهای بالا حذف نشده‌اند، چون
            # `pipeline.py:714-715` و `health.json`ِ منتشرشده آن‌ها را
            # می‌خوانند. این دو کلیدِ نو، سنجهٔ *واقعیِ* ناوردا هستند.
            "sock_before": sock_before,
            "sock_after": sock_after,
        },
    }

    # ── دو ناوردا که *پس از* اجرا سنجیده می‌شوند، نه پیش از آن ────────────────
    if tally[ERR_EMFILE]:
        raise FileDescriptorExhaustion(
            f"{tally[ERR_EMFILE]} EMFILE errors at concurrency={conc}; "
            f"the measurement is void. Lower L2_CONCURRENCY or raise "
            f"`ulimit -n` (soft limit is currently "
            f"{_soft_nofile()}). In a past run this exact condition "
            f"reported 1.1% instead of the true 48.0% — with exit code 0."
        )
    # ناوردای دوم — نشتِ **سوکت**، و فقط سوکت (F-13).
    #
    # سنجهٔ پیشین `fd_after > fd_before` بود؛ یعنی اختلافِ کلِ fdهای فرآیند
    # روی بازه‌ای که خیلی بیش از سوکت‌های کاوش در آن می‌گذرد. با اجرا ثابت
    # شد که آن سنجه در هر دو جهت خطا می‌داد: یک `open(os.devnull)`ِ بی‌آزار
    # اجرای سالم را باطل می‌کرد، و برعکس، بسته‌شدنِ ۲ fdِ بی‌ربط ۲ سوکتِ
    # واقعاً نشت‌کرده را **پنهان** می‌کرد. شرحِ کامل در `socket_fd_count`.
    #
    # چرا `sock_before >= 0` (و نه `sock_after >= 0`): همان قراردادِ قبلی —
    # `-1` یعنی «‎/proc‏ نبود، نمی‌دانم»، و بی‌اطلاعی نباید سنجش را باطل کند.
    # ‎-1 → 4‏ عددی بزرگ‌تر است ولی هیچ نشتی را نشان نمی‌دهد.
    if sock_before >= 0 and sock_after > sock_before:
        raise FileDescriptorExhaustion(
            f"socket leak: {sock_after - sock_before} socket descriptor(s) "
            f"still open after the measurement ({sock_before} before, "
            f"{sock_after} after). Every socket opened by a probe must be "
            f"closed before returning. (Total file descriptors went "
            f"{fd_before} → {fd_after}; only the socket count is judged, "
            f"because an unrelated non-socket descriptor opened during the "
            f"measurement is not a leak of this module.)"
        )
    return res


def _soft_nofile() -> int:
    try:
        import resource
        return resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    except Exception:                             # noqa: BLE001
        return -1


def headroom_warning(concurrency: Optional[int] = None) -> Optional[str]:
    """اگر conc به سقفِ fd نزدیک باشد، متنِ هشدار؛ وگرنه None."""
    conc = int(concurrency or CONCURRENCY)
    soft = _soft_nofile()
    if soft > 0 and conc + _FD_HEADROOM > soft:
        return (f"concurrency={conc} leaves less than {_FD_HEADROOM} spare "
                f"descriptors under a soft limit of {soft}; at 1200 this "
                f"collapsed a 48.0% measurement to 1.1% with exit code 0")
    return None


def check_lines(lines: Iterable[str]) -> Dict[str, Any]:
    """
    L0 + L1 + L2 روی سطرهای خام. نتیجه به *کانفیگ* نسبت داده می‌شود، نه
    فقط به نقطهٔ پایانی — وگرنه بندهای بعدیِ آبشار نمی‌دانند چه بنویسند.

    افزوده‌ها بر خروجیِ `check_endpoints`:
        kept_open   : سطرهایی که نقطهٔ پایانی‌شان باز بود
        line_delay  : اندیسِ سطر در `kept_open` → تأخیرِ میلی‌ثانیه
        filter      : آمارِ L0/L1 از `filters.py`
    """
    import filters

    pre = filters.filter_lines(lines)
    res = check_endpoints(pre["endpoints"])

    kept_open: List[str] = []
    line_delay: List[int] = []
    for ep, idxs in pre["ep_to_lines"].items():
        if ep in res["open"]:
            for i in idxs:
                kept_open.append(pre["kept"][i])
                line_delay.append(res["open"][ep])

    res["kept_open"] = kept_open
    res["line_delay"] = line_delay
    res["filter"] = pre["stats"]
    res["stats"]["configs_in"] = pre["stats"]["input"]
    res["stats"]["configs_open"] = len(kept_open)
    res["stats"]["configs_open_pct"] = (
        round(100.0 * len(kept_open) / pre["stats"]["input"], 2)
        if pre["stats"]["input"] else 0.0
    )
    return res


def check_file(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return check_lines(fh)


def _main(argv: Sequence[str]) -> int:
    import json
    path = argv[1] if len(argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "all", "configs.txt")

    warn = headroom_warning()
    if warn:
        print(f"# warning: {warn}", file=sys.stderr)

    try:
        res = check_file(path)
    except FileDescriptorExhaustion as exc:
        print(f"!! {exc}", file=sys.stderr)
        return 2

    print(json.dumps({"stats": res["stats"], "errors": res["errors"],
                      "filter": res["filter"]},
                     ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
