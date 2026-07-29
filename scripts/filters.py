# -*- coding: utf-8 -*-
"""
filters.py — لایهٔ L0/L1 آبشارِ حقیقت‌سنجی: یکتاسازی و فیلترِ ارزانِ بی‌شبکه.

جای این ماژول در معماری
────────────────────────
    all/configs.txt → [L0 یکتاسازی] → [L1 فیلترِ ارزان] → L2 (TCP) → L3 (پروکسیِ واقعی)

هرچه یک کانفیگِ مرده دیرتر حذف شود، گران‌تر تمام می‌شود. L3 برای هر کانفیگ یک
پروکسیِ واقعی بالا می‌آورد و یک درخواستِ HTTP می‌فرستد؛ L1 فقط رشته را نگاه
می‌کند. پس هر چیزی که *بی شبکه* قابلِ داوری است باید همین‌جا حذف شود.

چرا L0 (یکتاسازی) اصلاً وجود دارد
──────────────────────────────────
اندازه‌گیریِ واقعی روی `all/configs.txt` (۸٬۰۲۸ کانفیگ، کامیتِ `37bd177`):

    کانفیگ‌ها ................. ۸٬۰۲۸
    نقاطِ پایانیِ یکتا (host,port) ۶٬۹۴۰
    میزبانِ یکتا ................ ۵٬۰۶۸

یعنی ۱۳.۶٪ از کارِ شبکه تکراری است. L2 و L3 روی *نقطهٔ پایانی* کار می‌کنند، نه
روی سطرِ کانفیگ، و همین یک تصمیم پیش از هر بهینه‌سازیِ دیگری ۱۳.۶٪ صرفه دارد.

قاعدهٔ داوری: پارسر داور است، نه regex
───────────────────────────────────────
درسِ گران‌قیمتِ این پروژه: هر بار که با `grep`/`rsplit` اندازه گرفتیم، عددمان
غلط بود (IPv6 برهنه با `rsplit(':',1)` مثله می‌شود؛ vmessِ base64 ریمارک ندارد؛
`vmess://` دو شکلِ متفاوت دارد). پس این ماژول **هیچ‌گاه** خودش URI را تجزیه
نمی‌کند و همیشه از `converters.parse_proxy()` می‌پرسد.

به همین دلیل `_is_unroutable_server` هم *بازاستفاده* می‌شود و بازنویسی نمی‌شود:
یک قاعده در دو جا = دو رفتارِ واگرا در آینده.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

import converters

#: پروتکل‌هایی که میدانِ `uuid` در آن‌ها *معنا* دارد. `shadowsocks`/`trojan`/
#: `hysteria2` رمزِ عبورِ آزاد دارند، پس داوریِ شناسه روی آن‌ها بی‌معناست.
UUID_PROTOCOLS = frozenset({"vless", "vmess", "tuic"})

#: شکلِ متعارفِ UUID با خط‌تیره: ۸-۴-۴-۴-۱۲ رقمِ شانزده‌شانزدهی.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

#: ★ سقفِ ۳۰ بایتیِ «رشتهٔ سفارشی» — از خودِ مشخصاتِ رسمیِ Xray، نه از حدس.
#:
#: این عدد نتیجهٔ یک تصحیحِ سختِ همین فاز است. نخستین پیاده‌سازیِ من شرط را
#: «UUIDِ متعارف، وگرنه حذف» گذاشت. اندازه‌گیری روی دادهٔ زنده ۱۱۳ حذف داد و
#: بازرسیِ آن ۱۱۳ نشان داد اکثرشان شناسه‌های *مشروع*‌اند:
#:
#:     '@free_conf_iran' ×۱۳ · '13094' · 'AlfredConfig' · 'f23bb427c1f9…' ×۲۰
#:
#: مستندِ رسمیِ Xray برای **هر دو** پروتکلِ VLESS و VMess صریح است:
#:
#:   «User ID … can be any string less than 30 bytes, or a valid UUID.
#:    A custom string and its mapped UUID are equivalent.»
#:   — xtls.github.io/en/config/inbounds/{vless,vmess}.html
#:
#: یعنی هستهٔ Xray رشتهٔ سفارشی را با نگاشتِ UUIDv5 (issue #158) به UUID تبدیل
#: می‌کند و آن دو **هم‌ارز**اند. پس قاعدهٔ اولِ من ۱۱۳ کانفیگِ سالم را می‌کشت.
#: شاهدِ تکمیلی: `sing-box check` و `mihomo -t` روی خروجیِ همان‌ها rc=0 دادند.
_CUSTOM_ID_MAX_BYTES = 30

#: شکلِ فشردهٔ ۳۲‌رقمیِ UUID (بی خط‌تیره). ۳۲ بایت است، پس از سقفِ ۳۰ بایتی
#: می‌گذرد و اگر صریحاً مجاز نشود حذف می‌شود. سنجشِ واقعی: ۲۰ کانفیگِ vmess با
#: شناسهٔ `f23bb427c1f94373876c2f43e9f790f3` که `sing-box check` و `mihomo -t`
#: هر دو با rc=0 پذیرفتندشان.
_UUID_RE_COMPACT = re.compile(r"^[0-9a-fA-F]{32}$")

#: UUIDِ تهی: شکلش بی‌عیب است ولی مقدارِ جانگهدارِ تولیدکنندهٔ بالادست است و
#: هیچ سروری آن را کاربرِ واقعی نمی‌داند.
_NIL_UUID = "00000000-0000-0000-0000-000000000000"

#: دلیل‌های حذف. رشته‌ها بخشی از قراردادِ خروجی‌اند (در `health.json` می‌نشینند)
#: پس تغییرشان تغییرِ شکسته‌ساز است.
REASON_UNPARSABLE = "unparsable"
REASON_INVALID_PORT = "invalid_port"
REASON_INVALID_UUID = "invalid_uuid"
REASON_UNROUTABLE = "unroutable_server"
REASON_INVALID_SERVER = "invalid_server"

ALL_REASONS = (
    REASON_UNPARSABLE,
    REASON_INVALID_PORT,
    REASON_INVALID_UUID,
    REASON_UNROUTABLE,
    REASON_INVALID_SERVER,
)


def is_invalid_port(port: Any) -> bool:
    """
    آیا پورت بیرونِ بازهٔ معتبرِ TCP است؟

    بازهٔ معتبر ۱..۶۵۵۳۵ است. `0` عمداً نامعتبر شمرده می‌شود: از نظرِ فنی
    «پورتِ رزروشده» است و هیچ سروری روی آن گوش نمی‌دهد، پس کانفیگش مرده است.
    مقدارِ غیرِعددی هم نامعتبر است — نه اینکه استثنا پرتاب کند.
    """
    try:
        p = int(str(port).strip())
    except (TypeError, ValueError):
        return True
    return not (0 < p < 65536)


def is_invalid_uuid(uuid: Any, proto: str) -> bool:
    """
    آیا شناسهٔ کاربر برای پروتکلی که شناسه می‌خواهد، *به‌حکمِ مشخصات* نامعتبر است؟

    قاعده مستقیماً از مستندِ رسمیِ Xray گرفته شده (بندِ `_CUSTOM_ID_MAX_BYTES`):
    شناسه معتبر است اگر **یا** UUIDِ متعارف باشد **یا** رشته‌ای کوتاه‌تر از
    ۳۰ بایت. پس تنها سه چیز نامعتبر است:

      • تهی — هیچ کاربری را مشخص نمی‌کند
      • ۳۰ بایت یا بیشتر و UUIDِ متعارف هم نیست — بیرونِ هر دو راهِ مجاز
      • UUIDِ تهی (`000…0`) — جانگهدار، نه کاربر

    برای پروتکل‌های بیرونِ `UUID_PROTOCOLS` همیشه `False`: در `shadowsocks`
    این میدان رمزِ عبور است و هر رشته‌ای مجاز. سنجیدنِ UUID روی آن‌ها یعنی
    حذفِ کانفیگِ سالم — همان خطایی که با «فهرستِ دستیِ رشته‌های بد» کرده بودیم.

    مقایسه با UUID *پس از* برداشتنِ خط‌تیره‌ها انجام نمی‌شود؛ شکلِ بی‌خط‌تیرهٔ
    ۳۲‌رقمی خودش زیرِ ۳۰ بایت نیست (۳۲ بایت است) ولی هستهٔ Xray می‌پذیردش، پس
    صریحاً در `_UUID_RE_COMPACT` مجاز شمرده می‌شود — سنجیده با دو کلاینتِ واقعی.
    """
    if proto not in UUID_PROTOCOLS:
        return False
    s = str(uuid or "").strip()
    if not s:
        return True
    if _UUID_RE.match(s) or _UUID_RE_COMPACT.match(s):
        return s.replace("-", "").lower() == _NIL_UUID.replace("-", "")
    return len(s.encode("utf-8")) >= _CUSTOM_ID_MAX_BYTES


def endpoint_of_proxy(p: Dict[str, Any]) -> Optional[Tuple[str, int]]:
    """
    `(host, port)` از یک پروکسیِ تجزیه‌شده — یا `None` اگر ساختاراً بی‌معنا باشد.

    کروشهٔ IPv6 برداشته می‌شود چون L2 نشانی را به `getaddrinfo`/`open_connection`
    می‌دهد و آن‌ها نشانیِ برهنه می‌خواهند، نه شکلِ URI.
    """
    host = str(p.get("server") or "").strip().strip("[]").lower()
    try:
        port = int(str(p.get("port")).strip())
    except (TypeError, ValueError):
        return None
    if not host or not (0 < port < 65536):
        return None
    return host, port


def classify(line: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    یک سطر را داوری می‌کند: `(proxy, None)` اگر بگذرد، `(None, reason)` اگر بیفتد.

    ترتیبِ دروازه‌ها *معنادار* است و از ارزان به گران چیده شده؛ اولین دلیلِ
    برخورد گزارش می‌شود تا آمار قابلِ‌ردیابی بماند:

      ۱. تجزیه‌ناپذیر  ← بی این، بقیهٔ داوری‌ها میدانی برای خواندن ندارند
      ۲. پورتِ نامعتبر
      ۳. سرورِ بدشکلِ ساختاری   (بازاستفاده از منطقِ فاز H8)
      ۴. سرورِ غیرقابلِ‌مسیریابی (بازاستفاده از منطقِ فاز H7)
      ۵. UUIDِ بدشکل
    """
    p = converters.parse_proxy(line)
    if not p:
        return None, REASON_UNPARSABLE
    if is_invalid_port(p.get("port")):
        return None, REASON_INVALID_PORT
    server = p.get("server")
    # بازاستفادهٔ آگاهانه: این دو قاعده در `converters` صاحبِ خانه دارند.
    if converters._is_structurally_invalid_server(server):
        return None, REASON_INVALID_SERVER
    if converters._is_unroutable_server(server):
        return None, REASON_UNROUTABLE
    if is_invalid_uuid(p.get("uuid"), str(p.get("type") or "")):
        return None, REASON_INVALID_UUID
    return p, None


def filter_lines(lines: Iterable[str]) -> Dict[str, Any]:
    """
    L0 + L1 روی یک دنبالهٔ سطر.

    خروجی — کلیدها بخشی از قراردادِ `health.json` هستند:
        kept          : سطرهایی که از L1 گذشتند (ترتیبِ ورودی حفظ می‌شود)
        endpoints     : `(host, port)` یکتا به‌ترتیبِ نخستین دیدار
        ep_to_lines   : نقطهٔ پایانی → فهرستِ اندیسِ سطرها در `kept`
        line_endpoint : اندیسِ `kept` → نقطهٔ پایانی
        dropped       : {دلیل: تعداد} — همهٔ دلیل‌ها حاضرند، حتی صفرها
        stats         : شمارش‌های خلاصه برای تلمتری
    """
    kept: List[str] = []
    endpoints: List[Tuple[str, int]] = []
    ep_index: Dict[Tuple[str, int], int] = {}
    ep_to_lines: Dict[Tuple[str, int], List[int]] = {}
    line_endpoint: List[Tuple[str, int]] = []
    dropped: Dict[str, int] = {r: 0 for r in ALL_REASONS}
    total = 0

    for raw in lines:
        line = (raw or "").strip()
        # سرآیندِ توضیحیِ فایل کانفیگ نیست. شمردنش آمار را باد می‌کند —
        # همان اشتباهی که در سنجش‌های پیشین مرتکب شدیم.
        if not line or line.startswith("#"):
            continue
        total += 1
        p, reason = classify(line)
        if reason is not None:
            dropped[reason] += 1
            continue
        ep = endpoint_of_proxy(p or {})
        if ep is None:
            # تورِ ایمنی: `classify` باید این را گرفته باشد. اگر این‌جا رسید،
            # یعنی ناسازگاری میانِ دو تابع — و باید در آمار دیده شود نه پنهان.
            dropped[REASON_INVALID_PORT] += 1
            continue
        idx = len(kept)
        kept.append(line)
        line_endpoint.append(ep)
        if ep not in ep_index:
            ep_index[ep] = len(endpoints)
            endpoints.append(ep)
            ep_to_lines[ep] = []
        ep_to_lines[ep].append(idx)

    dropped_total = sum(dropped.values())
    return {
        "kept": kept,
        "endpoints": endpoints,
        "ep_to_lines": ep_to_lines,
        "line_endpoint": line_endpoint,
        "dropped": dropped,
        "stats": {
            "input": total,
            "kept": len(kept),
            "dropped": dropped_total,
            "endpoints_unique": len(endpoints),
            "hosts_unique": len({h for h, _ in endpoints}),
            "removal_pct": round(100.0 * dropped_total / total, 2) if total else 0.0,
            "dedup_saving_pct": (
                round(100.0 * (1 - len(endpoints) / len(kept)), 2) if kept else 0.0
            ),
        },
    }


def filter_file(path: str) -> Dict[str, Any]:
    """`filter_lines` روی یک فایل. رمزگشاییِ بخشنده چون دادهٔ بالادست است."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        return filter_lines(fh)


if __name__ == "__main__":  # pragma: no cover - ابزارِ خطِ فرمان
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "all/configs.txt"
    res = filter_file(target)
    print(json.dumps({"stats": res["stats"], "dropped": res["dropped"]},
                     ensure_ascii=False, indent=2))
