# -*- coding: utf-8 -*-
"""
converters.py — تبدیل کانفیگ‌های V2Ray به فرمت‌های Clash (Mihomo) YAML و Sing-box JSON.

پشتیبانی: vless, vmess, trojan, shadowsocks (ss), hysteria2, tuic.

hysteria2 و tuic چرا اضافه شدند: توضیحاتِ مخزن این دو پروتکل را تبلیغ می‌کرد
ولی هیچ‌کدام از دو مبدل آن‌ها را تولید نمی‌کرد. اندازه‌گیریِ زندهٔ خروجی نشان داد
۸۰ کانفیگِ hysteria2 و ۱ کانفیگِ tuic در فایل‌های متنی منتشر می‌شوند اما در
clash.yaml و singbox.json **صفر** حضور دارند. کاربری که فقط اشتراکِ Clash را
وارد می‌کند، این‌ها را هرگز نمی‌بیند. فاصلهٔ میانِ آنچه تبلیغ می‌شود و آنچه
تحویل داده می‌شود، خودش یک نقصِ اعتماد است.

wireguard آگاهانه بیرون ماند: بر خلافِ بقیه، wireguard کلیدِ خصوصیِ سمتِ کلاینت
و نشانیِ داخلیِ تخصیص‌یافته لازم دارد. این‌ها در URI عمومی وجود ندارند، پس هر
تبدیلی ناچار است مقدارِ جعلی بگذارد و کانفیگی بسازد که هرگز وصل نمی‌شود.
شمارشِ زنده: صفر کانفیگِ wireguard در ورودی هست، پس تبدیلش هم سودی ندارد.

قاعدهٔ طلایی این ماژول: **هرگز خروجی نامعتبر تولید نکن.**
یک کانفیگ نامعتبر در وسط فایل، کل فایل را برای کلاینت غیرقابل‌استفاده می‌کند
(چون sing-box و mihomo هنگام بارگذاری، کل سند را رد می‌کنند). پس هر مقداری
که کلاینت نمی‌پذیرد یا drop می‌شود یا اصلاح می‌شود — نه اینکه خام عبور کند.

اعتبار همهٔ whitelist‌های زیر با اجرای واقعی روی این نسخه‌ها تأیید شده است:
  • sing-box 1.13.14
  • mihomo (Clash.Meta) v1.19.29
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional

# ──────────────────────────────────────────────────────────────────────────────
# whitelist‌های اعتبارسنجی (همه با تست واقعی کلاینت استخراج شده‌اند)
# ──────────────────────────────────────────────────────────────────────────────

#: رمزهای shadowsocks که **هم** sing-box 1.13 و **هم** mihomo 1.19 می‌پذیرند.
#: هر مقدار خارج از این مجموعه باعث خطای «unknown method» و رد شدن کل فایل می‌شود.
#: (نمونهٔ واقعی خرابی: UUID که به‌جای cipher در URI آمده بود.)
SS_CIPHERS: frozenset = frozenset({
    # AEAD مدرن
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    # Shadowsocks 2022 (کلید باید base64 با طول دقیق باشد → جدا اعتبارسنجی می‌شود)
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    # جریانی قدیمی (ناامن ولی پذیرفته‌شده در هر دو کلاینت)
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "rc4-md5", "chacha20-ietf", "none",
})

#: طول کلید لازم (بایت) برای هر روش Shadowsocks-2022.
#: sing-box با پیام «bad key length» کل فایل را رد می‌کند اگر طول غلط باشد.
SS2022_KEY_BYTES: Dict[str, int] = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}

#: اثرانگشت‌های uTLS معتبر در sing-box 1.13. مقدار نامعتبر → «unknown uTLS fingerprint».
UTLS_FINGERPRINTS: frozenset = frozenset({
    "chrome", "firefox", "edge", "safari", "ios", "android",
    "random", "randomized", "qq", "360",
})

#: اثرانگشت پیش‌فرض وقتی کانفیگ REALITY پارامتر fp ندارد.
#: sing-box **الزاماً** برای reality به uTLS نیاز دارد؛ نبودش خطای FATAL می‌دهد.
DEFAULT_UTLS_FINGERPRINT = "chrome"

#: مقادیر flow که در **هر دو** کلاینت معتبرند.
#: «xtls-rprx-vision-udp443» فقط در mihomo پذیرفته می‌شود و در sing-box
#: خطای «unsupported flow» می‌دهد؛ «xtls-rprx-direct/origin» در هیچ‌کدام.
#: چون یک flow نامعتبر کل فایل را رد می‌کند، فقط مقدار امن را نگه می‌داریم.
VLESS_FLOWS: frozenset = frozenset({"xtls-rprx-vision"})

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _sanitize_flow(flow: str) -> str:
    """flow نامعتبر را حذف می‌کند (به‌جای اینکه کل فایل را بشکند).

    نکته: udp443 صرفاً یک بهینه‌سازی مسیر UDP است؛ حذف آن اتصال را از بین
    نمی‌برد، در حالی که نگه‌داشتنش فایل sing-box را کاملاً بی‌استفاده می‌کند.
    """
    f = (flow or "").strip().lower()
    if f in VLESS_FLOWS:
        return f
    if f.startswith("xtls-rprx-vision"):
        return "xtls-rprx-vision"   # گونه‌های -udp443 → پایهٔ سازگار
    return ""


def _sanitize_short_id(sid: str) -> Optional[str]:
    """short-id رئالیتی باید hex با طول زوج و حداکثر ۱۶ کاراکتر باشد.

    None یعنی مقدار خراب است (مثلاً remark به‌اشتباه چسبیده) و کانفیگ باید
    drop شود؛ هر دو کلاینت با «invalid REALITY short ID» کل فایل را رد می‌کنند.
    رشتهٔ خالی مجاز است (سرور بدون short-id).
    """
    s = (sid or "").strip()
    if s == "":
        return ""
    if len(s) > 16 or len(s) % 2 != 0:
        return None
    if any(ch not in _HEX_DIGITS for ch in s):
        return None
    return s


def _sanitize_pbk(pbk: str) -> Optional[str]:
    """کلید عمومی REALITY: base64url بدون padding با طول ۴۳ کاراکتر (۳۲ بایت)."""
    s = (pbk or "").strip()
    if len(s) != 43:
        return None
    try:
        if len(base64.urlsafe_b64decode(s + "=")) != 32:
            return None
    except Exception:
        return None
    return s


def _sanitize_ss(cipher: str, password: str) -> Optional[tuple]:
    """اعتبارسنجی جفت (cipher, password) شادوساکس.

    None برمی‌گرداند اگر کانفیگ در کلاینت واقعی fail می‌شود — که یعنی باید
    drop شود تا کل فایل خراب نشود.
    """
    cipher = (cipher or "").strip().lower()
    if cipher not in SS_CIPHERS:
        return None
    if not password:
        return None
    need = SS2022_KEY_BYTES.get(cipher)
    if need is not None:
        # SS-2022: کلید باید base64 با طول دقیق باشد.
        # فرم چندکاربره «PSK:PSK» هم مجاز است (هر بخش جداگانه بررسی می‌شود).
        for part in password.split(":"):
            try:
                raw = base64.b64decode(part + "=" * ((4 - len(part) % 4) % 4), validate=False)
            except Exception:
                return None
            if len(raw) != need:
                return None
    return cipher, password


def _b64_json(b64: str) -> Optional[dict]:
    try:
        b64 = b64.strip()
        b64 += "=" * ((4 - len(b64) % 4) % 4)
        return json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
    except Exception:
        return None


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _remark_of(line: str) -> str:
    if "#" in line:
        try:
            return urllib.parse.unquote(line.split("#", 1)[1]).strip()
        except Exception:
            return line.split("#", 1)[1].strip()
    return ""


# ──────────────────────────────────────────────────────────────────────────────
# Parse → dict واسط (نمایش یکنواخت پروتکل)
# ──────────────────────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────────────────────
# شمارشِ کانفیگ‌های حذف‌شده در تبدیل
#
# چرا لازم است: تا پیش از این، هر کانفیگی که مبدل نمی‌توانست بیان کند بی‌صدا
# رد می‌شد. اندازه‌گیریِ واقعی روی ۸۰۱۷ کانفیگِ زندهٔ همین مخزن (پس از افزودنِ
# پشتیبانیِ hysteria2 و tuic) نشان داد این حذفِ خاموش کوچک نیست:
#
#   Clash   : ۶۸ حذف  → unparsable=۶۰ ، not_expressible=۸
#             به تفکیکِ پروتکل: ss=۳۰ ، ssr=۲۸ ، vless=۵ ، trojan=۳ ، vmess=۲
#   Sing-box: ۳۱۳ حذف → unparsable=۶۰ ، not_expressible=۲۵۳
#             به تفکیکِ پروتکل: vless=۲۴۰ ، ss=۳۰ ، ssr=۲۸ ، trojan=۱۲ ، vmess=۳
#
# هیچ‌کس این عددها را نمی‌دانست، چون نه لاگی بود نه شمارشی. کاربری که فایلِ
# Clash را وارد می‌کند و «۸۰۱۷ کانفیگ» را در توضیحاتِ مخزن خوانده، عددِ دیگری
# می‌بیند و دلیلش را نمی‌فهمد. بزرگ‌ترین قلم — ۲۴۰ عدد vless در Sing-box — همان
# حذفِ مشکوکِ قدیمی بود که تا امروز فقط گمان می‌رفت و حالا اندازه‌گیری شده است.
#
# با ثبتِ علتِ حذف، این عددها به health.json می‌روند و قابلِ پیگیری می‌شوند:
# اگر فردا یک تغییر باعث شود ۲۰۰۰ کانفیگ حذف شود، در گزارش دیده می‌شود.
# ──────────────────────────────────────────────────────────────────────────────

class _DropRecorder:
    """
    شمارشگرِ علت‌های حذف، به تفکیکِ مبدل و پروتکل.

    عمداً فقط *شمارش* می‌کند و خودِ کانفیگ‌ها را نگه نمی‌دارد: نگه‌داشتنِ هزاران
    رشته در حافظه سودی ندارد و گزارش را هم بی‌جهت بزرگ می‌کند.
    """

    def __init__(self) -> None:
        self.data: Dict[str, Dict[str, Any]] = {}

    def clear_target(self, target: str) -> None:
        self.data[target] = {"total": 0, "by_reason": {}, "by_protocol": {}}

    def record(self, target: str, reason: str, line: str,
               proto: Optional[str] = None) -> None:
        d = self.data.setdefault(
            target, {"total": 0, "by_reason": {}, "by_protocol": {}})
        d["total"] += 1
        d["by_reason"][reason] = d["by_reason"].get(reason, 0) + 1
        key = proto or _scheme_of(line)
        if key:
            d["by_protocol"][key] = d["by_protocol"].get(key, 0) + 1

    def snapshot(self) -> Dict[str, Dict[str, Any]]:
        """کپیِ آمار برای درج در گزارشِ سلامت."""
        return {
            t: {"total": v["total"],
                "by_reason": dict(sorted(v["by_reason"].items())),
                "by_protocol": dict(sorted(v["by_protocol"].items(),
                                           key=lambda kv: (-kv[1], kv[0])))}
            for t, v in sorted(self.data.items())
        }


_drops = _DropRecorder()


def _scheme_of(line: str) -> str:
    """schemeی خامِ یک خط، برای دسته‌بندیِ حذف‌ها وقتی نوع تحلیل نشده است."""
    s = (line or "").strip()
    i = s.find("://")
    return s[:i].lower() if 0 < i < 20 else ""


def drop_stats() -> Dict[str, Dict[str, Any]]:
    """آمارِ حذف‌های آخرین تبدیل. خطِ لوله آن را در health.json می‌نویسد."""
    return _drops.snapshot()


#: حالت‌های کنترلِ ازدحامِ پذیرفته‌شده در tuic. مقدارِ خارج از این مجموعه در
#: sing-box خطای بارگذاری می‌دهد و کلِ سند را رد می‌کند، پس به «cubic» می‌افتد.
_TUIC_CONGESTION = frozenset({"cubic", "new_reno", "bbr"})

#: مقادیرِ ALPN مجاز. رشتهٔ دلخواهِ کاربر مستقیم عبور داده نمی‌شود چون یک مقدارِ
#: بی‌معنا باعث می‌شود دست‌دادنِ TLS در سمتِ کلاینت شکست بخورد.
_ALPN_ALLOWED = frozenset({"h3", "h2", "http/1.1", "hysteria", "tuic", "quic"})


#: مقادیرِ نگهبان (sentinel) که «نامِ میزبان» نیستند بلکه «مقدارِ تهی» را در
#: قالبِ متن بیان می‌کنند. تولیدکنندهٔ بالادست یک `None`/`null` پایتونی یا
#: جاوااسکریپتی را مستقیم در URI چاپ کرده. مصداقِ واقعیِ سنجیده‌شده در دادهٔ
#: زنده: `sni=None` (۲ مورد) — و `None` در DNS هم شکست می‌خورد (gaierror).
_SNI_SENTINELS = frozenset({
    "none", "null", "undefined", "nil", "nan", "false", "true",
    "localhost", "0.0.0.0", "127.0.0.1", "::1", "example.com",
})

#: یک برچسبِ (label) نامِ میزبان. زیرخط عمداً مجاز است — بندِ توضیحی پایین.
_SNI_LABEL = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")


def _is_unroutable_server(host: Any) -> bool:
    """
    آیا نشانیِ سرور ذاتاً غیرقابلِ‌اتصال است؟

    این *بی‌ربط* به SNI است و یک نقصِ جداگانهٔ بالادست: بعضی کانفیگ‌ها نشانیِ
    سرورشان `127.0.0.1` یا `0.0.0.0` است. چنین کانفیگی روی دستگاهِ کاربر هرگز
    وصل نمی‌شود — کلاینت به خودش وصل می‌شود. اندازه‌گیریِ واقعی روی خروجیِ زنده
    (پیش از این بند)، در سه دسته ۳۲ رخداد:

        all    127.0.0.1  ×۵    127.0.0.53 ×۱۰   0.0.0.0 ×۱
        heavy  127.0.0.1  ×۲                     0.0.0.0 ×۱
        light  127.0.0.1  ×۳    127.0.0.53 ×۱۰

    `127.0.0.53` نشانیِ حل‌کنندهٔ محلیِ systemd-resolved است؛ یعنی تولیدکنندهٔ
    بالادست به‌جای نشانیِ سرور، نشانیِ DNSِ خودش را چاپ کرده. نگه‌داشتنشان تنها
    آمار را باد می‌کند و کاربر را سرِ کار می‌گذارد، پس drop می‌شوند و در
    تلمتریِ drop هم شمرده می‌شوند تا عدد قابلِ‌ردیابی بماند.

    نکته: نامِ میزبانِ *غیرِ* IP این‌جا رد نمی‌شود؛ داوری دربارهٔ آن به DNS نیاز
    دارد و در زمانِ تبدیل انجام نمی‌شود.
    """
    s = str(host or "").strip().strip("[]")
    if not s:
        return True
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False          # نامِ میزبان است، نه IP — این‌جا داوری نمی‌کنیم
    return bool(ip.is_loopback or ip.is_unspecified or ip.is_multicast
                or ip.is_reserved or ip.is_link_local)


def _clean_sni(raw: Any) -> str:
    """
    پاک‌سازیِ SNI — «ترمیم کن، بعد رد کن».

    نمونهٔ واقعی از ورودیِ زنده: `sni=https%3A%2F%2Ft.me%2Foneclickvpnkeys`.
    این یک نشانیِ تبلیغاتی است که در جای نامِ میزبان نشسته. هر دو کلاینت آن را
    هنگامِ *بارگذاری* می‌پذیرند (آزمون شد: mihomo و sing-box هر دو rc=0)، پس
    فایل نمی‌شکند؛ ولی هنگامِ *اتصال* دست‌دادنِ TLS شکست می‌خورد و کاربر آن را
    «کانفیگِ خراب» می‌بیند بدون اینکه بداند چرا. حذفِ SNI بی‌معنا بهتر است:
    کلاینت آن‌گاه به نامِ خودِ سرور برمی‌گردد که حداقل یک نامِ واقعی است.

    ▲ چرا نسخهٔ نخست کافی نبود
    ─────────────────────────
    نسخهٔ نخست فقط *رد* می‌کرد. اندازه‌گیری روی خروجیِ زندهٔ همین مخزن نشان داد
    بخشِ بزرگی از مقادیرِ «نامعتبر» در واقع نامِ میزبانِ درستی هستند که یک
    نویسهٔ اضافه دارند، و رد کردنشان یعنی دور ریختنِ SNIِ سالم:

        مقدارِ خام                         حقیقتِ DNS (سنجیده‌شده)
        ──────────────────────────────    ───────────────────────────────
        `$$hn.xiaohouzi.club`             gaierror  ← با `$` شکست می‌خورد
        `hn.xiaohouzi.club`               13.248.169.48 ✓ ← بی `$` کار می‌کند
        `world.yahoo.com:443`             درگاهِ چسبیده؛ نامش معتبر است
        `.afrcloud22.mmv.kr`              نقطهٔ ابتدا؛ بی‌آن → 104.26.14.21 ✓
        `t.me%2Fripaojiedian`             دوبار درصدکد‌شده؛ ذاتاً نشانی است ✗

    پس ترتیبِ درست این است: نخست نویسه‌های زائدِ *ساختاری* را برمی‌داریم
    (درصدکدگشاییِ چندلایه، درگاهِ چسبیده، `$`ِ نشانگرِ منبع، نقطهٔ ابتدا/انتها)
    و تنها پس از آن داوری می‌کنیم. سنجشِ A/B روی ۳ دستهٔ خروجی:

        قاعدهٔ پیشین   ۲٬۵۹۳ مقدارِ یکتا / ۸٬۷۷۹ رخداد
        قاعدهٔ کنونی   ۲٬۶۲۵ مقدارِ یکتا / ۸٬۸۷۶ رخداد      (‎+۹۷ رخداد)
        ترمیم‌شده در جا      ۵۹ مقدار /   ۲۱۷ رخداد
        تازه حذف‌شده          ۴ مقدار /    ۲۹ رخداد

    و آن ۴ مقدارِ تازه‌حذف‌شده یکی‌یکی با DNS آزموده شدند؛ هیچ‌کدام resolve
    نمی‌شوند (`None`, `Telegram-Leviko_v2ray`, `wbjj-bbcs-.MaQRor.Ir`, و یک نامِ
    غیرASCII) — یعنی حذفشان زیانی ندارد.

    ▲ چرا زیرخط (`_`) مجاز است
    ─────────────────────────
    RFC 1123 زیرخط را در نامِ میزبان مجاز نمی‌داند، ولی ما داوریِ کاغذی نمی‌کنیم؛
    آزمونِ DNS انجام دادیم:

        `TM_AZARBAYJAB1.new.99.workers.dev`  →  104.21.61.74 ✓
        `TM-AZARBAYJAB1.new.99.workers.dev`  →  104.21.61.74 ✓

    نامِ زیرخط‌دار واقعاً resolve می‌شود، پس ردش کردن یعنی خرابِ‌کردنِ کانفیگِ
    سالم. زیرخط را نگه می‌داریم و آن را به خط‌تیره هم *تبدیل نمی‌کنیم*، چون
    گواهیِ TLS بر پایهٔ نامِ اصلی صادر شده.

    ▲ چرا نقطهٔ پایانی برداشته می‌شود
    ───────────────────────────────
    `wwwuk.mobilex55.com.` در DNS کار می‌کند (138.68.140.39) ولی RFC 6066 §3
    صریح است: نامِ میزبان در افزونهٔ server_name «بدونِ نقطهٔ پایانی» بیان
    می‌شود. پس این‌جا نقطه را می‌بُریم نه اینکه مقدار را دور بریزیم.

    ▲ چرا نامِ بی‌نقطه رد می‌شود
    ──────────────────────────
    `Telegram-Leviko_v2ray` نامِ کانال است نه میزبان؛ نه نقطه دارد و نه resolve
    می‌شود. یک برچسبِ تنها نمی‌تواند نامِ کاملِ مقصد باشد.
    """
    s = str(raw or "").strip()
    if not s:
        return ""

    # درصدکدگشاییِ چندلایه: دادهٔ زنده هم `%2F` دارد و هم `%252F`.
    for _ in range(3):
        nxt = urllib.parse.unquote(s)
        if nxt == s:
            break
        s = nxt
    s = s.strip()

    # درگاهِ چسبیده به انتهای نام: `world.yahoo.com:443` → `world.yahoo.com`
    s = re.sub(r":\d{1,5}$", "", s)
    # `$`ِ نشانگرِ منبع و نقطهٔ ابتدا/انتها
    s = s.strip("$").strip(".").strip()

    if not s or len(s) > 253:
        return ""
    if s.lower() in _SNI_SENTINELS:
        return ""
    # نشانی، مسیر، یا نامِ کاربری هرگز ترمیم‌پذیر نیست
    if "://" in s or "/" in s or "?" in s or "@" in s or " " in s or ":" in s:
        return ""

    labels = s.split(".")
    if len(labels) < 2:
        return ""
    if not all(_SNI_LABEL.match(lb) for lb in labels):
        return ""
    return s


def _truthy(v: Any) -> bool:
    """
    تفسیرِ پرچم‌های متنیِ «آری/نه» در URI.

    منابعِ مختلف برای یک معنا سه نگارش می‌نویسند: «1», «true», «yes». اگر فقط
    یکی را بپذیریم، بقیه خاموشانه «نه» تفسیر می‌شوند و کاربر گواهیِ نامعتبر را
    رد می‌کند در حالی که سرور انتظارِ پذیرش دارد.
    """
    s = str(v or "").strip().lower()
    return s in ("1", "true", "yes", "on")


def _alpn_list(raw: Any) -> list:
    """
    رشتهٔ alpn جدا‌شده با کاما → فهرستِ پاک‌سازی‌شده.

    مقادیرِ ناشناخته دور ریخته می‌شوند نه اینکه خام عبور کنند: یک ALPN بی‌معنا
    باعثِ شکستِ دست‌دادنِ TLS می‌شود و کاربر آن را «کانفیگِ خراب» می‌بیند.
    """
    if not raw:
        return []
    out: list = []
    for part in str(raw).split(","):
        p = urllib.parse.unquote(part).strip().lower()
        if p in _ALPN_ALLOWED and p not in out:
            out.append(p)
    return out


def parse_proxy(line: str) -> Optional[Dict[str, Any]]:
    """یک URI کانفیگ → dict واسط استاندارد یا None."""
    line = line.strip()
    try:
        if line.startswith("vmess://"):
            obj = _b64_json(line[8:].split("#")[0])
            if not obj:
                return None
            return {
                "type": "vmess",
                "name": str(obj.get("ps") or obj.get("name") or "vmess"),
                "server": str(obj.get("add") or ""),
                "port": _safe_int(obj.get("port")),
                "uuid": str(obj.get("id") or ""),
                "alterId": _safe_int(obj.get("aid"), 0),
                "cipher": str(obj.get("scy") or "auto"),
                "network": (str(obj.get("net") or "tcp") or "tcp").lower(),
                "tls": str(obj.get("tls") or "").lower() in ("tls", "reality"),
                # پیش از این این سه مسیر (vmess/vless/trojan) خام عبور می‌کردند و
                # `_clean_sni` تنها بر hysteria2/tuic اعمال می‌شد. سنجشِ خروجیِ
                # زنده ۴۳۱ مقدارِ نامِ‌میزبانِ ساختاراً بی‌اعتبار را در همان سه
                # مسیر نشان داد. اکنون هر ورودیِ نامِ‌میزبان از یک دروازه می‌گذرد.
                "sni": _clean_sni(obj.get("sni") or obj.get("host")),
                "host": _clean_sni(obj.get("host")),
                "path": str(obj.get("path") or ""),
                # در vmess فیلد type برای grpc به‌عنوان serviceName استفاده می‌شود
                # و path معمولاً حامل آن است. fp نیز در برخی تولیدکننده‌ها هست.
                "servicename": str(obj.get("path") or "").lstrip("/"),
                "fp": str(obj.get("fp") or "").lower(),
                "reality": str(obj.get("tls") or "").lower() == "reality",
                "mode": str(obj.get("mode") or ""),
                "extra": str(obj.get("extra") or ""),
            }

        parsed = urllib.parse.urlparse(line.split("#")[0])
        q = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        scheme = parsed.scheme.lower()
        name = _remark_of(line) or scheme

        if scheme == "vless":
            return {
                "type": "vless",
                "name": name,
                "server": parsed.hostname or "",
                "port": _safe_int(parsed.port),
                "uuid": urllib.parse.unquote(parsed.username or ""),
                "network": (q.get("type") or "tcp").lower(),
                "tls": (q.get("security") or "").lower() in ("tls", "reality"),
                "reality": (q.get("security") or "").lower() == "reality",
                "sni": _clean_sni(q.get("sni") or q.get("host")),
                "host": _clean_sni(q.get("host")),
                "path": q.get("path") or "",
                "flow": q.get("flow") or "",
                "pbk": q.get("pbk") or "",
                "sid": q.get("sid") or "",
                "fp": q.get("fp") or "",
                "servicename": q.get("serviceName") or q.get("servicename") or "",
                # پارامترهای XHTTP (استاندارد Xray 2025/2026)
                "mode": q.get("mode") or "",
                "extra": q.get("extra") or "",
            }

        if scheme == "trojan":
            return {
                "type": "trojan",
                "name": name,
                "server": parsed.hostname or "",
                "port": _safe_int(parsed.port),
                "password": urllib.parse.unquote(parsed.username or ""),
                "network": (q.get("type") or "tcp").lower(),
                "sni": _clean_sni(q.get("sni") or q.get("host")),
                "host": _clean_sni(q.get("host")),
                "path": q.get("path") or "",
                "tls": True,  # trojan همیشه TLS
                "fp": q.get("fp") or "",
                "servicename": q.get("serviceName") or q.get("servicename") or "",
                "mode": q.get("mode") or "",
                "extra": q.get("extra") or "",
            }

        if scheme in ("ss", "shadowsocks"):
            # SIP002: ss://base64(method:pass)@host:port  یا  ss://method:pass@host:port
            rest = line[len(scheme) + 3:].split("#")[0]
            method = password = ""
            host = ""
            port = 0
            if "@" in rest:
                userinfo, hostpart = rest.rsplit("@", 1)
                hostpart = hostpart.split("?")[0]
                try:
                    dec = base64.urlsafe_b64decode(userinfo + "==").decode("utf-8", errors="ignore")
                    if ":" in dec:
                        userinfo = dec
                except Exception:
                    pass
                userinfo = urllib.parse.unquote(userinfo)
                if ":" in userinfo:
                    method, password = userinfo.split(":", 1)
                h, _, p = hostpart.rpartition(":")
                host, port = h, _safe_int(p)
            else:
                try:
                    dec = base64.urlsafe_b64decode(rest + "==").decode("utf-8", errors="ignore")
                    creds, _, hp = dec.rpartition("@")
                    if ":" in creds:
                        method, password = creds.split(":", 1)
                    h, _, p = hp.rpartition(":")
                    host, port = h, _safe_int(p)
                except Exception:
                    return None
            if not host or not port:
                return None
            # اعتبارسنجی سخت‌گیرانه: cipher نامعتبر (مثلاً UUIDی که اشتباهی در
            # جای method آمده) کل فایل Clash/Sing-box را برای کاربر می‌شکند.
            ok = _sanitize_ss(method, password)
            if not ok:
                return None
            method, password = ok
            return {
                "type": "shadowsocks",
                "name": name,
                "server": host,
                "port": port,
                "cipher": method,
                "password": password,
            }

        if scheme in ("hysteria2", "hy2"):
            # hysteria2://password@host:port/?sni=..&insecure=1&obfs=salamander
            #            &obfs-password=..&alpn=h3
            #
            # هر دو schemeی بالا در ورودیِ واقعی دیده می‌شود (اندازه‌گیری:
            # ۷۷ مورد با hysteria2:// و ۳ مورد با hy2://)، پس هر دو پذیرفته
            # می‌شوند وگرنه سه کانفیگ خاموشانه گم می‌شد.
            if not parsed.hostname or not parsed.port:
                return None
            # گذرواژه ممکن است در userinfo با یا بدونِ بخشِ کاربر بیاید
            pwd = urllib.parse.unquote(parsed.username or "")
            if parsed.password:
                pwd = f"{pwd}:{urllib.parse.unquote(parsed.password)}" if pwd else \
                    urllib.parse.unquote(parsed.password)
            if not pwd:
                return None
            obfs = (q.get("obfs") or "").strip().lower()
            # فقط salamander در hysteria2 استاندارد است؛ مقدارِ ناشناخته را
            # نادیده می‌گیریم تا کلاینت کلِ فایل را رد نکند.
            if obfs and obfs != "salamander":
                obfs = ""
            return {
                "type": "hysteria2",
                "name": name,
                "server": parsed.hostname,
                "port": _safe_int(parsed.port),
                "password": pwd,
                "sni": _clean_sni(q.get("sni") or q.get("peer")),
                "insecure": _truthy(q.get("insecure") or q.get("allowInsecure")
                                    or q.get("allow_insecure")),
                "obfs": obfs,
                "obfs_password": urllib.parse.unquote(
                    q.get("obfs-password") or q.get("obfs_password") or ""),
                "alpn": _alpn_list(q.get("alpn")),
                "tls": True,          # hysteria2 همیشه روی QUIC/TLS است
            }

        if scheme == "tuic":
            # tuic://uuid:password@host:port/?congestion_control=cubic
            #       &udp_relay_mode=native&sni=..&alpn=h3&allow_insecure=1
            if not parsed.hostname or not parsed.port:
                return None
            uuid = urllib.parse.unquote(parsed.username or "")
            pwd = urllib.parse.unquote(parsed.password or "")
            if not uuid or not pwd:
                return None
            cc = (q.get("congestion_control") or q.get("congestion-control")
                  or q.get("congestion") or "cubic").strip().lower()
            if cc not in _TUIC_CONGESTION:
                cc = "cubic"
            urm = (q.get("udp_relay_mode") or q.get("udp-relay-mode")
                   or "native").strip().lower()
            if urm not in ("native", "quic"):
                urm = "native"
            return {
                "type": "tuic",
                "name": name,
                "server": parsed.hostname,
                "port": _safe_int(parsed.port),
                "uuid": uuid,
                "password": pwd,
                "congestion_control": cc,
                "udp_relay_mode": urm,
                "sni": _clean_sni(q.get("sni")),
                "insecure": _truthy(q.get("allow_insecure") or q.get("insecure")
                                    or q.get("allowInsecure")),
                "alpn": _alpn_list(q.get("alpn")),
                "tls": True,          # tuic همیشه روی QUIC/TLS است
            }
    except Exception:
        return None
    return None


# ──────────────────────────────────────────────────────────────────────────────
# نرمال‌سازی transport
# ──────────────────────────────────────────────────────────────────────────────

#: نگاشت نام transport در URI به نام مورد انتظار mihomo.
#: «raw»/«tcp» نام‌های یکسانی برای حالت بدون transport هستند (Xray از 25.x
#: نام tcp را به raw تغییر داد). mihomo برای شبکهٔ ناشناخته به‌صورت خاموش به
#: TCP برمی‌گردد، پس نرمال‌سازی صریح لازم است تا داده گم نشود.
_CLASH_NETWORK_MAP: Dict[str, str] = {
    "tcp": "tcp", "raw": "tcp", "": "tcp", "none": "tcp",
    "ws": "ws", "websocket": "ws",
    "httpupgrade": "ws",       # mihomo آن را با ws + v2ray-http-upgrade می‌سازد
    "grpc": "grpc", "gun": "grpc",
    "xhttp": "xhttp", "splithttp": "xhttp",
    "h2": "h2", "http": "http",
    "kcp": "tcp", "mkcp": "tcp",   # mihomo از kcp پشتیبانی نمی‌کند → TCP
    "quic": "tcp",                 # پشتیبانی نمی‌شود → TCP
}

#: transport‌هایی که sing-box 1.13 واقعاً می‌شناسد (با تست تأیید شده).
#: xhttp در sing-box **وجود ندارد** → کانفیگ باید drop شود، نه اینکه بی‌سروصدا
#: به TCP تبدیل شود (که وصل نمی‌شود و کاربر فکر می‌کند سرور خراب است).
_SINGBOX_TRANSPORTS: frozenset = frozenset({"ws", "grpc", "http", "httpupgrade", "quic"})


def _clash_network(raw: str) -> str:
    return _CLASH_NETWORK_MAP.get((raw or "").lower(), "tcp")


def _reality_params(p: Dict[str, Any]) -> Optional[tuple]:
    """(pbk, sid) معتبر برای REALITY یا None.

    None در دو حالت: (الف) این کانفیگ اصلاً reality نیست → صدازننده باید بی‌خیال
    reality شود؛ (ب) مقادیر خراب‌اند → صدازننده باید کل کانفیگ را drop کند.
    برای تفکیک این دو، از کلید 'reality' استفاده می‌شود.
    """
    if not p.get("reality"):
        return None
    pbk = _sanitize_pbk(p.get("pbk", ""))
    if not pbk:
        return None
    sid = _sanitize_short_id(p.get("sid", ""))
    if sid is None:
        return None
    return pbk, sid


def _clash_transport_opts(p: Dict[str, Any], out: Dict[str, Any]) -> None:
    """گزینه‌های transport را به دیکشنری پروکسی Clash اضافه می‌کند.

    اسکیمای هر بخش از ساختارهای واقعی mihomo v1.19 استخراج شده است
    (adapter/outbound/vless.go: WSOptions / GrpcOptions / XHTTPOptions / HTTP2Options).
    """
    raw = (p.get("network") or "").lower()
    net = _clash_network(raw)
    host = p.get("host") or p.get("sni") or ""
    path = p.get("path") or "/"
    out["network"] = net

    if net == "ws":
        ws: Dict[str, Any] = {"path": path}
        if host:
            ws["headers"] = {"Host": host}
        if raw in ("httpupgrade",):
            # httpupgrade در mihomo یک شبکهٔ جدا نیست؛ ws با این پرچم است.
            ws["v2ray-http-upgrade"] = True
            ws["v2ray-http-upgrade-fast-open"] = True
        out["ws-opts"] = ws
    elif net == "grpc":
        # serviceName ممکن است در پارامتر serviceName یا در path آمده باشد.
        svc = p.get("servicename") or (p.get("path") or "").lstrip("/")
        out["grpc-opts"] = {"grpc-service-name": svc}
    elif net == "xhttp":
        xh: Dict[str, Any] = {"path": path}
        if host:
            xh["host"] = host
        if p.get("mode"):
            xh["mode"] = p["mode"]
        if p.get("extra"):
            # extra یک JSON خام از سمت Xray است؛ فقط کلیدهای شناخته‌شده را برمی‌داریم.
            try:
                ex = json.loads(p["extra"])
                if isinstance(ex, dict):
                    if isinstance(ex.get("xPaddingBytes"), (str, int)):
                        xh["x-padding-bytes"] = str(ex["xPaddingBytes"])
                    if isinstance(ex.get("noGRPCHeader"), bool):
                        xh["no-grpc-header"] = ex["noGRPCHeader"]
            except Exception:
                pass
        out["xhttp-opts"] = xh
    elif net == "h2":
        h2: Dict[str, Any] = {"path": path}
        if host:
            h2["host"] = [host]
        out["h2-opts"] = h2
    elif net == "http":
        ho: Dict[str, Any] = {"path": [path]}
        if host:
            ho["headers"] = {"Host": [host]}
        out["http-opts"] = ho
    # net == "tcp" → هیچ بخش transport لازم نیست


# ──────────────────────────────────────────────────────────────────────────────
# Clash / Mihomo YAML
# ──────────────────────────────────────────────────────────────────────────────

def _to_clash_proxy(p: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    t = p["type"]
    base = {"name": p["name"], "server": p["server"], "port": p["port"]}
    if not p["server"] or not p["port"]:
        return None
    try:
        if t == "vmess":
            out = {**base, "type": "vmess", "uuid": p["uuid"],
                   "alterId": p.get("alterId", 0), "cipher": p.get("cipher", "auto"),
                   "udp": True, "tls": p["tls"]}
            if p["sni"]:
                out["servername"] = p["sni"]
            _clash_transport_opts(p, out)
            return out
        if t == "vless":
            out = {**base, "type": "vless", "uuid": p["uuid"], "udp": True,
                   "tls": p["tls"]}
            flow = _sanitize_flow(p.get("flow", ""))
            if flow:
                out["flow"] = flow
            if p["sni"]:
                out["servername"] = p["sni"]
            if p.get("reality"):
                rp = _reality_params(p)
                if rp is None:
                    return None    # REALITY خراب → کل فایل را می‌شکند
                out["reality-opts"] = {"public-key": rp[0], "short-id": rp[1]}
            # client-fingerprint فقط مخصوص reality نیست — برای هر TLS معتبر است
            # و mihomo با آن ClientHello را شبیه مرورگر می‌کند (ضدسانسور).
            fp = (p.get("fp") or "").lower()
            if fp in UTLS_FINGERPRINTS:
                out["client-fingerprint"] = fp
            elif p.get("reality"):
                out["client-fingerprint"] = DEFAULT_UTLS_FINGERPRINT
            _clash_transport_opts(p, out)
            return out
        if t == "trojan":
            out = {**base, "type": "trojan", "password": p["password"], "udp": True}
            if p["sni"]:
                out["sni"] = p["sni"]
            fp = (p.get("fp") or "").lower()
            if fp in UTLS_FINGERPRINTS:
                out["client-fingerprint"] = fp
            _clash_transport_opts(p, out)
            return out
        if t == "shadowsocks":
            return {**base, "type": "ss", "cipher": p["cipher"], "password": p["password"], "udp": True}
        if t == "hysteria2":
            # نام‌گذاریِ کلیدها با mihomo v1.19.29 آزمون شد (rc=0).
            out = {**base, "type": "hysteria2", "password": p["password"]}
            if p.get("sni"):
                out["sni"] = p["sni"]
            if p.get("insecure"):
                out["skip-cert-verify"] = True
            if p.get("obfs"):
                out["obfs"] = p["obfs"]
                # obfs بدونِ گذرواژه در mihomo بی‌اثر است؛ اگر گذرواژه نبود
                # کلِ obfs را نمی‌نویسیم تا کاربر گمان نکند مخفی‌سازی فعال است.
                if p.get("obfs_password"):
                    out["obfs-password"] = p["obfs_password"]
                else:
                    out.pop("obfs")
            if p.get("alpn"):
                out["alpn"] = list(p["alpn"])
            return out
        if t == "tuic":
            out = {**base, "type": "tuic", "uuid": p["uuid"], "password": p["password"],
                   "congestion-controller": p.get("congestion_control", "cubic"),
                   "udp-relay-mode": p.get("udp_relay_mode", "native")}
            if p.get("sni"):
                out["sni"] = p["sni"]
            if p.get("insecure"):
                out["skip-cert-verify"] = True
            # tuic روی QUIC است و ALPN لازم دارد؛ اگر منبع آن را نگفت h3
            # پیش‌فرضِ استاندارد است. بدونِ ALPN، دست‌دادن در بسیاری از سرورها
            # شکست می‌خورد.
            out["alpn"] = list(p["alpn"]) if p.get("alpn") else ["h3"]
            return out
    except Exception:
        return None
    return None


#: سقف تعداد پروکسی در فایل‌های Clash/Sing-box.
#: سقف قبلی ۱۵۰۰ بود که ~۶۵٪ کانفیگ‌ها را دور می‌ریخت، در حالی که خروجی کامل
#: (~۴٬۲۰۰ پروکسی) فقط ۱.۳–۱.۸ مگابایت است و هر دو کلاینت آن را بی‌مشکل
#: بارگذاری می‌کنند (با sing-box 1.13.14 و mihomo 1.19.29 تست شد).
OUTPUT_PROXY_LIMIT = 20000


# ──────────────────────────────────────────────────────────────────────────────
# باگ خاموشِ ناسازگاریِ YAML 1.1 (PyYAML) با YAML 1.2 (Go / mihomo)
# ──────────────────────────────────────────────────────────────────────────────
# PyYAML طرح‌وارهٔ YAML 1.1 را پیاده می‌کند و `9e63` را «عدد» نمی‌شناسد (چون در
# ۱.۱ نماد علمی نیازمند نقطه است)، پس آن را **بدون کوتیشن** چاپ می‌کند.
# اما `gopkg.in/yaml.v3` که mihomo استفاده می‌کند طرح‌وارهٔ YAML 1.2 است و
# `9e63` را float ۹×۱۰⁶³ می‌خواند → مقدار به‌جای رشتهٔ hex، عدد می‌شود و
# mihomo با «invalid REALITY short ID» **کل فایل** را رد می‌کند.
#
# همین تله برای هر رشتهٔ دیگری هم هست: short-id، رمزِ فقط-عددی مثل `123456`
# (Go آن را int می‌خواند → خطای نوع)، UUIDهای عجیب، `0x…`، `true`/`null`.
# پس به‌جای وصلهٔ موردی، در سطحِ Dumper هر رشته‌ای که در YAML 1.2 ممکن است
# غیر-رشته تفسیر شود، اجباراً کوتیشن می‌شود.
_YAML12_AMBIGUOUS = re.compile(
    r"""^(?:
          [-+]?[0-9]+                                  # int ده‌دهی
        | 0[oO][0-7]+ | 0[xX][0-9a-fA-F]+              # اکتال / هگز
        | [-+]?(?:[0-9]+\.[0-9]*|\.[0-9]+|[0-9]+)      # float با/بدون نما
              (?:[eE][-+]?[0-9]+)?
        | [-+]?\.(?:inf|Inf|INF) | \.(?:nan|NaN|NAN)   # بی‌نهایت / NaN
        | true|True|TRUE|false|False|FALSE             # بولین
        | null|Null|NULL|~                             # تهی
        )$""",
    re.VERBOSE,
)


def _yaml_str_representer(dumper, data):  # type: ignore[no-untyped-def]
    """رشته‌های مبهم را با کوتیشن تک چاپ می‌کند تا Go آن‌ها را عدد نخواند."""
    if data == "" or _YAML12_AMBIGUOUS.match(data):
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="'")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


def _clash_dumper():  # type: ignore[no-untyped-def]
    """Dumper اختصاصی — بدون دست‌کاریِ حالتِ سراسریِ PyYAML.

    اگر libyaml موجود باشد از `CSafeDumper` استفاده می‌شود: در بنچمارکِ ۷٬۸۳۱
    پروکسی، ۳.۹۹s ← ۰.۹۷s (حدود ۴ برابر سریع‌تر). چون خروجی سه بار (all/heavy/
    light) تولید می‌شود، این تنها تغییر چند ثانیه از زمانِ هر اجرای CI می‌کاهد.
    اگر libyaml نبود، بی‌صدا به پیاده‌سازیِ پایتونی برمی‌گردیم.
    """
    import yaml

    base = getattr(yaml, "CSafeDumper", None) or yaml.SafeDumper

    class _SafeClashDumper(base):  # type: ignore[misc,valid-type]
        pass

    _SafeClashDumper.add_representer(str, _yaml_str_representer)
    return _SafeClashDumper


def build_clash_yaml(lines: List[str], limit: int = OUTPUT_PROXY_LIMIT) -> str:
    """لیست کانفیگ → رشتهٔ Clash YAML کامل (با proxy-groups)."""
    import yaml  # PyYAML

    proxies: List[Dict[str, Any]] = []
    used_names: set = set()
    _drops.clear_target("clash")
    for line in lines:
        if len(proxies) >= limit:
            _drops.record("clash", "over_limit", line)
            continue
        p = parse_proxy(line)
        if not p:
            _drops.record("clash", "unparsable", line)
            continue
        # سرورِ غیرقابلِ‌اتصال (loopback / 0.0.0.0 / …) در ریزه‌ی جداگانه شمرده
        # می‌شود نه در not_expressible: علتِ حذف نقصِ داده‌ی بالادست است، نه
        # محدودیتِ کلاینت؛ درهم‌ریختنِ این دو عدد، ریشه‌یابی را کور می‌کند.
        if _is_unroutable_server(p.get("server")):
            _drops.record("clash", "unroutable_server", line, p.get("type"))
            continue
        cp = _to_clash_proxy(p)
        if not cp:
            _drops.record("clash", "not_expressible", line, p.get("type"))
            continue
        # نام یکتا
        nm = cp["name"] or cp["type"]
        base_nm = nm
        i = 1
        while nm in used_names:
            nm = f"{base_nm} #{i}"
            i += 1
        cp["name"] = nm
        used_names.add(nm)
        proxies.append(cp)

    names = [p["name"] for p in proxies]
    doc = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "🚀 @Raydikalx", "type": "select",
             "proxies": ["♻️ Auto", "🔯 Fallback"] + names},
            {"name": "♻️ Auto", "type": "url-test",
             "url": "http://www.gstatic.com/generate_204",
             "interval": 300, "tolerance": 50, "proxies": names},
            {"name": "🔯 Fallback", "type": "fallback",
             "url": "http://www.gstatic.com/generate_204",
             "interval": 300, "proxies": names},
        ],
        "rules": ["MATCH,🚀 @Raydikalx"],
    }
    header = "# Clash subscription — generated by @Raydikalx aggregator\n"
    return header + yaml.dump(
        doc,
        Dumper=_clash_dumper(),
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        width=10 ** 6,   # هرگز خطِ بلند را نشکن؛ شکستنِ خط مقادیر base64 را خراب می‌کند
    )


# ──────────────────────────────────────────────────────────────────────────────
# Sing-box JSON
# ──────────────────────────────────────────────────────────────────────────────

def _singbox_tls(p: Dict[str, Any]) -> Dict[str, Any]:
    """بخش tls برای sing-box با تضمین حضور uTLS در صورت نیاز REALITY.

    نکتهٔ حیاتی: sing-box بدون uTLS برای reality خطای FATAL می‌دهد و
    **کل فایل** را رد می‌کند — نه فقط همان outbound. پس هر outbound دارای
    reality الزاماً باید utls داشته باشد.
    """
    tls: Dict[str, Any] = {"enabled": True, "server_name": p.get("sni") or p["server"]}
    rp = _reality_params(p)
    reality = rp is not None
    if reality:
        tls["reality"] = {"enabled": True, "public_key": rp[0], "short_id": rp[1]}
    fp = (p.get("fp") or "").lower()
    if fp not in UTLS_FINGERPRINTS:
        # اثرانگشت ناشناخته → «unknown uTLS fingerprint» و رد کل فایل.
        # پس یا مقدار پیش‌فرض معتبر می‌گذاریم (اجباری برای reality) یا رها می‌کنیم.
        fp = DEFAULT_UTLS_FINGERPRINT if reality else ""
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    if p.get("alpn"):
        tls["alpn"] = p["alpn"]
    return tls


def _singbox_transport(p: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """بخش transport برای sing-box، یا None اگر transport لازم نیست.

    مقدار بازگشتی «False» یعنی این کانفیگ در sing-box **قابل بیان نیست** و
    باید drop شود (مثل xhttp که sing-box 1.13 آن را نمی‌شناسد). تبدیل خاموش
    آن به TCP باعث می‌شود کاربر کانفیگی بگیرد که هرگز وصل نمی‌شود.
    """
    raw = (p.get("network") or "").lower()
    host = p.get("host") or p.get("sni") or ""
    path = p.get("path") or "/"

    if raw in ("", "tcp", "raw", "none"):
        return None                      # بدون transport
    if raw in ("ws", "websocket"):
        tr: Dict[str, Any] = {"type": "ws", "path": path}
        if host:
            tr["headers"] = {"Host": host}
        return tr
    if raw == "httpupgrade":
        tr = {"type": "httpupgrade", "path": path}
        if host:
            tr["host"] = host
        return tr
    if raw in ("grpc", "gun"):
        svc = p.get("servicename") or (p.get("path") or "").lstrip("/")
        return {"type": "grpc", "service_name": svc}
    if raw in ("h2", "http"):
        tr = {"type": "http", "path": path}
        if host:
            tr["host"] = [host]
        return tr
    if raw == "quic":
        return {"type": "quic"}
    # xhttp / splithttp / kcp / mkcp → sing-box پشتیبانی نمی‌کند
    return False  # type: ignore[return-value]


def _to_singbox_outbound(p: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    t = p["type"]
    if not p["server"] or not p["port"]:
        return None
    try:
        transport = _singbox_transport(p)
        if transport is False:
            return None   # transport غیرقابل‌بیان → drop (نه تبدیل خاموش به TCP)

        if t == "vmess":
            ob = {"type": "vmess", "tag": p["name"], "server": p["server"],
                  "server_port": p["port"], "uuid": p["uuid"],
                  "security": p.get("cipher", "auto"), "alter_id": p.get("alterId", 0)}
            if p["tls"]:
                ob["tls"] = _singbox_tls(p)
            if transport:
                ob["transport"] = transport
            return ob
        if t == "vless":
            if p.get("reality") and _reality_params(p) is None:
                return None    # REALITY خراب → کل فایل را می‌شکند
            ob = {"type": "vless", "tag": p["name"], "server": p["server"],
                  "server_port": p["port"], "uuid": p["uuid"]}
            flow = _sanitize_flow(p.get("flow", ""))
            if flow:
                ob["flow"] = flow
            if p["tls"]:
                ob["tls"] = _singbox_tls(p)
            if transport:
                ob["transport"] = transport
            return ob
        if t == "trojan":
            ob = {"type": "trojan", "tag": p["name"], "server": p["server"],
                  "server_port": p["port"], "password": p["password"],
                  "tls": _singbox_tls(p)}
            if transport:
                ob["transport"] = transport
            return ob
        if t == "shadowsocks":
            return {"type": "shadowsocks", "tag": p["name"], "server": p["server"],
                    "server_port": p["port"], "method": p["cipher"], "password": p["password"]}
        if t == "hysteria2":
            # ساختارِ زیر با sing-box 1.13.14 آزمون شد (rc=0). بر خلافِ Clash،
            # در sing-box مخفی‌سازی یک شیء تودرتو است نه دو کلیدِ جدا.
            ob = {"type": "hysteria2", "tag": p["name"], "server": p["server"],
                  "server_port": p["port"], "password": p["password"],
                  "tls": {"enabled": True,
                          "server_name": p.get("sni") or p["server"],
                          "insecure": bool(p.get("insecure"))}}
            if p.get("alpn"):
                ob["tls"]["alpn"] = list(p["alpn"])
            if p.get("obfs") and p.get("obfs_password"):
                ob["obfs"] = {"type": p["obfs"], "password": p["obfs_password"]}
            return ob
        if t == "tuic":
            ob = {"type": "tuic", "tag": p["name"], "server": p["server"],
                  "server_port": p["port"], "uuid": p["uuid"],
                  "password": p["password"],
                  "congestion_control": p.get("congestion_control", "cubic"),
                  "udp_relay_mode": p.get("udp_relay_mode", "native"),
                  "tls": {"enabled": True,
                          "server_name": p.get("sni") or p["server"],
                          "insecure": bool(p.get("insecure")),
                          "alpn": list(p["alpn"]) if p.get("alpn") else ["h3"]}}
            return ob
    except Exception:
        return None
    return None


def build_singbox_json(lines: List[str], limit: int = OUTPUT_PROXY_LIMIT) -> str:
    """لیست کانفیگ → رشتهٔ Sing-box JSON کامل (با selector/urltest)."""
    outbounds: List[Dict[str, Any]] = []
    used_tags: set = set()
    _drops.clear_target("singbox")
    for line in lines:
        if len(outbounds) >= limit:
            _drops.record("singbox", "over_limit", line)
            continue
        p = parse_proxy(line)
        if not p:
            _drops.record("singbox", "unparsable", line)
            continue
        if _is_unroutable_server(p.get("server")):
            _drops.record("singbox", "unroutable_server", line, p.get("type"))
            continue
        ob = _to_singbox_outbound(p)
        if not ob:
            _drops.record("singbox", "not_expressible", line, p.get("type"))
            continue
        tag = ob["tag"] or ob["type"]
        base_tag = tag
        i = 1
        while tag in used_tags:
            tag = f"{base_tag} #{i}"
            i += 1
        ob["tag"] = tag
        used_tags.add(tag)
        outbounds.append(ob)

    tags = [o["tag"] for o in outbounds]
    if not tags:
        # سند بدون هیچ outbound معتبر بی‌فایده است؛ selector/urltest خالی
        # در sing-box خطا می‌دهد. پس صریحاً خالی برنمی‌گردانیم.
        return json.dumps({"log": {"level": "info"}, "outbounds": [
            {"type": "direct", "tag": "direct"}]}, ensure_ascii=False, indent=2)

    # سند کامل و آمادهٔ استفاده مطابق اسکیمای sing-box ≥ 1.12/1.13:
    #   • DNS با فرمت جدید (type/server) — فرمت قدیمی address deprecated است
    #   • route.default_domain_resolver — نبودش هشدار deprecation می‌دهد
    #   • action-based route rules (sniff / hijack-dns / reject) به‌جای outbound=block
    #   • inbounds واقعی: tun برای موبایل/دسکتاپ + mixed برای مرورگر
    doc = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "proxy-dns", "type": "https", "server": "1.1.1.1",
                 "detour": "🚀 @Raydikalx"},
                {"tag": "local-dns", "type": "local"},
            ],
            "rules": [
                {"clash_mode": "Direct", "server": "local-dns"},
                {"clash_mode": "Global", "server": "proxy-dns"},
            ],
            "final": "proxy-dns",
            "strategy": "prefer_ipv4",
            "independent_cache": True,
        },
        "inbounds": [
            {"type": "tun", "tag": "tun-in",
             "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
             "auto_route": True, "strict_route": True, "stack": "mixed"},
            {"type": "mixed", "tag": "mixed-in",
             "listen": "127.0.0.1", "listen_port": 2080},
        ],
        "outbounds": [
            {"type": "selector", "tag": "🚀 @Raydikalx",
             "outbounds": ["♻️ Auto"] + tags, "default": "♻️ Auto"},
            {"type": "urltest", "tag": "♻️ Auto", "outbounds": tags,
             "url": "https://www.gstatic.com/generate_204",
             "interval": "5m", "tolerance": 50},
            *outbounds,
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": True, "outbound": "direct"},
            ],
            "final": "🚀 @Raydikalx",
            "auto_detect_interface": True,
            "default_domain_resolver": {"server": "local-dns"},
        },
        "experimental": {
            "cache_file": {"enabled": True, "store_fakeip": True},
            "clash_api": {"external_controller": "127.0.0.1:9090"},
        },
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)
