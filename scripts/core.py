# -*- coding: utf-8 -*-
"""
core.py — Self-contained V2Ray config processing engine for the aggregator.

این ماژول منطق اثبات‌شدهٔ ربات RaydikalxBot را به‌صورت standalone (بدون وابستگی
به دیتابیس/تلگرام) بازنویسی می‌کند تا داخل GitHub Actions اجرا شود:

  • _dedup_key()                  → اثرانگشت هویتِ سرور (CDN-aware)
  • _is_dummy_config()           → تشخیص کانفیگ خراب/جعلی
  • _detect_country_from_remark()→ تشخیص کشور (پرچم + کد + کلیدواژه)
  • brand_remark()               → برندینگ: «{CC} {flag} | @Raydikalx | {idx}»
  • protocol_of()                → تشخیص پروتکل یک کانفیگ
  • try_base64_decode()          → دیکد امن base64 (با بررسی کیفیت)
  • extract_valid_lines()        → استخراج خطوط کانفیگ معتبر از یک blob

منبع منطق: raydikalx/freeconfigs.py , raydikalx/fetcher.py , raydikalx/subscription.py
(کاملاً معادل، فقط مستقل و قابل اجرا در محیط CI)
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

# ──────────────────────────────────────────────────────────────────────────────
# ثابت‌ها
# ──────────────────────────────────────────────────────────────────────────────

# ══════════════════════════════════════════════════════════════════════════════
# 🔒 سیاستِ برندینگ — تصمیمِ مالکِ مخزن، غیرِقابلِ مذاکره
# ══════════════════════════════════════════════════════════════════════════════
# برندینگ یک «انتخابِ سلیقه‌ای» یا بدهیِ فنی نیست؛ **الزامِ محصول** است. مالکِ
# مخزن صریحاً اعلام کرده:
#
#     «بله برندینگ و اضافه کردن آیدی @Raydikalx عمدی است و میخواهم انجام شود
#      و به هیچ وجه نمیخوام برندینگ حذف شود یا انجام نشود
#      میخواهم *همیشه* آیدی کانالم @Raydikalx روی کانفیگ ها نوشته شود»
#
# پس ناوردایِ زیر باید همیشه برقرار باشد:
#
#     هر نودی که منتشر می‌شود — در `configs.txt`، `configs_base64.txt`،
#     `clash.yaml`، `singbox.json`، `protocols/*` و `archive/*` — باید
#     `BRAND_CHANNEL` را در ریمارک/نام/تگِ خود داشته باشد.
#
# ⚠️ برای هر کسی که بعداً این کد را می‌خواند (انسان یا عامل):
#
#   • «کاهشِ برندینگ» **رگرسیون** است، نه بهبود. نسخه‌های قدیمیِ نقشهٔ راه یک
#     آیتم به نامِ D-7 داشتند با عنوانِ «کاهشِ برندینگ به <۵٪». آن آیتم رسماً
#     `WON'T DO` شده است. اگر جایی آن را دیدید، سند قدیمی است — کد درست است.
#   • fallbackهای «بی‌برند» در `converters.py` هم عمداً به مقدارِ **برنددار**
#     هدف‌گیری شده‌اند؛ برگرداندنشان به `"vmess"`/`scheme`/`type` رگرسیون است.
#   • برندینگ **idempotent** است (اندازه‌گیری‌شده: ۴ نمونه × ۵ اعمالِ متوالی
#     ⇒ از نخستین اعمال پایدار)، پس اعمالِ دوباره‌اش بی‌خطر است. به همین دلیل
#     `aggregate.py` یک دروازهٔ fail-safe دارد که خطِ بی‌برند را دوباره برند
#     می‌زند و در نهایت — اگر بازهم بی‌برند بود — همان **یک خط** را کنار
#     می‌گذارد و در `health.json` می‌شمارد. هرگز کلِ اجرا را نمی‌شکند.
#   • تست‌های `test_pipeline.py` این ناوردا را روی هر ۴ قالبِ خروجی قفل
#     کرده‌اند. اگر تستی به‌خاطرِ «برند» شکست، تست درست است.
# ══════════════════════════════════════════════════════════════════════════════

#: برند کانال — تنها جای تعریف
BRAND_CHANNEL = "@Raydikalx"

# ──────────────────────────────────────────────────────────────────────────────
# 🧠 تشخیصِ هوشمندِ پروتکل (Dynamic / Future-proof)
# ──────────────────────────────────────────────────────────────────────────────
# سیستم به‌جای «لیستِ سفیدِ ثابت»، هر URI به‌شکلِ scheme://... را به‌عنوان یک
# کانفیگِ معتبر می‌پذیرد (مگر اینکه در لیستِ سیاهِ scheme‌های غیرپروکسی باشد).
# بنابراین اگر منابع فردا پروتکلِ جدیدی اضافه کنند (مثلاً anytls، juicity، snell،
# mieru، ssh، و…)، خودکار شناسایی، تجمیع، تکراری‌زدایی و دسته‌بندی می‌شود —
# بدونِ نیاز به تغییرِ کد.

#: نگاشتِ aliasهای شناخته‌شده → نامِ canonical (فقط برای تمیزی نام؛ نه محدودیت)
_SCHEME_ALIASES: Dict[str, str] = {
    "ss": "shadowsocks",
    "shadowsocks": "shadowsocks",
    "ssr": "shadowsocksr",
    "hy": "hysteria",
    "hysteria": "hysteria",
    "hy2": "hysteria2",
    "hysteria2": "hysteria2",
    "wg": "wireguard",
    "wireguard": "wireguard",
    "warp": "wireguard",
    "socks": "socks",
    "socks5": "socks",
}

#: scheme‌هایی که «پروکسی» نیستند و باید نادیده گرفته شوند (لیستِ سیاه)
#: (لینک‌های وب، فایل، تصویر و…)، تا متنِ نویزِ منابع به‌اشتباه کانفیگ تلقی نشود.
_NON_PROXY_SCHEMES: frozenset = frozenset({
    "http", "https", "ftp", "ftps", "file", "data", "mailto", "tel", "sms",
    "magnet", "git", "ssh+git", "ws", "wss", "tcp", "udp", "ipfs",
    "android-app", "intent", "javascript", "blob", "about", "chrome",
})

#: الگوی یک URI پروکسی:  scheme://...   (scheme معتبرِ RFC: حروف/عدد/+/-/.)
_URI_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+\-.]*)://", re.IGNORECASE)

#: حداقل طولِ یک کانفیگِ معتبر (کوتاه‌تر از این = نویز)
_MIN_CONFIG_LEN = 12

#: ترتیبِ ترجیحیِ نمایشِ پروتکل‌های پرکاربرد در خروجی/متادیتا.
#: پروتکل‌های ناشناخته/جدید بعد از این‌ها به‌ترتیبِ الفبا می‌آیند (خودکار).
PROTOCOL_ORDER: Tuple[str, ...] = (
    "vless", "vmess", "trojan", "shadowsocks", "shadowsocksr",
    "hysteria2", "hysteria", "tuic", "wireguard",
    "juicity", "anytls", "snell", "mieru", "socks",
)


def normalize_scheme(scheme: str) -> str:
    """نامِ scheme را به نامِ canonical پروتکل تبدیل می‌کند (هوشمند، با fallback)."""
    s = (scheme or "").strip().lower()
    return _SCHEME_ALIASES.get(s, s)


def is_proxy_config(line: str) -> bool:
    """
    تشخیصِ هوشمندِ اینکه آیا یک خط، کانفیگِ پروکسیِ معتبر است.

    منطق (future-proof):
      • باید الگوی scheme:// داشته باشد
      • scheme نباید در لیستِ سیاهِ غیرپروکسی باشد (http, ws, file, …)
      • طولِ کافی داشته باشد و حاوی فاصلهٔ خالی نباشد (URIهای واقعی فاصله ندارند)
    هر پروتکلِ جدیدی که این شرایط را داشته باشد، خودکار پذیرفته می‌شود.
    """
    if not line:
        return False
    line = line.strip()
    if len(line) < _MIN_CONFIG_LEN or " " in line.split("#", 1)[0]:
        return False
    m = _URI_SCHEME_RE.match(line)
    if not m:
        return False
    scheme = m.group(1).lower()
    if scheme in _NON_PROXY_SCHEMES:
        return False
    # باید بعد از :// محتوای واقعی داشته باشد
    after = line.split("://", 1)[1]
    return bool(after) and not after.startswith(("/", "#"))


#: سازگاریِ عقب‌رو: برخی توابع قدیمی هنوز به این نام رجوع می‌کنند.
#: حالا این فقط «prefixهای رایج» است (برای heuristicِ تشخیصِ base64)، نه محدودیتِ پذیرش.
VALID_PREFIXES: Tuple[str, ...] = (
    "vmess://", "vless://", "trojan://", "ss://",
    "shadowsocks://", "ssr://", "hy://", "hy2://", "hysteria://", "hysteria2://",
    "tuic://", "wireguard://", "wg://", "warp://",
    "juicity://", "anytls://", "snell://", "mieru://", "socks://", "socks5://",
)

# ──────────────────────────────────────────────────────────────────────────────
# تشخیص کشور (vendored از freeconfigs.py)
# ──────────────────────────────────────────────────────────────────────────────

_FLAG_EMOJI_RE = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")

_COUNTRY_KEYWORD_MAP: Dict[str, Tuple[str, str]] = {
    "united states": ("US", "🇺🇸"), "usa": ("US", "🇺🇸"), "america": ("US", "🇺🇸"),
    "آمریکا": ("US", "🇺🇸"), "امریکا": ("US", "🇺🇸"),
    "germany": ("DE", "🇩🇪"), "deutschland": ("DE", "🇩🇪"), "آلمان": ("DE", "🇩🇪"),
    "finland": ("FI", "🇫🇮"), "فنلاند": ("FI", "🇫🇮"),
    "turkey": ("TR", "🇹🇷"), "turkiye": ("TR", "🇹🇷"), "ترکیه": ("TR", "🇹🇷"),
    "united kingdom": ("GB", "🇬🇧"), "uk": ("GB", "🇬🇧"), "england": ("GB", "🇬🇧"),
    "انگلیس": ("GB", "🇬🇧"), "بریتانیا": ("GB", "🇬🇧"),
    "france": ("FR", "🇫🇷"), "فرانسه": ("FR", "🇫🇷"),
    "netherlands": ("NL", "🇳🇱"), "holland": ("NL", "🇳🇱"), "هلند": ("NL", "🇳🇱"),
    "switzerland": ("CH", "🇨🇭"), "سوئیس": ("CH", "🇨🇭"),
    "sweden": ("SE", "🇸🇪"), "سوئد": ("SE", "🇸🇪"),
    "norway": ("NO", "🇳🇴"), "نروژ": ("NO", "🇳🇴"),
    "ireland": ("IE", "🇮🇪"), "ایرلند": ("IE", "🇮🇪"),
    "italy": ("IT", "🇮🇹"), "ایتالیا": ("IT", "🇮🇹"),
    "austria": ("AT", "🇦🇹"), "اتریش": ("AT", "🇦🇹"),
    "belgium": ("BE", "🇧🇪"), "بلژیک": ("BE", "🇧🇪"),
    "portugal": ("PT", "🇵🇹"), "پرتغال": ("PT", "🇵🇹"),
    "spain": ("ES", "🇪🇸"), "اسپانیا": ("ES", "🇪🇸"),
    "denmark": ("DK", "🇩🇰"), "دانمارک": ("DK", "🇩🇰"),
    "poland": ("PL", "🇵🇱"), "لهستان": ("PL", "🇵🇱"),
    "czech republic": ("CZ", "🇨🇿"), "czechia": ("CZ", "🇨🇿"), "czech": ("CZ", "🇨🇿"),
    "romania": ("RO", "🇷🇴"), "رومانی": ("RO", "🇷🇴"),
    "hungary": ("HU", "🇭🇺"), "مجارستان": ("HU", "🇭🇺"),
    "serbia": ("RS", "🇷🇸"), "صربستان": ("RS", "🇷🇸"),
    "bulgaria": ("BG", "🇧🇬"), "بلغارستان": ("BG", "🇧🇬"),
    "croatia": ("HR", "🇭🇷"), "کرواسی": ("HR", "🇭🇷"),
    "luxembourg": ("LU", "🇱🇺"), "لوکزامبورگ": ("LU", "🇱🇺"),
    "latvia": ("LV", "🇱🇻"), "لتونی": ("LV", "🇱🇻"),
    "lithuania": ("LT", "🇱🇹"), "لیتوانی": ("LT", "🇱🇹"),
    "estonia": ("EE", "🇪🇪"), "استونی": ("EE", "🇪🇪"),
    "greece": ("GR", "🇬🇷"), "یونان": ("GR", "🇬🇷"),
    "slovakia": ("SK", "🇸🇰"), "اسلواکی": ("SK", "🇸🇰"),
    "moldova": ("MD", "🇲🇩"), "مولداوی": ("MD", "🇲🇩"),
    "russia": ("RU", "🇷🇺"), "روسیه": ("RU", "🇷🇺"),
    "ukraine": ("UA", "🇺🇦"), "اوکراین": ("UA", "🇺🇦"),
    "kazakhstan": ("KZ", "🇰🇿"), "قزاقستان": ("KZ", "🇰🇿"),
    "singapore": ("SG", "🇸🇬"), "سنگاپور": ("SG", "🇸🇬"),
    "japan": ("JP", "🇯🇵"), "ژاپن": ("JP", "🇯🇵"),
    "south korea": ("KR", "🇰🇷"), "korea": ("KR", "🇰🇷"), "کره": ("KR", "🇰🇷"),
    "hong kong": ("HK", "🇭🇰"), "hongkong": ("HK", "🇭🇰"), "هنگ کنگ": ("HK", "🇭🇰"),
    "taiwan": ("TW", "🇹🇼"), "تایوان": ("TW", "🇹🇼"),
    "china": ("CN", "🇨🇳"), "چین": ("CN", "🇨🇳"),
    "india": ("IN", "🇮🇳"), "هند": ("IN", "🇮🇳"),
    "iran": ("IR", "🇮🇷"), "ایران": ("IR", "🇮🇷"),
    "indonesia": ("ID", "🇮🇩"), "اندونزی": ("ID", "🇮🇩"),
    "vietnam": ("VN", "🇻🇳"), "ویتنام": ("VN", "🇻🇳"),
    "thailand": ("TH", "🇹🇭"), "تایلند": ("TH", "🇹🇭"),
    "malaysia": ("MY", "🇲🇾"), "مالزی": ("MY", "🇲🇾"),
    "pakistan": ("PK", "🇵🇰"), "پاکستان": ("PK", "🇵🇰"),
    "uae": ("AE", "🇦🇪"), "dubai": ("AE", "🇦🇪"), "امارات": ("AE", "🇦🇪"),
    "egypt": ("EG", "🇪🇬"), "مصر": ("EG", "🇪🇬"),
    "south africa": ("ZA", "🇿🇦"), "آفریقای جنوبی": ("ZA", "🇿🇦"),
    "canada": ("CA", "🇨🇦"), "کانادا": ("CA", "🇨🇦"),
    "australia": ("AU", "🇦🇺"), "استرالیا": ("AU", "🇦🇺"),
    "new zealand": ("NZ", "🇳🇿"), "نیوزیلند": ("NZ", "🇳🇿"),
    "brazil": ("BR", "🇧🇷"), "برزیل": ("BR", "🇧🇷"),
    "argentina": ("AR", "🇦🇷"), "آرژانتین": ("AR", "🇦🇷"),
    "mexico": ("MX", "🇲🇽"), "مکزیک": ("MX", "🇲🇽"),
}

_VALID_CC = frozenset(v[0] for v in _COUNTRY_KEYWORD_MAP.values())
_SORTED_KEYWORDS = sorted(_COUNTRY_KEYWORD_MAP.items(), key=lambda x: len(x[0]), reverse=True)


def _flag_to_country_code(flag: str) -> Optional[str]:
    if len(flag) != 2:
        return None
    try:
        c1 = chr(ord(flag[0]) - 0x1F1E6 + 65)
        c2 = chr(ord(flag[1]) - 0x1F1E6 + 65)
        code = f"{c1}{c2}"
        return code if code in _VALID_CC else None
    except Exception:
        return None


def detect_country_from_remark(remark: str) -> Tuple[str, str]:
    """
    تشخیصِ کشور از روی متنِ ریمارک — تنها به‌عنوانِ چارهٔ آخر.

    این تابع پیش از این منبعِ *اصلیِ* برچسبِ کشور بود و سه مرحله داشت. مرحلهٔ
    سوم هر واژهٔ دوحرفیِ لاتین را کدِ کشور فرض می‌کرد، که یک حدس بود نه یک
    اندازه‌گیری. نمونه‌های واقعی از خروجیِ همین مخزن:

        «join-us-on-Telegram»      → US   (واژهٔ «us» انگلیسی است، نه کشور)
        «剩余流量：55.26 GB»        → GB   (یکای گیگابایت، نه بریتانیا)
        «Speed: 20 mb/s NO limit»  → NO   (قیدِ نفی، نه نروژ)

    اندازه‌گیریِ دقتِ کلِ این روش روی ۶۷۵ کانفیگ با کشورِ واقعیِ مستقل
    (ip-api.com): ۵۳٫۶٪ درست، ۱۴٫۷٪ **غلط**، ۳۱٫۷٪ تسلیم. برچسبِ غلط از نبودِ
    برچسب زیان‌بارتر است، چون کاربر آن را باور می‌کند.

    اکنون منبعِ اصلی، مکانِ واقعیِ شبکه است (geo.py). این تابع فقط وقتی به کار
    می‌آید که پایگاهِ دادهٔ GeoIP در دسترس نباشد — یعنی حالتِ کاهش‌یافته. پس:

      • مرحلهٔ پرچمِ یونیکد نگه داشته شد: پرچم یک ادعای صریحِ ماشین‌خوان است.
      • مرحلهٔ کلیدواژه نگه داشته شد ولی تنها با مرزِ واژه، تا «Vienna» دیگر
        در «Viennam» یا نامِ کاربری گم نشود.
      • حلقهٔ حدسِ دوحرفی **حذف شد**. هیچ برچسبی بهتر از برچسبِ اشتباه است.

    چرا حتی نسخهٔ «محافظه‌کارِ» حدس هم برنگشت
    ────────────────────────────────────────
    این پرسش جدی گرفته شد و آزموده شد، نه رد. فرضیه: «شاید کدِ دوحرفی اگر فقط
    در *ابتدای* ریمارک و پیش از یک جداکننده باشد، قابلِ اعتماد است.» سه راهبرد
    روی ۴٬۲۹۱ ریمارکِ **واقعیِ منابعِ بالادست** (نه ریمارکِ برندشدهٔ خودمان،
    که پرچم دارد و آزمون را بی‌معنا می‌کند) با مرجعِ مستقلِ ip-api سنجیده شد:

        الف) حدس در هر جای متن   درست ۳۹٫۵٪   غلط ۸٫۲٪   تسلیم ۵۲٫۳٪
        ب ) بدونِ حدس (فعلی)     درست ۳۹٫۱٪   غلط ۶٫۰٪   تسلیم ۵۵٫۰٪
        ج ) حدسِ فقط ابتدای متن  درست ۳۹٫۲٪   غلط ۶٫۳٪   تسلیم ۵۴٫۵٪

    «ج» در برابرِ «ب» ‎+۰٫۱۶٪ درست می‌آورد ولی ‎+۰٫۳۳٪ غلط — یعنی به ازای هر
    برچسبِ درستِ تازه، دو برچسبِ غلط. نمونهٔ واقعیِ شکستش: «AE_speednode_0001»
    که کدِ ابتدای متنش AE است ولی سرور در فرانسه است، و «CN_speednode_0005»
    که در آمریکا است. پس حدس، حتی مهارشده، سود نمی‌دهد و برنگشت.

    توجه: حذفِ حدس، «تسلیم» را از ۵۲٫۳٪ به ۵۵٫۰٪ می‌برد؛ این بهاست، نه باگ. در
    حالتِ عادی GeoIP آن ۵۵٪ را پر می‌کند و تسلیم به ۰٪ می‌رسد.
    """
    if not remark:
        return ("Global", "🌐")
    for flag in _FLAG_EMOJI_RE.findall(remark):
        code = _flag_to_country_code(flag)
        if code:
            return (code, flag)
    remark_lower = remark.lower()
    for keyword, info in _SORTED_KEYWORDS:
        # مرزِ واژه لازم است: بدونِ آن کلیدواژهٔ «us» داخلِ «trust» یا
        # «status» هم می‌افتد. اندازه‌گیری نشان داد بیشترِ خطاهای مرحلهٔ
        # کلیدواژه از همین جای‌گیریِ درونِ واژه می‌آمد.
        if _keyword_hit(remark_lower, keyword):
            return info
    return ("Global", "🌐")


def _keyword_hit(haystack: str, needle: str) -> bool:
    """
    آیا کلیدواژه به‌صورتِ واژهٔ مستقل در متن آمده است؟

    برای کلیدواژه‌های کوتاه (تا سه حرف) مرزِ واژه الزامی است، چون رشتهٔ کوتاه
    به‌سادگی داخلِ واژه‌های بی‌ربط پیدا می‌شود. برای کلیدواژه‌های بلندتر مانند
    «netherlands» جست‌وجوی ساده کافی و مطلوب است، چون در نام‌های مرکب مانند
    «amsterdam-netherlands-01» هم باید پیدا شود.
    """
    if len(needle) > 3:
        return needle in haystack
    i = haystack.find(needle)
    while i != -1:
        before = haystack[i - 1] if i > 0 else ""
        after = haystack[i + len(needle)] if i + len(needle) < len(haystack) else ""
        if not before.isalnum() and not after.isalnum():
            return True
        i = haystack.find(needle, i + 1)
    return False


# ──────────────────────────────────────────────────────────────────────────────
# پایداریِ برچسبِ کشور
#
# چرا این بخش وجود دارد: برچسبِ کشور تا پیش از این فقط از متنِ ریمارکِ منبع
# خوانده می‌شد. هر منبع برای یک سرورِ یکسان ریمارکِ متفاوتی می‌دهد، پس یک
# کانفیگِ ثابت در اجرای اول «RU 🇷🇺» و در اجرای بعدی «US 🇺🇸» برچسب می‌خورد.
# پیامدِ عملی: ۳۲۶۸ خط از ۳۵۳۷ خط در هر اجرا فقط به‌خاطرِ ریمارک تغییر می‌کرد
# (بدنهٔ فنی دست‌نخورده)، پس هر انتشار تقریباً کل فایل را از نو می‌نوشت.
#
# راهکار: برچسب به «مقصدِ اتصال» گره می‌خورد، نه به متنِ منبع. برای یک
# host/IP یکسان همیشه یک برچسب تولید می‌شود، مستقل از این‌که کدام منبع آن را
# آورده باشد. اگر هیچ منبعی کشور را نگوید، «Global 🌐» می‌ماند.
# ──────────────────────────────────────────────────────────────────────────────

_HOST_COUNTRY_CACHE: dict = {}


# ──────────────────────────────────────────────────────────────────────────────
# دیکدِ base64 که به نسخهٔ مفسر وابسته نیست
# ──────────────────────────────────────────────────────────────────────────────
#
# ⚠️ چرا این تابع وجود دارد — یک یافتهٔ اندازه‌گیری‌شده، نه احتیاطِ نظری.
#
# `base64.urlsafe_b64decode` روی ورودیِ حاویِ padding در **میانه** بین نسخه‌های
# CPython رفتارِ متفاوت دارد. اندازه‌گیریِ مستقیم روی `urlsafe_b64decode(s + "==")`:
#
#     s = "QUJDRA==EFGH"       →  3.10 : b"ABCD"                 3.13 : b"ABCD\x01\x05\x18"
#     s = "QUJDRA==@host:443"  →  3.10 : b"ABCD"                 3.13 : binascii.Error  ← پرتاب!
#     s = "QUJDRQ=XYZ"         →  3.10 : binascii.Error          3.13 : binascii.Error
#     s = "QUJD@RA=="          →  3.10 : b"ABCD"                 3.13 : b"ABCD"
#
# سه رفتارِ متفاوت، و یکی از آن‌ها استثنا می‌پرتابد. چون `dedup_key` استثنا را با
# `except: pass` می‌بلعد، نتیجه یک **کلیدِ هویتِ متفاوت** است، بی‌هیچ صدایی.
#
# پیامدِ واقعی که سنجیده شد: دو کانفیگ از ۸٬۱۳۶ کانفیگِ منتشرشده برچسبی داشتند
# که مفسرِ ۳.۱۳ بازتولید نمی‌کرد، در حالی که ۳.۱۰ و CI (۳.۱۲) هر دو همان برچسبِ
# منتشرشده را می‌دادند (`3BA0F5`، `25CF83`). ورودی اثباتاً یکسان بود: sha256 فایلِ
# نمونه و sha256 خودِ `userinfo` در دو محیط برابر بودند و تنها خروجیِ دیکد
# ۷۴ بایت در برابر ۸۰ بایت شد.
#
# `dedup_key` تابعِ **هویتِ** این مخزن است: یکتاسازی، ترتیبِ خروجی، برچسبِ ریمارک،
# و شمارشِ مالکیت در `unique_yield` (فاز D) همه به آن تکیه دارند. یک تابعِ هویت
# نباید به نسخهٔ مفسر وابسته باشد.
#
# راهکار: به‌جای تقلیدِ رفتارِ نامستندِ یک نسخهٔ خاص، **صورتِ مسئله را حذف می‌کنیم**:
# اگر ورودی نحواً base64 نیست، تظاهر به دیکد نمی‌کنیم و `None` برمی‌گردانیم. برای
# ورودیِ تمیز (که ۹۹.۹۷٪ موارد است) نتیجه با همهٔ نسخه‌ها یکسان است — و این
# اندازه‌گیری شد، نه فرض.
#
# 🚫 عمداً در `try_base64_decode` (دیکدِ **بدنهٔ منابع**) استفاده نمی‌شود. آن‌جا
#    اندازه‌گیریِ زنده روی هر ۲۱ منبعِ واقعی (شاملِ ۴ منبعِ base64) نشان داد
#    ۳.۱۰ و ۳.۱۳ **کاملاً یکسان**اند (۲۰٬۵۲۰ خط در هر دو، ۰ منبع با تفاوت)، و
#    محافظِ چگالیِ ۲۰٪ هم آن مسیر را مقاوم می‌کند. اِعمالِ گیتِ نحوی آن‌جا
#    می‌توانست منبعی را که امروز جزئاً دیکد می‌شود کاملاً رد کند — یعنی از دست
#    دادنِ کانفیگ در ازای مشکلی که وجود ندارد.

#: بدنهٔ base64 — هر دو گونهٔ استاندارد (`+/`) و urlsafe (`-_`) با padding اختیاری
#: در **انتها**. وجودِ `=` در میانه یا هر کاراکترِ خارج از الفبا ⇒ ورودی base64 نیست.
_B64_BODY_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")


def decode_base64_text(candidate: str) -> Optional[str]:
    """
    اگر `candidate` **نحواً** base64 باشد متنِ دیکدشده را برمی‌گرداند، وگرنه None.

    قطعی است: خروجی فقط تابعِ ورودی است، نه نسخهٔ CPython. جزئیاتِ چرایی در
    کامنتِ بالای همین بخش.
    """
    s = (candidate or "").strip()
    if not s or not _B64_BODY_RE.match(s):
        return None
    body = s.rstrip("=")
    # طولِ ۴k+1 در base64 ممکن نیست؛ همهٔ نسخه‌ها این را خطا می‌دانند.
    if len(body) % 4 == 1:
        return None
    body += "=" * ((4 - len(body) % 4) % 4)
    try:
        # `urlsafe_b64decode` هر دو الفبا را می‌پوشاند: `-`/`_` را ترجمه می‌کند و
        # `+`/`/` را دست‌نخورده رد می‌کند. پس یک فراخوانی کافی است.
        raw = base64.urlsafe_b64decode(body)
    except Exception:
        return None
    return raw.decode("utf-8", errors="ignore")


def endpoint_of(line: str) -> str:
    """آدرسِ مقصدِ کانفیگ (host یا IP) بدونِ پورت. برای vmess از JSON خوانده می‌شود."""
    line = (line or "").strip()
    if not line:
        return ""
    try:
        if line.startswith("vmess://"):
            # اکثرِ vmessها بدنهٔ base64+JSON دارند، ولی *نه همه‌شان*. بعضی منابع
            # vmess را در قالبِ استانداردِ URI می‌دهند، دقیقاً مثلِ vless:
            #
            #   vmess://<uuid>@91.107.139.186:51459?encryption=auto&type=tcp#…
            #
            # پیش از این، شکستِ JSON این‌جا به `return ""` می‌رسید و مقصد «نامعلوم»
            # می‌شد. پیامدِ واقعی‌اش فقط یک برچسبِ ازدست‌رفته نبود: چون
            # `brand_remark` بی‌مقصد کاری نمی‌کند، ریمارکِ بالادست دست‌نخورده
            # منتشر می‌شد و تبلیغِ کانالِ رقیب («📯1@oneclickvpnkeys») در خروجیِ
            # ما می‌نشست. شمارشِ زنده در همین اجرا: ۱ مورد از ۸٬۰۱۸.
            #
            # پس در صورتِ شکست، به تجزیهٔ عمومیِ URI پایین می‌افتیم و همان‌جا
            # میزبان درست به‌دست می‌آید.
            b64 = line[8:].split("#")[0].strip()
            _txt = decode_base64_text(b64)
            try:
                obj = json.loads(_txt) if _txt is not None else None
            except Exception:
                obj = None
            if isinstance(obj, dict):
                host = str(obj.get("add") or obj.get("host") or "").strip().lower()
                if host:
                    return host
            # نه JSON بود و نه میزبانی داشت → ادامه با مسیرِ عمومی
        # سایر پروتکل‌ها: scheme://[userinfo@]host[:port][?query][#fragment]
        rest = line.split("://", 1)[1] if "://" in line else line
        rest = rest.split("#", 1)[0].split("?", 1)[0]
        if "@" in rest:
            rest = rest.rsplit("@", 1)[1]
        rest = rest.split("/", 1)[0]
        if rest.startswith("["):                      # IPv6 literal
            return rest.split("]", 1)[0][1:].lower()
        return rest.rsplit(":", 1)[0].lower() if ":" in rest else rest.lower()
    except Exception:
        return ""


def country_for_endpoint(endpoint: str, remark_hint: str = "") -> Tuple[str, str]:
    """
    برچسبِ پایدارِ کشور برای یک مقصد، با ترتیبِ اولویتِ زیر:

        ۱. GeoIP روی نشانیِ واقعیِ شبکه   ← معتبرترین، اندازه‌گیری‌شده ۹۷٫۹٪ درست
        ۲. پرچمِ یونیکدِ داخلِ ریمارک       ← ادعای صریحِ منبع (حالتِ کاهش‌یافته)
        ۳. کلیدواژهٔ نامِ کشور در ریمارک    ← حالتِ کاهش‌یافته
        ۴. «Global 🌐»                     ← اعترافِ صادقانه به ندانستن

    چرا GeoIP بالاتر از پرچمِ منبع است: پرچمِ ریمارک را نویسندهٔ منبع می‌نویسد و
    اندازه‌گیری نشان داد که ۱۴٫۷٪ از برچسب‌های حاصل از ریمارک با کشورِ واقعیِ
    سرور نمی‌خواند. مکانِ واقعیِ شبکه قابلِ اندازه‌گیری است؛ متنِ ریمارک نه.
    برای همین، پرچمِ نادرستِ بالادست بازنویسی می‌شود.

    پایداری: نتیجه برای هر مقصد یک بار محاسبه و در حافظه قفل می‌شود، پس اگر
    ده منبعِ مختلف یک سرور را با ده ریمارکِ متفاوت بیاورند، همه یک برچسب
    می‌گیرند و خروجی بینِ اجراها ثابت می‌ماند.
    """
    ep = (endpoint or "").strip().lower()
    if not ep:
        return detect_country_from_remark(remark_hint)
    cached = _HOST_COUNTRY_CACHE.get(ep)
    if cached is not None:
        return cached

    # ۱) مکانِ واقعیِ شبکه. اگر پایگاهِ دادهٔ GeoIP نبود، geo ماژول None
    #    برمی‌گرداند و به مرحلهٔ بعد می‌رویم؛ نبودِ آن هرگز خطا نمی‌دهد.
    try:
        from . import geo  # type: ignore
    except Exception:
        try:
            import geo  # type: ignore
        except Exception:
            geo = None  # type: ignore
    if geo is not None:
        try:
            hit = geo.country_for_host(ep)
        except Exception:
            hit = None
        if hit:
            _HOST_COUNTRY_CACHE[ep] = hit
            return hit

    # ۲و۳) حالتِ کاهش‌یافته: خواندنِ ریمارک
    info = detect_country_from_remark(remark_hint)
    # فقط نتیجهٔ قاطع را قفل می‌کنیم؛ «Global» یعنی هنوز نمی‌دانیم، پس اگر
    # منبعِ بعدی کشور را گفت اجازهٔ ارتقا می‌دهیم.
    if info[0] != "Global":
        _HOST_COUNTRY_CACHE[ep] = info
    return info


def reset_country_cache() -> None:
    """پاک‌سازیِ حافظهٔ برچسب‌ها (برای تست‌های مستقل)."""
    _HOST_COUNTRY_CACHE.clear()


def stable_label(line: str) -> str:
    """
    شناسهٔ پایدارِ کانفیگ برای انتهای ریمارک.

    پیش از این شماره از موقعیتِ خط می‌آمد (enumerate)، پس افزودن یا حذفِ یک
    کانفیگ، شمارهٔ همهٔ خطوطِ بعدی را جابه‌جا می‌کرد و باعثِ تغییرِ سراسریِ فایل
    می‌شد. اکنون شناسه از خودِ محتوای کانفیگ مشتق می‌شود، پس تا وقتی کانفیگ
    عوض نشود شناسه‌اش هم عوض نمی‌شود.
    """
    key = dedup_key(line) or (line or "").strip()
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:6].upper()


# ──────────────────────────────────────────────────────────────────────────────
# dedup key (vendored از freeconfigs._dedup_key)
# ──────────────────────────────────────────────────────────────────────────────

_IDENTITY_PARAMS = frozenset({
    "security", "sni", "pbk", "sid", "host", "path", "servicename",
    "flow", "type", "headertype", "encryption", "mode",
    "obfs", "obfs-password", "obfspassword",
    "congestion_control", "congestion",
    "publickey", "presharedkey", "address",
})


def _norm_type(t: str) -> str:
    t = (t or "").strip().lower()
    return "tcp" if t in ("", "raw", "none", "tcp") else t


def _norm_identity_value(key: str, val: str) -> str:
    v = (val or "").strip().lower()
    if key in ("sni", "host"):
        for _ in range(2):
            nv = urllib.parse.unquote(v)
            if nv == v:
                break
            v = nv
        v = v.strip().lower()
    if key == "type":
        return _norm_type(v)
    if key == "encryption":
        return "" if v in ("", "none") else v
    if key == "security":
        return "" if v in ("", "none") else v
    if key == "headertype":
        return "" if v in ("", "none") else v
    if key == "flow":
        return "" if v == "" else v
    return v


def dedup_key(line: str) -> str:
    """Fingerprint هویتِ سرور — CDN-aware (دقیقاً معادل ربات)."""
    line = line.strip()
    if not line:
        return line

    if line.startswith("vmess://"):
        try:
            b64 = line[8:].split("#")[0].strip()
            _txt = decode_base64_text(b64)
            if _txt is None:
                raise ValueError("vmess payload is not base64")
            obj = json.loads(_txt)
            add = (str(obj.get("add") or "")).strip().lower()
            host = _norm_identity_value("host", str(obj.get("host") or ""))
            sni = _norm_identity_value("sni", str(obj.get("sni") or ""))
            tls = (str(obj.get("tls") or "")).strip().lower()
            tls = "" if tls in ("", "none") else tls
            net = _norm_type(str(obj.get("net") or ""))
            path = str(obj.get("path") or "").rstrip("/")
            fronting = host or sni
            add_for_key = "" if fronting else add
            return (
                f"vmess:{add_for_key}|ep={fronting}"
                f":{str(obj.get('port', '')).strip()}"
                f":{str(obj.get('id', '')).strip().lower()}"
                f":{net}:{path}:{tls}"
            )
        except Exception:
            return line.split("#")[0].strip()[:120]

    if line.startswith("ss://"):
        try:
            without_remark = line.split("#")[0].strip()
            rest = without_remark[5:]
            # جدا کردنِ authority از query — پیش از هر rsplit روی '@'.
            #
            # چرا: پیش از این `rest.rsplit("@", 1)` روی **کلِ** رشته اجرا می‌شد.
            # اگر query خودش '@' داشت (در دادهٔ واقعی فراوان است، مثلِ
            # `?note=@SomeChannel`)، آخرین '@' داخلِ query بود و نتیجه:
            #
            #   ss://<b64>@1.2.3.4:11201?note=@FreeOnlineVPN
            #     userinfo → "<b64>@1.2.3.4:11201?note="   (دیگر base64 نیست)
            #     hostpart → "FreeOnlineVPN"
            #     host     → ""            port → "FreeOnlineVPN"
            #
            # یعنی هویتِ endpoint کاملاً نابود می‌شد. شمارشِ زنده روی پیکره:
            # ۱۴ کلید از ۳٬۰۰۶ خطِ ss (۱۲ موردِ '@' در query + ۲ موردِ '/'
            # چسبیده به port). پس از وصله: ۰ کلید با hostِ خالی یا portِ
            # غیرعددی. پارتیشنِ یکتاسازی عوض نمی‌شود (splits=0, merges=0).
            #
            # قاعده **عیناً** همان است که `endpoint_of()` در همین فایل به‌کار
            # می‌برد: (۱) برشِ query  (۲) rsplit روی '@'  (۳) برشِ path.
            # عمداً سرِ '/' *قبل از* rsplit نمی‌بُریم: userinfoِ SS2022 حاویِ
            # base64ِ استاندارد است و '/' و '+' رمزنگاری‌نشده دارد، مثلِ
            # `ss://2022-blake3-aes-256-gcm:bw2o/kKF…=:o0BV…=@host:port` —
            # بریدن سرِ '/' آن را به شاخهٔ legacy می‌انداخت و کلید را خراب‌تر
            # می‌کرد.
            authority = rest.split("?", 1)[0]
            if "@" in authority:
                userinfo, hostpart = authority.rsplit("@", 1)
                # host:port هرگز '/' ندارد؛ userinfo می‌تواند داشته باشد.
                hostpart = hostpart.split("/", 1)[0]
                decoded_ui = decode_base64_text(userinfo)
                if decoded_ui and ":" in decoded_ui:
                    userinfo = decoded_ui
                userinfo = urllib.parse.unquote(userinfo).lower()
                host, _, port = hostpart.rpartition(":")
                return f"ss:sip002:{userinfo}@{host.lower()}:{port}"
            else:
                decoded = decode_base64_text(rest)
                if decoded is None:
                    raise ValueError("ss legacy body is not base64")
                return f"ss:legacy:{decoded.lower()}"
        except Exception:
            return line.split("#")[0].strip()[:120]

    try:
        without_remark = line.split("#")[0].strip()
        parsed = urllib.parse.urlparse(without_remark)
        raw_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        meaningful = {}
        for pk, pv in raw_params.items():
            kl = pk.strip().lower()
            if kl not in _IDENTITY_PARAMS:
                continue
            nv = _norm_identity_value(kl, str(pv[0]) if pv else "")
            if nv != "":
                meaningful[kl] = nv
        username = urllib.parse.unquote(parsed.username or "").lower()
        password = urllib.parse.unquote(parsed.password or "").lower()
        conn_host = (parsed.hostname or "").lower()
        try:
            port = str(parsed.port or "")
        except Exception:
            port = ""
        path = parsed.path.rstrip("/")
        sni_val = meaningful.get("sni", "")
        host_val = meaningful.get("host", "")
        fronting_domain = sni_val or host_val
        if fronting_domain:
            endpoint = fronting_domain
            meaningful.pop("sni", None)
            meaningful.pop("host", None)
            host_for_key = ""
        else:
            endpoint = ""
            host_for_key = conn_host
        sorted_query = "&".join(f"{k2}={meaningful[k2]}" for k2 in sorted(meaningful))
        return (
            f"{parsed.scheme.lower()}:"
            f"{username}:{password}"
            f"@{host_for_key}|ep={endpoint}"
            f":{port}{path}?{sorted_query}"
        )
    except Exception:
        pass
    return line.split("#")[0].strip()[:200]


# ──────────────────────────────────────────────────────────────────────────────
# تشخیص کانفیگ خراب/جعلی (vendored از subscription._is_dummy_config)
# ──────────────────────────────────────────────────────────────────────────────

_DUMMY_INDICATORS = (
    "00000000-0000-0000-0000-000000000000",
    "app%20not%20supported",
    "app not supported",
    "proxies: []",
)


def is_dummy_config(config: str) -> bool:
    """تشخیص کانفیگ جعلی/خراب."""
    if not config:
        return False
    c = config.lower()
    return any(ind in c for ind in _DUMMY_INDICATORS)


# ──────────────────────────────────────────────────────────────────────────────
# برندینگ ریمارک (vendored از freeconfigs._rename_free_config_remark)
# ──────────────────────────────────────────────────────────────────────────────

def brand_remark(line: str, idx=None) -> str:
    """
    برندینگ: «{CC} {flag} | @Raydikalx | {tag}».

    `tag` از محتوای کانفیگ مشتق می‌شود، نه از موقعیتِ خط. پارامترِ `idx` برای
    سازگاری با فراخوان‌های قدیمی پذیرفته می‌شود ولی در برچسب به کار نمی‌رود؛
    اگر شماره‌گذاریِ موقعیتی به ریمارک برگردد، افزودنِ یک کانفیگ ریمارکِ همهٔ
    خطوطِ بعدی را جابه‌جا می‌کند و فایل در هر انتشار از نو نوشته می‌شود.
    """
    line = line.strip()
    if not line:
        return line

    tag = stable_label(line)

    # نکته: «vmess بودن» مساویِ «base64+JSON بودن» نیست. بعضی منابع vmess را در
    # قالبِ استانداردِ URI می‌دهند. پیش از این، شکستِ JSON به `return line` می‌رسید
    # و کانفیگ *برندنخورده* منتشر می‌شد — یعنی ریمارکِ بالادست، از جمله تبلیغِ
    # کانالِ رقیب، در خروجیِ ما می‌ماند. اندازه‌گیریِ زنده: ۱ مورد از ۸٬۰۱۸ با
    # ریمارکِ «📯1@oneclickvpnkeys». پس فقط وقتی مسیرِ JSON را می‌رویم که واقعاً
    # JSON باشد؛ در غیرِ این‌صورت به مسیرِ عمومیِ fragment می‌افتیم که همان کار را
    # برای vless/trojan/… انجام می‌دهد.
    _vmess_obj = None
    if line.startswith("vmess://"):
        try:
            # مهم: بخش fragment (#...) باید قبل از decode جدا شود، وگرنه
            # base64 خراب می‌شود و برندینگ خاموشانه رد می‌شود (کانفیگ بدون برند
            # از پایپ‌لاین بیرون می‌آید). dedup_key هم همین کار را می‌کند.
            b64 = line[8:].split("#")[0].strip()
            _txt = decode_base64_text(b64)
            _cand = json.loads(_txt) if _txt is not None else None
            if isinstance(_cand, dict):
                _vmess_obj = _cand
        except Exception:
            _vmess_obj = None

    if _vmess_obj is not None:
        try:
            obj = _vmess_obj
            old_ps = str(obj.get("ps") or obj.get("name") or "")
            code, flag = country_for_endpoint(endpoint_of(line), old_ps)
            label = "Global 🌐" if code == "Global" else f"{code} {flag}"
            new_ps = f"{label} | {BRAND_CHANNEL} | {tag}"
            obj["ps"] = new_ps
            if "name" in obj:
                obj["name"] = new_ps
            encoded = base64.b64encode(
                json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ).decode("utf-8")
            return f"vmess://{encoded}"
        except Exception:
            return line

    if "#" in line:
        core, old_remark_enc = line.split("#", 1)
        try:
            old_remark = urllib.parse.unquote(old_remark_enc).strip()
        except Exception:
            old_remark = old_remark_enc.strip()
    else:
        core = line
        old_remark = ""

    code, flag = country_for_endpoint(endpoint_of(line), old_remark)
    label = "Global 🌐" if code == "Global" else f"{code} {flag}"
    new_remark = f"{label} | {BRAND_CHANNEL} | {tag}"
    return f"{core}#{new_remark}"


# ──────────────────────────────────────────────────────────────────────────────
# راستی‌آزماییِ برند
# ──────────────────────────────────────────────────────────────────────────────

def remark_of(line: str) -> str:
    """ریمارکِ قابلِ‌مشاهده‌ی کاربر را برمی‌گرداند (یا رشتهٔ تهی).

    «قابلِ مشاهده» عمداً تأکید شده: در `vmess://` ریمارک درونِ JSONِ base64شده
    (کلیدِ `ps`) می‌نشیند و در متنِ خامِ خط **دیده نمی‌شود**، ولی کلاینت آن را
    به کاربر نشان می‌دهد. پس هر بازرسیِ برند که فقط `BRAND_CHANNEL in line`
    را چک کند، روی همهٔ vmessها منفیِ کاذب می‌دهد (اندازه‌گیری‌شده: ۲٬۳۷۳ نود
    از ۸٬۱۳۶ در دادهٔ زنده). این تابع همان چیزی را می‌خواند که کاربر می‌بیند.
    """
    if not line:
        return ""
    s = line.strip()
    if s.startswith("vmess://"):
        b64 = s[8:].split("#")[0].strip()
        txt = decode_base64_text(b64)
        if txt is not None:
            try:
                obj = json.loads(txt)
                if isinstance(obj, dict):
                    return str(obj.get("ps") or obj.get("name") or "")
            except Exception:
                pass
        # vmessِ غیرِJSON (قالبِ URI) از مسیرِ fragment برند می‌خورد — بیفت پایین
    if "#" in s:
        return s.split("#", 1)[1]
    return ""


def is_branded(line: str) -> bool:
    """آیا ریمارکِ این خط `BRAND_CHANNEL` را دارد؟

    این تابع **تعریفِ اجراییِ** ناوردایِ برندینگ است (سیاست، بالای همین فایل).
    یک‌جا نگه‌داشتنش لازم است چون سه مصرف‌کننده دارد که نباید واگرا شوند:
    دروازهٔ انتشار در `aggregate.py`، آزمون‌های `test_pipeline.py`، و هر
    ابزارِ بازرسیِ آینده.

    سنجش روی *ریمارک* است نه کلِ خط: `BRAND_CHANNEL in line` هم منفیِ کاذب
    می‌دهد (vmess، بالا) و هم مثبتِ کاذب — مثلاً میزبانی که تصادفاً رشتهٔ
    برند را در query داشته باشد، «برنددار» شمرده می‌شد در حالی که کاربر هیچ
    برندی نمی‌بیند.
    """
    return BRAND_CHANNEL in remark_of(line)


# ──────────────────────────────────────────────────────────────────────────────
# تشخیص پروتکل
# ──────────────────────────────────────────────────────────────────────────────

def protocol_of(line: str) -> Optional[str]:
    """
    نامِ canonical پروتکلِ یک کانفیگ را برمی‌گرداند (هوشمند).
    برای هر scheme:// معتبر کار می‌کند — حتی پروتکل‌های جدید/ناشناخته.
    """
    if not line:
        return None
    m = _URI_SCHEME_RE.match(line.strip())
    if not m:
        return None
    scheme = m.group(1).lower()
    if scheme in _NON_PROXY_SCHEMES:
        return None
    return normalize_scheme(scheme)


# ──────────────────────────────────────────────────────────────────────────────
# base64 decode (vendored از fetcher._try_base64_decode)
# ──────────────────────────────────────────────────────────────────────────────

def try_base64_decode(raw: str) -> Optional[str]:
    """دیکد امن base64 با بررسی کیفیت (density >= 20%)."""
    clean_raw = re.sub(r"\s+", "", raw)
    if not clean_raw:
        return None
    padded = clean_raw + "=" * (-len(clean_raw) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            decoded_bytes = decoder(padded)
        except Exception:
            continue
        for encoding in ("utf-8", "latin-1"):
            try:
                text = decoded_bytes.decode(encoding)
                non_empty = [l.strip() for l in text.splitlines() if l.strip()]
                if not non_empty:
                    continue
                # هوشمند: هر scheme:// معتبر (نه فقط prefixهای ثابت) شمارش می‌شود
                valid = [l for l in non_empty if is_proxy_config(l)]
                if valid and (len(valid) / len(non_empty)) >= 0.20:
                    return text
            except UnicodeDecodeError:
                continue
    return None


def extract_valid_lines(content: str) -> List[str]:
    """از یک blob (direct یا base64) خطوط کانفیگ معتبر را استخراج می‌کند."""
    if not content:
        return []
    first_real = next(
        (l.strip() for l in content.splitlines()
         if l.strip() and not l.strip().startswith("//") and not l.strip().startswith("#")),
        "",
    )
    # اگر اولین خطِ واقعی، کانفیگِ پروکسی نبود → احتمالاً blob base64 است
    if not is_proxy_config(first_real):
        decoded = try_base64_decode(content)
        if decoded:
            content = decoded
    # هوشمند: هر scheme:// معتبر پذیرفته می‌شود (حتی پروتکل‌های جدید)
    return [
        line for raw in content.splitlines()
        if (line := raw.strip()) and is_proxy_config(line)
    ]


def encode_base64_subscription(lines: List[str]) -> str:
    """لیست کانفیگ‌ها → بلوک base64 استاندارد اشتراک (v2rayN/v2rayNG)."""
    joined = "\n".join(lines)
    return base64.b64encode(joined.encode("utf-8")).decode("ascii")
