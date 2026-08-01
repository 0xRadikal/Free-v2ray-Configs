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


def _ssr_b64_text(s: Optional[str], *, allow_empty: bool = False) -> Optional[str]:
    """
    base64 (هر دو الفبا، با یا بدونِ padding) → متنِ UTF-8، یا None.

    ⚠️ این تابع **آینهٔ مو‌به‌موی** `converters._ub64_text` است و باید بماند.
    عمداً `decode_base64_text` بالایی را به کار نمی‌بریم و عمداً هم آن را
    سهل‌گیر نمی‌کنیم: آن تابع کلیدِ **همهٔ** طرح‌ها را می‌سازد و شل‌کردنش
    می‌توانست هزاران رکورد را جابه‌جا کند. این یکی دامنه‌اش تنها `ssr://` است.

    دو تفاوتِ عمدی با `decode_base64_text`:
      • `errors="ignore"` ندارد — بایتِ نامعتبر ⇒ None، نه رمزِ نیمه‌خورده.
        دلیلش همان است که `converters` نوشته: گذرواژهٔ مثله‌شده کانفیگی
        می‌سازد که «معتبر به‌نظر می‌رسد ولی هرگز وصل نمی‌شود».
      • الگوی نحویِ `_B64_BODY_RE` را تحمیل نمی‌کند، چون مبدل هم نمی‌کند و
        هر اختلافی این‌جا یعنی واگرایی از تجزیه‌کنندهٔ واقعیِ خروجی.
    """
    s = (s or "").strip()
    if not s:
        return "" if allow_empty else None
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * ((4 - len(s) % 4) % 4)
    try:
        return base64.b64decode(s, validate=False).decode("utf-8")
    except Exception:
        return None


def _ssr_parts(line: str) -> Optional[Tuple[str, str, str, str, str, str, str, str]]:
    """
    اجزای هویتیِ یک `ssr://`، یا None اگر تجزیه‌شدنی نبود.

    گرامر عیناً از `converters.parse_proxy` شاخهٔ `ssr` برداشته شده:

        ssr://base64( host:port:protocol:method:obfs:base64(password)
                      /?obfsparam=b64&protoparam=b64&remarks=b64&group=b64 )

    چهار قاعدهٔ ریزِ آن‌جا که این‌جا هم عیناً رعایت می‌شود، وگرنه دو
    تجزیه‌کنندهٔ واگرا می‌سازیم (درسِ K-L6):
      ۱. برشِ `#` **پیش از** رمزگشایی — نویسهٔ `#` در هیچ الفبای base64 نیست.
      ۲. `partition("/?")` برای جدا کردنِ query.
      ۳. **شش** بخشِ الزامی؛ کم یا زیاد ⇒ رد. این IPv6 را هم رد می‌کند، عیناً
         مثلِ مبدل (مشخصهٔ ssr هیچ فرمِ IPv6 تعریف نکرده).
      ۴. میزبانِ ناتهی و پورتِ عددی.

    خروجی: (host, port, protocol, method, obfs, password, obfsparam, protoparam)
    همه رمزگشایی‌شده و **خام** — یعنی از `_sanitize_ssr` نگذشته. عمدی است:
    پاک‌سازی چند مقدارِ متفاوت را روی یک مقدار می‌نشاند و کلیدسازی روی آن
    می‌توانست دو کانفیگِ متمایز را ادغام کند. قاعدهٔ مستندِ مخزن «در تردید،
    ادغام نکن» است، پس مقادیرِ خام = جهتِ تفکیک‌گرا = ایمن.

    این مجموعه دقیقاً همان چیزی است که مبدل به خروجی امیت می‌کند
    (`server, port, cipher, password, obfs, protocol, obfs_param,
    protocol_param`) منهای `name` — که برند بازنویسی‌اش می‌کند و هویت نمی‌سازد.
    `remarks` و `group` هم هرگز به خروجی نمی‌رسند، پس در کلید وزن نمی‌گیرند.
    """
    if not line.startswith("ssr://"):
        return None
    body = line[len("ssr://"):].split("#", 1)[0].strip()
    txt = _ssr_b64_text(body)
    if not txt:
        return None
    main, _sep, qs = txt.partition("/?")
    parts = main.split(":")
    if len(parts) != 6:
        return None
    host, port_s, proto, method, obfs, pwd_b64 = parts
    if not host or not port_s.isdigit():
        return None
    pwd = _ssr_b64_text(pwd_b64, allow_empty=True)
    if pwd is None:
        return None
    sq = urllib.parse.parse_qs(qs)
    obfsparam = _ssr_b64_text(
        (sq.get("obfsparam") or [""])[0], allow_empty=True) or ""
    protoparam = _ssr_b64_text(
        (sq.get("protoparam") or [""])[0], allow_empty=True) or ""
    return (host, port_s, proto, method, obfs, pwd, obfsparam, protoparam)


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
        if line.startswith("ssr://"):
            # ssr **کلِ** بدنه را base64 می‌کند، پس تجزیهٔ عمومیِ URI پایین
            # روی متنِ رمزشده کار می‌کرد و یک رشتهٔ base64 را به‌جای میزبان
            # برمی‌گرداند. پیامدِ اندازه‌گیری‌شده: هر ۱۱۲ خطِ ssr مقصدِ بی‌معنا
            # داشتند ⇒ GeoIP همیشه شکست ⇒ برچسبِ «Global 🌐» برای همه.
            # با رمزگشایی، ۹۶ خط از ۱۱۲ برچسبِ کشورِ واقعی می‌گیرند.
            _p = _ssr_parts(line)
            if _p:
                return _p[0].strip().lower()
            # تجزیه‌نشدنی → مثلِ قبل به مسیرِ عمومی می‌افتد (رفتارِ پیشین حفظ می‌شود)
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
    # ★ فاز J / J-7a: `alpn` و `extra` اثباتاً بر «رسیدن» مؤثرند — نقشهٔ
    # وابستگیِ اندازه‌گیری‌شده نشان داد `alpn` به فیلدِ `alpn` و `extra` به
    # فیلدِ `extra` امیت می‌شوند. بی این دو، «alpn=h3» و «بی‌alpn» یک کلید
    # می‌گرفتند و یکی خاموش به `r.duplicates` می‌رفت (= حذفِ خاموش).
    "alpn", "extra",
    "obfs", "obfs-password", "obfspassword",
    "congestion_control", "congestion",
    "publickey", "presharedkey", "address",
})


def _norm_type(t: str) -> str:
    t = (t or "").strip().lower()
    return "tcp" if t in ("", "raw", "none", "tcp") else t


#: پروتکل‌هایی که `insecure` را واقعاً امیت می‌کنند: `converters.py:896`/`:915`
#: (`skip-cert-verify` در clash) و `converters.py:1179`/`:1193`
#: (`tls.insecure` در sing-box). vless/trojan هیچ‌کدام را نمی‌نویسند.
_INSECURE_SCHEMES = frozenset({"hysteria2", "hy2", "tuic"})

#: نگارشِ **حرف‌به‌حرفِ** کلیدهایی که `converters.py:691-692` و `:727`
#: می‌خوانند. عمداً کوچک نمی‌شوند: اگر منبع `allowinsecure` تمام‌کوچک بنویسد،
#: مبدّل آن را **نمی‌بیند** پس به خروجی نمی‌رسد و نباید در کلید وزن بگیرد.
_INSECURE_KEYS = ("insecure", "allowInsecure", "allow_insecure")

#: عیناً `converters.py:507` (`_truthy`).
_TRUTHY_VALUES = frozenset({"1", "true", "yes", "on"})


def _insecure_flag(raw_params: dict) -> str:
    """«۱» یا «۰» — دقیقاً همان چیزی که مبدّل از این خط برداشت می‌کند."""
    for k in _INSECURE_KEYS:
        v = raw_params.get(k)
        if v:
            return "1" if str(v[0] or "").strip().lower() in _TRUTHY_VALUES else "0"
    return "0"


_FRONT_HOST_BAD_CHARS = frozenset(' \t\r\n/:@?#{}"\\,;|<>()[]')


def _is_plausible_fronting_host(v: str) -> bool:
    """آیا `v` می‌تواند واقعاً یک دامنهٔ fronting باشد؟ — **فقط نحوی، بدونِ DNS**.

    چرا لازم است — ★ این دلیل در فازِ I **به‌روز شد**: پیش از فازِ I، وجودِ
    `sni`/`host` باعث می‌شد کلید میزبانِ واقعی را دور بریزد (`host_for_key = ""`)
    و هویت را به همان مقدار بسپارد؛ آن‌وقت یک مقدارِ زباله‌ی مشترک دو سرورِ
    متفاوت را یکی می‌کرد و یکی‌شان در `aggregate.py` به `duplicates` می‌رفت و
    **منتشر نمی‌شد**. اکنون میزبانِ واقعی **همیشه** در کلید می‌ماند، پس آن
    مسیرِ ادغام بسته شده است؛ ولی این اعتبارسنجی همچنان لازم است، برای جهتِ
    **عکس**: اگر مقدارِ زباله در `ep` بنشیند، دو خطِ یکسان که یکی‌شان آن زباله
    را دارد و دیگری ندارد به دو کلید می‌شکنند و **دو بار منتشر** می‌شوند
    (در فازِ H سنجیده شد: ۳۶ افراز). نمونه‌های واقعیِ سنجیده‌شده در پیکرهٔ زنده:

        sni=https%3A%2F%2Ft.me%2Foneclickvpnkeys → «https://t.me/oneclickvpnkeys»
        sni=t.me%2Fripaojiedian                  → «t.me/ripaojiedian»
        sni=rd.autos.yahoo.com:40069             → پورت داخلِ نامِ میزبان
        host=d2e1v87ko56lyw.cloudfront.net:assets.opensignal.com
        host={"host":"..."}                      → بلوکِ JSON
        host=/?bia_telegram@marambashi_...       → مسیر و پارامتر
        host=v2raynplus--v2raynplus--v2raynplus  → تک‌برچسبی، نامِ کانال

    قاعده‌ها و دلیلِ هرکدام:
      • بدونِ DNS و بدونِ فهرستِ TLD — این تابع روی **هر خط** صدا زده می‌شود، پس
        باید خالص و ارزان بماند. (پس مثلاً `fuck.rkn` که TLDش در IANA نیست
        **گرفته نمی‌شود** — آگاهانه بیرون از دامنه است.)
      • حداقل یک نقطه لازم است: یک دامنهٔ frontingِ عمومی همیشه FQDN است.
        اندازه‌گیری: پذیرشِ مقادیرِ تک‌برچسبی باعث می‌شد ۱۲ افراز، **یک** نقطهٔ
        پایانیِ واقعی را به دو کلید ببرند.
      • یک نقطهٔ پایانی (FQDNِ ریشه‌لنگر، مثلِ `example.com.`) قانونی است و
        نباید رد شود؛ در نسخهٔ اولِ ابزارِ سنجشم همین مورد ۴ مثبتِ کاذب ساخت.
    """
    if not v or len(v) > 253:
        return False
    if v.startswith("[") and v.endswith("]") and len(v) > 2:
        return True                              # لیترالِ IPv6
    for ch in v:
        if ch in _FRONT_HOST_BAD_CHARS:
            return False
    if v.endswith("."):
        v = v[:-1]
    if not v or ".." in v or "." not in v:
        return False
    for lab in v.split("."):
        if not lab or len(lab) > 63:
            return False
        if lab[0] == "-" or lab[-1] == "-":
            return False
        for ch in lab:
            if not (ch.isascii() and (ch.isalnum() or ch == "-")):
                return False
    return True


def _sni_is_endpoint(security: str) -> bool:
    """آیا `sni` را می‌توان «نقطهٔ پایانیِ واقعیِ» سرور شمرد؟

    فقط برای TLSِ معمولی. دو واقعیتِ **مستندِ** پروتکلی:

      ۱. SNI یک **افزونهٔ TLS** است. اگر `security` برابرِ none/غایب باشد هیچ
         دست‌تکانیِ TLS رخ نمی‌دهد، پس کلاینت هرگز SNI نمی‌فرستد و آن پارامتر
         **بی‌اثر** است؛ نمی‌تواند سازوکارِ رسیدن به یک backendِ متمایز باشد.

      ۲. در **REALITY**، مقدارِ `serverName` عمداً دامنهٔ یک **سایتِ ثالث** است
         که گواهی‌اش قرض گرفته می‌شود، نه میزبانِ خودِ سرور. مستنداتِ رسمیِ
         XTLS (xtls.github.io/en/config/transports/reality.html):
           «REALITY … uses the appearance and handshake characteristics of a
            **target site** as camouflage.»
           `serverNames`: «Usually this should stay consistent with `target`.»
           «best practice … is still to **borrow certificates from the same
            ASN**.»
         پس دو سرورِ کاملاً متفاوت که یک دامنهٔ استتارِ مشترک قرض می‌گیرند،
         پیش از این **یک هویت** شمرده می‌شدند و یکی‌شان حذف می‌شد.

    اندازه‌گیریِ واقعی روی پیکرهٔ زنده (۱۸٬۷۳۵ خط): کلیدهایی که ≥۲ نقطهٔ پایانیِ
    **واقعیِ متفاوت** را در خود جمع کرده بودند از **۶۴۱ به ۵۰۰** رسید، و
    ادغامِ کاذبِ **تازه‌ساخته‌شده = ۰**.

    ⚠️ پارامترِ `host` عمداً از این قاعده مستثناست: هدرِ HTTP `Host` سازوکارِ
    دیگری است و در `type=ws` حتی بدونِ TLS هم مسیریابی می‌کند.
    """
    return security == "tls"


def _norm_aid(v) -> str:
    """`alterId` را همان‌گونه نرمال می‌کند که خودِ محصول می‌کند.

    ★ چرا لازم است: `converters.parse_proxy` مقدار را با
    `_safe_int(obj.get("aid"), 0)` می‌خواند، پس `aid` غایب و `aid=0` و
    `aid=""` هر سه خروجیِ **مو‌به‌مو یکسان** می‌دهند. اگر کلید
    رشتهٔ خام را بنویسد، همان کانفیگ دو کلید می‌گیرد و دو بار
    منتشر می‌شود — زیانِ (ب)، که اینجا به‌راحتی اجتناب‌پذیر است.
    """
    try:
        return str(int(str(v).strip() or "0"))
    except Exception:
        return "0"


_CASE_SENSITIVE_PARAMS = frozenset({
    "path", "servicename", "pbk", "publickey", "presharedkey",
    "obfs-password", "obfspassword",
})


def _norm_identity_value(key: str, val: str) -> str:
    # ★ فاز J / J-7e: کوچک‌سازیِ فراگیر دو مسیرِ متمایز را خاموش یکی
    # می‌کرد (در پیکره: `path=TG%40ZDYZ2` و `path=tg%40zdyz2`)، در حالی
    # که محصول مسیر را عیناً امیت می‌کند و مسیرِ HTTP به بزرگی/کوچکی
    # حساس است. دربارهٔ `pbk`/`publickey` بدتر است: base64url است و
    # کوچک‌سازی کلیدِ عمومیِ دیگری می‌سازد.
    if key in _CASE_SENSITIVE_PARAMS:
        return (val or "").strip()
    v = (val or "").strip().lower()
    if key in ("sni", "host"):
        for _ in range(2):
            nv = urllib.parse.unquote(v)
            if nv == v:
                break
            v = nv
        v = v.strip().lower()
    if key == "type":
        # ★ رفعِ نامتقارنی: `_norm_type` برای ("", "raw", "none", "tcp") مقدارِ
        # "tcp" برمی‌گرداند و حلقهٔ شاخهٔ عمومی آن را با شرطِ `nv != ""` نگه
        # می‌دارد — اما `type`ِ **غایب** هرگز وارد `meaningful` نمی‌شود. پس
        # `?type=tcp` و `?` (بی‌type) دو کلیدِ متفاوت می‌ساختند برای یک سرور.
        # با بازگرداندنِ "" برای مقدارِ پیش‌فرض، این دو یکی می‌شوند.
        # `_norm_type` عامداً دست‌نخورده می‌ماند: شاخهٔ vmess مقدارِ `net` را
        # **موضعی** می‌نویسد و در آنجا "" باید همان "tcp" بماند.
        nt = _norm_type(v)
        return "" if nt == "tcp" else nt
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
            # هر مقداری که مبدّلِ خودِ این مخزن آن را «TLS» نمی‌شمارد، با
            # «بی‌TLS» یکسان است. مرجع: `converters.py:553` که مقدار را به
            # بولین بدل می‌کند (`in ("tls", "reality")`)، و
            # `pipeline.py:94` (`FS_TLS_VALUES = {"tls","reality","xtls"}`).
            # پس `auto`/`none`/`""`/هر زبالهٔ دیگر ⇒ خروجیِ مو‌به‌مو یکسان.
            # `xtls` عامدانه در فهرست نگه داشته شده تا این قاعده فقط
            # بتواند بشکافد، نه ادغام کند (جهتِ محافظه‌کارانه).
            tls = tls if tls in ("tls", "reality", "xtls") else ""
            net = _norm_type(str(obj.get("net") or ""))
            path = str(obj.get("path") or "")
            # ★ فاز J / J-7d: تنها هم‌ارزیِ اثبات‌شده («» ≡ «/») نگه داشته
            # می‌شود؛ `rstrip("/")` پیشین `/abc/` را هم با `/abc` یکی
            # می‌کرد که دو مسیرِ متفاوتِ HTTP‌اند (RFC 3986 §6.2.2).
            path = "/" if path == "" else path
            # اعتبارسنجیِ مقدارِ fronting پیش از سپردنِ هویت به آن — چراییِ
            # کامل در `_is_plausible_fronting_host` و `_sni_is_endpoint`.
            if host and not _is_plausible_fronting_host(host):
                host = ""
            # `sni` تنها وقتی «نقطهٔ پایانی» است که TLS آن را نامِ سرور کند.
            # این نگهبان دست‌نخورده می‌ماند؛ رسیدنِ `sni` به خروجی از راهِ
            # **دیگر** (servername/هدرِ Host، بی‌نیاز از TLS) پایین‌تر با
            # مؤلفهٔ `srv=` پوشش داده می‌شود — فاز K / K-D.
            if sni and not (_is_plausible_fronting_host(sni)
                            and _sni_is_endpoint(tls)):
                sni = ""
            # ★ فاز K / K-D — «نامِ سرورِ مؤثر» (effective servername).
            #
            # چرا لازم است: `converters.parse_proxy` در شاخهٔ vmess می‌نویسد
            # `"sni": _clean_sni(obj.get("sni") or obj.get("host"))`
            # (`converters.py:558`) و `_to_clash_proxy` آن را **بی‌قید و شرط**
            # امیت می‌کند: `if p["sni"]: out["servername"] = p["sni"]`
            # (`converters.py:854-855`) — نه TLS شرطش است و نه transport.
            # پس `sni` حتی در `net=tcp`/`grpc` و بی‌TLS هم به خروجی می‌رسد.
            # سنجشِ مستقیمِ بایت‌ها (۳ جفتِ همزاد، `/tmp/k5_diag.py`):
            #     net=tcp  + sni  ⇒ clash `servername` هست / نیست  → متفاوت
            #     host + sni متفاوت ⇒ `servername` دو مقدارِ متفاوت → متفاوت
            #     net=grpc + sni  ⇒ `servername` هست / نیست        → متفاوت
            # نگهبانِ بالا این مقدار را صفر می‌کند، پس بی این مؤلفه هر سه
            # جفت **یک کلید** می‌گرفتند و یکی خاموش به `r.duplicates` می‌رفت
            # (زیانِ «الف»: حذفِ بی‌صدا). در پیکرهٔ امروز چنین جفتی نیست، پس
            # نقصْ **نهفته** بود؛ ولی جهتِ زیان همان است و باید بسته شود.
            #
            # چرا `sni or host` و نه `sni` تنها: مبدّل همین fallback را دارد.
            # نسخهٔ بی‌fallback سنجیده شد و **۳ افرازِ کاذب** ساخت، چون در
            # پیکره خطوطی هستند که `sni == host` دارند و خطِ همزادشان `sni`
            # ندارد — خروجی‌شان مو‌به‌مو یکسان است. با fallback: **۰**.
            #
            # کاملیِ اثبات‌شده: هر دو مصرف‌کنندهٔ خروجی تابعی از همین جفت‌اند —
            # `servername = sni or host` و هدرِ Host در ws/h2/grpc
            # (`converters.py:792` و `:1102`) `= host or sni`. کلید هم `host`
            # را دارد و هم `sni or host`، پس جفت را یکتا تعیین می‌کند.
            #
            # سنجش روی پیکرهٔ کامل (۱۸٬۷۳۵ خط): این مؤلفه به‌تنهایی جای
            # نگهبانِ فهرست‌محورِ K-C را می‌گیرد و **افرازِ یکسان** می‌سازد
            # (loss ۴۷→۴۲، افرازِ کاذب ۰، گروهِ شکافته‌شده ۰) — پس فهرستِ
            # `_HOST_HEADER_NETS` که داوریِ دستی دربارهٔ transportها بود
            # حذف شد و یک دستهٔ کاملِ خطای آینده با آن رفت.
            srv = _norm_identity_value(
                "sni", str(obj.get("sni") or "") or str(obj.get("host") or ""))
            if srv and not _is_plausible_fronting_host(srv):
                srv = ""
            # ★ فاز J / J-7b: `host or sni` این دو را قاطی می‌کرد، پس
            # «host=X, sni=∅» و «host=∅, sni=X» یک کلید می‌گرفتند و یکی
            # خاموش حذف می‌شد — در حالی که محصول آن‌ها را به **دو فیلدِ
            # متفاوت** امیت می‌کند (`Host` در clash و `servername`/
            # `server_name` در TLS). پس دو مصنوعِ متمایزند.
            fronting = f"{host}~{sni}" if sni else host
            # ★ فازِ I: fronting دیگر میزبانِ واقعی را جانشین نمی‌شود.
            add_for_key = add
            return (
                f"vmess:{add_for_key}|ep={fronting}"
                f":{str(obj.get('port', '')).strip()}"
                f":{str(obj.get('id', '')).strip().lower()}"
                # ★ فاز J / J-7c: `alterId` هم امیت می‌شود (`alterId` در
                # clash و `alter_id` در sing-box) و mihomo آن را به
                # `newAlterIDs` می‌دهد. هم‌ارزی **اثبات نشد**، پس بر پایهٔ
                # قاعدهٔ «در تردید، ادغام نکن» می‌شکافیم.
                f":{net}:{path}:{tls}"
                f":{_norm_aid(obj.get('aid'))}"
                # ★ فاز K / K-A: `scy` رمزنگاریِ VMess است و امیت می‌شود:
                # `converters.py:551` آن را می‌خواند، `:852` به `cipher`
                # (clash) و `:1143` به `security` (sing-box) می‌نویسد —
                # **حرف‌به‌حرف و بی‌کوچک‌سازی**. پس کلید هم عیناً همان را
                # می‌گیرد؛ کوچک‌کردنش «AUTO» و «auto» را ادغام می‌کرد در
                # حالی که خروجی‌شان متفاوت است. سنجیده شد: ۱ کانفیگ نجات،
                # ۰ افرازِ کاذب.
                f":{str(obj.get('scy') or 'auto')}"
                # ★ فاز K / K-D — چرایی در بالا، کنارِ محاسبهٔ `srv`.
                f":srv={srv}"
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
                # ★ یکی‌سازیِ دو فرمِ Shadowsocks. بدنهٔ رمزگشایی‌شدهٔ فرمِ قدیم
                # دقیقاً `method:pass@host:port` است — همان چیزی که شاخهٔ
                # SIP002 از اجزای جدا می‌سازد. پیش از این، یک سرورِ یکسان که
                # هم به فرمِ قدیم و هم به فرمِ SIP002 آمده بود دو کلید می‌گرفت
                # و **دو بار** منتشر می‌شد (۴ مورد در پیکره).
                # ادغامِ کاذبِ تازه ساختاراً ناممکن است: یکی شدن فقط وقتی رخ
                # می‌دهد که روش، گذرواژه، میزبان و پورت هر چهار یکی باشند.
                _d = decoded.split("#")[0].split("?")[0]
                if "@" in _d:
                    _ui, _hp = _d.rsplit("@", 1)
                    _hp = _hp.split("/", 1)[0]
                    _h, _, _pt = _hp.rpartition(":")
                    if _h and _pt:
                        _ui = urllib.parse.unquote(_ui).lower()
                        return f"ss:sip002:{_ui}@{_h.lower()}:{_pt}"
                return f"ss:legacy:{decoded.lower()}"
        except Exception:
            return line.split("#")[0].strip()[:120]

    # ★ فاز O4 — کلیدِ ساختاریِ ssr به‌جای کلیدِ متنیِ base64.
    #
    # چرا لازم بود: شاخهٔ عمومیِ پایین `urlparse` را روی `ssr://<base64>`
    # اجرا می‌کرد. آن base64 **کلِ** بدنه است (میزبان، پورت، رمز، پارامترها و
    # حتی `remarks`/`group`)، پس کلید عملاً «رشتهٔ رمزشده» می‌شد. دو پیامدِ
    # اندازه‌گیری‌شده روی پیکرهٔ ۳۳٬۰۶۶ خطی (۱۱۲ خطِ ssr):
    #   ۱. یک نودِ یکسان که با padding یا الفبای متفاوت (`+/` در برابر `-_`)
    #      یا با `remarks`/`group`ِ دیگر آمده بود، **کلیدِ متفاوت** می‌گرفت
    #      ⇒ افرازِ کاذب. اندازه‌گیری: ۵۲ گروه → ۲۸ گروه (۲۴ ادغام، هیستوگرامِ
    #      کاملاً یکنواختِ {۴: ۲۸}).
    #   ۲. `endpoint_of` هم روی همان رشته کار می‌کرد ⇒ GeoIP همیشه شکست ⇒
    #      همهٔ ۱۱۲ خط برچسبِ «Global 🌐». حالا ۹۶ خط کشورِ واقعی می‌گیرند.
    #
    # ایمنیِ اثبات‌شده پیش از تغییر (`o4_probe.py` + `o4_probe2.py`):
    #   • `data_killing_merges = 0` — هیچ‌یک از ۲۴ ادغام دو مصنوعِ متمایز را
    #     یکی نکرد؛ هر ۲۴ گروه **یک** مصنوعِ یکتا داشتند.
    #   • `false_splits = 0` · زیانِ کل ۹۹ → ۹۹ (Δ صفر).
    #   • sha256ِ کلیدهای ۳۲٬۹۵۴ خطِ غیر-ssr **مو‌به‌مو یکسان** ⇒ هیچ طرحِ
    #     دیگری تکان نخورد.
    #   • برخوردِ بین‌طرحی: ۰ (پیشوندِ یکتای `ssr:` مثلِ بقیهٔ شاخه‌ها).
    #
    # مجموعهٔ هویتی = عیناً همان چیزی که مبدل امیت می‌کند، منهای `name`.
    # مقادیر **خام**اند (نه `_sanitize_ssr`-شده): پاک‌سازی چندبه‌یک است و
    # می‌توانست دو کانفیگِ متمایز را ادغام کند. چراییِ کامل در `_ssr_parts`.
    if line.startswith("ssr://"):
        try:
            p = _ssr_parts(line)
            if p:
                host, port_s, proto, method, obfs, pwd, obfsparam, protoparam = p
                # میزبان/پروتکل/متد/obfs بی‌حساسیت به بزرگ‌وکوچک‌اند (نام
                # دامنه و شناسه‌های ثابت)، ولی گذرواژه و پارامترها **نه** —
                # مبدل آن‌ها را حرف‌به‌حرف امیت می‌کند، پس کوچک‌کردنشان
                # دو خروجیِ متفاوت را ادغام می‌کرد.
                #
                # ★ چرا `quote`: سه جزءِ آزادمتنِ آخر (گذرواژه و دو پارامتر)
                # می‌توانند خودشان «:» و «=» داشته باشند، و آن‌وقت کلید
                # **یک‌به‌یک نیست**. این حرف نظری نیست؛ جهش‌آزمایی (M4) آن را
                # لو داد و با دو خطِ واقعی اثبات شد:
                #
                #   pwd="x:op=y", op=""      ⟶ …:x:op=y:op=:pp=
                #   pwd="x",      op="y:op=" ⟶ …:x:op=y:op=:pp=   ← یک کلید!
                #
                # هر دو را `parse_proxy` می‌پذیرد و مصنوعشان **متفاوت** است
                # (گذرواژه و obfs_paramِ متفاوت) ⇒ یکی خاموش حذف می‌شد؛ همان
                # «ادغامِ داده‌کُش» که کلِ این فاز برای بستنش است.
                #
                # `quote(safe="")` هر «:» را به `%3A`، هر «=» را به `%3D` و هر
                # «%» را به `%25` بدل می‌کند. پس هیچ جزئی نمی‌تواند جداکننده
                # بسازد و کلید به یک چندگانهٔ ۹جزئیِ بی‌ابهام تبدیل می‌شود.
                # چهار جزءِ نخست ساختاراً «:»-ندارند (از `split(":")` با شمارِ
                # الزامیِ شش آمده‌اند)، پس نیازی به گریز ندارند و خوانا می‌مانند.
                q = urllib.parse.quote
                return (
                    f"ssr:{host.strip().lower()}:{port_s}"
                    f":{proto.strip().lower()}:{method.strip().lower()}"
                    f":{obfs.strip().lower()}:{q(pwd, safe='')}"
                    f":op={q(obfsparam, safe='')}:pp={q(protoparam, safe='')}"
                )
        except Exception:
            pass
        # تجزیه‌نشدنی → **هیچ تغییری**؛ به شاخهٔ عمومیِ پایین می‌افتد، یعنی
        # عیناً کلیدِ امروز. سه دلیلِ عمدی برای اینکه این‌جا مثلِ شاخه‌های
        # vmess/ss به `[:120]` برنمی‌گردیم:
        #   ۱. سنجه‌ها با همین معنا گرفته شدند (`o4_probe.py:200` برای موردِ
        #      تجزیه‌نشدنی `k_before` را نگه می‌دارد). هر معنای دیگری یعنی
        #      رفتاری که **اندازه‌گیری نشده** — و ادعای بی‌سنجه ممنوع است.
        #   ۲. بریدنِ ۱۲۰ نویسه خودش خطرِ ادغام می‌سازد: بدنه‌های ssrِ واقعی
        #      بلندترند، پس دو کانفیگِ متمایز با پیشوندِ مشترک یک کلید
        #      می‌گرفتند — همان «ادغامِ الکی» که ممنوع است.
        #   ۳. بی‌اثر بودنش روی خروجی اثبات‌شده است: هر خطی که این تجزیه‌کننده
        #      رد کند، `converters.parse_proxy` هم رد می‌کند (گرامرِ آینه‌ای،
        #      قفل‌شده با تستِ ضدواگرایی)، پس هرگز به خروجی نمی‌رسد و افرازش
        #      دیده نمی‌شود.

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
        # ★ فاز K / K-B: `insecure` تفاوتِ «گواهی را بررسی کن» و «نکن» است و
        # در hysteria2/tuic به خروجی می‌رسد، پس هویت‌ساز است. دامنه‌اش عامدانه
        # همان دو پروتکل است: افزودنِ بی‌دامنه سنجیده شد و **۷۶ افرازِ کاذب**
        # ساخت، چون `_to_clash_proxy` برای vless/trojan هیچ `skip-cert-verify`
        # نمی‌نویسد ⇒ پارامترِ نارسا. با دامنه: ۱ کانفیگ نجات، ۰ افرازِ کاذب.
        if parsed.scheme.lower() in _INSECURE_SCHEMES:
            meaningful["insecure"] = _insecure_flag(raw_params)
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
        # ── اعتبارسنجیِ fronting ─────────────────────────────────────────────
        # دو نوعِ **متفاوت** ردکردن، با پیامدهای متفاوت:
        #   (۱) مقدار hostname معتبر **نیست** ⇒ زباله است و هیچ اطلاعِ هویتی
        #       ندارد ⇒ کاملاً از `meaningful` حذف می‌شود. اگر فقط «تنزیل» شود و
        #       در query بماند، همان زباله هویت را می‌شکند: سنجیده شد که ۳۶
        #       افراز، **یک** نقطهٔ پایانیِ واقعی را به چند کلید می‌بردند، چون
        #       یک خط `host=/?bia_telegram@…` داشت و خطِ دیگر نداشت.
        #   (۲) مقدار معتبر است ولی قاعدهٔ TLS/REALITY آن را نقطهٔ پایانی
        #       نمی‌داند ⇒ یک پارامترِ واقعیِ کانفیگ است و **در query می‌ماند**،
        #       تا تمایزهای امروزی حفظ شوند و افرازِ تازه‌ای ساخته نشود.
        security_val = meaningful.get("security", "")
        if sni_val and not _is_plausible_fronting_host(sni_val):
            sni_val = ""
            meaningful.pop("sni", None)                       # (۱)
        elif sni_val and not _sni_is_endpoint(security_val):
            sni_val = ""                                      # (۲)
        if host_val and not _is_plausible_fronting_host(host_val):
            host_val = ""
            meaningful.pop("host", None)                      # (۱)
        # ─────────────────────────────────────────────────────────────────────
        fronting_domain = sni_val or host_val
        # ★ فازِ I: هم میزبانِ واقعی و هم دامنهٔ fronting در کلید می‌مانند.
        endpoint = fronting_domain
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


# ── بازسازیِ جداکنندهٔ `&` که به‌صورتِ موجودیتِ HTML خراب شده است ─────────────
# چرا لازم است: `urllib.parse.parse_qs` روی `&` می‌شکند. اگر منبع، لینک را از
# دلِ HTML برداشته باشد، `&` به `&amp;` بدل شده و نامِ پارامترها `amp;security`
# … می‌شوند. نه `dedup_key` و نه `converters.parse_proxy` این را جبران
# نمی‌کردند؛ سنجشِ زندهٔ خروجی روی هر ۱۰ خطِ آسیب‌دیده نشان داد
# `tls=False`, `sni=''`, `host=''`, `path=''` و فروریختنِ `network` به `tcp`.
# یعنی کانفیگ منتشر می‌شد ولی کار نمی‌کرد.
#
# قاعده عامدانه **شرطی** است: تنها جایی `&amp;` به `&` بدل می‌شود که پس از آن
# یک نامِ پارامترِ معتبر و یک `=` بیاید. اندازه‌گیری روی پیکرهٔ ۱۸٬۷۳۵ خطی:
# از ۵۵ رخدادِ `&amp;`، هر ۵۵ مورد جداکننده بودند و ۰ مورد غیرِ جداکننده. پس
# این قاعده روی دادهٔ واقعی بی‌استثنا است و در عینِ حال محافظه‌کارانه می‌ماند:
# اگر روزی `&amp;` در **مقدارِ** یک پارامتر بیاید، دست‌نخورده رد می‌شود.
_AMP_SEP = re.compile(r"&amp;(?=[A-Za-z_][A-Za-z0-9_.\-]*=)")


def _repair_amp_separator(line: str) -> str:
    """`&amp;` را فقط در نقشِ **جداکننده** به `&` بازمی‌گرداند."""
    if "&amp;" not in line:
        return line
    return _AMP_SEP.sub("&", line)


# ── ترمیمِ بایت‌های کنترلیِ خام در متنِ کانفیگ ─────────────────────────────────
# سنجشِ کاملِ پیکرهٔ منتشرشده (۵۰ فایل، ۳۷ مگابایت) نشان داد **یک** کانفیگ
# حاوی بایت‌های کنترلیِ خام است و همان یک خط، شش بایتِ کنترلی را به سه فایلِ
# متنی (all/configs.txt, heavy/configs.txt, protocols/shadowsocks.txt) و سه
# نسخهٔ base64شان تزریق می‌کرد:
#
#     ss://…@37.32.27.224:9147?prefix=\x16\x03\x01\x00…#IR 🇮🇷 | @Raydikalx | …
#
# منشأ: پارامترِ `prefix` در shadowsocks عامدانه بایتِ خام می‌گیرد (اینجا سرآیندِ
# TLS ClientHello برای obfuscation). یعنی دادهٔ بدخواه نیست؛ اما در یک فایلِ
# متنیِ منتشرشده بایتِ کنترلیِ خام یک نقصِ یکپارچگی است: NUL می‌تواند رشته را در
# مصرف‌کنندهٔ C-محور نصف کند و 0x16 در ترمینال/لاگ رفتارِ نامعلوم بسازد.
#
# چرا «ترمیم» و نه «حذفِ کانفیگ»؟ اندازه‌گیری نشان داد converterها پارامترِ
# `prefix` را دور می‌اندازند، پس همین نود در clash.yaml و singbox.json **حاضر و
# سالم** است. حذفِ خط، نودی را از خروجی کم می‌کرد که امروز منتشر می‌شود.
#
# قاعده عامدانه **دو-ناحیه‌ای** است:
#   • در `query` و `fragment` → percent-encoding (بی‌اتلاف و idempotent؛
#     RFC 3986 §2.1 همین را برای بایتِ غیرمجاز تجویز می‌کند و کلاینت با
#     unquote دقیقاً همان بایتِ اصلی را بازمی‌سازد ⇒ کانفیگ کار می‌کند).
#   • پیش از `?` (scheme/authority) → خط **دور انداخته می‌شود**؛ بایتِ کنترلی
#     در میزبان/پورت یعنی خطِ خراب است و percent-encoding آن را «قابلِ قبول»
#     جلوه می‌دهد بی‌آنکه سالم کند.
#
# دو سنجشِ مستقل روی پیکرهٔ **واقعیِ** منتشرشده. پیکره هر ۱۵ دقیقه از نو ساخته
# می‌شود، پس تعدادِ خط عددِ ثابتی نیست و عامداً هر دو اندازه‌گیری با تاریخ ثبت
# شده تا بازبینی‌پذیر باشد (نسبت‌ها بازتولید می‌شوند، نه عددِ خام):
#   • ۲۰۲۶-۰۸-۰۱، پیکرهٔ ۱۰٬۰۹۱ خطی → ۱۰٬۰۹۰ بی‌تغییر، ۱ ترمیم، ۰ حذف
#   • ۲۰۲۶-۰۸-۰۱، بازسنجیِ زنده روی پیکرهٔ ۱۰٬۰۱۹ خطی، این بار با فراخوانیِ
#     خودِ همین پیاده‌سازی (نه شبیه‌سازی) → ۱۰٬۰۱۸ بی‌تغییر، ۱ ترمیم، ۰ حذف
# در هر دو سنجش `dedup_key` و `stable_label` پیش و پس از ترمیم یکسان ماندند و
# خروجیِ clash/sing-box بایت‌به‌بایت تغییر نکرد ⇒ صفر ریزشِ قابلِ مشاهده.
_CTRL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


def _pct_encode_ctrl(text: str) -> str:
    """هر بایتِ کنترلی را به شکلِ `%XX` (RFC 3986) بازنویسی می‌کند."""
    return _CTRL_CHAR_RE.sub(lambda m: "%%%02X" % ord(m.group(0)), text)


def _repair_control_chars(line: str) -> str:
    """بایتِ کنترلیِ خام را در `query`/`fragment` percent-encode می‌کند.

    اگر بایتِ کنترلی **پیش از** `?` باشد، رشتهٔ خالی برمی‌گرداند تا فراخوان
    خط را دور بیندازد (رفتارِ fail-safe؛ در `extract_valid_lines` همین رشتهٔ
    خالی باعثِ short-circuit و حذفِ خط می‌شود).
    """
    if not _CTRL_CHAR_RE.search(line):
        return line
    head, frag_sep, frag = line.partition("#")
    authority, query_sep, query = head.partition("?")
    if _CTRL_CHAR_RE.search(authority):
        return ""
    repaired = authority + query_sep + _pct_encode_ctrl(query)
    if frag_sep:
        repaired += frag_sep + _pct_encode_ctrl(frag)
    return repaired


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
    # ترتیب عامدانه است: نخست نرمال‌سازیِ `&amp;`، سپس ترمیمِ بایتِ کنترلی. پس از
    # sanitizer هیچ مرحله‌ای بایتِ کنترلی بازنمی‌گرداند ⇒ هر خطی که از این تابع
    # بیرون می‌آید، تضمیناً بدونِ بایتِ کنترلیِ خام است.
    return [
        line for raw in content.splitlines()
        if (line := _repair_control_chars(_repair_amp_separator(raw.strip())))
        and is_proxy_config(line)
    ]


def encode_base64_subscription(lines: List[str]) -> str:
    """لیست کانفیگ‌ها → بلوک base64 استاندارد اشتراک (v2rayN/v2rayNG)."""
    joined = "\n".join(lines)
    return base64.b64encode(joined.encode("utf-8")).decode("ascii")


# ══════════════════════════════════════════════════════════════════════════════
# 🛡️ گاردِ خروجی — دفاعِ لایه‌دوم در برابرِ بایتِ کنترلی
# ══════════════════════════════════════════════════════════════════════════════
# `_repair_control_chars` نقص را در **ورودی** می‌بندد. این گارد همان تضمین را
# در **خروجی** تکرار می‌کند تا اگر روزی مسیرِ سومی (سرآیند، برچسب، متنِ تولیدی)
# بایتِ کنترلی بسازد، به‌جای انتشارِ خاموش، بلند شکست بخورد.
#
# چرا fail-closed (استثنا) و نه پاک‌سازیِ خاموش؟ در این مخزن، شکستِ aggregate
# یعنی مرحلهٔ publish اجرا نمی‌شود و آخرین خروجیِ **سالمِ** قبلی روی main
# می‌مانَد. پس بدترین پیامدِ این گارد «کهنگیِ داده + یک اجرای سرخِ کاملاً
# دیدنی» است، نه انتشارِ دادهٔ خراب. اولویتِ درستی بر تازگی، انتخابِ آگاهانه.
#
# چرا هر بایتِ C0 جز LF ممنوع است (و صفر مثبتِ کاذب می‌دهد) — سه اندازه‌گیریِ
# مستقل و هم‌سو:
#   ۱) سنجشِ کلِ جمعیتِ خروجیِ واقعیِ منتشرشده: TAB=۰، CR=۰، DEL=۰ در همهٔ
#      فایل‌ها؛ تنها بایتِ کنترلیِ مجاز، LF بود.
#   ۲) بررسیِ ایستا: تنها `\t`/`\r` در کلِ ماژول‌های نویسنده در
#      `_FRONT_HOST_BAD_CHARS` است که مجموعهٔ **ردّ** است، نه متنِ نوشتنی؛
#      سرآیندها هم فقط `#`, متن و LF دارند.
#   ۳) معناشناسیِ serializerها: `json.dumps` و `yaml.dump` هر بایتِ C0 را
#      escape می‌کنند (آزمونِ زنده: `\x16`, `\t`, `\r` هر سه به شکلِ متنی
#      درآمدند) ⇒ clash.yaml و singbox.json ساختاراً نمی‌توانند بایتِ خام
#      داشته باشند. پس `.json`/`.yaml` نیز بی‌خطر از این گارد می‌گذرند.
#   و base64 فقط الفبای ASCII تولید می‌کند.
#
# نتیجه: در کارکردِ عادی این گارد هرگز شلیک نمی‌کند؛ یک assertion است، نه فیلتر.


class ControlByteInOutput(ValueError):
    """خروجی حاوی بایتِ کنترلیِ خام است — انتشار باید متوقف شود."""


#: هر بایتِ C0 جز `\n`، به‌علاوهٔ DEL. عامدانه TAB و CR را هم شامل می‌شود:
#: نبودشان اندازه‌گیری شده و حضورشان یعنی آلودگیِ CRLF یا سرآیندِ ناخواسته.
_FORBIDDEN_OUTPUT_CHAR_RE = re.compile(r"[\x00-\x09\x0b-\x1f\x7f]")


def assert_no_control_bytes(path: str, content: str) -> None:
    """اگر `content` بایتِ کنترلیِ ممنوع داشته باشد، استثنا می‌اندازد.

    پیامِ خطا عامدانه «قابلِ اقدام» است: مسیر، بایت، شمارهٔ خط و ستون، و یک
    نمونهٔ کوتاه که با `repr` نمایش داده می‌شود تا خودِ لاگ آلوده نشود.
    """
    m = _FORBIDDEN_OUTPUT_CHAR_RE.search(content)
    if m is None:
        return
    offset = m.start()
    line_no = content.count("\n", 0, offset) + 1
    line_start = content.rfind("\n", 0, offset) + 1
    column = offset - line_start + 1
    total = len(_FORBIDDEN_OUTPUT_CHAR_RE.findall(content))
    excerpt = content[max(line_start, offset - 40):offset + 40]
    raise ControlByteInOutput(
        f"refusing to write {path!r}: forbidden control byte "
        f"0x{ord(m.group(0)):02X} at line {line_no}, column {column} "
        f"(byte offset {offset}); {total} forbidden byte(s) in total; "
        f"excerpt={excerpt!r}"
    )
