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
import json
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

# ──────────────────────────────────────────────────────────────────────────────
# ثابت‌ها
# ──────────────────────────────────────────────────────────────────────────────

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
    """تشخیص کشور از روی ریمارک. Returns: (country_code, flag_emoji)."""
    if not remark:
        return ("Global", "🌐")
    for flag in _FLAG_EMOJI_RE.findall(remark):
        code = _flag_to_country_code(flag)
        if code:
            return (code, flag)
    remark_lower = remark.lower()
    for keyword, info in _SORTED_KEYWORDS:
        if keyword in remark_lower:
            return info
    for word in re.findall(r"\b[A-Za-z]{2}\b", remark):
        code = word.upper()
        if code in _VALID_CC:
            for _kw, (cc, fl) in _COUNTRY_KEYWORD_MAP.items():
                if cc == code:
                    return (cc, fl)
    return ("Global", "🌐")


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
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            obj = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
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
            if "@" in rest:
                userinfo, hostpart = rest.rsplit("@", 1)
                hostpart = hostpart.split("?")[0]
                try:
                    decoded_ui = base64.urlsafe_b64decode(
                        userinfo + "==").decode("utf-8", errors="ignore")
                    if ":" in decoded_ui:
                        userinfo = decoded_ui
                except Exception:
                    pass
                userinfo = urllib.parse.unquote(userinfo).lower()
                host, _, port = hostpart.rpartition(":")
                return f"ss:sip002:{userinfo}@{host.lower()}:{port}"
            else:
                decoded = base64.urlsafe_b64decode(
                    rest + "==").decode("utf-8", errors="ignore")
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

def brand_remark(line: str, idx: int) -> str:
    """برندینگ: «{CC} {flag} | @Raydikalx | {idx}»."""
    line = line.strip()
    if not line:
        return line

    if line.startswith("vmess://"):
        try:
            b64 = line[8:].strip()
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            obj = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
            old_ps = str(obj.get("ps") or obj.get("name") or "")
            code, flag = detect_country_from_remark(old_ps)
            label = "Global 🌐" if code == "Global" else f"{code} {flag}"
            new_ps = f"{label} | {BRAND_CHANNEL} | {idx}"
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

    code, flag = detect_country_from_remark(old_remark)
    label = "Global 🌐" if code == "Global" else f"{code} {flag}"
    new_remark = f"{label} | {BRAND_CHANNEL} | {idx}"
    return f"{core}#{new_remark}"


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
