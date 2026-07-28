# -*- coding: utf-8 -*-
"""
converters.py — تبدیل کانفیگ‌های V2Ray به فرمت‌های Clash (Mihomo) YAML و Sing-box JSON.

پشتیبانی: vless, vmess, trojan, shadowsocks (ss).
پروتکل‌های hysteria2/tuic/wireguard فعلاً به Clash/Sing-box تبدیل نمی‌شوند
(در فایل‌های txt/base64 و per-protocol کامل موجودند).

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
                "sni": str(obj.get("sni") or obj.get("host") or ""),
                "host": str(obj.get("host") or ""),
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
                "sni": q.get("sni") or q.get("host") or "",
                "host": q.get("host") or "",
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
                "sni": q.get("sni") or q.get("host") or "",
                "host": q.get("host") or "",
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
    for line in lines:
        if len(proxies) >= limit:
            break
        p = parse_proxy(line)
        if not p:
            continue
        cp = _to_clash_proxy(p)
        if not cp:
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
    except Exception:
        return None
    return None


def build_singbox_json(lines: List[str], limit: int = OUTPUT_PROXY_LIMIT) -> str:
    """لیست کانفیگ → رشتهٔ Sing-box JSON کامل (با selector/urltest)."""
    outbounds: List[Dict[str, Any]] = []
    used_tags: set = set()
    for line in lines:
        if len(outbounds) >= limit:
            break
        p = parse_proxy(line)
        if not p:
            continue
        ob = _to_singbox_outbound(p)
        if not ob:
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
