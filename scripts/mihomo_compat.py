# -*- coding: utf-8 -*-
"""
mihomo_compat.py — the "one bad line sinks the whole subscription" gate.

Why this module exists (measured, not assumed)
──────────────────────────────────────────────
mihomo / Clash.Meta — and every app built on it (Clash Verge Rev, FlClash,
Clash Meta for Android, Mihomo Party, …) — loads a plain-text or base64
subscription through `adapter/provider/provider.go`:

    for idx, mapping := range schema.Proxies {
        proxy, err := adapter.ParseProxy(mapping, …)
        if err != nil {
            return nil, fmt.Errorf("proxy %d error: %w", idx, err)   // ← whole file
        }
    }

A single proxy that fails `ParseProxy` makes the provider return **zero**
proxies. Measured with the pinned CI binary (mihomo v1.19.29) and the latest
release (v1.19.32) on the 2026-10-15 output of this repository:

    verified/configs.txt   798 lines →   798 loaded
    all/configs.txt      12107 lines →     0 loaded   (proxy 598: unknown method: chacha20-poly1305)
    heavy/configs.txt     9457 lines →     0 loaded
    light/configs.txt     3300 lines →     0 loaded   (proxy 211: REALITY requires TLS)
    protocols/vless.txt   4702 lines →     0 loaded
    protocols/shadowsocks.txt 1003 →     0 loaded

Removing the **6** fatal lines out of 12,107 makes the same `all/configs.txt`
load 11,651 proxies. Historical outputs back to 2026-07-29 show the same
failure (then caused by `hysteria2 … missing obfs password`).

CI never saw this because `validate.py` only runs `mihomo -t` on
`clash.yaml`; `mihomo -t` does not load file providers, so the `.txt` /
`_base64.txt` files were never exercised.

Design
──────
* Every rule below reproduces one concrete `return error` path in the mihomo
  source at tag v1.19.29 (commit e26714a1), and every rule was confirmed by
  loading a crafted line next to two healthy lines with the real binary. The
  rule fires **only** when the real binary would reject the line; it is not a
  style filter.
* Lines that mihomo's *converter* merely skips (`continue` in
  `common/convert/converter.go`) are **not** reported: they cost nothing in
  mihomo and dropping them would be a policy change, not a fix. The one
  exception is a port that is not a number in a branch that passes
  `url.Port()` straight through (trojan / tuic / hysteria, and vmess JSON):
  there the empty / non-numeric port reaches `strconv.ParseInt` and IS fatal.
* C1 control characters (U+0080–U+009F) were suspected and then **ruled out**
  by measurement: 59 such lines added to 500 healthy lines still load all 468
  loadable proxies. They are deliberately not a rule here.
* The gate is a *predicate* (`fatal_reason(line) -> Optional[str]`). Callers
  decide what to do; `aggregate.py` drops the line from the published text
  outputs and counts the drop in `health.json`.
* No network, no subprocess, pure function — cheap enough for the whole pool.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse
from typing import Dict, Optional

# ──────────────────────────────────────────────────────────────────────────────
# Accepted value sets — each one was enumerated against the real binary.
# ──────────────────────────────────────────────────────────────────────────────

#: Shadowsocks methods mihomo accepts, case-sensitive (measured: "AES-128-GCM"
#: is rejected with "unknown method"). This is deliberately the intersection
#: the project already ships in `converters.SS_CIPHERS`; values that only one
#: client accepts (e.g. `chacha20`, `aes-128-gcm-siv`) are excluded so that the
#: text output stays loadable in both mihomo and sing-box based clients.
SS_METHODS = frozenset({
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "rc4-md5", "chacha20-ietf", "xchacha20", "none",
})

#: SIP022 key length per method (base64 of exactly this many bytes, per part).
SS2022_KEY_BYTES: Dict[str, int] = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}

#: VMess `cipher` values mihomo accepts. Case-insensitive (measured: "AUTO",
#: "NONE", "AES-128-GCM" all load) but **not** whitespace-tolerant
#: (" auto" is rejected). "aes-256-gcm" is rejected.
VMESS_CIPHERS = frozenset({
    "auto", "none", "zero", "aes-128-gcm", "aes-128-cfb", "chacha20-poly1305",
})

#: xhttp modes implemented by `transport/xhttp/client.go::NewClient`.
#: Case-sensitive (measured: "Auto" is rejected).
XHTTP_MODES = frozenset({"auto", "stream-one", "stream-up", "packet-up"})

#: hysteria2 obfs types (`adapter/outbound/hysteria2.go`). Case-sensitive.
HY2_OBFS = frozenset({"salamander", "gecko"})

#: `adapter/outbound/shadowsocks.go` — the only modes accepted per plugin.
_SS_OBFS_MODES = frozenset({"tls", "http"})
_SS_V2RAY_MODES = frozenset({"websocket"})

#: `tlsC.RealityMaxShortIDLen` — 8 bytes ⇒ at most 16 hex digits.
_REALITY_MAX_SID_HEX = 16

_HEX = frozenset("0123456789abcdefABCDEF")

# Reasons — stable strings, they end up in health.json.
REASON_SS_METHOD = "ss_unknown_method"
REASON_SS_KEY = "ss_bad_key"
REASON_SS_PLUGIN = "ss_bad_plugin_mode"
REASON_REALITY_NO_TLS = "reality_without_tls"
REASON_REALITY_KEY = "reality_bad_public_key"
REASON_REALITY_SID = "reality_bad_short_id"
REASON_VLESS_ENC = "vless_bad_encryption"
REASON_XHTTP_MODE = "xhttp_bad_mode"
REASON_VMESS_CIPHER = "vmess_bad_cipher"
REASON_VMESS_INT = "vmess_non_integer_field"
REASON_HY2_OBFS = "hysteria2_bad_obfs"
REASON_PORT = "missing_port"


def _query(head: str) -> Dict[str, str]:
    """First value of each query key, mirroring Go's `url.Values.Get`."""
    qs = head.split("?", 1)[1] if "?" in head else ""
    out: Dict[str, str] = {}
    try:
        for k, v in urllib.parse.parse_qsl(qs, keep_blank_values=True):
            out.setdefault(k, v)
    except ValueError:
        pass
    return out


def _b64_raw_url(s: str) -> Optional[bytes]:
    """Go's `base64.RawURLEncoding.DecodeString`: url alphabet, NO padding."""
    if "=" in s or "+" in s or "/" in s:
        return None
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        return None


def _authority_port(head: str) -> Optional[str]:
    """Port text of a `scheme://userinfo@host:port[/?…]` URI, '' if absent.

    Returns None when the URI has no authority we can read.
    """
    rest = head.split("://", 1)[1] if "://" in head else ""
    rest = re.split(r"[/?]", rest, maxsplit=1)[0]
    hostport = rest.rsplit("@", 1)[-1]
    if hostport.startswith("["):
        close = hostport.find("]")
        if close < 0:
            return None
        tail = hostport[close + 1:]
        return tail[1:] if tail.startswith(":") else ""
    if ":" not in hostport:
        return ""
    return hostport.rpartition(":")[2]


def _reality_reason(q: Dict[str, str]) -> Optional[str]:
    """`adapter/outbound/reality.go::RealityOptions.Parse` + vless.go:556."""
    pbk = q.get("pbk", "")
    if not pbk:
        return None
    sec = q.get("security", "").lower()
    # common/convert/v.go: tls is set only when security ends with "tls" or is
    # exactly "reality"; reality-opts is set whenever pbk is non-empty.
    if not (sec.endswith("tls") or sec == "reality"):
        return REASON_REALITY_NO_TLS
    key = _b64_raw_url(pbk)
    if key is None or len(key) != 32:
        return REASON_REALITY_KEY
    sid = q.get("sid", "")
    if len(sid) > _REALITY_MAX_SID_HEX or len(sid) % 2 or any(c not in _HEX for c in sid):
        return REASON_REALITY_SID
    return None


def _xhttp_reason(q: Dict[str, str]) -> Optional[str]:
    if q.get("type", "").lower() != "xhttp":
        return None
    mode = q.get("mode", "")
    if mode and mode not in XHTTP_MODES:
        return REASON_XHTTP_MODE
    return None


def _vless_encryption_reason(q: Dict[str, str]) -> Optional[str]:
    """`transport/vless/encryption/factory.go::NewClient` (case-sensitive)."""
    enc = q.get("encryption", "")
    if enc in ("", "none"):
        return None
    parts = enc.split(".")
    if len(parts) < 4 or parts[0] != "mlkem768x25519plus":
        return REASON_VLESS_ENC
    if parts[1] not in ("native", "xorpub", "random") or parts[2] not in ("1rtt", "0rtt"):
        return REASON_VLESS_ENC
    keys = 0
    for r in parts[3:]:
        if len(r) < 20:
            continue                       # padding spec, not a key
        raw = _b64_raw_url(r)
        if raw is None or len(raw) not in (32, 1184):
            return REASON_VLESS_ENC
        keys += 1
    if keys == 0:                          # "failed to use encryption: empty nfsPKeysBytes"
        return REASON_VLESS_ENC
    return None


def _ss_reason(head: str, q: Dict[str, str]) -> Optional[str]:
    """Mirror of the `case "ss"` branch in common/convert/converter.go."""
    try:
        u = urllib.parse.urlsplit(head)
        port = u.port
        host_enc = u.netloc.rsplit("@", 1)[-1]
        user = u.username
        password = u.password
    except ValueError:
        return None                        # converter `continue`s — handled as REASON_PORT
    if port is None:
        # Legacy form: the whole authority is base64(method:pass@host:port).
        try:
            dec = base64.b64decode(host_enc + "=" * (-len(host_enc) % 4), validate=True)
            u = urllib.parse.urlsplit("ss://" + dec.decode("utf-8"))
            if u.port is None:
                return None
            user, password = u.username, u.password
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return None                    # converter skips it, not fatal
    if user is None:
        return None
    if password is not None:
        method = urllib.parse.unquote(user)
        password = urllib.parse.unquote(password)
    else:
        raw = urllib.parse.unquote(user)
        dec = None
        for cand in (raw, raw + "=" * (-len(raw) % 4)):
            for fn in (base64.urlsafe_b64decode, base64.b64decode):
                try:
                    dec = fn(cand).decode("utf-8", errors="replace")
                    break
                except (binascii.Error, ValueError):
                    continue
            if dec is not None:
                break
        if dec is None or ":" not in dec:
            return None                    # converter `continue`s
        method, password = dec.split(":", 1)
    if method not in SS_METHODS:
        return REASON_SS_METHOD
    need = SS2022_KEY_BYTES.get(method)
    if need is not None:
        for part in password.split(":"):
            try:
                if len(base64.b64decode(part, validate=True)) != need:
                    return REASON_SS_KEY
            except (binascii.Error, ValueError):
                return REASON_SS_KEY
    elif method != "none" and password == "":
        return REASON_SS_KEY
    plugin = q.get("plugin", "")
    if ";" in plugin:
        info = dict(urllib.parse.parse_qsl("pluginName=" + plugin.replace(";", "&"),
                                           keep_blank_values=True))
        name = info.get("pluginName", "")
        if "obfs" in name:
            if info.get("obfs", "") not in _SS_OBFS_MODES:
                return REASON_SS_PLUGIN
        elif "v2ray-plugin" in name:
            mode = info.get("mode") or info.get("obfs", "")
            if mode not in _SS_V2RAY_MODES:
                return REASON_SS_PLUGIN
    return None


def _vmess_json_reason(body: str) -> Optional[str]:
    b = body.strip()
    try:
        raw = base64.b64decode(b + "=" * (-len(b) % 4))
    except (binascii.Error, ValueError):
        try:
            raw = base64.urlsafe_b64decode(b + "=" * (-len(b) % 4))
        except (binascii.Error, ValueError):
            return None
    try:
        obj = json.loads(raw.decode("utf-8", errors="replace"))
    except ValueError:
        return None
    if not isinstance(obj, dict) or not isinstance(obj.get("ps"), str):
        return None                        # converter skips (needs a string ps)
    for field in ("port", "aid"):
        v = obj.get(field)
        if isinstance(v, str) and v != "" and not re.fullmatch(r"[+-]?[0-9]+", v):
            return REASON_VMESS_INT
        if isinstance(v, str) and v == "":
            return REASON_VMESS_INT
    scy = obj.get("scy")
    if isinstance(scy, str) and scy != "" and scy.lower() not in VMESS_CIPHERS:
        return REASON_VMESS_CIPHER
    net = str(obj.get("net") or "").lower()
    if net == "xhttp":
        mode = obj.get("mode")
        if isinstance(mode, str) and mode and mode not in XHTTP_MODES:
            return REASON_XHTTP_MODE
    return None


def fatal_reason(line: str) -> Optional[str]:
    """Why a mihomo-based client would reject the whole subscription because
    of this line — or None if the line is safe.

    Never raises: any unexpected shape is treated as "not provably fatal".
    """
    try:
        return _fatal_reason(line)
    except Exception:                      # noqa: BLE001 — predicate must be total
        return None


def _fatal_reason(line: str) -> Optional[str]:
    if not line or "://" not in line:
        return None
    scheme = line.split("://", 1)[0].strip().lower()
    head = line.split("#", 1)[0]

    if scheme == "vmess":
        body = head[len("vmess://"):]
        if "@" not in body:                # V2RayN base64-JSON form
            return _vmess_json_reason(body)
        q = _query(head)
        enc = q.get("encryption", "")
        if enc and enc.lower() not in VMESS_CIPHERS:
            return REASON_VMESS_CIPHER
        return _reality_reason(q) or _xhttp_reason(q)

    if scheme in ("trojan", "tuic", "hysteria"):
        # These three converter branches copy `url.Port()` into the proxy map
        # without checking it, so a MISSING port reaches strconv.ParseInt and
        # kills the provider (measured: "cannot parse 'port' as int").
        # A non-numeric port is NOT fatal: Go's url.Parse rejects it first and
        # the converter `continue`s (measured: "trojan://pw@h:abc" → skipped).
        # Only when Go's url.Parse would SUCCEED — otherwise the converter
        # `continue`s first (measured: "trojan://8r<[9'l6hAO" is skipped, not
        # fatal; Python's urlsplit rejects the same unbalanced "[" with
        # ValueError, which is the closest pure-Python proxy for that check).
        try:
            parsed = urllib.parse.urlsplit(head)
            parsed.port                    # noqa: B018 — raises on a bad port
        except ValueError:
            return None
        if parsed.hostname and _authority_port(head) == "":
            return REASON_PORT

    q = _query(head)
    if scheme == "vless":
        return (_reality_reason(q) or _vless_encryption_reason(q) or _xhttp_reason(q))
    if scheme == "trojan":
        return _xhttp_reason(q)
    if scheme == "ss":
        return _ss_reason(head, q)
    if scheme in ("hysteria2", "hy2"):
        obfs = q.get("obfs", "")
        if obfs and (obfs not in HY2_OBFS or not q.get("obfs-password")):
            return REASON_HY2_OBFS
    return None
