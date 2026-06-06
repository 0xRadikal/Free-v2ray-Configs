# -*- coding: utf-8 -*-
"""
converters.py — تبدیل کانفیگ‌های V2Ray به فرمت‌های Clash YAML و Sing-box JSON.

پشتیبانی: vless, vmess, trojan, shadowsocks (ss).
پروتکل‌های hysteria2/tuic/wireguard در Clash classic پشتیبانی محدودی دارند؛
برای حفظ سادگی و سازگاری، فقط چهار پروتکل اصلی به Clash/Sing-box تبدیل می‌شوند
(بقیه در فایل‌های txt/base64 و per-protocol کامل موجودند).

خروجی‌ها best-effort هستند: هر کانفیگی که parse نشود نادیده گرفته می‌شود
(کرش نمی‌کند).
"""
from __future__ import annotations

import base64
import json
import urllib.parse
from typing import Any, Dict, List, Optional


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
                "servicename": q.get("serviceName") or "",
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
            return {
                "type": "shadowsocks",
                "name": name,
                "server": host,
                "port": port,
                "cipher": method or "aes-256-gcm",
                "password": password,
            }
    except Exception:
        return None
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Clash YAML
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
                   "udp": True, "network": p["network"], "tls": p["tls"]}
            if p["sni"]:
                out["servername"] = p["sni"]
            if p["network"] == "ws":
                out["ws-opts"] = {"path": p["path"] or "/", "headers": {"Host": p["host"] or p["sni"]}}
            return out
        if t == "vless":
            out = {**base, "type": "vless", "uuid": p["uuid"], "udp": True,
                   "network": p["network"], "tls": p["tls"]}
            if p.get("flow"):
                out["flow"] = p["flow"]
            if p["sni"]:
                out["servername"] = p["sni"]
            if p.get("reality") and p.get("pbk"):
                out["reality-opts"] = {"public-key": p["pbk"], "short-id": p.get("sid", "")}
                if p.get("fp"):
                    out["client-fingerprint"] = p["fp"]
            if p["network"] == "ws":
                out["ws-opts"] = {"path": p["path"] or "/", "headers": {"Host": p["host"] or p["sni"]}}
            elif p["network"] == "grpc" and p.get("servicename"):
                out["grpc-opts"] = {"grpc-service-name": p["servicename"]}
            return out
        if t == "trojan":
            out = {**base, "type": "trojan", "password": p["password"], "udp": True}
            if p["sni"]:
                out["sni"] = p["sni"]
            if p["network"] == "ws":
                out["network"] = "ws"
                out["ws-opts"] = {"path": p["path"] or "/", "headers": {"Host": p["host"] or p["sni"]}}
            return out
        if t == "shadowsocks":
            return {**base, "type": "ss", "cipher": p["cipher"], "password": p["password"], "udp": True}
    except Exception:
        return None
    return None


def build_clash_yaml(lines: List[str], limit: int = 1500) -> str:
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
    return header + yaml.dump(doc, allow_unicode=True, sort_keys=False, default_flow_style=False)


# ──────────────────────────────────────────────────────────────────────────────
# Sing-box JSON
# ──────────────────────────────────────────────────────────────────────────────

def _to_singbox_outbound(p: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    t = p["type"]
    if not p["server"] or not p["port"]:
        return None
    try:
        if t == "vmess":
            ob = {"type": "vmess", "tag": p["name"], "server": p["server"],
                  "server_port": p["port"], "uuid": p["uuid"],
                  "security": p.get("cipher", "auto"), "alter_id": p.get("alterId", 0)}
            if p["tls"]:
                ob["tls"] = {"enabled": True, "server_name": p["sni"] or p["server"]}
            if p["network"] == "ws":
                ob["transport"] = {"type": "ws", "path": p["path"] or "/",
                                   "headers": {"Host": p["host"] or p["sni"]}}
            return ob
        if t == "vless":
            ob = {"type": "vless", "tag": p["name"], "server": p["server"],
                  "server_port": p["port"], "uuid": p["uuid"]}
            if p.get("flow"):
                ob["flow"] = p["flow"]
            if p["tls"]:
                tls = {"enabled": True, "server_name": p["sni"] or p["server"]}
                if p.get("reality") and p.get("pbk"):
                    tls["reality"] = {"enabled": True, "public_key": p["pbk"],
                                      "short_id": p.get("sid", "")}
                if p.get("fp"):
                    tls["utls"] = {"enabled": True, "fingerprint": p["fp"]}
                ob["tls"] = tls
            if p["network"] == "ws":
                ob["transport"] = {"type": "ws", "path": p["path"] or "/",
                                   "headers": {"Host": p["host"] or p["sni"]}}
            elif p["network"] == "grpc" and p.get("servicename"):
                ob["transport"] = {"type": "grpc", "service_name": p["servicename"]}
            return ob
        if t == "trojan":
            ob = {"type": "trojan", "tag": p["name"], "server": p["server"],
                  "server_port": p["port"], "password": p["password"]}
            ob["tls"] = {"enabled": True, "server_name": p["sni"] or p["server"]}
            if p["network"] == "ws":
                ob["transport"] = {"type": "ws", "path": p["path"] or "/",
                                   "headers": {"Host": p["host"] or p["sni"]}}
            return ob
        if t == "shadowsocks":
            return {"type": "shadowsocks", "tag": p["name"], "server": p["server"],
                    "server_port": p["port"], "method": p["cipher"], "password": p["password"]}
    except Exception:
        return None
    return None


def build_singbox_json(lines: List[str], limit: int = 1500) -> str:
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
    doc = {
        "log": {"level": "info"},
        "outbounds": [
            {"type": "selector", "tag": "🚀 @Raydikalx",
             "outbounds": ["♻️ Auto"] + tags, "default": "♻️ Auto"},
            {"type": "urltest", "tag": "♻️ Auto", "outbounds": tags,
             "url": "http://www.gstatic.com/generate_204", "interval": "5m"},
            *outbounds,
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {"final": "🚀 @Raydikalx"},
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)
