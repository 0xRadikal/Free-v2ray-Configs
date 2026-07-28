# -*- coding: utf-8 -*-
"""
validate.py — دروازهٔ اعتبارسنجی خروجی‌ها با **کلاینت واقعی**.

مسئلهٔ بنیادینی که این ماژول حل می‌کند
────────────────────────────────────────
یک کانفیگ نامعتبر در وسط `clash.yaml` یا `singbox.json` باعث می‌شود کلاینت
**کل فایل** را رد کند، نه فقط همان یک نود. یعنی یک خط خراب = صفر کانفیگ برای
کاربر. تولید فایل «تقریباً درست» بی‌معنی است.

پس پیش از انتشار، همان باینری‌هایی که کاربر استفاده می‌کند خروجی را
اعتبارسنجی می‌کنند:
  • `sing-box check -c <file>`
  • `mihomo -t -f <file>`

اگر باینری در دسترس نباشد (توسعهٔ محلی)، اعتبارسنجی ساختاری انجام می‌شود
(JSON/YAML قابل تجزیه + وجود کلیدهای الزامی) و نتیجه «skipped» علامت
می‌خورد — هرگز به‌دروغ «pass» گزارش نمی‌شود.

اجرا به‌صورت مستقل:
    python scripts/validate.py --out .            # اعتبارسنجی خروجی‌های موجود
    python scripts/validate.py --out . --strict   # کد خروج ≠۰ در صورت شکست
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

CATEGORIES = ("all", "heavy", "light")

#: زمان بیشینهٔ اجرای هر باینری اعتبارسنج (ثانیه).
CHECK_TIMEOUT = 180

#: sing-box/mihomo پیام‌ها را رنگی چاپ می‌کنند؛ در لاگ CI به بایت‌های زائد
#: تبدیل می‌شود و مقایسهٔ رشته‌ای را می‌شکند، پس پاک می‌شود.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _clean(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _find_binary(*names: str) -> Optional[str]:
    """مسیر باینری در PATH یا محل‌های متعارف نصب در CI."""
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    for n in names:
        for cand in (f"/usr/local/bin/{n}", f"/usr/bin/{n}", f"./{n}"):
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
    return None


def _run(cmd: List[str]) -> Tuple[int, str]:
    try:
        pr = subprocess.run(cmd, capture_output=True, text=True, timeout=CHECK_TIMEOUT)
        return pr.returncode, _clean((pr.stdout or "") + (pr.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {CHECK_TIMEOUT}s"
    except Exception as e:  # noqa: BLE001
        return 125, f"{type(e).__name__}: {e}"


# ──────────────────────────────────────────────────────────────────────────────
# اعتبارسنجی ساختاری (وقتی باینری نیست)
# ──────────────────────────────────────────────────────────────────────────────

def _structural_singbox(path: str) -> Tuple[bool, str]:
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except Exception as e:  # noqa: BLE001
        return False, f"JSON parse error: {e}"
    if not isinstance(doc.get("outbounds"), list) or not doc["outbounds"]:
        return False, "missing/empty outbounds"
    tags = {o.get("tag") for o in doc["outbounds"] if isinstance(o, dict)}
    # هر ارجاعی در selector/urltest باید به یک tag موجود اشاره کند،
    # وگرنه sing-box با «outbound not found» کل فایل را رد می‌کند.
    for o in doc["outbounds"]:
        if not isinstance(o, dict):
            return False, "non-object outbound"
        if o.get("type") in ("selector", "urltest"):
            for ref in o.get("outbounds", []):
                if ref not in tags:
                    return False, f"dangling reference: {ref!r}"
    final = (doc.get("route") or {}).get("final")
    if final and final not in tags:
        return False, f"route.final points to unknown tag: {final!r}"
    return True, f"structural ok ({len(doc['outbounds'])} outbounds)"


def _structural_clash(path: str) -> Tuple[bool, str]:
    try:
        import yaml
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except Exception as e:  # noqa: BLE001
        return False, f"YAML parse error: {e}"
    proxies = doc.get("proxies")
    if not isinstance(proxies, list) or not proxies:
        return False, "missing/empty proxies"
    names = {p.get("name") for p in proxies if isinstance(p, dict)}
    if len(names) != len(proxies):
        return False, "duplicate proxy names (mihomo rejects the file)"
    for g in doc.get("proxy-groups") or []:
        for ref in g.get("proxies", []):
            if ref not in names and ref not in {gg.get("name") for gg in doc["proxy-groups"]}:
                return False, f"group {g.get('name')!r} references unknown proxy {ref!r}"
    return True, f"structural ok ({len(proxies)} proxies)"


# ──────────────────────────────────────────────────────────────────────────────
# اعتبارسنجی با کلاینت واقعی
# ──────────────────────────────────────────────────────────────────────────────

def check_singbox(path: str, binary: Optional[str]) -> Dict[str, Any]:
    if not os.path.isfile(path):
        return {"status": "missing", "detail": "file not found"}
    if not binary:
        ok, detail = _structural_singbox(path)
        return {"status": "skipped" if ok else "fail", "detail": detail,
                "note": "sing-box binary unavailable; structural check only"}
    code, out = _run([binary, "check", "-c", path])
    if code == 0:
        return {"status": "pass", "detail": "sing-box check OK"}
    return {"status": "fail", "detail": out.splitlines()[0][:300] if out else f"exit {code}"}


def check_clash(path: str, binary: Optional[str]) -> Dict[str, Any]:
    if not os.path.isfile(path):
        return {"status": "missing", "detail": "file not found"}
    if not binary:
        ok, detail = _structural_clash(path)
        return {"status": "skipped" if ok else "fail", "detail": detail,
                "note": "mihomo binary unavailable; structural check only"}
    # mihomo برای -t به یک دایرکتوری کاری قابل‌نوشتن نیاز دارد.
    with tempfile.TemporaryDirectory() as d:
        code, out = _run([binary, "-t", "-d", d, "-f", path])
    bad = [ln for ln in out.splitlines() if "level=error" in ln or "level=fatal" in ln]
    if code == 0 and not bad:
        return {"status": "pass", "detail": "mihomo -t OK"}
    detail = (bad[0] if bad else out.splitlines()[0] if out else f"exit {code}")
    return {"status": "fail", "detail": detail[:300]}


def validate_outputs(out_dir: str) -> Dict[str, Any]:
    """همهٔ فایل‌های Clash/Sing-box را اعتبارسنجی می‌کند و گزارش برمی‌گرداند."""
    sb = _find_binary("sing-box")
    mh = _find_binary("mihomo", "clash-meta", "clash")
    report: Dict[str, Any] = {
        "tools": {
            "sing_box": sb or None,
            "mihomo": mh or None,
        },
        "results": {},
        "summary": {"pass": 0, "fail": 0, "skipped": 0, "missing": 0},
    }
    for cat in CATEGORIES:
        report["results"][cat] = {
            "singbox": check_singbox(os.path.join(out_dir, cat, "singbox.json"), sb),
            "clash": check_clash(os.path.join(out_dir, cat, "clash.yaml"), mh),
        }
    for cat_res in report["results"].values():
        for res in cat_res.values():
            report["summary"][res["status"]] = report["summary"].get(res["status"], 0) + 1
    report["ok"] = report["summary"]["fail"] == 0 and report["summary"]["missing"] == 0
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate generated client configs")
    ap.add_argument("--out", default=os.getcwd(), help="repo root containing all/ heavy/ light/")
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero when any file fails validation")
    ap.add_argument("--json", dest="json_path", default="",
                    help="also write the report to this path")
    args = ap.parse_args()

    rep = validate_outputs(os.path.abspath(args.out))
    print("🔍 Client validation")
    print(f"   sing-box: {rep['tools']['sing_box'] or 'NOT FOUND (structural fallback)'}")
    print(f"   mihomo  : {rep['tools']['mihomo'] or 'NOT FOUND (structural fallback)'}")
    icons = {"pass": "✅", "fail": "❌", "skipped": "⚠️", "missing": "🚫"}
    for cat, res in rep["results"].items():
        for kind, r in res.items():
            print(f"   {icons.get(r['status'], '?')} {cat:<5} {kind:<8} "
                  f"{r['status']:<8} {r['detail']}")
    s = rep["summary"]
    print(f"   → pass={s['pass']} fail={s['fail']} "
          f"skipped={s['skipped']} missing={s['missing']}")

    if args.json_path:
        os.makedirs(os.path.dirname(os.path.abspath(args.json_path)) or ".", exist_ok=True)
        with open(args.json_path, "w", encoding="utf-8") as f:
            json.dump(rep, f, ensure_ascii=False, indent=2)

    if args.strict and not rep["ok"]:
        print("❌ Validation gate FAILED — outputs must not be published.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
