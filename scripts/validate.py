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

دو گونهٔ دسته، با دو قاعدهٔ متفاوت
──────────────────────────────────
`all/ heavy/ light/` همیشه تولید می‌شوند، پس نبودنشان خطاست.

`verified/ fast/ secure/` (فاز B) تنها وقتی تولید می‌شوند که آزمونِ واقعیِ
پروکسی در آن اجرا فعال باشد. قاعدهٔ آن‌ها «الزامی به‌شرطِ حضور» است: اگر
دایرکتوری نبود، از بررسی رد می‌شود؛ ولی اگر بود و فایلش خراب یا ناقص بود،
**شکست** است — نه «skipped» و نه نادیده‌گرفتن.

چرا این تفکیک لازم بود؟ `report["ok"]` شرطِ `missing == 0` دارد. افزودنِ
سادهٔ سه دستهٔ تازه به همان تاپل، دروازه را بی‌درنگ می‌شکست: سنجیده شد که
پیش از این تغییر ۶ بررسی و rc=0 بود، و با افزودنِ ساده ۶ موردِ `missing`
و rc=1 می‌شد — یعنی انتشار می‌ایستاد پیش از آنکه اصلاً کدِ تولیدکنندهٔ
آن دسته‌ها نوشته شود.

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

#: دسته‌هایی که خط‌لوله **همیشه** تولید می‌کند. نبودنشان خطاست.
CORE_CATEGORIES = ("all", "heavy", "light")

#: دسته‌های فاز B (آبشارِ اعتبارسنجی). این‌ها تنها وقتی تولید می‌شوند که
#: لایهٔ L3 در آن اجرا فعال باشد، و «فعال‌بودن» به محیطِ اجرا بسته است.
#:
#: چرا جدا؟ چون `report["ok"]` شرطِ `missing == 0` دارد. اگر این سه به
#: `CORE_CATEGORIES` اضافه می‌شدند، همان لحظه دروازه با `--strict` کدِ ۱
#: می‌داد و انتشار را می‌بست — پیش از آنکه اصلاً کدِ تولیدکننده‌شان نوشته
#: شود. سنجیده شد: پیش از این تغییر ۶ بررسی و rc=0؛ با افزودنِ ساده به
#: همان تاپل، ۶ موردِ `missing` و rc=1.
#:
#: قاعدهٔ درست «الزامی به‌شرطِ حضور» است: اگر دایرکتوری نباشد، رد می‌شود؛
#: ولی اگر باشد و فایلش خراب یا ناقص باشد، **شکست** است. یعنی حذفِ خودکارِ
#: یک دسته هرگز به‌شکلِ «موفق» ظاهر نمی‌شود.
OPTIONAL_CATEGORIES = ("verified", "fast", "secure")

#: سازگاریِ عقب‌رو: هر مصرف‌کنندهٔ بیرونیِ `CATEGORIES` باید کار کند.
CATEGORIES = CORE_CATEGORIES + OPTIONAL_CATEGORIES

# نرم‌شدنِ قاعده هرگز نباید به دسته‌های اصلی سرایت کند. اگر روزی کسی نامی را
# جابه‌جا کند، `all/` می‌توانست بی‌صدا «تولیدنشده» به حساب بیاید و دروازه با
# صفر کانفیگ سبز بماند — بدترین شکستِ خاموشِ ممکن برای این پروژه. پس این‌جا
# در زمانِ import می‌شکند، نه در زمانِ انتشار.
assert not (set(CORE_CATEGORIES) & set(OPTIONAL_CATEGORIES)), \
    "a core category must never be optional"
assert len(set(CATEGORIES)) == len(CATEGORIES), "duplicate category name"

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

def _total_check(fn):
    """یک بررسیِ ساختاری را به تابعی **کل** بدل می‌کند: هرگز استثنا نمی‌دهد.

    ── چرا این لایه لازم است (F-4) ───────────────────────────────────────────
    دو بررسیِ زیر شکلِ سندِ خوانده‌شده را «مفروض» می‌گرفتند. با اجرا (نه با
    خواندنِ کد) روی سندهای بدشکل، **۲۳** شکلِ متمایز پیدا شد که استثنا
    می‌دادند — گزارشِ اولیه فقط ۱۲ موردِ «سطحِ بالا dict نیست» را دیده بود.
    نمونه‌های تازه‌کشف‌شده:

        route یک رشته باشد        → AttributeError ('str' has no 'get')
        tag یک لیست باشد          → TypeError: unhashable type: 'list'
        selector.outbounds عدد    → TypeError: 'int' object is not iterable
        proxy-groups رشته/dict    → AttributeError
        group.proxies عدد         → TypeError

    و این استثناها گزارش نمی‌شدند، بلکه **می‌کشتند**: هر دو فراخوانی
    (`check_singbox:170` و `check_clash:183`) هیچ `try` ندارند، پس با اجرا
    ثابت شد که `check_singbox(path, None)` خودش استثنا بیرون می‌دهد و
    `validate.py` می‌میرد — یعنی به‌جای «یک فایلِ خراب = یک `fail`» کلِ
    دروازهٔ اعتبارسنجی از کار می‌افتاد.

    ── چرا یک لفافِ کل، و نه فقط شمردنِ شکل‌ها ────────────────────────────────
    گاردهای دقیق (پایین‌تر) پیامِ خوانا می‌دهند و باید باشند. ولی شمارشِ
    دستیِ شکل‌ها شمارشی است که هر بار یک شکلِ نو جا می‌ماند — همان‌طور که
    گزارشِ اولیه ۱۱ شکل را جا انداخت. پس این لفاف پشتوانهٔ نهایی است:

      • این توابع **اعتبارسنج** اند؛ کارشان همین است که بگویند «این فایل
        قابل‌قبول است یا نه». هر شکلِ غیرمنتظره، به تعریف، «قابل‌قبول نیست».
        پس تبدیلِ استثنا به `(False, …)` نه پنهان‌کاری است، نه نرم‌کردنِ
        دروازه — دقیقاً همان معناست.
      • fail-closed می‌ماند: `check_*` مقدارِ `False` را به وضعیتِ `"fail"`
        نگاشت می‌کند، `fail` در `summary` شمرده می‌شود و `report["ok"]` را
        `False` می‌کند (سطرِ ~۲۶۲)، پس با `--strict` انتشار می‌ایستد.
        یعنی خروجیِ خراب هرگز بی‌صدا منتشر نمی‌شود.
      • نامِ استثنا در پیام می‌آید تا عیب‌یابی کور نشود.
    """
    def wrapper(path: str) -> Tuple[bool, str]:
        try:
            return fn(path)
        except Exception as e:  # noqa: BLE001
            # یک شکلِ پیش‌بینی‌نشده. «نمی‌دانم» در یک اعتبارسنج یعنی «رد».
            return False, (f"unexpected document shape "
                           f"({type(e).__name__}: {str(e)[:120]})")
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    wrapper.__wrapped__ = fn
    return wrapper


@_total_check
def _structural_singbox(path: str) -> Tuple[bool, str]:
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except Exception as e:  # noqa: BLE001
        return False, f"JSON parse error: {e}"
    # JSONِ معتبر لازم نیست یک شیء باشد: `[]`، `"x"`، `42`، `null`، `true`
    # همه سندِ معتبرند و همه پیش از این `AttributeError` می‌دادند.
    if not isinstance(doc, dict):
        return False, (f"top-level JSON must be an object, "
                       f"got {type(doc).__name__}")
    if not isinstance(doc.get("outbounds"), list) or not doc["outbounds"]:
        return False, "missing/empty outbounds"
    tags = set()
    for o in doc["outbounds"]:
        if not isinstance(o, dict):
            return False, "non-object outbound"
        tag = o.get("tag")
        # `tag` باید هش‌شدنی باشد وگرنه ساختنِ همین مجموعه می‌شکست
        # (`TypeError: unhashable type: 'list'`).
        if isinstance(tag, (dict, list, set)):
            return False, f"outbound tag must be a scalar, got {type(tag).__name__}"
        tags.add(tag)
    # هر ارجاعی در selector/urltest باید به یک tag موجود اشاره کند،
    # وگرنه sing-box با «outbound not found» کل فایل را رد می‌کند.
    for o in doc["outbounds"]:
        if o.get("type") in ("selector", "urltest"):
            refs = o.get("outbounds", [])
            # فقط لیست پیمایش می‌شود: عدد `TypeError` می‌داد، و رشته/dict
            # کاراکتر‌به‌کاراکتر یا کلید‌به‌کلید پیمایش می‌شد و پیامِ
            # گمراه‌کنندهٔ «dangling reference: 'a'» می‌ساخت.
            if not isinstance(refs, list):
                return False, (f"{o.get('tag')!r}: selector/urltest outbounds "
                               f"must be a list, got {type(refs).__name__}")
            for ref in refs:
                if ref not in tags:
                    return False, f"dangling reference: {ref!r}"
    route = doc.get("route")
    # `route` تُنُک ولی غیرشیء (`"oops"`, `[…]`, `7`) → پیش از این
    # `(doc.get("route") or {}).get(...)` استثنا می‌داد.
    if route is not None and not isinstance(route, dict):
        return False, f"route must be an object, got {type(route).__name__}"
    final = (route or {}).get("final")
    if final and final not in tags:
        return False, f"route.final points to unknown tag: {final!r}"
    return True, f"structural ok ({len(doc['outbounds'])} outbounds)"


@_total_check
def _structural_clash(path: str) -> Tuple[bool, str]:
    try:
        import yaml
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except Exception as e:  # noqa: BLE001
        return False, f"YAML parse error: {e}"
    # `safe_load` روی فایلِ خالی یا فقط-توضیح `None` می‌دهد، و روی سندِ
    # لیستی/اسکالر یک non-dict. همه پیش از این `AttributeError` می‌دادند.
    if not isinstance(doc, dict):
        got = "empty document" if doc is None else type(doc).__name__
        return False, f"top-level YAML must be a mapping, got {got}"
    proxies = doc.get("proxies")
    if not isinstance(proxies, list) or not proxies:
        return False, "missing/empty proxies"
    names = set()
    for p in proxies:
        # پیش از این، ورودیِ غیر-dict فقط از `names` می‌افتاد و بعد با
        # پیامِ گمراه‌کنندهٔ «duplicate proxy names» گزارش می‌شد. آینهٔ
        # همان قاعدهٔ «non-object outbound» در sing-box است.
        if not isinstance(p, dict):
            return False, "non-object proxy entry"
        nm = p.get("name")
        if isinstance(nm, (dict, list, set)):
            return False, f"proxy name must be a scalar, got {type(nm).__name__}"
        names.add(nm)
    if len(names) != len(proxies):
        return False, "duplicate proxy names (mihomo rejects the file)"
    groups = doc.get("proxy-groups") or []
    if not isinstance(groups, list):
        return False, f"proxy-groups must be a list, got {type(groups).__name__}"
    group_names = {g.get("name") for g in groups if isinstance(g, dict)}
    for g in groups:
        if not isinstance(g, dict):
            return False, "non-object proxy-group entry"
        refs = g.get("proxies", [])
        if not isinstance(refs, list):
            return False, (f"group {g.get('name')!r}: proxies must be a list, "
                           f"got {type(refs).__name__}")
        for ref in refs:
            if ref not in names and ref not in group_names:
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
    absent: List[str] = []
    for cat in CATEGORIES:
        cat_dir = os.path.join(out_dir, cat)
        # دستهٔ اختیاری که کلاً وجود ندارد: هنوز تولید نمی‌شود، پس بررسی‌ای
        # هم ندارد. ولی اگر دایرکتوری *باشد*، دقیقاً مثل دسته‌های اصلی
        # سنجیده می‌شود — نه نرم‌تر.
        if cat in OPTIONAL_CATEGORIES and not os.path.isdir(cat_dir):
            absent.append(cat)
            continue
        report["results"][cat] = {
            "singbox": check_singbox(os.path.join(cat_dir, "singbox.json"), sb),
            "clash": check_clash(os.path.join(cat_dir, "clash.yaml"), mh),
        }
    report["absent_optional"] = absent
    # ناوردا: دستهٔ اصلی هرگز از بررسی رد نمی‌شود، حتی اگر دایرکتوری‌اش نباشد
    # (در آن حالت فایل‌ها `missing` می‌شوند و دروازه همان‌جا می‌شکند).
    assert all(c in report["results"] for c in CORE_CATEGORIES), \
        "every core category must be checked"
    for cat_res in report["results"].values():
        for res in cat_res.values():
            report["summary"][res["status"]] = report["summary"].get(res["status"], 0) + 1

    report["ok"] = (report["summary"]["fail"] == 0
                    and report["summary"]["missing"] == 0)
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
    for cat in rep.get("absent_optional", []):
        print(f"   ➖ {cat:<5} {'—':<8} not produced in this run")
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
