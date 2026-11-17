#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
آخرین خروجیِ سالم (last-known-good) برای دسته‌های آزمون‌شده.

مسئله (بازتولید شد، ۲۰۲۶-۱۱-۱۷)
───────────────────────────────
گامِ انتشار درخت را از پوشهٔ کاری می‌سازد و پوشهٔ کاری checkoutِ انتشارِ قبلی
است. دو رفتارِ پیشین هر دو بد بودند:

  • پیش از PR #36: اگر آبشار شکست می‌خورد، خروجیِ دورِ قبل **با سرآیندِ «همین
    دور»** دوباره منتشر می‌شد (ادعای نادرست).
  • پس از PR #36: خروجی پیش از آبشار پاک می‌شد؛ با سه شکستِ پیاپیِ شبیه‌سازی‌شده،
    `verified fast secure top100.txt Countries google` از دورِ اول به بعد
    **هیچ‌وقت** منتشر نشدند ⇒ مشترکِ این لینک‌ها چیزی دریافت نمی‌کرد.

راهِ درست: «آخرین خروجیِ سالم» نگه داشته شود، ولی **صادقانه**:

  stash   پیش از aggregate (که index.json/health.json را از نو می‌سازد): مسیرهای
          هر مجموعه به `.cache/lkg/<set>/files/` منتقل و بلوک‌های توصیفیِ
          index/health و زمانِ آزمونشان ذخیره می‌شود.
  settle  پس از گامِ تولیدکننده (`if: always()`): اگر خروجیِ تازه **کامل و
          ناتهی** است، نگه داشته و زمانِ آزمونش ثبت می‌شود؛ وگرنه خروجیِ ناقص
          حذف، خروجیِ قبلی **بایت‌به‌بایت** برگردانده و در index/health با
          `stale: true` و زمانِ آزمونِ واقعی‌اش دوباره تبلیغ می‌شود.

هر فایلِ `configs.txt` خودش سطرِ `# tested: …` دارد، پس خروجیِ برگشتی سنِ
واقعی‌اش را به کاربر هم می‌گوید. گامِ ورک‌فلو یک تورِ ایمنیِ shell هم دارد:
اگر این ماژول بشکند، هر مسیرِ غایب از stash برگردانده می‌شود.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import shutil
import sys
from typing import Any, Dict, List, Optional, Tuple

STASH_ROOT = os.path.join(".cache", "lkg")

#: هر مجموعه: مسیرهای خروجی، کدام‌ها برای «کامل» لازم‌اند، و کلیدهای توصیفی.
#: `Countries/` اختیاری است: اگر آبشار موفق باشد ولی آن را نسازد، تنها همان
#: مسیر از نسخهٔ قبلی برمی‌گردد (index.jsonِ خودش `generated_at` دارد).
SETS: Dict[str, Dict[str, Any]] = {
    "cascade": {
        "paths": ("verified", "fast", "secure", "top100.txt", "Countries"),
        "required": tuple(f"{c}/{f}" for c in ("verified", "fast", "secure")
                          for f in ("configs.txt", "configs_base64.txt",
                                    "clash.yaml", "singbox.json")) + ("top100.txt",),
        "nonempty": "verified/configs.txt",
        "optional": ("Countries",),
        "index_keys": (("cascade_categories", "verified"), ("cascade_categories", "fast"),
                       ("cascade_categories", "secure"), ("top100",), ("countries",)),
        "health_keys": (("cascade",),),
    },
    "google": {
        "paths": ("google",),
        "required": tuple(f"google/{f}" for f in ("configs.txt", "configs_base64.txt",
                                                    "clash.yaml", "singbox.json")),
        "nonempty": "google/configs.txt",
        "optional": (),
        "index_keys": (("cascade_categories", "google"),),
        "health_keys": (("google",),),
    },
}

#: سنجش (۲۰۲۶-۱۱-۱۷، هر فهرست همان لحظه با آزمونِ L3ِ CI دوباره سنجیده شد):
#: فهرستِ verifiedِ ۱۵ دقیقه‌ای ۹۲٫۲٪، ۳ ساعته ۹۴٫۶٪، ۶ ساعته ۸۸٫۶٪، ۱۲ ساعته
#: ۸۶٫۵٪ و ۲۴ ساعته ۸۲٫۳٪ هنوز کار می‌کرد — در برابرِ ۰٪ برای ۴۰۴. تا ۲۴ ساعت
#: (بازهٔ سنجیده) هیچ دلیلی برای قطع نیست؛ پس از آن تنها هشدار بلندتر می‌شود.
ALERT_AFTER_MINUTES = 24 * 60

TESTED_RE = re.compile(r"^# tested: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}) UTC\s*$", re.M)


def utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def stamp(t: _dt.datetime) -> str:
    """شکلِ یکسانِ زمان در سرآیندها و JSON (دقیقه کافی است؛ هر دور ۱۵ دقیقه است)."""
    return t.astimezone(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def tested_line(t: Optional[_dt.datetime] = None) -> str:
    return f"# tested: {stamp(t or utc_now())}\n"


def _parse_stamp(s: Any) -> Optional[_dt.datetime]:
    if not isinstance(s, str):
        return None
    for fmt in ("%Y-%m-%d %H:%M UTC", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            d = _dt.datetime.strptime(s, fmt)
            return d.replace(tzinfo=_dt.timezone.utc) if d.tzinfo is None else d
        except ValueError:
            continue
    return None


def _count_configs(path: str) -> int:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return sum(1 for ln in fh if ln.strip() and not ln.startswith("#") and not ln.startswith("//"))
    except OSError:
        return 0


def _header_tested(path: str) -> Optional[str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            head = fh.read(8192)
    except OSError:
        return None
    m = TESTED_RE.search(head)
    return f"{m.group(1)} UTC" if m else None


def _load(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else None
    except Exception:  # noqa: BLE001
        return None


def _dump(path: str, doc: Dict[str, Any]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def _get(doc: Any, keys: Tuple[str, ...]) -> Any:
    for k in keys:
        if not isinstance(doc, dict) or k not in doc:
            return None
        doc = doc[k]
    return doc


def _set(doc: Dict[str, Any], keys: Tuple[str, ...], value: Any) -> None:
    for k in keys[:-1]:
        nxt = doc.get(k)
        if not isinstance(nxt, dict):
            nxt = {}
            doc[k] = nxt
        doc = nxt
    doc[keys[-1]] = value


def _remove(path: str) -> None:
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    elif os.path.lexists(path):
        os.remove(path)


def _stash_dir(out: str, name: str) -> str:
    return os.path.join(out, STASH_ROOT, name)


# ──────────────────────────────────────────────────────────────────────────────
# stash
# ──────────────────────────────────────────────────────────────────────────────

def stash(out: str, name: str) -> Dict[str, Any]:
    """
    مسیرهای مجموعه را به stash منتقل می‌کند (پیش از aggregate).

    ترتیب عمدی است: اول متادیتا نوشته می‌شود، بعد فایل‌ها منتقل می‌شوند، و هر
    انتقال جداگانه است — اگر وسطِ کار چیزی بشکند، `settle` هر آنچه را واقعاً در
    stash هست برمی‌گرداند و آنچه منتقل نشده سرِ جایش مانده است.
    """
    spec = SETS[name]
    base = _stash_dir(out, name)
    files = os.path.join(base, "files")
    if os.path.lexists(base):
        shutil.rmtree(base)
    os.makedirs(files)
    idx = _load(os.path.join(out, "index.json")) or {}
    hl = _load(os.path.join(out, "health.json")) or {}
    prev_fresh = _get(hl, ("freshness", name)) or {}
    # زمانِ آزمونِ خروجیِ موجود — به ترتیبِ اعتبار:
    #  ۱) سرآیندِ خودِ فایل (`# tested:`)  ۲) freshnessِ دورِ قبل
    #  ۳) `checked_at`ِ دورِ قبل، تنها اگر بلوکِ این مجموعه در health بوده
    #     (یعنی همان دور آن را ساخته بود؛ تقریبی: آغازِ آن دور)
    tested = _header_tested(os.path.join(out, spec["nonempty"]))
    source = "header" if tested else None
    if not tested and isinstance(prev_fresh, dict) and prev_fresh.get("tested_at"):
        tested, source = prev_fresh["tested_at"], "previous-freshness"
    if not tested and any(_get(hl, k) is not None for k in spec["health_keys"]):
        t = _parse_stamp(hl.get("checked_at"))
        if t:
            tested, source = stamp(t), "previous-round-start"
    meta = {
        "set": name,
        "tested_at": tested,
        "tested_at_source": source,
        "index": {"/".join(k): _get(idx, k) for k in spec["index_keys"] if _get(idx, k) is not None},
        "health": {"/".join(k): _get(hl, k) for k in spec["health_keys"] if _get(hl, k) is not None},
        "moved": [],
    }
    _dump(os.path.join(base, "meta.json"), meta)
    for p in spec["paths"]:
        src = os.path.join(out, p)
        if os.path.lexists(src):
            os.replace(src, os.path.join(files, p))
            meta["moved"].append(p)
            _dump(os.path.join(base, "meta.json"), meta)
    return meta


# ──────────────────────────────────────────────────────────────────────────────
# settle
# ──────────────────────────────────────────────────────────────────────────────

def is_fresh_complete(out: str, name: str) -> Tuple[bool, str]:
    spec = SETS[name]
    missing = [r for r in spec["required"] if not os.path.isfile(os.path.join(out, r))]
    if missing:
        return False, f"missing {missing[:3]}{'…' if len(missing) > 3 else ''}"
    n = _count_configs(os.path.join(out, spec["nonempty"]))
    if n < 1:
        return False, f"{spec['nonempty']} has no configs"
    return True, f"{n} configs"


def restore_files(out: str, name: str, paths: Optional[List[str]] = None) -> List[str]:
    """
    مسیرهای stash‌شده را برمی‌گرداند — **پیش از** هر کارِ دیگری در settle، و
    با کمترین وابستگی، چون از دست رفتنِ این‌ها یعنی ۴۰۴ برای کاربر.
    """
    files = os.path.join(_stash_dir(out, name), "files")
    restored: List[str] = []
    if not os.path.isdir(files):
        return restored
    for p in (paths if paths is not None else sorted(os.listdir(files))):
        src = os.path.join(files, p)
        if not os.path.lexists(src):
            continue
        dst = os.path.join(out, p)
        if os.path.lexists(dst):
            _remove(dst)
        os.replace(src, dst)
        restored.append(p)
    return restored


def _age_minutes(tested: Optional[str], now: _dt.datetime) -> Optional[int]:
    t = _parse_stamp(tested)
    return int((now - t).total_seconds() // 60) if t else None


def settle(out: str, name: str, *, producer_ok: bool, reason: str = "",
           now: Optional[_dt.datetime] = None) -> Dict[str, Any]:
    """
    تازه یا آخرین‌سالم. خروجی: بلوکِ freshness که در health.json و index.json هم
    نوشته می‌شود.
    """
    now = now or utc_now()
    spec = SETS[name]
    base = _stash_dir(out, name)
    meta = _load(os.path.join(base, "meta.json")) or {}
    complete, why = is_fresh_complete(out, name)
    fresh = producer_ok and complete
    restored: List[str] = []
    if fresh:
        # خروجیِ تازه کامل است. تنها مسیرِ اختیاری‌ای که این دور ساخته نشد از
        # نسخهٔ قبلی برمی‌گردد.
        for p in spec["optional"]:
            if not os.path.lexists(os.path.join(out, p)):
                restored += restore_files(out, name, [p])
        tested = _header_tested(os.path.join(out, spec["nonempty"])) or stamp(now)
        block = {"state": "fresh", "tested_at": tested, "age_minutes": _age_minutes(tested, now) or 0,
                 "detail": why}
        if restored:
            block["restored_optional"] = restored
    else:
        # خروجیِ ناقص/تهیِ این دور حذف و نسخهٔ قبلی برگردانده می‌شود.
        for p in spec["paths"]:
            if os.path.lexists(os.path.join(base, "files", p)) and os.path.lexists(os.path.join(out, p)):
                _remove(os.path.join(out, p))
        restored = restore_files(out, name)
        tested = meta.get("tested_at")
        in_place = (not restored and _count_configs(os.path.join(out, spec["nonempty"])) > 0)
        if restored:
            block = {"state": "stale", "tested_at": tested, "age_minutes": _age_minutes(tested, now),
                     "reason": reason or why, "restored": restored}
        elif in_place:
            # stash اجرا نشده بود (یا شکست)، پس خروجیِ قبلی سرِ جایش ماند. سنش از
            # سرآیندِ خودِ فایل خوانده می‌شود؛ بی آن، «نامعلوم» گزارش می‌شود.
            tested = _header_tested(os.path.join(out, spec["nonempty"]))
            block = {"state": "stale", "tested_at": tested, "age_minutes": _age_minutes(tested, now),
                     "reason": (reason or why) + " (no stash: previous output left in place)",
                     "restored": []}
        else:
            block = {"state": "missing", "tested_at": None, "age_minutes": None,
                     "reason": reason or why, "restored": []}
    _annotate(out, name, block, meta, fresh)
    shutil.rmtree(base, ignore_errors=True)
    return block


def _annotate(out: str, name: str, block: Dict[str, Any], meta: Dict[str, Any], fresh: bool) -> None:
    """index.json/health.json: بلوکِ freshness، و در حالتِ stale تبلیغِ دوبارهٔ
    بلوک‌های قبلی با `stale: true`. هر شکستِ این بخش فقط گزارش می‌شود: فایل‌ها
    همین بالا برگشته‌اند و مهم‌ترین چیز همان‌اند."""
    try:
        for fname in ("health.json", "index.json"):
            path = os.path.join(out, fname)
            doc = _load(path)
            if doc is None:
                continue
            fr = doc.get("freshness")
            if not isinstance(fr, dict):
                fr = {}
            fr[name] = block
            doc["freshness"] = fr
            if not fresh and block["state"] == "stale":
                saved = meta.get("index" if fname == "index.json" else "health") or {}
                for key, value in saved.items():
                    keys = tuple(key.split("/"))
                    if keys[0] == "countries" and "Countries" not in block.get("restored", []):
                        continue
                    if isinstance(value, dict):
                        value = dict(value, stale=True, tested_at=block["tested_at"])
                    current = _get(doc, keys)
                    if current is not None:
                        # گزارشِ تلاشِ همین دور (مثلاً «skipped» با دلیلش) پنهان نشود:
                        # کنارِ بلوکِ برگشتی با پسوندِ `_attempt` می‌ماند.
                        _set(doc, keys[:-1] + (keys[-1] + "_attempt",), current)
                    _set(doc, keys, value)
            elif fresh and block.get("restored_optional"):
                saved = meta.get("index" if fname == "index.json" else "health") or {}
                if "countries" in saved and "Countries" in block["restored_optional"]:
                    v = saved["countries"]
                    if isinstance(v, dict):
                        v = dict(v, stale=True)
                    doc["countries"] = v
            _dump(path, doc)
    except Exception as exc:  # noqa: BLE001
        print(f"⚠️ lkg: could not annotate index/health for {name}: {type(exc).__name__}: {exc}",
              file=sys.stderr)


def _main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="last-known-good outputs")
    ap.add_argument("action", choices=("stash", "settle"))
    ap.add_argument("--set", dest="name", required=True, choices=sorted(SETS))
    ap.add_argument("--out", default=".")
    ap.add_argument("--outcome", default="", help="cascade: steps.cascade.outcome")
    ap.add_argument("--github-output", default=os.environ.get("GITHUB_OUTPUT", ""))
    a = ap.parse_args(argv)
    if a.action == "stash":
        meta = stash(a.out, a.name)
        print(f"🗄️ lkg stash {a.name}: moved {meta['moved']} (tested {meta['tested_at']})")
        return 0
    if a.name == "google":
        g = _get(_load(os.path.join(a.out, "health.json")) or {}, ("google",)) or {}
        ok = g.get("status") == "published"
        reason = f"google step status: {g.get('status')!r}" + (f" — {g['reason']}" if g.get("reason") else "")
    else:
        ok, reason = a.outcome == "success", f"cascade outcome: {a.outcome!r}"
    block = settle(a.out, a.name, producer_ok=ok, reason=reason)
    state = block["state"]
    msg = (f"{a.name}: {state} — tested {block.get('tested_at')} "
           f"({block.get('age_minutes')} min ago) — {block.get('reason') or block.get('detail')}")
    age = block.get("age_minutes")
    if state == "fresh":
        print(f"✅ lkg {msg}")
    elif isinstance(age, int) and age > ALERT_AFTER_MINUTES:
        # بیرون از بازهٔ سنجیده: تنها هشدارِ بلندتر، نه حذف — خروجیِ کهنه هنوز
        # بهتر از ۴۰۴ است، ولی مالک باید ببیند که آبشار مدتی است شکسته.
        print(f"::error title=Last-known-good {a.name} is over {ALERT_AFTER_MINUTES // 60}h old::{msg}")
    else:
        print(f"::warning title=Serving last-known-good {a.name}::{msg}")
    if a.github_output:
        with open(a.github_output, "a", encoding="utf-8") as fh:
            fh.write(f"{a.name}_fresh={'true' if state == 'fresh' else 'false'}\n")
            fh.write(f"{a.name}_state={state}\n")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
