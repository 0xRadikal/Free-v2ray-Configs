# -*- coding: utf-8 -*-
"""
state.py — حافظهٔ بین‌دوره‌ایِ خطِ لوله (فاز D).

چرا این ماژول لازم است — با عددِ سنجیده
──────────────────────────────────────────
`sources.py` خطوط ۱۴–۱۶ خودش قاعده‌ای اعلام کرده:

    «منبعی که چند دور پیاپی صفر کانفیگ برگرداند باید حذف شود، نه اینکه در
     لیست بماند و هر ۵ دقیقه بودجهٔ شبکه بسوزاند.»

ولی این قاعده سه نقطهٔ کورِ *سنجیده‌شده* داشت — و همین‌ها انگیزهٔ ساختنِ این
ماژول بودند (اعداد و مثال‌های زیر، ثبتِ وضعیتِ **همان زمان**اند، نه امروز):

  ۱. معیارش «صفر کانفیگ» است، نه «صفر کانفیگِ یکتا». اندازه‌گیریِ زنده:
     `mahdibland/Eternity.txt` با ۱۹۸ کانفیگ، **زیرمجموعهٔ محضِ ۱۰۰.۰۰٪** از
     `mahdibland/sub/sub_merge.txt` بود (هر دو از یک مخزنِ بالادست). پس
     بازدهِ یکتایش صفر بود ولی `health.json` آن را `status: ok` می‌دید و
     قاعده هرگز روی آن نمی‌افتاد.
  ۲. `health.json` آن روز «۲۱ از ۲۱ سالم، ۰ ناسالم» می‌داد ⇒ هیچ سیگنالی
     برای فعال‌شدنِ قاعده تولید نمی‌شد.
  ۳. قاعده دستی است و از قبل دریفت کرده بود: docstring می‌گفت «۱۸ منبع»،
     در حالی که `LIGHT(7) + HEAVY(14) = 21`.

پس این ماژول، *مکانیزمِ اجرایِ* قاعده‌ای است که مخزن خودش نوشته: بازدهِ
**یکتا**ی هر منبع را دور به دور به یاد می‌آورد.

✅ و این مکانیزم عمل کرد: همان `Eternity.txt` بعداً با ۸ دورِ پیاپیِ «۰ یکتا»
   خودکار غیرفعال شد — یعنی نقطهٔ کورِ ۱ واقعاً بسته شد، نه فقط ادعا.
   در بازنگریِ ۲۷ آگوست ۲۰۲۶ همان منبع در `sources.py` هم کامنت شد.

تضمین‌های طراحی
───────────────
  • **fail-open، هرگز fail-closed نیست.** هیچ خرابی‌ای در این فایل نباید یک
    دورِ سالم را بشکند؛ حافظهٔ خراب ⇒ حافظهٔ خالی + هشدار.
  • **کرانِ رشدِ ثابت.** هر آرایهٔ تاریخچه سقفِ `MAX_HISTORY` دارد، پس حجم با
    شمارِ دورها رشد نمی‌کند.
  • **هویتِ محتوامحور، نه موقعیتی.** کلیدِ هر منبع `sha256(url)[:12]` است تا
    جابه‌جاییِ ترتیبِ لیست در `sources.py` حافظه را نشکند (همان اصلِ D6/D11).
  • **نوشتنِ اتمی.** `tmp` + `os.replace` تا دورِ هم‌زمان فایلِ نیم‌نوشته نبیند.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Dict, List

#: نسخهٔ schema. هر عددِ دیگری «ناشناس» است و حافظه از صفر ساخته می‌شود.
SCHEMA = 1

#: سقفِ طولِ هر آرایهٔ تاریخچه. کرانِ رشد از همین می‌آید.
MAX_HISTORY = 20

#: حداقل دورِ لازم قبل از هر تصمیمِ auto-disable.
MIN_ROUNDS = 10

#: هرگز تعدادِ منابعِ فعال را زیرِ این نبر.
MIN_ACTIVE = 8

#: وتوی دورِ جاری «تحملِ صفر» است: هر بازدهِ یکتای ناصفرِ امروز، تاریخچه را
#: باطل می‌کند و منبع می‌ماند.
#:
#: ⚠️ در طرحِ اولیه یک آستانهٔ کسری هم بود (`VETO_SHARE = 0.005`، یعنی «اگر
#: سهمِ امروزش > ۰.۵٪ بود بماند»). آزمونِ جهشِ D-14 نشان داد حذفش هیچ تستی را
#: نمی‌شکند، و بررسیِ حسابی ثابت کرد **دست‌نیافتنی** بوده است: برای هر
#: union > 0 داریم {today : today/union > 0.005} ⊂ {today : today > 0}، پس
#: گاردِ سخت‌ترِ `today > 0` همیشه اول عمل می‌کرد و آن شاخه هرگز اجرا نمی‌شد.
#: کدِ مرده‌ای که ظاهرِ ایمنی می‌دهد بی‌آنکه چیزی را ایمن کند، بدتر از نبودنش
#: است — پس حذف شد، نه اینکه دورش تست نوشته شود.

#: نامِ فایلِ منتشرشده. باید در `OUTPUT_PATHS`ِ ورک‌فلو هم باشد، وگرنه
#: rolling squash آن را از snapshot بیرون می‌گذارد و حافظه هر دور صفر می‌شود.
STATE_PATH = "state.json"


def source_key(url: str) -> str:
    """کلیدِ پایدارِ یک منبع — محتوامحور، نه موقعیتی."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def empty_state() -> Dict:
    """حافظهٔ خالیِ معتبر — همان چیزی که در هر حالتِ خرابی برگردانده می‌شود."""
    return {"schema": SCHEMA, "updated_at": _now_iso(), "round": 0, "sources": {}}


def _clip(seq, n: int = MAX_HISTORY) -> List[int]:
    """آخرین n عددِ صحیحِ یک دنباله. هر چیزِ غیرعددی بی‌صدا دور ریخته می‌شود.

    این تابع هم کرانِ رشد را اعمال می‌کند و هم سناریوی N4 (حافظه‌ای که با
    آرایهٔ ۱۰٬۰۰۰تایی دست‌کاری شده) را بی‌خطر می‌کند.
    """
    if not isinstance(seq, list):
        return []
    out: List[int] = []
    for v in seq:
        if isinstance(v, bool):
            continue
        if isinstance(v, int):
            out.append(v)
        elif isinstance(v, float) and v == int(v):
            out.append(int(v))
    return out[-n:] if n > 0 else []


def load_state(path: str = STATE_PATH) -> Dict:
    """حافظه را بخوان. **هرگز استثنا نمی‌دهد.**

    هر یک از این حالت‌ها ⇒ حافظهٔ خالی + هشدار روی stdout:
      • فایل نیست (اولین دور)            → سناریو N1
      • JSONِ ناقص/خالی/غیرقابل‌تجزیه     → سناریو N2
      • schemaِ ناشناس                    → سناریو N3
      • ساختارِ درست ولی نوعِ غلط          → همان مسیرِ N2
    """
    if not os.path.exists(path):
        print(f"🧠 no {path} yet — starting with an empty memory (first round)")
        return empty_state()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception as exc:                       # noqa: BLE001 — عمداً وسیع
        print(f"⚠️ {path} is unreadable ({type(exc).__name__}) — "
              f"falling back to an empty memory instead of failing the round")
        return empty_state()
    if not isinstance(raw, dict):
        print(f"⚠️ {path} is a {type(raw).__name__}, not an object — empty memory")
        return empty_state()
    if raw.get("schema") != SCHEMA:
        print(f"⚠️ {path} has schema={raw.get('schema')!r}, expected {SCHEMA} — "
              f"rebuilding memory from scratch")
        return empty_state()
    srcs = raw.get("sources")
    if not isinstance(srcs, dict):
        print(f"⚠️ {path} has no usable 'sources' object — empty memory")
        return empty_state()

    clean: Dict[str, Dict] = {}
    for key, ent in srcs.items():
        if not isinstance(key, str) or not isinstance(ent, dict):
            continue
        url = ent.get("url")
        if not isinstance(url, str) or "://" not in url:
            continue
        clean[key] = {
            "url": url,
            "tier": ent.get("tier") if isinstance(ent.get("tier"), str) else "unknown",
            "rounds": int(ent["rounds"]) if isinstance(ent.get("rounds"), int) else 0,
            "last_seen": ent.get("last_seen") if isinstance(ent.get("last_seen"), str) else None,
            "yield": _clip(ent.get("yield")),
            "unique": _clip(ent.get("unique")),
            "fail": int(ent["fail"]) if isinstance(ent.get("fail"), int) else 0,
            "disabled_since": (ent.get("disabled_since")
                               if isinstance(ent.get("disabled_since"), str) else None),
            "reason": ent.get("reason") if isinstance(ent.get("reason"), str) else None,
        }
    rnd = raw.get("round")
    return {
        "schema": SCHEMA,
        "updated_at": raw.get("updated_at") if isinstance(raw.get("updated_at"), str) else _now_iso(),
        "round": int(rnd) if isinstance(rnd, int) and rnd >= 0 else 0,
        "sources": clean,
    }


def save_state(state: Dict, path: str = STATE_PATH) -> bool:
    """حافظه را اتمی بنویس. در خرابی `False` می‌دهد و **نمی‌شکند**.

    نوشتنِ اتمی (‎`tmp` + `os.replace`‎) سناریوی N10 را می‌پوشاند: اگر دو دور
    هم‌زمان بنویسند، هیچ خواننده‌ای فایلِ نیم‌نوشته نمی‌بیند.
    """
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)
        return True
    except Exception as exc:                       # noqa: BLE001
        print(f"⚠️ could not write {path} ({type(exc).__name__}) — "
              f"this round still succeeds, memory just does not advance")
        try:
            os.remove(tmp)
        except OSError:
            pass
        return False


def record_round(state: Dict,
                 per_source: Dict[str, Dict],
                 live_urls: List[str]) -> Dict:
    """یک دور را در حافظه ثبت کن و کلیدهای مرده را GC کن.

    `per_source[url] = {"tier": str, "total": int, "unique": int}`

    `live_urls` فهرستِ urlهای امروزِ `sources.py` است. هر کلیدی که urlش در آن
    نباشد پاک می‌شود (D-8) — وگرنه حافظه با هر ویرایشِ لیست، زباله جمع می‌کند
    و کرانِ رشد بی‌معنی می‌شود.
    """
    live_keys = {source_key(u) for u in live_urls}
    srcs: Dict[str, Dict] = {k: v for k, v in state.get("sources", {}).items()
                             if k in live_keys}

    now = _now_iso()
    for url, obs in per_source.items():
        key = source_key(url)
        if key not in live_keys:
            continue
        ent = srcs.get(key) or {
            "url": url, "tier": obs.get("tier", "unknown"), "rounds": 0,
            "last_seen": None, "yield": [], "unique": [], "fail": 0,
            "disabled_since": None, "reason": None,
        }
        ent["url"] = url
        ent["tier"] = obs.get("tier", ent.get("tier", "unknown"))
        total = int(obs.get("total", 0) or 0)
        uniq = int(obs.get("unique", 0) or 0)
        ent["yield"] = _clip(list(ent.get("yield", [])) + [total])
        ent["unique"] = _clip(list(ent.get("unique", [])) + [uniq])
        ent["rounds"] = int(ent.get("rounds", 0)) + 1
        ent["last_seen"] = now
        ent["fail"] = int(ent.get("fail", 0)) + (1 if total == 0 else 0)
        srcs[key] = ent

    state["schema"] = SCHEMA
    state["sources"] = srcs
    state["round"] = int(state.get("round", 0)) + 1
    state["updated_at"] = now
    return state


def disable_candidates(state: Dict,
                       current_unique: Dict[str, int],
                       union_size: int) -> Dict[str, str]:
    """منابعی که *مجازند* غیرفعال شوند → `{url: reason}`.

    هر سه شرط باید برقرار باشد. هیچ‌کدام اختیاری نیست:

      ۱. `rounds >= MIN_ROUNDS`      — با شاهدِ کم تصمیم گرفته نشود (N7).
      ۲. آخرین `MIN_ROUNDS` مقدارِ `unique` همه صفر باشند.
      ۳. وتوی دورِ جاری: اگر امروز *هر* بازدهِ یکتایی داشت، بمان (N8).
      ٭ و یک کفِ سراسری: تعدادِ فعال زیرِ `MIN_ACTIVE` نرود (N5).

    شرطِ ۳ عمداً به *دادهٔ امروز* حقِ وتو بر *تاریخچه* می‌دهد؛ چون یک منبعِ
    خفته که ناگهان محتوای یکتا می‌آورد نباید قربانیِ گذشته‌اش شود.

    شرطِ ۱ *به‌ظاهر* زیرمجموعهٔ شرطِ ۲ است، چون در کارکردِ عادی
    `len(unique) == min(rounds, MAX_HISTORY)`. ولی `state.json` از مسیرِ
    force-push می‌آید و دست‌کاری‌پذیر است؛ حافظه‌ای با `rounds: 3` و آرایهٔ
    ۱۰تاییِ صفر کاملاً بارگذاری‌شدنی است و آن‌جا شرطِ ۱ تنها گارد است. تستِ
    مربوطه همین حالتِ جدا‌افتاده را می‌آزماید، نه حالتِ جفت‌شده را.

    ⚠️ غیرفعال‌سازی **چسبنده** است: منبعِ رد‌شده دیگر واکشی نمی‌شود، پس شاهدِ
    تازه‌ای هم تولید نمی‌کند تا خودش را تبرئه کند. راهِ بازگشت، دستیِ آگاهانه
    است: حذفِ ورودی‌اش از `state.json`ِ منتشرشده (که `reason` را هم نشان
    می‌دهد). به همین دلیل شرطِ ۳ «تحملِ صفر» است و آستانهٔ کسری ندارد.
    """
    srcs = state.get("sources", {})
    active = [k for k, e in srcs.items() if not e.get("disabled_since")]
    eligible: List[tuple] = []

    for key in active:
        ent = srcs[key]
        rounds = int(ent.get("rounds", 0))
        hist = _clip(ent.get("unique"), MIN_ROUNDS)
        if rounds < MIN_ROUNDS:
            continue
        if len(hist) < MIN_ROUNDS or any(v != 0 for v in hist):
            continue
        today = int(current_unique.get(ent["url"], 0) or 0)
        if today > 0:
            continue        # شرطِ ۳ — وتوی امروز بر تاریخچه (تحملِ صفر)
        eligible.append((key, rounds))

    # کفِ سراسری. کم‌ارزش‌ترین‌ها اول، ولی هرگز زیرِ MIN_ACTIVE.
    budget = max(0, len(active) - MIN_ACTIVE)
    eligible.sort(key=lambda kv: -kv[1])
    out: Dict[str, str] = {}
    for key, rounds in eligible[:budget]:
        out[srcs[key]["url"]] = (
            f"zero unique yield in the last {MIN_ROUNDS} of {rounds} rounds, "
            f"and zero again this round")
    return out


def mark_disabled(state: Dict, reasons: Dict[str, str]) -> Dict:
    """منابعِ تصمیم‌گرفته‌شده را در حافظه علامت بزن."""
    now = _now_iso()
    for url, why in reasons.items():
        ent = state.get("sources", {}).get(source_key(url))
        if ent is not None and not ent.get("disabled_since"):
            ent["disabled_since"] = now
            ent["reason"] = why
    return state


def disabled_urls(state: Dict) -> List[str]:
    """urlهایی که حافظه می‌گوید باید رد شوند."""
    return [e["url"] for e in state.get("sources", {}).values()
            if e.get("disabled_since") and isinstance(e.get("url"), str)]


def summary(state: Dict) -> str:
    """یک‌خطیِ خوانا برای لاگِ دور."""
    srcs = state.get("sources", {})
    off = sum(1 for e in srcs.values() if e.get("disabled_since"))
    return (f"🧠 memory: round={state.get('round', 0)} "
            f"sources={len(srcs)} disabled={off}")
