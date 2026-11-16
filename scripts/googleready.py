#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
لایهٔ «Google Ready» — آزمونِ واقعیِ دسترسی به سرویس‌های گوگل، **پس از** آبشار.

جایگاه:

    L0/L1 → L2 → L3×n  ⇒  verified/        (pipeline.py — دست‌نخورده)
                              ↓
                     همین ماژول ⇒ google/

ورودی فقط `verified/configs.txt`ِ **همین اجرا** است؛ پس `google/` همیشه
زیرمجموعهٔ `verified/` است و منطقِ L3 هیچ تغییری نمی‌کند.

──────────────────────────────────────────────────────────────────────────────
چرا این دسته اطلاعاتِ تازه می‌دهد — سنجش، نه حدس (۲۰۲۶-۱۱-۱۶)
──────────────────────────────────────────────────────────────────────────────
همهٔ ۱٬۱۷۶ کانفیگِ `verified/`، سه دور، همین پنلِ پنج‌مقصدی با xray-knife
10.1.1 (همان باینری و checksumِ CI)، از یک سرورِ آلمان. از ۹۸۳ کانفیگی که
مقصدِ کنترل (Cloudflare) در **هر سه** دور برایشان موفق بود:

    gstatic   ۹۲۳ همیشه موفق ·   ۱ همیشه ناموفق
    youtube   ۸۹۰ همیشه موفق ·  ۲۶ همیشه ناموفق  (۱۱ تا خروجِ ایران)
    play      ۸۹۲ همیشه موفق ·  ۲۲ همیشه ناموفق
    maven     ۷۰۸ همیشه موفق · ۲۰۹ همیشه ناموفق  (۱۵۰ تا HTTP 404 در هر سه دور)
    همهٔ چهار سرویس در همهٔ دورها: ۶۴۴ (۶۵٫۵٪)

یعنی تقریباً یک‌سوم از کانفیگ‌هایی که «کار می‌کنند»، دست‌کم یک سرویسِ گوگل را
باز نمی‌کنند. 404ِ Maven با curl از همان تونل بازتولید شد: گواهیِ معتبرِ
`*.google.com`، هدرِ `server: downloads`، و گوگل همان IP را `GL=US` می‌داند —
پس پاسخِ واقعیِ گوگل است و نه مرزبندیِ کشوری. روی همان میزبان کلیدِ Chrome
200 می‌داد و Maven/SDK اندروید 404.

──────────────────────────────────────────────────────────────────────────────
تصمیم‌های طراحی
──────────────────────────────────────────────────────────────────────────────
۱) **مقصدِ کنترل در همان اجرای هر کانفیگ.** نخستین مقصدِ پنل
   `cp.cloudflare.com/generate_204` است (همان نشانیِ L3). اگر کنترل شکست
   بخورد، شکستِ گوگل قابلِ نسبت‌دادن به گوگل نیست ⇒ «نامعلوم»، نه «رد».
   سنجش: وقتی کنترل شکسته بود، gstatic در حدودِ نیمی از موارد هم شکسته بود.

۲) **دو دور، موفق در هر دو.** دقتِ پیش‌بینی روی دورِ کنارگذاشته
   (leave-one-out): یک دور ۰٫۹۲۲–۰٫۹۵۵، دو دور ۰٫۹۳۷–۰٫۹۷۳. هر دور
   ۸۴–۹۳ ثانیه با ۱۰۰ رشته. دورِ سوم بیش از ۹۰ ثانیه به jobی می‌افزود که
   سقفِ ۹۰۰ ثانیه دارد.

۳) **داوری از ستونِ `endpoints`، نه از `status`.** در حالتِ پنلی، اگر
   درخواستِ جانبیِ `--rip` به Cloudflare شکست بخورد، ابزار وضعیت را
   `semi-passed` می‌کند حتی وقتی همهٔ مقصدها موفق بوده‌اند (خوانده‌شده از
   `pkg/http/examiner.go`). پس تنها منبعِ معتبر، نتیجهٔ تک‌تکِ مقصدهاست.

۴) **دروازهٔ مرجع، fail-closed.** پیش از هر کار، خودِ رانر مستقیم همهٔ
   مقصدها را می‌زند (Maven با بررسیِ محتوای POM). اگر یکی خراب باشد، این دور
   `google/` منتشر **نمی‌شود** — انتشار نکردن بهتر از انتشارِ غلط است.

۵) **هیچ دادهٔ بایاتی.** `google/` نخستین کارِ این ماژول حذف می‌شود و
   خروجیِ تازه در پوشهٔ موقت نوشته و سپس اتمیک جابه‌جا می‌شود. سنجیده شد که
   گامِ انتشار درخت را از **پوشهٔ کاری** می‌سازد، و پوشهٔ کاری checkoutِ
   انتشارِ قبلی است؛ پس هر دوری که این گام کامل نشود، بدونِ حذفِ اولیه
   `google/`ِ کهنه را دوباره منتشر می‌کرد.

۶) **بودجهٔ زمانی.** گام‌های پس از این (validate ≤۹s، publish ≤۱۱s،
   purge ≤۶۵s در ۱۲ اجرای واقعی) باید در سقفِ ۹۰۰ ثانیهٔ job جا شوند. اگر
   پیش از یک دور زمانِ کافی نماند، آن دور اجرا نمی‌شود و دسته منتشر نمی‌شود.

۷) **کارِ ناامنی که سنجش رد کرد:** «یک کانفیگ برای هر IPِ خروجی» بار را نصف
   می‌کرد، ولی در هر دور ۶ تا ۸ IP هم 200 و هم 404 گرفتند ⇒ حکم صددرصد تابعِ
   IP نیست و این بهینه‌سازی نتیجه را خراب می‌کرد.

محدودیتِ ادعا (در سرآیندِ فایل هم نوشته می‌شود): «در زمانِ آزمون، از محلِ
رانر، این مقصدهای مشخص پاسخِ درست دادند» — نه «همهٔ سرویس‌های گوگل کار
می‌کنند» و نه «پخشِ ویدئو کار می‌کند».
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import converters  # noqa: E402
import core  # noqa: E402
import pipeline  # noqa: E402
import realtest  # noqa: E402

# ──────────────────────────────────────────────────────────────────────────────
# ثابت‌ها
# ──────────────────────────────────────────────────────────────────────────────

CATEGORY = "google"
SOURCE_CATEGORY = "verified"

#: فایلِ POMِ کوچک (۲٬۰۰۸ بایت، سنجیده شد) از مخزنِ رسمیِ Google Maven.
#: `maven.google.com` با 301 به همین نشانی می‌فرستد (سنجیده شد)، پس نشانیِ
#: نهایی مستقیم آمده تا یک رفت‌وبرگشتِ اضافه از هر پروکسی کم شود.
MAVEN_URL = ("https://dl.google.com/dl/android/maven2/androidx/annotation/"
             "annotation/1.9.1/annotation-1.9.1.pom")

#: (نام، نشانی، کدِ لازم). کنترل **باید** نخستین مقصد باشد.
CONTROL: Tuple[str, str, int] = (
    "control", "https://cp.cloudflare.com/generate_204", 204)
SERVICES: Tuple[Tuple[str, str, int], ...] = (
    ("gstatic", "https://www.gstatic.com/generate_204", 204),
    ("youtube", "https://www.youtube.com/generate_204", 204),
    ("play", "https://play.google.com/generate_204", 204),
    ("maven", MAVEN_URL, 200),
)
PANEL: Tuple[Tuple[str, str, int], ...] = (CONTROL,) + SERVICES

ROUNDS = int(os.environ.get("GR_ROUNDS", "2"))

#: کمینهٔ زمانِ باقی‌مانده برای شروعِ یک دور (ثانیه). سنجش: ۸۴–۹۳ ثانیه برای
#: هر دور با ۱۰۰ رشته روی ۱٬۱۷۶ کانفیگ ⇒ ۱۲۰ یعنی «دستِ‌کم یک دورِ سنجیده +
#: حاشیه». کمتر از این، دور به احتمالِ زیاد وسطِ کار با مهلت قطع می‌شود.
MIN_ROUND_SECONDS = int(os.environ.get("GR_MIN_ROUND_SECONDS", "120"))

#: سرِ هر دور این مقدار از بودجه کم می‌شود تا نوشتنِ فایل‌ها هم جا شود.
WRITE_RESERVE_SECONDS = 15

REFERENCE_TIMEOUT = 10.0
REFERENCE_ATTEMPTS = 2


def xk_label(url: str) -> str:
    """
    برچسبی که xray-knife در ستونِ `endpoints` برای این نشانی می‌نویسد.

    همان قاعدهٔ `endpointLabel` در `pkg/http/examiner.go` (v10.1.1): نامِ
    میزبان، بی پیشوندِ `www.` و بی درگاه.
    """
    host = urlsplit(url).hostname or ""
    return host[4:] if host.startswith("www.") else host


LABELS: Dict[str, str] = {name: xk_label(url) for name, url, _ in PANEL}

# اگر دو مقصد یک برچسب بگیرند، ستونِ `endpoints` نمی‌تواند آن‌ها را از هم جدا
# کند و یک شکست می‌تواند زیرِ نامِ موفق پنهان شود. پس در زمانِ import می‌شکند.
assert len(set(LABELS.values())) == len(LABELS), f"ambiguous labels: {LABELS}"
assert PANEL[0] is CONTROL, "the control endpoint must be probed first"

#: شکلِ دقیقِ هر نشانه در ستونِ `endpoints` (از `summarizeEndpoints`).
_EP_RE = re.compile(
    r"^(?P<label>[^=;\s]+)="
    r"(?:ok\((?P<ok>\d+)ms\)|slow\((?P<slow>\d+)ms\)|status(?P<st>-?\d+)|(?P<err>error))$")

OK = "ok"


# ──────────────────────────────────────────────────────────────────────────────
# تجزیه و داوری
# ──────────────────────────────────────────────────────────────────────────────

class UnparsedEndpoints(ValueError):
    """ستونِ `endpoints` با شکلِ سنجیده نمی‌خواند — بالادست چیزی را عوض کرده."""


def parse_endpoints(text: str) -> Dict[str, str]:
    """
    `"gstatic.com=ok(408ms); dl.google.com=status404"` →
    `{"gstatic.com": "ok", "dl.google.com": "status404"}`.

    نشانهٔ ناشناخته **بلند** می‌شکند: خواندنِ خاموشِ آن یعنی شاید یک شکست
    «موفق» شمرده شود.
    """
    out: Dict[str, str] = {}
    if not (text or "").strip():
        return out
    for token in text.split(";"):
        token = token.strip()
        if not token:
            continue
        m = _EP_RE.match(token)
        if not m:
            raise UnparsedEndpoints(f"unrecognised endpoint token: {token!r}")
        if m["ok"] is not None:
            outcome = OK
        elif m["slow"] is not None:
            outcome = "slow"
        elif m["st"] is not None:
            outcome = f"status{m['st']}"
        else:
            outcome = "error"
        out[m["label"]] = outcome
    return out


def judge_row(row: Optional[Dict[str, str]]) -> Dict[str, str]:
    """
    نتیجهٔ هر مقصد برای یک سطر: `{نام: outcome}`.

    سطرِ غایب (خروجیِ ناقص) یا تجزیه‌ناپذیر ⇒ همهٔ مقصدها `missing` /
    `unparsed` — هیچ‌کدام هرگز `ok` شمرده نمی‌شوند.
    """
    if row is None:
        return {name: "missing" for name, _, _ in PANEL}
    try:
        eps = parse_endpoints(row.get("endpoints", ""))
    except UnparsedEndpoints:
        return {name: "unparsed" for name, _, _ in PANEL}
    return {name: eps.get(LABELS[name], "absent") for name, _, _ in PANEL}


def classify_rounds(links: Sequence[str],
                    rounds: Sequence[Dict[str, Dict[str, str]]]) -> Dict[str, Any]:
    """
    حکمِ نهایی از چند دور.

        ready    کنترل و هر چهار سرویس در **همهٔ** دورها ok
        fail     کنترل در همهٔ دورها ok، ولی سرویسی دست‌کم یک بار ناموفق
        unknown  کنترل دست‌کم یک بار ناموفق ⇒ شکستِ گوگل قابلِ نسبت‌دادن نیست

    ترتیبِ `ready` همان ترتیبِ ورودی است (یعنی ترتیبِ `verified/` که بر
    میانهٔ تأخیرِ L3 مرتب شده) تا خروجی بازتولیدپذیر بماند.
    """
    if not rounds:
        raise ValueError("at least one round is required")
    ready: List[str] = []
    fail: List[str] = []
    unknown: List[str] = []
    per_service: Dict[str, Dict[str, Any]] = {
        name: {"all_ok": 0, "all_fail": 0, "mixed": 0, "fail_outcomes": {}}
        for name, _, _ in SERVICES}

    for link in links:
        verdicts = [judge_row(r.get(link)) for r in rounds]
        if not all(v["control"] == OK for v in verdicts):
            unknown.append(link)
            continue
        all_good = True
        for name, _, _ in SERVICES:
            seq = [v[name] for v in verdicts]
            n_ok = sum(1 for s in seq if s == OK)
            bucket = per_service[name]
            if n_ok == len(seq):
                bucket["all_ok"] += 1
            else:
                all_good = False
                bucket["all_fail" if n_ok == 0 else "mixed"] += 1
                for s in seq:
                    if s != OK:
                        bucket["fail_outcomes"][s] = bucket["fail_outcomes"].get(s, 0) + 1
        (ready if all_good else fail).append(link)

    return {"ready": ready, "fail": fail, "unknown": unknown,
            "per_service": per_service}


# ──────────────────────────────────────────────────────────────────────────────
# دروازهٔ مرجع
# ──────────────────────────────────────────────────────────────────────────────

def _maven_body_ok(body: bytes) -> bool:
    text = body.decode("utf-8", "replace")
    return "<project" in text and "<artifactId>annotation</artifactId>" in text


def _fetch(url: str, timeout: float) -> Tuple[int, bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(65536)
    except urllib.error.HTTPError as exc:
        return exc.code, b""


def reference_check(fetch: Callable[[str, float], Tuple[int, bytes]] = _fetch,
                    attempts: int = REFERENCE_ATTEMPTS,
                    timeout: float = REFERENCE_TIMEOUT) -> Dict[str, Any]:
    """
    خودِ رانر، **بی پروکسی**، همهٔ مقصدها را می‌زند.

    اگر مقصدی از خودِ رانر هم خراب باشد، شکستِ آن در پروکسی‌ها نشانهٔ محیط
    است، نه کانفیگ ⇒ این دور منتشر نمی‌شود.
    """
    results: Dict[str, Any] = {}
    for name, url, expect in PANEL:
        last = "not attempted"
        good = False
        for _ in range(max(1, attempts)):
            try:
                code, body = fetch(url, timeout)
            except Exception as exc:  # noqa: BLE001
                last = f"{type(exc).__name__}: {exc}"
                continue
            last = str(code)
            if code == expect and (name != "maven" or _maven_body_ok(body)):
                good = True
                break
            if name == "maven" and code == expect:
                last = f"{code} (unexpected body)"
        results[name] = {"ok": good, "result": last, "expect": expect}
    return {"ok": all(r["ok"] for r in results.values()), "endpoints": results}


# ──────────────────────────────────────────────────────────────────────────────
# اجرا
# ──────────────────────────────────────────────────────────────────────────────

def read_source_lines(path: str) -> List[str]:
    """خطوطِ کانفیگِ `verified/configs.txt` — بی سرآیند و بی سپرِ `#`."""
    if not os.path.isfile(path):
        return []
    out: List[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            text = line.strip()
            if not text or text.startswith("#") or text.startswith("//"):
                continue
            out.append(text)
    return list(dict.fromkeys(out))


def _rows_of(result: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    rows = result.get("rows")
    if not isinstance(rows, dict):
        raise TypeError(f"unexpected realtest rows shape: {type(rows).__name__}")
    return rows


def default_round(lines: Sequence[str], hard_timeout: int) -> Dict[str, Dict[str, str]]:
    """یک دورِ پنل با همان `realtest` (همان قفل‌های ضدِّ hang و دادهٔ کهنه)."""
    res = realtest.test_lines(
        lines,
        test_urls=[url for _, url, _ in PANEL],
        hard_timeout=hard_timeout,
        threads=int(os.environ.get("GR_THREADS", str(realtest.THREADS))),
    )
    return _rows_of(res)


def remove_outputs(out_dir: str) -> List[str]:
    removed: List[str] = []
    for name in (CATEGORY, CATEGORY + ".tmp"):
        path = os.path.join(out_dir, name)
        if os.path.lexists(path):
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            removed.append(name)
    return removed


def _header(count: int, rounds: int) -> str:
    services = ", ".join(f"{name} ({url})" for name, url, _ in SERVICES)
    return (
        core.hiddify_profile_header("GOOGLE READY") +
        f"# @Raydikalx — GOOGLE READY — {count} configs\n"
        f"# criterion: verified AND, in ALL {rounds} runs of this round, a real\n"
        f"# proxied request succeeded to each of: {services}.\n"
        f"# generate_204 must answer exactly 204; Maven must answer 2xx.\n"
        f"# limits: measured from the CI runner at test time. This does NOT\n"
        f"# promise every Google service, sign-in, or video playback.\n")


def write_category(out_dir: str, lines: Sequence[str], rounds: int) -> Dict[str, str]:
    """
    چهار فایلِ استاندارد را در پوشهٔ موقت می‌نویسد و سپس اتمیک جابه‌جا می‌کند.

    اگر حتی یکی از چهار فایل ساخته نشود، کلِ دسته رها می‌شود: `validate.py`
    دستهٔ موجودِ ناقص را `missing` می‌شمارد و با `--strict` **کلِ انتشار** را
    می‌شکست (همان سنجشی که در `pipeline.write_buckets` ثبت شده).
    """
    tmp = os.path.join(out_dir, CATEGORY + ".tmp")
    final = os.path.join(out_dir, CATEGORY)
    if os.path.lexists(tmp):
        shutil.rmtree(tmp)
    head = _header(len(lines), rounds)
    shielded = core.shield_unsupported_runs(list(lines))
    try:
        pipeline._write_lines(os.path.join(tmp, "configs.txt"), head, shielded)
        bodies = (
            ("configs_base64.txt", core.encode_base64_subscription(list(lines), header=head)),
            ("clash.yaml", head + converters.build_clash_yaml(list(lines))),
            ("singbox.json", converters.build_singbox_json(list(lines))),
        )
        for name, body in bodies:
            pipeline._write_lines(os.path.join(tmp, name), "", [body.rstrip("\n")])
        # همان بررسیِ `validate.py::check_singbox` (json.load) — پیش از جابه‌جایی.
        with open(os.path.join(tmp, "singbox.json"), encoding="utf-8") as fh:
            json.load(fh)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    if os.path.lexists(final):
        shutil.rmtree(final)
    os.replace(tmp, final)
    return {name: os.path.join(final, name)
            for name in ("configs.txt", "configs_base64.txt", "clash.yaml", "singbox.json")}


def _load_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        print(f"⚠️ {path} could not be read ({exc})", file=sys.stderr)
        return None
    return doc if isinstance(doc, dict) else None


def _dump_json(path: str, doc: Dict[str, Any]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


CRITERION = ("verified AND, in all rounds, a real proxied request succeeded to "
             "gstatic, YouTube and Play generate_204 (exactly 204) and to a "
             "Google Maven POM (2xx); measured from the CI runner")


def merge_health(out_dir: str, block: Dict[str, Any]) -> Optional[str]:
    path = os.path.join(out_dir, "health.json")
    doc = _load_json(path) if os.path.exists(path) else None
    if doc is None:
        return None
    doc[CATEGORY] = block
    _dump_json(path, doc)
    return path


def merge_index(out_dir: str, count: int) -> Optional[str]:
    """
    `google` را زیرِ `cascade_categories` تبلیغ می‌کند — **فقط** اگر هر چهار
    فایل روی دیسک باشند. کلیدِ بسته‌ی `categories` دست نمی‌خورد (همان
    قراردادِ `pipeline.merge_index` و تستِ مربوط به آن).
    """
    path = os.path.join(out_dir, "index.json")
    doc = _load_json(path) if os.path.exists(path) else None
    if doc is None:
        return None
    primary = doc.get("primary_base")
    mirror = doc.get("mirror_base") or ""
    cascade = doc.get("cascade_categories")
    if not isinstance(cascade, dict):
        cascade = {}
    cat_dir = os.path.join(out_dir, CATEGORY)
    files: Dict[str, str] = {}
    if isinstance(primary, str) and primary and count > 0:
        for fname, key in (("configs.txt", "configs_txt"),
                           ("configs_base64.txt", "configs_base64"),
                           ("clash.yaml", "clash_yaml"),
                           ("singbox.json", "singbox_json")):
            if not os.path.isfile(os.path.join(cat_dir, fname)):
                files = {}
                break
            files[key] = f"{primary}/{CATEGORY}/{fname}"
            if isinstance(mirror, str) and mirror:
                files[f"{key}_mirror"] = f"{mirror}/{CATEGORY}/{fname}"
    if files:
        cascade[CATEGORY] = {"unique": count, "criterion": CRITERION, "files": files}
    else:
        cascade.pop(CATEGORY, None)
    if cascade:
        doc["cascade_categories"] = cascade
    else:
        doc.pop("cascade_categories", None)
    _dump_json(path, doc)
    return path


def run(out_dir: str, *,
        rounds: Optional[int] = None,
        deadline_epoch: float = 0.0,
        cascade_outcome: str = "success",
        reference: Callable[[], Dict[str, Any]] = reference_check,
        round_fn: Callable[[Sequence[str], int], Dict[str, Dict[str, str]]] = default_round,
        clock: Callable[[], float] = time.time) -> Dict[str, Any]:
    """
    کلِ لایه. همیشه یک بلوکِ گزارش برمی‌گرداند و در `health.json` می‌نویسد؛
    `google/` تنها وقتی وجود دارد که همهٔ شرط‌ها برقرار باشند.
    """
    rounds = ROUNDS if rounds is None else int(rounds)
    if rounds < 1:
        raise ValueError(f"rounds must be >= 1, got {rounds!r}")
    t0 = clock()
    removed = remove_outputs(out_dir)
    block: Dict[str, Any] = {
        "status": "skipped",
        "reason": "",
        "criterion": CRITERION,
        "rounds": rounds,
        "panel": {name: {"url": url, "expect": expect} for name, url, expect in PANEL},
        "removed_previous": removed,
    }

    def finish(status: str, reason: str = "") -> Dict[str, Any]:
        block["status"] = status
        block["reason"] = reason
        block["seconds"] = round(clock() - t0, 2)
        merge_health(out_dir, block)
        merge_index(out_dir, block.get("ready", 0) if status == "published" else 0)
        print(f"→ google: {status}" + (f" ({reason})" if reason else ""))
        return block

    if cascade_outcome != "success":
        # `verified/` ممکن است بایاتِ انتشارِ قبلی باشد ⇒ رویش آزمون نمی‌زنیم.
        return finish("skipped", f"cascade outcome is {cascade_outcome!r}")

    links = read_source_lines(os.path.join(out_dir, SOURCE_CATEGORY, "configs.txt"))
    block["input"] = len(links)
    if not links:
        return finish("skipped", "verified/configs.txt is missing or empty")

    ref = reference()
    block["reference"] = ref
    if not ref.get("ok"):
        return finish("skipped", "reference check failed from the runner itself")

    results: List[Dict[str, Dict[str, str]]] = []
    per_round_seconds: List[float] = []
    for i in range(rounds):
        limit = int(realtest.HARD_TIMEOUT)
        if deadline_epoch:
            remaining = int(deadline_epoch - clock()) - WRITE_RESERVE_SECONDS
            if remaining < MIN_ROUND_SECONDS:
                block["per_round_seconds"] = per_round_seconds
                return finish("skipped",
                              f"time budget: {remaining}s left before round {i + 1}, "
                              f"need >= {MIN_ROUND_SECONDS}s")
            limit = min(limit, remaining)
        t = clock()
        try:
            results.append(round_fn(links, limit))
        except Exception as exc:  # noqa: BLE001
            block["per_round_seconds"] = per_round_seconds
            return finish("failed", f"round {i + 1}: {type(exc).__name__}: {str(exc)[:300]}")
        per_round_seconds.append(round(clock() - t, 2))
    block["per_round_seconds"] = per_round_seconds

    verdict = classify_rounds(links, results)
    block.update({
        "ready": len(verdict["ready"]),
        "fail": len(verdict["fail"]),
        "unknown": len(verdict["unknown"]),
        "judged": len(verdict["ready"]) + len(verdict["fail"]),
        "per_service": verdict["per_service"],
    })
    judged = block["judged"]
    block["ready_pct_of_judged"] = round(100.0 * block["ready"] / judged, 2) if judged else 0.0

    if not verdict["ready"]:
        return finish("empty", "no config passed every endpoint in every round")
    try:
        write_category(out_dir, verdict["ready"], rounds)
    except Exception as exc:  # noqa: BLE001
        return finish("failed", f"writing {CATEGORY}/: {type(exc).__name__}: {str(exc)[:300]}")
    return finish("published")


def _main(argv: Sequence[str]) -> int:
    ap = argparse.ArgumentParser(description="Google Ready layer (runs after the cascade)")
    ap.add_argument("--out", default=".", help="output directory (repo root)")
    ap.add_argument("--rounds", type=int, default=None)
    ap.add_argument("--deadline-epoch", type=float, default=0.0,
                    help="unix time by which this step must be done (0 = no deadline)")
    ap.add_argument("--cascade-outcome", default="success",
                    help="outcome of the cascade step; anything but 'success' skips")
    args = ap.parse_args(argv)
    block = run(args.out, rounds=args.rounds, deadline_epoch=args.deadline_epoch,
                cascade_outcome=args.cascade_outcome)
    summary = {k: block.get(k) for k in ("status", "reason", "input", "ready", "fail",
                                         "unknown", "per_round_seconds", "seconds")}
    print(json.dumps(summary, ensure_ascii=False))
    return 1 if block["status"] == "failed" else 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
