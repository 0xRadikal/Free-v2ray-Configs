# -*- coding: utf-8 -*-
"""
test_pipeline.py — تست‌های واحد برای خط‌لولهٔ تجمیع.

چرا این فایل وجود دارد
──────────────────────
هر باگی که در این پروژه پیدا شد یک ویژگیِ مشترک داشت: **خاموش** بود. خروجی
تولید می‌شد، فایل حجم داشت، هیچ خطایی چاپ نمی‌شد — ولی کلاینت آن را رد می‌کرد
یا کانفیگ هرگز وصل نمی‌شد. تنها راهِ جلوگیری از بازگشتِ چنین باگ‌هایی، تثبیتِ
هر قاعده در یک تستِ اجراییِ خودکار است.

هر تست به یک باگِ واقعیِ کشف‌شده گره خورده و شمارهٔ آن ذکر شده است.

اجرا:
    python -m pytest scripts/test_pipeline.py -q
    python scripts/test_pipeline.py          # بدون pytest هم کار می‌کند
"""
from __future__ import annotations

import base64
import json
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import yaml  # noqa: E402

import converters  # noqa: E402
import core  # noqa: E402
import filters  # noqa: E402
import reachability  # noqa: E402
import realtest  # noqa: E402
import pipeline  # noqa: E402
import validate  # noqa: E402
import sources  # noqa: E402
import state  # noqa: E402
import aggregate  # noqa: E402


# ──────────────────────────────────────────────────────────────────────────────
# P0-1 — لیستِ سفیدِ رمزهای shadowsocks و طولِ کلیدِ SS-2022
# ──────────────────────────────────────────────────────────────────────────────

def test_ss_cipher_whitelist_rejects_uuid_as_cipher():
    """باگِ واقعی: یک UUID به‌جای نامِ رمز می‌آمد و mihomo کلِ فایل را رد می‌کرد.

    پیام: `unknown method: 0fb53a60-2372-412a-a693-5157b58ecc94`
    """
    assert converters._sanitize_ss("0fb53a60-2372-412a-a693-5157b58ecc94", "pw") is None
    assert converters._sanitize_ss("aes-256-gcm", "pw") == ("aes-256-gcm", "pw")
    assert converters._sanitize_ss("CHACHA20-IETF-POLY1305", "pw") is not None
    assert converters._sanitize_ss("", "pw") is None


def test_ss2022_key_length_must_match_exactly():
    """SS-2022 کلیدِ base64 با طولِ بایتیِ دقیق می‌خواهد؛ وگرنه کلاینت خطا می‌دهد."""
    import base64
    ok16 = base64.b64encode(b"A" * 16).decode()
    ok32 = base64.b64encode(b"A" * 32).decode()

    assert converters._sanitize_ss("2022-blake3-aes-128-gcm", ok16) is not None
    assert converters._sanitize_ss("2022-blake3-aes-256-gcm", ok32) is not None
    # طولِ اشتباه → حذف
    assert converters._sanitize_ss("2022-blake3-aes-128-gcm", ok32) is None
    assert converters._sanitize_ss("2022-blake3-aes-256-gcm", ok16) is None
    # کلیدِ غیر-base64 → حذف
    assert converters._sanitize_ss("2022-blake3-aes-256-gcm", "not-base64!!") is None
    # چند-کاربره «PSK:PSK» باید پذیرفته شود
    assert converters._sanitize_ss("2022-blake3-aes-256-gcm", f"{ok32}:{ok32}") is not None


# ──────────────────────────────────────────────────────────────────────────────
# P0-2 / BONUS — اعتبارسنجیِ REALITY و flow
# ──────────────────────────────────────────────────────────────────────────────

def test_reality_short_id_must_be_even_length_hex():
    """باگِ واقعی: `sid=cfe08c23a85f24@GEMINI_PROXIES³` → mihomo: invalid REALITY short ID."""
    assert converters._sanitize_short_id("cfe08c23a85f24") == "cfe08c23a85f24"
    assert converters._sanitize_short_id("") == ""                 # خالی مجاز است
    assert converters._sanitize_short_id("abc") is None            # طولِ فرد
    assert converters._sanitize_short_id("zz") is None             # غیر-hex
    assert converters._sanitize_short_id("a" * 18) is None         # بیش از ۱۶
    assert converters._sanitize_short_id("cfe08c23a85f24@GEMINI") is None


def test_reality_public_key_must_be_32_bytes_base64url():
    good = "XF21CCK2RAaefcs24Vtp3UwgFQX_xkC9ANNOcfJ_c2w"   # ۴۳ کاراکتر
    assert converters._sanitize_pbk(good) == good
    assert converters._sanitize_pbk("tooshort") is None
    assert converters._sanitize_pbk("") is None


def test_flow_whitelist_strips_udp443_suffix():
    """باگِ واقعی: sing-box با `unsupported flow: xtls-rprx-vision-udp443` می‌مرد."""
    assert converters._sanitize_flow("xtls-rprx-vision-udp443") == "xtls-rprx-vision"
    assert converters._sanitize_flow("xtls-rprx-vision") == "xtls-rprx-vision"
    assert converters._sanitize_flow("xtls-rprx-direct") == ""     # ناشناخته → حذف
    assert converters._sanitize_flow("") == ""


def test_utls_is_always_emitted_for_reality():
    """sing-box بدون uTLS برای reality هارد-فِیل می‌کند: «uTLS is required by reality client»."""
    p = {"reality": True, "pbk": "XF21CCK2RAaefcs24Vtp3UwgFQX_xkC9ANNOcfJ_c2w",
         "sid": "9e63", "sni": "example.com", "server": "1.2.3.4", "fp": ""}
    tls = converters._singbox_tls(p)
    assert tls["reality"]["enabled"] is True
    # اگر کانفیگ هیچ fp نداشته باشد، باز هم باید uTLS داشته باشد
    assert tls["utls"]["enabled"] is True
    assert tls["utls"]["fingerprint"] == converters.DEFAULT_UTLS_FINGERPRINT
    # اثرانگشتِ نامعتبر هم باید به مقدارِ پیش‌فرضِ معتبر برگردد
    p["fp"] = "totally-bogus"
    assert converters._singbox_tls(p)["utls"]["fingerprint"] in converters.UTLS_FINGERPRINTS
    # و برای کانفیگِ غیر-reality نباید uTLS ِ الکی درج شود
    plain = converters._singbox_tls({"sni": "a.com", "server": "1.2.3.4", "fp": ""})
    assert "reality" not in plain and "utls" not in plain


def test_reality_with_broken_keys_is_dropped_not_emitted():
    """مقادیرِ خرابِ REALITY باید باعثِ حذفِ کانفیگ شوند، نه درجِ ناقص."""
    assert converters._reality_params({"reality": True, "pbk": "short", "sid": ""}) is None
    assert converters._reality_params(
        {"reality": True,
         "pbk": "XF21CCK2RAaefcs24Vtp3UwgFQX_xkC9ANNOcfJ_c2w",
         "sid": "cfe08c23a85f24@GEMINI"}) is None
    # غیر-reality هم None می‌دهد (ولی به معنای «بی‌خیالِ reality»)
    assert converters._reality_params({"pbk": "x", "sid": "aa"}) is None


# ──────────────────────────────────────────────────────────────────────────────
# P0-3 — از دست رفتنِ خاموشِ برند
# ──────────────────────────────────────────────────────────────────────────────

def test_brand_remark_strips_fragment_before_base64_decode():
    """باگِ واقعی: در vmess، `#fragment` داخلِ رشتهٔ base64 حساب می‌شد و decode
    شکست می‌خورد، پس برندینگ **بی‌صدا** انجام نمی‌شد."""
    import base64
    payload = {"v": "2", "ps": "original-name", "add": "1.2.3.4", "port": "443",
               "id": "11111111-1111-1111-1111-111111111111", "aid": "0",
               "net": "ws", "tls": "tls"}
    raw = base64.b64encode(json.dumps(payload).encode()).decode()
    line = f"vmess://{raw}#some-fragment"

    branded = core.brand_remark(line, 7)
    decoded = json.loads(base64.b64decode(
        branded[8:].split("#")[0] + "=" * (-len(branded[8:].split("#")[0]) % 4)))
    assert "@Raydikalx" in decoded["ps"], f"برند درج نشد: {decoded['ps']!r}"

    # ★ این assert عوض شد و دلیلش یک اندازه‌گیری است:
    #   قبلاً انتظار `| 7` بود، یعنی شمارندهٔ **موقعیتی**. آن شمارنده حذف شد
    #   چون هر بار که یک کانفیگ به ابتدای لیست اضافه می‌شد، remarkِ همهٔ
    #   خطوطِ بعدی جابه‌جا می‌شد و delta compressionِ گیت بی‌اثر می‌شد.
    #   حالا برچسب از خودِ محتوا مشتق است، پس idx نباید در خروجی دیده شود.
    assert decoded["ps"].endswith(core.stable_label(line)), \
        f"remark must end with the content-derived tag, got {decoded['ps']!r}"
    assert not decoded["ps"].endswith("| 7"), \
        "the positional index leaked back into the remark"

    # و همین موضوع برای vmess هم باید idempotent باشد: برندینگِ دوباره روی
    # خروجیِ برندشده نباید چیزی را عوض کند (منابعِ این حوزه خروجیِ ما را
    # بازنشر می‌کنند، پس این حالت واقعاً پیش می‌آید).
    assert core.brand_remark(branded) == branded, \
        "brand_remark is not idempotent for vmess"


def test_plain_uri_vmess_is_branded_not_passed_through():
    """باگِ واقعیِ کشف‌شده در بازبینیِ خروجیِ زنده.

    فرضِ نادرست در دو تابع این بود که «vmess بودن ⇒ base64+JSON بودن». بعضی
    منابع vmess را در قالبِ استانداردِ URI می‌دهند، درست مثلِ vless:

        vmess://<uuid>@91.107.139.186:51459?encryption=auto&type=tcp#…

    پیامدش دو مرحله‌ای بود: `endpoint_of` رشتهٔ تهی برمی‌گرداند و بعد
    `brand_remark` در `except` همان خطِ خام را پس می‌داد. پس کانفیگ *برندنخورده*
    منتشر می‌شد و ریمارکِ بالادست — که اتفاقاً تبلیغِ کانالِ رقیب بود — در
    خروجیِ ما می‌نشست. مصداقِ واقعی در فایلِ منتشرشده: «📯1@oneclickvpnkeys».

    این آزمون هر سه ادعا را می‌پاید: مقصد پیدا شود، برند درج شود، و نامِ رقیب
    بیرون برود.
    """
    line = ("vmess://500cdc83-b189-4d79-b06b-139c7972a57f@91.107.139.186:51459"
            "?encryption=auto&security=none&type=tcp#%F0%9F%93%AF1%40oneclickvpnkeys")

    assert core.endpoint_of(line) == "91.107.139.186", (
        f"a plain-URI vmess must still yield its host, got {core.endpoint_of(line)!r}"
    )

    branded = core.brand_remark(line, 1)
    assert "#" in branded, branded
    remark = urllib.parse.unquote(branded.split("#", 1)[1])
    assert "@Raydikalx" in remark, f"برند درج نشد: {remark!r}"
    assert "oneclickvpnkeys" not in branded, (
        f"a competitor's channel must not survive branding: {remark!r}"
    )
    # و بدنهٔ فنی باید دست‌نخورده بماند، وگرنه کانفیگ از کار می‌افتد
    assert branded.split("#")[0] == line.split("#")[0], "technical body must not change"

    # این مسیر هم باید idempotent باشد
    assert core.brand_remark(branded) == branded, \
        "brand_remark is not idempotent for plain-URI vmess"


# ──────────────────────────────────────────────────────────────────────────────
# P0-4 — از دست رفتنِ خاموشِ transport
# ──────────────────────────────────────────────────────────────────────────────

def test_clash_network_maps_aliases_and_never_invents_names():
    """mihomo برای networkِ ناشناخته **بی‌صدا** به TCP برمی‌گردد؛ یعنی کانفیگ
    معتبر به نظر می‌رسد ولی هرگز وصل نمی‌شود. پس نگاشت باید صریح باشد."""
    assert converters._clash_network("websocket") == "ws"
    assert converters._clash_network("httpupgrade") == "ws"   # ws + v2ray-http-upgrade
    assert converters._clash_network("gun") == "grpc"
    assert converters._clash_network("splithttp") == "xhttp"
    assert converters._clash_network("raw") == "tcp"
    assert converters._clash_network("") == "tcp"
    assert converters._clash_network("totallybogus") == "tcp"


def test_httpupgrade_becomes_ws_with_upgrade_flag():
    """در mihomo، httpupgrade یک network نیست: ws است + `v2ray-http-upgrade: true`."""
    out: dict = {}
    converters._clash_transport_opts(
        {"network": "httpupgrade", "path": "/x", "host": "h.com"}, out)
    assert out["network"] == "ws"
    assert out["ws-opts"]["v2ray-http-upgrade"] is True
    assert out["ws-opts"]["path"] == "/x"
    # و ws معمولی نباید این پرچم را بگیرد
    out2: dict = {}
    converters._clash_transport_opts({"network": "ws", "path": "/x"}, out2)
    assert "v2ray-http-upgrade" not in out2["ws-opts"]


def test_xhttp_opts_are_emitted_for_clash():
    out: dict = {}
    converters._clash_transport_opts(
        {"network": "xhttp", "path": "/p", "host": "h.com", "mode": "packet-up"}, out)
    assert out["network"] == "xhttp"
    assert out["xhttp-opts"]["path"] == "/p"
    assert out["xhttp-opts"]["mode"] == "packet-up"


def test_grpc_service_name_falls_back_to_path():
    """برخی منابع serviceName را در path می‌گذارند؛ نباید گم شود."""
    out: dict = {}
    converters._clash_transport_opts({"network": "grpc", "path": "/mysvc"}, out)
    assert out["grpc-opts"]["grpc-service-name"] == "mysvc"
    out2: dict = {}
    converters._clash_transport_opts(
        {"network": "gun", "servicename": "explicit", "path": "/ignored"}, out2)
    assert out2["network"] == "grpc"
    assert out2["grpc-opts"]["grpc-service-name"] == "explicit"


def test_singbox_drops_transports_it_cannot_express():
    """sing-box 1.13 اصلاً transportِ xhttp ندارد. تنزل‌دادن به TCP یعنی دادنِ
    کانفیگی که هرگز وصل نمی‌شود؛ پس باید **حذف** شود."""
    assert converters._singbox_transport({"network": "xhttp"}) is False   # حذفِ نود
    assert converters._singbox_transport({"network": "splithttp"}) is False
    assert converters._singbox_transport({"network": "kcp"}) is False
    assert converters._singbox_transport({"network": "tcp"}) is None      # بدون transport
    assert converters._singbox_transport({"network": ""}) is None
    ws = converters._singbox_transport({"network": "ws", "path": "/a", "host": "h"})
    assert ws and ws["type"] == "ws"
    hu = converters._singbox_transport({"network": "httpupgrade", "path": "/a"})
    assert hu and hu["type"] == "httpupgrade"    # sing-box این را جدا دارد
    # هر تایپِ تولیدشده باید در فهرستِ مجازِ sing-box باشد
    for net in ("ws", "websocket", "httpupgrade", "grpc", "gun", "h2", "http", "quic"):
        tr = converters._singbox_transport({"network": net, "path": "/a"})
        assert tr is not False and tr is not None
        assert tr["type"] in converters._SINGBOX_TRANSPORTS, f"{net} → {tr['type']}"


# ──────────────────────────────────────────────────────────────────────────────
# BONUS — ناسازگاریِ YAML 1.1 (PyYAML) با YAML 1.2 (Go/mihomo)
# ──────────────────────────────────────────────────────────────────────────────

def test_ambiguous_scalars_are_quoted_so_go_reads_them_as_strings():
    """باگِ واقعی: `short-id: 9e63` بدون کوتیشن چاپ می‌شد. PyYAML آن را رشته
    می‌داند (YAML 1.1) ولی yaml.v3 در Go عددِ ۹×۱۰⁶³ می‌خواند (YAML 1.2) و
    mihomo کلِ فایل را با «invalid REALITY short ID» رد می‌کرد."""
    ambiguous = ["9e63", "123456", "0x1f", "true", "False", "null", "~",
                 "1.5", "3e2", ".inf", "", "01", "+7", "0o17", ".5", "1e10"]
    dumped = yaml.dump({"v": ambiguous}, Dumper=converters._clash_dumper(),
                       allow_unicode=True, sort_keys=False,
                       default_flow_style=False, width=10 ** 6)
    for item in ambiguous:
        assert f"'{item}'" in dumped, f"{item!r} کوتیشن نشد → Go آن را عدد می‌خواند"
    # رفت‌وبرگشت: همه باید رشته بمانند
    for original, restored in zip(ambiguous, yaml.safe_load(dumped)["v"]):
        assert isinstance(restored, str) and restored == original


def test_plain_strings_are_not_needlessly_quoted():
    """کوتیشنِ بی‌مورد فایل را بزرگ و ناخوانا می‌کند."""
    dumped = yaml.dump({"v": ["chrome", "aes-256-gcm", "example.com"]},
                       Dumper=converters._clash_dumper(), allow_unicode=True,
                       sort_keys=False, default_flow_style=False, width=10 ** 6)
    assert "'chrome'" not in dumped and "chrome" in dumped


# ──────────────────────────────────────────────────────────────────────────────
# سلامتِ سراسریِ سند
# ──────────────────────────────────────────────────────────────────────────────

def test_singbox_document_has_no_deprecated_block_outbound():
    """`block` در sing-box 1.13 منسوخ است؛ جای آن action-based route rules است."""
    doc = json.loads(converters.build_singbox_json([
        "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443"
        "?type=ws&security=tls&sni=a.com&path=%2F#n1",
    ]))
    assert all(o.get("type") != "block" for o in doc["outbounds"])
    assert doc["route"]["default_domain_resolver"]["server"]
    tags = {o["tag"] for o in doc["outbounds"]}
    assert doc["route"]["final"] in tags
    for o in doc["outbounds"]:
        if o.get("type") in ("selector", "urltest"):
            assert set(o["outbounds"]) <= tags, "ارجاعِ آویزان → sing-box فایل را رد می‌کند"


def test_empty_input_yields_valid_minimal_documents():
    """اگر همهٔ منابع بیفتند، نباید فایلِ نامعتبر تولید شود."""
    doc = json.loads(converters.build_singbox_json([]))
    assert doc["outbounds"], "sing-box سندِ بدون outbound را رد می‌کند"
    y = yaml.safe_load(converters.build_clash_yaml([]))
    assert isinstance(y, dict)


def test_proxy_names_are_unique_in_clash_output():
    """نامِ تکراری باعث رد شدنِ کلِ فایل توسط mihomo می‌شود."""
    line = ("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443"
            "?type=ws&security=tls&sni=a.com&path=%2F#same")
    y = yaml.safe_load(converters.build_clash_yaml([line, line.replace("1.2.3.4", "5.6.7.8")]))
    names = [p["name"] for p in y["proxies"]]
    assert len(names) == len(set(names))


def test_output_limit_is_high_enough_not_to_discard_configs():
    """سقفِ قبلی ۱۵۰۰ بود و ~۶۵٪ کانفیگ‌ها را بی‌دلیل دور می‌ریخت."""
    assert converters.OUTPUT_PROXY_LIMIT >= 20000


# ──────────────────────────────────────────────────────────────────────────────
# انتشارِ فایلِ توخالی و بایگانیِ بی‌مصرف
# ──────────────────────────────────────────────────────────────────────────────

def _fresh_outdir():
    """یک پوشهٔ خروجیِ موقت با «فایل‌های دورِ قبل» از پیش کاشته‌شده."""
    import tempfile
    d = tempfile.mkdtemp(prefix="aggtest_")
    os.makedirs(os.path.join(d, "archive"), exist_ok=True)
    os.makedirs(os.path.join(d, "protocols"), exist_ok=True)
    return d


def test_duplicates_files_are_never_written_and_stale_ones_are_removed():
    """پوشهٔ archive/ حقِ تولیدِ ‎*_duplicates*‎ ندارد.

    باگِ واقعی: ۱۳.۸۲ مگابایت فایلِ «تکراری‌ها» در هر دور (۹۸ دور در روز)
    بازنویسی می‌شد. اندازه‌های اندازه‌گیری‌شده روی مخزنِ واقعی:
        all_duplicates_base64.txt   4,286,344 B
        heavy_duplicates_base64.txt 3,720,596 B
        all_duplicates.txt          3,214,809 B
        heavy_duplicates.txt        2,790,499 B
        light_duplicates_base64.txt   274,408 B
        light_duplicates.txt          205,857 B
    ارزشِ کاربردی: صفر (نسخهٔ یکتای همین‌ها در all/ منتشر است).
    """
    import aggregate

    d = _fresh_outdir()
    # فایل‌های دورِ قبل را می‌کاریم تا مطمئن شویم «حذف» می‌شوند نه فقط «نوشته نمی‌شوند»
    for stale in ("all_duplicates.txt", "all_duplicates_base64.txt"):
        with open(os.path.join(d, "archive", stale), "w") as f:
            f.write("STALE DATA FROM PREVIOUS ROUND\n")

    r = aggregate.CategoryResult()
    r.broken = ["vmess://brokenexample"]
    r.duplicates = ["vless://dup1", "vless://dup2"]
    aggregate.write_archive(d, "all", r)

    files = set(os.listdir(os.path.join(d, "archive")))
    dup = {f for f in files if "duplicates" in f}
    assert not dup, f"duplicates files must never be published, found: {dup}"
    # فایل broken باید بماند (کوچک و برای عیب‌یابی مفید)
    assert "all_broken.txt" in files
    assert "all_broken_base64.txt" in files


def test_empty_protocol_never_publishes_a_file_and_prunes_both_members():
    """پروتکلِ بدون کانفیگ نباید هیچ فایلی منتشر کند.

    باگِ واقعی روی مخزن: از ۲۸ فایلِ protocols/، ۱۴ فایل توخالی بودند —
    ۷ فایلِ ‎*_base64.txt‎ دقیقاً ۰ بایت و ۷ فایلِ ‎*.txt‎ فقط سرآیند
    (۳۸..۴۲ بایت). فایلِ خالی از نبودِ فایل بدتر است: کلاینتی که آن را
    subscribe کرده لیستش را با «هیچ» جانشین می‌کند.

    ★ این تست هم‌زمان باگِ کوتاه‌مداری را قفل می‌کند: نوشتنِ
      `if _remove_if_exists(txt) or _remove_if_exists(b64)` باعث می‌شد
      وقتی txt حذف شود، فایلِ base64 هرگز حذف نشود. هر دو عضو باید بروند.
    """
    import aggregate

    d = _fresh_outdir()
    pdir = os.path.join(d, "protocols")
    # جفت‌فایلِ دورِ قبل برای پروتکلی که این دور صفر کانفیگ دارد
    with open(os.path.join(pdir, "wireguard.txt"), "w") as f:
        f.write("# @Raydikalx — wireguard — 3 configs\nwireguard://old\n")
    with open(os.path.join(pdir, "wireguard_base64.txt"), "w") as f:
        f.write("d2lyZWd1YXJkOi8vb2xk\n")

    # ورودی هیچ کانفیگِ wireguard ندارد، ولی vless دارد
    counts = aggregate.write_protocols(d, ["vless://x@1.2.3.4:443#a"])

    left = set(os.listdir(pdir))
    assert "wireguard.txt" not in left, "empty protocol txt must be pruned"
    assert "wireguard_base64.txt" not in left, (
        "empty protocol base64 must ALSO be pruned — `or` short-circuits!")
    # هیچ فایلِ صفر-بایتی یا فقط-سرآیند نباید باقی بماند.
    # سنجهٔ درست «اندازهٔ بایت» نیست (فایلِ یک-کانفیگی قانوناً کوچک است)،
    # بلکه «وجودِ حداقل یک خطِ غیرِ سرآیند/غیرِ خالی» است.
    for f in left:
        p = os.path.join(pdir, f)
        assert os.path.getsize(p) > 0, f"{f} is zero bytes"
        with open(p, encoding="utf-8") as fh:
            body = [ln for ln in fh.read().splitlines()
                    if ln.strip() and not ln.startswith("#")]
        assert body, f"{f} has no payload line (header-only/empty)"
    # شمارش‌ها باید همهٔ پروتکل‌ها را داشته باشند (حتی صفرها) — اطلاعات گم نمی‌شود
    assert counts.get("wireguard") == 0
    assert counts.get("vless") == 1


def test_index_only_advertises_urls_whose_files_exist():
    """index.json نباید لینکی را تبلیغ کند که ۴۰۴ می‌دهد.

    دو باگِ واقعی که تست پیدا کرد:
      ۱) هر ۱۴ پروتکلِ PROTOCOL_ORDER بی‌قید در protocol_files فهرست
         می‌شدند، از جمله ۷ موردی که صفر کانفیگ داشتند.
      ۲) کلیدِ archive.light_broken بی‌قید فهرست می‌شد، حتی وقتی دستهٔ
         light هیچ کانفیگِ خرابی نداشت و فایلش نوشته نمی‌شد.
    """
    import aggregate

    results = {}
    for cat in ("all", "heavy", "light"):
        r = aggregate.CategoryResult()
        r.unique = ["vless://x@1.2.3.4:443#a"]
        r.broken = ["vmess://bad"] if cat != "light" else []   # light: صفر خراب
        results[cat] = r

    proto_counts = {"vless": 1, "vmess": 0, "wireguard": 0, "socks": 0}
    idx = aggregate.build_index(results, proto_counts, 1.0)

    # پروتکل‌های صفر نباید لینک داشته باشند
    for p, n in proto_counts.items():
        if n == 0:
            assert p not in idx["protocol_files"], f"{p} has 0 configs but is advertised"
            assert p not in idx.get("protocol_files_base64", {})
        else:
            assert p in idx["protocol_files"]
    # دستهٔ بدونِ کانفیگِ خراب نباید کلیدِ broken داشته باشد
    assert "light_broken" not in idx["archive"]
    assert "all_broken" in idx["archive"]
    # هیچ کلیدِ duplicates در archive نماند
    assert not [k for k in idx["archive"] if "duplicates" in k]
    # شمارشِ کاملِ پروتکل‌ها (شاملِ صفرها) باید حفظ شود
    assert idx["protocols"].get("wireguard") == 0


def test_primary_links_are_raw_not_jsdelivr():
    """هر لینکِ «اصلی» در index.json باید raw باشد، نه jsDelivr.

    چرا این تست وجود دارد (اندازه‌گیریِ زنده، نه حدس):
      raw.githubusercontent →  cache-control: max-age=300      (۵ دقیقه)
      cdn.jsdelivr.net      →  cache-control: s-maxage=43200   (۱۲ ساعت)
    در یک سنجشِ زنده jsDelivr نسخه‌ای ۱۲ساعت‌و‌۴۵دقیقه‌ای سرو می‌کرد
    (۴٬۳۵۳ کانفیگ) و raw نسخهٔ تازه را (۸٬۱۶۸ کانفیگ) — ۵۱ برابرِ بازهٔ
    هدفِ ۱۵ دقیقه‌ای. پیش از این تغییر، ۳۲ لینک از ۳۳ لینکِ index.json به jsDelivr
    اشاره می‌کرد؛ یعنی هدفِ «آپدیتِ هر ۱۵ دقیقه» برای عملاً همهٔ مشترکان
    بی‌اثر بود. این تست جلوی بازگشتِ آن را می‌گیرد.
    """
    import aggregate

    results = {}
    for cat in ("all", "heavy", "light"):
        r = aggregate.CategoryResult()
        r.unique = ["vless://x@1.2.3.4:443#a"]
        r.broken = ["vmess://bad"]
        results[cat] = r
    idx = aggregate.build_index(results, {"vless": 1}, 1.0)

    JSD = "cdn.jsdelivr.net"
    RAW = "raw.githubusercontent.com"

    # ۱) لینک‌های هر دسته: اصلی=raw، آینه=jsdelivr
    for cat in ("all", "heavy", "light"):
        files = idx["categories"][cat]["files"]
        for key in ("configs_txt", "configs_base64", "clash_yaml", "singbox_json"):
            assert RAW in files[key], f"{cat}.{key} is not raw: {files[key]}"
            assert JSD not in files[key], f"{cat}.{key} still points at jsDelivr"
            mk = f"{key}_mirror"
            assert mk in files, f"{cat}.{mk} missing — mirror must stay available"
            assert JSD in files[mk], f"{cat}.{mk} is not the jsDelivr mirror"

    # ۲) پروتکل‌ها و archive و health هم باید raw باشند
    for p, u in idx["protocol_files"].items():
        assert RAW in u and JSD not in u, f"protocol_files[{p}] not raw: {u}"
    for p, u in idx.get("protocol_files_base64", {}).items():
        assert RAW in u and JSD not in u, f"protocol_files_base64[{p}] not raw: {u}"
    for k, u in idx["archive"].items():
        assert RAW in u and JSD not in u, f"archive[{k}] not raw: {u}"
    assert RAW in idx["sources"]["health_url"]
    assert JSD in idx["sources"]["health_url_mirror"]

    # ۳) آینه باید هنوز کشف‌پذیر باشد (نه حذف‌شده)
    assert JSD in idx["mirror_base"]
    assert RAW in idx["primary_base"]
    assert idx["link_policy"]["primary_cache_seconds"] < \
           idx["link_policy"]["mirror_cache_seconds"], \
           "link_policy must state that primary is fresher"

    # ۴) شمارشِ نهایی: اکثریتِ قاطعِ لینک‌ها باید raw باشد
    blob = json.dumps(idx)
    n_raw = blob.count(RAW)
    n_jsd = blob.count(JSD)
    assert n_raw > n_jsd, f"jsDelivr still dominates: raw={n_raw} jsdelivr={n_jsd}"






def test_index_advertises_its_own_url():
    """index.json باید آدرسِ خودش را هم منتشر کند.

    در بازبینیِ «هر فایلِ منتشرشده باید تبلیغ شود»، تنها فایلی که آدرس نداشت
    خودِ index.json بود. مصرف‌کننده‌ای که فقط این سند را دارد باید بتواند
    منبعش را بدون hard-code کردنِ برنچ پیدا کند.
    """
    import aggregate

    r = aggregate.CategoryResult()
    r.unique = ["vless://x@1.2.3.4:443#a"]
    results = {c: r for c in ("all", "heavy", "light")}
    idx = aggregate.build_index(results, {"vless": 1}, 1.0)

    assert "self_url" in idx, "index.json must advertise its own URL"
    assert idx["self_url"].endswith("/index.json"), idx["self_url"]
    assert "raw.githubusercontent.com" in idx["self_url"]
    assert f"/{aggregate.GH_BRANCH}/" in idx["self_url"], \
        "self_url must sit on the configured data branch"
    assert "cdn.jsdelivr.net" in idx["self_url_mirror"]




def test_docs_do_not_advertise_files_the_pipeline_never_writes():
    """مستندات نباید فایلی را تبلیغ کند که خط‌لوله تولید نمی‌کند.

    تولیدِ `archive/*_duplicates*` حذف شد (۱۳.۸۲ MiB در هر دور).
    اگر README همچنان آن را لیست کند، کاربر روی یک ۴۰۴ فرود می‌آید.
    """
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in ("README.md", "README_FA.md"):
        txt = open(os.path.join(repo, name), encoding="utf-8").read()
        assert "duplicates.txt" not in txt, \
            f"{name} still advertises *_duplicates.txt, which the pipeline no longer writes"


# ──────────────────────────────────────────────────────────────────────────────
# انتشار روی شاخهٔ پیش‌فرض + قطعیتِ خروجی (rolling squash)
# ──────────────────────────────────────────────────────────────────────────────

def test_publish_branch_is_the_default_branch_and_configurable():
    """خروجی‌ها باید روی شاخهٔ پیش‌فرض (`main`) منتشر شوند.

    ★ این تست عمداً برعکسِ نسخهٔ قبلیِ خودش است و دلیلش اندازه‌گیری است:

    قبلاً خروجی‌ها به یک شاخهٔ orphan به نامِ `data` منتقل شده بودند تا
    تاریخِ گیت باد نکند. آن تصمیم مهندسی درست ولی از نظرِ محصول مخرب بود:

      • هر لینکی که کاربران قبلاً کپی کرده بودند (`.../main/all/configs.txt`)
        با HTTP 404 پاسخ می‌داد ⇒ اشتراکِ کاربرِ قدیمی بی‌صدا خالی می‌شد.
      • بازدیدکنندهٔ صفحهٔ اصلیِ مخزن هیچ فایلِ کانفیگی نمی‌دید. کاربرِ
        معمولی نمی‌داند «branch» چیست تا عوضش کند.
      • بررسیِ مخازنِ موفقِ همین حوزه: هیچ‌کدام خروجی را روی شاخهٔ جدا
        نمی‌گذارند — Epodonios (⭐3166، ۲۴.۷GB روی main)،
        mahdibland (⭐4003، master)، Pawdroid (⭐18420، main).

    مسئلهٔ حجم با «rolling squash» در ورک‌فلو حل شد (شاخه همیشه
    «تاریخِ سورس + دقیقاً یک کامیتِ خروجی» است ⇒ هزینه O(1)).
    پس اینجا الزام می‌کنیم که برنچِ پیش‌فرض `main` باشد، ولی hard-code نباشد.
    """
    import importlib, os as _os
    import aggregate

    assert aggregate.GH_BRANCH == "main", \
        f"outputs must be published on the default branch 'main', got {aggregate.GH_BRANCH!r}"
    assert "/main" in aggregate.RAW_BASE, aggregate.RAW_BASE
    assert "@main" in aggregate.CDN_BASE, aggregate.CDN_BASE

    # قابلِ override با env (چهار نام پشتیبانی می‌شود؛ دو تای آخر legacy)
    for var in ("AGG_PUBLISH_BRANCH", "PUBLISH_BRANCH",
                "AGG_DATA_BRANCH", "DATA_BRANCH"):
        saved = {k: _os.environ.get(k) for k in
                 ("AGG_PUBLISH_BRANCH", "PUBLISH_BRANCH",
                  "AGG_DATA_BRANCH", "DATA_BRANCH")}
        try:
            for k in saved:
                _os.environ.pop(k, None)
            _os.environ[var] = "some-other-branch"
            reloaded = importlib.reload(aggregate)
            assert reloaded.GH_BRANCH == "some-other-branch", \
                f"{var} is ignored by aggregate.py"
            assert "/some-other-branch" in reloaded.RAW_BASE
            assert "@some-other-branch" in reloaded.CDN_BASE
        finally:
            for k, v in saved.items():
                if v is None:
                    _os.environ.pop(k, None)
                else:
                    _os.environ[k] = v
            importlib.reload(aggregate)


def test_docs_advertise_the_default_branch_only():
    """هر لینکِ اشتراک در README/README_FA باید روی `main` باشد.

    اگر حتی یک لینکِ `@data` جا بماند، همان لینک بعد از بازنشستنِ شاخهٔ
    `data` یک ۴۰۴ می‌شود. این تست هر دو README را می‌خواند و
    branch-segmentِ هر لینک را می‌سنجد.
    """
    import re

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pat_raw = re.compile(
        r"https://raw\.githubusercontent\.com/[\w.-]+/[\w.-]+/([\w.-]+)/")
    pat_cdn = re.compile(
        r"https://cdn\.jsdelivr\.net/gh/[\w.-]+/[\w.-]+@([\w.-]+)/")

    checked = 0
    for name in ("README.md", "README_FA.md"):
        path = os.path.join(repo, name)
        assert os.path.exists(path), f"{name} is missing"
        txt = open(path, encoding="utf-8").read()
        for pat in (pat_raw, pat_cdn):
            for m in pat.finditer(txt):
                checked += 1
                assert m.group(1) == "main", \
                    f"{name}: link pinned to branch {m.group(1)!r}: {m.group(0)}"
        # آینه باید ذکر شده باشد ولی «اصلی» نباشد
        n_raw = txt.count("raw.githubusercontent.com")
        n_cdn = txt.count("cdn.jsdelivr.net")
        assert n_raw > n_cdn, \
            f"{name}: jsDelivr still dominates (raw={n_raw} cdn={n_cdn})"
        # هیچ اثری از شاخهٔ data نباید در مستندات بماند
        assert "-why-a-separate-data-branch" not in txt, \
            f"{name}: still contains the obsolete data-branch rationale anchor"

    assert checked >= 10, f"suspiciously few links checked: {checked}"


def test_workflow_publishes_to_the_same_branch_the_links_advertise():
    """شاخه‌ای که ورک‌فلو رویش push می‌کند باید همانی باشد که در لینک‌ها است.

    باگِ واقعیِ کشف‌شده (نسخهٔ قبلی): aggregate.py فقط `AGG_DATA_BRANCH` را
    می‌خواند، ولی ورک‌فلو `DATA_BRANCH` را ست می‌کرد ⇒ اگر مقدار عوض می‌شد،
    ورک‌فلو روی شاخهٔ X منتشر می‌کرد و index.json شاخهٔ Y را تبلیغ می‌کرد:
    ۳۴ لینکِ ۴۰۴ با buildِ سبز.
    این تست هر دو سمت را از خودِ فایلِ ورک‌فلو می‌خواند.
    """
    import importlib
    import aggregate

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    wf = os.path.join(repo, ".github", "workflows", "aggregate.yml")
    assert os.path.exists(wf), "workflow file is missing"
    doc = yaml.safe_load(open(wf, encoding="utf-8"))

    top_env = doc.get("env") or {}
    branch = top_env.get("PUBLISH_BRANCH")
    assert branch, "workflow must define PUBLISH_BRANCH at the top level"
    assert branch == "main", \
        f"outputs must be published on the default branch, got {branch!r}"
    # نامِ قدیمی باید به همان شاخه اشاره کند تا مصرف‌کنندهٔ قدیمی نشکند
    assert top_env.get("DATA_BRANCH") == branch, \
        "legacy DATA_BRANCH must alias PUBLISH_BRANCH"

    job = doc["jobs"][list(doc["jobs"])[0]]

    pushes = [s for s in job["steps"] if "git push" in (s.get("run") or "")]
    assert len(pushes) == 1, \
        f"expected exactly one pushing step, found {len(pushes)}"
    push_run = pushes[0]["run"]
    assert "refs/heads/$PUBLISH_BRANCH" in push_run, \
        "the push must target $PUBLISH_BRANCH, not a literal branch name"

    # ★ کدِ خروجی باید همان PUBLISH_BRANCH را ببیند
    keys = ("AGG_PUBLISH_BRANCH", "PUBLISH_BRANCH", "AGG_DATA_BRANCH", "DATA_BRANCH")
    saved = {k: os.environ.get(k) for k in keys}
    try:
        for k in keys:
            os.environ.pop(k, None)
        os.environ["PUBLISH_BRANCH"] = "branch-from-workflow"
        reloaded = importlib.reload(aggregate)
        assert reloaded.GH_BRANCH == "branch-from-workflow", (
            "aggregate.py ignores PUBLISH_BRANCH — the workflow would publish to "
            f"one branch while index.json advertises {reloaded.GH_BRANCH!r}")
        assert "/branch-from-workflow" in reloaded.RAW_BASE
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        importlib.reload(aggregate)

    assert aggregate.GH_BRANCH == branch, (
        f"workflow publishes to {branch!r} but links point at "
        f"{aggregate.GH_BRANCH!r}")


def test_publish_step_uses_rolling_squash_and_never_orphans_the_source():
    """مرحلهٔ انتشار باید «rolling squash»ِ ایمن باشد، نه force-pushِ خام.

    چرا این تست وجود دارد — با کنترلِ منفیِ اندازه‌گیری‌شده:
      حالا که خروجی روی `main` منتشر می‌شود، همان شاخه‌ای است که کدِ
      انسان‌نوشته رویش زندگی می‌کند. اگر روزی کسی `--force-with-lease` را به
      `--force` ساده تنزل بدهد، کامیتِ مالک **نابود می‌شود**. این را در
      exp/publish_verify.sh به‌صورتِ کنترلِ منفی اجرا کردم: با force-pushِ
      ساده، تعدادِ کامیتِ مالک روی origin به صفر رسید.
      پس این تست آن تنزل را از سطحِ «حادثهٔ تولید» به «شکستِ CI» می‌آورد.
    """
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    wf = os.path.join(repo, ".github", "workflows", "aggregate.yml")
    doc = yaml.safe_load(open(wf, encoding="utf-8"))
    top_env = doc.get("env") or {}
    job = doc["jobs"][list(doc["jobs"])[0]]

    pushes = [s for s in job["steps"] if "git push" in (s.get("run") or "")]
    assert len(pushes) == 1
    run = pushes[0]["run"]

    # ۱) lease الزامی است؛ force ساده ممنوع.
    assert "--force-with-lease=" in run, \
        "publishing to the default branch REQUIRES --force-with-lease"
    import re as _re
    bare_force = [ln for ln in run.split("\n")
                  if "git push" in ln and "--force " in f"{ln} "
                  and "--force-with-lease" not in ln]
    assert not bare_force, \
        f"a bare --force push would destroy owner commits: {bare_force}"

    # ۲) کامیت باید والد داشته باشد (rolling squash)، نه orphan.
    assert "commit-tree" in run, "the step must build the commit with plumbing"
    assert _re.search(r"commit-tree\s+\"?\$TREE\"?\s+-p\s+\"?\$ANCHOR\"?", run), \
        "the output commit must be parented on the source anchor (-p $ANCHOR)"

    # ۳) نشانگرِ خروجی باید تعریف و استفاده شده باشد تا anchor پیدا شود.
    mark = top_env.get("OUT_MARK")
    assert mark, "workflow must define OUT_MARK"
    assert "$OUT_MARK" in run, "the step must mark its own commits with $OUT_MARK"
    assert "grep -v -F \"$OUT_MARK\"" in run, \
        "the anchor search must exclude commits carrying $OUT_MARK"

    # ۳-ب) ★ anchor باید بر اساس «موضوعِ» کامیت (%s) پیدا شود، نه بدنهٔ کامل (%B).
    #
    # این یک تلهٔ واقعی است که در انتشارِ زندهٔ همین مخزن دیده شد، نه یک فرض:
    # کامیتِ سورسِ d5a31d8 خودِ الگوریتم را در بدنه‌اش توضیح می‌دهد و بنابراین
    # رشتهٔ «[auto-output]» در بدنه‌اش وجود دارد. اگر جست‌وجوی anchor روی %B
    # انجام شود، آن کامیتِ سورس اشتباهاً «کامیتِ خروجی» تشخیص داده می‌شود و
    # anchor به عقب می‌لغزد — یعنی کامیت‌های خروجی روی هم انباشته می‌شوند و
    # کلِ خاصیتِ O(1) از بین می‌رود (اندازه‌گیریِ زنده: با %s تعداد ۱، با %B تعداد ۲).
    #
    # پس این assert صرفاً سلیقه نیست؛ ضامنِ درستیِ الگوریتم است.
    for m in _re.finditer(r"git log --format='([^']*)'[^|]*\|\s*grep -v -F \"\$OUT_MARK\"",
                          run, _re.S):
        fmt = m.group(1)
        assert "%B" not in fmt, (
            "anchor detection must not match on the commit BODY (%B): a source "
            "commit that merely *documents* the marker would be misread as an "
            "output commit and the anchor would slide backwards. Use %s."
        )
        assert "%s" in fmt, \
            f"anchor detection must match on the commit subject (%s), got {fmt!r}"

    # ۴) گاردِ رگرسیونِ سورس باید وجود داشته باشد.
    assert "is_output_path" in run, \
        "the step must classify paths and refuse to regress source files"
    # ۴-ب) کلونِ CI عمق ۱ دارد، پس step باید تاریخ را باز کند تا anchor پیدا شود.
    #
    # ⚠️ این شرط قبلاً «وجودِ رشتهٔ deepen» بود. آن مکانیزم عوض شد چون
    # اندازه‌گیری نشان داد `--deepen` نسبی روی کلونی که نوکش force-push شده
    # مبنای مشخصی ندارد و همان مسیرِ «دانلودِ کلِ تاریخ» را باز می‌کند؛ حالا
    # نردبانِ عمقِ **مطلق** (`--depth=N`) استفاده می‌شود که در هر پله کرانمند
    # است. شرط را به خودِ خاصیت گره می‌زنیم، نه به نامِ یک سوییچِ خاص.
    assert _re.search(r"for\s+depth\s+in\s+[\d\s]+;\s*do", run), \
        ("the step must widen a shallow checkout through a bounded depth "
         "ladder, otherwise no anchor is found on a depth=1 checkout")
    assert _re.search(r"git fetch[^\n]*--depth=\"?\$depth\"?", run), \
        "the depth ladder must actually pass its rung to git fetch"

    # ۵) گاردهای fail-closed باید سرِ جایشان باشند.
    for guard in ("refusing to publish", "EMPTY tree", "MUST_EXIST"):
        assert guard in run, f"missing fail-closed guard: {guard}"


def test_every_workflow_fetch_is_bounded_and_time_capped():
    """هر `git fetch` در workflow باید هم عمقِ محدود داشته باشد و هم سقفِ زمانی.

    چرا این تست وجود دارد — با اندازه‌گیریِ واقعی روی همین مخزنِ ۳.۵۵ گیگابایتی،
    نه حدس:

      کلونِ CI (‏actions/checkout@v4) عمق ۱ دارد. مرحلهٔ انتشار خودش force-push
      است، پس کامیتی که checkout روی آن نشسته، به‌محضِ انتشارِ یک اجرای دیگر
      **از دسترس خارج** می‌شود. در آن لحظه تنها «have»ِ کلونِ shallow دیگر جزوِ
      تاریخِ نوکِ جدید نیست، سرور مبنایی برای بستهٔ کوچک ندارد و کلِ تاریخ را
      می‌فرستد. سنجشِ A/B روی همان نوکِ جابه‌جاشده:

        بدون --depth  → Enumerating 149,895 objects، دریافتِ 3.55 GiB،
                        ۹۶ ثانیه شبکه + ۲۱۴ ثانیه حلِ delta = ۳۵۲.۶ ثانیه
        با  --depth=2 → Enumerating       121 objects،            ۲.۸ ثانیه

      و این فقط نظری نیست: اجرای واقعیِ 30521888746 همین مسیر را ۲۷۰ ثانیه
      سوزاند (۹۸.۵٪ از کلِ ۲۷۴ ثانیهٔ آن مرحله).

    و چرا `timeout` **جدا** لازم است: محدودکردنِ عمق حجم را کم می‌کند ولی یک
    عملیاتِ شبکه‌ای همچنان می‌تواند «معلق» بماند. با یک شنوندهٔ بی‌پاسخ اندازه
    گرفتم: نسخهٔ بی‌سقف تا سقفِ بیرونیِ ۹۰ ثانیه معلق ماند (rc=124)، و نسخهٔ
    باسقف در ۴۵ ثانیه خودش fail-closed شد (rc=1) و شاخه دست‌نخورده ماند.
    """
    import re as _re

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    wf = os.path.join(repo, ".github", "workflows", "aggregate.yml")
    doc = yaml.safe_load(open(wf, encoding="utf-8"))
    job = doc["jobs"][list(doc["jobs"])[0]]

    fetches = []           # (step-name, logical command line)
    for step in job["steps"]:
        run = step.get("run") or ""
        # خطوطِ ادامه‌دار (\) را به یک «فرمانِ منطقی» بچسبان، وگرنه سوییچ‌هایی
        # که در خطِ بعدی آمده‌اند دیده نمی‌شوند و تست الکی سبز/سرخ می‌شود.
        logical, buf = [], ""
        for raw in run.split("\n"):
            stripped = raw.strip()
            if stripped.endswith("\\"):
                buf += stripped[:-1].rstrip() + " "
                continue
            logical.append(buf + stripped)
            buf = ""
        if buf:
            logical.append(buf)
        for cmd in logical:
            if _re.search(r"\bgit fetch\b", cmd):
                fetches.append((str(step.get("name", "?")), cmd))

    # ★ ضدِ تستِ توخالی: اگر الگو بشکند و هیچ fetchی پیدا نشود، تست باید
    #   بترکد — نه اینکه بی‌صدا سبز شود.
    assert len(fetches) >= 4, \
        f"the fetch scanner found only {len(fetches)} fetch commands — pattern broken"

    unbounded = [(n, c) for n, c in fetches if not _re.search(r"--depth[= ]", c)]
    assert not unbounded, (
        "every `git fetch` must carry an explicit --depth. Without it, a fetch "
        "into the shallow CI checkout re-downloads the ENTIRE 3.55 GiB history "
        "(measured: 149,895 objects / 352.6s) whenever the remote tip has moved."
        f" Offenders: {unbounded}"
    )

    uncapped = [(n, c) for n, c in fetches
                if not _re.search(r"\btimeout\s+\S+\s+git fetch\b", c)]
    assert not uncapped, (
        "every `git fetch` must be wrapped in `timeout`, because a half-open "
        "connection hangs forever (measured: rc=124 at a 90s outer cap). "
        f"Offenders: {uncapped}"
    )

    # هیچ fetchی نباید زیرِ `set -euo pipefail` کلِ مرحله را بکشد: یا با
    # `if ! …` گرفته می‌شود (و دور را دوباره تلاش می‌کند)، یا `|| true` دارد.
    unguarded = [(n, c) for n, c in fetches
                 if not c.lstrip().startswith("if !") and "|| true" not in c]
    assert not unguarded, (
        "a bare failing/timing-out fetch under `set -euo pipefail` kills the "
        "whole publish step and forfeits the round; guard it with `if ! …` + "
        f"retry, or `|| true`. Offenders: {unguarded}"
    )

    # سقفِ زمانیِ خودِ مرحلهٔ انتشار — قبلاً هیچ سقفی نداشت و تنها سقفِ موجود
    # سقفِ کلِ job بود؛ یعنی یک عملیاتِ گیرکرده می‌توانست مرحلهٔ purge را هم
    # قربانی کند.
    pub = [s for s in job["steps"] if "git push" in (s.get("run") or "")]
    assert len(pub) == 1
    step_cap = pub[0].get("timeout-minutes")
    assert isinstance(step_cap, int) and step_cap > 0, \
        "the publish step MUST declare its own timeout-minutes"
    job_cap = job.get("timeout-minutes")
    assert isinstance(job_cap, int) and step_cap <= job_cap, (
        f"publish step cap ({step_cap}m) must not exceed the job cap ({job_cap}m), "
        "otherwise the step ceiling is decorative"
    )


# ──────────────────────────────────────────────────────────────────────────────
# فاز D — حافظهٔ بین‌دوره‌ای
# ──────────────────────────────────────────────────────────────────────────────

def test_state_memory_never_raises_on_a_corrupt_or_missing_file():
    """حافظهٔ خراب هرگز نباید یک دورِ سالم را بشکند.

    چرا این تست هست: `state.json` در `OUTPUT_PATHS` است و با force-pushِ
    rolling squash منتشر می‌شود. یعنی می‌تواند نیم‌نوشته، از نسخهٔ دیگری از
    schema، یا دست‌کاری‌شده به دستِ خطِ لوله برسد. اگر `load_state` استثنا
    بدهد، خطِ لوله می‌شکند و **هیچ** خروجی‌ای منتشر نمی‌شود — یعنی حافظه‌ای که
    برای بهبودِ دورِ بعد اضافه شد، دورِ فعلی را نابود می‌کند. پس مسیرِ خرابی
    باید fail-open باشد، نه fail-closed.
    """
    import tempfile as _tf
    d = _tf.mkdtemp()
    p = os.path.join(d, "state.json")

    # ۱) فایل نیست — اولین دور
    st = state.load_state(p)
    assert st["sources"] == {} and st["schema"] == state.SCHEMA, st
    assert st["round"] == 0, st

    bad_inputs = [
        '',                                    # خالی
        '{"schema": 1, "sourc',                # نیم‌نوشته (force-push وسطِ نوشتن)
        'not json at all',                     # کاملاً غیرِ JSON
        '[]',                                  # نوعِ غلط در ریشه
        '{"schema":1,"sources":[]}',           # sources از نوعِ غلط
        '{"schema":99,"sources":{}}',          # schemaِ ناشناس
        '{"schema":1,"sources":{"k":"notadict"}}',
        '{"schema":1,"sources":{"k":{"url":"no-scheme-here"}}}',
        '{"schema":1,"round":-5,"sources":{}}',
    ]
    for raw in bad_inputs:
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(raw)
        st = state.load_state(p)                       # نباید استثنا بدهد
        assert isinstance(st, dict), raw
        assert st["schema"] == state.SCHEMA, raw
        assert isinstance(st["sources"], dict), raw
        assert st["sources"] == {}, (
            f"ورودیِ خرابِ {raw!r} نباید هیچ منبعی تولید کند، ولی "
            f"{len(st['sources'])} تا داد")
        assert st["round"] >= 0, raw


def test_state_history_growth_is_bounded():
    """حجمِ `state.json` نباید با شمارِ دورها رشد کند.

    چرا: انتشار force-push است و هر دور کلِ snapshot را می‌فرستد. فایلی که
    خطی رشد کند، در هزار دور مگابایتی می‌شود و هزینهٔ هر دور را بالا می‌برد —
    همان جنسِ بدهی‌ای که در اصلاحِ FETCH بسته شد.

    سنجیده‌شده: با ۲۱ منبع و ۱۰۰ دور، اوجِ حجم **۱۸.۴۵ KiB** بود و از دورِ ۲۰
    تا ۱۰۰ فقط **۲۹ بایت** (پهنایِ رقم‌ها) رشد کرد.
    """
    import tempfile as _tf
    d = _tf.mkdtemp()
    p = os.path.join(d, "state.json")
    urls = sources.all_sources()

    st = state.empty_state()
    sizes = []
    for i in range(60):
        obs = {u: {"tier": "light", "total": 1000 + i, "unique": 7 + i} for u in urls}
        st = state.record_round(st, obs, urls)
        assert state.save_state(st, p) is True
        st = state.load_state(p)
        sizes.append(os.path.getsize(p))

    for key, ent in st["sources"].items():
        assert len(ent["yield"]) <= state.MAX_HISTORY, (
            f"تاریخچهٔ yield به {len(ent['yield'])} رسید ولی سقف "
            f"{state.MAX_HISTORY} است ⇒ کرانِ رشد شکسته")
        assert len(ent["unique"]) <= state.MAX_HISTORY, len(ent["unique"])

    assert max(sizes) <= 64 * 1024, (
        f"state.json به {max(sizes)} بایت رسید؛ بودجه ۶۴ KiB است")
    # از دورِ MAX_HISTORY به بعد باید عملاً ثابت بماند (فقط پهنایِ رقم).
    tail = sizes[state.MAX_HISTORY:]
    assert max(tail) - min(tail) < 2048, (
        f"بعد از پرشدنِ تاریخچه، حجم {max(tail) - min(tail)} بایت نوسان کرد ⇒ "
        f"چیزی بی‌کران در حال رشد است")

    # حملهٔ رشد: تاریخچهٔ دست‌کاری‌شدهٔ ۱۰٬۰۰۰تایی باید بریده شود.
    k = state.source_key(urls[0])
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"schema": state.SCHEMA, "round": 5, "sources": {
            k: {"url": urls[0], "tier": "light", "rounds": 5,
                "yield": list(range(10000)), "unique": list(range(10000))}}}, fh)
    st = state.load_state(p)
    assert len(st["sources"][k]["yield"]) == state.MAX_HISTORY
    assert len(st["sources"][k]["unique"]) == state.MAX_HISTORY


def test_auto_disable_needs_evidence_and_respects_a_safety_floor():
    """auto-disable نباید بتواند خطِ لوله را از منابع خالی کند.

    چرا این تست هست: تصمیمِ «این منبع را دیگر واکشی نکن» **برگشت‌ناپذیرِ عملی**
    است (منبع دیگر شاهدِ تازه تولید نمی‌کند تا خودش را تبرئه کند). پس گاردها
    باید همگی اجرا شوند، و این تست هر کدام را **جدا‌افتاده** می‌آزماید:

      ۱. شاهدِ کافی: `rounds >= MIN_ROUNDS`
      ۲. پنجرهٔ تاریخچه هم پر باشد هم تماماً صفر
      ۳. وتوی دادهٔ امروز بر تاریخچه (تحملِ صفر)
      ٭ کفِ سراسری: تعدادِ فعال هرگز زیرِ `MIN_ACTIVE`

    ⚠️ «جدا‌افتاده» تشریفاتی نیست. نسخهٔ اولِ همین تست شرطِ ۱ را با
    `hist=[0]*3, rounds=3` می‌آزمود؛ آن‌جا شرطِ ۲ (`len(hist) < MIN_ROUNDS`) هم
    فعال بود، پس حذفِ کاملِ گاردِ شرطِ ۱ از `state.py` این تست را **نمی‌شکست**
    — آزمونِ جهشِ D-14 آن جهش را «بازمانده» گزارش کرد. هر حالت اکنون فقط یک
    گارد را نقض می‌کند تا نبودِ آن گارد قطعاً دیده شود.
    """
    def build(n, hist, rounds):
        st = state.empty_state()
        for i in range(n):
            u = f"https://example.com/s{i}.txt"
            st["sources"][state.source_key(u)] = {
                "url": u, "tier": "heavy", "rounds": rounds, "last_seen": None,
                "yield": [10] * state.MAX_HISTORY, "unique": list(hist),
                "fail": 0, "disabled_since": None, "reason": None}
        return st

    n = state.MIN_ACTIVE + 4
    all_zero = {f"https://example.com/s{i}.txt": 0 for i in range(n)}
    UNION = 8043

    # شرطِ ۱ جدا‌افتاده — پنجره پر و تماماً صفر است (پس شرطِ ۲ راضی است)، ولی
    # `rounds` کم است. تنها گاردِ فعال شرطِ ۱ است. چنین حافظه‌ای خیالی نیست:
    # `state.json` از مسیرِ force-push می‌آید و دست‌کاری‌پذیر است.
    st = build(n, [0] * state.MIN_ROUNDS, rounds=3)
    assert state.disable_candidates(st, all_zero, UNION) == {}, (
        f"منبعی با rounds=3 (< MIN_ROUNDS={state.MIN_ROUNDS}) غیرفعال شد، "
        f"هرچند پنجرهٔ تاریخچه‌اش پر بود ⇒ گاردِ «شاهدِ کافی» وجود ندارد و "
        f"حافظه‌ای دست‌کاری‌شده می‌تواند منبعِ سالم را حذف کند")

    # شرطِ ۲ جدا‌افتاده (الف) — پنجره کوتاه است ولی `rounds` بالاست
    st = build(n, [0] * 3, rounds=state.MIN_ROUNDS + 5)
    assert state.disable_candidates(st, all_zero, UNION) == {}, (
        f"منبعی با تاریخچهٔ ۳تایی (< MIN_ROUNDS={state.MIN_ROUNDS}) غیرفعال شد "
        f"⇒ گاردِ «پنجره باید پر باشد» وجود ندارد")

    # شرطِ ۲ جدا‌افتاده (ب) — یک مقدارِ ناصفر در پنجره ⇒ هیچ تصمیمی
    hist = [0] * state.MAX_HISTORY
    hist[-2] = 5
    st = build(n, hist, rounds=state.MIN_ROUNDS + 5)
    assert state.disable_candidates(st, all_zero, UNION) == {}, (
        "منبعی که در پنجرهٔ تاریخچه یک دور بازدهِ یکتا داشت غیرفعال شد")

    # حالتِ مثبت — واقعاً باید گرفته شود
    st = build(n, [0] * state.MAX_HISTORY, rounds=state.MIN_ROUNDS + 5)
    cand = state.disable_candidates(st, all_zero, UNION)
    assert cand, "منبعِ واقعاً افزونه گرفته نشد ⇒ تست پوچ است"
    budget = n - state.MIN_ACTIVE
    assert len(cand) == budget, (
        f"باید حداکثر {budget} تا (n={n} − کفِ {state.MIN_ACTIVE}) نامزد شود، "
        f"ولی {len(cand)} تا شد")

    # شرطِ ۴ — روی کف، هیچ تصمیمی
    st = build(state.MIN_ACTIVE, [0] * state.MAX_HISTORY, rounds=state.MIN_ROUNDS + 5)
    on_floor = {f"https://example.com/s{i}.txt": 0 for i in range(state.MIN_ACTIVE)}
    assert state.disable_candidates(st, on_floor, UNION) == {}, (
        f"با {state.MIN_ACTIVE} منبعِ فعال (== کف) بازهم غیرفعال‌سازی پیشنهاد "
        f"شد ⇒ خطِ لوله می‌تواند از منابع خالی شود")

    # شرطِ ۳ — وتوی امروز بر تاریخچه
    st = build(n, [0] * state.MAX_HISTORY, rounds=state.MIN_ROUNDS + 5)
    today = dict(all_zero)
    today["https://example.com/s0.txt"] = 90         # سهمِ چشمگیر
    today["https://example.com/s1.txt"] = 1          # ناچیز، ولی ناصفر
    cand = state.disable_candidates(st, today, UNION)
    assert "https://example.com/s0.txt" not in cand, (
        "منبعی که امروز بیش از سهمِ وتو کانفیگِ یکتا داد غیرفعال شد ⇒ دادهٔ "
        "تازه حقِ وتو بر تاریخچه ندارد")
    assert "https://example.com/s1.txt" not in cand, (
        "منبعی که امروز کانفیگِ یکتا داشت غیرفعال شد")
    for u in cand:
        assert today[u] == 0, f"{u} امروز {today[u]} یکتا داشت ولی غیرفعال شد"

    # علامت‌زدن باید idempotent باشد و کف را نگه دارد
    st = build(n, [0] * state.MAX_HISTORY, rounds=state.MIN_ROUNDS + 5)
    st = state.mark_disabled(st, state.disable_candidates(st, all_zero, UNION))
    assert len(state.disabled_urls(st)) == budget
    assert state.disable_candidates(st, all_zero, UNION) == {}, (
        "بعد از رسیدن به کف، دورِ بعد بازهم غیرفعال‌سازی پیشنهاد شد")


def test_unique_yield_detects_a_strict_subset_source():
    """معیارِ درست «بازدهِ یکتا» است، نه «تعدادِ کانفیگ» و نه «HTTP 200».

    چرا: قاعدهٔ نگهداریِ `sources.py` می‌گوید منبعِ صفر باید حذف شود، ولی
    معیارش زنده‌بودن است. اندازه‌گیریِ زندهٔ ۳۰ جولای ۲۰۲۶:
    `mahdibland/Eternity.txt` با ۱۹۸ کانفیگ و `status: ok`، زیرمجموعهٔ محضِ
    **۱۰۰.۰۰٪** از `mahdibland/sub/sub_merge.txt` است. با معیارِ «کانفیگ»
    نامرئی است؛ با معیارِ «یکتا» صفر می‌شود. این تست همان رابطه را می‌سازد و
    اطمینان می‌دهد تشخیص کار می‌کند.
    """
    big = [f"trojan://pw{i}@h{i}.example.com:443?sni=a#n{i}" for i in range(40)]
    subset = big[:12]                        # زیرمجموعهٔ محض
    own = [f"trojan://pw{i}@g{i}.example.net:8443?sni=b#m{i}" for i in range(6)]

    per = {"https://s/big.txt": big,
           "https://s/subset.txt": subset,
           "https://s/own.txt": own}
    totals, uniq, union = aggregate.unique_yield(per)

    assert totals["https://s/subset.txt"] == 12, totals
    assert uniq["https://s/subset.txt"] == 0, (
        f"زیرمجموعهٔ محض باید ۰ یکتا بدهد ولی {uniq['https://s/subset.txt']} داد "
        f"⇒ تشخیصِ افزونگی کار نمی‌کند")
    assert uniq["https://s/big.txt"] == 40 - 12, uniq
    assert uniq["https://s/own.txt"] == 6, uniq
    assert union == 40 + 6, union

    # ضدِ پوچی: منبعی با محتوای کاملاً اختصاصی باید ۱۰۰٪ یکتا بدهد
    solo = {"https://s/only.txt": own}
    _, u2, un2 = aggregate.unique_yield(solo)
    assert u2["https://s/only.txt"] == 6 and un2 == 6, (u2, un2)


def test_state_json_is_published_and_never_gates_the_round():
    """`state.json` باید در `OUTPUT_PATHS` باشد ولی در `MUST_EXIST` نباشد.

    دو خطای متقارن که این تست هر دو را می‌بندد:

      • **اگر در `OUTPUT_PATHS` نباشد:** درختِ snapshot از `$ANCHOR` + همان
        مسیرها ساخته می‌شود، پس `state.json` هر دور از snapshot بیرون می‌افتد و
        حافظه **بی‌صدا** صفر می‌شود — بدترین نوعِ باگ در این پروژه: خاموش.
      • **اگر در `MUST_EXIST` باشد:** در اولین دور فایل وجود ندارد، پس دروازهٔ
        fail-closed انتشار را رد می‌کند و مخزن هرگز به‌روز نمی‌شود.
    """
    wf = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      ".github", "workflows", "aggregate.yml")
    doc = yaml.safe_load(open(wf, encoding="utf-8"))
    steps = doc["jobs"]["aggregate"]["steps"]
    pub = [s for s in steps if "git push" in (s.get("run") or "")]
    assert len(pub) == 1, f"مرحلهٔ انتشار {len(pub)} تا پیدا شد، انتظار ۱"
    run = pub[0]["run"]

    import re as _re
    m = _re.search(r'OUTPUT_PATHS="([^"]+)"', run)
    assert m, "OUTPUT_PATHS در مرحلهٔ انتشار پیدا نشد ⇒ الگوی تست شکسته"
    paths = m.group(1).split()
    assert state.STATE_PATH in paths, (
        f"«{state.STATE_PATH}» در OUTPUT_PATHS نیست ({paths}) ⇒ rolling squash "
        f"هر دور حافظه را دور می‌ریزد و auto-disable هرگز به MIN_ROUNDS نمی‌رسد")

    # باید از دروازهٔ is_output_path() هم عبور کند، وگرنه REGRESS آن را
    # «تغییرِ سورس» می‌بیند.
    case = _re.search(r"is_output_path\(\)\s*\{(.+?)\n\s*\}", run, _re.S)
    assert case, "تابعِ is_output_path پیدا نشد ⇒ الگوی تست شکسته"
    assert state.STATE_PATH in case.group(1), (
        f"«{state.STATE_PATH}» در is_output_path() نیست ⇒ به‌عنوان فایلِ سورس "
        f"دیده می‌شود و منطقِ REGRESS را گمراه می‌کند")

    me = _re.search(r'MUST_EXIST="([^"]+)"', run, _re.S)
    assert me, "MUST_EXIST پیدا نشد ⇒ الگوی تست شکسته"
    assert state.STATE_PATH not in me.group(1).split(), (
        f"«{state.STATE_PATH}» در MUST_EXIST است ⇒ اولین دور (که فایل وجود "
        f"ندارد) fail-closed می‌شود و انتشار هرگز رخ نمی‌دهد")


def test_source_docstring_count_matches_the_actual_list():
    """عددِ منابع در docstringِ `sources.py` باید با خودِ لیست بخواند.

    چرا این تستِ به‌ظاهر بی‌اهمیت لازم است: قاعدهٔ نگهداریِ آن فایل **دستی**
    است و از قبل دریفت کرده بود — docstring می‌گفت «۱۸ منبع» در حالی که
    `LIGHT(7) + HEAVY(14) = 21` بود. یعنی مستنداتِ همان قاعده‌ای که قرار بود
    منابعِ مرده را حذف کند، خودش ۳ منبع عقب افتاده بود. این تست دریفت را
    غیرممکن می‌کند.
    """
    import re as _re
    doc = sources.__doc__ or ""
    fa = "۰۱۲۳۴۵۶۷۸۹"
    m = _re.search(r"هر ([۰-۹]+) منبع", doc)
    assert m, "جملهٔ «هر N منبع» در docstringِ sources.py پیدا نشد"
    claimed = int("".join(str(fa.index(ch)) for ch in m.group(1)))
    actual = len(sources.all_sources())
    assert claimed == actual, (
        f"docstring می‌گوید {claimed} منبع ولی لیست {actual} تا دارد ⇒ همان "
        f"دریفتی که فاز D بستنش را لازم دانست، برگشته")
    assert actual == len(sources.LIGHT_SOURCES) + len(sources.HEAVY_SOURCES), (
        "all_sources() تعدادِ متفاوتی داد ⇒ URLِ تکراری در لیست هست")


def test_remark_tag_is_content_derived_not_positional():
    """برچسبِ انتهایِ remark باید تابعِ محتوا باشد، نه موقعیت.

    باگِ واقعیِ اندازه‌گیری‌شده: برچسب قبلاً شمارندهٔ موقعیتی بود، پس
    اضافه‌شدنِ **یک** کانفیگ در ابتدای لیست، remarkِ همهٔ خطوطِ بعدی را
    جابه‌جا می‌کرد. نتیجه: دو کامیتِ پشت‌سرهمِ ربات از ۳۵۳۷ خط فقط ۹ خط
    مشترک داشتند (با نادیده‌گرفتنِ remark: ۳۲۷۷) ⇒ delta compressionِ گیت
    بی‌اثر می‌شد و تاریخ ۶۰۴ کیلوبایت در هر دور رشد می‌کرد.
    """
    line = "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=tcp"

    # همان کانفیگ، در دو موقعیتِ مختلف ⇒ باید برچسبِ یکسان بگیرد
    a = core.brand_remark(line, 1)
    b = core.brand_remark(line, 9999)
    assert a == b, f"remark is positional:\n  idx=1    {a}\n  idx=9999 {b}"

    # و برچسب باید از dedup_key مشتق شده باشد (پایدار و تکرارپذیر)
    tag = core.stable_label(line)
    assert tag in a, f"the stable tag {tag!r} is not in the remark {a!r}"
    assert core.stable_label(line) == tag, "stable_label is not deterministic"
    # طولِ ثابت و hex بزرگ
    assert len(tag) == 6 and tag.upper() == tag, tag


def test_country_label_is_locked_to_the_endpoint_not_the_source_remark():
    """برچسبِ کشور باید به endpoint گره بخورد، نه به remarkِ سورس.

    باگِ واقعیِ اندازه‌گیری‌شده: کشور فقط از remarkِ همان سورس خوانده می‌شد.
    یک سرورِ واحد که در دو سورس با remarkِ متفاوت آمده بود، در یک دور
    `RU 🇷🇺` و در دورِ بعد `US 🇺🇸` می‌شد — بسته به اینکه کدام سورس اول
    fetch شده. این «چرخشِ برچسب» یکی از سه ریشهٔ رشدِ تاریخ بود.
    """
    core.reset_country_cache()

    body = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@5.6.7.8:443?type=tcp"
    # اولین تشخیصِ قاطع باید قفل شود
    first  = core.brand_remark(body + "#RU Moscow")
    second = core.brand_remark(body + "#US New York")
    assert first == second, (
        "the country label flips with the source remark:\n"
        f"  first : {first}\n  second: {second}")

    # endpoint_of باید مقصد را درست بیرون بکشد
    assert core.endpoint_of(body) == "5.6.7.8"
    assert core.endpoint_of("trojan://p@example.com:443#x") == "example.com"
    assert core.endpoint_of("vless://u@[2001:db8::1]:443?type=tcp") == "2001:db8::1"

    # reset باید واقعاً پاک کند (وگرنه تست‌های بعدی به هم می‌ریزند): بعد از
    # پاک‌سازی، همان ورودی باید همان خروجیِ قبلی را بدهد — نه چیزِ دیگری.
    #
    # پیش از این، این بخش انتظارِ «US» داشت، چون تنها منبعِ برچسب متنِ ریمارک
    # بود و ریمارکِ ساختگیِ «US New York» همان را تحمیل می‌کرد. اکنون برچسب از
    # مکانِ واقعیِ شبکه می‌آید و 5.6.7.8 در پایگاهِ دادهٔ GeoIP آلمان است، پس
    # ادعای نادرستِ ریمارک بازنویسی می‌شود. آن انتظارِ قدیمی رفتارِ باگ‌دار را
    # تثبیت می‌کرد؛ خاصیتی که واقعاً باید ثابت بماند این است که برچسب به
    # *مقصد* گره خورده باشد و بینِ فراخوانی‌ها عوض نشود.
    core.reset_country_cache()
    third = core.brand_remark(body + "#US New York")
    assert third == first, (
        "after reset_country_cache() the same endpoint produced a different label:\n"
        f"  before reset: {first}\n  after  reset: {third}")
    core.reset_country_cache()
    fourth = core.brand_remark(body + "#CN Beijing")
    assert fourth == first, (
        "a different source remark changed the label for the same endpoint:\n"
        f"  with 'RU Moscow' : {first}\n  with 'CN Beijing': {fourth}")
    core.reset_country_cache()


def test_output_order_is_deterministic():
    """ترتیبِ خطوطِ خروجی باید قطعی باشد.

    اگر ترتیب به ترتیبِ رسیدنِ سورس‌ها وابسته باشد، فایل در هر دور
    جابه‌جا می‌شود و git هیچ deltaیی پیدا نمی‌کند — حتی اگر محتوا یکی باشد.
    """
    import aggregate

    lines = [
        "vless://cccccccc-cccc-cccc-cccc-cccccccccccc@3.3.3.3:443?type=tcp",
        "vless://aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa@1.1.1.1:443?type=tcp",
        "vless://bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb@2.2.2.2:443?type=tcp",
    ]
    core.reset_country_cache()
    r1 = aggregate.process_category({"u": lines}, ["u"])
    core.reset_country_cache()
    r2 = aggregate.process_category({"u": list(reversed(lines))}, ["u"])
    assert r1.unique == r2.unique, (
        "output order depends on input order:\n"
        f"  {r1.unique}\n  {r2.unique}")

    # و باید واقعاً «مرتب» باشد، نه فقط «یکسان»: کلیدِ یکتاسازی صعودی
    keys = [core.dedup_key(ln) or ln for ln in r1.unique]
    assert keys == sorted(keys), \
        f"output is stable but not sorted by dedup_key: {keys}"
    core.reset_country_cache()


def test_index_advertises_the_publish_branch_key():
    """index.json باید شاخهٔ انتشار را با نامِ جدید و قدیمی اعلام کند."""
    import aggregate

    r = aggregate.CategoryResult()
    r.unique = ["vless://x@1.2.3.4:443#a"]
    results = {c: r for c in ("all", "heavy", "light")}
    idx = aggregate.build_index(results, {"vless": 1}, 1.0)

    assert idx.get("publish_branch") == aggregate.GH_BRANCH, \
        "index.json must advertise publish_branch"
    # کلیدِ قدیمی برای مصرف‌کننده‌های موجود حفظ می‌شود
    assert idx.get("data_branch") == aggregate.GH_BRANCH, \
        "the legacy data_branch key must still be present and aliased"
    # نکتهٔ اندازه‌گیری‌شده: `primary_base` بدونِ اسلشِ انتهایی ساخته می‌شود
    #   (".../Free-v2ray-Configs/main")، پس الگوی "/main/" در آن پیدا نمی‌شود.
    #   assert را به همان شکلی می‌نویسیم که کد واقعاً تولید می‌کند.
    assert idx["primary_base"].endswith(f"/{aggregate.GH_BRANCH}"), \
        idx["primary_base"]
    assert f"/{aggregate.GH_BRANCH}/" in idx["self_url"], idx["self_url"]


def test_no_tracked_file_advertises_a_retired_branch():
    """T13 — هیچ فایلِ مخزن نباید URLِ محتوایی روی شاخه‌ای غیر از شاخهٔ انتشار بدهد.

    باگِ واقعیِ کشف‌شده و اندازه‌گیری‌شده: خروجی‌ها یک بار به شاخهٔ orphanِ `data`
    منتقل شدند و README به مدتِ **۸ ساعت و ۲۱ دقیقه و ۲۹ ثانیه**
    (کامیت `1c85af3` در 2026-07-28T22:33:08Z تا `d5a31d8` در 2026-07-29T06:54:37Z)
    نُه لینکِ `…/data/…` را تبلیغ کرد. آن شاخه در 2026-07-30 بازنشسته شد، پس هر
    لینکِ جامانده حالا یک ۴۰۴ است.

    تستِ قبلی (`test_docs_advertise_the_default_branch_only`) فقط دو README را
    می‌خواند. این تست عمداً **کلِ درختِ ردگیری‌شده** را می‌خواند، چون آن دفعه
    نشتی نه‌فقط در README بود: `index.json` هم `raw_base`/`self_url` را روی شاخهٔ
    اشتباه منتشر می‌کرد و مصرف‌کنندهٔ ماشینی از همان فایل ۵۶ لینکِ دیگر را کشف
    می‌کرد.

    نکتهٔ اندازه‌گیری‌شده: فقط دو هاستِ *محتوا* سنجیده می‌شوند
    (`raw.githubusercontent.com` و `cdn.jsdelivr.net`). نشانِ وضعیتِ
    `github.com/<owner>/<repo>/actions/...` در سطرِ ۳ هر دو README عمداً مطابقت
    نمی‌کند، چون آن URL محتوای اشتراک نیست و شاخه‌ای در مسیرش ندارد.
    """
    import re as _re
    import subprocess as _sp
    import aggregate

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    owner, name, branch = aggregate.GH_USER, aggregate.GH_REPO, aggregate.GH_BRANCH

    # فهرستِ فایل‌ها از خودِ گیت گرفته می‌شود تا فایل‌های موقتِ محلی
    # (که در چک‌اوتِ CI وجود ندارند) مثبتِ کاذب نسازند. اگر گیت نبود،
    # به پیمایشِ فایل‌سیستم برمی‌گردیم — تست نباید به گیت وابسته باشد.
    try:
        out = _sp.run(["git", "-C", repo, "ls-files", "-z"],
                      capture_output=True, check=True).stdout
        files = [f.decode("utf-8") for f in out.split(b"\0") if f]
    except Exception:
        files = []
        for root, dirs, names in os.walk(repo):
            dirs[:] = [d for d in dirs if d not in (".git", ".wrangler", "node_modules")]
            for n in names:
                files.append(os.path.relpath(os.path.join(root, n), repo))
    assert len(files) >= 20, f"suspiciously few files to scan: {len(files)}"

    pats = (
        _re.compile(_re.escape(f"raw.githubusercontent.com/{owner}/{name}/")
                    + r"([A-Za-z0-9_.\-]+)"),
        _re.compile(_re.escape(f"cdn.jsdelivr.net/gh/{owner}/{name}@")
                    + r"([A-Za-z0-9_.\-]+)"),
    )

    seen = 0
    offenders = []
    for rel in files:
        path = os.path.join(repo, rel)
        if not os.path.isfile(path):
            continue
        try:
            txt = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for pat in pats:
            for m in pat.finditer(txt):
                seen += 1
                if m.group(1) != branch:
                    offenders.append(f"{rel}: {m.group(0)}")

    assert not offenders, (
        f"{len(offenders)} content URL(s) still pinned to a retired branch "
        f"(publish branch is {branch!r}):\n  " + "\n  ".join(offenders[:20]))
    # ★ تستِ توخالی ممنوع: اگر الگو هیچ‌چیز پیدا نکند، assertِ بالا هم بی‌معنی است.
    assert seen >= 40, \
        f"the scanner matched only {seen} content URLs — the pattern is broken"


# ──────────────────────────────────────────────────────────────────────────────
# C3/C4/C12/C13 — حذفِ حدسِ دوحرفی و مرزِ واژه در کلیدواژه‌ها
#
# باگِ واقعی: مرحلهٔ سومِ تشخیصِ کشور هر واژهٔ دوحرفیِ لاتین را کدِ کشور فرض
# می‌کرد. نمونه‌های زیر همه از دادهٔ زندهٔ همین مخزن بیرون آمده‌اند.
# ──────────────────────────────────────────────────────────────────────────────

def test_gigabyte_unit_is_not_mistaken_for_great_britain():
    """C12 — «55.26 GB» یکای حجم است، نه بریتانیا.

    ریمارکِ واقعیِ منبعِ چینی: «剩余流量：55.26 GB». روشِ قدیمی GB برمی‌گرداند.
    """
    code, _flag = core.detect_country_from_remark("剩余流量：55.26 GB")
    assert code == "Global", f"expected Global, got {code}"


def test_english_word_us_is_not_mistaken_for_united_states():
    """C13 — «join-us-on-Telegram» یک دعوت است، نه ایالاتِ متحده.

    نکتهٔ سنجیده‌شده: «us» هرگز کلیدواژه نبود؛ فقط از راهِ حلقهٔ حدسِ دوحرفی
    برچسب می‌گرفت. پس حذفِ آن حلقه باید این مورد را کاملاً خاموش کند.
    """
    for remark in ("join-us-on-Telegram", "contact us", "trust us", "us server"):
        code, _flag = core.detect_country_from_remark(remark)
        assert code == "Global", f"{remark!r} → {code}"


def test_speed_and_negation_words_are_not_country_codes():
    """«NO limit» نروژ نیست، «my node» مالزی نیست، «Best CH speed» سوئیس نیست."""
    cases = {
        "Speed 20 mb/s NO limit": "Global",
        "my node": "Global",
        "Best CH speed": "Global",
    }
    for remark, expected in cases.items():
        code, _flag = core.detect_country_from_remark(remark)
        assert code == expected, f"{remark!r} → {code}, expected {expected}"


def test_unicode_flag_in_remark_is_still_honoured():
    """حذفِ حدس نباید مرحلهٔ پرچم را خراب کند — پرچم ادعای صریح است."""
    code, flag = core.detect_country_from_remark("🇩🇪 Frankfurt node")
    assert code == "DE", code
    assert flag == "🇩🇪", flag


def test_keyword_stage_requires_a_word_boundary():
    """C4 — کلیدواژهٔ کوتاه نباید داخلِ واژهٔ دیگر بیفتد."""
    # «uk» یک کلیدواژهٔ کوتاه است؛ داخلِ «Sukuma» نباید بگیرد
    assert core.detect_country_from_remark("Sukuma fast")[0] == "Global"
    # ولی به‌صورتِ واژهٔ مستقل باید بگیرد
    assert core.detect_country_from_remark("UK | London")[0] == "GB"


# ──────────────────────────────────────────────────────────────────────────────
# C5/C14 — اولویتِ GeoIP بر متنِ ریمارک
# ──────────────────────────────────────────────────────────────────────────────

def test_geoip_overrides_a_wrong_flag_in_the_remark():
    """C14 — اگر منبع پرچمِ غلط بدهد، مکانِ واقعیِ شبکه باید برنده شود.

    ۵.۶.۷.۸ در پایگاهِ دادهٔ GeoIP آلمان است. ریمارک می‌گوید آمریکا. برچسبِ
    نهایی باید DE باشد. اگر پایگاهِ داده در دسترس نباشد تست رد نمی‌شود، چون
    آن‌وقت رفتارِ درست همان تکیه بر ریمارک است.
    """
    try:
        import geo
    except Exception:
        return
    if not geo.database_available():
        return
    core.reset_country_cache()
    code, _flag = core.country_for_endpoint("5.6.7.8", "US 🇺🇸 New York")
    assert code == "DE", f"GeoIP must win over the remark; got {code}"
    core.reset_country_cache()


def test_country_label_is_stable_for_the_same_endpoint():
    """پایداری: یک مقصد، همیشه یک برچسب — مستقل از ریمارکِ منبع."""
    try:
        import geo
    except Exception:
        return
    if not geo.database_available():
        return
    core.reset_country_cache()
    a = core.country_for_endpoint("8.8.8.8", "RU Moscow")
    core.reset_country_cache()
    b = core.country_for_endpoint("8.8.8.8", "CN Beijing")
    core.reset_country_cache()
    c = core.country_for_endpoint("8.8.8.8", "")
    core.reset_country_cache()
    assert a == b == c, f"unstable label: {a} / {b} / {c}"


# ──────────────────────────────────────────────────────────────────────────────
# پایداریِ DNS — رأی‌گیری روی *مجموعهٔ* رکوردهای A
#
# باگِ واقعیِ اندازه‌گیری‌شده: gethostbyname یکی از چند نشانیِ round-robin را
# برمی‌گرداند و انتخابش عوض می‌شود، پس ۲٫۲۲٪ از میزبان‌ها در اجرای دوم کشورِ
# دیگری می‌گرفتند. راهکار: مجموعهٔ کاملِ رکوردها + رأی‌گیریِ اکثریت.
# ──────────────────────────────────────────────────────────────────────────────

def test_country_of_addrs_is_independent_of_response_order():
    """برچسب باید تابعِ *مجموعه* باشد، نه ترتیبِ پاسخِ DNS."""
    try:
        import geo
    except Exception:
        return
    if not geo.database_available():
        return
    addrs = ["8.8.8.8", "1.1.1.1", "5.6.7.8"]
    first = geo.country_of_addrs(addrs)
    for perm in ([addrs[2], addrs[0], addrs[1]],
                 [addrs[1], addrs[2], addrs[0]],
                 list(reversed(addrs))):
        assert geo.country_of_addrs(perm) == first, \
            f"order changed the result: {perm} → {geo.country_of_addrs(perm)} != {first}"


def test_country_of_addrs_breaks_ties_deterministically():
    """در تساویِ آرا، کوچک‌ترین IP (ترتیبِ الفبایی) تصمیم می‌گیرد.

    بدونِ قاعدهٔ صریحِ تساوی، نتیجه به ترتیبِ پیمایشِ dict وابسته می‌شد و
    همان ناپایداری از راهِ دیگری برمی‌گشت.
    """
    try:
        import geo
    except Exception:
        return
    if not geo.database_available():
        return
    # یک آمریکایی و یک آلمانی: تساویِ ۱-۱
    pair = ["8.8.8.8", "5.6.7.8"]
    expected = geo.country_of_addrs(pair)
    for _ in range(5):
        assert geo.country_of_addrs(list(reversed(pair))) == expected


def test_ip_literals_need_no_dns_and_are_detected():
    """۷۳٪ از میزبان‌ها IP خام‌اند؛ تشخیصِ آن‌ها نباید به شبکه دست بزند."""
    try:
        import geo
    except Exception:
        return
    assert geo.is_ip_literal("8.8.8.8")
    assert geo.is_ip_literal("2606:4700:4700::1111")
    assert not geo.is_ip_literal("example.com")
    assert not geo.is_ip_literal("")
    # برای IP خام، resolve_all باید همان را برگرداند و DNS نزند
    assert geo.resolve_all("8.8.8.8") == ("8.8.8.8",)


def test_flag_is_computed_from_iso_code_not_a_hardcoded_map():
    """پرچم با حسابِ نشانگرهای منطقه‌ای ساخته می‌شود، پس هیچ کشوری جا نمی‌افتد.

    نقشهٔ سختِ قدیمی ۵۶ کشور داشت و GeoIP روی دادهٔ زنده ۸۴ کشور پیدا کرد؛
    یعنی ۳۲ کشور اصلاً قابلِ بیان نبودند.
    """
    try:
        import geo
    except Exception:
        return
    assert geo.flag_of("DE") == "🇩🇪"
    assert geo.flag_of("IR") == "🇮🇷"
    # کشورهایی که در نقشهٔ سختِ قدیمی نبودند
    assert geo.flag_of("CY") == "🇨🇾"
    assert geo.flag_of("MT") == "🇲🇹"
    assert geo.flag_of("KZ") == "🇰🇿"
    # ورودیِ نامعتبر باید به کرهٔ زمین بیفتد، نه استثنا بدهد
    assert geo.flag_of("") == "🌐"
    assert geo.flag_of("XYZ") == "🌐"
    assert geo.flag_of("1A") == "🌐"


def test_geo_degrades_gracefully_without_a_database():
    """نبودِ پایگاهِ داده نباید هیچ استثنایی بدهد — فقط برچسبِ ضعیف‌تر."""
    import importlib
    import geo as _geo
    saved = os.environ.get("GEOIP_MMDB")
    os.environ["GEOIP_MMDB"] = "/nonexistent/definitely-absent.mmdb"
    try:
        fresh = importlib.reload(_geo)
        assert fresh.database_available() is False
        assert fresh.country_of_ip("8.8.8.8") is None
        assert fresh.country_for_host("8.8.8.8") is None
        assert fresh.stats()["db_loaded"] == 0
    finally:
        if saved is None:
            os.environ.pop("GEOIP_MMDB", None)
        else:
            os.environ["GEOIP_MMDB"] = saved
        importlib.reload(_geo)


def test_geo_stats_schema_is_stable():
    """کلیدهای گزارش باید همیشه حاضر باشند، وگرنه «صفر» با «نبود» قاطی می‌شود."""
    try:
        import geo
    except Exception:
        return
    s = geo.stats()
    for key in ("db_loaded", "by_ip_literal", "unknown_ip_literal", "by_dns",
                "dns_failed", "unknown_after_dns", "skipped_no_db",
                "hosts_resolved", "hosts_unknown"):
        assert key in s, f"missing stats key: {key}"
        assert isinstance(s[key], int), f"{key} must be int, got {type(s[key])}"


def test_geo_warm_up_never_double_counts_across_categories():
    """باگِ واقعیِ کشف‌شده در اجرای کاملِ خط‌لوله.

    `warm_up` سه بار صدا زده می‌شود (all / heavy / light). پیش از اصلاح، تنها
    *موفقیت‌ها* کش می‌شدند، پس هر میزبانِ ناموفق در هر سه دور از نو DNS می‌خورد و
    از نو شمرده می‌شد. عددِ منتشرشده در health.json چنین بود:

        dns_failed = ۹۲۴   در حالی که کلِ میزبانِ نامی ۱٬۳۷۵ است

    اندازه‌گیریِ دوریِ همان ورودی، بیش‌شماری را لو داد:
        دورِ ۱ → dns_failed=۲۲۷ ، دورِ ۲ → ۴۵۴ (‎+۲۲۷ تکراری) با by_dns بی‌تغییر

    این آزمون هم *بی‌هزینه بودنِ* دورِ دوم را می‌پاید و هم *ترازِ دقیقِ* آمار را،
    چون گزارشِ غلط بی‌آنکه خطایی بدهد، دروغ می‌گوید.
    """
    try:
        import geo
    except Exception:
        return
    geo.reset()

    calls = {"n": 0}
    real_resolve = geo.resolve_all

    # میزبان‌های ساختگی: یکی همیشه حل می‌شود، یکی هرگز. بی‌نیاز از شبکهٔ واقعی.
    def fake_resolve(host):
        calls["n"] += 1
        return ("8.8.8.8",) if host == "good.example" else ()

    geo.resolve_all = fake_resolve  # type: ignore
    try:
        hosts = ["good.example", "bad.example", "1.1.1.1"]
        geo.warm_up(hosts)
        s1 = geo.stats()
        first_calls = calls["n"]

        geo.warm_up(hosts)          # دورِ heavy
        geo.warm_up(hosts)          # دورِ light
        s3 = geo.stats()

        assert s3 == s1, f"repeat warm_up must be free; {s1} -> {s3}"
        assert calls["n"] == first_calls, (
            f"a failed host must not be re-resolved: {first_calls} -> {calls['n']}"
        )
        # ترازِ دقیق: هر میزبان دقیقاً یک بار در یکی از سبدها
        assert s3["hosts_resolved"] + s3["hosts_unknown"] == len(hosts), s3
    finally:
        geo.resolve_all = real_resolve  # type: ignore
        geo.reset()


# ──────────────────────────────────────────────────────────────────────────────
# C8/C9 — پروتکل‌های hysteria2 و tuic
#
# باگِ واقعی: ۸۰ کانفیگِ hysteria2 و ۱ کانفیگِ tuic در هر اجرا **صددرصد** حذف
# می‌شدند، بی‌هیچ پیامی. شمارشِ زنده: hysteria2:// = ۷۷ و hy2:// = ۳.
# ──────────────────────────────────────────────────────────────────────────────

_HY2 = "hysteria2://pass123@1.2.3.4:443?sni=example.com#HY2 node"
_HY2_ALT = "hy2://pass123@1.2.3.5:8443?insecure=1&obfs=salamander&obfs-password=xyz#HY2 alt"
_TUIC = ("tuic://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:secret@1.2.3.6:443"
         "?congestion_control=bbr&udp_relay_mode=quic&alpn=h3&sni=example.org#TUIC node")


def _sb_proxy(line: str) -> dict:
    """تنها outboundِ *پروکسیِ* سندِ sing-box را برمی‌گرداند.

    اندیس‌گذاریِ موقعیتی (`outbounds[0]`) در اینجا اشتباه است: سندِ خروجی همیشه
    با گروه‌ها آغاز می‌شود و با `direct` پایان می‌یابد. ترتیبِ واقعیِ سنجیده‌شده:

        ۰ selector «🚀 @Raydikalx»  ۱ urltest «♻️ Auto»  ۲ خودِ پروکسی  ۳ direct

    پس گزینش باید بر اساسِ *نوع* باشد نه جایگاه، وگرنه آزمون به‌جای پروکسی به
    selector نگاه می‌کند و با `KeyError` می‌ترکد — که خطای آزمون است نه کد.
    """
    doc = json.loads(converters.build_singbox_json([line]))
    groups = {"selector", "urltest", "direct", "block", "dns"}
    hits = [o for o in doc["outbounds"] if o.get("type") not in groups]
    assert len(hits) == 1, f"expected exactly one proxy outbound, got {hits}"
    return hits[0]


def test_hysteria2_is_accepted_under_both_schemes():
    """هر دو طرحِ نام باید پارس شوند؛ پذیرشِ یکی، ۳ کانفیگ را بی‌صدا می‌انداخت."""
    for line in (_HY2, _HY2_ALT):
        p = converters.parse_proxy(line)
        assert p is not None, f"failed to parse: {line}"
        assert p["type"] == "hysteria2", p["type"]


def test_tuic_is_parsed_with_uuid_and_password():
    p = converters.parse_proxy(_TUIC)
    assert p is not None, "tuic must parse"
    assert p["type"] == "tuic", p["type"]
    assert p["uuid"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", p["uuid"]
    assert p["password"] == "secret", p["password"]
    assert p["congestion_control"] == "bbr", p["congestion_control"]


def test_hysteria2_and_tuic_reach_the_clash_output():
    """پارس شدن کافی نیست — باید در فایلِ نهایی هم ظاهر شوند."""
    doc = yaml.safe_load(converters.build_clash_yaml([_HY2, _HY2_ALT, _TUIC]))
    types = [p["type"] for p in doc["proxies"]]
    assert types.count("hysteria2") == 2, types
    assert types.count("tuic") == 1, types


def test_hysteria2_and_tuic_reach_the_singbox_output():
    doc = json.loads(converters.build_singbox_json([_HY2, _HY2_ALT, _TUIC]))
    types = [o["type"] for o in doc["outbounds"] if o.get("type") in ("hysteria2", "tuic")]
    assert types.count("hysteria2") == 2, types
    assert types.count("tuic") == 1, types


def test_clash_uses_hyphenated_keys_and_singbox_uses_nested_objects():
    """شمای دو کلاینت *واقعاً* متفاوت است — با باینریِ اصلی سنجیده شد.

    mihomo: `obfs` / `obfs-password` / `skip-cert-verify` / `congestion-controller`
    sing-box: `obfs: {type, password}` و `tls: {enabled, server_name, insecure}`
    """
    cl = yaml.safe_load(converters.build_clash_yaml([_HY2_ALT]))["proxies"][0]
    assert cl["obfs"] == "salamander", cl
    assert cl["obfs-password"] == "xyz", cl
    assert cl["skip-cert-verify"] is True, cl

    sb = _sb_proxy(_HY2_ALT)
    assert isinstance(sb["obfs"], dict), sb["obfs"]
    assert sb["obfs"]["type"] == "salamander", sb["obfs"]
    assert sb["obfs"]["password"] == "xyz", sb["obfs"]

    # همان کلید در mihomo تخت است، در sing-box تودرتو — اثباتِ اینکه دو
    # امیت‌کننده واقعاً جدا هستند و یکی از دیگری کپی نشده
    assert "obfs-password" not in sb, "sing-box هرگز کلیدِ خط‌تیره‌دار نمی‌پذیرد"
    assert not isinstance(cl["obfs"], dict), "mihomo هرگز شیءِ تودرتو نمی‌پذیرد"

    sbt = _sb_proxy(_TUIC)
    assert isinstance(sbt["tls"], dict), sbt
    assert sbt["tls"]["enabled"] is True, sbt["tls"]
    assert sbt["tls"]["server_name"] == "example.org", sbt["tls"]
    assert sbt["tls"]["alpn"] == ["h3"], sbt["tls"]
    # sing-box زیرخط می‌خواهد، mihomo خط‌تیره — با باینریِ ۱٫۱۳٫۱۴ سنجیده شد
    assert sbt["congestion_control"] == "bbr", sbt
    assert sbt["udp_relay_mode"] == "quic", sbt
    assert "congestion-controller" not in sbt, sbt
    clt = yaml.safe_load(converters.build_clash_yaml([_TUIC]))["proxies"][0]
    assert clt.get("congestion-controller") == "bbr", clt
    assert clt.get("udp-relay-mode") == "quic", clt
    assert "congestion_control" not in clt, clt


def test_url_shaped_sni_is_dropped_not_forwarded():
    """SNI واقعیِ زنده: «https://t.me/oneclickvpnkeys».

    کلاینت‌ها آن را در بارگذاری می‌پذیرند (rc=0) ولی TLS در زمانِ اتصال شکست
    می‌خورد و کاربر فکر می‌کند کانفیگ خراب است. پس باید حذف شود تا کلاینت به
    نامِ واقعیِ سرور برگردد.
    """
    bad = "hysteria2://pw@1.2.3.4:443?sni=https%3A%2F%2Ft.me%2Foneclickvpnkeys#x"
    p = converters.parse_proxy(bad)
    assert p is not None
    assert not p.get("sni"), f"garbage SNI must be dropped, got {p.get('sni')!r}"


def test_sni_cleanup_is_applied_to_vless_vmess_and_trojan_too():
    """باگِ واقعی: `_clean_sni` تنها بر hysteria2/tuic اعمال می‌شد.

    اندازه‌گیری روی خروجیِ زندهٔ همین مخزن، پیش از رفع: ۴۳۱ مقدارِ نامِ‌میزبانِ
    ساختاراً بی‌اعتبار در سه دستهٔ خروجی — از جمله `sni=t.me/ripaojiedian` (۱۲
    بار) و یک قطعهٔ HTML. پس از رفع: ۱۰ (که همه‌شان نشانیِ سرورِ loopback بودند
    و با درِ جداگانه‌ای بسته شدند). vmess/vless/trojan خام عبور می‌کردند.
    """
    for line, label in (
        ("vless://" + "a" * 8 + "-bbbb-cccc-dddd-" + "e" * 12 +
         "@1.2.3.4:443?security=tls&type=tcp&sni=t.me%2Fripaojiedian#x", "vless"),
        ("trojan://pw@1.2.3.4:443?sni=t.me%2Fripaojiedian#x", "trojan"),
    ):
        p = converters.parse_proxy(line)
        assert p is not None, label
        assert not p.get("sni"), f"{label}: garbage SNI survived: {p.get('sni')!r}"


def test_repairable_sni_is_repaired_rather_than_thrown_away():
    """«ترمیم کن، بعد رد کن» — با حقیقتِ DNS سنجیده شد.

    رد کردنِ سرسریِ هر مقدارِ نامعتبر، SNIِ سالم را دور می‌ریخت:

        `$$hn.xiaohouzi.club` → در DNS شکست  |  `hn.xiaohouzi.club` → 13.248.169.48 ✓
        `.afrcloud22.mmv.kr`  → در DNS شکست  |  `afrcloud22.mmv.kr` → 104.26.14.21 ✓

    و RFC 6066 §3 می‌گوید نامِ server_name «بدونِ نقطهٔ پایانی» بیان می‌شود، پس
    نقطهٔ پایانی بریده می‌شود نه اینکه مقدار حذف شود.
    """
    cases = {
        "$$hn.xiaohouzi.club": "hn.xiaohouzi.club",
        "world.yahoo.com:443": "world.yahoo.com",
        ".afrcloud22.mmv.kr": "afrcloud22.mmv.kr",
        "wwwuk.mobilex55.com.": "wwwuk.mobilex55.com",
        # زیرخط عمداً نگه داشته می‌شود: این نام واقعاً resolve می‌شود
        # (TM_AZARBAYJAB1.new.99.workers.dev → 104.21.61.74)
        "TM_AZARBAYJAB1.new.99.workers.dev": "TM_AZARBAYJAB1.new.99.workers.dev",
    }
    for raw, want in cases.items():
        got = converters._clean_sni(raw)
        assert got == want, f"{raw!r} -> {got!r}, expected {want!r}"

    # و مقادیرِ ذاتاً غیرِ‌میزبان باید همچنان حذف شوند
    for raw in ("https%3A%2F%2Ft.me%2Foneclickvpnkeys", "t.me%2Fripaojiedian",
                "None", "Telegram-Leviko_v2ray", "/?BIA_TELEGRAM@ShadowProxy66"):
        assert converters._clean_sni(raw) == "", f"{raw!r} must be dropped"


def test_unroutable_server_addresses_are_dropped_and_counted():
    """نقصِ جداگانهٔ بالادست: نشانیِ سرور loopback یا 0.0.0.0 است.

    اندازه‌گیریِ زنده پیش از رفع، ۳۲ رخداد در سه دسته — از جمله `127.0.0.53`
    (نشانیِ حل‌کنندهٔ systemd-resolved) ×۲۰ و `0.0.0.0` ×۲. چنین کانفیگی روی
    دستگاهِ کاربر به خودِ دستگاه وصل می‌شود، پس هرگز کار نمی‌کند.

    نکته: نشانیِ خصوصی (`192.168.…`) عمداً حذف *نمی‌شود* — پروکسیِ درونِ شبکهٔ
    محلی برای بخشی از کاربران کاملاً مشروع است.
    """
    assert converters._is_unroutable_server("127.0.0.1")
    assert converters._is_unroutable_server("127.0.0.53")
    assert converters._is_unroutable_server("0.0.0.0")
    assert converters._is_unroutable_server("::1")
    assert not converters._is_unroutable_server("192.168.1.1"), \
        "پروکسیِ شبکهٔ محلی مشروع است و نباید حذف شود"
    assert not converters._is_unroutable_server("8.8.8.8")
    assert not converters._is_unroutable_server("example.com"), \
        "نامِ میزبان به DNS نیاز دارد و در زمانِ تبدیل داوری نمی‌شود"

    good = "trojan://pw@8.8.8.8:443?sni=example.com#ok"
    bad = "trojan://pw@127.0.0.1:443?sni=example.com#loopback"
    doc = yaml.safe_load(converters.build_clash_yaml([good, bad]))
    servers = [p["server"] for p in doc["proxies"]]
    assert servers == ["8.8.8.8"], servers
    st = converters.drop_stats()
    assert st["clash"]["by_reason"].get("unroutable_server") == 1, st["clash"]

    sb = json.loads(converters.build_singbox_json([good, bad]))
    assert [o["server"] for o in sb["outbounds"] if o.get("server")] == ["8.8.8.8"]
    st = converters.drop_stats()
    assert st["singbox"]["by_reason"].get("unroutable_server") == 1, st["singbox"]


def test_structurally_invalid_server_is_dropped_not_published():
    """H8 — نشانیِ سرور که ساختاراً نامِ میزبان نیست باید حذف شود.

    این نقص روی خروجیِ *زندهٔ* CI (کامیتِ `f692efc`، ۸٬۱۵۲ کانفیگ) پیدا شد، نه
    در آزمایشگاه: `_clean_sni` فقط `sni` و `host` را پاک می‌کرد و میدانِ
    `server` — همان جایی که کلاینت واقعاً به آن وصل می‌شود — هیچ سنجشِ شکلی
    نداشت. با پارسرِ خودِ ماژول ۶ کانفیگِ معیوب شمرده شد و **۴ موردشان در ۶
    فایلِ منتشرشده (۱۶ رخداد) حاضر بود**:

        trojan  'masir_sefid'                                 (تک‌برچسب)
        vless   'black_raven_ir'   ← از `@@Black_Raven_ir`    (تک‌برچسب)
        vless   'ip'                                          (تک‌برچسب)
        vmess   'https://github.com/ALIILAPRO/v2rayNG-Config' (کلِ یک URL)

    هر ۶ مقدار در DNS شکست می‌خورند (`gaierror`)، پس «ترمیم» ممکن نیست: تنها
    ترمیمِ موردِ URL تبدیل به `github.com` است که کلاینت را به GitHub می‌برد نه
    به پروکسی — یعنی «معتبر به‌نظر می‌رسد ولی هرگز وصل نمی‌شود». شاهدِ تکمیلی:
    `uuid` همان ردیف `aliilapro-v2rayng-config` است که UUID نیست؛ یک تبلیغ است.

    سنجشِ A/B روی همان ۸٬۱۵۲ خطِ زنده: clash ۸۰۶۷→۸۰۶۳ و singbox ۷۸۳۴→۷۸۳۰،
    یعنی **دقیقاً ۴ حذف در هر کلاینت و صفر حذفِ جانبی و صفر افزوده**.
    """
    f = converters._is_structurally_invalid_server

    # مقادیرِ واقعیِ معیوب — همه باید رد شوند
    for bad in ("", "   ", "masir_sefid", "black_raven_ir", "ip",
                "使用前记得更新订阅",
                "https://github.com/ALIILAPRO/v2rayNG-Config",
                "t.me/ripaojiedian", "example.com:443", "host name.com",
                "foo@bar.com", "a/b.com"):
        assert f(bad), f"{bad!r} باید ساختاراً نامعتبر شمرده شود"

    # مقادیرِ واقعیِ سالم — هیچ‌کدام نباید قربانی شوند
    for ok in ("1.2.3.4", "104.21.61.74",
               "2a01:4f8:1c1b:26eb::1", "[2a01:4f8:1c1b:26eb::1]",
               "TM_AZARBAYJAB1.new.99.workers.dev",  # زیرخط واقعاً حل می‌شود
               "afrcloud22.mmv.kr", "hn.xiaohouzi.club",
               "store.steampowered.com", "ip11-2.freegradely.xyz",
               "a.b", "xn--80ak6aa92e.com", "example.com."):
        assert not f(ok), f"{ok!r} سالم است و نباید حذف شود"

    # IPv6ِ لخت هرگز نباید با «باقی‌ماندهٔ پورت» اشتباه شود
    assert not f("2a0b:8800:580::12d")

    # و در خطِ لولهٔ واقعی: حذف می‌شود و با ریزه‌ی مخصوصِ خودش شمرده می‌شود
    good = "trojan://pw@example.com:443?sni=example.com#ok"
    bad = "trojan://pw@masir_sefid:443?sni=example.com#advert"
    doc = yaml.safe_load(converters.build_clash_yaml([good, bad]))
    assert [p["server"] for p in doc["proxies"]] == ["example.com"], doc["proxies"]
    st = converters.drop_stats()
    assert st["clash"]["by_reason"].get("invalid_server") == 1, st["clash"]
    # ریزه‌ی جدا از unroutable_server است — درهم‌ریختنشان ریشه‌یابی را کور می‌کند
    assert not st["clash"]["by_reason"].get("unroutable_server"), st["clash"]

    sb = json.loads(converters.build_singbox_json([good, bad]))
    assert [o["server"] for o in sb["outbounds"] if o.get("server")] == ["example.com"]
    st = converters.drop_stats()
    assert st["singbox"]["by_reason"].get("invalid_server") == 1, st["singbox"]


def test_invalid_server_gate_runs_in_both_emitters():
    """H8 — دروازه باید در *هر دو* حلقهٔ تولید باشد، نه یکی.

    درسِ سنجیده‌شدهٔ فاز H: `_clean_sni` نوشته شده بود ولی فقط به ۲ پروتکل از ۵
    وصل شده بود، و همین شکاف ۴۳۱ مقدارِ نامعتبر را منتشر کرد. پس «وجودِ تابع»
    شاهدِ کافی نیست؛ باید *فراخوانی‌اش* در هر دو مسیر اثبات شود. اینجا با AST
    بررسی می‌شود تا ذکرِ نام در توضیحات، تست را الکی سبز نکند.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(converters))
    wanted = {"build_clash_yaml", "build_singbox_json"}
    seen = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in wanted:
            calls = {
                c.func.id
                for c in ast.walk(node)
                if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
            }
            seen[node.name] = calls
    assert wanted <= set(seen), f"توابعِ تولید پیدا نشدند: {set(seen)}"
    for fn in wanted:
        assert "_is_structurally_invalid_server" in seen[fn], \
            f"{fn} دروازهٔ invalid_server را صدا نمی‌زند"
        assert "_is_unroutable_server" in seen[fn], \
            f"{fn} دروازهٔ unroutable_server را صدا نمی‌زند"


def test_alpn_values_are_whitelisted():
    """مقدارِ نامعتبرِ ALPN باید فیلتر شود، نه به کلاینت پاس داده شود."""
    line = "hysteria2://pw@1.2.3.4:443?alpn=h3%2Cgarbage%2Ch2#x"
    p = converters.parse_proxy(line)
    assert p is not None
    assert p["alpn"] == ["h3", "h2"], p["alpn"]


# ──────────────────────────────────────────────────────────────────────────────
# C10 — تلمتریِ حذف در تبدیل
# ──────────────────────────────────────────────────────────────────────────────

def test_drop_stats_counts_unparsable_lines_per_target():
    """حذفِ خاموش باید شمرده شود؛ اندازه‌گیریِ زنده: Clash ۶۸ ، Sing-box ۳۱۳."""
    lines = [_HY2, "vless://not-a-valid-config", "totally garbage line"]
    converters.build_clash_yaml(lines)
    converters.build_singbox_json(lines)
    st = converters.drop_stats()
    assert "clash" in st and "singbox" in st, st
    for target in ("clash", "singbox"):
        assert st[target]["total"] >= 1, st[target]
        assert "unparsable" in st[target]["by_reason"], st[target]


def test_drop_stats_is_reset_per_build_not_accumulated():
    """اگر پاک نشود، عددها بینِ سه دستهٔ all/heavy/light جمع می‌شوند و دروغ می‌گویند."""
    converters.build_clash_yaml(["garbage one", "garbage two"])
    first = converters.drop_stats()["clash"]["total"]
    converters.build_clash_yaml(["garbage one", "garbage two"])
    second = converters.drop_stats()["clash"]["total"]
    assert first == second, f"drop counters accumulated: {first} then {second}"


# ──────────────────────────────────────────────────────────────────────────────
# C1 — مرحلهٔ پایگاهِ دادهٔ GeoIP در ورک‌فلو
# ──────────────────────────────────────────────────────────────────────────────

def _workflow_text() -> str:
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        ".github", "workflows", "aggregate.yml")
    with open(path, encoding="utf-8") as f:
        return f.read()


def test_workflow_downloads_and_caches_the_geoip_database():
    """بدونِ این مرحله، خط‌لوله در CI بی‌صدا به برچسب‌گذاریِ ضعیف برمی‌گردد."""
    wf = _workflow_text()
    assert "download.db-ip.com" in wf, "the workflow must fetch the DB-IP database"
    assert "actions/cache@v4" in wf, "the database must be cached, not re-downloaded 96×/day"
    assert "dbip-country-lite.mmdb" in wf


def _workflow_run_text() -> str:
    """فقط بدنهٔ `run:`های ورک‌فلو — یعنی چیزی که *اجرا* می‌شود.

    خواندنِ کلِ فایل برای این کار غلط است: توضیحاتِ فایل عمداً می‌گویند «چرا
    MaxMind نه»، و آزمونی که واژه را در متنِ خام ممنوع کند، مستندسازیِ درست را
    جریمه می‌کند در حالی که هیچ ریسکِ اجرایی وجود ندارد. YAML پارس می‌شود تا
    کامنت‌ها طبعاً حذف شوند و تنها دستورهای واقعی بمانند.
    """
    doc = yaml.safe_load(_workflow_text())
    out = []
    for job in (doc.get("jobs") or {}).values():
        for step in (job.get("steps") or []):
            for key in ("run", "uses", "with"):
                v = step.get(key)
                if isinstance(v, str):
                    out.append(v)
                elif isinstance(v, dict):
                    out.extend(str(x) for x in v.values())
    return "\n".join(out)


def test_workflow_never_uses_maxmind_which_requires_a_licence_key():
    """آزمونِ زنده: MaxMind → HTTP 401 ، DB-IP → HTTP 200.

    ادعا دربارهٔ *دستورهای اجرایی* است، نه دربارهٔ توضیحات. توضیحاتِ فایل حق
    دارند نامِ MaxMind را ببرند تا دلیلِ رد شدنش ثبت بماند.
    """
    runs = _workflow_run_text().lower()
    assert "maxmind" not in runs, "GeoLite2 needs an account key; it would fail in CI"
    assert "geolite" not in runs
    assert "license_key" not in runs and "licence_key" not in runs
    # و آدرسِ واقعیِ دانلود باید همان DB-IP باشد
    assert "download.db-ip.com" in runs, "the executable step must fetch DB-IP"


def test_geoip_cache_directory_is_gitignored():
    """اگر نبود، هر اجرا ۸ مگابایت commit می‌کرد — همان الگوی رشدی که حذف شد."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, ".gitignore"), encoding="utf-8") as f:
        ignored = f.read()
    assert ".cache/" in ignored, ".cache/ must be gitignored"


def test_requirements_pin_the_mmdb_reader_without_heavy_extras():
    """maxminddb هیچ وابستگی‌ای ندارد؛ geoip2 برای همین کار aiohttp می‌آورد.

    سنجش: روی ۳۷۲۰ آی‌پیِ واقعی، نتیجه صددرصد یکسان و ۱٫۸۲ برابر سریع‌تر.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "requirements.txt"), encoding="utf-8") as f:
        req = f.read()
    assert "maxminddb==" in req, "the mmdb reader must be pinned in requirements.txt"


def test_health_report_carries_drop_and_geo_telemetry():
    """C10 — عددهای حذف و برچسب‌گذاری باید در health.json دیده شوند."""
    import aggregate
    rep = aggregate.build_health_report(1.0)
    assert "converters" in rep, "health.json must expose converter drop stats"
    assert "geo" in rep, "health.json must expose geo stats"


def test_aggregator_warms_up_the_geo_cache_before_branding():
    """بدونِ گرم‌کردن، ۱۳۶۵ پرسشِ DNS سری اجرا می‌شود (اندازه‌گیری: >۱۰ دقیقه).

    با گرم‌کردنِ همروند: ۴٫۹ ثانیه.
    """
    import ast
    import inspect
    import textwrap
    import aggregate

    # نکته: جست‌وجوی متنیِ ساده در اینجا *غلط* است. متنِ تابع یک بلوکِ توضیحِ
    # چندخطی دارد که در آن واژهٔ `brand_remark` برای *توضیحِ* دلیلِ گرم‌کردن آمده،
    # و آن توضیح بالاتر از خودِ فراخوانیِ `warm_up` است. پس `str.index` اولین
    # تطبیقش کامنت می‌شود و آزمون بی‌گناه‌سوز می‌گردد. پیمایشِ AST فقط کدِ
    # اجرایی را می‌بیند و کامنت‌ها در درختِ نحوی وجود ندارند.
    tree = ast.parse(textwrap.dedent(inspect.getsource(aggregate.process_category)))
    fn = tree.body[0]

    warm_lines = [
        n.lineno for n in ast.walk(fn)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "warm_up"
    ]
    brand_lines = [
        n.lineno for n in ast.walk(fn)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "brand_remark"
    ]
    assert warm_lines, "process_category must warm the geo cache in one concurrent pass"
    assert brand_lines, "process_category must brand every line"
    # ترتیب مهم است: گرم‌کردن باید *پیش از* حلقهٔ برندینگ باشد
    assert min(warm_lines) < min(brand_lines), (
        f"warm_up (line {min(warm_lines)}) must run before the branding loop "
        f"(line {min(brand_lines)}), otherwise it is pointless"
    )


# ──────────────────────────────────────────────────────────────────────────────
# فاز B — لایهٔ L0/L1 (`filters.py`)
#
# هر قاعدهٔ `filters.py` این‌جا یک آزمونِ اختصاصی دارد، و هر آزمون **کنترلِ
# منفی** هم دارد: نه‌تنها نشان می‌دهد قاعده مقدارِ بد را می‌گیرد، بلکه نشان
# می‌دهد مقدارِ *سالم* را نمی‌گیرد. بی این نیمهٔ دوم، یک قاعدهٔ «همه‌چیز را رد
# کن» هم در آزمون قبول می‌شد.
# ──────────────────────────────────────────────────────────────────────────────

def test_filters_port_rule_rejects_out_of_range_and_keeps_valid() -> None:
    for bad in (0, -1, 65536, 99999, "abc", None, "", "8.5"):
        assert filters.is_invalid_port(bad), f"port {bad!r} must be rejected"
    # کنترلِ منفی: مرزهای معتبر نباید رد شوند
    for good in (1, 80, 443, 8080, 65535, "443", " 443 "):
        assert not filters.is_invalid_port(good), f"port {good!r} must be kept"


def test_filters_custom_string_ids_are_valid_per_xray_spec() -> None:
    """
    مستندِ رسمیِ Xray برای VLESS و VMess: «any string less than 30 bytes, or a
    valid UUID». پس شناسه‌های سفارشی مثل `13094` مشروع‌اند.

    این آزمون یک اشکالِ *واقعیِ* همین فاز را قفل می‌کند: نخستین پیاده‌سازی
    «UUIDِ متعارف وگرنه حذف» بود و روی دادهٔ زنده ۱۱۳ کانفیگِ سالم را می‌کشت.
    """
    for proto in ("vless", "vmess", "tuic"):
        for ok in ("13094", "AlfredConfig", "@free_conf_iran", "x" * 29,
                   "f23bb427-c1f9-4373-876c-2f43e9f790f3",
                   "f23bb427c1f94373876c2f43e9f790f3"):
            assert not filters.is_invalid_uuid(ok, proto), (
                f"{proto} id {ok!r} is legal per the Xray spec and must be kept"
            )
        # ۳۰ بایت یا بیشتر و UUID هم نیست → بیرونِ هر دو راهِ مجاز
        assert filters.is_invalid_uuid("x" * 30, proto)
        assert filters.is_invalid_uuid("", proto)
        assert filters.is_invalid_uuid("00000000-0000-0000-0000-000000000000", proto)


def test_filters_id_rule_does_not_touch_password_protocols() -> None:
    """در ss/trojan/hysteria2 این میدان رمزِ عبور است، نه شناسه."""
    for proto in ("shadowsocks", "ss", "trojan", "hysteria2"):
        for anything in ("", "x" * 200, "@channel", "p@ssw0rd!"):
            assert not filters.is_invalid_uuid(anything, proto), (
                f"{proto} treats this field as a password; it must never be judged"
            )


def test_filters_reuses_converters_rules_instead_of_reimplementing() -> None:
    """
    L1 نباید قاعدهٔ خودش را برای «سرورِ بد» بنویسد؛ باید همان توابعِ
    `converters` را صدا بزند. دو پیاده‌سازیِ موازی = دو رفتارِ واگرا در آینده.
    داوری با AST، نه با جست‌وجوی رشته — چون رشته در توضیحات هم پیدا می‌شود.
    """
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(filters.classify))
    called = {
        n.func.attr for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    for required in ("_is_unroutable_server", "_is_structurally_invalid_server",
                     "parse_proxy"):
        assert required in called, (
            f"filters.classify must delegate to converters.{required}, "
            f"not reimplement it; calls found: {sorted(called)}"
        )


def _vmess_link(**over: str) -> str:
    """یک لینکِ vmess معتبر می‌سازد؛ فقط میدانِ موردِ آزمون را عوض می‌کنیم.

    برای میزبان‌هایی مثل «یک URLِ کامل» تنها همین قالب واقع‌گراست: در URIِ
    trojan/vless آن رشته پیش از رسیدن به میدانِ `server` تجزیه می‌شود
    (`server='https'`, `port=0`) و قاعدهٔ پورت زودتر شلیک می‌کند — چنان‌که
    دادهٔ زندهٔ این مخزن هم آن مورد را در vmess نشان داد، نه در trojan.
    """
    body = {"v": "2", "ps": "X", "add": "example.org", "port": "443",
            "id": "f23bb427-c1f9-4373-876c-2f43e9f790f3", "aid": "0",
            "net": "ws", "type": "none", "tls": "tls"}
    body.update(over)
    raw = json.dumps(body).encode("utf-8")
    return "vmess://" + base64.b64encode(raw).decode("ascii")


def test_filters_drops_unroutable_and_structurally_invalid_servers() -> None:
    for host in ("127.0.0.1", "0.0.0.0", "127.0.0.53"):
        line = f"trojan://pw@{host}:443#T"
        _, reason = filters.classify(line)
        assert reason == filters.REASON_UNROUTABLE, (host, reason)
    # هر سه مقدار از دادهٔ زندهٔ همین مخزن آمده‌اند (سندِ `converters`)
    for host in ("masir_sefid", "ip",
                 "https://github.com/ALIILAPRO/v2rayNG-Config",
                 "使用前记得更新订阅"):
        _, reason = filters.classify(_vmess_link(add=host))
        assert reason == filters.REASON_INVALID_SERVER, (host, reason)
    # کنترلِ منفی: میزبانِ سالم باید بگذرد — در هر دو قالب
    proxy, reason = filters.classify("trojan://pw@example.org:443#T")
    assert reason is None and proxy is not None
    proxy, reason = filters.classify(_vmess_link())
    assert reason is None and proxy is not None


def test_filters_checks_cheap_rules_before_expensive_ones() -> None:
    """
    ترتیبِ بندها بخشی از قراردادِ L1 است، نه سلیقه: پورت پیش از میزبان، و
    میزبان پیش از شناسه. اگر ترتیب عوض شود، دلیلِ حذفِ گزارش‌شده در
    `health.json` عوض می‌شود و آمارِ تاریخی ناسازگار می‌گردد.

    شاهدِ عینی: `trojan://pw@https://github.com/x/y:443` را پارسر به
    `server='https', port=0` تبدیل می‌کند؛ پس انتظارِ درست `invalid_port` است.
    """
    _, reason = filters.classify("trojan://pw@https://github.com/x/y:443#T")
    assert reason == filters.REASON_INVALID_PORT, reason
    # میزبانِ بد + شناسهٔ بد هم‌زمان → باید میزبان گزارش شود، نه شناسه
    _, reason = filters.classify(_vmess_link(add="masir_sefid", id=""))
    assert reason == filters.REASON_INVALID_SERVER, reason


def test_filters_deduplicates_endpoints_and_maps_them_back() -> None:
    """
    L0 روی *نقطهٔ پایانی* یکتا کار می‌کند، ولی هر نقطه باید به همهٔ سطرهایش
    برگردد — وگرنه نتیجهٔ آزمون به کانفیگ‌ها نسبت داده نمی‌شود.
    """
    lines = [
        "trojan://pw@example.org:443#A",
        "trojan://pw2@example.org:443#B",   # همان نقطهٔ پایانی
        "trojan://pw@example.net:443#C",
    ]
    res = filters.filter_lines(lines)
    assert res["stats"]["kept"] == 3
    assert res["stats"]["endpoints_unique"] == 2, res["endpoints"]
    assert res["ep_to_lines"][("example.org", 443)] == [0, 1]
    assert res["ep_to_lines"][("example.net", 443)] == [2]
    assert len(res["line_endpoint"]) == 3


def test_filters_skips_comment_header_and_counts_honestly() -> None:
    """
    نخستین سطرِ `configs.txt` توضیح است. شمردنش آمار را باد می‌کند — خطایی که
    در سنجش‌های پیشینِ همین پروژه واقعاً رخ داد.
    """
    res = filters.filter_lines([
        "# Free V2Ray configs — header",
        "",
        "   ",
        "trojan://pw@example.org:443#A",
    ])
    assert res["stats"]["input"] == 1, res["stats"]
    assert res["stats"]["kept"] == 1


def test_filters_reports_every_reason_key_even_when_zero() -> None:
    """
    کلیدهای `dropped` قراردادِ `health.json` هستند. اگر کلیدی تنها وقتی ظاهر
    شود که ≥۱ باشد، مصرف‌کننده مجبور به حدس‌زدن می‌شود.
    """
    res = filters.filter_lines(["trojan://pw@example.org:443#A"])
    assert set(res["dropped"]) == set(filters.ALL_REASONS)
    assert all(v == 0 for v in res["dropped"].values())


def test_filters_stats_are_internally_consistent() -> None:
    """input = kept + dropped، بی استثنا. تراز، خودش یک ناوردا است."""
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(repo, "all", "configs.txt")
    assert os.path.exists(path), f"{path} is tracked in git; it must exist"
    res = filters.filter_file(path)
    st = res["stats"]
    assert st["input"] == st["kept"] + st["dropped"], st
    assert st["dropped"] == sum(res["dropped"].values()), res["dropped"]
    assert st["endpoints_unique"] <= st["kept"]
    assert st["hosts_unique"] <= st["endpoints_unique"]
    # همهٔ نقاطِ پایانی باید به سطر نگاشت شوند
    assert sum(len(v) for v in res["ep_to_lines"].values()) == st["kept"]




# ──────────────────────────────────────────────────────────────────────────────
# فاز B — لایهٔ L2 (`reachability.py`)
#
# این آزمون‌ها عمداً **بی‌شبکه** هستند. آزمونِ واحدی که به اینترنت وصل شود روی
# runnerِ CI ناپایدار است و شکستش چیزی دربارهٔ کد نمی‌گوید. پس رفتارِ شبکه با
# جایگزینیِ `asyncio.open_connection` ساخته می‌شود و آنچه سنجیده می‌شود
# *منطقِ* لایه است: شمارشِ خطاها، سقفِ نشانی، نگاشتِ نتیجه به کانفیگ، و
# مهم‌تر از همه: بلندشدنِ صدای کمبودِ fd.
#
# سنجش‌های شبکه‌ایِ واقعی جای دیگری‌اند و در سندِ ماژول با عدد آمده‌اند.
# ──────────────────────────────────────────────────────────────────────────────

class _FakeWriter:
    """سوکتِ قلابی که می‌شمارد آیا بسته شد یا نه."""

    def __init__(self, ledger):
        self._ledger = ledger
        self._ledger["opened"] += 1

    def close(self):
        self._ledger["closed"] += 1

    async def wait_closed(self):
        return None


def _patch_connect(monkey, behaviour, ledger=None):
    """`asyncio.open_connection` را با یک تابعِ معین جایگزین می‌کند.

    `behaviour(ip, port)` یکی از این‌ها را برمی‌گرداند/می‌اندازد:
        None            → اتصال موفق
        استثنا          → همان استثنا بالا می‌رود
    """
    import asyncio as _a
    led = ledger if ledger is not None else {"opened": 0, "closed": 0}

    async def fake(ip, port, *a, **kw):
        outcome = behaviour(ip, port)
        if isinstance(outcome, BaseException):
            raise outcome
        return object(), _FakeWriter(led)

    monkey.append((_a, "open_connection", _a.open_connection))
    _a.open_connection = fake
    return led


def _unpatch(monkey):
    for obj, name, orig in monkey:
        setattr(obj, name, orig)


def _patch_dns(monkey, mapping):
    """DNS را قطع می‌کند: هیچ آزمونی نباید به resolverِ واقعی وابسته باشد."""
    monkey.append((reachability, "resolve_hosts", reachability.resolve_hosts))
    reachability.resolve_hosts = lambda hosts: ({h: mapping.get(h, ()) for h in hosts}, 0.0)


def test_reachability_emfile_raises_instead_of_reporting_a_wrong_rate() -> None:
    """
    مهم‌ترین آزمونِ این ماژول.

    در سنجشِ واقعیِ فاز B، هم‌روندیِ ۱۲۰۰ باعثِ ۵٬۷۰۰ خطای EMFILE شد و
    فرآیند با **کدِ خروجِ ۰** گزارش داد «۱٫۱٪ کار می‌کنند» — در حالی که
    واقعیت ۴۸٫۰٪ بود. یک شکستِ خاموشِ ۴۴ برابری.

    پس کمبودِ fd باید استثنا باشد، نه یک عددِ کوچک در گزارش.
    """
    monkey = []
    try:
        _patch_dns(monkey, {"a.example": ("203.0.113.1",)})
        _patch_connect(monkey, lambda ip, p: OSError(24, "Too many open files"))
        raised = False
        try:
            reachability.check_endpoints([("a.example", 443)])
        except reachability.FileDescriptorExhaustion as exc:
            raised = True
            assert "EMFILE" in str(exc), str(exc)
        assert raised, "EMFILE must raise FileDescriptorExhaustion, not be reported"
    finally:
        _unpatch(monkey)

    # کنترلِ منفی: خطای *معمولیِ* شبکه نباید استثنا بیندازد
    monkey = []
    try:
        _patch_dns(monkey, {"a.example": ("203.0.113.1",)})
        _patch_connect(monkey, lambda ip, p: ConnectionRefusedError(111, "refused"))
        res = reachability.check_endpoints([("a.example", 443)])
        assert res["errors"][reachability.ERR_REFUSED] == 1, res["errors"]
    finally:
        _unpatch(monkey)


def test_reachability_closes_every_socket_it_opens() -> None:
    """
    نشتِ fd همان فروپاشی را از راهِ دیگری می‌سازد. پس شمارشِ باز و بسته
    باید برابر باشد — و این با شمارنده سنجیده می‌شود، نه با اعتماد.
    """
    monkey = []
    try:
        _patch_dns(monkey, {f"h{i}.example": ("203.0.113.1",) for i in range(20)})
        led = _patch_connect(monkey, lambda ip, p: None)
        reachability.check_endpoints([(f"h{i}.example", 443) for i in range(20)])
        assert led["opened"] == 20, led
        assert led["closed"] == led["opened"], led
    finally:
        _unpatch(monkey)


def test_reachability_raises_when_the_real_fd_count_grows() -> None:
    """
    آزمونِ بالا شمارندهٔ *استاب* را می‌سنجد: «هرچه باز شد بسته شد». این
    خصوصیتِ فِیک است، نه خصوصیتِ ماژول. پس محافظِ واقعی — آن `raise` که
    وقتی `fd_after > fd_before` باشد نتیجه را باطل می‌کند — بی‌آزمون
    می‌ماند. (با mutation ثابت شد: برداشتنِ آن `raise` هیچ تستی را
    نشکست.)

    این‌جا خودِ محافظ سنجیده می‌شود، با جایگزینیِ `fd_count` که تنها دو
    بار صدا زده می‌شود: یک‌بار پیش از سنجش، یک‌بار پس از آن.

    سه حالت، چون یک محافظ که همیشه بیندازد هم به‌همان اندازه بی‌فایده است:
      ۱) رشدِ fd → استثنا، با پیامی که از پیامِ EMFILE قابلِ تفکیک است.
      ۲) fdِ ثابت → بی‌استثنا، و همان اعداد در `stats`.
      ۳) نبودِ ‎/proc‏ (‎-1‏) → *نباید* رشدِ کاذب تلقی شود؛ ‎-1 → 4‏ عددی
         بزرگ‌تر است ولی هیچ نشتی را نشان نمی‌دهد. این همان شرطِ
         `fd_before >= 0` است.
    """
    # ۱) رشدِ واقعیِ fd
    monkey = []
    grew = iter([4, 9])
    try:
        _patch_dns(monkey, {"a.example": ("203.0.113.1",)})
        _patch_connect(monkey, lambda ip, p: None)
        monkey.append((reachability, "fd_count", reachability.fd_count))
        reachability.fd_count = lambda: next(grew)
        msg = ""
        try:
            reachability.check_endpoints([("a.example", 443)])
        except reachability.FileDescriptorExhaustion as exc:
            msg = str(exc)
        assert msg, "رشدِ fd باید FileDescriptorExhaustion بیندازد، نه بی‌صدا بگذرد"
        assert "leak" in msg.lower(), f"پیام باید نشت را نام ببرد: {msg!r}"
        assert "4" in msg and "9" in msg, f"پیام باید هر دو عدد را بدهد: {msg!r}"
        assert "EMFILE" not in msg, (
            f"پیامِ نشت باید از پیامِ EMFILE جدا باشد، وگرنه علتِ خرابی "
            f"اشتباه تشخیص داده می‌شود: {msg!r}")
    finally:
        _unpatch(monkey)

    # ۲) کنترلِ منفی: fdِ ثابت → هیچ استثنایی
    monkey = []
    same = iter([7, 7])
    try:
        _patch_dns(monkey, {"a.example": ("203.0.113.1",)})
        _patch_connect(monkey, lambda ip, p: None)
        monkey.append((reachability, "fd_count", reachability.fd_count))
        reachability.fd_count = lambda: next(same)
        res = reachability.check_endpoints([("a.example", 443)])
        assert res["stats"]["fd_before"] == 7, res["stats"]
        assert res["stats"]["fd_after"] == 7, res["stats"]
    finally:
        _unpatch(monkey)

    # ۳) کنترلِ منفی: /proc نیست → -1، و -1 < 4 نباید «نشت» خوانده شود
    monkey = []
    noproc = iter([-1, 4])
    try:
        _patch_dns(monkey, {"a.example": ("203.0.113.1",)})
        _patch_connect(monkey, lambda ip, p: None)
        monkey.append((reachability, "fd_count", reachability.fd_count))
        reachability.fd_count = lambda: next(noproc)
        res = reachability.check_endpoints([("a.example", 443)])
        assert res["stats"]["fd_before"] == -1, res["stats"]
        assert ("a.example", 443) in res["open"], (
            "بی‌اطلاعی از fd نباید سنجش را باطل کند")
    finally:
        _unpatch(monkey)


def test_reachability_probes_up_to_the_address_cap_not_just_the_first() -> None:
    """
    سنجشِ واقعی: ۴۳۹ میزبان بیش از یک نشانی دارند و «فقط نشانیِ اول»
    ۲۱ نقطه از ۴۱۱ (۵٫۱٪) را از دست می‌داد. سقفِ ۳ آن‌ها را بازمی‌گرداند.

    این آزمون قاعده را قفل می‌کند: نشانیِ دوم و سوم *واقعاً* آزموده شوند،
    و نشانیِ چهارم *واقعاً* نه.
    """
    seen = []
    monkey = []
    try:
        _patch_dns(monkey, {"multi.example": ("203.0.113.1", "203.0.113.2",
                                              "203.0.113.3", "203.0.113.4")})

        def behave(ip, port):
            seen.append(ip)
            # تنها نشانیِ سوم باز است: اگر فقط اولی آزموده شود، نتیجه «بسته»
            return None if ip == "203.0.113.3" else ConnectionRefusedError(111, "x")

        _patch_connect(monkey, behave)
        res = reachability.check_endpoints([("multi.example", 443)])
        assert ("multi.example", 443) in res["open"], res["closed"]
        assert len(seen) == reachability.ADDR_CAP, seen
        assert "203.0.113.4" not in seen, "the cap must actually cap"
    finally:
        _unpatch(monkey)


def test_reachability_distinguishes_refusal_from_timeout_and_dns_failure() -> None:
    """
    سه شکستِ متفاوت با سه معنای متفاوت:
      رد شد   → سرور زنده است، این درگاه نه
      مهلت    → چیزی جواب نداد (فیلترینگ یا میزبانِ مرده)
      DNS     → اصلاً نامی برای وصل‌شدن نبود
    یکی‌کردنشان یعنی نابودیِ تنها نشانه‌ای که سرورِ زنده را لو می‌دهد.
    """
    import asyncio
    monkey = []
    try:
        _patch_dns(monkey, {"r.example": ("203.0.113.1",),
                            "t.example": ("203.0.113.2",),
                            "d.example": ()})

        def behave(ip, port):
            if ip == "203.0.113.1":
                return ConnectionRefusedError(111, "refused")
            return asyncio.TimeoutError()

        _patch_connect(monkey, behave)
        res = reachability.check_endpoints(
            [("r.example", 443), ("t.example", 443), ("d.example", 443)])
        e = res["errors"]
        assert e[reachability.ERR_REFUSED] == 1, e
        assert e[reachability.ERR_TIMEOUT] == 1, e
        assert e[reachability.ERR_DNS] == 1, e
        assert e[reachability.ERR_OTHER] == 0, e
        assert res["stats"]["open"] == 0, res["stats"]
    finally:
        _unpatch(monkey)


def test_reachability_error_keys_are_always_present_even_at_zero() -> None:
    """کلیدهای خطا قراردادِ `health.json` هستند؛ ظاهرشدنِ شرطی = حدس‌زنیِ مصرف‌کننده."""
    monkey = []
    try:
        _patch_dns(monkey, {"a.example": ("203.0.113.1",)})
        _patch_connect(monkey, lambda ip, p: None)
        res = reachability.check_endpoints([("a.example", 443)])
        assert set(res["errors"]) == set(reachability.ALL_ERRORS), res["errors"]
        assert res["errors"][reachability.ERR_EMFILE] == 0
    finally:
        _unpatch(monkey)


def test_reachability_maps_open_endpoints_back_to_every_config_line() -> None:
    """
    L2 روی نقطهٔ پایانی کار می‌کند ولی خروجیِ منتشرشده کانفیگ است. اگر
    نگاشتِ برگشتی بشکند، چند کانفیگِ سالم بی‌صدا حذف می‌شوند — دقیقاً همان
    صرفه‌جوییِ ۱۲٫۹۲ درصدیِ L0 به زیان درست می‌شود.
    """
    monkey = []
    try:
        _patch_dns(monkey, {"open.example": ("203.0.113.1",),
                            "shut.example": ("203.0.113.9",)})
        _patch_connect(monkey, lambda ip, p:
                       None if ip == "203.0.113.1"
                       else ConnectionRefusedError(111, "x"))
        lines = [
            "# header",
            "trojan://pw@open.example:443#A",
            "trojan://pw2@open.example:443#B",     # همان نقطهٔ پایانی
            "trojan://pw@shut.example:443#C",
        ]
        res = reachability.check_lines(lines)
        assert res["stats"]["configs_in"] == 3, res["stats"]
        assert res["stats"]["configs_open"] == 2, res["stats"]
        assert len(res["line_delay"]) == len(res["kept_open"])
        assert all("open.example" in ln for ln in res["kept_open"]), res["kept_open"]
    finally:
        _unpatch(monkey)


def test_reachability_resolver_accepts_ipv6_only_hosts() -> None:
    """
    `geo.resolve_all` عمداً AF_INET است (پایگاهِ کشور IPv4 است). اگر L2 به
    آن واگذار می‌شد، میزبانِ فقط-IPv6 «حل‌نشده» به حساب می‌آمد.

    دادهٔ زندهٔ همین مخزن یک نمونه دارد و در ۳ تکرار از ۳ تکرار فقط IPv6
    داشت. پس این آزمون بی‌شبکه فقط قاعده را قفل می‌کند: خودِ ماژول نباید
    خانوادهٔ نشانی را محدود کند.
    """
    import ast
    import inspect
    src = inspect.getsource(reachability._resolve_one)
    tree = ast.parse(src.strip())
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "AF_INET" not in names, \
        "L2 must not restrict the address family; a v6-only host exists in the data"
    assert "AF_INET6" not in names, "nor the other way round"
    # کنترلِ منفی: مرتب‌سازی هم باید حاضر باشد، وگرنه «سه نشانیِ اول» مسابقه است
    assert "sorted" in src, "addresses must be sorted for reproducibility"


def test_reachability_concurrency_stays_under_the_measured_fd_ceiling() -> None:
    """
    ۸۰۰ سقفِ سنجیده‌شده است، نه عددِ دلبخواه: در ۱۲۰۰ اندازه‌گیری فرو ریخت.
    اگر کسی این عدد را بالا ببرد، باید آگاهانه باشد.
    """
    assert reachability.CONCURRENCY <= 1000, reachability.CONCURRENCY
    assert reachability.headroom_warning(10) is None
    assert reachability.headroom_warning(1000000) is not None, \
        "an absurd concurrency must warn before the run, not after the damage"



# ──────────────────────────────────────────────────────────────────────────────
# فاز B — دروازهٔ اعتبارسنجی برای دسته‌های تازه (`validate.py`)
#
# سه دستهٔ verified/ fast/ secure/ هنوز تولید نمی‌شوند. خطرِ واقعی این است که
# افزودنشان به دروازه، دروازه را *همین حالا* بشکند (چون `ok` شرطِ
# `missing == 0` دارد) یا برعکس، آن‌قدر نرم شود که دستهٔ خرابِ حاضر بی‌صدا
# منتشر شود. این آزمون‌ها هر دو سر را قفل می‌کنند.
# ──────────────────────────────────────────────────────────────────────────────

def test_validate_knows_the_phase_b_categories() -> None:
    for cat in ("verified", "fast", "secure"):
        assert cat in validate.CATEGORIES, \
            f"{cat}/ is a published directory; the gate must know it"
    # کنترلِ منفی: دسته‌های اصلی نباید در فهرستِ اختیاری بیفتند
    for cat in ("all", "heavy", "light"):
        assert cat in validate.CORE_CATEGORIES, cat
        assert cat not in validate.OPTIONAL_CATEGORIES, \
            f"{cat}/ is always produced; excusing it would let the gate pass " \
            f"with zero configs"


def test_validate_optional_category_absence_does_not_break_the_gate() -> None:
    """
    سنجیده شد: پیش از تفکیک، ۶ بررسی و rc=0؛ با افزودنِ سادهٔ سه دسته به
    همان تاپل، ۶ موردِ `missing` و rc=1 — یعنی انتشار می‌ایستاد پیش از
    آنکه کدِ تولیدکنندهٔ آن دسته‌ها نوشته شود.
    """
    import tempfile
    with tempfile.TemporaryDirectory() as root:
        for cat in validate.CORE_CATEGORIES:
            os.makedirs(os.path.join(root, cat))
            with open(os.path.join(root, cat, "singbox.json"), "w",
                      encoding="utf-8") as f:
                json.dump({"outbounds": [{"type": "direct", "tag": "d"}]}, f)
            with open(os.path.join(root, cat, "clash.yaml"), "w",
                      encoding="utf-8") as f:
                yaml.safe_dump({"proxies": [{"name": "n", "type": "socks5",
                                             "server": "1.2.3.4", "port": 1080}]}, f)
        rep = validate.validate_outputs(root)
        assert sorted(rep["absent_optional"]) == ["fast", "secure", "verified"], \
            rep["absent_optional"]
        assert rep["summary"]["missing"] == 0, rep["summary"]
        assert rep["ok"] is True, rep


def test_validate_present_but_broken_optional_category_fails_the_gate() -> None:
    """
    نیمهٔ دومِ قاعده، و مهم‌ترش: «اختیاری» یعنی «ممکن است نباشد»، نه
    «اگر خراب بود اشکالی ندارد». یک `verified/` خراب باید انتشار را ببندد.
    """
    import tempfile
    with tempfile.TemporaryDirectory() as root:
        for cat in validate.CORE_CATEGORIES:
            os.makedirs(os.path.join(root, cat))
            with open(os.path.join(root, cat, "singbox.json"), "w",
                      encoding="utf-8") as f:
                json.dump({"outbounds": [{"type": "direct", "tag": "d"}]}, f)
            with open(os.path.join(root, cat, "clash.yaml"), "w",
                      encoding="utf-8") as f:
                yaml.safe_dump({"proxies": [{"name": "n", "type": "socks5",
                                             "server": "1.2.3.4", "port": 1080}]}, f)
        # دایرکتوریِ حاضر ولی نیمه‌نوشته: singbox هست، clash نیست
        os.makedirs(os.path.join(root, "verified"))
        with open(os.path.join(root, "verified", "singbox.json"), "w",
                  encoding="utf-8") as f:
            json.dump({"outbounds": [{"type": "direct", "tag": "d"}]}, f)

        rep = validate.validate_outputs(root)
        assert "verified" not in rep["absent_optional"], rep["absent_optional"]
        assert rep["results"]["verified"]["clash"]["status"] == "missing", \
            rep["results"]["verified"]
        assert rep["ok"] is False, "a half-written category must fail the gate"


def test_validate_always_checks_every_core_category() -> None:
    """
    ناوردا: دستهٔ اصلی هرگز از بررسی رد نمی‌شود، حتی وقتی غایب است — در آن
    حالت `missing` می‌شود و دروازه می‌شکند. اگر روزی `all/` در مسیرِ
    «تولیدنشده» بیفتد، دروازه با صفر کانفیگ سبز می‌ماند.
    """
    import tempfile
    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, "all"))
        with open(os.path.join(root, "all", "singbox.json"), "w",
                  encoding="utf-8") as f:
            json.dump({"outbounds": [{"type": "direct", "tag": "d"}]}, f)
        with open(os.path.join(root, "all", "clash.yaml"), "w",
                  encoding="utf-8") as f:
            yaml.safe_dump({"proxies": [{"name": "n", "type": "socks5",
                                         "server": "1.2.3.4", "port": 1080}]}, f)
        # heavy/ و light/ عمداً ساخته نمی‌شوند
        rep = validate.validate_outputs(root)
        for cat in validate.CORE_CATEGORIES:
            assert cat in rep["results"], f"{cat} must stay checked, not excused"
            assert cat not in rep["absent_optional"]
        assert rep["summary"]["missing"] == 4, rep["summary"]
        assert rep["ok"] is False



def _xray_knife_install_step() -> dict:
    """گامِ نصبِ xray-knife را از خودِ ورک‌فلو برمی‌گرداند.

    YAML پارس می‌شود، نه grepِ متنِ خام: کامنت‌های این فایل عمداً دلیلِ هر
    تصمیم را می‌نویسند، و آزمونی که رشته را در متنِ خام بجوید، با یک جملهٔ
    توضیحی هم سبز می‌شود بی‌آنکه گامی واقعاً وجود داشته باشد.
    """
    doc = yaml.safe_load(_workflow_text())
    for step in doc["jobs"]["aggregate"]["steps"]:
        if "Install xray-knife" in (step.get("name") or ""):
            return step
    raise AssertionError("no xray-knife install step in the workflow")


def test_workflow_installs_xray_knife_pinned_to_the_measured_version():
    """لایهٔ L3 بدونِ این ابزار وجود ندارد، و بدونِ pin قراردادش می‌شکند.

    چرا نسخه قفل است: خروجیِ CSVِ نسخهٔ ۱۰٫۱٫۱ پانزده ستون دارد و وضعیتِ
    غیرمستندِ `semi-passed` را تولید می‌کند. اگر upstream ستون‌ها را عوض کند،
    دستهٔ `verified/` بی‌صدا اشتباه پر می‌شود — نه با خطا، که بدترین حالت است.
    """
    step = _xray_knife_install_step()
    env = step.get("env") or {}
    assert env.get("XRAY_KNIFE_VERSION") == "10.1.1", \
        "the version must be pinned to the one whose CSV schema was measured"
    run = step["run"]
    # نسخه باید از همان متغیر ساخته شود، نه به‌صورتِ رشتهٔ ثابتِ دوم
    assert "${XRAY_KNIFE_VERSION}" in run, \
        "the download URL must derive from the pinned version variable"
    assert "lilendian0x00/xray-knife/releases/download" in run, \
        "the binary must come from the upstream release, not a mirror"


def test_workflow_verifies_both_the_xray_knife_archive_and_binary():
    """pinِ نسخه به‌تنهایی کافی نیست: assetِ یک انتشار قابلِ جای‌گزینی است.

    دو checksum لازم است، نه یکی:
      • sha256ِ آرشیو  → دانلودِ دست‌کاری‌شده را می‌گیرد
      • sha256ِ باینری → cacheِ خراب/آلوده را می‌گیرد، که آرشیو هرگز نمی‌بیند
    هر دو مقدار با فایلِ `.dgst`ِ رسمیِ upstream تطبیق داده شده‌اند.

    ⚠️ چرا «حضورِ رشته» سنجیده نمی‌شود: نگارشِ نخستِ این آزمون فقط بررسی
    می‌کرد که `$XRAY_KNIFE_ZIP_SHA256` جایی در متن هست و `exit 1` جایی هست.
    آزمونِ جهش نشانش داد که آن نگارش توخالی است: با تبدیلِ شرطِ آرشیو به
    `if false; then` سوئیت **سبز ماند**، چون رشته در پیامِ خطا هم بود و
    `exit 1` در شاخهٔ دیگر هم بود. پس اینجا خودِ *شرطِ مقایسه* و *بدنهٔ همان
    شرط* سنجیده می‌شود، نه حضورِ واژه‌ها.
    """
    step = _xray_knife_install_step()
    env = step.get("env") or {}
    assert env.get("XRAY_KNIFE_ZIP_SHA256") == \
        "39696103eb99b4cb55ae5d2c2456210d826f4bbcf0f89e298a05fb5fb82f09e5"
    assert env.get("XRAY_KNIFE_BIN_SHA256") == \
        "a3b10a40ccaf423d96836f9606ffec8b2e5f4fce36375eac1aadc10ba9c58034"
    run = step["run"]
    code = [ln for ln in run.splitlines() if not ln.strip().startswith("#")]
    assert run.count("sha256sum") >= 2, \
        "both the archive and the extracted binary must be hashed"

    # هر دو digest باید در یک شرطِ *واقعیِ نامساوی* به کار روند، و بدنهٔ آن
    # شرط باید job را بشکند. تابعِ کمکی هر دو را با هم می‌سنجد، چون جدا
    # سنجیدن‌شان همان سوراخی است که جهشِ m5 از آن گذشت.
    def _guarded(var: str) -> None:
        hits = [i for i, ln in enumerate(code)
                if var in ln and "!=" in ln and ln.strip().startswith("if ")]
        assert hits, (f"{var} must be compared with `!=` inside an `if`, "
                      f"not merely printed in a message")
        for i in hits:
            body = code[i + 1:i + 8]
            assert any("exit 1" in b for b in body), (
                f"the branch guarding {var} must `exit 1`; a warning would let "
                f"the job go green with an unverified binary")

    _guarded("$XRAY_KNIFE_ZIP_SHA256")
    _guarded("$XRAY_KNIFE_BIN_SHA256")


def test_workflow_verifies_the_xray_knife_binary_even_on_a_cache_hit():
    """این ظریف‌ترین بخشِ گام است و عمداً قفل شده.

    اگر تأییدِ باینری داخلِ شاخهٔ «اگر فایل نبود، دانلود کن» می‌بود، یک cacheِ
    آلوده کاملاً از کنترل می‌گشت و L3 با باینریِ ناشناس اجرا می‌شد. سنجش با
    یک cacheِ آلودهٔ ساختگی: خروج ۱ و فایلِ خراب پاک شد.
    """
    run = _xray_knife_install_step()["run"]
    lines = [ln.rstrip() for ln in run.splitlines()]

    # عمقِ تودرتویی را می‌شماریم، نه «بعد از نخستین fi بودن» را. تفاوت مهم
    # است: بلوکِ دانلود خودش یک `if`ِ داخلی برای checksumِ آرشیو دارد، پس
    # آزمونِ ساده‌ترِ «پس از نخستین fi» با یک رگرسیونِ واقعی هم سبز می‌ماند.
    # آزمونِ درست این است: مقایسهٔ باینری باید در عمقِ صفر باشد، یعنی هیچ
    # شرطی احاطه‌اش نکرده باشد.
    depth = 0
    depth_at = {}
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s == "fi":
            depth -= 1
        depth_at[i] = depth
        if s.startswith("if ") and s.endswith("then"):
            depth += 1
    assert depth == 0, f"unbalanced if/fi in the step body (ends at {depth})"

    bin_check = [i for i, ln in enumerate(lines)
                 if "$XRAY_KNIFE_BIN_SHA256" in ln and "sha256sum" not in ln]
    assert bin_check, "the binary digest must be compared somewhere"
    guard = min(bin_check)
    assert depth_at[guard] == 0, (
        "the binary checksum comparison must sit at the top level of the "
        "script, outside the `if [ ! -f $BIN ]` download branch — otherwise a "
        f"poisoned cache is never checked (found at nesting depth "
        f"{depth_at[guard]})")
    # و فایلِ ردشده باید حذف شود تا اجرای بعدی همان cacheِ خراب را نبیند
    assert 'rm -f "$BIN"' in run, \
        "a rejected binary must be deleted so the next run re-downloads"


def test_workflow_uses_the_xray_knife_flag_that_actually_exists():
    """آزمونِ زنده: `xray-knife version` خطای «unknown command» می‌دهد.

    پرچمِ درست `--version` است. اگر گام زیرفرمانِ نادرست را صدا می‌زد، با
    `set -e` کلِ job شکست می‌خورد — و آن شکست شبیهِ «ابزار خراب است» به نظر
    می‌رسید، نه «دستور اشتباه است».

    ⚠️ چرا کامنت‌ها حذف می‌شوند: نخستین نگارشِ این آزمون کلِ بدنهٔ `run:` را
    می‌کاوید و شکست خورد — ولی تنها تطبیق، *همین کامنت* بود که خروجیِ
    سنجیده‌شدهٔ ابزار («xray-knife version 10.1.1») را ثبت می‌کند. آن یک
    مثبتِ کاذب بود: ادعا دربارهٔ دستورهای اجرایی است، نه دربارهٔ مستندسازی.
    همین اصل در `test_workflow_never_uses_maxmind_...` هم به کار رفته: آزمونی
    که واژه را در متنِ خام ممنوع کند، مستندسازیِ درست را جریمه می‌کند.
    """
    import re as _re
    run = _xray_knife_install_step()["run"]
    assert "--version" in run, "the tool exposes --version, not a subcommand"
    code = "\n".join(ln for ln in run.splitlines()
                     if not ln.strip().startswith("#"))
    assert "--version" in code, \
        "the --version call must be real code, not only mentioned in a comment"
    assert not _re.search(r'xray-knife"?\s+version(\s|$)', code), \
        "`xray-knife version` is not a valid command in v10.1.1"


def test_workflow_caches_xray_knife_keyed_by_its_checksum():
    """۲۰ مگابایت × ۹۶ اجرا در روز، همان استدلالی که برای GeoIP به کار رفت.

    کلید شاملِ خودِ checksum است، پس تغییرِ pin به‌طورِ خودکار cache را
    بی‌اعتبار می‌کند و هیچ گامِ دستی‌ای فراموش نمی‌شود.
    """
    doc = yaml.safe_load(_workflow_text())
    caches = [s for s in doc["jobs"]["aggregate"]["steps"]
              if str(s.get("uses", "")).startswith("actions/cache")
              and "xray-knife" in str((s.get("with") or {}).get("path", ""))]
    assert caches, "the 57 MB binary must be cached, not re-downloaded 96×/day"
    key = str((caches[0].get("with") or {}).get("key", ""))
    assert "a3b10a40ccaf423d96836f9606ffec8b2e5f4fce36375eac1aadc10ba9c58034" in key, \
        "the cache key must embed the binary digest so re-pinning invalidates it"
    # مسیرِ cache باید gitignore شده باشد، وگرنه ۵۷ مگابایت commit می‌شود
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, ".gitignore"), encoding="utf-8") as f:
        assert ".cache/" in f.read(), ".cache/ must stay gitignored"



# ──────────────────────────────────────────────────────────────────────────────
# B4 — لایهٔ L3 (`realtest.py`): داوریِ سطر، تجزیهٔ CSV، و بستنِ مسیرهای قفل
#
# هر تستِ زیر به یک **سنجشِ زنده** گره خورده، نه به یک حدس. مرجعِ عددها
# سرشماریِ کاملِ ۳٬۸۴۵ سطری است (۴۴۹ passed · ۵۵ semi-passed · ۳٬۲۵۴ failed ·
# ۸۷ broken = ۵۰۴ موفق).
# ──────────────────────────────────────────────────────────────────────────────

#: سرآیندِ راستینِ CSV، برای ساختنِ ورودیِ تستی
_L3_HEADER = ("link,status,reason,tls,ip,delay,code,download,upload,"
              "location,ttfb,connect_time,success,total,endpoints")


class _FakeXk:
    """
    یک «xray-knife»ِ قلابی برای آزمونِ **رفتاریِ** آفلاین.

    چرا لازم است؟ چون آزمونِ جهش (m12/m17/m21) نشان داد تست‌هایی که فقط
    متنِ کد را می‌خوانند توخالی‌اند: با `if False:` رشتهٔ موردِ نظر هنوز در
    کد هست و تست سبز می‌ماند. تنها راهِ اثباتِ *رفتار*، اجرای واقعیِ
    `run_test` است — ولی بی نیاز به شبکه و بی نیاز به باینریِ ۵۷ مگابایتی.

    این شیم یک اسکریپتِ پوسته است که:
      • آرگومان‌های خود را در `argv.log` می‌نویسد (برای بازرسیِ پرچم‌ها)
      • اگر `csv_text` داده شده باشد، آن را در مسیرِ `-o` می‌نویسد
      • اگر `csv_text` تهی باشد، **هیچ فایلی نمی‌سازد** ولی `rc=0` می‌دهد —
        یعنی همان رفتارِ سنجیده‌شدهٔ «پوشهٔ والدِ ناموجود»
      • اگر `dedup_to` داده شود، فقط همان تعداد سطر می‌نویسد — یعنی همان
        رفتارِ سنجیده‌شدهٔ `--max-passed` (خروجیِ ناقص)
    """

    def __init__(self, csv_text: str = None, rc: int = 0,
                 rows_from_input: bool = False) -> None:
        self.csv_text = csv_text
        self.rc = rc
        self.rows_from_input = rows_from_input
        self.dir = ""
        self.binary = ""

    def __enter__(self) -> "_FakeXk":
        import stat
        import tempfile
        self.dir = tempfile.mkdtemp(prefix="fakexk_")
        self.binary = os.path.join(self.dir, "xray-knife")
        payload = os.path.join(self.dir, "payload.csv")
        if self.csv_text is not None:
            with open(payload, "w", encoding="utf-8") as fh:
                fh.write(self.csv_text)
        # اسکریپت عمداً ساده است: هرچه کمتر منطق، کمتر جای اشتباهِ خودِ شیم
        script = [
            "#!/bin/sh",
            'printf "%s\\n" "$@" > "$(dirname "$0")/argv.log"',
            "OUT=''",
            "while [ $# -gt 0 ]; do",
            '  if [ "$1" = "-o" ]; then OUT="$2"; fi',
            '  if [ "$1" = "-f" ]; then IN="$2"; fi',
            "  shift",
            "done",
            'echo "🎉 Results have been saved to $OUT"',
        ]
        if self.csv_text is not None:
            if self.rows_from_input:
                # یک سطرِ CSV برای هر لینکِ *یکتای* ورودی — همان کاری که
                # ابزارِ واقعی می‌کند («Removed N duplicate config link(s)»)
                script += [
                    f'head -1 "{payload}" > "$OUT"',
                    'sort -u "$IN" | while IFS= read -r L; do',
                    '  [ -n "$L" ] || continue',
                    '  printf "%s,passed,,tls,9.9.9.9,120,204,0,0,US,119,8,'
                    '1,1,cp.cloudflare.com=ok(120ms)\\n" "$L" >> "$OUT"',
                    "done",
                ]
            else:
                script += [f'cp "{payload}" "$OUT"']
        script += [f"exit {int(self.rc)}"]
        with open(self.binary, "w", encoding="utf-8") as fh:
            fh.write("\n".join(script) + "\n")
        os.chmod(self.binary, os.stat(self.binary).st_mode | stat.S_IEXEC)
        return self

    def __exit__(self, *exc: object) -> None:
        import shutil as _shutil
        _shutil.rmtree(self.dir, ignore_errors=True)

    def input(self, *links: str) -> str:
        """یک فایلِ ورودی با لینک‌های داده‌شده می‌سازد و مسیرش را می‌دهد."""
        path = os.path.join(self.dir, "in.txt")
        with open(path, "w", encoding="utf-8") as fh:
            for link in links:
                fh.write(link + "\n")
        return path

    def argv(self) -> list:
        """آرگومان‌هایی که واقعاً به فرزند رسیدند."""
        path = os.path.join(self.dir, "argv.log")
        if not os.path.isfile(path):
            return []
        with open(path, encoding="utf-8") as fh:
            return [ln.rstrip("\n") for ln in fh if ln.strip()]


def _l3_row(link: str = "vless://x@1.2.3.4:443#a", status: str = "passed",
            reason: str = "", tls: str = "tls", ip: str = "9.9.9.9",
            delay: str = "120", code: str = "204", location: str = "US",
            ttfb: str = "119", connect_time: str = "8",
            success: str = "1", total: str = "1",
            endpoints: str = "cp.cloudflare.com=ok(120ms)") -> str:
    """یک سطرِ CSV با شکلِ *دقیقاً* سنجیده‌شده؛ هر ستون قابلِ بازنویسی."""
    import csv as _csv
    import io as _io
    buf = _io.StringIO()
    _csv.writer(buf, lineterminator="").writerow(
        [link, status, reason, tls, ip, delay, code, "0", "0", location,
         ttfb, connect_time, success, total, endpoints])
    return buf.getvalue()


def _l3_csv(*rows: str) -> str:
    return _L3_HEADER + "\n" + "\n".join(rows) + "\n"


def test_realtest_accepts_semi_passed_because_it_means_rip_failed() -> None:
    """
    `semi-passed` باید **پذیرفته** شود — و این اصلاحِ پلنِ خودِ ما است.

    پلنِ اولیه ردکردنش را خواسته بود، بر پایهٔ متنِ راهنما نه داده. سنجشِ
    ۵۵ سطرِ `semi-passed` در سرشماریِ کامل، با صفر استثنا: `success == total`،
    `code == 204`، `endpoints=...ok(NNNms)`، `reason == "ip_info_failed"`،
    و `ip`/`location` برابرِ رشتهٔ `null`. یعنی پروکسی کامل کار کرده و فقط
    جست‌وجویِ *اختیاریِ* اطلاعاتِ IP شکست خورده. ردکردنش ۵۵ کانفیگِ سالم
    (۱۰٫۹٪ از خروجیِ نهایی) را خاموشانه دور می‌ریخت.
    """
    semi = {"status": "semi-passed", "reason": "ip_info_failed",
            "ip": "null", "location": "null", "delay": "101", "code": "204",
            "success": "1", "total": "1",
            "endpoints": "cp.cloudflare.com=ok(101ms)"}
    assert realtest.is_row_genuinely_ok(semi), (
        "semi-passed must be accepted: measured on 55/55 rows it means the "
        "proxy worked and only the optional --rip lookup failed")
    assert "semi-passed" in realtest.OK_STATUSES, \
        "OK_STATUSES must carry semi-passed, not only passed"
    # و location برای این سطرها None است، نه رشتهٔ "null"
    assert realtest.row_location(semi) is None, \
        "the literal string 'null' must not leak out as a country code"


def test_realtest_rejects_broken_rows_whose_success_equals_total() -> None:
    """
    سوراخِ واقعیِ قفل: سطرهای `broken` مقدارِ `success=0, total=0` دارند، پس
    شرطِ `success == total` برایشان **درست** است (۰ == ۰).

    سنجش: هر ۸۷ سطرِ `broken` در سرشماری این شرط را برآورده می‌کنند. بی
    شرطِ `total >= 1` همه‌شان «موفق» شمرده می‌شدند. این تست همان سوراخ را
    قفل می‌کند.
    """
    broken = {"status": "broken",
              "reason": "infra/conf: failed to build outbound handler",
              "ip": "null", "location": "null", "delay": "-1", "code": "-1",
              "success": "0", "total": "0", "endpoints": ""}
    assert broken["success"] == broken["total"], \
        "this fixture must reproduce the real hole: success == total (0 == 0)"
    assert not realtest.is_row_genuinely_ok(broken), (
        "a broken row satisfies success == total; only `total >= 1` keeps it "
        "out. All 87 broken rows in the census have total=0")
    # و همان سطر با total=0 ولی status موفق هم باید رد شود
    sneaky = dict(broken, status="passed", code="204")
    assert not realtest.is_row_genuinely_ok(sneaky), \
        "total=0 must be rejected regardless of the status label"


def test_realtest_requires_a_successful_http_code() -> None:
    """
    کدِ HTTP باید در بازهٔ موفق باشد. سنجش: تنها دو مقدار در سرشماری دیده
    شد — `204` روی هر ۵۰۴ سطرِ موفق و `-1` روی هر ۳٬۳۴۱ سطرِ ناموفق.
    """
    ok = {"status": "passed", "success": "1", "total": "1", "code": "204"}
    assert realtest.is_row_genuinely_ok(ok)
    for bad_code in ("-1", "0", "403", "500", "null", "", "abc"):
        row = dict(ok, code=bad_code)
        assert not realtest.is_row_genuinely_ok(row), \
            f"code={bad_code!r} is not a successful response"


def test_realtest_rejects_partial_endpoint_success() -> None:
    """
    اگر بخشی از نقاطِ پایانی موفق شده باشند (`success < total`) سطر پذیرفته
    نمی‌شود. سنجش: هر ۳٬۲۵۴ سطرِ `failed` الگویِ `success=0, total=1` دارند.
    """
    row = {"status": "passed", "success": "1", "total": "3", "code": "204"}
    assert not realtest.is_row_genuinely_ok(row), \
        "success must equal total; 1 of 3 endpoints is not a working config"
    assert realtest.is_row_genuinely_ok(dict(row, success="3"))


def test_realtest_guard_reproduces_the_measured_census_exactly() -> None:
    """
    قفلِ عددی باید دقیقاً همان مجموعه‌ای را بپذیرد که برچسبِ وضعیت می‌گوید —
    نه سخت‌گیرتر، نه سست‌تر.

    سنجشِ مرجع روی ۳٬۸۴۵ سطر: قفل ۵۰۴ سطر را پذیرفت و مجموعه‌اش با
    مجموعهٔ `status ∈ {passed, semi-passed}` اختلافِ دوسویهٔ صفر داشت. این
    تست همان هم‌ارزی را روی نمونه‌ای که هر چهار وضعیت را دارد بازآزمایی
    می‌کند.
    """
    rows = realtest.parse_csv(_l3_csv(
        _l3_row(link="p1", status="passed"),
        _l3_row(link="s1", status="semi-passed", reason="ip_info_failed",
                ip="null", location="null"),
        _l3_row(link="f1", status="failed", reason="Get ...: refused",
                ip="null", location="null", delay="-1", code="-1",
                ttfb="0", connect_time="0", success="0", total="1",
                endpoints="cp.cloudflare.com=error"),
        _l3_row(link="b1", status="broken", reason="parse protocol: ...",
                tls="", ip="null", location="null", delay="-1", code="-1",
                ttfb="0", connect_time="0", success="0", total="0",
                endpoints=""),
    ))
    by_guard = {r["link"] for r in rows if realtest.is_row_genuinely_ok(r)}
    by_label = {r["link"] for r in rows
                if r["status"] in realtest.OK_STATUSES}
    assert by_guard == by_label == {"p1", "s1"}, (
        f"the numeric guard and the status label must agree; guard={by_guard} "
        f"label={by_label}")

    res = realtest.classify(rows)
    assert res["stats"]["ok"] == 2
    assert res["stats"]["failed"] == 1
    assert res["stats"]["broken"] == 1
    assert res["stats"]["by_status"] == {
        "passed": 1, "semi-passed": 1, "failed": 1, "broken": 1}
    # broken جدا از failed شمرده می‌شود: broken دادهٔ بد است (در سرچشمه قابلِ
    # تعمیر)، failed سرورِ مرده است (طبیعی و گذرا)
    assert res["broken"] == ["b1"] and res["failed"] == ["f1"], \
        "broken and failed are different problems and must stay separate"


def test_realtest_parses_csv_with_commas_inside_quoted_fields() -> None:
    """
    تجزیه باید با ماژولِ `csv` باشد، نه `split(",")`.

    سنجش روی سرشماریِ ۳٬۸۴۵ سطری: **۲۳۶ سطر** با تفکیکِ سادهٔ کاما تعدادِ
    ستونِ اشتباه می‌دادند (۱۸۲ لینک خودشان کاما دارند و ۳٬۳۲۱ سطر
    گیومه‌گذاری‌شده‌اند). یعنی تفکیکِ ساده ~۶٪ داده را خراب می‌کرد.
    """
    link = "vless://u@1.2.3.4:443?type=tcp#remark, with comma"
    reason = 'https://x: Get "https://x": bad, very bad'
    text = _l3_csv(_l3_row(link=link, status="failed", reason=reason,
                           ip="null", location="null", delay="-1", code="-1",
                           success="0", total="1",
                           endpoints="cp.cloudflare.com=error"))
    # پیش‌شرط: این سطر واقعاً تله‌ی کاما دارد
    data_line = text.splitlines()[1]
    assert len(data_line.split(",")) != 15, \
        "this fixture must actually break a naive split(',')"

    rows = realtest.parse_csv(text)
    assert len(rows) == 1
    assert rows[0]["link"] == link, \
        "the link must survive parsing byte-for-byte, commas included"
    assert rows[0]["reason"] == reason
    assert rows[0]["endpoints"] == "cp.cloudflare.com=error", \
        "the last column must not absorb a shifted field"


def test_realtest_raises_on_a_changed_csv_schema() -> None:
    """
    اگر بالادست شِما را عوض کند باید **بلند** بشکنیم. خواندنِ خاموشِ ستونِ
    اشتباه یعنی داوریِ غلط روی هر کانفیگ.
    """
    assert len(realtest.CSV_COLUMNS) == 15, \
        "the measured contract is exactly 15 columns"
    for bad, label in (
            ("link,status\nx,passed\n", "too few columns"),
            (_L3_HEADER + ",extra\n", "an added column"),
            ("a,b,c,d,e,f,g,h,i,j,k,l,m,n,o\n", "renamed columns"),
    ):
        try:
            realtest.parse_csv(bad)
        except realtest.MalformedCsv:
            pass
        else:
            raise AssertionError(
                f"{label} must raise MalformedCsv, not parse silently")
    # ورودیِ تهی خطا نیست — صفر سطر است
    assert realtest.parse_csv("") == []
    assert realtest.parse_csv("   \n") == []


def test_realtest_refuses_an_empty_input_that_would_hang_the_job() -> None:
    """
    ★ مسیرِ قفل‌شدنِ CI، بسته‌شده پیش از فراخوانی.

    سنجشِ زنده زیرِ شرطِ واقعیِ CI (stdin یک FIFO که بسته نمی‌شود):

        فایلِ تهی     + stdin باز    → rc=124 (قفل روی «Please enter a config link»)
        فایلِ ناموجود  + stdin باز    → rc=124 (قفل)
        فایلِ تهی     + `</dev/null` → rc=1   (شکستِ پاک)

    در CI ورودیِ استاندارد بسته نمی‌شود، پس job تا سقفِ ۶ ساعتِ GitHub
    می‌سوزد و `concurrency: group: aggregate` هر اجرایِ بعدی را هم در صف
    نگه می‌دارد. حالتِ «فایلِ تهی» واقع‌بینانه است: هر بار که L2 صفر نقطهٔ
    بازِ باقی بگذارد همین رخ می‌دهد.

    ★ نکتهٔ حیاتیِ طراحیِ تست (اصلاحیهٔ جهشِ m21): هر فراخوانی در این‌جا
    یک `binary=` **عمداً ناموجود** می‌فرستد. دلیل: اگر `run_test` روزی
    باینری را **پیش از** ورودی resolve کند، روی ماشینی که ابزار نصب است
    (مثلِ CI و مثلِ محیطِ جهش‌سنجی که `L3_XK_BIN` را ست می‌کند) خطا هم‌چنان
    `EmptyInput` می‌شود و تست الکی سبز می‌ماند — یعنی تست توخالی است.
    با باینریِ ناموجود، ترتیبِ غلط ناچار `XrayKnifeMissing` می‌دهد و شاخهٔ
    `except` زیر آن را به‌عنوان شکست اعلام می‌کند. این تست باید بدونِ
    هیچ ابزارِ نصب‌شده‌ای و **مستقل از محیط** معنا داشته باشد.
    """
    import tempfile as _tf
    absent_xk = os.path.join(_tf.mkdtemp(prefix="l3_noxk_"), "xray-knife")
    assert not os.path.exists(absent_xk), "the shim path must not exist"

    missing = os.path.join(_tf.mkdtemp(prefix="l3_none_"), "nope.txt")
    try:
        realtest.run_test(missing, binary=absent_xk)
    except realtest.EmptyInput:
        pass
    except realtest.XrayKnifeMissing:
        raise AssertionError(
            "the input check must come BEFORE the binary lookup, otherwise a "
            "machine without the tool never exercises the hang guard")
    else:
        raise AssertionError("a missing input file must raise EmptyInput")

    for content, label in (("", "a zero-byte file"),
                           ("\n   \n\t\n", "a whitespace-only file")):
        path = os.path.join(_tf.mkdtemp(prefix="l3_empty_"), "in.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        try:
            realtest.run_test(path, binary=absent_xk)
        except realtest.EmptyInput:
            pass
        except realtest.XrayKnifeMissing:
            raise AssertionError(
                f"{label}: the input check must come BEFORE the binary lookup")
        else:
            raise AssertionError(
                f"{label} must raise EmptyInput; measured rc=124 otherwise")


def test_realtest_never_lets_the_subprocess_inherit_stdin() -> None:
    """
    لایهٔ دومِ دفاع در برابرِ قفل: حتی اگر بررسیِ ورودی روزی دور زده شود،
    فرزند نباید ورودیِ استاندارد را به ارث ببرد.

    این تست به **کدِ اجرایی** نگاه می‌کند نه به مستندات، چون یک رشتهٔ درستِ
    داخلِ توضیحات هیچ چیزی را تضمین نمی‌کند (درسِ بندِ B3: تستی که با یک
    کامنت سبز می‌شود توخالی است).
    """
    import inspect as _inspect
    import re as _re
    src = _inspect.getsource(realtest.run_test)
    code = "\n".join(ln for ln in src.splitlines()
                     if not ln.strip().startswith("#"))
    assert _re.search(r"stdin\s*=\s*subprocess\.DEVNULL", code), \
        "run_test must pass stdin=subprocess.DEVNULL in real code"
    assert _re.search(r"timeout\s*=\s*limit", code), \
        "run_test must pass a hard timeout to subprocess.run"


def test_realtest_deletes_a_stale_output_before_running() -> None:
    """
    ★ خطرناک‌ترین موردِ سنجیده‌شده: خروجیِ کهنه زنده می‌ماند.

    سنجش: CSVای با سطرِ `STALE_MARKER,passed` ساختیم و اجرایِ شکست‌خورده
    (فایلِ تهی) را با همان `-o` صدا زدیم؛ نتیجه `rc=1` بود و
    `STALE_MARKER` **دست‌نخورده باقی ماند**. بی حذفِ پیش از اجرا، دادهٔ
    دفعهٔ قبل «نتیجهٔ تازه» خوانده می‌شود.

    این تست **رفتاری** است، نه متنی: با یک باینریِ قلابی اجرا می‌شود.
    نسخهٔ اولش فقط `"OutputNotWritten" in code` را می‌سنجید و آزمونِ جهش
    (m12) نشانش داد توخالی است — با `if False: raise OutputNotWritten` آن
    رشته هنوز در کد بود و تست سبز می‌ماند. درسِ تکراریِ بندِ B3: «رشته
    حاضر است» هیچ چیزی را اثبات نمی‌کند.
    """
    stale = _l3_csv(_l3_row(link="STALE_MARKER_LINK", status="passed"))
    fresh = _l3_csv(_l3_row(link="FRESH_LINK", status="passed"))

    # ۱) خروجیِ کهنه باید ناپدید شود، نه این‌که با نتیجهٔ تازه قاطی شود
    with _FakeXk(csv_text=fresh) as fake:
        out = os.path.join(fake.dir, "out.csv")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(stale)
        res = realtest.run_test(fake.input("l1"), out_path=out,
                                binary=fake.binary)
        assert "STALE_MARKER_LINK" not in res["rows"], (
            "the previous run's rows were read as fresh results; measured: a "
            "failed run leaves the old CSV fully intact")
        assert "FRESH_LINK" in res["rows"]

    # ۱ب) موردِ **تمیزکنندهٔ** واقعی: اجرایی که هیچ فایلی نمی‌نویسد ولی
    #     rc=0 می‌دهد (رفتارِ سنجیده‌شدهٔ «پوشهٔ والدِ ناموجود»). اگر حذفِ
    #     پیش از اجرا نباشد، CSVِ کهنه سرِ جایش می‌ماند و بی هیچ هشداری
    #     «نتیجهٔ تازه» خوانده می‌شود — دقیقاً همان چیزی که سنجیدیم.
    #     زیرموردِ ۱ به‌تنهایی این را نمی‌گیرد، چون در آن اجرا خروجیِ تازه
    #     روی فایلِ کهنه بازنویسی می‌شود و اثرِ حذف دیده نمی‌شود.
    with _FakeXk(csv_text=None) as fake:
        out = os.path.join(fake.dir, "out.csv")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(stale)
        try:
            res = realtest.run_test(fake.input("l1b"), out_path=out,
                                    binary=fake.binary)
        except realtest.OutputNotWritten:
            pass
        else:
            raise AssertionError(
                "the stale CSV was not deleted before the run, so a run that "
                "wrote nothing returned the previous run's rows as fresh "
                f"results: {sorted(res['rows'])!r}")

    # ۲) پوشهٔ والدِ ناموجود باید ساخته شود، وگرنه دادهٔ کامل گم می‌شود
    with _FakeXk(csv_text=fresh) as fake:
        out = os.path.join(fake.dir, "no", "such", "dir", "out.csv")
        res = realtest.run_test(fake.input("l2"), out_path=out,
                                binary=fake.binary)
        assert os.path.isfile(out), (
            "run_test must create the output parent; measured: xray-knife "
            "exits 0 and prints 'Results have been saved to ...' while "
            "creating nothing")
        assert "FRESH_LINK" in res["rows"]

    # ۳) rc=0 بدونِ فایل باید **بلند** بشکند، نه «صفر کانفیگِ سالم» بدهد
    with _FakeXk(csv_text=None) as fake:          # موفق می‌شود، ولی نمی‌نویسد
        out = os.path.join(fake.dir, "never.csv")
        try:
            realtest.run_test(fake.input("l3"), out_path=out,
                              binary=fake.binary)
        except realtest.OutputNotWritten:
            pass
        else:
            raise AssertionError(
                "exit code 0 with no output file must raise OutputNotWritten; "
                "silently reporting zero working configs hides total data loss")


def test_realtest_pins_the_test_url_instead_of_trusting_the_default() -> None:
    """
    نشانیِ آزمون یک متغیرِ پنهان بود.

    سنجش: اجراهای مرجعِ ما HTTP 204 ثبت کرده‌اند چون
    `https://cp.cloudflare.com/generate_204` را داده بودند؛ ولی پیش‌فرضِ
    v10.1.1 یعنی `https://cloudflare.com/cdn-cgi/trace` که HTTP 200 می‌دهد.
    بی تثبیتِ صریح، نتایجِ دو اجرا قابلِ مقایسه نیستند.
    """
    assert realtest.TEST_URL == "https://cp.cloudflare.com/generate_204", \
        "the reference URL must stay pinned to the one that was measured"
    argv = realtest.build_argv("in.txt", "out.csv", binary="xk")
    assert "-u" in argv, "the URL must be passed explicitly, never defaulted"
    assert argv[argv.index("-u") + 1] == realtest.TEST_URL
    # و `--rip` نباید خاموش شود: سنجشِ A/B نشان داد با `--rip=false` ستونِ
    # location در صفر سطر پر می‌شود، که بندِ B6b را ناممکن می‌کند
    joined = " ".join(argv)
    assert "--rip=false" not in joined and "-r=false" not in joined, \
        "--rip must stay on; measured: with --rip=false, location is never set"
    # پرچم‌های سنجیده‌شده و ردشده نباید به‌طورِ پیش‌فرض حاضر باشند
    assert "--retries" not in joined, \
        "--retries hides the measured 32.7% flakiness inside a single run"
    assert "--max-passed" not in joined, \
        "--max-passed yields partial output; absence must never mean failure"
    assert "--prescan" not in joined, "--prescan was measured and rejected"


def test_realtest_marks_partial_output_but_not_mere_deduplication() -> None:
    """
    نبودِ یک لینک در CSV هرگز «شکست خورد» نیست.

    دو سنجشِ جدا: (الف) `--max-passed 2 -t 5` پنج سطر داد (۲ موفق + ۳
    نیمه‌کاره) — یعنی خروجی ناقص است. (ب) خودِ ابزار تکراری‌ها را حذف
    می‌کند («Removed 2 duplicate config link(s). Testing 1 unique configs»)
    — یعنی کمتربودنِ سطرها از *سطرهای ورودی* به‌تنهایی نشانهٔ نقص نیست.
    پس مقایسه باید با لینک‌های **یکتا** باشد، نه با تعدادِ سطرها.

    این تست **رفتاری** است. نسخهٔ اولش فقط `"unique" in code` را می‌سنجید و
    آزمونِ جهش (m17) نشانش داد توخالی است: با مقایسهٔ اشتباه در برابرِ
    تعدادِ سطرهای خام، آن واژه هنوز جایی در کد بود و تست سبز می‌ماند.
    """
    row = _l3_row(link="LINK_A", status="passed")

    # (الف) ورودیِ دارای تکرار: ۳ سطر، ۱ لینکِ یکتا، ۱ سطرِ CSV.
    #       این **ناقص نیست** — خودِ ابزار تکراری‌ها را حذف می‌کند.
    with _FakeXk(csv_text=_l3_csv(row)) as fake:
        path = fake.input("LINK_A", "LINK_A", "LINK_A")
        res = realtest.run_test(path, out_path=os.path.join(fake.dir, "o.csv"),
                                binary=fake.binary)
        assert res["stats"]["lines_in"] == 3
        assert res["stats"]["unique_in"] == 1
        assert res["partial"] is False, (
            "deduplication is not partial output; comparing against raw line "
            "count would mislabel every input that repeats a link, and the "
            "tool itself prints 'Removed N duplicate config link(s)'")

    # (ب) خروجیِ واقعاً ناقص: ۲ لینکِ یکتا، ولی CSV تنها یکی را دارد.
    #     سنجش: `--max-passed 2 -t 5` پنج سطر داد از ۲۰ لینک — پس نبودِ یک
    #     لینک هرگز «شکست خورد» نیست.
    with _FakeXk(csv_text=_l3_csv(row)) as fake:
        path = fake.input("LINK_A", "LINK_B")
        res = realtest.run_test(path, out_path=os.path.join(fake.dir, "o.csv"),
                                binary=fake.binary)
        assert res["stats"]["unique_in"] == 2 and len(res["rows"]) == 1
        assert res["partial"] is True, (
            "a link missing from the CSV must mark the result partial, never "
            "be silently counted as a failure")
        assert "LINK_B" not in res["failed"], \
            "an untested link must not appear in the failed bucket"

    # قراردادِ خروجی: کلیدهایی که بندهای B5/B6/B7/B13 روی آن‌ها حساب می‌کنند
    res = realtest.classify(realtest.parse_csv(_l3_csv(
        _l3_row(link="p1"),
        _l3_row(link="f1", status="failed", success="0", total="1",
                code="-1", delay="-1"))))
    for key in ("ok", "failed", "broken", "rows", "stats"):
        assert key in res, f"the B5/B6/B7/B13 contract needs the {key!r} key"
    assert res["rows"]["p1"]["status"] == "passed", \
        "rows must map link -> full row so later items can read every column"


def test_realtest_exposes_delay_and_tls_for_the_fast_and_secure_buckets() -> None:
    """
    بندهای B6 (`fast/`) و B7 (`secure/`) از همین دو کمک‌تابع تغذیه می‌شوند،
    پس قراردادشان همین‌جا تثبیت می‌شود.

    سنجشِ سرشماری: بازهٔ تأخیرِ سطرهای موفق ۵۴ تا ۴٬۷۷۶ میلی‌ثانیه، میانهٔ
    ۶۷۵؛ و مقادیرِ `tls` عبارت‌اند از `tls` (۲٬۰۳۲) · تهی (۸۲۸) ·
    `none` (۵۶۵) · `reality` (۴۱۴) · `false` (۴) · `…` (۱) · `auto` (۱).
    """
    assert realtest.row_delay_ms({"delay": "674"}) == 674
    for bad in ("-1", "null", "", "abc"):
        assert realtest.row_delay_ms({"delay": bad}) is None, \
            f"delay={bad!r} must not be reported as a real latency"
    assert realtest.row_tls({"tls": "reality"}) == "reality"
    assert realtest.row_tls({"tls": ""}) == ""
    assert realtest.row_tls({}) == "", "a missing column must not raise"
    assert realtest.row_location({"location": "NL"}) == "NL"
    for bad in ("null", "", "   "):
        assert realtest.row_location({"location": bad}) is None, \
            f"location={bad!r} must be reported as unknown, not as a country"


def test_realtest_stats_are_internally_consistent() -> None:
    """
    آمار باید خودسازگار باشد: هر سطر دقیقاً در یک سبد، و مجموع = تعدادِ سطرها.
    یک ناسازگاریِ خاموش در آمار یعنی گزارشِ سلامتِ دروغین در بندِ B13.
    """
    rows = realtest.parse_csv(_l3_csv(
        _l3_row(link="p1"), _l3_row(link="p2"),
        _l3_row(link="s1", status="semi-passed", ip="null", location="null"),
        _l3_row(link="f1", status="failed", success="0", total="1",
                code="-1", delay="-1"),
        _l3_row(link="b1", status="broken", success="0", total="0",
                code="-1", delay="-1", endpoints=""),
    ))
    res = realtest.classify(rows)
    s = res["stats"]
    assert s["rows"] == 5
    assert s["ok"] + s["failed"] + s["broken"] == s["rows"], \
        "every row must land in exactly one bucket"
    assert len(res["ok"]) == s["ok"] and len(res["failed"]) == s["failed"]
    assert sum(s["by_status"].values()) == s["rows"]
    assert set(s["by_status"]) == set(realtest.ALL_STATUSES), \
        "every measured status must be reported even at zero"
    assert s["ok_pct"] == 60.0
    # ۳ سطرِ موفق، ولی یکی از آن‌ها location ندارد
    assert s["with_location"] == 2, \
        "semi-passed rows carry no country; B6b must not over-count"
    assert s["delay_min"] == 120 and s["delay_max"] == 120


def test_realtest_reports_an_unknown_status_instead_of_hiding_it() -> None:
    """
    سنجشِ ما فقط چهار وضعیت را ثبت کرده. اگر روزی پنجمی بیاید، باید دیده
    شود — نه این‌که خاموشانه در سبدِ «ناموفق» گم شود.
    """
    rows = realtest.parse_csv(_l3_csv(
        _l3_row(link="x1", status="totally-new-status")))
    res = realtest.classify(rows)
    assert "unknown_status" in res["stats"], \
        "a fifth status value means upstream changed; it must surface"
    assert res["stats"]["unknown_status"] == {"totally-new-status": 1}
    assert res["stats"]["ok"] == 0, \
        "an unrecognised status must never be treated as working"




# ──────────────────────────────────────────────────────────────────────────────
# آبشارِ چهارلایه — بندهای B5/B6/B7/B8/B11
# ──────────────────────────────────────────────────────────────────────────────

def _pl_row(link: str, status: str = "passed", delay: int = 120,
            tls: str = "tls", code: int = 204, success: int = 1,
            total: int = 1) -> dict:
    """یک ردیفِ CSVِ L3 به‌شکلِ دیکشنری — همان ۱۵ ستونِ واقعی."""
    return {
        "link": link, "status": status, "reason": "", "tls": tls,
        "ip": "9.9.9.9", "delay": str(delay), "code": str(code),
        "download": "0", "upload": "0", "location": "US", "ttfb": "119",
        "connect_time": "8", "success": str(success), "total": str(total),
        "endpoints": "cp.cloudflare.com=ok",
    }


class _StubL3:
    """
    جایگزینِ `realtest.test_lines` که نتیجهٔ **هر اجرا را جداگانه** می‌دهد.

    چرا لازم است؟ چون قاعدهٔ «پایدار = موفق در همهٔ اجراها» تنها وقتی
    سنجیدنی است که اجراها بتوانند **با هم اختلاف داشته باشند**. یک شیمِ
    ثابت این قاعده را غیرقابلِ‌مشاهده می‌کند و تست را توخالی.
    """

    def __init__(self, per_round: list) -> None:
        self.per_round = per_round
        self.calls = 0
        self.seen_lines = []
        self._orig = None

    def __enter__(self) -> "_StubL3":
        self._orig = realtest.test_lines

        def fake(lines, **kwargs):
            self.seen_lines.append(list(lines))
            rows = self.per_round[min(self.calls, len(self.per_round) - 1)]
            self.calls += 1
            # شکلِ **واقعیِ** `realtest.run_test`: نقشهٔ لینک→ردیف، نه لیست.
            # این نکته با هزینه آموخته شد: شیمِ قبلی لیست می‌داد، همهٔ
            # آزمون‌ها سبز بودند و اجرای واقعی با
            # `'str' object has no attribute 'get'` شکست. یک فِیکِ
            # بدشکل، آزمون را از «اثبات» به «توهم» تبدیل می‌کند.
            return {"rows": {(r.get("link") or ""): r for r in rows}}

        realtest.test_lines = fake
        return self

    def __exit__(self, *exc: object) -> None:
        realtest.test_lines = self._orig


def test_pipeline_stable_requires_success_in_every_round():
    """
    قاعدهٔ B4b: «پایدار» = موفق در **همهٔ** اجراهای دور.

    سنجشِ واقعی که این قاعده را ساخت: از ۶۲۶ کانفیگی که دست‌کم یک بار کار
    کرد، تنها ۲۲۴ همیشه کار کرد ⇒ ۶۴٪ لرزان. پس «یک بار موفق» کافی نیست.
    """
    always = "vless://a@1.1.1.1:443?security=tls#always"
    sometimes = "vless://b@2.2.2.2:443?security=tls#sometimes"
    never = "vless://c@3.3.3.3:443?security=tls#never"

    rounds = [
        [_pl_row(always), _pl_row(sometimes), _pl_row(never, status="failed",
                                                     code=-1, success=0)],
        [_pl_row(always), _pl_row(sometimes, status="failed", code=-1,
                                 success=0), _pl_row(never, status="failed",
                                                     code=-1, success=0)],
        [_pl_row(always), _pl_row(sometimes), _pl_row(never, status="failed",
                                                     code=-1, success=0)],
    ]
    with _StubL3(rounds) as stub:
        res = pipeline.run_l3_round([always, sometimes, never], rounds=3)

    assert stub.calls == 3, \
        f"the round must run L3 exactly 3 times, ran {stub.calls}"
    assert res["stable"] == {always}, \
        ("only a config that succeeded in EVERY round may be stable; got "
         f"{sorted(res['stable'])!r}")
    assert res["ever_ok"] == {always, sometimes}, \
        f"ever_ok must union all rounds; got {sorted(res['ever_ok'])!r}"
    assert never not in res["ever_ok"], \
        "a config that never succeeded must not appear anywhere"
    # ۱ از ۲ لینکی که کار کرد، لرزان بود
    assert res["flaky_pct"] == 50.0, \
        f"flaky share must be measured and reported; got {res['flaky_pct']}"


def test_pipeline_one_bad_round_cannot_be_ignored():
    """
    کنترلِ منفی: اگر کانفیگی در **یک** اجرا شکست بخورد، نباید پایدار شود.

    این تست دقیقاً همان اشتباهی را می‌گیرد که «موفق در بیشتر اجراها» یا
    «موفق در آخرین اجرا» مرتکب می‌شود.
    """
    link = "vless://x@4.4.4.4:443?security=tls#x"
    for bad_index in (0, 1, 2):
        rounds = []
        for i in range(3):
            if i == bad_index:
                rounds.append([_pl_row(link, status="failed", code=-1,
                                       success=0)])
            else:
                rounds.append([_pl_row(link)])
        with _StubL3(rounds):
            res = pipeline.run_l3_round([link], rounds=3)
        assert res["stable"] == set(), \
            (f"a failure in round {bad_index} must disqualify the config, "
             f"but it was called stable")
        assert res["ever_ok"] == {link}, \
            "it did work in the other rounds, so ever_ok must still hold it"


def test_pipeline_broken_rows_never_become_stable():
    """
    ★ سوراخِ سنجیده: `success == total` برای هر ۸۷ ردیفِ `broken` هم درست است
    (۰ == ۰). قاعدهٔ چهارشرطی باید این‌ها را رد کند — در همهٔ اجراها.
    """
    link = "vless://b@5.5.5.5:443?security=tls#broken"
    broken = _pl_row(link, status="broken", code=-1, success=0, total=0,
                     delay=0)
    assert broken["success"] == broken["total"], \
        "the fixture must reproduce the real 0==0 trap, else the test is vacuous"
    with _StubL3([[broken]] * 3):
        res = pipeline.run_l3_round([link], rounds=3)
    assert res["stable"] == set(), \
        "a broken row satisfies success==total and MUST still be rejected"
    assert res["ever_ok"] == set(), \
        "a broken row must never count as having worked"


def test_pipeline_fast_uses_the_median_not_a_single_run():
    """
    قاعدهٔ B6: `fast` بر **میانهٔ** اجراها است، نه یک نمونه.

    سنجش: ۷۷ کانفیگ (۳۴٫۴٪) خطِ ۸۰۰ms را بینِ اجراها رد و بدل می‌کنند، پس
    یک نمونه برچسب را هر دور عوض می‌کند. این تست کانفیگی می‌سازد که در یک
    اجرا سریع و در دو اجرا کند است: میانه باید «کند» بگوید.
    """
    slowish = "vless://s@6.6.6.6:443?security=tls#slowish"
    quick = "vless://q@7.7.7.7:443?security=tls#quick"
    rounds = [
        [_pl_row(slowish, delay=100), _pl_row(quick, delay=100)],
        [_pl_row(slowish, delay=1500), _pl_row(quick, delay=200)],
        [_pl_row(slowish, delay=1600), _pl_row(quick, delay=150)],
    ]
    with _StubL3(rounds):
        res = pipeline.run_l3_round([slowish, quick], rounds=3)
    assert res["delays"][slowish] == 1500, \
        (f"median of (100,1500,1600) is 1500, got {res['delays'][slowish]} — "
         "a mean or a first/last sample would give a different number")
    assert res["delays"][quick] == 150, \
        f"median of (100,200,150) is 150, got {res['delays'][quick]}"

    buckets = pipeline.build_buckets(res, fast_ms=800)
    assert quick in buckets["fast"], "150ms median must be fast"
    assert slowish not in buckets["fast"], \
        ("1500ms median must NOT be fast even though one run measured 100ms — "
         "otherwise a single lucky sample decides the label")
    assert slowish in buckets["verified"], \
        "being slow does not make a config unverified"


def test_pipeline_secure_requires_forward_secrecy():
    """
    قاعدهٔ B7 — سنجیده، نه سلیقه‌ای. سه اثباتِ رمزنگاشتیِ اجراشده پشتِ آن است:
    `ss`+AEAD و `vmess` بی‌TLS با موادِ **منتشرشده** بازگشایی شدند، پس در یک
    مخزنِ عمومی «امن» نیستند؛ `vless` هم `encryption` را تنها `none` می‌پذیرد.
    """
    cases = [
        ("vless://a@1.1.1.1:443?security=reality&pbk=k#r", "reality", True,
         "REALITY does an (EC)DHE handshake"),
        ("vless://a@1.1.1.1:443?security=tls#t", "tls", True,
         "TLS gives forward secrecy"),
        ("trojan://p@1.1.1.1:443?sni=x#tj", "tls", True,
         "trojan is always a TLS socket"),
        ("hysteria2://p@1.1.1.1:443?sni=x#h2", "", True,
         "QUIC mandates TLS 1.3 per RFC 9001 §4.2, so an empty tls column "
         "must NOT be read as plaintext"),
        ("vless://a@1.1.1.1:443?security=none#n", "none", False,
         "VLESS encryption accepts only 'none' ⇒ genuinely plaintext"),
        ("ss://YWVzLTEyOC1nY206cHc@1.1.1.1:8388#ss", "", False,
         "shadowsocks AEAD is decryptable from the published link"),
        ("vmess://eyJhZGQiOiIxLjEuMS4xIn0=", "", False,
         "vmess without TLS: the published UUID yields the session key"),
    ]
    for link, tls_value, want, why in cases:
        got = pipeline.is_secure(link, tls_value)
        assert got is want, \
            f"is_secure({link[:34]}…, tls={tls_value!r}) = {got}, want {want}: {why}"


def test_pipeline_secure_rejects_a_link_that_disables_cert_checks():
    """
    یک لینکِ `tls` که خودش `insecure=1` گفته، در برابر MITM محافظت ندارد.
    سنجش: دقیقاً ۱ کانفیگ از ۲۲۴ پایدار چنین است و باید حذف شود.
    """
    base = "trojan://p@1.1.1.1:443?sni=x"
    assert pipeline.is_secure(base + "#ok", "tls") is True, \
        "the control case must be secure, otherwise the test proves nothing"
    for key in ("insecure", "allowInsecure", "skip-cert-verify"):
        for val in ("1", "true", "yes"):
            link = f"{base}&{key}={val}#bad"
            assert pipeline.declares_insecure(link) is True, \
                f"{key}={val} must be detected"
            assert pipeline.is_secure(link, "tls") is False, \
                (f"{key}={val} disables certificate validation, so the config "
                 "must not be labelled secure despite tls=tls")
    # صفر/غایب نباید حذف کند
    for link in (base + "&insecure=0#z", base + "#absent"):
        assert pipeline.declares_insecure(link) is False, \
            f"insecure=0 or absent must NOT be treated as insecure: {link}"


def test_pipeline_verified_never_holds_a_failed_config():
    """
    ★ B11 — کنترلِ منفیِ اصلی: هیچ سبدی نباید کانفیگی داشته باشد که در آزمونِ
    واقعی نپذیرفته شده. این تست هر چهار خروجی را با هم می‌سنجد.
    """
    good = "vless://g@1.1.1.1:443?security=tls#good"
    bads = {
        "failed": _pl_row("vless://f@2.2.2.2:443?security=tls#f",
                          status="failed", code=-1, success=0),
        "broken": _pl_row("vless://b@3.3.3.3:443?security=tls#b",
                          status="broken", code=-1, success=0, total=0),
        "code_400": _pl_row("vless://c@4.4.4.4:443?security=tls#c",
                            code=400),
        "partial_success": _pl_row("vless://p@5.5.5.5:443?security=tls#p",
                                   success=1, total=2),
    }
    rows = [_pl_row(good)] + list(bads.values())
    with _StubL3([rows] * 3):
        res = pipeline.run_l3_round([good] + [r["link"] for r in bads.values()],
                                    rounds=3)
    buckets = pipeline.build_buckets(res)
    for cat in ("verified", "fast", "secure", "top"):
        assert buckets[cat] == [good], \
            (f"{cat} must contain exactly the one genuinely-ok config; got "
             f"{buckets[cat]!r}")
        for label, row in bads.items():
            assert row["link"] not in buckets[cat], \
                f"{cat} leaked a {label} config — the publication gate is broken"


def test_pipeline_top_file_is_sorted_and_never_padded():
    """
    B8: `top100.txt` بر تأخیر مرتب است و اگر استخر کوچک بود، **پر نمی‌شود**.
    پرکردنِ مصنوعی با کانفیگِ نیازموده بدترین شکلِ ادعای الکی است.
    """
    links = [f"vless://u{i}@1.1.1.{i}:443?security=tls#u{i}" for i in range(5)]
    delays = [900, 100, 500, 300, 700]
    rows = [_pl_row(L, delay=d) for L, d in zip(links, delays)]
    with _StubL3([rows] * 3):
        res = pipeline.run_l3_round(links, rounds=3)
    buckets = pipeline.build_buckets(res, top_n=3)
    got = [res["delays"][L] for L in buckets["top"]]
    assert got == [100, 300, 500], \
        f"top must be sorted ascending by median delay; got {got}"
    assert len(buckets["top"]) == 3

    # استخرِ کوچک‌تر از سقف
    buckets2 = pipeline.build_buckets(res, top_n=100)
    assert len(buckets2["top"]) == 5, \
        "with only 5 stable configs the file must hold 5, not 100"
    assert buckets2["stats"]["top_short_by"] == 95, \
        "the shortfall must be counted so it can be announced honestly"

    # ── ضدِ پرکردن، با استخری که «هرچه کار کرد» > «پایدار» است ────────────
    # چرا این بند لازم است؟ در چیدمانِ بالا `ever_ok == stable` بود، پس
    # منبعِ پرکردن **تهی** بود و «پر کردنِ سقف با کانفیگِ ناپایدار» به‌کل
    # غیرقابلِ‌مشاهده می‌ماند. آزمونِ جهش همین را گرفت (m20). حالا چهار
    # لینکِ لرزان می‌سازیم که **سریع‌تر** از پایدارها هستند تا اگر روزی کسی
    # سقف را پر کند، آن‌ها جذاب‌ترین گزینه برای پرکردن باشند.
    flaky = [f"vless://f{i}@3.3.3.{i}:443?security=tls#f{i}" for i in range(4)]
    stable_rows = [_pl_row(L, delay=d) for L, d in zip(links, delays)]
    round1 = stable_rows + [_pl_row(L, delay=10) for L in flaky]
    round2 = stable_rows                                  # لرزان‌ها همه افتادند
    round3 = stable_rows + [_pl_row(flaky[0], delay=10)]  # یکی برگشت
    with _StubL3([round1, round2, round3]):
        res2 = pipeline.run_l3_round(links + flaky, rounds=3)
    assert len(res2["stable"]) == 5, \
        f"only the 5 always-ok links are stable; got {len(res2['stable'])}"
    assert len(res2["ever_ok"]) == 9, \
        ("the fixture must offer a NON-empty padding source, otherwise this "
         f"test cannot observe padding at all; ever_ok={len(res2['ever_ok'])}")

    buckets3 = pipeline.build_buckets(res2, top_n=100)
    assert len(buckets3["top"]) == 5, \
        (f"top must never be padded past the stable pool; it holds "
         f"{len(buckets3['top'])} while only 5 configs passed every round")
    for L in flaky:
        for cat in ("verified", "fast", "secure", "top"):
            assert L not in buckets3[cat], \
                f"a flaky config leaked into {cat!r}: {L}"


def test_pipeline_writes_files_with_an_honest_shortfall_notice():
    """خروجی باید معیارش را بنویسد و کمبود را **اعلام** کند، نه پنهان."""
    import tempfile as _tf
    good = "vless://g@1.1.1.1:443?security=tls#g"
    plain = "vless://p@2.2.2.2:443?security=none#p"
    rows = [_pl_row(good, delay=100), _pl_row(plain, delay=100, tls="none")]
    with _StubL3([rows] * 3):
        res = pipeline.run_l3_round([good, plain], rounds=3)
    buckets = pipeline.build_buckets(res, top_n=100)
    out = _tf.mkdtemp(prefix="pl_out_")
    paths = pipeline.write_buckets(out, buckets)

    for cat in ("verified", "fast", "secure"):
        with open(paths[cat], encoding="utf-8") as fh:
            body = fh.read()
        assert body.startswith("#"), f"{cat} must carry a header"
        assert good in body, f"{cat} must list the good config"
    with open(paths["secure"], encoding="utf-8") as fh:
        sec = fh.read()
    assert plain not in sec, \
        "a security=none config must not be written into secure/"
    assert "forward secrecy" in sec, \
        "secure/ must state its measured criterion, not just a label"

    with open(paths["top"], encoding="utf-8") as fh:
        top = fh.read()
    assert "98 short of 100" in top, \
        f"the shortfall must be announced in the file itself; got:\n{top[:400]}"
    assert "NOT padded" in top, \
        "the file must say explicitly that it was not padded"


def test_pipeline_refuses_an_empty_input_loudly():
    """
    ورودیِ تهی باید **بلند** بشکند — همان درسِ لایهٔ L3.

    و مهم‌تر: باید **پیش از** فراخوانیِ L3 بشکند. اگر فقط استثنا را بسنجیم،
    آزمونِ جهش (m22) نشان داد که برداشتنِ نگهبانِ این ماژول هیچ‌چیز را
    نمی‌شکند، چون `realtest.test_lines` خودش همان `EmptyInput` را می‌دهد.
    اما آن مسیر یک فایلِ موقت می‌سازد و xray-knife را اجرا می‌کند؛ و در CI
    با stdinِ باز، فایلِ تهی دقیقاً همان‌جاست که ابزار قفل می‌کرد (rc=124).
    پس «هیچ اجرایی رخ نداد» رفتارِ قابلِ‌سنجش و لازم است.
    """
    spy = {"calls": 0}
    orig = realtest.test_lines

    def counting(lines, **kwargs):
        spy["calls"] += 1
        return {"rows": []}

    realtest.test_lines = counting
    try:
        for bad in ([], ["", "   ", "\t"]):
            try:
                pipeline.run_l3_round(bad, rounds=3)
            except realtest.EmptyInput:
                pass
            else:
                raise AssertionError(
                    "an input with no usable configs must raise EmptyInput: "
                    f"{bad!r}")
            assert spy["calls"] == 0, \
                ("L3 must never be launched for an empty input — that is the "
                 "measured CI hang (rc=124); it was launched "
                 f"{spy['calls']}× for {bad!r}")

        try:
            pipeline.run_l3_round(["vless://a@1.1.1.1:443#a"], rounds=0)
        except ValueError:
            pass
        else:
            raise AssertionError(
                "rounds=0 must be rejected, not silently accepted")
        assert spy["calls"] == 0, \
            f"rounds=0 must not launch L3 either; got {spy['calls']} call(s)"
    finally:
        realtest.test_lines = orig


def test_pipeline_reproduces_the_measured_secure_share():
    """
    قفلِ عددی روی دادهٔ **واقعیِ** ۵ اجرا: قاعدهٔ B7 باید همان ۸۱ از ۲۲۴ را
    بدهد که مستقلاً سنجیده شد (۳۶٫۲٪). اگر روزی قاعده عوض شد، این تست
    می‌شکند و کسی مجبور می‌شود عدد را دوباره توجیه کند.
    """
    import csv as _csv
    base = "/home/user/exp/b4b"
    if not os.path.isdir(base):
        return  # دادهٔ سنجش در این محیط نیست؛ تست بی‌صدا رد می‌شود
    ok_sets, tls_of = [], {}
    for n in range(1, 6):
        path = os.path.join(base, f"run{n}.csv")
        if not os.path.isfile(path):
            return
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(_csv.DictReader(fh))
        ok_sets.append({r["link"] for r in rows
                        if realtest.is_row_genuinely_ok(r)})
        for r in rows:
            tls_of.setdefault(r["link"], (r["tls"] or "").strip())
    stable = set.intersection(*ok_sets)
    assert len(stable) == 224, \
        f"the measured stable set is 224 configs, got {len(stable)}"
    secure = [L for L in stable if pipeline.is_secure(L, tls_of.get(L, ""))]
    assert len(secure) == 81, \
        (f"the measured secure count is 81/224 = 36.2%, got {len(secure)}. "
         "The plan's original 47% figure came from a 36-config pilot and was "
         "corrected.")


def test_pipeline_matches_the_real_l3_result_contract():
    """
    شیمِ آزمون باید همان شکلی را بدهد که `realtest` واقعاً می‌دهد.

    این تست از یک شکستِ **واقعاً رخ‌داده** محافظت می‌کند: `rows` در
    `realtest.run_test` یک **dict**ِ لینک→ردیف است (خطِ «"rows": by_link»)،
    ولی شیم لیست می‌داد. نتیجه: ۱۲۲ آزمون سبز و اجرای واقعی شکسته. پس
    قرارداد را از خودِ منبع می‌خوانیم، نه از حافظه.
    """
    # قرارداد را **رفتاری** می‌سنجیم، نه با جست‌وجوی متنِ کد. منبعِ شکلِ
    # `rows` تابعِ `classify` است؛ پس همان را با یک ردیفِ واقعی صدا می‌زنیم.
    probe = _pl_row("vless://probe@1.2.3.4:443?security=tls#p")
    shape = realtest.classify([probe])
    assert isinstance(shape["rows"], dict), \
        (f"realtest.classify now returns rows as {type(shape['rows']).__name__},"
         " not a link→row map; the pipeline contract helper and the test stub "
         "must be revisited")
    assert shape["rows"][probe["link"]] == probe, \
        "the rows map must be keyed by the config link"

    # ۱) شیم باید dict بدهد، مثل منبع
    rows = [_pl_row("vless://x@1.1.1.1:443?security=tls#x")]
    with _StubL3([rows]) as stub:
        out = realtest.test_lines(["vless://x@1.1.1.1:443?security=tls#x"])
    assert isinstance(out["rows"], dict), \
        f"the stub must mimic the real dict shape, got {type(out['rows'])}"

    # ۲) خودِ pipeline باید هر دو شکل را درست بخواند و شکلِ بیگانه را
    #    **بلند** رد کند — نه آن‌که خاموش صفر ردیف ببیند.
    row = _pl_row("vless://y@2.2.2.2:443?security=tls#y")
    assert pipeline._rows_of({"rows": {row["link"]: row}}) == [row]
    assert pipeline._rows_of({"rows": [row]}) == [row]
    for bad in ({"rows": None}, {"rows": "oops"}, {}):
        try:
            pipeline._rows_of(bad)
        except pipeline.StabilityError:
            pass
        else:
            raise AssertionError(
                f"an unexpected rows shape must break loudly: {bad!r}")


def test_pipeline_output_survives_the_publication_gate():
    """
    شرطِ خروجِ ۷ فاز B: آبشار نباید دروازهٔ انتشار را بشکند.

    این تست از یک اشتباهِ **سنجیده‌شده** محافظت می‌کند، نه فرضی: وقتی
    `write_buckets` تنها `configs.txt` می‌نوشت، `validate.py` روی همان
    دایرکتوری `ok=False` و `missing=2` داد — چون هر دسته‌ای که **وجود
    داشته باشد** به‌سختیِ دسته‌های اصلی سنجیده می‌شود. یعنی وصل‌کردنِ
    آبشار به CI، کلِ انتشار را می‌شکست.
    """
    import tempfile as _tf
    import validate as _validate

    links = [
        "vless://11111111-1111-1111-1111-111111111111@1.1.1.1:443"
        "?security=tls&sni=a.example&type=ws#a",
        "trojan://pw@2.2.2.2:443?security=tls&sni=b.example#b",
    ]
    rows = [_pl_row(L, delay=120) for L in links]
    with _StubL3([rows] * 3):
        res = pipeline.run_l3_round(links, rounds=3)
    buckets = pipeline.build_buckets(res)

    out = _tf.mkdtemp(prefix="pl_gate_")
    pipeline.write_buckets(out, buckets)

    # دسته‌های اصلی را هم می‌سازیم، چون دروازه بی‌قید و شرط سراغشان می‌رود.
    for cat in _validate.CORE_CATEGORIES:
        base = os.path.join(out, cat)
        os.makedirs(base, exist_ok=True)
        with open(os.path.join(base, "configs.txt"), "w",
                  encoding="utf-8") as fh:
            fh.write("\n".join(links) + "\n")
        with open(os.path.join(base, "clash.yaml"), "w",
                  encoding="utf-8") as fh:
            fh.write(converters.build_clash_yaml(links))
        with open(os.path.join(base, "singbox.json"), "w",
                  encoding="utf-8") as fh:
            fh.write(converters.build_singbox_json(links))

    for cat in pipeline.CATEGORIES:
        for name in ("configs.txt", "configs_base64.txt", "clash.yaml",
                     "singbox.json"):
            p = os.path.join(out, cat, name)
            assert os.path.isfile(p), \
                (f"{cat}/{name} is missing — the publication gate counts a "
                 "missing artifact as a failure, so the whole publish breaks")

    rep = _validate.validate_outputs(out)
    assert rep["summary"]["missing"] == 0, \
        (f"the gate found missing artifacts: {rep['summary']} / "
         f"{rep['results']}")
    assert rep["ok"], f"the publication gate rejected pipeline output: {rep}"


# ──────────────────────────────────────────────────────────────────────────────
# B13 — آمارِ هر لایه و کشورِ خروج در health.json
# ──────────────────────────────────────────────────────────────────────────────

def test_pipeline_merges_layer_stats_into_health_without_losing_anything():
    """
    `health.json` را `aggregate.py` می‌سازد و **پیش از** آبشار اجرا می‌شود.
    پس ادغام باید افزایشی باشد: اگر آبشار فایل را بازنویسی کند، آمارِ
    منابع و مبدل‌ها و GeoIP نابود می‌شود و مانیتورینگ کور می‌شود.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as out:
        original = {
            "brand": "@Raydikalx",
            "summary": {"total": 21, "ok": 21, "empty": 0, "fail": 0},
            "sources": [{"url": "https://example.invalid/a", "status": "ok"}],
            "converters": {"dropped": 7},
            "geo": {"db_loaded": True},
        }
        hp = os.path.join(out, "health.json")
        with open(hp, "w", encoding="utf-8") as fh:
            json.dump(original, fh)

        cascade = {"exit_country": {"loc": "US"}, "total_seconds": 149.34}
        got = pipeline.merge_health(out, cascade)
        assert got == hp, f"مسیرِ برگشتی غلط: {got!r}"

        with open(hp, encoding="utf-8") as fh:
            after = json.load(fh)

        # کلیدِ تازه هست
        assert after.get("cascade") == cascade, (
            f"بلوکِ cascade درست نوشته نشد: {after.get('cascade')!r}")
        # و **هیچ** کلیدِ قبلی گم نشده
        for k, v in original.items():
            assert after.get(k) == v, (
                f"ادغام کلیدِ «{k}» را خراب کرد: {after.get(k)!r} در برابر {v!r}")


def test_pipeline_survives_a_missing_or_broken_health_file():
    """
    آمارِ سلامت **مانیتورینگ** است، نه محصول. اگر `health.json` نبود یا
    خراب بود، آبشار باید هشدار بدهد و رد شود — نه آن‌که کلِ انتشارِ
    کانفیگ‌ها را با یک استثنا بشکند.
    """
    import contextlib
    import io
    import tempfile

    def _warned(fn):
        """(خروجی, هشدارِ چاپ‌شده روی stderr) را برمی‌گرداند."""
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            value = fn()
        return value, buf.getvalue()

    with tempfile.TemporaryDirectory() as out:
        # ۱) فایل وجود ندارد
        got, warn_absent = _warned(lambda: pipeline.merge_health(out, {"x": 1}))
        assert got is None, "نبودنِ health.json باید None بدهد، نه استثنا"

        # ۲) JSONِ خراب
        hp = os.path.join(out, "health.json")
        with open(hp, "w", encoding="utf-8") as fh:
            fh.write("{ this is not json")
        got, warn_broken = _warned(lambda: pipeline.merge_health(out, {"x": 1}))
        assert got is None, "JSONِ خراب باید None بدهد، نه استثنا"

        # ۳) JSONِ درست ولی نه یک شیء (مثلاً آرایه)
        with open(hp, "w", encoding="utf-8") as fh:
            json.dump([1, 2, 3], fh)
        got, warn_notdict = _warned(lambda: pipeline.merge_health(out, {"x": 1}))
        assert got is None, "آرایهٔ JSON باید None بدهد، نه استثنا"

        # ── و سه شکستِ بالا باید از هم **قابلِ تشخیص** باشند ───────────────
        # هر سه `None` برمی‌گردانند، پس تنها چیزی که در لاگِ CI می‌ماند
        # همین هشدار است. اگر پیام‌ها یکی شوند، نگهدارنده نمی‌فهمد فایل
        # ساخته نشده یا ساخته و خراب شده — دو عیبِ کاملاً متفاوت با دو
        # راه‌حلِ متفاوت. (جهشِ m5 نشان داد نگهبانِ os.path.exists از نظرِ
        # مقدارِ بازگشتی زائد است و ارزشش فقط همین تفکیکِ تشخیصی است؛
        # پس همان ارزش اینجا صریحاً سنجیده می‌شود.)
        assert warn_absent.strip(), "نبودنِ فایل باید هشدار بدهد، نه سکوت"
        assert warn_broken.strip(), "خرابیِ JSON باید هشدار بدهد، نه سکوت"
        assert warn_notdict.strip(), "نوعِ نادرست باید هشدار بدهد، نه سکوت"
        assert "نیست" in warn_absent, (
            f"هشدارِ «نبودنِ فایل» باید همین را بگوید: {warn_absent!r}")
        assert warn_absent != warn_broken, (
            "هشدارِ «فایل نیست» و «فایل خراب است» یکی شده‌اند؛ "
            f"عیب‌یابی در CI کور می‌شود: {warn_absent!r}")
        assert warn_broken != warn_notdict, (
            "هشدارِ «JSONِ خراب» و «شیء نبودن» یکی شده‌اند: "
            f"{warn_broken!r}")


def test_pipeline_exit_country_never_raises_and_parses_the_real_format():
    """
    کشورِ خروج باید «بهترین تلاش» باشد. این تست شکلِ **واقعیِ** پاسخِ
    `cdn-cgi/trace` را تزریق می‌کند (سنجیده شد: کلیدهای `key=value` در
    خطوطِ جدا، شاملِ `loc` و `colo`) و بعد شبکه را می‌شکند تا ثابت شود
    خطا به بالا پرت نمی‌شود.
    """
    import urllib.request

    real_body = (b"fl=123abc\nh=cp.cloudflare.com\nip=203.0.113.7\n"
                 b"ts=1785367152.1\nvisit_scheme=https\ncolo=IAD\n"
                 b"sliver=none\nhttp=http/2\nloc=US\ntls=TLSv1.3\n")

    class _Resp:
        def read(self, n=-1):
            return real_body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    orig = urllib.request.urlopen
    try:
        urllib.request.urlopen = lambda *a, **k: _Resp()
        got = pipeline.exit_country()
        assert got is not None, "پاسخِ سالم باید تجزیه شود"
        assert got.get("loc") == "US", f"loc غلط: {got!r}"
        assert got.get("colo") == "IAD", f"colo غلط: {got!r}"
        assert got.get("source") == pipeline.TRACE_URL, f"source غلط: {got!r}"
        # ip نباید در گزارشِ عمومی بیفتد
        assert "ip" not in got, f"نشانیِ IP نباید منتشر شود: {got!r}"

        # شبکه خراب ⇒ None، نه استثنا
        def boom(*a, **k):
            raise OSError("network is unreachable")

        urllib.request.urlopen = boom
        assert pipeline.exit_country() is None, (
            "خطای شبکه باید None بدهد، نه استثنا")

        # پاسخی که هیچ کلیدی ندارد — مثلاً صفحهٔ خطای یک captive portal یا
        # یک پراکسیِ میانی. این حالت با «خطای شبکه» یکی نیست: اتصال موفق
        # است ولی محتوا بی‌ربط. باید None بدهد، نه نقشهٔ تهی؛ چون `{}` در
        # health.json یعنی «سنجیده شد و کشوری نداشت» در حالی که واقعیت
        # «سنجیده نشد» است و این دو برای عیب‌یابی یکی نیستند.
        # (این حالت با جهشِ m4 کشف شد: آزمونِ قبلی این شاخه را نمی‌سنجید.)
        class _Html:
            def read(self, n=-1):
                return b"<html><body>403 Forbidden</body></html>"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        urllib.request.urlopen = lambda *a, **k: _Html()
        got_html = pipeline.exit_country()
        assert got_html is None, (
            f"پاسخِ غیرقابل‌تجزیه باید None بدهد، نه {got_html!r}")
    finally:
        urllib.request.urlopen = orig


def test_pipeline_reports_every_layer_with_input_output_time_and_reasons():
    """
    B13 چهار چیز می‌خواهد: ورودی، خروجی، زمان، و **دلیلِ حذف** برای هر لایه.
    این تست ساختار را روی یک اجرای واقعیِ آبشار (با L3ِ بدل) می‌سنجد.
    """
    import tempfile

    good = "vless://a@1.1.1.1:443?security=tls#a"
    rows = [_pl_row(good, delay=100)]

    # ── چرا ورودی **نامتقارن** است ─────────────────────────────────────────
    # یک سطرِ نامعتبر لازم است تا «ورودیِ خام» و «چیزی که از L0/L1 رد شد»
    # دو عددِ متفاوت باشند (سنجیده شد: input=2 ولی kept=1). با ورودیِ
    # یک‌سطریِ سالم هر دو برابرِ ۱ می‌شوند و تست نسبت به این اشتباه که
    # ورودیِ L2 از شمارشِ خام برداشته شود **کور** می‌ماند — دقیقاً همان
    # اشتباهی که در اجرای زنده رخ داد (۳۰۰ در برابرِ ۲۹۵).
    # همچنین دو نرخِ عبور از هم جدا می‌شوند: ۱/۲=۵۰٪ در برابرِ ۱/۱=۱۰۰٪.
    lines = [good, "این یک کانفیگ نیست"]

    with tempfile.TemporaryDirectory() as out:
        with open(os.path.join(out, "health.json"), "w", encoding="utf-8") as fh:
            json.dump({"brand": "@Raydikalx", "sources": []}, fh)

        real_check = reachability.check_lines
        real_country = pipeline.exit_country
        try:
            # بدل، رفتارِ **واقعیِ** `check_lines` را بازمی‌سازد: سطرهای خام
            # را می‌گیرد و `configs_in` را برابرِ ورودیِ خام می‌گذارد،
            # و `configs_open_pct` را هم نسبت به همان خام حساب می‌کند.
            reachability.check_lines = lambda L: {
                "kept_open": [good],
                "stats": {"configs_in": 2, "configs_open": 1,
                          "configs_open_pct": 50.0, "dns_failed": 0,
                          "dns_s": 0.1, "tcp_s": 0.2,
                          "fd_before": 4, "fd_after": 4},
            }
            pipeline.exit_country = lambda *a, **k: {"loc": "US", "colo": "IAD"}
            with _StubL3([rows, rows, rows]):
                res = pipeline.run_pipeline(lines, out)
        finally:
            reachability.check_lines = real_check
            pipeline.exit_country = real_country

        casc = res["stats"]["cascade"]
        assert casc["exit_country"]["loc"] == "US", (
            f"کشورِ خروج ثبت نشد: {casc.get('exit_country')!r}")

        layers = casc["layers"]
        for name in ("l0_l1", "l2", "l3"):
            assert name in layers, f"لایهٔ «{name}» در گزارش نیست: {list(layers)}"
            assert "seconds" in layers[name], f"زمانِ «{name}» ثبت نشده"
            assert isinstance(layers[name]["seconds"], (int, float)), (
                f"زمانِ «{name}» عدد نیست: {layers[name]['seconds']!r}")

        for name in ("l0_l1", "l2"):
            for k in ("in", "out"):
                assert k in layers[name], f"«{k}» برای «{name}» ثبت نشده"

        # دلیلِ حذف — همان چیزی که `check_lines` بیرون نمی‌دهد
        dropped = layers["l0_l1"]["dropped"]
        assert isinstance(dropped, dict), f"dropped باید نقشه باشد: {dropped!r}"
        for reason in (filters.REASON_UNPARSABLE, filters.REASON_INVALID_PORT,
                       filters.REASON_INVALID_UUID, filters.REASON_UNROUTABLE,
                       filters.REASON_INVALID_SERVER):
            assert reason in dropped, (
                f"دلیلِ «{reason}» در گزارش نیست: {sorted(dropped)}")

        assert layers["l3"]["rounds"] == 3, f"تعدادِ راند: {layers['l3']!r}"
        assert casc["total_seconds"] >= 0

        # ── زنجیره باید حسابی درست باشد ────────────────────────────────────
        # خروجیِ هر لایه ورودیِ لایهٔ بعد است. این در یک اجرای واقعی نقض
        # شده بود: `reachability.check_lines` سطرهای خام را می‌گیرد و
        # `configs_in` را برابرِ ورودیِ **خام** می‌گذارد (۳۰۰) در حالی که
        # L0/L1 تنها ۲۹۵ را نگه داشته بود. گزارش این‌طور خوانده می‌شد که
        # ۵ کانفیگ از هیچ‌جا پیدا شده‌اند.
        assert layers["l2"]["in"] == layers["l0_l1"]["out"], (
            f"زنجیره پاره است: L0/L1 خروجی={layers['l0_l1']['out']} ولی "
            f"ورودیِ L2={layers['l2']['in']}")
        assert layers["l3"]["in"] == layers["l2"]["out"], (
            f"زنجیره پاره است: L2 خروجی={layers['l2']['out']} ولی "
            f"ورودیِ L3={layers['l3']['in']}")
        # و `in`/`out` هر لایه باید با دلایلِ حذف جمع بزند
        assert (layers["l0_l1"]["in"] - layers["l0_l1"]["out"]
                == sum(layers["l0_l1"]["dropped"].values())), (
            f"جمعِ دلایلِ حذف با اختلافِ ورودی/خروجی نمی‌خواند: "
            f"{layers['l0_l1']!r}")
        # درصدِ عبورِ L2 باید نسبت به ورودیِ **همان لایه** باشد
        exp = round(100.0 * layers["l2"]["out"] / layers["l2"]["in"], 2)
        assert abs(layers["l2"]["open_pct"] - exp) < 0.01, (
            f"open_pct نسبت به ورودیِ لایه نیست: "
            f"{layers['l2']['open_pct']} در برابرِ {exp}")

        # و در health.json هم نشسته باشد
        with open(os.path.join(out, "health.json"), encoding="utf-8") as fh:
            doc = json.load(fh)
        assert doc.get("brand") == "@Raydikalx", "ادغام brand را پاک کرد"
        assert doc["cascade"]["layers"]["l3"]["rounds"] == 3, (
            "بلوکِ cascade در health.json ننشست")


# ──────────────────────────────────────────────────────────────────────────────
# B5 در CI — گامِ آبشار در ورک‌فلو
# ──────────────────────────────────────────────────────────────────────────────

def test_workflow_runs_the_cascade_before_it_validates_and_publishes():
    """
    ترتیبِ گام‌ها **رفتار** است، نه سلیقه.

    اگر آبشار بعد از اعتبارسنجی بیاید، دسته‌های تازه‌ساخته هرگز سنجیده
    نمی‌شوند؛ و اگر بعد از انتشار بیاید، همان دور منتشر نمی‌شوند. پس
    این تست اندیسِ واقعیِ گام‌ها را در YAMLِ تجزیه‌شده مقایسه می‌کند، نه
    متنِ فایل را.
    """
    doc = yaml.safe_load(_workflow_text())
    steps = doc["jobs"]["aggregate"]["steps"]
    names = [s.get("name", "") for s in steps]

    def idx(pred, what):
        hits = [i for i, n in enumerate(names) if pred(n)]
        assert hits, f"گامِ «{what}» در ورک‌فلو نیست: {names}"
        return hits[0]

    cascade = idx(lambda n: "L3 cascade" in n, "آبشار L3")
    validate = idx(lambda n: n.startswith("🔍 Validate"), "اعتبارسنجی")
    publish = idx(lambda n: "Publish" in n, "انتشار")

    assert cascade < validate, (
        f"آبشار (گام {cascade}) بعد از اعتبارسنجی (گام {validate}) اجرا "
        f"می‌شود ⇒ دسته‌های verified/fast/secure هرگز سنجیده نمی‌شوند")
    assert validate < publish, (
        f"اعتبارسنجی (گام {validate}) بعد از انتشار (گام {publish}) است ⇒ "
        f"دروازه بی‌اثر می‌شود")

    step = steps[cascade]
    run = step.get("run", "")
    assert "scripts/pipeline.py" in run, (
        f"گامِ آبشار خودِ pipeline.py را صدا نمی‌زند: {run!r}")
    assert "all/configs.txt" in run, (
        f"ورودیِ آبشار باید خروجیِ همین دور باشد؛ دیده شد: {run!r}")

    # این لایه به شبکه وابسته است و **نباید** انتشارِ all/heavy/light را
    # بشکند — آن‌ها با معیارِ دیگری تولید می‌شوند.
    assert step.get("continue-on-error") is True, (
        "گامِ آبشار continue-on-error ندارد ⇒ یک دورِ بدشبکه کلِ انتشار را "
        "می‌شکند")

    # بودجهٔ سنجیده‌شده ۱۴۹٫۳۴ ثانیه بود؛ سقف باید وجود داشته باشد و از آن
    # بزرگ‌تر ولی از بودجهٔ ۹۰۰ ثانیه‌ایِ CI کوچک‌تر باشد.
    tmo = step.get("timeout-minutes")
    assert isinstance(tmo, int), (
        f"گامِ آبشار سقفِ زمانی ندارد ⇒ یک اجرای گیرکرده runner را می‌بلعد "
        f"(دیده شد: {tmo!r})")
    assert 149.34 / 60.0 < tmo <= 15, (
        f"سقفِ زمانیِ {tmo} دقیقه با بودجهٔ سنجیده‌شدهٔ ۱۴۹٫۳۴s نمی‌خواند")


def test_workflow_publishes_the_cascade_categories_it_builds():
    """
    اشکالی که با خواندنِ گامِ انتشار پیدا شد، نه با حدس.

    درختِ snapshot از `$ANCHOR` ساخته می‌شود و **فقط** مسیرهای
    `$OUTPUT_PATHS` را stage می‌کند. پس اگر آبشار `verified/` را بسازد ولی
    آن مسیر در فهرست نباشد، فایل تولید می‌شود و بعد **بی‌صدا دور ریخته
    می‌شود** — بدونِ هیچ خطایی. این تست همان سوراخ را می‌بندد.
    """
    import re as _re

    text = _workflow_text()
    m = _re.search(r'OUTPUT_PATHS="([^"]*)"', text)
    assert m, "متغیرِ OUTPUT_PATHS در گامِ انتشار پیدا نشد"
    paths = m.group(1).split()

    for need in ("verified", "fast", "secure", "top100.txt"):
        assert need in paths, (
            f"«{need}» در OUTPUT_PATHS نیست ⇒ آبشار می‌سازدش و انتشار "
            f"بی‌صدا دورش می‌ریزد. فهرستِ دیده‌شده: {paths}")

    # مسیرهای قدیمی نباید قربانیِ افزودنِ جدیدها شده باشند.
    for old in ("all", "heavy", "light", "index.json", "health.json"):
        assert old in paths, f"مسیرِ قدیمیِ «{old}» از OUTPUT_PATHS افتاده"


def _summary_cascade_snippet() -> str:
    """کدِ پایتونِ بلوکِ «نرخِ کارکرد» را از گامِ خلاصه بیرون می‌کشد.

    از خودِ YAML خوانده می‌شود تا تودرتوییِ ۱۰ فاصله‌ای دستی حذف نشود:
    `run: |` را که yaml باز می‌کند، فاصله‌ها همان‌جا برداشته می‌شوند.
    """
    import re as _re

    doc = yaml.safe_load(_workflow_text())
    job = doc["jobs"][next(iter(doc["jobs"]))]
    steps = [s for s in job["steps"] if "Job summary" in str(s.get("name", ""))]
    assert len(steps) == 1, f"گامِ «Job summary» یکتا نیست: {len(steps)}"
    blocks = _re.findall(
        r"python - <<'PY' >> \"\$GITHUB_STEP_SUMMARY\"\n(.*?)\nPY\n",
        steps[0]["run"], _re.S)
    casc = [b for b in blocks if "cascade" in b]
    assert len(casc) == 1, (
        f"باید دقیقاً یک بلوکِ خلاصهٔ آبشار باشد، {len(casc)} پیدا شد")
    return casc[0]


def test_workflow_summary_reports_the_measured_working_rate_every_run():
    """
    شرطِ خروجیِ ② فاز B: نرخِ کارکردِ `verified/` باید «با CI» سنجیده شود،
    نه یک‌بار روی یک ماشین و بعد به‌صورت عددِ ثابت در README بماند.

    این تست متن را match نمی‌کند — خودِ بلوک را **اجرا** می‌کند، چون یک
    بلوکِ خلاصه که syntax درستی دارد ولی عدد اشتباه می‌دهد بدتر از نبودنش
    است.

    سه سناریو:
      ۱) آبشار موجود → درصدها باید نسبت به **کلِ pool** حساب شوند، نه نسبت
         به ورودیِ L3. (تفاوتشان این‌جا ۵٪ در برابر ۱۲٫۵٪ است.)
      ۲) آبشار غایب (مرحله `continue-on-error` شکسته) → خروجیِ خالی، بدونِ
         استثنا؛ خلاصهٔ خراب کلِ گزارش را می‌بلعد.
      ۳) `exit_country` تهی → «از کجا» نامعلوم، ولی گزارش باید بایستد.
    """
    import subprocess as _sp
    import tempfile as _tf

    code = _summary_cascade_snippet()
    cascade = {
        "exit_country": {"loc": "DE", "colo": "FRA",
                         "source": "https://example.invalid/trace"},
        "layers": {
            "l0_l1": {"in": 1000, "out": 900,
                      "dropped": {"unparsable": 100}, "seconds": 0.5},
            "l2": {"in": 900, "out": 400, "open_pct": 44.44, "seconds": 9.0},
            "l3": {"in": 400, "rounds": 3, "per_run_ok": [80, 70, 60],
                   "ever_ok": 90, "stable": 50, "flaky_pct": 44.44,
                   "seconds": 30.0},
        },
        "buckets": {"verified": 50, "fast": 20, "secure": 7, "top": 50},
        "total_seconds": 39.5,
    }

    def render(doc) -> tuple[int, str, str]:
        with _tf.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "health.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(doc, fh, ensure_ascii=False)
            with open(os.path.join(tmp, "snippet.py"), "w",
                      encoding="utf-8") as fh:
                fh.write(code + "\n")
            p = _sp.run([sys.executable, "snippet.py"], cwd=tmp,
                        capture_output=True, text=True, timeout=120)
            return p.returncode, p.stdout, p.stderr

    # ۱) آبشارِ موجود
    rc, out, err = render({"summary": {}, "cascade": cascade})
    assert rc == 0, f"بلوکِ خلاصه نباید خطا بدهد: {err[-400:]}"
    assert "DE/FRA" in out, f"محلِ سنجش باید ذکر شود: {out!r}"
    assert "50" in out and "90" in out, out
    # ۵۰ از ۱۰۰۰ = ۵٫۰٪ ؛ اگر مخرج اشتباه (۴۰۰) باشد ۱۲٫۵٪ می‌شود
    assert "5.0%" in out, (
        f"درصدِ پایدار باید نسبت به کلِ pool (۱۰۰۰) باشد، نه ورودیِ L3: {out!r}")
    assert "12.5%" not in out, (
        f"مخرجِ اشتباه (ورودیِ L3) به‌کار رفته است: {out!r}")
    assert "9.0%" in out, f"درصدِ «حداقل یک‌بار» غایب است: {out!r}"
    assert "[80, 70, 60]" in out, (
        f"شمارشِ هر راند باید دیده شود، وگرنه پایداری قابلِ بازبینی نیست: {out!r}")
    assert "verified=50" in out and "secure=7" in out, out

    # ۲) کنترلِ منفی: آبشار نیست → سکوت، نه خطا
    rc, out, err = render({"summary": {}, "sources": []})
    assert rc == 0, f"غیبتِ آبشار نباید خلاصه را بشکند: {err[-400:]}"
    assert out.strip() == "", f"باید ساکت بماند، این چاپ شد: {out!r}"

    # ۳) exit_country تهی
    no_geo = json.loads(json.dumps(cascade))
    no_geo["exit_country"] = None
    rc, out, err = render({"summary": {}, "cascade": no_geo})
    assert rc == 0, f"نبودِ ژئو نباید گزارش را بشکند: {err[-400:]}"
    assert "?/?" in out, f"محلِ نامعلوم باید صریح باشد: {out!r}"


def test_workflow_treats_cascade_output_as_output_not_as_source():
    """
    `is_output_path` قلبِ گاردِ رگرسیونِ سورس است.

    اگر `verified/*` را «سورس» بشمارد، وجودِ آن هر بار به‌عنوان «تغییرِ
    سورس» دیده می‌شود و انتشار در حلقهٔ تلاشِ مجدد گیر می‌کند. این تست
    خودِ تابعِ شل را جدا می‌کند و **اجرا** می‌کند — به متن اکتفا نمی‌کند.
    """
    import re as _re
    import subprocess

    text = _workflow_text()
    m = _re.search(r"is_output_path\(\)\s*\{(.*?)\n          \}", text, _re.S)
    assert m, "تابعِ is_output_path در گامِ انتشار پیدا نشد"
    body = m.group(1)

    fn = "is_output_path() {" + body + "\n}\n"
    script = fn + '\nfor p in "$@"; do\n' \
                  '  if is_output_path "$p"; then echo "OUT $p"; ' \
                  'else echo "SRC $p"; fi\ndone\n'

    cases_out = ["verified/configs.txt", "verified/singbox.json",
                 "fast/clash.yaml", "secure/configs_base64.txt",
                 "top100.txt", "all/configs.txt", "health.json"]
    cases_src = ["scripts/pipeline.py", ".github/workflows/aggregate.yml",
                 "README.md"]

    proc = subprocess.run(["bash", "-c", script, "bash"] + cases_out + cases_src,
                          capture_output=True, text=True)
    assert proc.returncode == 0, f"اجرای تابع شکست: {proc.stderr}"
    verdict = dict(reversed(ln.split(" ", 1))
                   for ln in proc.stdout.strip().splitlines() if " " in ln)

    for p in cases_out:
        assert verdict.get(p) == "OUT", (
            f"«{p}» خروجی است ولی تابع «{verdict.get(p)}» گفت ⇒ گاردِ "
            f"رگرسیون آن را تغییرِ سورس می‌بیند و انتشار قفل می‌شود")
    for p in cases_src:
        assert verdict.get(p) == "SRC", (
            f"«{p}» سورس است ولی تابع «{verdict.get(p)}» گفت ⇒ ربات "
            f"می‌تواند کارِ مالک را پاک کند")


# ──────────────────────────────────────────────────────────────────────────────
# فاز E — کارگاه A: برندینگ یک **ناوردا** است، نه یک اتفاق
# ──────────────────────────────────────────────────────────────────────────────
# مالکِ مخزن صریحاً خواسته آیدی کانال «همیشه» روی کانفیگ‌ها باشد. پیش از این
# فاز، برندینگ عملاً ۱۰۰٪ بود ولی **هیچ تستی آن را قفل نکرده بود** — یعنی هر
# رگرسیونی بی‌صدا منتشر می‌شد. اندازه‌گیریِ فاز E سه ریسک پیدا کرد:
#
#   ۱. چهار fallbackِ «بی‌برند» در `converters.py` که *امروز* شلیک نمی‌کنند
#      (روی ۸٬۱۳۶ کانفیگِ واقعی سنجیده شد) ولی موضعِ دفاعی‌شان به سمتِ غلط بود.
#   ۲. نامِ سه گروهِ خروجی (`♻️ Auto` در clash و sing-box، `🔯 Fallback` در clash)
#      برند نداشتند — و در UIِ کلاینت **گروه نخستین چیزی است که کاربر می‌بیند**.
#   ۳. هیچ تستی روی نامِ گروه‌ها نبود؛ سوئیتِ ۱۴۰ تستی با نام‌های بی‌برند هم
#      سبز می‌ماند. همین ثابت می‌کند پوشش وجود نداشته.

def _e4_freeze_country(host: str, port: int) -> None:
    """کشور را در کش قفل می‌کند تا تست به DNS/GeoIP دست نزند (قطعی و بی‌شبکه)."""
    core._HOST_COUNTRY_CACHE[f"{host}:{port}".lower()] = ("DE", "🇩🇪")
    core._HOST_COUNTRY_CACHE[host.lower()] = ("DE", "🇩🇪")


#: ریمارک‌های خصمانه. هر ردیف یک شکستِ واقعی یا محتمل است، نه تزئین:
#:   • تبلیغِ کانالِ رقیب — یک موردِ **واقعی** در خروجیِ زنده دیده شده بود
#:   • خالی / فقط‌فاصله — مسیرِ fallbackها را فعال می‌کند
#:   • percent-encoded — اگر unquote نشود برند در متنِ خام گم می‌شود
#:   • یونیکد/RTL — شکستنِ تحلیل‌گرهای ساده
#:   • «a | b | c» — شکلِ لوله‌ای که می‌تواند تحلیلِ ریمارک را گمراه کند
#:   • از قبل برنددار — برندزنیِ دوباره نباید برند را تکرار کند
#:   • ۳۰۰ کاراکتر — طولِ بیمارگونه
_E4_REMARKS = [
    "",
    "📯1@oneclickvpnkeys",
    "%F0%9F%87%A9%F0%9F%87%AA%20DE%20node",
    "🇩🇪 آلمان — سرور تست",
    "a | b | c",
    "DE 🇩🇪 | @Raydikalx | DEADBE",
    "x" * 300,
    "  ",
]


def _e4_corpus():
    """پیکرهٔ خصمانه: ۷ خانوادهٔ پروتکل × ۸ ریمارک = ۵۶ کانفیگِ **خام** (بی‌برند)."""
    host, port = "test-node.example.com", 443
    uuid = "eb78e1f0-d921-4ca9-a889-261fcc5a0547"
    _e4_freeze_country(host, port)

    def vmess_json(rem: str) -> str:
        obj = {"v": "2", "ps": rem, "add": host, "port": str(port), "id": uuid,
               "aid": "0", "net": "ws", "type": "none", "host": host,
               "path": "/", "tls": "tls", "sni": host, "scy": "auto"}
        body = base64.b64encode(
            json.dumps(obj, separators=(",", ":")).encode("utf-8")).decode("utf-8")
        return "vmess://" + body

    ss_ui = base64.b64encode(b"chacha20-ietf-poly1305:secretpass").decode().rstrip("=")
    bases = {
        "vmess-uri": f"vmess://{uuid}@{host}:{port}?encryption=none&security=tls&type=ws&path=%2F",
        "vless": f"vless://{uuid}@{host}:{port}?encryption=none&security=tls&type=ws&path=%2F&sni={host}",
        "trojan": f"trojan://password123@{host}:{port}?security=tls&type=tcp&sni={host}",
        "ss-sip002": f"ss://{ss_ui}@{host}:{port}",
        "hysteria2": f"hysteria2://password123@{host}:{port}?sni={host}",
        "tuic": f"tuic://{uuid}:password123@{host}:{port}?congestion_control=bbr&alpn=h3&sni={host}",
    }
    out = []
    for rem in _E4_REMARKS:
        out.append(("vmess-json", vmess_json(rem)))
        for kind, base in bases.items():
            out.append((kind, base if not rem else base + "#" + rem))
    return out


def _e4_remark_of(line: str) -> str:
    """
    ریمارکِ منتشرشدهٔ یک خط را می‌خواند — برای vmess از داخلِ base64/JSON.

    عمداً از `core` استفاده نمی‌کند تا تست، پیاده‌سازیِ زیرِ آزمون را بازگو
    نکند؛ وگرنه تست با هر باگی هم‌داستان می‌شود و بی‌ارزش است.
    """
    if line.startswith("vmess://"):
        body = line[8:].split("#")[0].strip()
        for pad in ("", "=", "==", "==="):
            try:
                obj = json.loads(
                    base64.urlsafe_b64decode(body + pad).decode("utf-8", "ignore"))
                if isinstance(obj, dict):
                    return str(obj.get("ps") or obj.get("name") or "")
            except Exception:
                continue
    if "#" in line:
        try:
            return urllib.parse.unquote(line.split("#", 1)[1])
        except Exception:
            return line.split("#", 1)[1]
    return ""


def test_branding_survives_every_adversarial_remark_in_the_text_outputs():
    """
    ناوردا: پس از `brand_remark` **هر** خط باید برند داشته باشد — مهم نیست
    ریمارکِ بالادست چه بوده. `configs.txt`، `configs_base64.txt`،
    `protocols/*` و `archive/*` همه از همین یک خط مشتق می‌شوند، پس این تست
    هر چهار قالبِ متنی را پوشش می‌دهد.
    """
    corpus = _e4_corpus()
    assert len(corpus) == 56, f"پیکره کوچک شده: {len(corpus)}"

    bad = []
    for kind, raw in corpus:
        branded = core.brand_remark(raw)
        if core.BRAND_CHANNEL not in _e4_remark_of(branded):
            bad.append((kind, _e4_remark_of(raw)[:40]))
    assert not bad, (
        f"{len(bad)} از {len(corpus)} کانفیگ بی‌برند منتشر می‌شوند — "
        f"خواستهٔ صریحِ مالک نقض می‌شود. نمونه: {bad[:5]}")

    # برندِ رقیب باید **بازنویسی** شود، نه اینکه کنارِ برندِ ما بنشیند.
    ad = [l for k, l in corpus if k == "vless" and "oneclickvpnkeys" in l][0]
    assert "oneclickvpnkeys" not in _e4_remark_of(core.brand_remark(ad)), \
        "تبلیغِ کانالِ رقیب در ریمارکِ منتشرشدهٔ ما باقی مانده است"


def test_branding_survives_in_clash_and_singbox_for_the_adversarial_corpus():
    """
    همان ناوردا در دو قالبِ **ساختاریافته**، با تحلیل‌گرِ رسمی (yaml/json) نه
    regex — چون در فاز E یک «یافتهٔ» غلط دقیقاً از همین اشتباه زاده شد:
    regexِ ساده‌تر از قالبِ داده، `proxy-group` را `proxy` شمرد و ۲ موردِ
    بی‌برندِ کاذب ساخت. قاعده: وقتی ابزارِ سنجش از قالبِ داده ساده‌تر است،
    مرجع، تحلیل‌گرِ رسمی است.
    """
    branded = [core.brand_remark(l) for _, l in _e4_corpus()]

    doc = yaml.safe_load(converters.build_clash_yaml(branded))
    names = [p["name"] for p in doc["proxies"]]
    assert names, "clash هیچ نودی تولید نکرد — تست بی‌معنا می‌شود"
    unbranded = [n for n in names if core.BRAND_CHANNEL not in n]
    assert not unbranded, f"{len(unbranded)} نامِ نودِ clash بی‌برند: {unbranded[:5]}"

    sb = json.loads(converters.build_singbox_json(branded))
    node_tags = [o["tag"] for o in sb["outbounds"]
                 if o["type"] not in ("selector", "urltest", "direct")]
    assert node_tags, "sing-box هیچ outbound نودی تولید نکرد"
    unbranded = [t for t in node_tags if core.BRAND_CHANNEL not in t]
    assert not unbranded, f"{len(unbranded)} تگِ sing-box بی‌برند: {unbranded[:5]}"


def test_every_output_group_name_carries_the_brand():
    """
    گروه‌ها در UIِ کلاینت **بالاتر از** فهرستِ نودها دیده می‌شوند، پس بی‌برند
    بودنشان از بی‌برند بودنِ یک نود بدتر است. تا پیش از فاز E سه گروه بی‌برند
    بودند: `♻️ Auto` (clash و sing-box) و `🔯 Fallback` (clash).
    """
    branded = [core.brand_remark(l) for _, l in _e4_corpus()]

    doc = yaml.safe_load(converters.build_clash_yaml(branded))
    gnames = [g["name"] for g in doc["proxy-groups"]]
    assert len(gnames) >= 3, f"تعدادِ گروه‌های clash کم شد: {gnames}"
    for n in gnames:
        assert core.BRAND_CHANNEL in n, f"گروهِ clash بی‌برند: {n!r}"

    for rule in doc["rules"]:
        target = rule.split(",")[-1]
        assert target in gnames, f"هدفِ rule وجود ندارد: {target!r}"
        assert core.BRAND_CHANNEL in target, f"هدفِ rule بی‌برند: {target!r}"

    sb = json.loads(converters.build_singbox_json(branded))
    gtags = [o["tag"] for o in sb["outbounds"] if o["type"] in ("selector", "urltest")]
    assert len(gtags) >= 2, f"تعدادِ گروه‌های sing-box کم شد: {gtags}"
    for t in gtags:
        assert core.BRAND_CHANNEL in t, f"گروهِ sing-box بی‌برند: {t!r}"
    assert core.BRAND_CHANNEL in sb["route"]["final"], "route.final بی‌برند است"


def test_no_group_reference_is_left_dangling():
    """
    نامِ گروه در چند نقطه ارجاع می‌شود: `proxies` گروهِ select، `rules`،
    `outbounds`/`default` سلکتور، `route.final` و `dns…detour`. اگر نام در یک
    نقطه عوض شود و در بقیه نه، فایل **بی‌صدا** خراب می‌شود: کلاینت گروهی را
    می‌جوید که وجود ندارد. برای همین نام‌ها در `converters.GROUP_*` یک‌جا
    تعریف شده‌اند؛ این تست همان قرارداد را قفل می‌کند.
    """
    branded = [core.brand_remark(l) for _, l in _e4_corpus()]

    doc = yaml.safe_load(converters.build_clash_yaml(branded))
    universe = ({p["name"] for p in doc["proxies"]}
                | {g["name"] for g in doc["proxy-groups"]})
    for g in doc["proxy-groups"]:
        for ref in g.get("proxies", []):
            assert ref in universe, \
                f"گروهِ {g['name']!r} به {ref!r} ارجاع می‌دهد که وجود ندارد"

    # `rules` جدا بررسی می‌شود، نه با فرضِ «چون گروه‌ها درست‌اند قاعده هم
    # درست است». جهش‌سنجی نشان داد نبودِ این بخش یک شکافِ واقعی بود: قاعده‌ی
    # `MATCH,<گروهِ ناموجود>` از همهٔ بررسی‌های قبلی سالم رد می‌شد و کلاینت
    # عملاً هیچ ترافیکی را پروکسی نمی‌کرد.
    assert doc.get("rules"), "Clash بدونِ هیچ قاعده‌ای منتشر شده است"
    for rule in doc["rules"]:
        parts = [s.strip() for s in str(rule).split(",")]
        # قالبِ Clash: «MATCH,TARGET» یا «TYPE,VALUE,TARGET[,params]»
        target = parts[1] if parts[0].upper() == "MATCH" else (
            parts[2] if len(parts) >= 3 else None)
        assert target, f"هدفِ قاعده‌ی {rule!r} قابلِ استخراج نیست"
        assert target in universe or target.upper() in ("DIRECT", "REJECT"), (
            f"قاعده‌ی {rule!r} به {target!r} ارجاع می‌دهد که نه نود است نه گروه "
            f"⇒ کلاینت هیچ چیز را پروکسی نمی‌کند")

    sb = json.loads(converters.build_singbox_json(branded))
    tags = {o["tag"] for o in sb["outbounds"]}
    for o in sb["outbounds"]:
        if o["type"] in ("selector", "urltest"):
            for ref in o.get("outbounds", []):
                assert ref in tags, f"{o['tag']!r} به {ref!r} ارجاع می‌دهد که وجود ندارد"
            if o.get("default"):
                assert o["default"] in tags, f"defaultِ {o['tag']!r} وجود ندارد"
    for srv in sb["dns"]["servers"]:
        if srv.get("detour"):
            assert srv["detour"] in tags, f"detourِ DNS وجود ندارد: {srv['detour']!r}"

    # همان شکاف در sing-box: `route.final` معادلِ `MATCH` در Clash است.
    final = sb["route"].get("final")
    assert final, "sing-box بدونِ route.final منتشر شده است"
    assert final in tags, (
        f"route.final = {final!r} در هیچ outboundای وجود ندارد ⇒ فایل بی‌صدا "
        f"خراب است")
    for r in (sb["route"].get("rules") or []):
        ob = r.get("outbound")
        if ob:
            assert ob in tags, f"قاعده‌ی route به {ob!r} ارجاع می‌دهد که نیست"
    # سرورِ DNSِ نهایی هم باید موجود باشد، وگرنه resolve بی‌صدا می‌شکند
    dns_tags = {s["tag"] for s in sb["dns"]["servers"] if s.get("tag")}
    if sb["dns"].get("final"):
        assert sb["dns"]["final"] in dns_tags, "dns.final وجود ندارد"
    for r in (sb["dns"].get("rules") or []):
        if r.get("server"):
            assert r["server"] in dns_tags, f"قاعده‌ی DNS به {r['server']!r} …"


def test_a_node_can_never_shadow_a_group_name():
    """
    در Clash فضایِ نامِ گروه و نود **یکی** است. نودی که همنامِ یک گروه شود،
    ارجاعِ گروه را می‌دزدد و کلاینت به‌جای گروه به آن نود می‌رسد. امروز با
    برندینگِ ۱۰۰٪ برخورد ممکن نیست، ولی درستی نباید به «بختِ داده» بند باشد:
    نامِ گروه‌ها از پیش در `used_names`/`used_tags` رزرو شده‌اند.
    """
    host, port = "shadow-test.example.com", 8443
    _e4_freeze_country(host, port)
    uuid = "eb78e1f0-d921-4ca9-a889-261fcc5a0547"

    hostile = [
        f"vless://{uuid}@{host}:{port}?encryption=none&security=tls&type=tcp"
        f"&sni={host}#{urllib.parse.quote(g)}"
        for g in (converters.GROUP_MAIN, converters.GROUP_AUTO,
                  converters.GROUP_FALLBACK)
    ]

    doc = yaml.safe_load(converters.build_clash_yaml(hostile))
    gnames = {g["name"] for g in doc["proxy-groups"]}
    pnames = [p["name"] for p in doc["proxies"]]
    assert not (set(pnames) & gnames), (
        f"نودی همنامِ گروه منتشر شد ⇒ ارجاعِ گروه می‌شکند: "
        f"{sorted(set(pnames) & gnames)}")
    assert len(set(pnames)) == len(pnames), "نامِ نودها یکتا نیست"

    sb = json.loads(converters.build_singbox_json(hostile))
    gtags = {o["tag"] for o in sb["outbounds"] if o["type"] in ("selector", "urltest")}
    ntags = [o["tag"] for o in sb["outbounds"]
             if o["type"] not in ("selector", "urltest", "direct")]
    assert not (set(ntags) & gtags), \
        f"outbound همنامِ گروه منتشر شد: {sorted(set(ntags) & gtags)}"


# ──────────────────────────────────────────────────────────────────────────────
# E-2 / E-5 / E-9 / E-10 — قفلِ fallbackهای برنددار، idempotency، قطعیتِ base64
#                          و پینِ نسخهٔ Python
# ──────────────────────────────────────────────────────────────────────────────
# این نیمهٔ دوم بلوکِ فاز E است. نیمهٔ اول (پیکرهٔ خصمانه + گروه‌ها) بالاتر است و
# کمک‌تابع‌های `_e4_corpus` / `_e4_remark_of` / `_e4_freeze_country` را تعریف
# کرده؛ اینجا از همان‌ها استفاده می‌شود تا دو پیکرهٔ موازی و واگرا نداشته باشیم.


def test_converter_default_names_are_branded_not_bare_protocol():
    """E-2 — هیچ نودی نباید با نامِ «برهنه»ی پروتکل («vmess»/«ss»/…) منتشر شود.

    چرا رفتاری و نه جست‌وجویِ متنِ سورس: کامنت‌های خودِ `converters.py` عبارتِ
    قدیمیِ `or "vmess"` را برای توضیحِ «قبلاً چه بود» نقل می‌کنند. آزمونی که در
    متنِ فایل بگردد، روی مستندسازیِ درست مثبتِ کاذب می‌دهد — همان درسی که در این
    مخزن قبلاً با `str.index()` ثبت شده است. پس رفتار سنجیده می‌شود.

    سه لایه پوشش داده می‌شود، چون سه نقطهٔ متفاوتِ کد است:
      ۱) خودِ `_branded_fallback` (واحد)
      ۲) مسیرِ `parse_proxy` — جایی که ریمارکِ بالادست خالی/غایب است
      ۳) موقعیتِ دفاعیِ درونِ `build_clash_yaml` / `build_singbox_json` که با
         دادهٔ امروزی **دست‌نیافتنی** است. برای رسیدن به آن، مبدل‌های سطحِ‌پایین
         موقتاً monkeypatch می‌شوند تا نام/تگِ خالی برگردانند. بدونِ این کار آن
         دو خط هرگز اجرا نمی‌شوند و «پوشش» توهمی است.
    """
    brand = converters.BRAND

    # ── لایهٔ ۱: واحد ────────────────────────────────────────────────────────
    for kind in (None, "", "   ", "vmess", "vless", "ss", "trojan", "🙂"):
        got = converters._branded_fallback(kind)
        assert brand in got, (
            f"_branded_fallback({kind!r}) = {got!r} بی‌برند است ⇒ نودِ بی‌نام "
            f"بی‌برند منتشر می‌شود")
        assert got != (kind or ""), "نام نباید فقط نامِ پروتکلِ برهنه باشد"
    # ورودیِ تهی نباید نامِ بی‌معنیِ « | @brand» بسازد
    assert converters._branded_fallback(None) == f"node | {brand}"
    assert converters._branded_fallback("") == converters._branded_fallback("   ")
    # قطعی است: فقط تابعِ kind، بی‌اثرِ زمان/موقعیت
    assert (converters._branded_fallback("vmess")
            == converters._branded_fallback("vmess"))

    # ── لایهٔ ۲: مسیرِ parse_proxy با ریمارکِ غایب ───────────────────────────
    uu = "eb78e1f0-d921-4ca9-a889-261fcc5a0547"
    host = "test-node.example.com"

    vmess_obj = {"v": "2", "ps": "", "add": host, "port": "443", "id": uu,
                 "aid": "0", "net": "tcp", "type": "none", "tls": "tls"}
    cases = {
        "vmess (ps خالی)": "vmess://" + base64.b64encode(
            json.dumps(vmess_obj).encode()).decode(),
        "vless (بدون #)": f"vless://{uu}@{host}:443?security=tls&type=tcp",
        "trojan (بدون #)": f"trojan://password123@{host}:443?security=tls",
    }
    for label, line in cases.items():
        p = converters.parse_proxy(line)
        assert p is not None, f"«{label}» باید پارس شود"
        assert brand in (p.get("name") or ""), (
            f"«{label}» نامِ {p.get('name')!r} گرفت — بی‌برند")

    # کلیدِ ps کاملاً غایب (نه خالی) هم همان مسیر را می‌رود
    vmess_obj.pop("ps")
    p = converters.parse_proxy("vmess://" + base64.b64encode(
        json.dumps(vmess_obj).encode()).decode())
    assert p is not None and brand in p["name"], "vmess بدون کلیدِ ps بی‌برند شد"

    # ── لایهٔ ۳: موقعیتِ دفاعیِ درونِ سازندهٔ خروجی ──────────────────────────
    lines = [ln for _k, ln in _e4_corpus()]
    _e4_freeze_country(host, 443)

    orig_clash = converters._to_clash_proxy
    orig_sing = converters._to_singbox_outbound
    try:
        def _blank_name(p):
            cp = orig_clash(p)
            if cp:
                cp = dict(cp)
                cp["name"] = ""          # ← شبیه‌سازیِ مبدلی که نام نمی‌دهد
            return cp

        converters._to_clash_proxy = _blank_name
        doc = yaml.safe_load(converters.build_clash_yaml(lines))
        names = [p["name"] for p in doc["proxies"]]
        assert names, "پیکره باید حداقل یک پروکسیِ Clash تولید کند"
        unbranded = [n for n in names if brand not in n]
        assert not unbranded, (
            f"{len(unbranded)} نودِ Clash با نامِ خالی به fallbackِ بی‌برند "
            f"رسید — نمونه: {unbranded[:3]}")
        # و یکتاسازی هم باید کار کند، وگرنه گروه به نودِ همنام می‌شکند
        assert len(set(names)) == len(names), "نام‌های fallback یکتا نشدند"
    finally:
        converters._to_clash_proxy = orig_clash

    try:
        def _blank_tag(p):
            ob = orig_sing(p)
            if ob:
                ob = dict(ob)
                ob["tag"] = ""
            return ob

        converters._to_singbox_outbound = _blank_tag
        sb = json.loads(converters.build_singbox_json(lines))
        tags = [o["tag"] for o in sb["outbounds"]
                if o["type"] not in ("selector", "urltest", "direct")]
        assert tags, "پیکره باید حداقل یک outboundِ نود تولید کند"
        unbranded = [t for t in tags if brand not in t]
        assert not unbranded, (
            f"{len(unbranded)} outboundِ sing-box با تگِ خالی به fallbackِ "
            f"بی‌برند رسید — نمونه: {unbranded[:3]}")
        assert len(set(tags)) == len(tags), "تگ‌های fallback یکتا نشدند"
    finally:
        converters._to_singbox_outbound = orig_sing

    # بازگردانیِ موفق را هم اثبات کن؛ وگرنه آزمون‌های بعدی روی حالتِ آلوده
    # اجرا می‌شوند و شکستشان گمراه‌کننده است.
    assert converters._to_clash_proxy is orig_clash
    assert converters._to_singbox_outbound is orig_sing


def test_brand_remark_is_idempotent_over_the_adversarial_corpus():
    """E-5 — `brand_remark` باید تابعِ خودتوان (idempotent) باشد.

    اهمیت: خط‌لوله ممکن است ورودی‌ای بگیرد که *قبلاً* برندخوردهٔ همین مخزن
    است (کانفیگ‌های ما در منابعِ دیگر بازنشر می‌شوند و از آن‌ها fetch می‌کنیم).
    اگر برندینگ خودتوان نباشد، ریمارک با هر دور رشد می‌کند:
    «DE | @X | AAA | @X | AAA | …» — و هم زشت است، هم در برخی کلاینت‌ها
    نامِ بیش‌ازحد بلند را می‌بُرد و برند را قربانی می‌کند.

    ناوردا روی *ریمارکِ استخراج‌شده* سنجیده می‌شود، نه روی رشتهٔ خامِ خط.
    دلیلِ اندازه‌گیری‌شده: در `vmess://` ریمارک درونِ JSONِ base64شده
    (کلیدِ `ps`) می‌نشیند، پس رشتهٔ برند در متنِ خامِ خط **صفر** بار دیده
    می‌شود در حالی که کاربر آن را می‌بیند. شمارشِ خام، آزمونی غلط می‌ساخت.
    """
    brand = core.BRAND_CHANNEL
    _e4_freeze_country("test-node.example.com", 443)

    for kind, line in _e4_corpus():
        once = core.brand_remark(line, 0)

        # (۱) دو بار = یک بار
        twice = core.brand_remark(once, 0)
        assert twice == once, (
            f"[{kind}] brand_remark خودتوان نیست:\n  once={once[:160]!r}"
            f"\n  twice={twice[:160]!r}")

        # (۲) پنج اعمالِ متوالی هم نقطهٔ ثابت را ترک نمی‌کند
        cur = once
        for i in range(5):
            nxt = core.brand_remark(cur, 0)
            assert nxt == cur, (
                f"[{kind}] در اعمالِ #{i + 2} از نقطهٔ ثابت خارج شد")
            cur = nxt

        # (۳) برند دقیقاً یک بار در ریمارک — نه صفر، نه تکراری
        rem = _e4_remark_of(once)
        cnt = rem.count(brand)
        assert cnt == 1, (
            f"[{kind}] برند {cnt} بار در ریمارک آمد (باید ۱): {rem[:160]!r}")

        # (۴) قالبِ سه‌بخشیِ «کشور | برند | TAG» حفظ شود و بخشِ سومْ همان
        #     برچسبِ هویتِ خطِ اصلی باشد (نه برچسبِ خطِ برندخورده — چون
        #     `dedup_key` نباید به ریمارک وابسته باشد).
        parts = [s.strip() for s in rem.split("|")]
        assert len(parts) >= 3, f"[{kind}] قالبِ ریمارک شکست: {rem[:160]!r}"
        assert parts[1] == brand, (
            f"[{kind}] برند در جایگاهِ دومِ ریمارک نیست: {parts!r}")
        assert parts[2] == core.stable_label(line), (
            f"[{kind}] برچسبِ هویت با stable_label(خطِ خام) نمی‌خواند ⇒ "
            f"هویت به ریمارک وابسته شده است")


def test_decode_base64_text_refuses_ambiguous_input_deterministically():
    """E-9 — رگرسیونِ وکتورهای base64: خروجی نباید به نسخهٔ Python وابسته باشد.

    زمینه (اندازه‌گیری‌شده در فاز E): `base64.b64decode(..., validate=False)`
    در Python ≤۳.۱۱ نویسه‌های بیرونِ الفبا — از جمله `=`ِ میانِ رشته — را دور
    می‌ریزد و *چیزی* برمی‌گرداند؛ در ۳.۱۲+ رفتارِ هرس تغییر کرده و خروجیِ
    دیگری می‌دهد. چون `dedup_key` روی همین خروجی ساخته می‌شود، هویتِ کانفیگ
    بین مفسرها فرق می‌کرد. `decode_base64_text` با «اول اعتبارسنجیِ نحوی،
    بعد دیکود» این را قطعی می‌کند: ورودیِ مبهم ⇒ `None`.

    مقادیرِ زیر همه *سنجیده* شده‌اند، نه حدس.
    """
    d = core.decode_base64_text

    # ── ورودیِ مبهم (padding در میانِ رشته) ⇒ قطعاً None ────────────────────
    ambiguous = [
        "QUJDRA==EFGH",          # کمینه‌ترین بازتولیدکنندهٔ اختلافِ نسخه‌ها
        "QUJDRA==@host:443",     # همان الگو در بافتِ واقعیِ ss:sip002
        "QUJDRQ=XYZ",            # یک `=` میانی
        "QUJD=RA==",             # `=` میانی + padding پایانی
        "====",                  # فقط padding
    ]
    for v in ambiguous:
        got = d(v)
        assert got is None, (
            f"{v!r} نحواً base64 نیست ولی تابع {got!r} داد ⇒ رفتارْ "
            f"نسخه‌وابسته باقی مانده است")

    # ── نویسهٔ بیرونِ الفبا ⇒ None (نه «هرسِ خاموش») ─────────────────────────
    for v in ("!!!!", "AB CD", "ab\ncd", "ABCD%3D", "زبان"):
        assert d(v) is None, f"{v!r} باید رد شود، نه هرس"

    # ── طولِ نامعتبر (۴k+1) ⇒ None ──────────────────────────────────────────
    for v in ("ABCDE", "a-b_c", "A"):
        assert d(v) is None, f"طولِ {len(v)} نمی‌تواند base64 معتبر باشد: {v!r}"

    # ── ورودیِ درست ⇒ دیکودِ درست (رگرسیونِ معکوس: تابع نباید همه را رد کند) ─
    good = {
        "QUJDRA==": "ABCD",
        "QUJDRA": "ABCD",       # بدون padding — پذیرفته و ترمیم می‌شود
        "SGVsbG8=": "Hello",
        "QQ==": "A",
    }
    for src, want in good.items():
        assert d(src) == want, f"{src!r} باید {want!r} بدهد، داد {d(src)!r}"

    # هر دو الفبا (استاندارد و url-safe) باید کار کنند، چون منابعِ بالادست
    # هر دو را می‌فرستند.
    raw = b"\xfb\xff\xfe~ok"
    std = base64.b64encode(raw).decode()
    url = base64.urlsafe_b64encode(raw).decode()
    assert "+" in std or "/" in std, "وکتورِ آزمون باید نویسهٔ افتراقی داشته باشد"
    assert "-" in url or "_" in url
    assert d(std) is not None and d(url) is not None, (
        "هر دو الفبا باید پشتیبانی شوند")
    assert d(std) == d(url), "دو الفبای همان بایت‌ها باید یک نتیجه بدهند"

    # ── تهی/None ⇒ None و هرگز استثنا ───────────────────────────────────────
    for v in ("", None):
        assert d(v) is None
    # قطعیت: ۳ فراخوانِ متوالی همان نتیجه
    for v in ambiguous + list(good):
        assert d(v) == d(v) == d(v)


def test_the_identity_functions_never_call_the_version_dependent_primitive():
    """E-9 — قفلِ ساختاری: مسیرِ هویت نباید مستقیماً `b64decode` صدا بزند.

    آزمونِ رفتاری بالا فقط *امروز* را می‌بندد؛ این آزمون **الگو** را می‌بندد:
    اگر کسی فردا در `dedup_key` دوباره `base64.b64decode(...)` بنویسد،
    ممکن است روی مفسرِ CI هم نتیجهٔ درست بدهد و آزمونِ رفتاری سبز بماند،
    در حالی که هویت دوباره نسخه‌وابسته شده است.

    از AST استفاده می‌شود، نه جست‌وجویِ متن: در همین فایل و در `core.py`
    نامِ `b64decode` داخلِ **کامنت** آمده (برای توضیحِ همین باگ)، و آزمونِ
    متنی روی مستندسازی مثبتِ کاذب می‌دهد — درسِ ثبت‌شدهٔ همین مخزن.
    """
    import ast as _ast
    import inspect as _inspect

    tree = _ast.parse(_inspect.getsource(core))
    funcs = {n.name: n for n in tree.body if isinstance(n, _ast.FunctionDef)}

    identity_path = ["dedup_key", "stable_label", "endpoint_of", "brand_remark"]
    for name in identity_path:
        assert name in funcs, f"تابعِ «{name}» در core.py پیدا نشد"
        offenders = []
        for sub in _ast.walk(funcs[name]):
            if isinstance(sub, _ast.Attribute) and "b64decode" in sub.attr:
                offenders.append(f"{name}: .{sub.attr} (خط {sub.lineno})")
            elif isinstance(sub, _ast.Name) and "b64decode" in sub.id:
                offenders.append(f"{name}: {sub.id} (خط {sub.lineno})")
        assert not offenders, (
            "مسیرِ هویت مستقیماً از پریمیتیوِ نسخه‌وابسته استفاده می‌کند "
            f"⇒ {offenders}. از `core.decode_base64_text()` استفاده کنید.")

    # روی معکوس هم صحت‌سنجی: آزمون باید *بتواند* تخلف را ببیند. اگر هیچ
    # تابعی در فایل b64decode نداشته باشد، آزمونِ بالا بی‌معنی و همیشه‌سبز
    # است. `try_base64_decode` استثنایِ **عمدی** است: روی *بدنهٔ منبع* کار
    # می‌کند نه روی هویت، و باید بیشینه‌بخشنده بماند.
    assert "try_base64_decode" in funcs, "تابعِ استثنا حذف/تغییرِ نام شده است"
    exception_hits = [
        sub.attr for sub in _ast.walk(funcs["try_base64_decode"])
        if isinstance(sub, _ast.Attribute) and "b64decode" in sub.attr]
    assert exception_hits, (
        "`try_base64_decode` دیگر b64decode صدا نمی‌زند ⇒ یا رفتارش عوض شده "
        "یا آزمونِ باقیِ این تابع سنجهٔ خود را از دست داده است")

    # و خودِ پریمیتیوِ قطعی باید فقط یک الفبا داشته باشد (urlsafe کافی است،
    # چون پیش از دیکود نویسه‌های `-_` و `+/` هر دو مجاز شمرده می‌شوند).
    assert "decode_base64_text" in funcs, "پریمیتیوِ قطعی حذف شده است"
    prim = [sub.attr for sub in _ast.walk(funcs["decode_base64_text"])
            if isinstance(sub, _ast.Attribute) and "b64decode" in sub.attr]
    assert prim == ["urlsafe_b64decode"], (
        f"decode_base64_text باید تنها از urlsafe_b64decode استفاده کند، "
        f"دیده شد: {prim}")


def test_workflow_pins_python_precisely_because_identity_depends_on_it():
    """E-10 — پینِ `python-version` در ورک‌فلو **بارکش** است، نه تزئینی.

    با اصلاحِ فاز E، `dedup_key` دیگر بین ۳.۱۰ و ۳.۱۳ فرق نمی‌کند (اثباتِ
    md5 روی کلِ ۸٬۱۳۶ کلید). ولی پینِ دقیق همچنان لازم است: هر رفتارِ
    نسخه‌وابستهٔ *بعدی* در کتابخانهٔ استانداردْ می‌تواند هویت را جابه‌جا کند و
    نتیجه‌اش «بازنویسیِ کلِ فایلِ خروجی در یک ران» است. این آزمون سه چیز را
    قفل می‌کند:

      ۱) حداقل یک مرحلهٔ `setup-python` وجود دارد (حذفش باید آزمون را بشکند)
      ۲) هر مرحله پینِ *صریح* دارد — نه غایب، نه `3.x`، نه فقط `3`
      ۳) مقدار در YAML **رشته** است. اگر بی‌نقل‌قول نوشته شود، YAML آن را
         عدد می‌خواند و `3.10` به `3.1` تبدیل می‌شود — نسخه‌ای که وجود ندارد
         و CI را می‌شکند یا بدتر، نسخهٔ نادرست نصب می‌کند.
    """
    doc = yaml.safe_load(_workflow_text())
    jobs = doc.get("jobs") or {}
    assert jobs, "ورک‌فلو هیچ jobای ندارد"

    pins = []
    for job_name, job in jobs.items():
        for step in (job.get("steps") or []):
            uses = str(step.get("uses") or "")
            if "actions/setup-python" in uses:
                pins.append((job_name, uses, (step.get("with") or {}).get(
                    "python-version")))

    assert pins, (
        "هیچ مرحلهٔ actions/setup-python پیدا نشد ⇒ CI روی Pythonِ پیش‌فرضِ "
        "runner اجرا می‌شود که GitHub بی‌اطلاع ما ارتقایش می‌دهد، و هویتِ "
        "کانفیگ‌ها می‌تواند یک‌شبه جابه‌جا شود")

    for job_name, uses, pin in pins:
        assert pin is not None, (
            f"[{job_name}/{uses}] بدونِ python-version ⇒ پین وجود ندارد")
        assert isinstance(pin, str), (
            f"[{job_name}] python-version باید در YAML نقل‌قول شود؛ الان "
            f"{type(pin).__name__} است ({pin!r}) — «3.10» بی‌نقل‌قول به «3.1» "
            f"تبدیل می‌شود")
        pin_s = pin.strip()
        assert pin_s, f"[{job_name}] python-version تهی است"
        bits = pin_s.split(".")
        assert len(bits) >= 2, (
            f"[{job_name}] پینِ «{pin_s}» دقیق نیست؛ حداقل major.minor لازم است")
        assert all(b.isdigit() for b in bits[:2]), (
            f"[{job_name}] پینِ «{pin_s}» شاملِ محدودهٔ شناور است (مثلِ x/*) — "
            f"نسخه باید عددیِ صریح باشد")


# ──────────────────────────────────────────────────────────────────────────────
# E-6 / E-11 — دروازهٔ انتشارِ برند و انتسابِ درستِ آمارِ حذفِ مبدل‌ها
# ──────────────────────────────────────────────────────────────────────────────


def _e6_sources(lines):
    """یک «منبع» ساختگی برای `aggregate.process_category` بساز."""
    url = "https://example.invalid/e6"
    return {url: list(lines)}, [url]


def test_the_publish_gate_drops_unbranded_lines_instead_of_publishing_them():
    """E-6 — اگر برندینگ روی خطی شکست بخورد، آن خط **منتشر نمی‌شود**.

    ناوردایِ محصول (سیاستِ مالک، بالای `core.py`): هر نودِ منتشرشده باید برند
    داشته باشد. `brand_remark` امروز روی ۱۰۰٫۰۰٪ خطوط موفق است، ولی «امروز
    موفق است» ضمانتِ فردا نیست: قالبی تازه از بالادست می‌تواند مسیری بسازد که
    برندینگ خاموشانه ردش کند.

    چهار سناریو سنجیده می‌شود — چون هر چهار، رفتارِ *متفاوتی* از دروازه
    می‌خواهند و آزمونی که فقط یکی را ببیند، بقیه را باز می‌گذارد:

      ۱) خطِ سالم        → منتشر می‌شود، هیچ شمارنده‌ای تکان نمی‌خورد
      ۲) برندینگِ شکسته  → حذف + شمارش، و **اجرا ادامه می‌یابد** (نه abort)
      ۳) شکستِ گذرا      → تلاشِ دوم نجاتش می‌دهد و جدا شمرده می‌شود
      ۴) شکستِ جزئی      → فقط خطِ بد می‌افتد، خطوطِ خوبِ همان دور می‌مانند
    """
    _e4_freeze_country("test-node.example.com", 443)
    corpus = [ln for _k, ln in _e4_corpus()]
    per_source, urls = _e6_sources(corpus)

    # ── ۱) خطِ سالم: صفر مداخله ─────────────────────────────────────────────
    r = aggregate.process_category(per_source, urls, {})
    assert r.unique, "پیکره باید کانفیگِ یکتا تولید کند"
    assert r.unbranded_dropped == 0, (
        f"دروازه {r.unbranded_dropped} خطِ سالم را انداخت ⇒ رگرسیون")
    assert r.unbranded_rebranded == 0, "خطِ سالم نباید نیاز به برندِ دوباره داشته باشد"
    assert all(core.is_branded(x) for x in r.unique), (
        "خروجیِ دروازه باید ۱۰۰٪ برنددار باشد")
    healthy_count = len(r.unique)

    orig = core.brand_remark
    try:
        # ── ۲) برندینگِ کاملاً شکسته ────────────────────────────────────────
        core.brand_remark = lambda line, idx=None: (
            line.split("#")[0] + "#no-brand")
        r2 = aggregate.process_category(per_source, urls, {})
        assert r2.unique == [], (
            f"{len(r2.unique)} خطِ بی‌برند منتشر شد ⇒ نقضِ ناوردایِ محصول")
        assert r2.unbranded_dropped == healthy_count, (
            f"شمارشِ حذف غلط: {r2.unbranded_dropped} != {healthy_count}")
        # سقفِ نمونه‌ها: `health.json` را کاربران دانلود می‌کنند
        assert len(r2.unbranded_samples) <= 3, (
            f"{len(r2.unbranded_samples)} نمونه ذخیره شد ⇒ health.json باد می‌کند")
        assert r2.unbranded_samples, "بدونِ نمونه، ریشه‌یابی ناممکن است"
        assert all(len(s) <= 160 for s in r2.unbranded_samples), (
            "نمونه‌ها باید کوتاه شوند")

        # ── ۳) شکستِ گذرا: تلاشِ دوم نجات می‌دهد ────────────────────────────
        calls = {"n": 0}

        def _flaky(line, idx=None):
            calls["n"] += 1
            if calls["n"] % 2 == 1:
                return line.split("#")[0] + "#no-brand"
            return orig(line, idx)

        core.brand_remark = _flaky
        r3 = aggregate.process_category(per_source, urls, {})
        assert r3.unbranded_dropped == 0, (
            "تلاشِ دوباره موفق بود ولی خط حذف شد")
        assert r3.unbranded_rebranded == healthy_count, (
            f"شمارشِ rebranded غلط: {r3.unbranded_rebranded}")
        assert len(r3.unique) == healthy_count and all(
            core.is_branded(x) for x in r3.unique)

        # ── ۴) شکستِ جزئی: خطوطِ خوب قربانیِ خطِ بد نشوند ───────────────────
        #
        # نکتهٔ ظریف که اولین طرحِ این آزمون را غلط کرد: دروازه برای هر خط
        # `brand_remark` را **دو بار** صدا می‌زند (تلاش + تلاشِ دوباره). پس
        # شمارشِ فراخوانی، خطِ قربانی را مشخص نمی‌کند — تلاشِ دومْ خطِ بد را
        # نجات می‌داد و آزمون رفتارِ درست را «شکست» می‌دید. قربانی باید با
        # *هویتِ خط* شناسایی شود تا هر دو تلاش شکست بخورد.
        victim_core = None
        for _k, ln in _e4_corpus():
            if _k == "vless":
                victim_core = ln.split("#")[0]
                break
        assert victim_core, "پیکره باید نمونهٔ vless داشته باشد"

        def _one_bad(line, idx=None):
            if line.split("#")[0] == victim_core:
                return line.split("#")[0] + "#no-brand"
            return orig(line, idx)

        core.brand_remark = _one_bad
        r4 = aggregate.process_category(per_source, urls, {})
        assert r4.unbranded_dropped >= 1, "خطِ بد باید حذف شود"
        assert r4.unbranded_rebranded == 0, (
            "خطِ بد در هر دو تلاش بی‌برند بود، پس نباید rebranded شمرده شود")
        assert len(r4.unique) >= healthy_count - 2, (
            f"شکستِ یک خط، {healthy_count - len(r4.unique)} خط را برد ⇒ "
            f"دروازه بیش‌ازحد تنبیه‌گر است")
        assert all(core.is_branded(x) for x in r4.unique)
    finally:
        core.brand_remark = orig
    assert core.brand_remark is orig, "monkeypatch بازگردانده نشد"


def test_is_branded_reads_the_remark_the_user_actually_sees():
    """E-6 — تعریفِ «برنددار» باید همان چیزی باشد که کاربر می‌بیند.

    این آزمون دو خطای *دقیقاً مقابلِ هم* را می‌بندد:

      • منفیِ کاذب — `BRAND_CHANNEL in line`: در `vmess://` ریمارک درونِ JSONِ
        base64شده است و در متنِ خام دیده نمی‌شود. اندازه‌گیریِ زنده: از ۸٬۱۳۶
        خطِ منتشرشده، ۲٬۳۵۶ خط رشتهٔ برند را در متنِ خام **ندارند** ولی همه
        در کلاینت برنددار دیده می‌شوند. با آن تعریفِ ساده، دروازه ۲٬۳۵۶ نودِ
        سالم را می‌انداخت.
      • مثبتِ کاذب — برند جایی غیر از ریمارک (مثلاً در query یا نامِ میزبان)
        نباید «برنددار» شمرده شود، چون کاربر چیزی نمی‌بیند.
    """
    brand = core.BRAND_CHANNEL
    _e4_freeze_country("test-node.example.com", 443)

    # همهٔ اعضای پیکره پس از برندینگ باید «برنددار» تشخیص داده شوند
    for kind, line in _e4_corpus():
        b = core.brand_remark(line, 1)
        assert core.is_branded(b), (
            f"[{kind}] برندخورده است ولی is_branded منفی داد: {b[:140]!r}")
        assert brand in core.remark_of(b), f"[{kind}] ریمارک برند ندارد"

    # منفیِ کاذبِ تعریفِ ساده را *اثبات* کن: باید حداقل یک vmess باشد که
    # رشتهٔ برند در متنِ خامش نیست ولی is_branded مثبت است.
    hidden = [core.brand_remark(ln, 1) for k, ln in _e4_corpus()
              if k == "vmess-json"]
    assert hidden, "پیکره باید vmess-json داشته باشد"
    assert any(brand not in h for h in hidden), (
        "وکتورِ آزمون بی‌سنجه است: باید vmessای باشد که برند را در متنِ خام "
        "نشان ندهد")
    assert all(core.is_branded(h) for h in hidden), (
        "vmessِ برنددار باید مثبت تشخیص داده شود (منفیِ کاذبِ تعریفِ ساده)")

    # مثبتِ کاذب: برند در query، نه در ریمارک
    uu = "eb78e1f0-d921-4ca9-a889-261fcc5a0547"
    sneaky = f"vless://{uu}@test-node.example.com:443?sni={brand}#plain-name"
    assert not core.is_branded(sneaky), (
        "برندِ بیرونِ ریمارک نباید «برنددار» شمرده شود — کاربر آن را نمی‌بیند")
    assert core.remark_of(sneaky) == "plain-name"

    # خطِ بی‌ریمارک و ورودی‌های مرزی
    for v in ("", "   ", f"vless://{uu}@test-node.example.com:443"):
        assert core.remark_of(v) == ""
        assert not core.is_branded(v)


def test_health_report_attributes_converter_drops_to_the_right_category():
    """E-11 — عددِ حذفِ مبدل در `health.json` باید به دستهٔ درست تعلق داشته باشد.

    ریشهٔ باگ (اندازه‌گیری‌شده): `converters._drops` سراسری است و
    `build_clash_yaml`/`build_singbox_json` در شروعِ کار `clear_target()`
    می‌زنند. فایل‌ها به ترتیبِ all → heavy → light نوشته می‌شوند و گزارشِ
    سلامت **بعد** از همهٔ آن‌ها ساخته می‌شد، پس عددِ منتشرشده فقط به `light`
    تعلق داشت. رویِ دادهٔ زنده: منتشر می‌شد clash=۲۱ / singbox=۱۰۲ در حالی که
    مقدارِ درستِ `all` برابرِ clash=۹۳ / singbox=۳۵۶ بود — یعنی خطای بیش از
    چهاربرابر در همان سنجه‌ای که برای «هشدارِ حذفِ ناگهانیِ هزاران کانفیگ»
    ساخته شده بود.
    """
    _e4_freeze_country("test-node.example.com", 443)
    branded = [core.brand_remark(ln, i + 1)
               for i, (_k, ln) in enumerate(_e4_corpus())]

    class _R:
        def __init__(self, u):
            self.unique = list(u)
            self.broken = []
            self.duplicates = []
            self.total_seen = len(u)
            self.active_sources = 1
            self.protocol_counts = {}
            self.unbranded_dropped = 0
            self.unbranded_rebranded = 0
            self.unbranded_samples = []

    # دو دسته با تعدادِ حذفِ *متفاوت* — وگرنه آزمون سنجه‌ای ندارد
    big = _R(branded)
    small = _R(branded[:6])
    results = {"all": big, "light": small}

    import tempfile as _tf
    with _tf.TemporaryDirectory() as td:
        # الف) رفتارِ باگ‌دار را بازتولید کن: snapshot فقط در پایان
        for cat, rr in results.items():
            aggregate.write_category(td, cat, rr)
        buggy = converters.drop_stats()

        # ب) رفتارِ درست: snapshot پس از هر دسته
        per_cat = {}
        for cat, rr in results.items():
            aggregate.write_category(td, cat, rr)
            per_cat[cat] = converters.drop_stats()

    a_total = per_cat["all"]["clash"]["total"]
    l_total = per_cat["light"]["clash"]["total"]
    assert a_total != l_total, (
        f"وکتورِ آزمون بی‌سنجه است: all و light هر دو {a_total} حذف دارند")
    assert buggy["clash"]["total"] == l_total, (
        "فرضِ ریشهٔ باگ تأیید نشد — سنجهٔ این آزمون نامعتبر است")

    health = aggregate.build_health_report(1.0, per_cat, results)
    assert health["converters"]["clash"]["total"] == a_total, (
        f"عددِ منتشرشده {health['converters']['clash']['total']} است ولی "
        f"دستهٔ `all` — همان لینکِ پیش‌فرضِ کاربران — {a_total} حذف داشت")
    assert health["converters_by_category"], "تفکیکِ دسته‌ها منتشر نمی‌شود"
    assert set(health["converters_by_category"]) == set(results), (
        "همهٔ دسته‌ها باید در تفکیک باشند")

    # شمارنده‌های دروازهٔ برند هم باید رصدپذیر باشند
    assert health["brand_gate"] is not None, "brand_gate در گزارش نیست"
    for cat in results:
        assert health["brand_gate"][cat] == {
            "dropped": 0, "rebranded": 0, "samples": []}, (
            f"brand_gate[{cat}] نادرست است")

    # سازگاریِ عقب‌رو: امضای قدیمی نباید بشکند (مصرف‌کننده‌های بیرونی)
    old = aggregate.build_health_report(1.0)
    assert "converters" in old and old["converters_by_category"] is None
    assert old["brand_gate"] is None
    assert set(old) >= {"brand", "checked_at", "summary", "sources",
                        "converters", "geo"}, "کلیدهای قدیمیِ گزارش حفظ نشدند"


def test_the_drop_stats_snapshot_happens_inside_the_per_category_loop():
    """E-11 — نقطهٔ *فراخوانی* هم قفل شود، نه فقط تابعِ گزارش.

    آزمونِ بالا `build_health_report` را مستقیم صدا می‌زند و صحتِ آن را ثابت
    می‌کند، ولی باگِ اصلی در **جای فراخوانی** بود: snapshot باید *درونِ* حلقهٔ
    دسته‌ها و بلافاصله پس از `write_category` گرفته شود، وگرنه
    `clear_target()`ِ دستهٔ بعدی آن را پاک می‌کند. اگر کسی فردا آن خط را از
    حلقه بیرون ببرد، همان باگ برمی‌گردد و هیچ آزمونِ رفتاری آن را نمی‌بیند
    (چون `main()` شبکه می‌خواهد و در این مجموعه اجرا نمی‌شود).

    از AST استفاده می‌شود، نه جست‌وجویِ متن: توضیحاتِ خودِ `aggregate.py` نامِ
    `drop_stats` را برای شرحِ همین باگ نقل می‌کنند.
    """
    import ast as _ast
    import inspect as _inspect

    tree = _ast.parse(_inspect.getsource(aggregate))
    main_fn = [n for n in tree.body
               if isinstance(n, _ast.FunctionDef) and n.name == "main"]
    assert main_fn, "تابعِ main در aggregate.py پیدا نشد"

    def _called(node):
        names = set()
        for s in _ast.walk(node):
            if isinstance(s, _ast.Call):
                f = s.func
                nm = (f.attr if isinstance(f, _ast.Attribute)
                      else (f.id if isinstance(f, _ast.Name) else ""))
                if nm:
                    names.add(nm)
        return names

    write_loops = [n for n in _ast.walk(main_fn[0])
                   if isinstance(n, _ast.For) and "write_category" in _called(n)]
    assert write_loops, "حلقه‌ای که write_category صدا می‌زند پیدا نشد"
    for loop in write_loops:
        assert "drop_stats" in _called(loop), (
            f"حلقهٔ نوشتنِ دسته‌ها (خط {loop.lineno}) snapshotِ drop_stats "
            f"نمی‌گیرد ⇒ عددِ health.json دوباره به آخرین دسته تعلق می‌گیرد")

    # و گزارش باید با هر دو آرگومانِ تازه صدا زده شود، نه با امضای قدیمی
    health_calls = [s for s in _ast.walk(main_fn[0])
                   if isinstance(s, _ast.Call)
                   and isinstance(s.func, _ast.Name)
                   and s.func.id == "build_health_report"]
    assert health_calls, "main باید build_health_report را صدا بزند"
    for c in health_calls:
        assert len(c.args) + len(c.keywords) >= 3, (
            "build_health_report بدونِ تفکیکِ دسته‌ها و نتایج صدا زده شده ⇒ "
            "گزارش به رفتارِ باگ‌دارِ قبلی برمی‌گردد")


# ──────────────────────────────────────────────────────────────────────────────
# اجرا بدون pytest
# ──────────────────────────────────────────────────────────────────────────────

# ══════════════════════════════════════════════════════════════════════════════
# فاز F — پارسِ authority در شاخهٔ ss:// از dedup_key
#
# پیش از این فاز، شاخهٔ ss هیچ تستی نداشت (`grep sip002` → صفر). نقص: عبارتِ
# `rest.rsplit("@", 1)` روی **کلِ** بدنه اجرا می‌شد، پس '@'ِ داخلِ query
# (مثلِ `?note=@SomeChannel`) به‌عنوان مرزِ userinfo/host گرفته می‌شد و
# host خالی و port نامِ کانال می‌شد. شمارشِ زنده: ۱۴ کلید از ۳٬۰۰۶ خطِ ss.
# ══════════════════════════════════════════════════════════════════════════════

def _f_ss_parts(key: str):
    """(userinfo, host, port) را از کلیدِ `ss:sip002:...` بیرون می‌کشد."""
    assert key.startswith("ss:sip002:"), f"not a sip002 key: {key!r}"
    body = key[len("ss:sip002:"):]
    body, _, port = body.rpartition(":")
    userinfo, _, host = body.rpartition("@")
    return userinfo, host, port


def _f_ss_key_old_algorithm(line: str) -> str:
    """بازسازیِ **الگوریتمِ قدیمِ باگ‌دار** — فقط برای تستِ کنترل.

    این تابع عمداً کدِ قبل از وصله را تکرار می‌کند تا بتوانیم اثبات کنیم
    تست‌های این بلوک واقعاً ابطال‌پذیرند: اگر وصله برگردد، خروجی همین می‌شود.
    """
    without_remark = line.split("#")[0].strip()
    rest = without_remark[5:]
    if "@" in rest:
        userinfo, hostpart = rest.rsplit("@", 1)
        hostpart = hostpart.split("?")[0]
        decoded_ui = core.decode_base64_text(userinfo)
        if decoded_ui and ":" in decoded_ui:
            userinfo = decoded_ui
        userinfo = urllib.parse.unquote(userinfo).lower()
        host, _, port = hostpart.rpartition(":")
        return f"ss:sip002:{userinfo}@{host.lower()}:{port}"
    return ""


# userinfoِ base64 که به `chacha20-ietf-poly1305:deadbeefcafe1234` باز می‌شود.
_F_UI_B64 = base64.b64encode(
    b"chacha20-ietf-poly1305:deadbeefcafe1234").decode("ascii")


def test_zz_f_ss_at_in_query_does_not_destroy_endpoint():
    """S1 — '@' داخلِ query نباید host/port را نابود کند."""
    line = f"ss://{_F_UI_B64}@1.2.3.4:11201?note=@SomeChannel#tag"
    ui, host, port = _f_ss_parts(core.dedup_key(line))
    assert host == "1.2.3.4", f"host={host!r}"
    assert port == "11201", f"port={port!r}"
    assert "note=" not in ui, f"query leaked into userinfo: {ui!r}"
    assert "somechannel" not in ui.lower(), f"tag leaked: {ui!r}"


def test_zz_f_ss_two_at_in_query():
    """S2 — دو '@' در query هم باید بی‌اثر باشد."""
    line = f"ss://{_F_UI_B64}@1.2.3.4:11201?note=@A&ref=@B"
    _ui, host, port = _f_ss_parts(core.dedup_key(line))
    assert (host, port) == ("1.2.3.4", "11201"), (host, port)


def test_zz_f_ss_slash_before_query_port_clean():
    """S3 — '/' قبل از '?' نباید به port بچسبد."""
    line = f"ss://{_F_UI_B64}@1.2.3.4:443/?plugin=obfs-local"
    _ui, host, port = _f_ss_parts(core.dedup_key(line))
    assert port == "443", f"port polluted by slash: {port!r}"
    assert host == "1.2.3.4", f"host={host!r}"


def test_zz_f_ss_2022_userinfo_with_slash_preserved():
    """S4 — userinfoِ SS2022 با '/' و '+' و '=' باید حفظ شود و host درست بیاید.

    این حالت رگرسیونِ *کاندیدِ اولِ خودم* بود: بریدنِ authority سرِ نخستین '/'
    (قاعدهٔ خالصِ RFC 3986) این خط را به شاخهٔ legacy می‌انداخت و کلید را
    خراب‌تر می‌کرد. الگوریتمِ درست فقط سرِ '?' می‌بُرد.
    """
    ui = "2022-blake3-aes-256-gcm:bw2o/kKFuOWo+xcI3F6PqNg=:o0BV/LUba3D+ZA="
    line = f"ss://{ui}@5.6.7.8:8388"
    key = core.dedup_key(line)
    assert key.startswith("ss:sip002:"), f"fell back: {key!r}"
    got_ui, host, port = _f_ss_parts(key)
    assert (host, port) == ("5.6.7.8", "8388"), (host, port)
    assert "bw2o/kkfuowo+xci3f6pqng=" in got_ui, f"userinfo mangled: {got_ui!r}"


def test_zz_f_ss_base64_userinfo_decoded():
    """S5 — userinfoِ base64 باید به `method:password` باز شود."""
    line = f"ss://{_F_UI_B64}@1.2.3.4:11201?note=@X"
    ui, _h, _p = _f_ss_parts(core.dedup_key(line))
    assert ui == "chacha20-ietf-poly1305:deadbeefcafe1234", f"ui={ui!r}"


def test_zz_f_ss_plain_userinfo_kept():
    """S6 — userinfoِ متنی نباید تحریف شود."""
    line = "ss://aes-256-gcm:hunter2@1.2.3.4:8388"
    ui, host, port = _f_ss_parts(core.dedup_key(line))
    assert ui == "aes-256-gcm:hunter2", f"ui={ui!r}"
    assert (host, port) == ("1.2.3.4", "8388")


def test_zz_f_ss_ipv6_bracketed():
    """S7 — IPv6ِ کروشه‌دار: port باید درست جدا شود."""
    line = f"ss://{_F_UI_B64}@[2001:db8::1]:8388?note=@Y"
    _ui, host, port = _f_ss_parts(core.dedup_key(line))
    assert port == "8388", f"port={port!r}"
    assert "2001:db8::1" in host, f"host={host!r}"


def test_zz_f_ss_legacy_no_at():
    """S8 — بدنهٔ legacy (بی '@') باید ss:legacy بدهد."""
    body = base64.b64encode(b"aes-256-gcm:pw@1.2.3.4:8388").decode("ascii")
    key = core.dedup_key(f"ss://{body}")
    # ★ فاز J / J-4: بدنهٔ رمزگشودهٔ legacy دقیقاً
    # `method:pass@host:port` است — همان چیزی که شاخهٔ sip002 از
    # اجزا می‌سازد؛ پس یکسان‌سازی هم‌ارزی است، نه ادغامِ
    # کاذب: برخورد تنها وقتی رخ می‌دهد که method و گذرواژه و
    # میزبان و پورت هر چهار یکی باشند ⇒ همان سرور.
    assert key == "ss:sip002:aes-256-gcm:pw@1.2.3.4:8388", f"key={key!r}"
    assert "1.2.3.4" in key
    # ★ خودِ هدفِ J-4: همین کانفیگ در فرمِ sip002 باید **همان**
    # کلید را بدهد. پیش از وصله دو کلیدِ متفاوت می‌ساختند و
    # یک کانفیگ دو بار منتشر می‌شد (اندازه‌گیری: ۴ مورد).
    _ui = base64.b64encode(b"aes-256-gcm:pw").decode("ascii")
    assert core.dedup_key(f"ss://{_ui}@1.2.3.4:8388") == key


def test_zz_f_ss_legacy_not_base64_fallback():
    """S9 — legacyِ غیر-base64 باید fallbackِ قطعی بدهد، نه استثنا."""
    key = core.dedup_key("ss://!!!not-base64-at-all!!!")
    assert key == "ss://!!!not-base64-at-all!!!", f"key={key!r}"
    assert key == core.dedup_key("ss://!!!not-base64-at-all!!!")


def test_zz_f_ss_no_query_semantics_unchanged():
    """S10 — بدونِ query و path، وصله نباید هیچ چیزی را عوض کند."""
    line = f"ss://{_F_UI_B64}@1.2.3.4:8388"
    assert core.dedup_key(line) == _f_ss_key_old_algorithm(line)


def test_zz_f_ss_fragment_with_at_stripped():
    """S11 — '@' داخلِ fragment نباید به کلید نفوذ کند."""
    a = f"ss://{_F_UI_B64}@1.2.3.4:8388"
    b = f"ss://{_F_UI_B64}@1.2.3.4:8388#@SomeChannel"
    assert core.dedup_key(a) == core.dedup_key(b)


def test_zz_f_ss_percent_encoded_userinfo():
    """S12 — percent-encoding در userinfo باید unquote شود."""
    line = "ss://aes-256-gcm:p%40ss@1.2.3.4:8388?note=@Z"
    ui, host, port = _f_ss_parts(core.dedup_key(line))
    assert ui == "aes-256-gcm:p@ss", f"ui={ui!r}"
    assert (host, port) == ("1.2.3.4", "8388")


def test_zz_f_ss_host_lowercased():
    """S13 — hostِ حروف‌بزرگ باید یکسان‌سازی شود."""
    up = f"ss://{_F_UI_B64}@Example.COM:8388?note=@Q"
    lo = f"ss://{_F_UI_B64}@example.com:8388?note=@Q"
    assert core.dedup_key(up) == core.dedup_key(lo)


def test_zz_f_ss_note_tag_does_not_split_identity():
    """S14 — دو URI که فقط در `?note=` فرق دارند باید **یک** هویت باشند."""
    a = f"ss://{_F_UI_B64}@1.2.3.4:8388?note=@ChannelA"
    b = f"ss://{_F_UI_B64}@1.2.3.4:8388?note=@ChannelB"
    assert core.dedup_key(a) == core.dedup_key(b), "same server split by tag"
    # و اثبات اینکه قبلاً این‌طور نبود:
    assert _f_ss_key_old_algorithm(a) != _f_ss_key_old_algorithm(b)


def test_zz_f_ss_query_presence_does_not_split_identity():
    """★ S14b — **همان سرور** با و بدونِ query باید یک هویت باشد.

    این حالت با S14 فرق دارد و مهم‌تر است: S14 دو خط را مقایسه می‌کند که
    **هر دو** query دارند؛ اینجا یکی query دارد و دیگری ندارد.

    چرا مهم است — و چرا باید صادقانه ثبت شود: در کدِ قدیم این دو خط
    **دو کلیدِ متفاوت** می‌ساختند (خطِ باquery کلیدِ خراب با hostِ خالی
    می‌گرفت)، پس یک سرور **دو بار** شمرده می‌شد. با وصله هر دو یک کلید
    می‌شوند؛ یعنی وصله می‌تواند باعثِ **ادغامِ درست** شود و تعدادِ نودِ
    منتشرشده را کمی کم کند.

    این را با اجرای واقعی سنجیدم (HEAD در برابرِ درختِ کاری):
        old → ۲ کلیدِ یکتا   |   new → ۱ کلیدِ یکتا
    در پیکرهٔ امروز چنین جفتی هم‌زمان وجود ندارد، پس `merges = 0` سنجیده شد و
    اثرِ عملیِ امروز صفر است — ولی مدعیِ «هرگز ادغام نمی‌شود» **نیستم**.
    """
    a = f"ss://{_F_UI_B64}@1.2.3.4:8388?note=@Chan"
    b = f"ss://{_F_UI_B64}@1.2.3.4:8388"
    assert core.dedup_key(a) == core.dedup_key(b), (
        f"same server split by query presence: {core.dedup_key(a)!r} != "
        f"{core.dedup_key(b)!r}"
    )
    # شاهدِ ابطال‌پذیری: الگوریتمِ قدیم این دو را از هم جدا می‌کرد
    assert _f_ss_key_old_algorithm(a) != _f_ss_key_old_algorithm(b), (
        "control invalid: old algorithm already merged these"
    )


def test_zz_f_ss_fragment_does_not_split_identity():
    """S15 — تفاوت در fragment نباید هویت را بشکند."""
    a = f"ss://{_F_UI_B64}@1.2.3.4:8388#one"
    b = f"ss://{_F_UI_B64}@1.2.3.4:8388#two"
    assert core.dedup_key(a) == core.dedup_key(b)


def test_zz_f_ss_different_host_not_merged():
    """S16 — hostِ متفاوت با queryِ یکسان نباید ادغام شود (ادغامِ کاذب)."""
    a = f"ss://{_F_UI_B64}@1.2.3.4:8388?note=@Same"
    b = f"ss://{_F_UI_B64}@5.6.7.8:8388?note=@Same"
    assert core.dedup_key(a) != core.dedup_key(b)


def test_zz_f_ss_key_deterministic():
    """S17 — کلید باید قطعی باشد (چند بار صدا زدن، یک خروجی)."""
    lines = [
        f"ss://{_F_UI_B64}@1.2.3.4:8388?note=@X#t",
        "ss://aes-256-gcm:pw@[2001:db8::2]:443/?plugin=p",
        "ss://!!!bad!!!",
    ]
    for ln in lines:
        keys = {core.dedup_key(ln) for _ in range(5)}
        assert len(keys) == 1, f"non-deterministic for {ln!r}: {keys}"


def test_zz_f_ss_last_at_is_the_delimiter():
    """authority با چند '@': مرزِ userinfo/host **آخرین** '@' است.

    RFC 3986 اجازهٔ '@'ِ رمزنگاری‌نشده در userinfo را نمی‌دهد، و
    `endpoint_of()` هم همین قاعده را به‌کار می‌برد.

    ⚠️ **هشدارِ صداقت — این تست جهشِ M5 را نمی‌کُشد.**
    تبدیلِ `rsplit("@", 1)` → `split("@", 1)` این تست را **نمی‌شکند**، و من
    این را با اجرایِ واقعیِ جهش سنجیدم (نه حدس). دلیلش «بازچینشِ رشتهٔ کلید»
    است: قالبِ کلید `f"{userinfo}@{host}:{port}"` است، پس هرجای authority را
    که بشکنید، `userinfo + "@" + host` دوباره **همان** authority را می‌سازد و
    رشتهٔ کلید تغییر نمی‌کند — هرچند `host` در باطن آلوده است
    (`word@1.2.3.4` به‌جای `1.2.3.4`).
    کُشتنِ M5 نیازمندِ ورودی‌ای است که در آن تبدیل‌های **نامتقارنِ** روی
    userinfo (percent-decode / base64-decode) رشته را واقعاً جابه‌جا کنند؛
    آن تست جداگانه است: `test_zz_f_ss_userinfo_spans_to_last_at`.
    """
    line = "ss://aes-256-gcm:pw@word@1.2.3.4:8388?note=@Chan"
    ui, host, port = _f_ss_parts(core.dedup_key(line))
    assert host == "1.2.3.4", f"host={host!r} (باید از آخرین '@' جدا شود)"
    assert port == "8388", f"port={port!r}"
    assert ui == "aes-256-gcm:pw@word", f"ui={ui!r}"
    # و هم‌خوانی با endpoint_of
    assert core.endpoint_of(line) == "1.2.3.4"


def test_zz_f_ss_userinfo_spans_to_last_at():
    """★ تستی که واقعاً جهشِ M5 (`rsplit`→`split`) را می‌کُشد.

    **ویژگیِ سنجیده‌شده:** percent-decoding باید روی **کلِ** userinfo — یعنی
    هرچه پیش از آخرین '@' است — اعمال شود، چون کلِ آن userinfo است.

    چرا این ورودی کار می‌کند و ورودیِ سادهٔ دو-'@' نه: `unquote()` فقط روی
    userinfo اجرا می‌شود و روی host نه. پس اگر بخشِ percent-encoded **بینِ**
    دو '@' بنشیند، جای مرز تعیین می‌کند که آن بخش رمزگشایی شود یا نه، و
    «بازچینشِ رشتهٔ کلید» دیگر جهش را پنهان نمی‌کند.

    اندازه‌گیریِ واقعی (جهش روی نسخهٔ کپیِ `core.py`، نه بازنویسیِ دستی):
        rsplit → ss:sip002:aes-256-gcm:pw@ab@1.2.3.4:8388     ← درست
        split  → ss:sip002:aes-256-gcm:pw@%41%42@1.2.3.4:8388 ← جهش

    توجه: `%41%42` یعنی `AB`، و چون کلید lowercase می‌شود انتظارِ `ab` داریم.
    """
    line = "ss://aes-256-gcm:pw@%41%42@1.2.3.4:8388"
    key = core.dedup_key(line)
    ui, host, port = _f_ss_parts(key)
    # ۱) نقطهٔ برش درست است → host/port سالم
    assert host == "1.2.3.4", f"host={host!r}"
    assert port == "8388", f"port={port!r}"
    # ۲) percent-decoding روی کلِ userinfo (تا آخرین '@') اعمال شده
    assert ui == "aes-256-gcm:pw@ab", f"ui={ui!r}"
    # ۳) هیچ percent-encoding رمزگشایی‌نشده‌ای در کلید نمانده باشد
    assert "%41" not in key and "%42" not in key, f"key={key!r}"
    # ۴) شاهدِ دوم و مستقل: '/'ِ رمزنگاری‌شده هم باید رمزگشایی شود
    line2 = "ss://aes-256-gcm:pw@a%2Fb@1.2.3.4:8388"
    key2 = core.dedup_key(line2)
    ui2, host2, port2 = _f_ss_parts(key2)
    assert ui2 == "aes-256-gcm:pw@a/b", f"ui2={ui2!r}"
    assert host2 == "1.2.3.4" and port2 == "8388"
    assert "%2f" not in key2 and "%2F" not in key2, f"key2={key2!r}"
    # ۵) و هم‌خوانی با endpoint_of در هر دو
    assert core.endpoint_of(line) == "1.2.3.4"
    assert core.endpoint_of(line2) == "1.2.3.4"


def test_zz_f_ss_host_agrees_with_endpoint_of():
    """★ ناوردایِ بین‌تابعی: hostِ کلید باید با `endpoint_of` یکی باشد.

    `endpoint_of()` از پیش قاعدهٔ درست را داشت (برشِ query → rsplit '@' →
    برشِ path). این تست دو تابع را به هم گره می‌زند تا واگراییِ آینده گرفته شود.
    """
    cases = [
        f"ss://{_F_UI_B64}@1.2.3.4:11201?note=@SomeChannel#tag",
        f"ss://{_F_UI_B64}@1.2.3.4:443/?plugin=obfs",
        "ss://aes-256-gcm:hunter2@example.com:8388",
        f"ss://{_F_UI_B64}@[2001:db8::1]:8388?note=@Y",
        "ss://aes-256-gcm:pw@word@9.9.9.9:1080?note=@N",   # دو '@' در authority
    ]
    for ln in cases:
        _ui, host, _port = _f_ss_parts(core.dedup_key(ln))
        want = core.endpoint_of(ln)
        got = host.strip("[]")          # کلید کروشهٔ IPv6 را نگه می‌دارد
        assert got == want, f"{ln!r}: key host={got!r} endpoint_of={want!r}"


def test_zz_f_ss_control_patch_is_falsifiable():
    """S18 — تستِ کنترلِ داربست: اثبات اینکه الگوریتمِ قدیم **می‌شکست**.

    اگر بقیهٔ تست‌ها بدونِ وصله هم پاس شوند، داربست بی‌اثر است. این‌جا صریحاً
    نشان می‌دهیم الگوریتمِ قدیم روی همان ورودی hostِ خالی و portِ غیرعددی
    می‌ساخت، و وصلهٔ فعلی هر دو نشانه را از بین می‌برد.
    """
    line = f"ss://{_F_UI_B64}@1.2.3.4:11201?note=@FreeOnlineVPN"
    old = _f_ss_key_old_algorithm(line)
    _o_ui, o_host, o_port = _f_ss_parts(old)
    assert o_host == "", f"control invalid: old host was {o_host!r}"
    assert o_port == "FreeOnlineVPN", f"control invalid: old port {o_port!r}"
    assert not o_port.isdigit()
    _n_ui, n_host, n_port = _f_ss_parts(core.dedup_key(line))
    assert n_host == "1.2.3.4" and n_port.isdigit()
    assert old != core.dedup_key(line)


def test_zz_f_ss_patch_scope_is_surgical():
    """اثباتِ دامنه: وصله نباید هیچ پروتکلِ دیگری را عوض کند."""
    others = [
        "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443"
        "?type=tcp&sni=a.com#x",
        "trojan://pass@1.2.3.4:443?sni=b.com#y",
        "hysteria2://pw@1.2.3.4:443?sni=c.com#z",
        "vmess://" + base64.b64encode(
            json.dumps({"add": "1.2.3.4", "port": 443, "id": "u",
                        "net": "ws", "path": "/p"}).encode()).decode(),
    ]
    for ln in others:
        k1 = core.dedup_key(ln)
        k2 = core.dedup_key(ln)
        assert k1 == k2 and k1 and not k1.startswith("ss:")


# ══════════════════════════════════════════════════════════════════════════════
# فاز H — اعتبارسنجیِ مقدارِ fronting در `dedup_key` (همهٔ پروتکل‌ها جز ss)
#
# نقصِ ساختاری: `dedup_key` هرگاه `sni`/`host` وجود داشت، **میزبانِ واقعی را
# دور می‌ریخت** (`host_for_key = ""`) و هویتِ سرور را به آن مقدار می‌سپرد. پس
# هر دو سرورِ متفاوت با مقدارِ frontingِ مشترک یک هویت می‌شدند و در
# `aggregate.py` (خطوط ۲۵۹–۲۶۳) دومی به `r.duplicates` می‌رفت و **هرگز منتشر
# نمی‌شد** — یعنی حذفِ خاموشِ یک سرورِ سالم.
#
# دو واقعیتِ **مستندِ** پروتکلی که قاعده بر آن‌ها بنا شد:
#   ۱. SNI یک افزونهٔ TLS است ⇒ با `security` = none/غایب هرگز ارسال نمی‌شود.
#   ۲. در REALITY مقدارِ `serverName` عمداً دامنهٔ یک **سایتِ ثالث** است که
#      گواهی‌اش قرض گرفته می‌شود (مستنداتِ رسمیِ XTLS)، نه میزبانِ خودِ سرور.
#
# سنجشِ زنده روی یک عکسِ ثابتِ ۱۸٬۷۳۵ خطی: کلیدهایی که ≥۲ نقطهٔ پایانیِ واقعیِ
# متفاوت را در خود جمع کرده بودند **۶۴۱ → ۵۰۰**، و ادغامِ کاذبِ **تازه = ۰**.
# ══════════════════════════════════════════════════════════════════════════════

_H_UUID = "11111111-1111-1111-1111-111111111111"


def _h_parts(key: str):
    """(host_for_key, endpoint, port, مجموعهٔ پارامترها) از کلیدِ شاخهٔ عمومی."""
    assert "|ep=" in key, f"not a generic key: {key!r}"
    head, _, tail = key.partition("|ep=")
    host_for_key = head.rpartition("@")[2]
    body, _, query = tail.rpartition("?")
    endpoint, _, port = body.rpartition(":")
    return host_for_key, endpoint, port, {p for p in query.split("&") if p}


def _h_vmess_parts(key: str):
    """(add_for_key, fronting) از کلیدِ شاخهٔ vmess."""
    assert key.startswith("vmess:") and "|ep=" in key, f"not vmess: {key!r}"
    head, _, tail = key.partition("|ep=")
    return head[len("vmess:"):], tail.split(":", 1)[0]


def _h_old_fronting_generic(line: str) -> str:
    """frontingِ **الگوریتمِ قدیم** برای شاخهٔ عمومی — فقط برای تستِ کنترل.

    قاعدهٔ قدیم: `sni or host`، **بدونِ هیچ اعتبارسنجی**. این تابع عمداً
    بازسازی می‌شود تا ثابت شود تست‌های این بلوک ابطال‌پذیرند: اگر وصله برگردد،
    خروجی دوباره همین می‌شود.
    """
    without_remark = line.split("#")[0].strip()
    parsed = urllib.parse.urlparse(without_remark)
    raw = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    def _nv(name: str) -> str:
        v = (raw.get(name, [""])[0] or "").strip().lower()
        for _ in range(2):                      # همان دو دورِ unquote در core
            nxt = urllib.parse.unquote(v)
            if nxt == v:
                break
            v = nxt
        return v.strip().lower()

    return _nv("sni") or _nv("host")


def _h_vless(query: str) -> str:
    return f"vless://{_H_UUID}@1.2.3.4:443?{query}#tag"


def _h_vmess(**kw) -> str:
    obj = {"add": "1.2.3.4", "port": 443, "id": "u1", "net": "ws", "path": "/p"}
    obj.update(kw)
    return "vmess://" + base64.b64encode(
        json.dumps(obj).encode("utf-8")).decode("ascii")


# ── ۱) قاعدهٔ REALITY: sni دامنهٔ استتارِ ثالث است، نقطهٔ پایانی نیست ──────────

def test_zz_h_reality_sni_keeps_real_host():
    """REALITY + sni ⇒ میزبانِ واقعی باید در کلید بماند، نه دامنهٔ استتار."""
    key = core.dedup_key(_h_vless("security=reality&sni=www.apple.com&pbk=K&type=tcp"))
    host, ep, port, params = _h_parts(key)
    assert host == "1.2.3.4", f"میزبانِ واقعی گم شد: {key!r}"
    assert ep == "", f"دامنهٔ استتار به‌عنوان نقطهٔ پایانی نشست: {key!r}"
    assert port == "443"
    # مقدارِ معتبر ولی «ردشده با قاعدهٔ TLS» باید در query بماند (نوعِ ۲).
    assert "sni=www.apple.com" in params, (
        f"sni معتبر بود و باید به‌عنوان پارامترِ هویتی می‌ماند: {params!r}")


def test_zz_h_security_none_sni_keeps_real_host():
    """`security=none` ⇒ هیچ TLSی نیست ⇒ SNI ارسال نمی‌شود ⇒ بی‌اثر."""
    key = core.dedup_key(_h_vless("security=none&sni=www.apple.com&type=tcp"))
    host, ep, _p, params = _h_parts(key)
    assert host == "1.2.3.4" and ep == "", key
    assert "sni=www.apple.com" in params


def test_zz_h_security_absent_sni_keeps_real_host():
    """پارامترِ `security` غایب ⇒ همان حکمِ none."""
    key = core.dedup_key(_h_vless("sni=www.apple.com&type=tcp"))
    host, ep, _p, _q = _h_parts(key)
    assert host == "1.2.3.4" and ep == "", key


def test_zz_h_reality_sni_two_servers_stay_distinct():
    """★ سنجهٔ اصلی: دو سرورِ REALITYِ متفاوت با استتارِ مشترک نباید یکی شوند."""
    a = f"vless://{_H_UUID}@1.2.3.4:443?security=reality&sni=www.apple.com&type=tcp#a"
    b = f"vless://{_H_UUID}@5.6.7.8:443?security=reality&sni=www.apple.com&type=tcp#b"
    ka, kb = core.dedup_key(a), core.dedup_key(b)
    assert ka != kb, (
        "دو سرورِ متفاوت هم‌هویت شدند ⇒ یکی در aggregate به duplicates می‌رود "
        f"و منتشر نمی‌شود: {ka!r}")
    # و اثباتِ ابطال‌پذیری: با قاعدهٔ قدیم هم‌هویت **بودند**.
    assert _h_old_fronting_generic(a) == _h_old_fronting_generic(b) != ""


# ── ۲) مواردی که **نباید** عوض شوند ────────────────────────────────────────────

def test_zz_h_tls_valid_sni_key_unchanged():
    """`security=tls` + sniِ معتبر ⇒ کلید **دقیقاً** مثلِ قبل بماند."""
    line = _h_vless("security=tls&sni=cdn.example.com&type=ws")
    host, ep, _p, params = _h_parts(core.dedup_key(line))
    assert ep == "cdn.example.com", "frontingِ مشروع نباید رد شود"
    # ★ قرارداد در فازِ I عوض شد: میزبانِ واقعی **دیگر حذف نمی‌شود** و `sni` هم
    # در query می‌ماند، چون `ep` جای میزبان را نگرفته است. آنچه این تست از فازِ H
    # پاس می‌دارد — استخراجِ درستِ مقدارِ fronting — همچنان سنجیده می‌شود.
    assert host == "1.2.3.4", "فازِ I: میزبانِ واقعی باید در کلید بماند"
    assert "security=tls" in params
    assert "sni=cdn.example.com" in params, "فازِ I: sni دیگر دور ریخته نمی‌شود"
    assert ep == _h_old_fronting_generic(line)


def test_zz_h_host_param_unchanged_by_tls_rule():
    """`host` هرگز به قاعدهٔ TLS مشروط نشد — فقط اعتبارِ نحوی."""
    line = _h_vless("security=none&host=cdn.example.com&type=ws")
    host, ep, _p, _q = _h_parts(core.dedup_key(line))
    assert ep == "cdn.example.com", (
        "host با security=none هم fronting معتبر است (هدرِ HTTP، نه TLS)")
    assert host == "1.2.3.4", "فازِ I: میزبانِ واقعی حفظ می‌شود"
    assert ep == _h_old_fronting_generic(line)


def test_zz_h_trailing_dot_fqdn_accepted():
    """FQDNِ لنگرانداخته به ریشه (`a.com.`) از نظرِ DNS معتبر است ⇒ پذیرش."""
    line = _h_vless("security=tls&sni=ayar24gold.com.&type=ws")
    _h, ep, _p, _q = _h_parts(core.dedup_key(line))
    assert ep == "ayar24gold.com.", (
        "نقطهٔ پایانی نباید باعثِ ردِ FQDN شود — این دقیقاً باگی بود که در "
        "نسخهٔ اولِ ابزارِ سنجشِ خودم ۴ مثبتِ کاذب ساخت")


def test_zz_h_ipv6_literal_fronting_accepted():
    """لیترالِ IPv6 در کروشه مقدارِ نحوی‑معتبر است."""
    line = _h_vless("security=tls&sni=%5B2001%3Adb8%3A%3A1%5D&type=ws")
    _h, ep, _p, _q = _h_parts(core.dedup_key(line))
    assert ep == "[2001:db8::1]", ep


# ── ۳) مقادیرِ زباله: هم به‌عنوان نقطهٔ پایانی رد، هم از query حذف ─────────────

def test_zz_h_garbage_fronting_rejected_and_popped():
    """زباله هیچ اطلاعِ هویتی ندارد ⇒ باید **کاملاً** از کلید بیرون برود.

    اگر فقط «تنزیل» شود و در query بماند، همان زباله هویت را می‌شکند: سنجیده
    شد که ۳۶ افراز، **یک** نقطهٔ پایانیِ واقعی را به چند کلید می‌بردند.
    """
    cases = [
        ("security=tls&sni=https%3A%2F%2Ft.me%2Fx&type=ws", "sni"),
        ("security=tls&sni=t.me%2Fripaojiedian&type=ws", "sni"),
        ("security=tls&sni=rd.autos.yahoo.com:40069&type=ws", "sni"),
        ("security=tls&sni=v2raynplus--v2raynplus&type=ws", "sni"),
        ("security=none&host=%7B%22host%22%3A%22a%22%7D&type=ws", "host"),
        ("security=none&host=%2F%3Fbia%40mar&type=ws", "host"),
        ("security=none&host=a.com%2Cb.com&type=ws", "host"),
        ("security=none&host=d2e.cloudfront.net%3Aassets.opensignal.com&type=ws",
         "host"),
    ]
    for query, which in cases:
        line = _h_vless(query)
        host, ep, _p, params = _h_parts(core.dedup_key(line))
        assert host == "1.2.3.4", f"میزبانِ واقعی گم شد ({query}): {host!r}"
        assert ep == "", f"زباله نقطهٔ پایانی شد ({query}): {ep!r}"
        assert not any(p.startswith(which + "=") for p in params), (
            f"زباله در query ماند و هویت را می‌شکند ({query}): {params!r}")
        # ابطال‌پذیری: الگوریتمِ قدیم همین زباله را نقطهٔ پایانی می‌کرد.
        assert _h_old_fronting_generic(line) not in ("",), query


def test_zz_h_single_label_fronting_rejected():
    """دامنهٔ frontingِ عمومی همیشه FQDN است؛ مقدارِ تک‌برچسبی نامِ کانال است."""
    line = _h_vless("security=tls&sni=v2raynplus--v2raynplus--v2raynplus&type=ws")
    host, ep, _p, _q = _h_parts(core.dedup_key(line))
    assert host == "1.2.3.4" and ep == "", (
        "پذیرشِ مقادیرِ تک‌برچسبی ۱۲ افرازِ هم‑نقطه‌پایانی باقی می‌گذاشت")


# ── ۴) شاخهٔ vmess ────────────────────────────────────────────────────────────

def test_zz_h_vmess_reality_sni_keeps_add():
    add, front = _h_vmess_parts(core.dedup_key(
        _h_vmess(tls="reality", sni="www.apple.com")))
    assert add == "1.2.3.4" and front == "", (add, front)


def test_zz_h_vmess_tls_valid_sni_unchanged():
    add, front = _h_vmess_parts(core.dedup_key(
        _h_vmess(tls="tls", sni="cdn.example.com")))
    # ★ فاز J / J-7b: `fronting` دیگر `host or sni` نیست؛ دو منبع
    # صریحاً تفکیک می‌شوند («میزبان~sni»)، چون محصول آن‌ها را به
    # دو فیلدِ متفاوت امیت می‌کند (`Host` و `servername`) و یکی‌کردنِ
    # آن‌ها یک مصنوع را خاموش حذف می‌کرد.
    assert front == "~cdn.example.com", (add, front)
    # ★ دروازهٔ تمایز: همان مقدار اگر از `host` بیاید باید کلیدِ
    # دیگری بدهد — وگرنه تفکیک بی‌معناست.
    _a2, f2 = _h_vmess_parts(core.dedup_key(
        _h_vmess(tls="tls", host="cdn.example.com")))
    assert f2 != front, (front, f2)
    assert add == "1.2.3.4", "فازِ I: `add` باید در کلید بماند"


def test_zz_h_vmess_host_kept_without_tls():
    """در vmess هم `host` مشروط به TLS نیست."""
    add, front = _h_vmess_parts(core.dedup_key(_h_vmess(host="cdn.example.com")))
    assert front == "cdn.example.com", (add, front)
    assert add == "1.2.3.4", "فازِ I: `add` باید در کلید بماند"


def test_zz_h_vmess_garbage_host_falls_back_to_add():
    add, front = _h_vmess_parts(core.dedup_key(_h_vmess(host="t.me/chan")))
    assert add == "1.2.3.4" and front == "", (add, front)


def test_zz_h_vmess_invalid_host_valid_sni_shifts_to_sni():
    """`host` نامعتبر و `sni` معتبر با tls ⇒ fronting به sni منتقل می‌شود."""
    add, front = _h_vmess_parts(core.dedup_key(
        _h_vmess(host="onelabel", sni="cdn.example.com", tls="tls")))
    # ★ فاز J / J-7b: اطلاعاتِ فاز H دست‌نخورده می‌مانَد (sni در
    # کلید می‌آید)، فقط اکنون **منبعش** هم ثبت می‌شود.
    assert front == "~cdn.example.com", (add, front)
    assert "cdn.example.com" in front
    assert add == "1.2.3.4", "فازِ I: `add` باید در کلید بماند"


# ── ۵) پروتکل‌های دیگر (اثباتِ اینکه وصله فقط ss را دست‌نخورده می‌گذارد) ───────

def test_zz_h_other_schemes_follow_same_rule():
    # پس از فازِ I میزبانِ واقعی در **همهٔ** حالت‌ها می‌ماند، پس `ep`ِ انتظاری هم
    # سنجیده می‌شود تا تست قدرتِ تفکیکش را از دست ندهد.
    for line, want_host, want_ep in (
        ("trojan://pw@5.6.7.8:443?security=reality&sni=www.bing.com#t",
         "5.6.7.8", ""),
        ("hysteria2://pw@5.6.7.8:443?sni=t.me%2Fripaojiedian#h",
         "5.6.7.8", ""),
        ("tuic://u:p@5.6.7.8:443?security=none&sni=a.example.com#u",
         "5.6.7.8", ""),
        ("trojan://pw@5.6.7.8:443?security=tls&sni=cdn.example.com#ok",
         "5.6.7.8", "cdn.example.com"),
    ):
        host, ep, _p, _q = _h_parts(core.dedup_key(line))
        assert (host, ep) == (want_host, want_ep), (line, host, ep)


def test_zz_h_ss_branch_untouched():
    """دامنهٔ وصلهٔ H: شاخهٔ ss (دستاوردِ فازِ F) باید دست‌نخورده بماند.

    ⚠️ نسخهٔ اولِ همین تست را **خودم غلط** نوشتم: با `_f_ss_key_old_algorithm`
    مقایسه کردم، در حالی که آن تابع عمداً بازسازیِ الگوریتمِ **باگ‌دارِ** پیش از
    فازِ F است و برای موردِ `?note=@SomeChannel` باید نتیجهٔ *متفاوتی* بدهد.
    پس ثابتِ درست این است: کلیدِ ss هنوز host/port را درست می‌دهد (یعنی وصلهٔ F
    زنده است) و برای آن مورد **برابرِ** الگوریتمِ باگ‌دار نیست.
    """
    tricky = f"ss://{_F_UI_B64}@1.2.3.4:11201?note=@SomeChannel#tag"
    ui, host, port = _f_ss_parts(core.dedup_key(tricky))
    assert (host, port) == ("1.2.3.4", "11201"), (host, port)
    assert ui == "chacha20-ietf-poly1305:deadbeefcafe1234", ui
    assert core.dedup_key(tricky) != _f_ss_key_old_algorithm(tricky), (
        "دستاوردِ فازِ F از دست رفته است")
    for line, want in (
        (f"ss://{_F_UI_B64}@1.2.3.4:8388", ("1.2.3.4", "8388")),
        (f"ss://{_F_UI_B64}@[2001:db8::1]:8388?note=@Y", ("[2001:db8::1]", "8388")),
        (f"ss://{_F_UI_B64}@1.2.3.4:443/?plugin=obfs-local", ("1.2.3.4", "443")),
    ):
        _u, h, p = _f_ss_parts(core.dedup_key(line))
        assert (h, p) == want, (line, h, p)


# ── ۶) ساختار و پایداری ──────────────────────────────────────────────────────

def test_zz_h_other_identity_params_preserved():
    """همهٔ پارامترهای هویتی جز sni/host باید بایت‑به‑بایت دست‌نخورده بمانند."""
    line = _h_vless(
        "security=reality&sni=www.apple.com&pbk=PBK&sid=SID&flow=xtls-rprx-vision"
        "&type=grpc&mode=gun&servicename=SVC&encryption=none")
    _h, _e, _p, params = _h_parts(core.dedup_key(line))
    # ★ فاز J / J-7e: پارامترهای **حساس به بزرگی/کوچکی** دیگر
    # کوچک نمی‌شوند (`pbk` base64url است، `servicename` مانندِ مسیر
    # حساس است)، ولی `sid` عامداً کوچک می‌ماند چون shortId
    # مبنای ۱۶ است و hex غیرحساس است.
    for expect in ("pbk=PBK", "sid=sid", "flow=xtls-rprx-vision",
                   "type=grpc", "mode=gun", "servicename=SVC",
                   "security=reality"):
        assert expect in params, (expect, params)
    assert not any(p.startswith("host=") for p in params)


def test_zz_h_kept_host_agrees_with_endpoint_of():
    """وقتی fronting رد شد، میزبانِ کلید باید همان `endpoint_of` باشد."""
    for query in ("security=reality&sni=www.apple.com",
                  "security=none&sni=a.example.com",
                  "security=tls&sni=t.me%2Fx",
                  "security=none&host=%2Fjunk"):
        line = _h_vless(query)
        host, ep, _p, _q = _h_parts(core.dedup_key(line))
        assert ep == "" and host == core.endpoint_of(line), (query, host, ep)


def test_zz_h_dedup_key_is_deterministic():
    lines = [_h_vless("security=reality&sni=www.apple.com&type=tcp"),
             _h_vless("security=tls&sni=cdn.example.com&type=ws"),
             _h_vmess(tls="reality", sni="www.apple.com"),
             _h_vmess(host="t.me/chan")]
    for ln in lines:
        assert core.dedup_key(ln) == core.dedup_key(ln) != ""


def test_zz_h_remark_does_not_affect_key():
    a = _h_vless("security=reality&sni=www.apple.com&type=tcp")
    b = a.replace("#tag", "#@SomeOtherChannel")
    assert core.dedup_key(a) == core.dedup_key(b)


# ── ۷) تست‌های واحدِ دو کمک‌تابع ───────────────────────────────────────────────

def test_zz_h_is_plausible_fronting_host_table():
    """جدولِ سنجیده‌شدهٔ کمک‌تابع — هر ردیف یک قاعدهٔ مستقل."""
    ok = ["a.com", "a.b.c.com", "example.com.", "[2001:db8::1]", "1.2.3.4",
          "xn--bcher-kva.com", "[x]",
          ("a" * 60) + "." + ("b" * 60) + "." + ("c" * 60) + "." +
          ("d" * 60) + ".com"]
    bad = ["", "onelabel", "a..com", ".com", "com.", "-a.com", "a-.com",
           "tést.com", "a b.com", "a/b.com", "a:b.com", "a@b.com",
           '{"h":"a"}', "https://t.me/x", ("a" * 64) + ".com",
           ("a" * 250) + ".com", "[]", "a.com..", "a.com:443", "a,b.com"]
    for v in ok:
        assert core._is_plausible_fronting_host(v) is True, repr(v[:40])
    for v in bad:
        assert core._is_plausible_fronting_host(v) is False, repr(v[:40])


def test_zz_h_sni_is_endpoint_only_for_tls():
    """فقط TLSِ معمولی؛ مقدار پیش از فراخوانی در core به حروفِ کوچک آمده است."""
    assert core._sni_is_endpoint("tls") is True
    for s in ("reality", "none", "", "xtls", "TLS"):
        assert core._sni_is_endpoint(s) is False, s


# ── ۸) تستِ کنترل (H‑9): اثبات اینکه الگوریتمِ قدیم نتیجهٔ دیگری می‌داد ────────

def test_zz_h_control_old_algorithm_gave_different_result():
    """اگر این تست بی‌اثر شود یعنی وصله کاری نکرده و بقیهٔ تست‌ها پوچ‌اند."""
    changed = [
        _h_vless("security=reality&sni=www.apple.com&type=tcp"),
        _h_vless("security=none&sni=www.apple.com&type=tcp"),
        _h_vless("security=tls&sni=https%3A%2F%2Ft.me%2Fx&type=ws"),
        _h_vless("security=none&host=%2F%3Fbia%40mar&type=ws"),
        _h_vless("security=tls&sni=v2raynplus--v2raynplus&type=ws"),
    ]
    for line in changed:
        _h, ep, _p, _q = _h_parts(core.dedup_key(line))
        old = _h_old_fronting_generic(line)
        assert old != "", f"تستِ کنترل بی‌اثر است: {line!r}"
        assert ep != old, (
            f"وصله اثری نداشت — نقطهٔ پایانی همان frontingِ قدیم است: {old!r}")
    unchanged = [_h_vless("security=tls&sni=cdn.example.com&type=ws"),
                 _h_vless("security=none&host=cdn.example.com&type=ws")]
    for line in unchanged:
        _h, ep, _p, _q = _h_parts(core.dedup_key(line))
        assert ep == _h_old_fronting_generic(line), (
            f"وصله بیش از دامنهٔ خود عمل کرد: {line!r}")


# ══════════════════════════════════════════════════════════════════════════════
# فازِ I — «مقدارِ fronting جانشینِ میزبانِ واقعی نمی‌شود»
#
# چه چیزی عوض شد و چرا:
#   پیش از فازِ I، اگر یک مقدارِ fronting (`sni` یا `host`) اعتبارسنجیِ فازِ H را
#   رد می‌کرد، کلیدِ یکتاسازی **میزبانِ واقعی را دور می‌ریخت** (`host_for_key=""`
#   در شاخهٔ عمومی و `add_for_key=""` در شاخهٔ vmess) و همان مقدار را هم از
#   `meaningful` بیرون می‌انداخت. نتیجه: چند سرورِ **واقعاً متفاوت** که پشتِ یک
#   دامنهٔ fronting نشسته بودند یک کلید می‌گرفتند و در
#   `aggregate.py` (خطوطِ ۲۵۹–۲۶۳) بازنده‌ها به `r.duplicates` می‌رفتند که
#   **هیچ‌وقت منتشر نمی‌شود** ⇒ حذفِ خاموشِ یک سرورِ سالم.
#
# چرا IPهای متفاوت پشتِ یک دامنه «تکراری» نیستند — مستندِ رسمیِ Hiddify:
#   «Due to the severe filtering of the Internet in Iran … To reduce the impact
#    of these disturbances, you should find clean IPs (IPs that are not
#    disturbed).»  یعنی IP دقیقاً همان میدانی است که کاربر برای دسترسی‌پذیری
#   می‌گردد و انتخاب می‌کند؛ و این خط‌لوله **هیچ آزمونِ دسترسی‌پذیریِ
#   per-config ندارد**، پس انداختنِ یک کانفیگ صرفاً «از دست دادن» است.
#
# سنجشِ زنده روی همان عکسِ ثابتِ ۱۸٬۷۳۵ خطی (i_measure.py / i_verify.py،
# drift = 0): کلیدِ آلوده ۸۳۴ → ۴۱۰، کانفیگِ ادغام‌شده ۱۹۵۱ → ۵۰۵،
# یکتا ۸۶۶۰ → ۱۰۱۰۷، ادغامِ کاذبِ تازه ۰، افرازِ تازه ۰ (تکراری ۲۷ → ۲۷).
# ══════════════════════════════════════════════════════════════════════════════


def _i_vless(host: str, query: str, uuid: str = _H_UUID) -> str:
    return f"vless://{uuid}@{host}:443?{query}#tag"


def _i_old_key_generic(key: str) -> str:
    """کلیدِ **پیش از فازِ I** را از کلیدِ امروزیِ شاخهٔ عمومی بازمی‌سازد.

    فقط برای تستِ کنترل. قاعدهٔ قدیم دقیقاً دو کار می‌کرد که فازِ I برداشت:
      • `host_for_key = ""` (میزبانِ واقعی از کلید حذف می‌شد)،
      • `meaningful.pop("sni")` و `meaningful.pop("host")`.
    بقیهٔ ساختِ کلید دست‌نخورده مانده، پس این بازسازیِ *متنی* وفادار است.
    """
    host, endpoint, _port, _params = _h_parts(key)
    if endpoint == "":
        return key                     # وقتی fronting نیست، قدیم و جدید یکی‌اند
    head, sep, tail = key.partition("|ep=")
    assert head.endswith(host), f"ساختارِ کلید عوض شده: {key!r}"
    head = head[: len(head) - len(host)]                 # حذفِ میزبانِ واقعی
    body, q_sep, query = tail.rpartition("?")
    kept = [p for p in query.split("&")
            if p and p.split("=", 1)[0] not in ("sni", "host")]
    return head + sep + body + q_sep + "&".join(kept)


def _i_old_key_vmess(key: str) -> str:
    """همان بازسازی برای شاخهٔ vmess: قدیم `add_for_key = ""` می‌گذاشت."""
    _add, fronting = _h_vmess_parts(key)
    if fronting == "":
        return key
    _head, sep, tail = key.partition("|ep=")
    return "vmess:" + sep + tail


# ── ۱) هستهٔ فازِ I: دو سرورِ متفاوت پشتِ یک دامنه باید دو کلید بگیرند ────────

def test_zz_i_fronting_does_not_replace_real_host():
    """همان آسیبِ سنجیده‌شده (۷۰۴–۱۴۲۰ سرورِ حذف‌شده) دیگر رخ نمی‌دهد."""
    q = "security=tls&sni=cdn.example.com&type=ws"
    k1 = core.dedup_key(_i_vless("1.2.3.4", q))
    k2 = core.dedup_key(_i_vless("5.6.7.8", q))
    assert k1 != k2, f"دو میزبانِ متفاوت یک کلید گرفتند ⇒ حذفِ خاموش: {k1!r}"
    for k, want in ((k1, "1.2.3.4"), (k2, "5.6.7.8")):
        host, ep, port, params = _h_parts(k)
        assert host == want, f"میزبانِ واقعی در کلید نیست: {k!r}"
        assert ep == "cdn.example.com", f"دامنهٔ fronting گم شد: {k!r}"
        assert port == "443", k
        assert "sni=cdn.example.com" in params, (
            f"مقدارِ fronting از query بیرون انداخته شد: {k!r}")
    # تستِ کنترل — قاعدهٔ قدیم این دو را **یکی** می‌کرد.
    old1, old2 = _i_old_key_generic(k1), _i_old_key_generic(k2)
    assert old1 != k1, "بازسازیِ قاعدهٔ قدیم بی‌اثر است ⇒ تست پوچ می‌شود"
    assert old1 == old2, (
        "تستِ کنترل بی‌اثر است: قاعدهٔ قدیم هم این دو را جدا می‌کرد")


# ── ۲) «IPِ پاک»: تنوعِ کارکردیِ چند IP پشتِ یک دامنه باید حفظ شود ───────────

def test_zz_i_cdn_clean_ip_diversity_preserved():
    """سه IPِ متفاوتِ لبهٔ CDN با یک `host` ⇒ سه کلیدِ متفاوت."""
    ips = ("104.16.1.1", "104.17.2.2", "172.67.3.3")
    q = "security=none&host=cdn.example.com&type=ws"
    keys = {core.dedup_key(_i_vless(ip, q)) for ip in ips}
    assert len(keys) == len(ips), f"IPهای پاک ادغام شدند: {sorted(keys)!r}"
    olds = {_i_old_key_generic(k) for k in keys}
    assert len(olds) == 1, (
        f"تستِ کنترل بی‌اثر است — قاعدهٔ قدیم هم جدا می‌کرد: {sorted(olds)!r}")


# ── ۳) مقدارِ fronting بازنده هم دیگر از کلید بیرون انداخته نمی‌شود ──────────

def test_zz_i_loser_fronting_value_retained():
    """`sni` برنده می‌شود ولی `host` هم باید در query بماند (pop برداشته شد)."""
    base = "security=tls&sni=cdn.example.com&type=ws&host="
    k1 = core.dedup_key(_i_vless("1.2.3.4", base + "h1.example.com"))
    k2 = core.dedup_key(_i_vless("1.2.3.4", base + "h2.example.com"))
    assert k1 != k2, f"دو مقدارِ `host` متفاوت یک کلید گرفتند: {k1!r}"
    _h1, ep1, _p1, params1 = _h_parts(k1)
    assert ep1 == "cdn.example.com", k1
    assert "host=h1.example.com" in params1, f"`host` حذف شد: {k1!r}"
    old1, old2 = _i_old_key_generic(k1), _i_old_key_generic(k2)
    assert old1 != k1, "بازسازیِ قاعدهٔ قدیم بی‌اثر است ⇒ تست پوچ می‌شود"
    assert old1 == old2, "تستِ کنترل بی‌اثر است"


# ── ۴) شاخهٔ vmess: `add` دیگر خالی نمی‌شود ───────────────────────────────────

def test_zz_i_vmess_add_retained():
    """vmess با `host`ِ معتبر باید `add` را در کلید نگه دارد."""
    k1 = core.dedup_key(_h_vmess(add="1.2.3.4", host="cdn.example.com", tls="tls"))
    k2 = core.dedup_key(_h_vmess(add="5.6.7.8", host="cdn.example.com", tls="tls"))
    assert k1 != k2, f"دو `add` متفاوت یک کلید گرفتند ⇒ حذفِ خاموش: {k1!r}"
    add1, fr1 = _h_vmess_parts(k1)
    assert add1 == "1.2.3.4", f"`add` از کلید حذف شد: {k1!r}"
    assert fr1 == "cdn.example.com", f"fronting گم شد: {k1!r}"
    old1, old2 = _i_old_key_vmess(k1), _i_old_key_vmess(k2)
    assert old1 != k1, "بازسازیِ قاعدهٔ قدیم بی‌اثر است ⇒ تست پوچ می‌شود"
    assert old1 == old2, "تستِ کنترل بی‌اثر است"


# ── ۵) تستِ کنترلِ چند-طرحی: قاعدهٔ قدیم در همهٔ طرح‌ها ادغام می‌کرد ──────────

def test_zz_i_control_old_rule_merged_them_all_schemes():
    """برای هر طرحِ شاخهٔ عمومی: کلیدِ جدید جدا، کلیدِ بازسازی‌شدهٔ قدیم یکی."""
    templates = (
        "vless://" + _H_UUID + "@{h}:443?security=tls&sni=cdn.example.com&type=ws#t",
        "trojan://pw@{h}:443?security=tls&sni=cdn.example.com&type=ws#t",
        "tuic://u:p@{h}:443?security=tls&sni=cdn.example.com#t",
        "hysteria2://pw@{h}:443?security=tls&sni=cdn.example.com#t",
    )
    for tpl in templates:
        k1 = core.dedup_key(tpl.format(h="1.2.3.4"))
        k2 = core.dedup_key(tpl.format(h="5.6.7.8"))
        assert k1 != k2, f"ادغامِ خاموش در {tpl!r}: {k1!r}"
        old1, old2 = _i_old_key_generic(k1), _i_old_key_generic(k2)
        assert old1 != k1, f"بازسازیِ قدیم بی‌اثر است: {tpl!r}"
        assert old1 == old2, f"تستِ کنترل بی‌اثر است: {tpl!r}"


# ── ۶) دستاوردهای فازِ H و F باید دست‌نخورده بمانند ──────────────────────────

def test_zz_i_phase_h_and_f_gains_intact():
    """وصلهٔ فازِ I نباید اعتبارسنجیِ فازِ H یا شاخهٔ ssِ فازِ F را بشکند."""
    # (الف) مقدارِ زبالهٔ fronting همچنان باید از کلید بیرون انداخته شود.
    host, ep, _p, params = _h_parts(
        core.dedup_key(_h_vless("security=none&host=%2F%3Fbia%40mar&type=ws")))
    assert host == "1.2.3.4", "میزبانِ واقعی گم شد"
    assert ep == "", f"مقدارِ زباله نقطهٔ پایانی شد: {ep!r}"
    assert not any(p.startswith("host=") for p in params), (
        f"مقدارِ زباله در query ماند ⇒ افراز: {sorted(params)!r}")
    # (ب) REALITY: sni دامنهٔ استتار است، نقطهٔ پایانی نیست.
    host, ep, _p, params = _h_parts(core.dedup_key(
        _h_vless("security=reality&sni=www.apple.com&pbk=K&type=tcp")))
    assert (host, ep) == ("1.2.3.4", ""), f"قاعدهٔ REALITY شکست: {host!r} {ep!r}"
    assert "sni=www.apple.com" in params, "sniِ ردشده باید در query بماند"
    # (ج) شاخهٔ ss دست‌نخورده: نه `|ep=` دارد و نه میزبانش را گم می‌کند.
    k_ss = core.dedup_key(f"ss://{_F_UI_B64}@1.2.3.4:8388#x")
    assert "|ep=" not in k_ss, f"شاخهٔ ss آلوده شد: {k_ss!r}"
    _ui, ss_host, ss_port = _f_ss_parts(k_ss)
    assert (ss_host, ss_port) == ("1.2.3.4", "8388"), k_ss
    assert core.dedup_key(f"ss://{_F_UI_B64}@5.6.7.8:8388#x") != k_ss


# ── ۷) یکتاسازی همچنان کار می‌کند (وصله dedup را خاموش نکرده) ────────────────

def test_zz_i_true_duplicates_still_collapse():
    """دو خطِ واقعاً یکسان (فقط ترتیبِ پارامتر/برچسب متفاوت) ⇒ یک کلید."""
    a = _i_vless("1.2.3.4", "security=tls&sni=cdn.example.com&type=ws")
    b = f"vless://{_H_UUID}@1.2.3.4:443?type=ws&sni=cdn.example.com&security=tls#other"
    assert core.dedup_key(a) == core.dedup_key(b), (
        f"یکتاسازیِ درست از کار افتاد:\n  {core.dedup_key(a)!r}\n  {core.dedup_key(b)!r}")
    v1 = core.dedup_key(_h_vmess(add="1.2.3.4", host="cdn.example.com", tls="tls"))
    v2 = core.dedup_key(_h_vmess(add="1.2.3.4", host="cdn.example.com", tls="tls",
                                 ps="یک برچسبِ دیگر"))
    assert v1 == v2, f"برچسب واردِ کلیدِ vmess شد: {v1!r} / {v2!r}"


# ── ۸) دو بُعدی که سنجش نشان داد امروز هیچ آسیبی از آن‌ها نمی‌آید ────────────

def test_zz_i_port_and_credential_still_distinguish():
    """پورت و اعتبارنامه باید همچنان تمایز بسازند (A_diff_port/B_diff_cred = 0)."""
    q = "security=tls&sni=cdn.example.com&type=ws"
    k443 = core.dedup_key(_i_vless("1.2.3.4", q))
    k8080 = core.dedup_key(
        f"vless://{_H_UUID}@1.2.3.4:8080?{q}#tag")
    assert k443 != k8080, f"دو پورتِ متفاوت یک کلید گرفتند: {k443!r}"
    other_uuid = "22222222-2222-2222-2222-222222222222"
    assert core.dedup_key(_i_vless("1.2.3.4", q, uuid=other_uuid)) != k443, (
        "دو اعتبارنامهٔ متفاوت یک کلید گرفتند")


# ── ۹) دامنهٔ وصله محدود است: بی‌fronting هیچ چیز عوض نشده ───────────────────

def test_zz_i_patch_scope_no_fronting_unchanged():
    """خطِ بدونِ sni/host: کلید باید عیناً همان قبل باشد (قدیم == جدید)."""
    for line in (_i_vless("1.2.3.4", "security=none&type=tcp"),
                 _i_vless("1.2.3.4", "type=grpc&servicename=svc"),
                 "trojan://pw@1.2.3.4:443?type=tcp#t"):
        key = core.dedup_key(line)
        host, ep, _p, _q = _h_parts(key)
        assert ep == "", f"fronting از هوا آمد: {key!r}"
        assert host == "1.2.3.4", f"میزبان گم شد: {key!r}"
        assert _i_old_key_generic(key) == key, (
            f"وصله بیرونِ دامنهٔ خود اثر گذاشت: {key!r}")


# ══════════════════════════════════════════════════════════════════════════════
# فاز J — سناریوهای رفتاری + کنترل‌های ابطال‌پذیر
# ══════════════════════════════════════════════════════════════════════════════
#
# چرا این بلوک وجود دارد
# ──────────────────────
# فازِ J یازده یافته را سنجید و از میانِ آن‌ها **نُه** تغییر را روی
# `core.py` نشاند (J-1…J-4 و J-7a…J-7e). هر تغییر با «اوراکلِ هم‌ارزیِ
# برگرفته از خودِ محصول» اثبات شد: دو خط تنها آن‌گاه هم‌ارزند که همین
# مخزن از هر دو خروجیِ **مو‌به‌موی یکسان** بسازد
# (`converters.parse_proxy` + `_to_clash_proxy` + `_to_singbox_outbound`،
# منهای `name`/`tag` که آرایشی‌اند).
#
# دو زیانِ **متفاوت** — که هرگز با هم جمع نمی‌شوند:
#   (الف) ادغامِ کاذب  ⇒ بازنده به `r.duplicates` می‌رود و **هرگز منتشر
#         نمی‌شود** (`aggregate.py:259-263`) ⇒ **حذفِ خاموش**.
#   (ب)  افرازِ کاذب   ⇒ همان سرور **چند بار** منتشر می‌شود ⇒ فقط شلوغی.
# (الف) از (ب) مهم‌تر است چون پیامدش **از جنسِ دیگری** است. پس قاعده:
# «در تردید، ادغام نکن» و «وقتی هم‌ارزی **اثبات** شد، نشکاف».
#
# ⚠️ هر تستِ این بلوک یک **کنترلِ ابطال‌پذیر** هم دارد: در کنارِ «چه چیزی
# حالا یکی می‌شود» همیشه «چه چیزی هنوز باید جدا بماند» هم سنجیده می‌شود،
# تا تستی که با خاموش‌کردنِ کلِ یکتاسازی هم سبز بماند وجود نداشته باشد.

_J_UUID = "22222222-2222-2222-2222-222222222222"
_J_PBK = "jWVk2Z7eFkyDcu2xgzqX8JsPbZuCVhHUWD463Vfgazw"


def _j_vless(query: str, host: str = "1.2.3.4", port: int = 443,
             uuid: str = _J_UUID) -> str:
    return f"vless://{uuid}@{host}:{port}?{query}#tag"


def _j_vmess_obj(obj: dict) -> str:
    """vmess از یک dictِ **دقیقاً همان** — بدونِ هیچ پیش‌فرضِ تزریقی."""
    return "vmess://" + base64.b64encode(
        json.dumps(obj).encode("utf-8")).decode("ascii")


_J_VM_BASE = {"add": "9.9.9.9", "port": 8443, "id": "u9", "net": "ws",
              "path": "/p"}


def _j_vmess(**kw) -> str:
    obj = dict(_J_VM_BASE)
    obj.update(kw)
    return _j_vmess_obj(obj)


def _j_query_of(key: str) -> set:
    """مجموعهٔ جفت‌های queryِ داخلِ کلیدِ شاخهٔ عمومی."""
    if "?" not in key:
        return set()
    return {p for p in key.split("?", 1)[1].split("&") if p}


def _j_old_norm_identity_value(key: str, val: str) -> str:
    """بازپیاده‌سازیِ نرمال‌سازِ **پیش از فاز J** — برای کنترلِ ابطال‌پذیری.

    این تابع عمداً در فایلِ تست زندگی می‌کند و از `core` نمی‌آید: کارش
    این است که نشان دهد قاعدهٔ جدید واقعاً چیزی را عوض کرده، نه اینکه
    تست‌ها همان‌طوری هم سبز می‌شدند.
    """
    v = (val or "").strip().lower()
    if key in ("sni", "host"):
        for _ in range(2):
            nv = urllib.parse.unquote(v)
            if nv == v:
                break
            v = nv
        v = v.strip().lower()
    if key == "type":
        return core._norm_type(v)          # ← «tcp» برمی‌گشت و در کلید می‌ماند
    if key in ("encryption", "security", "headertype"):
        return "" if v in ("", "none") else v
    return v                               # ← همه‌چیز کوچک‌شده


# ── J-1) `&amp;` — نقصِ **تجزیه‌گر**، نه یکتاسازی ─────────────────────────────

def test_zz_j_amp_entity_repaired_in_ingestion_funnel():
    """`&amp;` در قیفِ یگانهٔ ورود (`extract_valid_lines`) ترمیم می‌شود.

    باگِ واقعی: ۱۰ کانفیگِ منتشرشده در پیکرهٔ زنده، `&amp;` داشتند؛ یعنی
    `security=tls&amp;sni=…` یک پارامترِ **واحد** به نامِ `security` با
    مقدارِ `tls&amp;sni=…` می‌شد و همهٔ پارامترهای بعدی نابود می‌شدند.
    تنها فراخوانندهٔ این تابع `aggregate.py:159` است، پس همین یک نقطه
    کافی است و `converters.py` دست‌نخورده می‌ماند.
    """
    broken = _j_vless("security=tls&amp;sni=cdn.example.com&amp;type=ws")
    clean = _j_vless("security=tls&sni=cdn.example.com&type=ws")
    got = core.extract_valid_lines(broken)
    assert len(got) == 1, f"قیفِ ورود خط را انداخت: {got!r}"
    assert "&amp;" not in got[0], f"`&amp;` ترمیم نشد: {got[0]!r}"
    assert got[0] == clean, f"ترمیم دقیق نبود:\n  {got[0]!r}\n  {clean!r}"
    assert core.dedup_key(got[0]) == core.dedup_key(clean), (
        "خطِ ترمیم‌شده و خطِ سالم باید یک کلید بگیرند")


def test_zz_j_amp_control_raw_line_really_is_broken():
    """کنترلِ ابطال‌پذیر: خطِ **ترمیم‌نشده** واقعاً خروجیِ خراب می‌دهد.

    اگر این تست شکست بخورد، یعنی `&amp;` بی‌آزار بود و ترمیمِ J-1 بی‌دلیل.
    سنجشِ واقعی: `network` از `ws` به `tcp` فرومی‌ریزد و `sni` خالی می‌شود.
    """
    broken = _j_vless("security=tls&amp;sni=cdn.example.com&amp;type=ws")
    clean = _j_vless("security=tls&sni=cdn.example.com&type=ws")
    p_bad = converters.parse_proxy(broken)
    p_ok = converters.parse_proxy(clean)
    assert p_bad is not None and p_ok is not None, "هر دو خط باید تجزیه شوند"
    assert p_bad != p_ok, "خطِ خراب و سالم خروجیِ یکسان دادند ⇒ J-1 بی‌دلیل بود"
    assert p_ok.get("network") == "ws", f"خطِ سالم: {p_ok.get('network')!r}"
    assert p_bad.get("network") == "tcp", (
        f"انتظار فروریزیِ network به tcp، دیده شد: {p_bad.get('network')!r}")
    assert p_ok.get("sni") == "cdn.example.com", p_ok.get("sni")
    assert not p_bad.get("sni"), f"sniِ خطِ خراب باید خالی باشد: {p_bad.get('sni')!r}"


def test_zz_j_amp_repair_precision_non_separator_untouched():
    """`&amp;` که **جداکننده نیست** دست‌نخورده می‌ماند (قاعدهٔ محافظه‌کارانه).

    سنجش روی پیکرهٔ ۱۸٬۷۳۵ خطی: از ۵۵ رخدادِ `&amp;`، هر ۵۵ جداکننده
    بودند و ۰ مورد استثنا. ولی قاعده عمداً شرطی است تا اگر روزی `&amp;`
    داخلِ **مقدار** بیاید، خرابش نکند.
    """
    line = _j_vless("security=tls&note=a&amp;b&type=ws")
    got = core.extract_valid_lines(line)[0]
    assert "&amp;b" in got, f"`&amp;` غیرِ جداکننده ترمیم شد: {got!r}"
    line2 = f"vless://{_J_UUID}@1.2.3.4:443?path=%2Fa&amp;%2Fb&type=ws#t"
    assert core.extract_valid_lines(line2)[0].count("&amp;") == 1, (
        "`&amp;` پیش از یک مقدارِ درصدرمز نباید جداکننده شمرده شود")


def test_zz_j_amp_repair_is_idempotent_and_key_stable():
    """ترمیم idempotent است و روی خطِ بی‌`&amp;` هیچ اثری ندارد."""
    broken = _j_vless("security=tls&amp;sni=cdn.example.com&amp;type=ws")
    once = core._repair_amp_separator(broken)
    assert core._repair_amp_separator(once) == once, "ترمیم idempotent نیست"
    for neutral in (_j_vless("security=tls&sni=a.example.com&type=ws"),
                    _j_vmess(tls="tls", sni="a.example.com"),
                    "trojan://pw@1.2.3.4:443?type=tcp#t"):
        assert core._repair_amp_separator(neutral) == neutral, (
            f"خطِ بی‌`&amp;` عوض شد: {neutral!r}")


# ── J-2) vmess `tls`: هر مقداری که محصول «TLS» نمی‌شمارد ≡ بی‌TLS ────────────

def test_zz_j_vmess_tls_auto_equals_absent():
    """`tls:"auto"` ≡ `tls:""` ≡ `tls:"none"` — خروجی مو‌به‌مو یکسان است.

    پنج شاهدِ مستقل: ویکیِ v2rayN (`auto` به `scy` تعلق دارد)،
    `Global.cs:62-63`، `V2rayOutboundService.cs:401,452` (بی‌`else`)،
    `SingboxOutboundService.cs:391` (بازگشتِ زودهنگام)، و ★ قاطع‌ترین:
    `converters.py:553` که مقدار را به یک **بولین** بدل می‌کند
    (`in ("tls","reality")`). در پیکره ۲۸ خط `tls:auto` داشتند.
    """
    k_auto = core.dedup_key(_j_vmess(tls="auto"))
    k_absent = core.dedup_key(_j_vmess())
    k_none = core.dedup_key(_j_vmess(tls="none"))
    k_empty = core.dedup_key(_j_vmess(tls=""))
    assert k_auto == k_absent == k_none == k_empty, (
        f"مقادیرِ هم‌ارزِ tls جدا افتادند:\n  auto={k_auto!r}\n"
        f"  absent={k_absent!r}\n  none={k_none!r}\n  empty={k_empty!r}")


def test_zz_j_vmess_tls_real_values_still_split():
    """کنترل: مقادیرِ **واقعیِ** TLS هرگز ادغام نمی‌شوند.

    `xtls` عامدانه در فهرستِ مجاز مانده تا این قاعده فقط بتواند بشکافد،
    نه ادغام کند (جهتِ محافظه‌کارانه؛ در پیکره هیچ `xtls` نبود).
    """
    keys = {
        "absent": core.dedup_key(_j_vmess()),
        "tls": core.dedup_key(_j_vmess(tls="tls")),
        "reality": core.dedup_key(_j_vmess(tls="reality")),
        "xtls": core.dedup_key(_j_vmess(tls="xtls")),
    }
    assert len(set(keys.values())) == 4, (
        f"مقادیرِ متمایزِ TLS ادغام شدند: {keys!r}")


# ── J-3) تقارنِ `type` پیش‌فرض با **غیبتِ** `type` ───────────────────────────

def test_zz_j_type_default_symmetric_with_absence():
    """`?type=tcp` ≡ `?type=raw` ≡ `?type=none` ≡ بی‌`type` (۸ نشرِ تکراری).

    نامتقارنی: `_norm_type` برای مقادیرِ پیش‌فرض «tcp» برمی‌گرداند و
    حلقهٔ شاخهٔ عمومی آن را با شرطِ `nv != ""` نگه می‌داشت — اما `type`ِ
    **غایب** هرگز واردِ `meaningful` نمی‌شد. پس یک سرورِ واحد دو کلید
    می‌گرفت و دو بار منتشر می‌شد.
    """
    base = "security=tls&sni=cdn.example.com"
    keys = [core.dedup_key(_j_vless(q)) for q in (
        base, base + "&type=tcp", base + "&type=raw", base + "&type=none",
        base + "&type=TCP", base + "&type=%20tcp%20")]
    assert len(set(keys)) == 1, f"تقارنِ typeِ پیش‌فرض شکست: {set(keys)!r}"
    assert not any(p.startswith("type=") for p in _j_query_of(keys[0])), (
        f"`type`ِ پیش‌فرض نباید در کلید بنشیند: {keys[0]!r}")


def test_zz_j_type_real_transport_still_splits():
    """کنترل: لایهٔ انتقالِ **واقعی** همچنان تمایز می‌سازد."""
    base = "security=tls&sni=cdn.example.com"
    keys = {t: core.dedup_key(_j_vless(base + f"&type={t}"))
            for t in ("ws", "grpc", "http", "h2", "xhttp")}
    keys["absent"] = core.dedup_key(_j_vless(base))
    assert len(set(keys.values())) == 6, f"انتقال‌ها ادغام شدند: {keys!r}"


def test_zz_j_norm_type_deliberately_untouched():
    """`_norm_type` عامدانه دست‌نخورده مانده — شاخهٔ vmess به آن وابسته است.

    در شاخهٔ vmess مقدارِ `net` **موضعی** در کلید نوشته می‌شود و آنجا
    «» باید همان «tcp» بماند؛ اگر `_norm_type` را عوض می‌کردیم،
    `net:""` و `net:"tcp"` جدا می‌شدند (افرازِ کاذبِ تازه).
    """
    assert core._norm_type("") == "tcp", core._norm_type("")
    assert core._norm_type("raw") == "tcp", core._norm_type("raw")
    assert core._norm_type("none") == "tcp", core._norm_type("none")
    assert core._norm_type("ws") == "ws", core._norm_type("ws")
    assert core.dedup_key(_j_vmess(net="")) == core.dedup_key(_j_vmess(net="tcp")), (
        "شاخهٔ vmess: `net` خالی و `tcp` باید یکی بمانند")


# ── J-4) دو فرمِ Shadowsocks یکی می‌شوند ─────────────────────────────────────

def test_zz_j_ss_legacy_unified_with_sip002():
    """فرمِ قدیمِ ss (بی‌`@`) به همان کلیدِ SIP002 می‌رسد (۴ نشرِ تکراری).

    بدنهٔ رمزگشایی‌شدهٔ فرمِ قدیم دقیقاً `method:pass@host:port` است —
    همان چیزی که شاخهٔ SIP002 از اجزای جدا می‌سازد.
    """
    legacy = "ss://" + base64.b64encode(
        b"aes-256-gcm:pw@1.2.3.4:8388").decode("ascii").rstrip("=") + "#x"
    sip002 = "ss://" + base64.b64encode(
        b"aes-256-gcm:pw").decode("ascii").rstrip("=") + "@1.2.3.4:8388#x"
    k_leg, k_sip = core.dedup_key(legacy), core.dedup_key(sip002)
    assert k_leg == k_sip, f"دو فرمِ ss جدا ماندند:\n  {k_leg!r}\n  {k_sip!r}"
    assert k_leg == "ss:sip002:aes-256-gcm:pw@1.2.3.4:8388", k_leg
    assert not k_leg.startswith("ss:legacy:"), k_leg


def test_zz_j_ss_legacy_distinct_parts_still_split():
    """کنترل: ادغامِ کاذب ساختاراً ناممکن است — هر چهار جزء باید یکی باشند."""
    def leg(body: bytes) -> str:
        return "ss://" + base64.b64encode(body).decode("ascii").rstrip("=") + "#x"
    keys = {
        "base": core.dedup_key(leg(b"aes-256-gcm:pw@1.2.3.4:8388")),
        "pass": core.dedup_key(leg(b"aes-256-gcm:pw2@1.2.3.4:8388")),
        "host": core.dedup_key(leg(b"aes-256-gcm:pw@5.6.7.8:8388")),
        "port": core.dedup_key(leg(b"aes-256-gcm:pw@1.2.3.4:9999")),
        "method": core.dedup_key(leg(b"chacha20-ietf-poly1305:pw@1.2.3.4:8388")),
    }
    assert len(set(keys.values())) == 5, f"اجزای متفاوتِ ss ادغام شدند: {keys!r}"


def test_zz_j_ss_legacy_not_base64_still_falls_back():
    """بدنهٔ غیرِbase64 باید به مسیرِ fallback برود، نه استثنا بدهد."""
    k = core.dedup_key("ss://!!!not-base64!!!#x")
    assert k == "ss://!!!not-base64!!!", k
    k2 = core.dedup_key("ss://" + base64.b64encode(
        b"no-at-sign-here").decode("ascii").rstrip("=") + "#x")
    assert k2.startswith("ss:legacy:"), (
        f"بدنهٔ base64ِ بی‌`@` باید legacy بماند: {k2!r}")


# ── J-7a) `alpn` و `extra` هویتی‌اند ────────────────────────────────────────

def test_zz_j_alpn_and_extra_are_identity():
    """`alpn`/`extra` بر «رسیدن» مؤثرند ⇒ نبودشان در کلید = حذفِ خاموش."""
    base = "security=tls&sni=cdn.example.com&type=ws"
    k_none = core.dedup_key(_j_vless(base))
    k_h3 = core.dedup_key(_j_vless(base + "&alpn=h3"))
    k_h2 = core.dedup_key(_j_vless(base + "&alpn=h2"))
    assert len({k_none, k_h3, k_h2}) == 3, (
        f"alpn هویت نساخت: {(k_none, k_h3, k_h2)!r}")
    assert "alpn=h3" in _j_query_of(k_h3), k_h3
    k_ex = core.dedup_key(_j_vless(base + "&extra=%7B%22a%22%3A1%7D"))
    assert k_ex != k_none, f"extra هویت نساخت: {k_ex!r}"


def test_zz_j_alpn_same_value_still_collapses():
    """کنترل: `alpn` یکسان با ترتیبِ متفاوتِ پارامتر ⇒ همان یک کلید."""
    a = _j_vless("security=tls&sni=cdn.example.com&type=ws&alpn=h3")
    b = _j_vless("alpn=h3&type=ws&sni=cdn.example.com&security=tls")
    assert core.dedup_key(a) == core.dedup_key(b), (
        f"ترتیبِ پارامتر کلید را عوض کرد:\n  {core.dedup_key(a)!r}\n"
        f"  {core.dedup_key(b)!r}")


# ── J-7b) vmess: `host` و `sni` دو مصنوعِ متمایزند ──────────────────────────

def test_zz_j_vmess_host_and_sni_no_longer_conflated():
    """`host or sni` این دو را قاطی می‌کرد ⇒ یکی خاموش حذف می‌شد.

    محصول آن‌ها را به **دو فیلدِ متفاوت** امیت می‌کند: هدرِ `Host` در
    clash و `servername`/`server_name` در TLS.
    """
    k_host = core.dedup_key(_j_vmess(host="cdn.example.com", tls="tls"))
    k_sni = core.dedup_key(_j_vmess(sni="cdn.example.com", tls="tls"))
    assert k_host != k_sni, f"host و sni یک کلید گرفتند: {k_host!r}"
    assert "~" not in k_host.split("|ep=", 1)[1].split(":", 1)[0], k_host
    assert k_sni.split("|ep=", 1)[1].startswith("~cdn.example.com"), k_sni
    k_both = core.dedup_key(_j_vmess(host="a.example.com",
                                     sni="cdn.example.com", tls="tls"))
    assert len({k_host, k_sni, k_both}) == 3, (
        f"سه ترکیبِ متمایزِ fronting ادغام شدند: {(k_host, k_sni, k_both)!r}")
    # کنترل: مقدارِ یکسان در همان جایگاه ⇒ همان کلید.
    assert core.dedup_key(_j_vmess(host="cdn.example.com", tls="tls",
                                   ps="برچسبِ دیگر")) == k_host


# ── J-7c) vmess `alterId` ───────────────────────────────────────────────────

def test_zz_j_vmess_alter_id_normalized_like_the_product():
    """`aid` غایب ≡ `0` ≡ `"0"` ≡ `""` ≡ زباله؛ ولی `4` جداست.

    محصول مقدار را با `converters._safe_int(obj.get("aid"), 0)` می‌خواند،
    پس همهٔ صورت‌های «صفر» خروجیِ مو‌به‌مو یکسان می‌دهند (افرازِ کاذبِ
    اجتناب‌پذیر = زیانِ ب). ولی هم‌ارزیِ `aid` **واقعی** اثبات نشد
    (`mihomo/transport/vmess/vmess.go:107` آن را به `newAlterIDs`
    می‌دهد) ⇒ بر پایهٔ «در تردید، ادغام نکن» می‌شکافیم.
    """
    assert core._norm_aid(None) == "0", core._norm_aid(None)
    assert core._norm_aid("") == "0"
    assert core._norm_aid(" 4 ") == "4"
    assert core._norm_aid("xx") == "0", "مقدارِ نامعتبر باید به پیش‌فرض برود"
    assert core._norm_aid("07") == "7"
    zeros = {core.dedup_key(_j_vmess()),
             core.dedup_key(_j_vmess(aid=0)),
             core.dedup_key(_j_vmess(aid="0")),
             core.dedup_key(_j_vmess(aid="")),
             core.dedup_key(_j_vmess(aid="xx"))}
    assert len(zeros) == 1, f"صورت‌های «صفر»ِ aid جدا افتادند: {zeros!r}"
    k4 = core.dedup_key(_j_vmess(aid=4))
    assert k4 not in zeros, f"aid=4 با صفر ادغام شد: {k4!r}"
    assert core.dedup_key(_j_vmess(aid=4)) != core.dedup_key(_j_vmess(aid=64))


# ── J-7d) vmess `path`: تنها هم‌ارزیِ **اثبات‌شده** ─────────────────────────

def test_zz_j_vmess_path_root_equivalent_but_trailing_slash_not():
    """`""` ≡ `"/"`؛ ولی `/abc/` ≢ `/abc`.

    شاهد: `mihomo/transport/vmess/websocket.go:350-351` اگر مسیر با `/`
    شروع نشود، `/` را **جلوش می‌گذارد** ⇒ «» و «/» یکی‌اند. ولی
    `rstrip("/")` پیشین `/abc/` را هم با `/abc` یکی می‌کرد که دو مسیرِ
    متفاوتِ HTTP‌اند (RFC 3986 §6.2.2) ⇒ ادغامِ کاذبِ نهفته.
    """
    no_path = {"add": "9.9.9.9", "port": 8443, "id": "u9", "net": "ws"}
    k_absent = core.dedup_key(_j_vmess_obj(no_path))
    k_empty = core.dedup_key(_j_vmess_obj(dict(no_path, path="")))
    k_slash = core.dedup_key(_j_vmess_obj(dict(no_path, path="/")))
    assert k_absent == k_empty == k_slash, (
        f"«» و «/» جدا افتادند: {(k_absent, k_empty, k_slash)!r}")
    k_abc = core.dedup_key(_j_vmess(path="/abc"))
    k_abc_slash = core.dedup_key(_j_vmess(path="/abc/"))
    assert k_abc != k_abc_slash, (
        f"`/abc` و `/abc/` ادغام شدند (ادغامِ کاذب): {k_abc!r}")
    assert k_abc != k_slash and k_abc_slash != k_slash


# ── J-7e) حساسیت به بزرگی/کوچکی — نقصِ واقعیِ یکتاسازی ─────────────────────

def test_zz_j_case_sensitive_params_preserved():
    """`path`/`servicename`/`pbk`/`presharedkey` باید عیناً بمانند (۲۷ مصنوع).

    RFC 3986 §6.2.2.1: تنها `scheme` و `host` بی‌حساس به بزرگی‌اند.
    در پیکرهٔ زنده `path=TG%40ZDYZ2` و `path=tg%40zdyz2` یک کلید
    می‌گرفتند و یکی خاموش حذف می‌شد. دربارهٔ `pbk` بدتر است: base64url
    است و کوچک‌سازی یک **کلیدِ عمومیِ دیگر** می‌سازد.
    """
    base = "security=tls&sni=cdn.example.com&type=ws"
    k_up = core.dedup_key(_j_vless(base + "&path=%2FTG%40ZDYZ2"))
    k_lo = core.dedup_key(_j_vless(base + "&path=%2Ftg%40zdyz2"))
    assert k_up != k_lo, f"دو مسیرِ متفاوت یک کلید گرفتند: {k_up!r}"
    assert "path=/TG@ZDYZ2" in _j_query_of(k_up), k_up
    rq = f"security=reality&sni=www.apple.com&type=grpc&pbk={_J_PBK}"
    k_pbk = core.dedup_key(_j_vless(rq))
    assert f"pbk={_J_PBK}" in _j_query_of(k_pbk), (
        f"`pbk` کوچک شد ⇒ کلیدِ عمومیِ دیگری ساخته شد: {k_pbk!r}")
    assert k_pbk != core.dedup_key(_j_vless(
        f"security=reality&sni=www.apple.com&type=grpc&pbk={_J_PBK.lower()}"))
    k_svc = core.dedup_key(_j_vless(
        "security=tls&sni=a.example.com&type=grpc&servicename=SvcName"))
    assert "servicename=SvcName" in _j_query_of(k_svc), k_svc


def test_zz_j_case_insensitive_params_still_folded():
    """کنترل: پارامترهایی که واقعاً بی‌حساس‌اند همچنان تا می‌خورند.

    `sid` (shortId) هگز است، `flow` یک شناسهٔ ثابت، و `sni`/`host` نامِ
    میزبان‌اند (RFC 3986 §6.2.2.1) ⇒ کوچک‌سازی درست است.
    """
    rq = f"security=reality&sni=www.apple.com&type=grpc&pbk={_J_PBK}"
    assert core.dedup_key(_j_vless(rq + "&sid=ABCD")) == \
        core.dedup_key(_j_vless(rq + "&sid=abcd")), "sid نباید حساس شود"
    assert core.dedup_key(_j_vless(
        "security=tls&sni=a.example.com&type=tcp&flow=XTLS-RPRX-VISION")) == \
        core.dedup_key(_j_vless(
            "security=tls&sni=a.example.com&type=tcp&flow=xtls-rprx-vision"))
    assert core.dedup_key(_j_vless("security=tls&sni=CDN.Example.COM&type=ws")) == \
        core.dedup_key(_j_vless("security=tls&sni=cdn.example.com&type=ws"))


# ── کنترلِ کلان: قواعدِ قدیم واقعاً چیزِ دیگری می‌گفتند ─────────────────────

def test_zz_j_control_old_rules_really_differed():
    """اثباتِ غیرِتُهی‌بودنِ فازِ J: قاعدهٔ قدیم و جدید هم‌ارز نیستند.

    اگر این تست شکست بخورد، یعنی هیچ‌یک از تست‌های بالا چیزی را تثبیت
    نمی‌کند — همان‌قدر با قاعدهٔ قدیم هم سبز می‌شدند.
    """
    # (۱) `type` پیش‌فرض: قدیم «tcp» می‌داد و در کلید می‌نشست، جدید «».
    assert _j_old_norm_identity_value("type", "tcp") == "tcp"
    assert core._norm_identity_value("type", "tcp") == "", (
        core._norm_identity_value("type", "tcp"))
    # (۲) بزرگی/کوچکی: قدیم `path` را تا می‌زد، جدید نه.
    assert _j_old_norm_identity_value("path", "/TG@ZDYZ2") == \
        _j_old_norm_identity_value("path", "/tg@zdyz2"), "قاعدهٔ قدیم تا می‌زد"
    assert core._norm_identity_value("path", "/TG@ZDYZ2") != \
        core._norm_identity_value("path", "/tg@zdyz2"), "قاعدهٔ جدید نباید تا بزند"
    assert core._norm_identity_value("path", "/TG@ZDYZ2") == "/TG@ZDYZ2"
    # (۳) `alpn`/`extra` پیش از J هرگز واردِ کلید نمی‌شدند.
    for p in ("alpn", "extra"):
        assert p in core._IDENTITY_PARAMS, f"{p} از فهرستِ هویت افتاد"
    # (۴) پارامترهای حساس، صریحاً فهرست شده‌اند.
    for p in ("path", "servicename", "pbk", "publickey", "presharedkey"):
        assert p in core._CASE_SENSITIVE_PARAMS, f"{p} در فهرستِ حساس نیست"
    # (۵) قواعدِ بی‌حساس نباید به فهرست راه یافته باشند.
    for p in ("sni", "host", "sid", "flow", "security", "type"):
        assert p not in core._CASE_SENSITIVE_PARAMS, (
            f"{p} نباید حساس باشد — نامِ میزبان/هگز/شناسهٔ ثابت است")


def test_zz_j_phase_f_h_i_gains_intact():
    """دستاوردهای فازهای F/H/I پس از وصله‌های J هنوز برجایند.

    این تست عمداً ترکیبی است: هر سه ویژگی در **همین** `dedup_key` زندگی
    می‌کنند، پس اگر وصله‌های J چیزی را بشکنند، اینجا دیده می‌شود.
    """
    # F: '@' داخلِ query نباید هویتِ endpoint را نابود کند.
    ui = base64.b64encode(b"aes-256-gcm:pw").decode("ascii").rstrip("=")
    k_f = core.dedup_key(f"ss://{ui}@1.2.3.4:11201?note=@FreeVPN#x")
    assert k_f == "ss:sip002:aes-256-gcm:pw@1.2.3.4:11201", k_f
    # H: مقدارِ زبالهٔ fronting کاملاً از کلید حذف می‌شود (نه در ep، نه در query).
    k_h = core.dedup_key(_j_vless(
        "security=tls&sni=https%3A%2F%2Ft.me%2Fx&type=ws"))
    assert "|ep=:" in k_h, f"زباله نقطهٔ پایانی شد: {k_h!r}"
    assert not any(p.startswith("sni=") for p in _j_query_of(k_h)), (
        f"زباله در query ماند ⇒ افراز: {k_h!r}")
    # I: میزبانِ واقعی همیشه در کلید می‌ماند و دو میزبان را جدا می‌کند.
    a = _j_vless("security=tls&sni=cdn.example.com&type=ws", host="1.2.3.4")
    b = _j_vless("security=tls&sni=cdn.example.com&type=ws", host="5.6.7.8")
    assert "@1.2.3.4|ep=cdn.example.com" in core.dedup_key(a), core.dedup_key(a)
    assert core.dedup_key(a) != core.dedup_key(b), (
        "دو میزبانِ متفاوت با fronting مشترک ادغام شدند ⇒ حذفِ خاموش")


def _run_all() -> int:
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ✅ {name}")
        except AssertionError as e:
            failed += 1
            print(f"  ❌ {name}\n       {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  💥 {name}\n       {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
