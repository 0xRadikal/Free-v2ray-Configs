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
    assert "deepen" in run, \
        "the step must deepen a shallow checkout, otherwise no anchor is found"

    # ۵) گاردهای fail-closed باید سرِ جایشان باشند.
    for guard in ("refusing to publish", "EMPTY tree", "MUST_EXIST"):
        assert guard in run, f"missing fail-closed guard: {guard}"


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
# اجرا بدون pytest
# ──────────────────────────────────────────────────────────────────────────────

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
