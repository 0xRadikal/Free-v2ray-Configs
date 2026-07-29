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

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import yaml  # noqa: E402

import converters  # noqa: E402
import core  # noqa: E402


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

    # reset باید واقعاً پاک کند (وگرنه تست‌های بعدی به هم می‌ریزند)
    core.reset_country_cache()
    third = core.brand_remark(body + "#US New York")
    assert "US" in third, third
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
