#!/usr/bin/env python3
"""Build the GitHub Pages landing page from `docs-src/`.

    python3 docs-src/build.py            # writes docs/index.html and docs/fa/index.html
    python3 docs-src/build.py --check    # exit 1 if the committed pages are stale

Inputs
    docs-src/template.html   one template for both languages
    docs-src/i18n/en.json    English strings
    docs-src/i18n/fa.json    Persian strings (must carry exactly the same keys)
    docs/styles.css, docs/app.js, docs/vendor/*.js
                             hand-written runtime; their content hash becomes the
                             `?v=` cache-buster so a deploy never serves stale CSS/JS

Template syntax
    {{a.b}}      string from the language file, HTML-escaped
    {{{a.b}}}    string from the language file, inserted raw (keys end in `_html`)
    {{@x}}       build variable, HTML-escaped
    {{{@x}}}     build variable, inserted raw (pre-escaped JSON / generated HTML)

Only the Python standard library is used, so the page can be rebuilt anywhere.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DOCS = os.path.join(REPO, "docs")

SITE = "https://0xradikal.github.io/Free-v2ray-Configs/"
REPO_URL = "https://github.com/0xRadikal/Free-v2ray-Configs"
RAW = "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main"
QR_VENDOR = "vendor/qrcode-generator-1.4.4.js"

LANGS = {
    "en": {
        "out": "index.html",
        "dir": "ltr",
        "base": "",
        "canonical": SITE,
        "og_locale": "en_US",
        "og_locale_alt": "fa_IR",
        "alt_href": "fa/",
        "alt_lang": "fa",
        "alt_label": "فارسی",
        "font_preload": "fonts/manrope-latin.woff2",
        "sister_href": "https://0xradikal.github.io/Free-Telegram-Proxy/",
    },
    "fa": {
        "out": "fa/index.html",
        "dir": "rtl",
        "base": "../",
        "canonical": SITE + "fa/",
        "og_locale": "fa_IR",
        "og_locale_alt": "en_US",
        "alt_href": "../",
        "alt_lang": "en",
        "alt_label": "English",
        "font_preload": "fonts/estedad-arabic.woff2",
        "sister_href": "https://0xradikal.github.io/Free-Telegram-Proxy/fa/",
    },
}

_TOKEN = re.compile(r"\{\{\{(@?[\w.]+)\}\}\}|\{\{(@?[\w.]+)\}\}")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _short_hash(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()[:10]


def _flatten(obj, prefix: str = "") -> dict:
    out = {}
    for key, val in obj.items():
        name = f"{prefix}{key}"
        if isinstance(val, dict):
            out.update(_flatten(val, name + "."))
        else:
            out[name] = val
    return out


def _script_json(obj) -> str:
    """JSON that is safe inside <script>: no `</script>`, no `<!--`, no U+2028/9."""
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return (text.replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026").replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029"))


def _faq_html(items) -> str:
    rows = []
    for i, (q, a) in enumerate(items):
        rows.append(
            f'      <details class="faq-item" id="faq-{i + 1}">'
            f"<summary><span>{html.escape(q)}</span>"
            '<span class="faq-plus" aria-hidden="true"></span></summary>'
            f"<p>{html.escape(a)}</p></details>")
    return "\n".join(rows)


def _jsonld(strings: dict, lang: str, canonical: str) -> dict:
    faq = strings["faq"]["items"]
    return {
        "@context": "https://schema.org",
        "@graph": [
            {
                "@type": "WebSite",
                "@id": SITE + "#website",
                "url": SITE,
                "name": "Raydikalx Free V2Ray Configs",
                "inLanguage": ["en", "fa"],
            },
            {
                "@type": "WebPage",
                "@id": canonical + "#webpage",
                "url": canonical,
                "name": strings["meta"]["title"],
                "description": strings["meta"]["desc"],
                "inLanguage": lang,
                "isPartOf": {"@id": SITE + "#website"},
            },
            {
                "@type": "SoftwareSourceCode",
                "name": "Free-v2ray-Configs",
                "codeRepository": REPO_URL,
                "programmingLanguage": "Python",
                "license": "https://spdx.org/licenses/MIT.html",
                "creator": {"@type": "Person", "name": "0xRadikal",
                            "url": "https://github.com/0xRadikal"},
            },
            {
                "@type": "Dataset",
                "name": "Free V2Ray Configs (verified subscription)",
                "description": strings["meta"]["desc"],
                "url": canonical,
                "sameAs": REPO_URL,
                "isAccessibleForFree": True,
                "license": "https://spdx.org/licenses/MIT.html",
                "creator": {"@type": "Person", "name": "0xRadikal"},
                "distribution": [
                    {"@type": "DataDownload", "encodingFormat": "text/plain",
                     "contentUrl": f"{RAW}/verified/configs_base64.txt"},
                    {"@type": "DataDownload", "encodingFormat": "text/plain",
                     "contentUrl": f"{RAW}/verified/configs.txt"},
                    {"@type": "DataDownload", "encodingFormat": "application/yaml",
                     "contentUrl": f"{RAW}/verified/clash.yaml"},
                    {"@type": "DataDownload", "encodingFormat": "application/json",
                     "contentUrl": f"{RAW}/verified/singbox.json"},
                    {"@type": "DataDownload", "encodingFormat": "application/json",
                     "contentUrl": f"{RAW}/index.json"},
                ],
            },
            {
                "@type": "FAQPage",
                "inLanguage": lang,
                "mainEntity": [
                    {"@type": "Question", "name": q,
                     "acceptedAnswer": {"@type": "Answer", "text": a}}
                    for q, a in faq
                ],
            },
        ],
    }


def render(lang: str, template: str, strings: dict, hashes: dict) -> str:
    cfg = LANGS[lang]
    flat = _flatten(strings)
    build = {
        "lang": lang,
        "dir": cfg["dir"],
        "base": cfg["base"],
        "canonical": cfg["canonical"],
        "url_en": LANGS["en"]["canonical"],
        "url_fa": LANGS["fa"]["canonical"],
        "og_locale": cfg["og_locale"],
        "og_locale_alt": cfg["og_locale_alt"],
        "alt_href": cfg["alt_href"],
        "alt_lang": cfg["alt_lang"],
        "alt_label": cfg["alt_label"],
        "font_preload": cfg["font_preload"],
        "sister_href": cfg["sister_href"],
        "css_v": hashes["css"],
        "js_v": hashes["js"],
        "qr_v": hashes["qr"],
        "faq_html": _faq_html(strings["faq"]["items"]),
        "jsonld": _script_json(_jsonld(strings, lang, cfg["canonical"])),
        "i18n_json": _script_json({"lang": lang, "dir": cfg["dir"], **strings["js"]}),
    }
    missing = []

    def sub(m: re.Match) -> str:
        raw_key, esc_key = m.group(1), m.group(2)
        key = raw_key or esc_key
        if key.startswith("@"):
            val = build.get(key[1:])
        else:
            val = flat.get(key)
        if not isinstance(val, str):
            missing.append(key)
            return ""
        if raw_key is not None:
            if not key.startswith("@") and not key.endswith("_html"):
                raise SystemExit(f"build: raw insertion of non-_html key {key!r}")
            return val
        return html.escape(val, quote=True)

    out = _TOKEN.sub(sub, template)
    if missing:
        raise SystemExit(f"build[{lang}]: unresolved template keys: {sorted(set(missing))}")
    if "{{" in out or "}}" in out.replace("}}]}", ""):
        leftover = re.findall(r"\{\{.{0,40}", out)
        if leftover:
            raise SystemExit(f"build[{lang}]: leftover template syntax: {leftover[:3]}")
    return out


def _check_parity(en: dict, fa: dict) -> None:
    a, b = set(_flatten(en)), set(_flatten(fa))
    if a != b:
        raise SystemExit(f"build: en/fa key mismatch: only-en={sorted(a - b)} "
                         f"only-fa={sorted(b - a)}")
    if len(en["faq"]["items"]) != len(fa["faq"]["items"]):
        raise SystemExit("build: en/fa FAQ item count differs")
    for lang, s in (("en", en), ("fa", fa)):
        for key, val in _flatten(s["js"]).items():
            ref = _flatten(en["js"])[key]
            if set(re.findall(r"\{\w+\}", val)) != set(re.findall(r"\{\w+\}", ref)):
                raise SystemExit(f"build[{lang}]: placeholder mismatch in js.{key}")


def main(argv) -> int:
    check = "--check" in argv
    template = _read(os.path.join(HERE, "template.html"))
    strings = {lang: json.loads(_read(os.path.join(HERE, "i18n", f"{lang}.json")))
               for lang in LANGS}
    _check_parity(strings["en"], strings["fa"])
    hashes = {
        "css": _short_hash(os.path.join(DOCS, "styles.css")),
        "js": _short_hash(os.path.join(DOCS, "app.js")),
        "qr": _short_hash(os.path.join(DOCS, QR_VENDOR)),
    }
    stale = []
    for lang, cfg in LANGS.items():
        page = render(lang, template, strings[lang], hashes)
        path = os.path.join(DOCS, cfg["out"])
        if check:
            current = _read(path) if os.path.exists(path) else None
            if current != page:
                stale.append(cfg["out"])
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(page)
        print(f"build: docs/{cfg['out']}  {len(page.encode('utf-8')):,} B")
    if stale:
        print(f"build --check: stale, rebuild with `python3 docs-src/build.py`: {stale}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
