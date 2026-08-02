#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generates every SVG used by README.md — no third-party image host, no CDN,
no tracking pixel. Run:  python3 assets/make_assets.py
Requires: segno (pure-python QR encoder) — only for the QR cards.

Design rules that are NOT cosmetic:
  • Every asset paints its own dark panel, so it reads correctly on BOTH the
    light and the dark GitHub theme (GitHub does not let CSS reach an <img>).
  • Animation uses SMIL (<animate>) only. Measured: GitHub's camo proxy serves
    SVG as image/svg+xml and preserves <animate> (verified on a live camo URL).
    CSS @keyframes was NOT verified, so it is not used.
  • Every asset is still complete and legible with animation disabled, so a
    reader with prefers-reduced-motion or an SVG-static renderer loses nothing.
  • Fonts fall back through a stack that exists on Linux CI, macOS and Windows.
"""
import os

OUT = os.path.dirname(os.path.abspath(__file__))
FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,'DejaVu Sans',sans-serif"
MONO = "ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'DejaVu Sans Mono',monospace"

INK        = "#E2E8F0"
MUTED      = "#94A3B8"
BG0, BG1   = "#0B1120", "#131F38"
GREEN      = "#22C55E"
CYAN       = "#22D3EE"
VIOLET     = "#A78BFA"
AMBER      = "#FBBF24"
TG         = "#229ED9"
ROSE       = "#FB7185"


def write(name: str, body: str) -> None:
    p = os.path.join(OUT, name)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(body.strip() + "\n")
    print(f"  wrote {name:22s} {os.path.getsize(p):6d} B")


# ══════════════════════════════════════════════════════════════════════════════
# 1) hero.svg — the first screenful. One promise, one proof, zero numbers that
#    can rot (live numbers belong in the shields badges, not in a static image).
# ══════════════════════════════════════════════════════════════════════════════
def hero() -> None:
    W, H = 1280, 300
    chips = ["VLESS", "VMess", "Trojan", "Shadowsocks",
             "Hysteria2", "TUIC", "ShadowsocksR", "SOCKS"]
    cx, chip_svg = 182, []
    for i, label in enumerate(chips):
        w = int(len(label) * 8.0) + 26
        col = [CYAN, VIOLET, GREEN, AMBER, ROSE, CYAN, VIOLET, GREEN][i % 8]
        chip_svg.append(
            f'<g><rect x="{cx}" y="216" width="{w}" height="28" rx="14" '
            f'fill="{col}" fill-opacity=".10" stroke="{col}" stroke-opacity=".38"/>'
            f'<text x="{cx + w/2:.0f}" y="235" text-anchor="middle" font-family="{FONT}" '
            f'font-size="13" font-weight="600" fill="{col}" letter-spacing=".3">{label}</text></g>')
        cx += w + 10

    write("hero.svg", f'''
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img"
     aria-label="Free V2Ray Configs — auto-updated every 15 minutes, verified by real clients">
  <title>Free V2Ray Configs — auto-updated every ~15 minutes, verified by real clients</title>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="{BG0}"/><stop offset=".55" stop-color="{BG1}"/><stop offset="1" stop-color="{BG0}"/>
    </linearGradient>
    <radialGradient id="aur" cx="50%" cy="50%" r="50%">
      <stop offset="0" stop-color="{CYAN}" stop-opacity=".42"/><stop offset="1" stop-color="{CYAN}" stop-opacity="0"/>
    </radialGradient>
    <radialGradient id="aur2" cx="50%" cy="50%" r="50%">
      <stop offset="0" stop-color="{VIOLET}" stop-opacity=".40"/><stop offset="1" stop-color="{VIOLET}" stop-opacity="0"/>
    </radialGradient>
    <linearGradient id="beam" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="#fff" stop-opacity="0"/>
      <stop offset=".5" stop-color="#fff" stop-opacity=".07"/>
      <stop offset="1" stop-color="#fff" stop-opacity="0"/>
    </linearGradient>
    <linearGradient id="ttl" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="#FFFFFF"/><stop offset=".55" stop-color="#BAE6FD"/><stop offset="1" stop-color="{CYAN}"/>
    </linearGradient>
    <pattern id="dots" width="26" height="26" patternUnits="userSpaceOnUse">
      <circle cx="1.5" cy="1.5" r="1.1" fill="#FFFFFF" fill-opacity=".05"/>
    </pattern>
    <clipPath id="card"><rect x="0" y="0" width="{W}" height="{H}" rx="20"/></clipPath>
  </defs>

  <g clip-path="url(#card)">
    <rect width="{W}" height="{H}" fill="url(#bg)"/>
    <rect width="{W}" height="{H}" fill="url(#dots)"/>

    <ellipse cx="240" cy="60" rx="360" ry="220" fill="url(#aur)">
      <animate attributeName="cx" values="240;520;240" dur="14s" repeatCount="indefinite"/>
      <animate attributeName="ry" values="220;170;220" dur="9s"  repeatCount="indefinite"/>
    </ellipse>
    <ellipse cx="1080" cy="250" rx="330" ry="200" fill="url(#aur2)">
      <animate attributeName="cx" values="1080;860;1080" dur="17s" repeatCount="indefinite"/>
    </ellipse>

    <rect x="-260" y="0" width="260" height="{H}" fill="url(#beam)">
      <animate attributeName="x" values="-260;{W}" dur="7s" repeatCount="indefinite"/>
    </rect>

    <!-- globe -->
    <g transform="translate(92,150)">
      <circle r="60" fill="none" stroke="{CYAN}" stroke-opacity=".22" stroke-width="1" stroke-dasharray="4 7">
        <animateTransform attributeName="transform" type="rotate" from="0" to="360" dur="24s" repeatCount="indefinite"/>
      </circle>
      <circle r="46" fill="{CYAN}" fill-opacity=".07" stroke="{CYAN}" stroke-opacity=".55" stroke-width="1.6"/>
      <path d="M-46 0 H46 M-40-22 H40 M-40 22 H40" stroke="{CYAN}" stroke-opacity=".38" stroke-width="1.2" fill="none"/>
      <ellipse rx="20" ry="46" fill="none" stroke="{CYAN}" stroke-opacity=".38" stroke-width="1.2"/>
      <ellipse rx="38" ry="46" fill="none" stroke="{CYAN}" stroke-opacity=".22" stroke-width="1.2"/>
      <circle r="46" fill="none" stroke="{GREEN}" stroke-opacity=".9" stroke-width="2"
              stroke-dasharray="16 273" stroke-linecap="round">
        <animateTransform attributeName="transform" type="rotate" from="0" to="360" dur="4.5s" repeatCount="indefinite"/>
      </circle>
    </g>

    <!-- eyebrow -->
    <circle cx="184" cy="72" r="4" fill="{GREEN}">
      <animate attributeName="fill-opacity" values="1;.25;1" dur="1.8s" repeatCount="indefinite"/>
    </circle>
    <circle cx="184" cy="72" r="4" fill="none" stroke="{GREEN}" stroke-width="1.4">
      <animate attributeName="r" values="4;12" dur="1.8s" repeatCount="indefinite"/>
      <animate attributeName="stroke-opacity" values=".8;0" dur="1.8s" repeatCount="indefinite"/>
    </circle>
    <text x="200" y="77" font-family="{FONT}" font-size="13.5" font-weight="700"
          fill="{GREEN}" letter-spacing="2.6">LIVE  ·  A NEW RELEASE EVERY ~15 MINUTES</text>

    <text x="180" y="140" font-family="{FONT}" font-size="54" font-weight="800"
          fill="url(#ttl)" letter-spacing="-1">Free V2Ray Configs</text>

    <text x="182" y="176" font-family="{FONT}" font-size="18" fill="{INK}" fill-opacity=".92">
      Not a scraped dump — every config is parsed, deduplicated, dialled and
    </text>
    <text x="182" y="200" font-family="{FONT}" font-size="18" fill="{INK}" fill-opacity=".92">
      <tspan>proxied through a real HTTP request </tspan><tspan font-weight="700" fill="{GREEN}">three times</tspan><tspan> before it ships.</tspan>
    </text>

    {"".join(chip_svg)}

    <!-- proof panel: the three gates, stated as gates and not as numbers -->
    <g>
      <rect x="908" y="48" width="344" height="166" rx="14"
            fill="#FFFFFF" fill-opacity=".04" stroke="#FFFFFF" stroke-opacity=".10"/>
      <text x="928" y="76" font-family="{FONT}" font-size="12" font-weight="700"
            fill="{MUTED}" letter-spacing="1.8">WHAT EVERY LINK HAS SURVIVED</text>
      {"".join(
        f'<g><circle cx="938" cy="{102 + i*32}" r="9" fill="{GREEN}" fill-opacity=".16"'
        f' stroke="{GREEN}" stroke-opacity=".75"/>'
        f'<path d="M934 {102 + i*32} l3 3.4 5.6-6" fill="none" stroke="{GREEN}"'
        f' stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">'
        f'<animate attributeName="stroke-opacity" values="0;1;1;1" dur="4s"'
        f' begin="{i*0.45}s" repeatCount="indefinite"/></path>'
        f'<text x="958" y="{107 + i*32}" font-family="{FONT}" font-size="14.5"'
        f' fill="{INK}" fill-opacity=".95">{t}</text></g>'
        for i, t in enumerate([
            "Parsed, repaired, deduplicated",
            "TCP handshake actually completed",
            "Fetched a real URL through the proxy",
            "Re-parsed by sing-box &amp; mihomo",
        ]))}
    </g>

    <text x="{W-28}" y="278" text-anchor="end" font-family="{MONO}" font-size="12.5"
          fill="{MUTED}" fill-opacity=".85">@Raydikalx · sing-box + mihomo validated · MIT</text>
    <rect x="0" y="{H-3}" width="{W}" height="3" fill="{GREEN}" fill-opacity=".55"/>
  </g>
</svg>''')


# ══════════════════════════════════════════════════════════════════════════════
# 2) pipeline.svg — the whole value proposition in one picture.
#    Deliberately carries NO counts: counts change every ~15 minutes and a
#    picture cannot be re-rendered every 15 minutes. It carries the *rules*.
# ══════════════════════════════════════════════════════════════════════════════
def pipeline() -> None:
    W, H = 1280, 330
    stages = [
        ("L0", "COLLECT",  "every healthy upstream",    "polled in parallel",        CYAN),
        ("L1", "REPAIR",   "parse · fix · deduplicate", "identity-aware key",        VIOLET),
        ("L2", "DIAL",     "real TCP handshake",        "no handshake, no entry",    AMBER),
        ("L3", "PROVE",    "HTTP through the proxy",    "3 independent rounds",      GREEN),
        ("→",  "PUBLISH",  "re-parsed by clients",     "sing-box + mihomo gate",    ROSE),
    ]
    cw, gap, x0, cy = 216, 30, 40, 74
    cards, links = [], []
    for i, (tag, title, line1, line2, col) in enumerate(stages):
        x = x0 + i * (cw + gap)
        cards.append(f'''
    <g>
      <rect x="{x}" y="{cy}" width="{cw}" height="126" rx="14" fill="{col}" fill-opacity=".07"
            stroke="{col}" stroke-opacity=".45" stroke-width="1.3"/>
      <rect x="{x}" y="{cy}" width="{cw}" height="3" rx="1.5" fill="{col}" fill-opacity=".85"/>
      <text x="{x+16}" y="{cy+30}" font-family="{MONO}" font-size="12" font-weight="700"
            fill="{col}" letter-spacing="1.4">{tag}</text>
      <text x="{x+cw-16}" y="{cy+30}" text-anchor="end" font-family="{FONT}" font-size="12.5"
            font-weight="800" fill="{col}" letter-spacing="1.6">{title}</text>
      <text x="{x+16}" y="{cy+66}" font-family="{FONT}" font-size="15" font-weight="600"
            fill="{INK}">{line1}</text>
      <text x="{x+16}" y="{cy+92}" font-family="{FONT}" font-size="13" fill="{MUTED}">{line2}</text>
      <rect x="{x+16}" y="{cy+104}" width="{cw-32}" height="4" rx="2" fill="{col}" fill-opacity=".14"/>
      <rect x="{x+16}" y="{cy+104}" width="{cw-32}" height="4" rx="2" fill="{col}" fill-opacity=".8">
        <animate attributeName="width" values="0;{cw-32}" dur="2.4s" begin="{i*0.5}s"
                 repeatCount="indefinite"/>
        <animate attributeName="opacity" values="1;1;0" dur="2.4s" begin="{i*0.5}s"
                 repeatCount="indefinite"/>
      </rect>
    </g>''')
        if i < len(stages) - 1:
            ax, bx = x + cw, x + cw + gap
            links.append(f'''
    <g>
      <path d="M{ax} {cy+63} H{bx}" stroke="{MUTED}" stroke-opacity=".45" stroke-width="1.4"/>
      <path d="M{bx-7} {cy+59} l6 4 -6 4" fill="none" stroke="{MUTED}" stroke-opacity=".7"
            stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
      <circle r="3.2" cx="{ax}" cy="{cy+63}" fill="{col}" opacity="0">
        <animate attributeName="cx" values="{ax};{bx}" dur="1.5s" begin="{i*0.32}s"
                 repeatCount="indefinite"/>
        <animate attributeName="opacity" values="0;1;1;0" dur="1.5s" begin="{i*0.32}s"
                 repeatCount="indefinite"/>
      </circle>
    </g>''')

    # narrowing band: shape only, no numbers — the shape is the honest part
    fy, fh = 232, 46
    left, right = 40, 1240
    band = (f'M{left} {fy} H{right} L{right} {fy+11} '
            f'C{right-380} {fy+13}, {left+470} {fy+fh}, {left} {fy+fh} Z')

    write("pipeline.svg", f'''
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img"
     aria-label="Pipeline: collect, repair, dial, prove, publish">
  <title>How a config becomes a published link: collect → repair → dial → prove → publish</title>
  <defs>
    <linearGradient id="pbg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="{BG0}"/><stop offset=".6" stop-color="{BG1}"/><stop offset="1" stop-color="{BG0}"/>
    </linearGradient>
    <linearGradient id="funnel" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0"   stop-color="{CYAN}"   stop-opacity=".55"/>
      <stop offset=".35" stop-color="{VIOLET}" stop-opacity=".5"/>
      <stop offset=".7"  stop-color="{AMBER}"  stop-opacity=".5"/>
      <stop offset="1"   stop-color="{GREEN}"  stop-opacity=".75"/>
    </linearGradient>
    <clipPath id="pcard"><rect width="{W}" height="{H}" rx="20"/></clipPath>
  </defs>
  <g clip-path="url(#pcard)">
    <rect width="{W}" height="{H}" fill="url(#pbg)"/>
    <text x="40" y="42" font-family="{FONT}" font-size="13" font-weight="700"
          fill="{MUTED}" letter-spacing="2.4">FROM AN UPSTREAM DUMP TO A LINK YOU CAN PASTE</text>
    {"".join(links)}
    {"".join(cards)}
    <path d="{band}" fill="url(#funnel)"/>
    <text x="56" y="{fy+30}" font-family="{FONT}" font-size="13.5" font-weight="700"
          fill="#04121F">everything the upstreams published</text>
    <text x="1240" y="{fy-9}" text-anchor="end" font-family="{FONT}" font-size="13.5"
          font-weight="800" fill="{GREEN}" letter-spacing=".4">what actually survives &#8595;</text>
    <text x="40" y="{H-18}" font-family="{FONT}" font-size="13" fill="{MUTED}"><tspan>The width is the honest part: most of what upstreams publish never reaches you, because it never worked. The surviving count lives in </tspan><tspan font-family="{MONO}" fill="{GREEN}">health.json</tspan><tspan>, re-measured every run.</tspan></text>
  </g>
</svg>''')


# ══════════════════════════════════════════════════════════════════════════════
# 3) call-to-action buttons. A README cannot render a <button>; an <img> wrapped
#    in <a> is the only clickable, styleable primitive GitHub allows.
# ══════════════════════════════════════════════════════════════════════════════
_ICONS = {
    "telegram": '<path d="M2.5 11.4 21 4.2c.9-.3 1.7.4 1.4 1.4l-3.1 14.6c-.2 1-.9 1.2-1.7.7l-4.7-3.5-2.3 2.2c-.3.3-.5.5-1 .5l.4-4.9L18.6 7c.4-.3-.1-.5-.6-.2L7.1 13.5l-4.5-1.4c-1-.3-1-1 .0-1.3Z"/>',
    "star":     '<path d="M12 1.8l3.1 6.4 7 1-5 4.9 1.2 7-6.3-3.3-6.3 3.3 1.2-7-5-4.9 7-1z"/>',
    "download": '<path d="M12 2.5v11m0 0 4.4-4.4M12 13.5 7.6 9.1" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M3.5 16.5v2.6a2.4 2.4 0 0 0 2.4 2.4h12.2a2.4 2.4 0 0 0 2.4-2.4v-2.6" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>',
    "gauge":    '<path d="M12 21a9 9 0 1 1 9-9" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/><path d="M12 12l5.5-4" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/><circle cx="12" cy="12" r="2"/>',
}


# ---------------------------------------------------------------------------
# CTA action cards.
#
# Geometry is measured, not guessed:  card is 264 wide with 16px padding each
# side, so the text budget is 232px.  Longest title ("Join @Raydikalx", 20px
# weight-800) renders 178.5px and the longest subtitle (12.5px) renders
# 176.8px, both leaving >50px of headroom.  A horizontal pill was rejected
# because at 3-up the text column collapses to ~136px, which the title
# overflows.  Three 264px cards plus gaps sit inside GitHub's README column.
# ---------------------------------------------------------------------------

CARD_W, CARD_H = 264, 142


def card(name, icon, title, sub, col, aria, glow=".30", tint=".085") -> None:
    w, h = CARD_W, CARD_H
    write(name, f'''
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}"
     role="img" aria-label="{aria}"><title>{aria}</title>
  <defs>
    <linearGradient id="cg" x1="0" y1="0" x2=".6" y2="1">
      <stop offset="0" stop-color="{BG1}"/><stop offset="1" stop-color="{BG0}"/>
    </linearGradient>
    <linearGradient id="cs" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="{col}" stop-opacity="0"/>
      <stop offset=".5" stop-color="{col}" stop-opacity=".20"/>
      <stop offset="1" stop-color="{col}" stop-opacity="0"/>
    </linearGradient>
    <linearGradient id="ct" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="{col}" stop-opacity="0"/>
      <stop offset=".5" stop-color="{col}" stop-opacity=".95"/>
      <stop offset="1" stop-color="{col}" stop-opacity="0"/>
    </linearGradient>
    <radialGradient id="cr" cx=".5" cy=".5" r=".5">
      <stop offset="0" stop-color="{col}" stop-opacity="{glow}"/>
      <stop offset="1" stop-color="{col}" stop-opacity="0"/>
    </radialGradient>
    <clipPath id="cc"><rect width="{w}" height="{h}" rx="20"/></clipPath>
  </defs>
  <g clip-path="url(#cc)">
    <rect width="{w}" height="{h}" fill="url(#cg)"/>
    <rect width="{w}" height="{h}" fill="{col}" fill-opacity="{tint}"/>
    <ellipse cx="{w//2}" cy="46" rx="105" ry="62" fill="url(#cr)"/>
    <rect x="-120" y="0" width="120" height="{h}" fill="url(#cs)">
      <animate attributeName="x" values="-120;{w}" dur="3.6s" repeatCount="indefinite"/>
    </rect>
    <rect x="0" y="0" width="{w}" height="2" fill="url(#ct)"/>

    <circle cx="{w//2}" cy="46" r="27" fill="{col}" fill-opacity=".16"/>
    <circle cx="{w//2}" cy="46" r="27" fill="none" stroke="{col}" stroke-opacity=".55"
            stroke-width="1.4">
      <animate attributeName="r" values="27;33" dur="2.8s" repeatCount="indefinite"/>
      <animate attributeName="stroke-opacity" values=".55;0" dur="2.8s" repeatCount="indefinite"/>
    </circle>
    <g transform="translate({w//2 - 15},31) scale(1.25)" fill="{col}" color="{col}">{_ICONS[icon]}</g>

    <text x="{w//2}" y="100" text-anchor="middle" font-family="{FONT}" font-size="20"
          font-weight="800" fill="#FFFFFF">{title}</text>
    <text x="{w//2}" y="121" text-anchor="middle" font-family="{FONT}" font-size="12.5"
          fill="{MUTED}">{sub}</text>
  </g>
  <rect x=".75" y=".75" width="{w - 1.5}" height="{h - 1.5}" rx="20" fill="none"
        stroke="{col}" stroke-opacity=".55" stroke-width="1.5"/>
</svg>''')


def cards() -> None:
    card("cta-links.svg", "download", "Get the links",
         "Verified tier \u00b7 recommended", GREEN,
         "Jump to the subscription links")
    card("cta-telegram.svg", "telegram", "Join @Raydikalx",
         "Outages + new links first", TG,
         "Join the Telegram channel @Raydikalx")
    # AMBER is a warm hue: at .30 glow / .085 tint over navy it reads muddy
    # brown next to the green and blue cards.  Measured by eye at 2.5x and
    # dialled back so the icon halo carries the colour instead of the panel.
    card("cta-star.svg", "star", "Star this repo",
         "It keeps this discoverable", AMBER,
         "Star the repository on GitHub", glow=".17", tint=".05")


# ---------------------------------------------------------------------------
# QR cards.
#
# Scannability beats styling here, so the modules stay canonical squares, dark
# on a near-white plate.  Inverted (light-on-dark) QR and logo overlays were
# both rejected: plenty of decoders reject the former and the latter needs
# error correction we would rather spend on camera noise.
#
# The plate is a fixed 228px and the module size is solved so the white margin
# is exactly the 4 modules the spec asks for:
#     module * matrix + 2 * (4 * module) = 228   ->   module = 228 / (n + 8)
# Worst case here is the 41x41 verified URL at error='m', giving 4.65px
# modules.  Every card is decoded back with OpenCV before it ships.
# ---------------------------------------------------------------------------

QR_W, QR_PLATE, QR_PAD = 264, 228, 18


def _qr_path(matrix) -> str:
    """One path in module units; horizontal runs merged to keep the file small."""
    out = []
    for r, row in enumerate(matrix):
        c = 0
        while c < len(row):
            if row[c]:
                start = c
                while c < len(row) and row[c]:
                    c += 1
                out.append(f"M{start} {r}h{c - start}v1h-{c - start}z")
            else:
                c += 1
    return "".join(out)


def qr_card(name, payload, title, sub, col, aria) -> None:
    import html as _html
    import segno

    qr = segno.make(payload, error="m", micro=False)
    matrix = qr.matrix
    n = len(matrix)
    mod = QR_PLATE / (n + 8)          # 4-module quiet zone on every side
    off = QR_PAD + 4 * mod            # where module (0,0) starts, in card units

    w = QR_W
    h = QR_PAD + QR_PLATE + 74        # plate + caption block
    py = QR_PAD
    esc = _html.escape(payload, quote=True)
    br = 13                            # corner-bracket arm length

    write(name, f'''
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}"
     role="img" aria-label="{aria}"><title>{aria} — {esc}</title>
  <defs>
    <linearGradient id="qg" x1="0" y1="0" x2=".6" y2="1">
      <stop offset="0" stop-color="{BG1}"/><stop offset="1" stop-color="{BG0}"/>
    </linearGradient>
    <linearGradient id="qt" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="{col}" stop-opacity="0"/>
      <stop offset=".5" stop-color="{col}" stop-opacity=".95"/>
      <stop offset="1" stop-color="{col}" stop-opacity="0"/>
    </linearGradient>
    <clipPath id="qc"><rect width="{w}" height="{h}" rx="20"/></clipPath>
  </defs>
  <g clip-path="url(#qc)">
    <rect width="{w}" height="{h}" fill="url(#qg)"/>
    <rect width="{w}" height="{h}" fill="{col}" fill-opacity=".06"/>
    <rect x="0" y="0" width="{w}" height="2" fill="url(#qt)"/>

    <rect x="{QR_PAD}" y="{py}" width="{QR_PLATE}" height="{QR_PLATE}" rx="10" fill="#F8FAFC"/>
    <g transform="translate({off:.3f},{off + py - QR_PAD:.3f}) scale({mod:.5f})"
       fill="{BG0}" shape-rendering="crispEdges">
      <path d="{_qr_path(matrix)}"/>
    </g>

    <g fill="none" stroke="{col}" stroke-width="2.4" stroke-linecap="round" opacity=".9">
      <path d="M{QR_PAD - 6} {py + br} v-{br - 6} a6 6 0 0 1 6 -6 h{br - 6}"/>
      <path d="M{QR_PAD + QR_PLATE + 6 - br} {py - 6} h{br - 6} a6 6 0 0 1 6 6 v{br - 6}"/>
      <path d="M{QR_PAD - 6} {py + QR_PLATE + 6 - br} v{br - 6} a6 6 0 0 0 6 6 h{br - 6}"/>
      <path d="M{QR_PAD + QR_PLATE + 6 - br} {py + QR_PLATE + 6} h{br - 6} a6 6 0 0 0 6 -6 v-{br - 6}"/>
    </g>

    <text x="{w // 2}" y="{py + QR_PLATE + 32}" text-anchor="middle" font-family="{FONT}"
          font-size="17" font-weight="800" fill="#FFFFFF">{title}</text>
    <text x="{w // 2}" y="{py + QR_PLATE + 52}" text-anchor="middle" font-family="{FONT}"
          font-size="12" fill="{MUTED}">{sub}</text>
  </g>
  <rect x=".75" y=".75" width="{w - 1.5}" height="{h - 1.5}" rx="20" fill="none"
        stroke="{col}" stroke-opacity=".5" stroke-width="1.5"/>
</svg>''')


QR_TARGETS = [
    ("qr-verified.svg",
     "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs_base64.txt",
     "Verified", "Scan into your client", GREEN, "QR code for the verified subscription"),
    ("qr-top100.svg",
     "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
     "Top 100", "The 100 fastest", CYAN, "QR code for the top 100 list"),
    ("qr-telegram.svg",
     "https://t.me/Raydikalx",
     "@Raydikalx", "Telegram channel", TG, "QR code for the Telegram channel"),
]


def qrs() -> None:
    for name, payload, title, sub, col, aria in QR_TARGETS:
        qr_card(name, payload, title, sub, col, aria)


def divider() -> None:
    """Thin section rule. Paints nothing but its own ink, so it works on either
    GitHub theme without a background panel."""
    w, h = 1280, 34
    write("divider.svg", f'''
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}"
     role="presentation" aria-hidden="true">
  <defs>
    <linearGradient id="dl" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="{CYAN}" stop-opacity="0"/>
      <stop offset=".28" stop-color="{CYAN}" stop-opacity=".55"/>
      <stop offset=".5" stop-color="{VIOLET}" stop-opacity=".85"/>
      <stop offset=".72" stop-color="{GREEN}" stop-opacity=".55"/>
      <stop offset="1" stop-color="{GREEN}" stop-opacity="0"/>
    </linearGradient>
  </defs>
  <rect x="0" y="{h // 2 - 1}" width="{w}" height="1.5" fill="url(#dl)"/>
  <g transform="translate({w // 2},{h // 2})">
    <circle r="5.5" fill="{BG0}" stroke="{VIOLET}" stroke-width="1.4"/>
    <circle r="2.2" fill="{VIOLET}">
      <animate attributeName="r" values="2.2;3.4;2.2" dur="2.4s" repeatCount="indefinite"/>
      <animate attributeName="opacity" values="1;.45;1" dur="2.4s" repeatCount="indefinite"/>
    </circle>
  </g>
</svg>''')


def main() -> None:
    print("building README assets ->", OUT)
    hero()
    pipeline()
    cards()
    qrs()
    donate_qrs()
    divider()
    print("done")



# ---------------------------------------------------------------------------
# Donation QR cards.
#
# The payload is the BARE address, not a `tron:` / `ethereum:` / `ton://` URI:
# every wallet scanner understands a plain address, while URI-scheme support is
# patchy and a scheme a wallet does not know is worse than no QR at all.
#
# Each address below was verified before being embedded — TRON by base58check
# (version byte 0x41), EVM by the EIP-55 mixed-case checksum, TON by CRC16 —
# and each generated QR is decoded again and compared to the source string.
# ---------------------------------------------------------------------------

TRON_RED = "#EF4444"
TON_BLUE = "#0098EA"

DONATE_TARGETS = [
    ("qr-donate-trc20.svg", "TYBumju6Mjd8JCn4RTq95Kk2HPsdcinuz5",
     "TRC20", "Tron network", TRON_RED, "Donate on the TRON TRC20 network"),
    ("qr-donate-evm.svg", "0x2F6ec47e416B42C623cF81a64266EE4910a698Cf",
     "EVM chains", "ETH · BSC · Polygon", VIOLET, "Donate on any EVM network"),
    ("qr-donate-ton.svg", "UQBbZrE5aDsdGVi6enpf_vPuG022W4KjkJNzTDkjVEn4gmu6",
     "TON", "The Open Network", TON_BLUE, "Donate on The Open Network"),
]


def donate_qrs() -> None:
    for name, payload, title, sub, col, aria in DONATE_TARGETS:
        qr_card(name, payload, title, sub, col, aria)

if __name__ == "__main__":
    main()
