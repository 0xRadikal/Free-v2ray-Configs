#!/usr/bin/env python3
"""Free-Telegram-Proxy sister-project banner: desktop (1280x300) + mobile (640x600).

It is the mirror image of the "Free V2Ray Configs" banner that Free-Telegram-Proxy
shows for this repository (assets/readme/promo-v2ray*.svg over there): the same
geometry, the same Raydikalx blue gradient, the same reduced-motion classes. Only the
icon (a Telegram paper plane instead of a globe) and the words differ.

No third-party dependency. Called from make_brand_assets.main(); also runnable alone:

    python3 assets/make_promo_proxy.py
"""
from pathlib import Path
from xml.sax.saxutils import escape

DIR = Path(__file__).resolve().parent
FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,'DejaVu Sans',sans-serif"
# Every pill names something the sister project really publishes: the MTProto lists
# and its faketls (ee), secure (dd) and classic tiers.
PILLS = ["MTProto", "FakeTLS · ee", "Secure · dd", "Classic"]
FILES = ("promo-proxy.svg", "promo-proxy-mobile.svg")

TITLE = "Free Telegram Proxy — the sister project"
DESC = ("Sister project by Raydikalx: free MTProto proxies for Telegram (FakeTLS ee, secure dd "
        "and classic), each verified in three rounds by relaying a real request to a Telegram "
        "datacenter, updated about every 15 minutes. Opens the GitHub repository.")

STYLE = ('<style>@media (prefers-reduced-motion: reduce){.rm0{opacity:0.5!important}'
         '.rm1{transform:none!important;opacity:0!important}.rm2{opacity:.9!important}.rm3{transform:none!important}}</style>')


def defs(w, h):
    return ('<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#247EFD" />'
            '<stop offset=".58" stop-color="#2076F0" /><stop offset="1" stop-color="#135CCF" /></linearGradient>'
            '<radialGradient id="cloud"><stop stop-color="#B4D8FF" stop-opacity=".24" />'
            '<stop offset="1" stop-color="#B4D8FF" stop-opacity="0" /></radialGradient>'
            '<linearGradient id="sweep"><stop stop-color="#fff" stop-opacity="0" />'
            '<stop offset=".5" stop-color="#fff" stop-opacity=".14" /><stop offset="1" stop-color="#fff" stop-opacity="0" />'
            '</linearGradient><linearGradient id="edge"><stop stop-color="#EFF2F9" stop-opacity=".12" />'
            '<stop offset=".45" stop-color="#EFF2F9" stop-opacity=".8" /><stop offset="1" stop-color="#EFF2F9" stop-opacity=".12" />'
            f'</linearGradient><clipPath id="round"><rect width="{w}" height="{h}" rx="22" /></clipPath></defs>')


def t(x, y, s, size, weight, fill="#EFF2F9", extra=""):
    return (f'<text x="{x}" y="{y}" font-family="{FONT}" font-size="{size}" font-weight="{weight}" '
            f'fill="{fill}"{extra}>{escape(s)}</text>')


def plane(cx, cy, r):
    """Telegram paper plane inside a ring, in the frosted tile the globe uses on the twin banner."""
    tile = r + 30
    sw = r / 16
    g = (f'<rect x="{cx - tile}" y="{cy - tile}" width="{2 * tile}" height="{2 * tile}" rx="{tile * 0.32:.0f}" '
         'fill="#EFF2F9" fill-opacity=".14" stroke="#EFF2F9" stroke-opacity=".35" />'
         f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#EFF2F9" stroke-width="{sw:.1f}" stroke-opacity=".7" />')
    # The plane outline of the CTA cards, centred on its own bounding box and scaled to the ring.
    k = r * 1.18 / 33
    pts = [(-17, 0), (16, -13), (9, 15), (1, 8), (-4, 15), (-4, 6)]
    px = lambda x: cx + (x + 0.5) * k   # noqa: E731
    py = lambda y: cy + (y - 1) * k     # noqa: E731
    d = "M" + " ".join(f"{px(x):.1f} {py(y):.1f}" for x, y in pts) + "Z"
    fold = f"M{px(-4):.1f} {py(6):.1f}L{px(16):.1f} {py(-13):.1f}"
    g += (f'<g fill="none" stroke="#EFF2F9" stroke-width="{sw:.1f}" stroke-linecap="round" stroke-linejoin="round">'
          f'<path d="{d}" fill="#EFF2F9" fill-opacity=".16" /><path d="{fold}" stroke-opacity=".7" /></g>')
    # Three relay nodes on the ring, one pulsing — the same rhythm as the globe's nodes.
    nodes = [(cx + r * 0.70, cy - r * 0.71), (cx - r * 0.98, cy + r * 0.2), (cx + r * 0.45, cy + r * 0.89)]
    for x, y in nodes:
        g += f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r / 7:.1f}" fill="#FFFFFF" stroke="#135CCF" stroke-width="{r / 22:.1f}" />'
    x, y = nodes[0]
    g += (f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r / 3.2:.1f}" fill="#FFFFFF" opacity=".9" class="rm2" fill-opacity=".35">'
          '<animate attributeName="opacity" values=".9;0;.9" dur="2.6s" repeatCount="indefinite" /></circle>')
    return g


def pills(x, y, h, size, gap, maxw=0):
    out, cx, row = "", x, 0
    for p in PILLS:
        w = round(len(p) * size * 0.64 + 2 * size)
        if maxw and cx + w > x + maxw:
            row += 1
            cx = x
        yy = y + row * (h + 12)
        out += (f'<rect x="{cx}" y="{yy}" width="{w}" height="{h}" rx="{h / 2:.0f}" fill="#EFF2F9" fill-opacity=".16" '
                'stroke="#EFF2F9" stroke-opacity=".38" />'
                + t(cx + w / 2, yy + h / 2 + size * 0.36, p, size, 700, "#FFFFFF", ' text-anchor="middle"'))
        cx += w + gap
    return out


def button(x, y, w, h, label, size):
    """Label left-aligned, arrow pinned to the right edge: no overlap whatever font the viewer has."""
    pad = round(size * 1.15)
    ax = x + w - pad - size * 0.9
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{h / 2:.0f}" fill="#FFFFFF" />'
            + t(x + pad, y + h / 2 + size * 0.36, label, size, 800, "#135CCF")
            + f'<g class="rm3"><path d="M{ax:.1f} {y + h / 2:.1f}h{size * 0.9:.1f}m-{size * 0.38:.1f}-{size * 0.38:.1f} '
              f'{size * 0.38:.1f} {size * 0.38:.1f}-{size * 0.38:.1f} {size * 0.38:.1f}" fill="none" stroke="#135CCF" '
              f'stroke-width="{size / 7:.1f}" stroke-linecap="round" stroke-linejoin="round" />'
              '<animateTransform attributeName="transform" type="translate" values="0 0;5 0;0 0" dur="1.8s" '
              'repeatCount="indefinite" /></g>')


def shell(w, h, body):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
            f'aria-label="{escape(TITLE)}">' + STYLE + f'<title>{escape(TITLE)}</title><desc>{escape(DESC)}</desc>'
            + defs(w, h)
            + f'<g clip-path="url(#round)"><rect width="{w}" height="{h}" fill="url(#bg)" />'
            + f'<circle cx="{w * 0.15:.0f}" cy="{h * 0.1:.0f}" r="{h * 0.75:.0f}" fill="url(#cloud)" opacity=".5" class="rm0">'
              '<animate attributeName="opacity" values=".34;.58;.34" dur="11s" repeatCount="indefinite" /></circle>'
            + f'<circle cx="{w * 0.93:.0f}" cy="{h * 0.85:.0f}" r="{h * 0.6:.0f}" fill="url(#cloud)" opacity=".4" />'
            + f'<g class="rm1" transform="translate(-400 0)"><rect x="0" y="0" width="260" height="{h}" fill="url(#sweep)" '
              f'transform="skewX(-18)" /><animateTransform attributeName="transform" type="translate" '
              f'values="-400 0;{w + 400} 0" dur="7s" repeatCount="indefinite" /></g>'
            + body
            + f'<rect x="1" y="1" width="{w - 2}" height="{h - 2}" rx="21" stroke="#EFF2F9" stroke-opacity=".30" fill="none" />'
            + f'<path d="M16 2H{w - 16}" stroke="url(#edge)" stroke-width="2" /></g></svg>\n')


def desktop():
    d = plane(170, 150, 74)
    d += t(320, 82, "RAYDIKALX · SISTER PROJECT", 15, 760, "#DBEBFF", ' letter-spacing="2.2"')
    d += t(318, 142, "Free Telegram Proxy", 54, 820)
    d += t(320, 182, "Free MTProto proxies — open in Telegram with one tap", 21, 560, "#DBEBFF")
    d += pills(320, 206, 36, 15, 10)
    d += button(960, 108, 290, 64, "Open on GitHub", 21)
    d += t(1105, 206, "Verified 3× · every ~15 min", 15, 600, "#DBEBFF", ' text-anchor="middle"')
    return shell(1280, 300, d)


def mobile():
    m = plane(320, 128, 62)
    m += t(320, 262, "RAYDIKALX · SISTER PROJECT", 22, 760, "#DBEBFF", ' text-anchor="middle" letter-spacing="2.4"')
    m += t(320, 322, "Free Telegram Proxy", 52, 820, "#EFF2F9", ' text-anchor="middle"')
    m += t(320, 364, "Proxies that open in Telegram", 26, 560, "#DBEBFF", ' text-anchor="middle"')
    m += pills(52, 390, 42, 20, 10, maxw=540)
    m += button(135, 506, 370, 66, "Open on GitHub", 25)
    return shell(640, 600, m)


def main():
    for name, body in zip(FILES, (desktop(), mobile())):
        (DIR / name).write_text(body, encoding="utf-8")
        print(f"  wrote {name:22s} {(DIR / name).stat().st_size:6d} B")


if __name__ == "__main__":
    main()
