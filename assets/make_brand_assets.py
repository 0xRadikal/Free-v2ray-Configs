#!/usr/bin/env python3
"""Build Free-v2ray-Configs SVG artwork in the Raydikalx style.
Requires segno (same as make_assets.py). QR payloads are read from
make_assets.py, so URLs and wallet addresses have a single source of truth. Includes the three donation QR cards.
"""
from pathlib import Path
from xml.sax.saxutils import escape
from base64 import b64encode

DIR=Path(__file__).resolve().parent
P="#2C78F8";BLUE="#247EFD";B2="#1969E9";B3="#1559CD";DARK="#103FAD"
WHITE="#EFF2F9";HI="#F7F9FD";ICE="#DAE5F9";MUTE="#C9DDFA";INK="#0E377F"
FONT="'Segoe UI',Inter,Arial,'DejaVu Sans',sans-serif"
MONO="Consolas,Menlo,'DejaVu Sans Mono',monospace"
# Payloads are NOT duplicated here: they come from make_assets.py (the one
# place a wallet address or URL is edited), so the two generators can never
# publish different addresses. QR matrices are encoded at build time with the
# same segno settings make_assets.py uses, never hardcoded.
import sys
sys.path.insert(0,str(DIR))
import make_assets as _upstream
QR_TARGETS={name:payload for name,payload,*_ in _upstream.QR_TARGETS+_upstream.DONATE_TARGETS}
assert set(QR_TARGETS)=={'qr-top100.svg','qr-verified.svg','qr-telegram.svg','qr-donate-trc20.svg','qr-donate-evm.svg','qr-donate-ton.svg'},sorted(QR_TARGETS)
DONATE_INFO={
  'qr-donate-trc20.svg':('TRC20','Tron network'),
  'qr-donate-evm.svg':('EVM','ETH · BSC · Polygon'),
  'qr-donate-ton.svg':('TON','The Open Network'),
}

# QR content itself never animates.
def qr_matrix(payload):
    import segno
    q=segno.make(payload,error='m',micro=False)
    return [''.join('1' if c else '0' for c in row) for row in q.matrix]
FILES={'hero.svg','pipeline.svg','cta-links.svg','cta-telegram.svg','cta-star.svg',
       'qr-top100.svg','qr-verified.svg','qr-telegram.svg','qr-donate-trc20.svg','qr-donate-evm.svg','qr-donate-ton.svg','divider.svg','social-preview.svg'}

def txt(x,y,s,size=18,w=600,color=WHITE,anchor='',space='',family=FONT):
    a=f' text-anchor="{anchor}"' if anchor else ''
    sp=f' letter-spacing="{space}"' if space else ''
    return f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" font-weight="{w}" fill="{color}"{a}{sp}>{escape(s)}</text>'

def shell(w,h,title,desc,rounded=24):
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-labelledby="title desc">
<title id="title">{escape(title)}</title><desc id="desc">{escape(desc)}</desc>
<defs><linearGradient id="blue" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{P}"/><stop offset=".53" stop-color="{BLUE}"/><stop offset="1" stop-color="{B3}"/></linearGradient>
<linearGradient id="stroke" x1="0" y1="0" x2="1" y2="0"><stop stop-color="{WHITE}" stop-opacity=".06"/><stop offset=".52" stop-color="{WHITE}" stop-opacity=".42"/><stop offset="1" stop-color="{WHITE}" stop-opacity=".08"/></linearGradient>
<radialGradient id="soft"><stop stop-color="{ICE}" stop-opacity=".14"/><stop offset="1" stop-color="{ICE}" stop-opacity="0"/></radialGradient>
<clipPath id="mask"><rect x="0" y="0" width="{w}" height="{h}" rx="{rounded}"/></clipPath></defs>
<g clip-path="url(#mask)"><rect x="0" y="0" width="{w}" height="{h}" fill="url(#blue)"/>
<circle cx="{int(w*.16)}" cy="0" r="{int(h*.85)}" fill="url(#soft)"/>
<circle cx="{int(w*.98)}" cy="{int(h*.95)}" r="{int(h*.68)}" fill="url(#soft)"/>
<rect x="1" y="1" width="{w-2}" height="{h-2}" rx="{rounded-1}" fill="none" stroke="url(#stroke)" stroke-width="1.5"/>
'''

def out(name,data):
    assert name in FILES
    (DIR/name).write_text(data+'</g></svg>\n',encoding='utf-8')

def logo_image(x,y,w,h):
    source=(DIR/'brand-mark-320.png').read_bytes()
    return f'<image x="{x}" y="{y}" width="{w}" height="{h}" preserveAspectRatio="xMidYMid meet" href="data:image/png;base64,{b64encode(source).decode()}"/>'

def moving_dot(x0,x1,y,sec,begin='0s',r=3):
    return f'<circle cx="{x0}" cy="{y}" r="{r}" fill="{HI}" opacity=".7"><animate attributeName="cx" values="{x0};{x1}" dur="{sec}s" begin="{begin}" repeatCount="indefinite"/><animate attributeName="opacity" values="0;1;0" dur="{sec}s" begin="{begin}" repeatCount="indefinite"/></circle>'

def hero():
    w,h=1280,300
    s=shell(w,h,'Raydikalx — Free V2Ray Configs','Open-source V2Ray subscriptions with real proxy testing and client validation')
    # Original 3D logo is never recreated. The framed blue square is centered precisely.
    s+='<rect x="39" y="36" width="224" height="228" rx="28" fill="white" fill-opacity=".09" stroke="white" stroke-opacity=".25"/>'
    s+=logo_image(48,48,206,206)
    s+='<circle cx="151" cy="151" r="124" stroke="'+ICE+'" stroke-width="1.4" stroke-opacity=".25" fill="none" stroke-dasharray="2 13"/>'
    s+='<circle cx="151" cy="27" r="4.1" fill="'+HI+'"><animateTransform attributeName="transform" type="rotate" from="0 151 151" to="360 151 151" dur="20s" repeatCount="indefinite"/></circle>'
    s+=txt(300,61,'RAYDIKALX  /  OPEN SOURCE',14,750,ICE,space='1.65')
    s+=txt(298,123,'Free V2Ray Configs',53,800,WHITE)
    s+=txt(301,161,'Verified, deduplicated, client-ready subscriptions.',18.5,510,ICE)
    s+=txt(301,191,'Real HTTP requests through the proxies — three rounds.',18,510,ICE)
    pills=[(301,120,'VERIFIED'),(433,115,'TOP 100'),(561,189,'REFRESH ~15 MIN')]
    for x,width,label in pills:
        s+=f'<rect x="{x}" y="219" width="{width}" height="38" rx="16" fill="{HI}" fill-opacity=".11" stroke="{HI}" stroke-opacity=".3"/>'
        s+=txt(x+width/2,243,label,12.4,780,WHITE,anchor='middle',space='.45')
    s+='<rect x="917" y="43" width="327" height="215" rx="22" fill="white" fill-opacity=".105" stroke="white" stroke-opacity=".25"/>'
    s+=txt(942,77,'HOW VERIFIED IS EARNED',13.8,790,WHITE,space='1.1')
    for i,line in enumerate(['Parse and deduplicate','Open a real TCP connection','Request HTTP through the proxy','Re-parse with supported clients']):
        y=110+i*34
        s+=f'<rect x="941" y="{y-14}" width="21" height="21" rx="7" fill="{ICE}" fill-opacity=".15" stroke="{HI}" stroke-opacity=".33"/>'
        s+=f'<path d="M947 {y-3}l4 4 6-8" stroke="{WHITE}" stroke-width="2" stroke-linecap="round" fill="none"/>'
        s+=txt(976,y,line,15,570,WHITE)
    s+='<path d="M941 237h278" stroke="'+HI+'" stroke-opacity=".16"/>'
    s+=txt(941,249,'Independent verification  ·  no guarantees',12.3,530,ICE)
    s+=moving_dot(941,1219,237,8,'0s',2.2)
    out('hero.svg',s)

def pipeline():
    w,h=1280,344
    s=shell(w,h,'V2Ray verification pipeline','Collect, normalize, dial, prove with three HTTP rounds, validate clients, publish')
    s+=txt(40,48,'THE VERIFICATION PIPELINE',13.8,790,ICE,space=1.8)
    s+=txt(40,92,'Proof before publication.',36,800,WHITE)
    steps=[('01','COLLECT','Healthy upstreams','Parallel ingestion'),('02','NORMALIZE','Parse and repair','Identity deduplication'),('03','DIAL','Real TCP handshake','Connectivity gate'),('04','PROVE','HTTP via proxy × 3','Independent rounds'),('05','PUBLISH','Client validation','Formats and lists')]
    cw=208; gap=40; y=127
    for i,(n,title,main,sub) in enumerate(steps):
        x=40+i*(cw+gap)
        s+=f'<rect x="{x}" y="{y}" width="{cw}" height="164" rx="20" fill="{WHITE}" fill-opacity=".11" stroke="{WHITE}" stroke-opacity=".28"/>'
        s+=f'<rect x="{x+16}" y="{y+16}" width="35" height="33" rx="11" fill="{HI}" fill-opacity=".15"/>'
        s+=txt(x+33.5,y+39,n,13,790,WHITE,anchor='middle')
        s+=txt(x+62,y+39,title,14.5,790,WHITE,space='.35')
        s+=txt(x+16,y+89,main,15,680,WHITE)
        s+=txt(x+16,y+116,sub,13.2,500,ICE)
        s+=f'<path d="M{x+16} {y+145}h176" stroke="{HI}" stroke-opacity=".2" stroke-width="3" stroke-linecap="round"/>'
        s+=moving_dot(x+17,x+191,y+145,4.2,f'{i*.6:.1f}s',2.7)
        if i<4:
            a=x+cw+5; z=x+cw+gap-5; yy=y+80
            s+=f'<path d="M{a} {yy}h{z-a}m-6 -5 6 5 -6 5" fill="none" stroke="{ICE}" stroke-opacity=".75" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'
    s+=txt(40,327,'Measured from the test runner; reachability varies by network and time.',14.3,545,ICE)
    out('pipeline.svg',s)

ICONS={
  'link': f'<path d="M-17 -2v-8h13M4 -16h12v12M-17 8v8h13M4 16h12V4" stroke="{WHITE}" stroke-width="2.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/><path d="M-8 0h17m-5-5 5 5-5 5" stroke="{WHITE}" stroke-width="2.5" fill="none" stroke-linecap="round"/>',
  'telegram': f'<path d="M-18 -3 18-16c3-1 5 1 4 4l-6 29c-.5 3-3 4-6 2L2 12l-8 7-1-11 20-19L-11 4-18 1c-3-1-3-3 0-4z" fill="none" stroke="{WHITE}" stroke-width="2.1" stroke-linejoin="round"/>',
  'star': f'<path d="M0 -19 5.8 -6 20 -4l-10 10 2 14L0 13l-12 7 2-14-10-10 14.2-2Z" fill="none" stroke="{WHITE}" stroke-width="2.5" stroke-linejoin="round"/>',
}
def cta(name,title,subtitle,icon):
    w,h=264,142
    s=shell(w,h,title,subtitle,20)
    s+='<rect x="17" y="17" width="55" height="55" rx="17" fill="white" fill-opacity=".14" stroke="white" stroke-opacity=".28"/>'
    s+=f'<g transform="translate(44.5 44.5)">{ICONS[icon]}</g>'
    s+=txt(90,36,'RAYDIKALX',11.5,790,ICE,space=1.2)
    s+=txt(90,57,'QUICK ACCESS',11,580,ICE)
    s+=txt(20,101,title,20.5,780,WHITE)
    s+=txt(20,124,subtitle,12.8,545,ICE)
    s+=f'<path d="M18 133H245" stroke="{HI}" stroke-opacity=".25"/>'
    s+=moving_dot(18,245,133,6.8,'0s',2.2)
    out(name,s)

def qr(name,title,subtitle):
    w,h=264,320
    s=shell(w,h,title+' scannable QR',QR_TARGETS[name],20)
    s+=f'<rect x="15" y="14" width="234" height="234" rx="13" fill="{HI}"/>'
    m=qr_matrix(QR_TARGETS[name]);n=len(m); side=204;unit=side/(n+8);ox=30+4*unit;oy=29+4*unit
    parts=[]
    for j,row in enumerate(m):
        for i,b in enumerate(row):
            if b=='1':parts.append(f'M{ox+i*unit:.4f},{oy+j*unit:.4f}h{unit+.012:.4f}v{unit+.012:.4f}h-{unit+.012:.4f}Z')
    s+=f'<path d="{"".join(parts)}" fill="{INK}" shape-rendering="crispEdges"/>'
    s+=txt(132,279,title,20.5,790,WHITE,anchor='middle')
    s+=txt(132,302,subtitle,13.6,555,ICE,anchor='middle')
    # Animation is separate from QR matrix & quiet-zone to preserve scannability.
    s+=f'<path d="M20 312H244" stroke="{ICE}" stroke-opacity=".24" stroke-width="1.15"/>'
    s+=moving_dot(20,244,312,7.2,'0s',2)
    out(name,s)


def donate(name):
    title,subtitle=DONATE_INFO[name]
    qr(name,title,subtitle)

def divider():
    s=f'''<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="34" viewBox="0 0 1280 34" role="presentation" aria-hidden="true"><defs><linearGradient id="line"><stop stop-color="{BLUE}" stop-opacity="0"/><stop offset=".25" stop-color="{BLUE}" stop-opacity=".48"/><stop offset=".5" stop-color="{BLUE}" stop-opacity=".82"/><stop offset=".75" stop-color="{BLUE}" stop-opacity=".48"/><stop offset="1" stop-color="{BLUE}" stop-opacity="0"/></linearGradient></defs><path d="M34 17H1246" stroke="url(#line)" stroke-width="2"/><circle cx="640" cy="17" r="5" fill="{BLUE}"/><circle cx="640" cy="17" r="7" fill="none" stroke="{BLUE}" stroke-opacity=".35"><animate attributeName="r" values="7;13;7" dur="4s" repeatCount="indefinite"/><animate attributeName="stroke-opacity" values=".35;0;.35" dur="4s" repeatCount="indefinite"/></circle>{moving_dot(140,1140,17,12,'0s',2.6)}</svg>'''
    (DIR/'divider.svg').write_text(s+'\n',encoding='utf-8')

def social():
    w,h=1280,640
    s=shell(w,h,'Free V2Ray Configs social preview','Raydikalx official blue and white repository social sharing art')
    s+='<rect x="0" y="0" width="1280" height="7" fill="'+HI+'" fill-opacity=".44"/>'
    s+='<rect x="58" y="58" width="198" height="198" rx="27" fill="white" fill-opacity=".1" stroke="white" stroke-opacity=".25"/>'
    s+=logo_image(69,69,176,176)
    s+=txt(291,90,'RAYDIKALX  /  OPEN SOURCE',18,785,ICE,space=2)
    s+=txt(287,170,'Free V2Ray Configs',73,800,WHITE)
    s+=txt(290,218,'A verified open-source subscription, rebuilt frequently.',25,540,ICE)
    s+=txt(290,258,'VLESS · VMess · Trojan · Shadowsocks · Hysteria2',19,560,ICE)
    s+=txt(60,343,'PROOF-DRIVEN PIPELINE',14.5,795,ICE,space=1.6)
    stages=[('01','PARSE','Normalize formats'),('02','DEDUP','Unique endpoints'),('03','DIAL','TCP handshake'),('04','PROVE','Real HTTP × 3'),('05','CHECK','Client validation')]
    for i,(number,title,sub) in enumerate(stages):
        x=60+i*242
        s+=f'<rect x="{x}" y="367" width="215" height="116" rx="19" fill="white" fill-opacity=".12" stroke="white" stroke-opacity=".27"/>'
        s+=txt(x+17,397,number,14,770,ICE)
        s+=txt(x+17,430,title,23,790,WHITE)
        s+=txt(x+17,461,sub,14.6,575,ICE)
    s+='<rect x="190" y="519" width="900" height="74" rx="26" fill="white" fill-opacity=".115" stroke="white" stroke-opacity=".3"/>'
    s+=txt(640,566,'github.com/0xRadikal/Free-v2ray-Configs',29,670,WHITE,anchor='middle',family=MONO)
    s+=f'<circle cx="1168" cy="60" r="5" fill="{ICE}"><animate attributeName="opacity" values=".35;.85;.35" dur="4s" repeatCount="indefinite"/></circle>'
    out('social-preview.svg',s)

def main():
    hero();pipeline()
    cta('cta-links.svg','Get the links','Verified tier · recommended','link')
    cta('cta-telegram.svg','Join @Raydikalx','Updates & new connections','telegram')
    cta('cta-star.svg','Star this repo','Support open source','star')
    qr('qr-top100.svg','Top 100','Fastest verified links')
    qr('qr-verified.svg','Verified','Scan with your client')
    qr('qr-telegram.svg','@Raydikalx','Telegram channel')
    donate('qr-donate-trc20.svg')
    donate('qr-donate-evm.svg')
    donate('qr-donate-ton.svg')
    divider();social()
    assert {p.name for p in DIR.glob('*.svg')}==FILES,'Extra/missing SVG outputs'
    print(f'Generated {len(FILES)} SVG files, including donation cards.')

if __name__=='__main__': main()
