#!/usr/bin/env python3
"""Build Free-v2ray-Configs SVG artwork in the Raydikalx style.
Only standard Python libraries required for generating SVGs. Fixed QR matrices
are derived from exactly the URLs or wallet addresses listed under QR_TARGETS
and checked during QA. Includes the three donation QR cards.
"""
from pathlib import Path
from xml.sax.saxutils import escape
from base64 import b64encode

DIR=Path(__file__).resolve().parent
P="#2C78F8";BLUE="#247EFD";B2="#1969E9";B3="#1559CD";DARK="#103FAD"
WHITE="#EFF2F9";HI="#F7F9FD";ICE="#DAE5F9";MUTE="#C9DDFA";INK="#0E377F"
FONT="'Segoe UI',Inter,Arial,'DejaVu Sans',sans-serif"
MONO="Consolas,Menlo,'DejaVu Sans Mono',monospace"
QR_TARGETS={'qr-top100.svg': 'https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt', 'qr-verified.svg': 'https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs_base64.txt', 'qr-telegram.svg': 'https://t.me/Raydikalx', 'qr-donate-trc20.svg': 'TYBumju6Mjd8JCn4RTq95Kk2HPsdcinuz5', 'qr-donate-evm.svg': '0x4A0579eb11de7f80F719C9a4Df6CD39510400E02', 'qr-donate-ton.svg': 'UQBbZrE5aDsdGVi6enpf_vPuG022W4KjkJNzTDkjVEn4gmu6'}
DONATE_INFO={
  'qr-donate-trc20.svg':('TRC20','Tron network'),
  'qr-donate-evm.svg':('EVM','ETH · BNB · Polygon'),
  'qr-donate-ton.svg':('TON','The Open Network'),
}

# Reproducible QR matrices are embedded below by build setup. QR content itself never animates.
QR_MATRICES={'qr-top100.svg': ['1111111001011110010110011100101111111', '1000001001000101010000101001001000001', '1011101010110010100011010000101011101', '1011101011001001011000111110001011101', '1011101011100111010100110010101011101', '1000001011100000101010100111001000001', '1111111010101010101010101010101111111', '0000000010010101001011110001100000000', '1011111001010101110110111111001111100', '1111100011100001000111110000110100010', '0010111100001011101001100011101011111', '0110110001011001001111001010100000001', '0101101010100001010100111110111110111', '1111100010100010100111010100100100001', '1100111111111011100011100001101111011', '0101110000011110001111011011000110010', '1111111011010000001100101110011110110', '1011110101010101111101010000100001010', '0100001001000000001001100101101011111', '1001110011111000101001101000011100001', '0110011010010010000000101111011011100', '1000000101000110110110010010110001000', '0000001111100101110010101111101111001', '0100000000001001011101111010111110001', '0011111001011110100010101111011110110', '1000010011110011001100110011110100000', '1000111110100101111000100011111100011', '1001000010110011001001000011110110000', '1000101011101111010000110110111111110', '0000000010100000101111110011100011000', '1111111001011101001001000100101010111', '1000001011000001100111000010100011011', '1011101011101001001110001101111110101', '1011101010101001100101110001101010001', '1011101010001100001011100100100000011', '1000001001101010100001010011100011001', '1111111010000110010000011111011011111'], 'qr-verified.svg': ['11111110100101101110000100110010101111111', '10000010001011010101000001100001001000001', '10111010010010011001110100000111001011101', '10111010110011101111111011101000101011101', '10111010111001111110101100011000001011101', '10000010100100001101101011101111101000001', '11111110101010101010101010101010101111111', '00000000111111001111110010111100000000000', '10001011100010011101111000010101011111001', '00010101011111101010001100011110001111001', '00111011110110000000101101010100100110001', '01110000011101110101011000100101100011010', '01001010101010001101011010001000110000010', '01010001010101010001100000111100001110001', '00001110001111111000100001111010111010111', '01000101111001100110011010110111000101001', '10101110101011010101111110000101000100001', '11101101001110111010110101011010011110001', '00100110100000010100000100110010100101001', '10001101011001011110101000011101100101001', '11011110010110011011001011110111010111110', '01111101010000100100000001111000101111001', '00000111100000101010101110111100101011001', '00101000001010000100110010010111110101000', '11001011111101010100111110000100110001011', '11000101100111110000000101111000101110101', '00001111000000101000010110011000111010001', '00000101111001111101010110100101110011010', '01110110111110000101111000011100010000011', '10010001101110001111010011111110001110111', '00010011001110110011011111111110110110001', '00110101100110000111110100000110010010001', '11100011010100110100111000010101111111000', '00000000100110010110000100111011100011101', '11111110101101001010111111110111101011101', '10000010000011111000110111011101100011011', '10111010101110001001100011000111111111010', '10111010010110110110101110111010100100110', '10111010010100001100110100010010110001101', '10000010010100000100110110011110100101011', '11111110111000010011011100000111110110010'], 'qr-telegram.svg': ['1111111010011010001111111', '1000001001101000001000001', '1011101011110101001011101', '1011101001110110001011101', '1011101000001010001011101', '1000001010100100101000001', '1111111010101010101111111', '0000000001100010000000000', '1010001100101000000100101', '0111110011011001101001011', '1001101010100111000111101', '1010110011010010001101000', '1000001110110001101000001', '0001010000100101101100011', '1111101100010101100001101', '0000000101000001010111000', '1100001000011001111110010', '0000000011001111100010001', '1111111011001111101010001', '1000001001011001100010001', '1011101001000111111110001', '1011101000100101110010110', '1011101010110000010111011', '1000001001000100110110000', '1111111011011101101001001'], 'qr-donate-trc20.svg': ['11111110000010011010001111111', '10000010110101101110101000001', '10111010101101010001001011101', '10111010111110001111101011101', '10111010010110011000101011101', '10000010010100010110101000001', '11111110101010101010101111111', '00000000101100111010100000000', '10000010111000000000111001110', '01011001001111001111101111110', '01011110110101111010111011000', '00101100001111001010001001001', '01110110000101010100001001011', '11001001110000010001000011100', '11110110010100010010110011000', '10101000010000011010110111111', '00001010011010001100100000111', '10101101010111111001101110110', '11011010000110010011100101001', '10001101100111001000101001000', '10010010101100111100111111100', '00000000111100110011100011111', '11111110011000010000101011000', '10000010011100111011100010001', '10111010001001101001111110011', '10111010001011111010100001001', '10111010010110111110001110110', '10000010001010101001111111101', '11111110101111100101010100000'], 'qr-donate-evm.svg': ['11111110000011001111001111111', '10000010110000100110101000001', '10111010101110010000001011101', '10111010110011100111001011101', '10111010001000100101001011101', '10000010001010001010101000001', '11111110101010101010101111111', '00000000110100000000000000000', '10000010100011011100111001110', '01111100011100011011100110101', '01101110101010011010100111000', '00111001010110001001100010000', '11100110011111010011001000001', '00000100100110010001001010011', '11000111111000111000000110010', '11000001000010001011011010101', '00111010010111001000010101111', '10110101101010110010111011011', '11001110111011110101101100101', '10010000101100010010011010000', '10100011000101011100111111110', '00000000111010011011100011110', '11111110011101010101101011110', '10000010001010001010100010001', '10111010001111111011111110010', '10111010011111001000010000101', '10111010001010111100111111010', '10000010011001111011011111101', '11111110110111110000011110100'], 'qr-donate-ton.svg': ['111111100111011001011110001111111', '100000100011011111001010001000001', '101110101101010011111111001011101', '101110101101001110011010101011101', '101110101000000100100101001011101', '100000101110101111001010101000001', '111111101010101010101010101111111', '000000001101000100100100000000000', '101111100011001110001010101111100', '000110001100000110001000011100100', '010101101110100100100110101001110', '100110000011001000011110011001111', '110011100001100100100010010110101', '110110010100011110001011101000010', '011111100110110000110100110100010', '100000011100110010111111010001110', '010111101111001011010001110100110', '000110000001101001011111001000101', '011110101101010101000110001110010', '010011000111100001100111101101101', '111001111011101110001000110100001', '110110010101000100100111010001010', '101001111101110110001010000100010', '100101010011000100000100010001100', '101010111010011110001010111111000', '000000001110011000111101100010101', '111111100000001100100011101010010', '100000101010100100011101100011111', '101110101101001100110100111111101', '101110101011111110001100110010011', '101110101100010001010111100000000', '100000100101110010011110110111100', '111111101101010011110011101111110']}
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
    m=QR_MATRICES[name];n=len(m); side=204;unit=side/(n+8);ox=30+4*unit;oy=29+4*unit
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
    s=f'''<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="34" viewBox="0 0 1280 34" role="img" aria-label="Raydikalx decorative section separator"><title>Raydikalx section divider</title><desc>Fine electric blue divider with restrained traveling highlight.</desc><defs><linearGradient id="line"><stop stop-color="{BLUE}" stop-opacity="0"/><stop offset=".25" stop-color="{BLUE}" stop-opacity=".48"/><stop offset=".5" stop-color="{BLUE}" stop-opacity=".82"/><stop offset=".75" stop-color="{BLUE}" stop-opacity=".48"/><stop offset="1" stop-color="{BLUE}" stop-opacity="0"/></linearGradient></defs><path d="M34 17H1246" stroke="url(#line)" stroke-width="2"/><circle cx="640" cy="17" r="5" fill="{BLUE}"/><circle cx="640" cy="17" r="7" fill="none" stroke="{BLUE}" stroke-opacity=".35"><animate attributeName="r" values="7;13;7" dur="4s" repeatCount="indefinite"/><animate attributeName="stroke-opacity" values=".35;0;.35" dur="4s" repeatCount="indefinite"/></circle>{moving_dot(140,1140,17,12,'0s',2.6)}</svg>'''
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
