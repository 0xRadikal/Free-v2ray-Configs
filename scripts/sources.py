# -*- coding: utf-8 -*-
"""
sources.py — منابع کانفیگ رایگان.

سه دسته (به ترتیب کیفیت نزولی):

  • LIGHT  — منابعی که **خودشان** کانفیگ‌ها را تست کرده‌اند یا دستچین‌شده‌اند.
             حجم کم، نرخ اتصال بالا. مناسب کاربری که فقط می‌خواهد «وصل شود».
  • HEAVY  — تجمیع‌کننده‌های انبوه. حجم بالا، تنوع زیاد، نرخ اتصال پایین‌تر.
  • ALL    — LIGHT + HEAVY بدون URL تکراری.

قاعدهٔ نگهداری این فایل
───────────────────────
هر URL پیش از افزودن **باید** با درخواست واقعی HTTP بررسی شود و تعداد
کانفیگ معتبرش شمرده شود. منبعی که چند دور پیاپی صفر کانفیگ برگرداند
باید حذف شود، نه اینکه در لیست بماند و هر ۵ دقیقه بودجهٔ شبکه بسوزاند.
وضعیت زندهٔ همهٔ منابع در `health.json` منتشر می‌شود.

آخرین اعتبارسنجی همهٔ URLهای زیر: ۲۸ جولای ۲۰۲۶ (هر ۱۸ منبع HTTP 200 و
تعداد کانفیگ > ۰ برگرداندند).
"""
from __future__ import annotations
from typing import List

# ── سبک / با کیفیت (۷ منبع) ───────────────────────────────────────────────────
# نکته: چهار آدرس mci/sub_2..4 و mtn/sub_2..4 که قبلاً اینجا بودند حذف شدند؛
# همهٔ آن‌ها HTTP 200 با بدنهٔ صفر بایت برمی‌گرداندند (منبع مرده ولی نامرئی).
LIGHT_SOURCES: List[str] = [
    # کانفیگ‌های تست‌شده با سرعت‌سنجی واقعی (بالاترین کیفیت موجود در گیت‌هاب)
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt",
    # لیست تست‌شدهٔ NoMoreWalls
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    # جمع‌آور با اعتبارسنجی ساختاری
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    # ماهسانت (فقط sub_1 زنده است)
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mci/sub_1.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_1.txt",
    # منابع دستچین‌شدهٔ متوسط‌حجم
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription_num",
]

# ── انبوه / حجم بالا (۱۴ منبع) ────────────────────────────────────────────────
HEAVY_SOURCES: List[str] = [
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_base64_Sub.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no1.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no2.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no3.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no4.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no5.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no6.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no7.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no8.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no9.txt",
    "https://raw.githubusercontent.com/ShadowException/VPN/refs/heads/main/configs/VPN-cat",
    # جایگزین‌های منبع مردهٔ MahsaNetConfigTopic/xray_final.txt (HTTP 404):
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
]


def all_sources() -> List[str]:
    """LIGHT + HEAVY بدون URL تکراری (ترتیب حفظ می‌شود)."""
    seen = set()
    out: List[str] = []
    for url in LIGHT_SOURCES + HEAVY_SOURCES:
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out
