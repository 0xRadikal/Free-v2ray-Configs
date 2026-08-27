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

⚠️ نقطهٔ کورِ **سنجیده‌شدهٔ** قاعدهٔ بالا، و پاسخِ فاز D
────────────────────────────────────────────────────────
معیارِ «صفر کانفیگ» افزونگی را نمی‌بیند. اندازه‌گیریِ زنده (۳۰ جولای ۲۰۲۶):
`mahdibland/Eternity.txt` با ۱۹۸ کانفیگ و `status: ok`، **زیرمجموعهٔ محضِ
۱۰۰.۰۰٪** از `mahdibland/sub/sub_merge.txt` است — هر دو از یک مخزنِ بالادست.
پس بازدهِ یکتایش صفر است ولی این قاعده هرگز رویش نمی‌افتد. همچنین
`barry-far/All_Configs_base64_Sub.txt` و `Epodonios/All_Configs_Sub.txt`
شباهتِ Jaccard = **۹۸.۳۳٪** دارند، و ۹ منبعِ `V2RAYCONFIGSPOOL` جمعاً فقط
**۵۶** کانفیگِ یکتا از **۸٬۰۴۳** (۰.۷٪) می‌دهند.

از این‌رو `state.py` سنجهٔ درست را دور به دور به یاد می‌آورد: **بازدهِ یکتا**،
نه «تعدادِ کانفیگ» و نه «HTTP 200». تصمیمِ حذف هم دیگر دستی نیست
(`disable_candidates()` با چهار شرطِ ایمنی).

⚠️ این عددِ زیر **دستی** نگه‌داشته می‌شود و قبلاً دریفت کرده بود (می‌گفت «۱۸»
در حالی که آن زمان ۲۱ منبع در لیست بود). حالا تستِ
`test_source_docstring_count_matches_the_actual_list` آن را قفل می‌کند، پس هر
افزودن/حذفِ منبع باید همین جمله را هم به‌روز کند.

نکتهٔ مهم برای نگهدارندهٔ بعدی: منبعی که **کامنت** شده در شمارش نمی‌آید، چون
`all_sources()` فقط عضوهای زندهٔ لیست‌ها را برمی‌گرداند. پس عددِ بالا همیشه
«تعدادِ منابعِ فعال» است، نه تعدادِ خطوطِ فایل.

آخرین اعتبارسنجی همهٔ URLهای زیر: ۲۷ آگوست ۲۰۲۶ (هر ۱۹ منبع HTTP 200 و
تعداد کانفیگ > ۰ برگرداندند).

بازنگریِ ۲۷ آگوست ۲۰۲۶ — بر پایهٔ آبشارِ واقعی، نه حدس
────────────────────────────────────────────────────────
چهار منبع کامنت شدند و دو منبع افزوده شد. روشِ تصمیم، عبور دادنِ هر منبع از
**همان** آبشارِ L0/L1 → L2 → L3×۳ (xray-knife v10.1.1) بود، و برای حذفِ رانشِ
شبکه همهٔ منابع در **یک** مجموعهٔ یکتا و همزمان سنجیده شدند (۷٬۶۲۳ خطِ باز).

اعتبارِ خودِ سنجه هم آزموده شد، نه فرض:
  • کنترلِ مثبت — ۶۰ کانفیگ از `verified/`  → ۴۱ پایدار (۶۸.۳٪)
  • کنترلِ منفی — ۶۰ کانفیگِ ردشدهٔ پروداکشن → ۰ پایدار (۰.۰٪)
  • این محیط از DE/FRA بیرون می‌رود و پروداکشن از US/ORD؛ پس روی ۹ بلابِ
    نقطه-در-زمانِ پروداکشن کالیبره شد: **ρ اسپیرمن = ۰.۹۵**، و برای هر سه
    مدافعِ این بازنگری نسبتِ سندباکس/پروداکشن ۱.۰۰–۱.۰۲x بود ⇒ اعداد قابلِ نقل.

معیارِ برنده «چند کانفیگ دارد» نبود، بلکه **ارزشِ حاشیه‌ای** بود: چند کانفیگِ
*پایدار* می‌دهد که هیچ منبعِ دیگری در پیکره ندارد. جزئیاتِ کاملِ هر اندازه‌گیری
در `docs/source-audit-20260827.md`.
"""
from __future__ import annotations
from typing import List

# ── سبک / با کیفیت (۵ منبع فعال) ──────────────────────────────────────────────
# نکته: چهار آدرس mci/sub_2..4 و mtn/sub_2..4 که قبلاً اینجا بودند حذف شدند؛
# همهٔ آن‌ها HTTP 200 با بدنهٔ صفر بایت برمی‌گرداندند (منبع مرده ولی نامرئی).
# سه منبعِ کامنت‌شدهٔ زیر عمداً پاک نشده‌اند: دلیلِ سنجیده‌شدهٔ کنارشان تنها
# جایی است که این اندازه‌گیری‌ها ثبت شده، و پاک‌کردنشان همان دانش را می‌سوزاند.
LIGHT_SOURCES: List[str] = [
    # ── غیرفعال ۲۰۲۶-۰۸-۲۷ (کامنت، نه حذف) ───────────────────────────────────
    # mahdibland/Eternity.txt — دو دلیلِ مستقلِ سنجیده‌شده:
    #   ۱) زیرمجموعهٔ محضِ ۱۰۰.۰۰٪ از `sub/sub_merge.txt` (همین docstring، بالا)
    #   ۲) `state.json` از پیش با ۸ دورِ پیاپیِ «۰ یکتا» auto-disable کرده بود
    # مسابقهٔ آبشارِ واقعی: ۷۲ پایدار از ۲۰۰ — ولی «پایدارِ تازه» = ۰ ⇒ سودِ
    # حاشیه‌ایِ صفر. کامنت می‌ماند تا تاریخ و دلیلش گم نشود.
    # "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt",
    #
    # peasoft/NoMoreWalls/list_raw.txt — مسابقهٔ آبشارِ واقعی: تنها **۲** کانفیگِ
    # پایدار از ۱۵۷ (۱.۲۷٪)، میانهٔ تأخیر ۹۵۱ms، و «پایدارِ تازه» = ۰.
    # نرخِ پروداکشن (کالیبره‌شده روی بلابِ نقطه-در-زمان) = ۰.۳۴٪ — یعنی این عدد
    # سوگیریِ سندباکس نیست: نسبتِ سندباکس/پروداکشن = ۱.۰۰x.
    # "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    #
    # جایگزینِ peasoft — whitedns-sub (بالاترین نرخِ پایداریِ کلِ میدان):
    # ۲۷۵ پایدار از ۴۰۵ خام (۶۷.۹٪)، میانهٔ ۱۳۷ms (سریع‌ترین)، ۸۱ کانفیگِ پایدارِ
    # یکتا که در `all/configs.txt` نبودند. در دورِ تأییدیِ مستقل ۲۶۴ تکرار شد.
    "https://raw.githubusercontent.com/iampedii/whitedns-sub/main/base64.txt",
    # جمع‌آور با اعتبارسنجی ساختاری
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    # ماهسانت (فقط sub_1 زنده است)
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mci/sub_1.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_1.txt",
    # منابع دستچین‌شدهٔ متوسط‌حجم
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
    # ── غیرفعال ۲۰۲۶-۰۸-۲۷ (کامنت، نه حذف) ───────────────────────────────────
    # w1770946466/Auto_proxy/Long_term_subscription_num — دلیلِ قاطع:
    # آخرین کامیتِ **همین مسیر** در بالادست `2024-03-20T18:13:17Z` است
    # (GitHub Commits API با until=cutoff) ⇒ ~۲.۴ سال کهنه.
    # مسابقهٔ آبشارِ واقعی: **۰** پایدار از ۵۶۰ خام؛ ۱۵۵ نقطهٔ پایانی در L2 باز
    # شد ولی هیچ‌کدام از L3 عبور نکرد. نرخِ پروداکشن هم ۰.۰۰٪ است ⇒ هم‌خوان.
    # جایگزینی برایش اضافه *نشد* (تصمیمِ مالک): PSG در مسابقه فقط ۱۶ پایدار از
    # ۳۱۵ (۵.۰۸٪) و تنها **+۱** کانفیگِ یکتا داد ⇒ ارزشِ حاشیه‌ای ناچیز.
    # "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription_num",
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
    # ── غیرفعال ۲۰۲۶-۰۸-۲۷ (کامنت، نه حذف) ───────────────────────────────────
    # mahdibland/sub/sub_merge.txt — مسابقهٔ آبشارِ واقعی: ۸۰ پایدار از ۴۰۱۹
    # (۱.۹۹٪). L2 هم ۳۱.۸۵٪ بود، یعنی حجمِ بالا اما کیفیتِ پایین.
    # vmess تنها ۰.۵۱٪ عبور داد (۵ از ۹۷۷). نرخِ پروداکشن ۲.۱۹٪ ⇒ نسبتِ
    # سندباکس/پروداکشن = ۱.۰۲x، پس این عدد قابلِ نقل است و سوگیری نیست.
    # "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    #
    # جایگزینِ sub_merge — Delta-Kronecker (بردِ قاطعِ دوئلِ HEAVY):
    # ۹۵۲ پایدار از ۶۲۹۷ خام (۱۵.۱۲٪) در برابر ۸۰ تای مدافع؛ L2 برابرِ ۹۱.۹۲٪
    # (بالاترینِ HEAVY). ۵۲۷ کانفیگِ پایدارِ یکتا که در `all/configs.txt` نبودند
    # ⇒ سودِ خالصِ تعویض +۵۱۸. فایلِ اصلی از کدِ خودِ بالادست تعیین شد:
    # `writer.go:192 writeFile(cfg.Output.MainFile, all)` + `main.go:106`.
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/all_configs.txt",
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
