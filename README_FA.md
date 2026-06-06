# 🚀 کانفیگ‌های رایگان V2Ray — توسط [@Raydikalx](https://t.me/Raydikalx)

[![Aggregate](https://github.com/0xRadikal/Free-v2ray-Configs/actions/workflows/aggregate.yml/badge.svg)](https://github.com/0xRadikal/Free-v2ray-Configs/actions/workflows/aggregate.yml)
![Update](https://img.shields.io/badge/%D8%A8%D9%87%E2%80%8C%D8%B1%D9%88%D8%B2%D8%B1%D8%B3%D8%A7%D9%86%DB%8C-%D9%87%D8%B1%20%DB%B3%DB%B1%20%D8%AF%D9%82%DB%8C%D9%82%D9%87-blue)

> 🇬🇧 [English version](README.md)

کانفیگ‌های رایگان V2Ray / Xray که به‌صورت **خودکار** جمع‌آوری، **تکراری‌زدایی** و
**برندینگ** می‌شوند. از **۲۲ منبع** (۹ سبک + ۱۳ انبوه) گرفته می‌شوند، با موتورِ
تکراری‌زداییِ **CDN-aware** تمیز می‌شوند و **هر حدود ۳۱ دقیقه** از طریق GitHub Actions
به‌روزرسانی می‌شوند.

ریمارکِ همهٔ کانفیگ‌ها به این فرمت بازنویسی می‌شود: `{کد کشور} {پرچم} | @Raydikalx | {شماره}`

> ⚠️ هیچ تستِ اتصال (TCP) انجام نمی‌شود (به‌خاطر شرایط شبکهٔ ایران). کانفیگ‌های
> خراب فقط با قوانینِ ساختاری (UUID صفر / App not supported) حذف می‌شوند.

---

## 📥 اشتراک سریع (لینک را در کلاینت خود وارد کنید)

> از طریق **jsDelivr CDN** سرو می‌شود (سریع‌تر و پایدارتر — پیشنهادی).

### 🌐 همهٔ کانفیگ‌ها (سبک + انبوه)
| فرمت | لینک CDN |
|---|---|
| ساده (v2ray) | `https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/all/configs.txt` |
| **Base64** (اشتراک) | `https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/all/configs_base64.txt` |
| Clash YAML | `https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/all/clash.yaml` |
| Sing-box JSON | `https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/all/singbox.json` |

### ⭐ سبک (کیفیتِ بالا، حجم کمتر)
- ساده: `…@main/light/configs.txt`
- Base64: `…@main/light/configs_base64.txt`
- Clash: `…@main/light/clash.yaml` · Sing-box: `…@main/light/singbox.json`

### 📦 انبوه (حجمِ بالا، تنوعِ زیاد)
- ساده: `…@main/heavy/configs.txt`
- Base64: `…@main/heavy/configs_base64.txt`
- Clash: `…@main/heavy/clash.yaml` · Sing-box: `…@main/heavy/singbox.json`

### 🎯 بر اساس پروتکل (از دستهٔ ALL)
`vless` · `vmess` · `trojan` · `shadowsocks` · `hysteria2` · `hysteria` · `tuic` · `wireguard`

```
https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/protocols/vless.txt
https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/protocols/vless_base64.txt
… برای هر پروتکل به همین شکل
```

> لینکِ raw گیت‌هاب را ترجیح می‌دهید؟ پیشوند را با این جایگزین کنید:
> `https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/…`

---

## 🗂️ ساختار ریپازیتوری

```
all/        configs.txt · configs_base64.txt · clash.yaml · singbox.json   (سبک + انبوه)
heavy/      configs.txt · configs_base64.txt · clash.yaml · singbox.json   (۱۳ منبع انبوه)
light/      configs.txt · configs_base64.txt · clash.yaml · singbox.json   (۹ منبع سبک)
protocols/  vless.txt · vmess.txt · trojan.txt · … (+ *_base64.txt)         (تفکیک از ALL)
archive/    <دسته>_broken.txt · <دسته>_duplicates.txt (+ base64)           (کانفیگ‌های حذف‌شده)
index.json  متادیتای کامل: شمارش‌ها، زمان‌ها، تفکیک پروتکل، همهٔ لینک‌ها
scripts/    خط‌لولهٔ تجمیع (core.py · converters.py · sources.py · aggregate.py)
```

## 📊 متادیتای زنده — `index.json`

`https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/index.json`

شاملِ شمارشِ هر دسته (یکتا / تکراری / خراب)، تفکیکِ پروتکل، زمانِ آخرین به‌روزرسانی،
زمانِ تقریبیِ به‌روزرسانیِ بعدی، و آدرسِ همهٔ فایل‌ها (raw + CDN).

---

## ⚙️ چطور کار می‌کند

۱) **واکشی** — ۲۲ منبع به‌صورت هم‌زمان دانلود می‌شوند (تشخیصِ خودکارِ base64/direct).
۲) **تمیزسازی** — حذفِ خراب/جعلی (UUID صفر، `App not supported`، proxies خالی).
۳) **تکراری‌زدایی** — اثرانگشتِ هویتِ سرور به‌صورتِ CDN-aware (IPهای چرخانِ CDN merge می‌شوند).
۴) **برندینگ** — ریمارکِ هر کانفیگ به `{کد} {پرچم} | @Raydikalx | {شماره}` بازنویسی می‌شود.
۵) **تولید** — txt + base64 + Clash YAML + Sing-box JSON، تفکیکِ پروتکل، بایگانی، `index.json`.
۶) **انتشار** — GitHub Actions هر ۳۱ دقیقه نتایج را commit می‌کند؛ از طریق jsDelivr CDN سرو می‌شود.

## 🙌 منابع

با تشکر از همهٔ نگه‌دارندگانِ منابعِ بالادست. این ریپازیتوری صرفاً کانفیگ‌های
عمومیِ در دسترس را تجمیع و تمیزسازی می‌کند.

## 📜 سلب مسئولیت

برای اهدافِ آموزشی و پژوهشی. هیچ تضمینی برای کیفیت/در دسترس بودن وجود ندارد.

---

**کانال:** [@Raydikalx](https://t.me/Raydikalx) · **ربات:** [@RaydikalxBot](https://t.me/RaydikalxBot)
