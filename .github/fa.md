<h1 align="center">Filter Checker</h1>

<p align="center"><a href="https://hits.sh/github.com/Plus98ir/Filter-Checker/"><img src="https://hits.sh/github.com/Plus98ir/Filter-Checker.svg?style=for-the-badge&label=views&color=2563eb" alt="Views"></a> <a href="https://corenetbase.com/#support"><img src="https://img.shields.io/badge/support-buy%20me%20a%20coffee-e11d2a?style=for-the-badge&logo=buymeacoffee&logoColor=white" alt="Support"></a></p>

<details>
<summary><b>☕ Support · حمایت</b> — USDT (TRC20) / TRX</summary>
<br>
<p align="center"><img src="https://raw.githubusercontent.com/Plus98ir/.github/main/tron-qr.png" width="200" alt="TRON address QR"></p>

```
TA53aFyGNfSAcrCaJi9QmA9x5W47nPJcf7
```

> [!WARNING]
> **TRON network only.** Sending from ERC20 / BEP20 will lose the funds.<br>
> **فقط شبکه‌ی TRON.** ارسال از ERC20 یا BEP20 پول را از بین می‌برد.

</details>

<div align="center">

[🇬🇧 English](https://github.com/Plus98ir/Filter-Checker) &nbsp;|&nbsp; **🇮🇷 فارسی**

</div>

<div dir="rtl">

مشخص می‌کند یک سایت فیلتر شده یا نه، و اگر شده، چطور. فقط Python 3.10 به بالا لازم دارد (بدون `pip install`).

</div>

```
python server.py               # رابط کاربری: http://127.0.0.1:8080
python server.py check x.com   # خروجی JSON در ترمینال
```

<div dir="rtl">

نسخه‌ی وب / PWA (روی گوشی نصب می‌شود): https://corenetbase.com/Filter-Checker/
مرورگر نمی‌تواند TCP/SNI را مستقیم تست کند؛ نسخه‌ی وب فقط می‌گوید سایت از همان دستگاه باز می‌شود یا نه، و اگر نه، مسدودی روی IP است یا روی اسم دامنه (DNS/SNI). برای تشخیص دقیق لایه، `server.py` را روی کامپیوتر اجرا کنید.

## چه چیزهایی تست می‌شود

| تست | چه کار می‌کند | نشانه‌ی فیلتر |
|------|----------------|-------------------|
| DNS  | جواب DNS سیستم با DoH (Cloudflare/Google/AdGuard روی IP) مقایسه می‌شود | IP `10.10.34.x` یا IP خصوصی، یا NXDOMAIN در سیستم ولی جواب درست در DoH |
| TCP  | اتصال به IP درست (از DoH) روی پورت ۴۴۳ | وصل نمی‌شود ← مسدودی IP |
| SNI  | هندشیک TLS با اسم سایت و با `www.example.com` روی همان IP | فقط با اسم سایت timeout/reset ← فیلتر SNI |
| TLS  | همان هندشیک‌ها | TCP وصل می‌شود ولی هندشیک با هر اسمی (حتی کنترل) شکست می‌خورد ← TLS روی آن IP مختل است |
| HTTP | درخواست GET روی پورت ۸۰، هم با DNS سیستم هم مستقیم روی IP | ریدایرکت / صفحه‌ی `peyvandha` |

## نتیجه‌ها

- `open`: سایت باز است
- `blocked`: فیلتر است (`reasons`: `dns`، `http`، `ip`، `sni`، `tls`)
  - `issues` در خروجی: هر اختلال با `layer` (کجا) و `how` (چطور: `timeout` = دور ریختن بسته، `reset` = تزریق RST، `eof` = قطع وسط هندشیک، `poison`، `blockpage`)
- `nxdomain`: دامنه وجود ندارد
- `unknown`: DoH هم جواب نداد و نتیجه قطعی نیست

## نکته‌ها

- با دوبار کلیک روی `server.py` پنجره‌ی cmd بسته می‌شود و سرور در پس‌زمینه می‌ماند؛ حدود ۱۵ ثانیه بعد از بستن تب (یا ۹۰ ثانیه بدون پینگ) خودش خاموش می‌شود. اگر از ترمینال اجرا شود، ترمینال باز می‌ماند و با Ctrl+C بسته می‌شود.
- اگر VPN یا پروکسی روشن باشد، نتیجه وضعیت VPN را نشان می‌دهد، نه اینترنت مستقیم را.
- DNSهای «تحریم‌شکن» (مثلاً gg-zone و شکن) IP پروکسی خودشان را می‌دهند؛ در رابط کاربری به‌صورت «متفاوت با DoH» نشان داده می‌شود.
- گواهی DoH اول بررسی می‌شود؛ اگر Python گواهی میانی را نداشت، بدون بررسی دوباره امتحان می‌کند (`"verified": false` در خروجی).

</div>
