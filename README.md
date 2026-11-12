# Filter Checker

<div align="center">
<table><tr><td><b>🇺🇸 English</b></td><td><a href="https://github.com/Plus98ir/Filter-Checker/blob/main/README.fa.md">🇮🇷 فارسی</a></td></tr></table>
</div>

<a href="https://hits.sh/github.com/Plus98ir/Filter-Checker/"><img src="https://hits.sh/github.com/Plus98ir/Filter-Checker.svg?style=for-the-badge&label=views&color=2563eb" alt="Views"></a> <a href="https://corenetbase.com/#support"><img src="https://img.shields.io/badge/support-buy%20me%20a%20coffee-e11d2a?style=for-the-badge&logo=buymeacoffee&logoColor=white" alt="Support"></a>

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

Tells you whether a site is filtered, and how. Needs only Python 3.10+ (no `pip install`).

```
python server.py               # UI: http://127.0.0.1:8080
python server.py check x.com   # JSON result in the terminal
```

Web / PWA version (installs on a phone): https://corenetbase.com/Filter-Checker/
A browser cannot test TCP/SNI directly, so the web version only tells you whether the site opens from that device and, if not, whether the block is on the IP or on the domain name (DNS/SNI). For an exact answer per layer, run `server.py` on a PC.

## What is tested

| Test | What it does | Sign of a filter |
|------|--------------|------------------|
| DNS  | Compares the system DNS answer with DoH (Cloudflare/Google/AdGuard by IP) | IP `10.10.34.x` or private, or NXDOMAIN from the system but an answer from DoH |
| TCP  | Connects to the real IP (from DoH) on port 443 | No connection → IP block |
| SNI  | TLS handshake with the site name and with `www.example.com` on the same IP | Timeout/reset only with the site name → SNI filter |
| TLS  | The same handshakes | TCP connects but every handshake fails, even the control → TLS is broken on that IP |
| HTTP | GET on port 80, through the system DNS and straight to the IP | Redirect / the `peyvandha` block page |

## Results

- `open` – the site is open
- `blocked` – filtered (`reasons`: `dns`, `http`, `ip`, `sni`, `tls`)
  - `issues` in the output: each problem with its `layer` (where) and `how` (`timeout` = dropped, `reset` = injected RST, `eof` = cut during the handshake, `poison`, `blockpage`)
- `nxdomain` – the domain does not exist
- `unknown` – DoH did not answer either, so the result is not certain

## Notes

- Double-clicking `server.py` closes the cmd window and keeps the server in the background; it stops by itself ~15 seconds after the tab is closed (or after 90 seconds without a ping). Started from a terminal, the terminal stays open and Ctrl+C stops it.
- With a VPN or proxy on, the result shows the VPN's view, not your direct internet.
- "Anti-sanction" DNS services (e.g. gg-zone, Shecan) return the IP of their own proxy; the UI shows that as "different from DoH".
- The DoH certificate is verified first; if Python lacks an intermediate certificate it tries again without verification (`"verified": false` in the output).
