# Filter-Checker — ARCHIVE
Newest on top. Move finished items here from TASKS.md.

## 2026-10-27 - Check a 3x-ui (Sanaei) panel
- Panel box now has a Hiddify / 3x-ui switch. 3x-ui: panel link + username + password -> server.py logs in and lists domains from enabled inbounds (REALITY SNIs, TLS SNI, CDN Host, external proxy, sub domain, panel host). Endpoint renamed /api/hiddify/targets -> /api/panel/targets. Tested against a mock 3x-ui server (login, wrong pass, wrong path, user:pass@ link, disabled inbound skipped) and headless Edge (page JS runs, box shows).

## 2026-10-22 - Check a Hiddify panel
- Full mode only (server.py): "Check a Hiddify panel" box under the domains list. Admin link -> POST /api/hiddify/targets (Host must be 127.0.0.1/localhost, JSON only) -> the panel's domains-page API -> list = panel domains (valid), REALITY SNIs (domain + servernames), fake SNIs (telegram/shadowtls/ssfaketls), filled into the domains box; the user presses Check (so the VPN, if needed for the panel, can be turned off first). Rows get a role tag and, when blocked, advice (e.g. change the REALITY SNI). Tested against a real 14.0.5 panel from Iran: www.paltalk.com (REALITY SNI) correctly reported as SNI-filtered, the rest open. Screenshots 2560 FA / 390 EN.

## 2026-10-16
- Mobile (<=640px): results table becomes one card per domain (domain + result on top, interference in a full-width box, details as a labelled 2-column grid); RTL alignment fixed for domain, IPs and the details label. Commit d21b2bd, live.
- Removed Claude co-author trailers: this repo (amended) and Smart-Caddy (last 4 commits rewritten, v1.6.1 tag moved, release kept). Claude attribution now off in ~/.claude/settings.json.
- Glass theme (dark + light), FA/EN switch (`?lang=fa|en`), full-width layout.
- PWA: manifest, service worker, icons (icon.svg → PNGs), install button + iOS hint; web mode with browser-only checks.
- "Interference" column: layer (DNS/IP/SNI/TLS/HTTP) + how (timeout, RST, mid-handshake drop, refused, poison, block page). TLS-on-IP case split out from the old "unreachable".
- No cmd window on double-click (relaunch with pythonw), auto-exit when the tab closes.
- Pushed to GitHub Plus98ir/Filter-Checker, GitHub Pages at plus98ir.dpdns.org/Filter-Checker/, cover Filter-Checker.png.
