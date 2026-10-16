# Filter-Checker — PLAN
_Updated 2026-10-16_

## Goal
Tell whether a website is filtered and exactly where the interference is (DNS, IP, SNI, TLS, HTTP), on PC and on phone.

## Architecture
- Full mode: `server.py` on the PC does the real network tests; the page is its UI.
- Web mode / PWA: same `index.html` on GitHub Pages, installable on phone; browser-only checks (open / blocked on IP / blocked on name).

## Decisions (Sadeq)
- Pages full-width, glass theme, FA + EN.
- No cmd window: server opens with the page and closes when the page closes.
- PWA lives on the main site (plus98ir.dpdns.org) so it can be installed and used live on the phone.
