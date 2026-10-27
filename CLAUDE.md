# Filter-Checker — CLAUDE.md
_Updated 2026-10-27_

Tool that checks whether a website is filtered (Iran) and on which layer: DNS, IP, SNI, TLS, HTTP. Repo: GitHub Plus98ir/Filter-Checker. Live PWA: https://plus98ir.dpdns.org/Filter-Checker/ (GitHub Pages, main branch root).

## Key facts
- `server.py` = full mode (Python stdlib only). Serves `index.html` + PWA files and `/api/check`, `/api/ping`, `/api/bye`.
- Hiddify panel check: `hiddify_targets(link)` in server.py reads https://host/<admin path>/api/v2/admin/domains-page/ with the admin UUID from the link as Hiddify-API-Key; POST /api/panel/targets ({kind: hiddify|xui, link, username, password}) is the only endpoint with a Host + JSON check (it uses an admin credential). Web mode hides the box (CORS: the browser can't call the panel).
- 3x-ui (Sanaei) panel check: `xui_targets(link, user, pass)` talks like CF-Clean-Scanner/xui_link.py: GET <base>/csrf-token (or the login page's csrf-token meta) -> X-CSRF-Token on every POST (newer panels answer 403 without it), same-origin headers, login form then JSON fallback (cookie), reads <base>/panel/api/inbounds/list (fallback POST panel/inbound/list) + panel/setting/all; base = link path before /panel or /login. Enabled inbounds only: REALITY serverNames = reality; link host, TLS serverName, ws/httpupgrade/xhttp/grpc host, tcp http Host, externalProxy dest, subURI/subDomain = panel. 2FA not supported. Errors carry the panel's own msg / HTTP code as `detail`. Remember stores link+user+pass in localStorage (fc_xui) only when ticked.
- `index.html` = one page for both modes: it calls `api/ping`; 204 → full mode (server.py), otherwise web mode (browser-only checks).
- Web mode can't do raw TCP/SNI: it uses DoH (1.1.1.1, 8.8.8.8, cloudflare-dns.com, dns.google) + `fetch(no-cors)` to https://domain, then to https://<real IP>. Browser can't tell "refused" from a cert error, so: IP timeout → "IP / TLS"; site timeout + IP fast → "DNS / SNI" (probable); both fast → "layer unclear". Verified 2026-10-16: twitter.com in a browser follows the redirect to x.com, so it can show blocked while server.py says open.
- Double-click on server.py: relaunches itself with pythonw (no cmd window) and exits ~15 s after the tab closes (heartbeat 10 s, idle 90 s). From a terminal it stays in the foreground.
- `sw.js` is network-first, same-origin only; never touches `/api/` or cross-origin test requests. Bump `CACHE` name when shell files change a lot.
- Cover for the projects page: `Filter-Checker.png` in repo root (picked up automatically). Repo homepage is set to the live URL so the card links there.
- Icons are rendered from `icon.svg` with headless Chrome (no PIL on this PC).

## Working rules (all projects)
- All script/CLI output in English; end-user pages bilingual FA + EN with a language switch, dark, modern, mobile-ready.
- HTML pages full-width (no narrow centered container with empty sides).
- Tools must be universal — never hard-code Sadeq's own servers into shipped code.
- Be smart: build, don't ask how. Ask only before destructive actions (deleting certs, data, users).
- Never bump a version number without asking.
- Don't send a README unless asked.
- Short on time/tokens — get it right the first time; test before handing over.

## The 4-file system
- **CLAUDE.md** — stable context + rules. Read first, every session.
- **PLAN.md** — goal, architecture, decisions, roadmap. Update when a decision changes.
- **TASKS.md** — live to-do list (Now / Next / Later / Blocked). Update every session.
- **ARCHIVE.md** — finished tasks + resolved gotchas, newest on top, dated. Move items here from TASKS.md when done.
