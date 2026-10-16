# Filter Checker

Tashkhis inke ye site filter shode ya na. Faghat Python 3.10+ lazem dare (bedune pip install).

```
python server.py               # UI: http://127.0.0.1:8080
python server.py check x.com   # khoruji JSON dar terminal
```

Neskhe-ye web / PWA (nasb ruye gushi): https://plus98ir.dpdns.org/Filter-Checker/
Browser test-e mostaghim-e TCP/SNI nemitune bokone; neskhe-ye web faghat mige site az hamun dastgah baz mishe ya na, va age na, block ruye IP e ya ruye esm-e domain (DNS/SNI). Baraye tashkhis-e daghigh-e laye, `server.py` ro ruye PC ejra kon.

## Che chizi test mishe

| Test | Chi kar mikone | Neshune-ye filter |
|------|----------------|-------------------|
| DNS  | Javab-e DNS-e system ba DoH (Cloudflare/Google/AdGuard ruye IP) moghayese mishe | IP `10.10.34.x` ya private, ya NXDOMAIN dar system vali javab dar DoH |
| TCP  | Etesal be IP-e dorost (az DoH) ruye port 443 | Vasl nemishe → IP block |
| SNI  | TLS handshake ba esm-e site va ba `www.example.com` ruye hamun IP | Faghat ba esm-e site timeout/reset → filter SNI |
| TLS  | Hamun handshake-ha | TCP vasl mishe vali handshake ba har esmi (hatta control) fail → TLS ruye IP mokhtal e |
| HTTP | GET ruye port 80, ham ba DNS-e system ham mostaghim ruye IP | Redirect/safhe-ye `peyvandha` |

## Natije-ha

- `open` – baz e
- `blocked` – filter e (`reasons`: `dns`, `http`, `ip`, `sni`, `tls`)
  - `issues` dar khoruji: har ekhtelal ba `layer` (koja) va `how` (chetor: `timeout` = drop, `reset` = tazrigh-e RST, `eof` = ghat vasat-e handshake, `poison`, `blockpage`)
- `nxdomain` – domain vojud nadare
- `unknown` – DoH ham javab nadad, natije ghat'i nist

## Nokte-ha

- Ba double-click ruye `server.py` panjere-ye cmd baste mishe va server dar background mimune; ~15 sanie bad az bastan-e tab (ya 90 sanie bedune ping) khodesh khamush mishe. Age az terminal ejra beshe, terminal baz mimune va ba Ctrl+C baste mishe.
- Age VPN ya proxy roshan e, natije vaziat-e VPN ro neshun mide, na internet-e mostaghim.
- DNS-haye "tahrim-shekan" (masalan gg-zone, shecan) IP-e proxy-e khodeshun ro midan; dar UI be soorat-e "motefavet ba DoH" neshun dade mishe.
- Certificate-e DoH aval verify mishe; age Python cert-e intermediate ro nadasht, bedune verify dobare emtehan mikone (`"verified": false` dar khoruji).
