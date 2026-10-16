"""
Filter Checker - tashkhis inke ye site filter shode ya na.

Ejra:
    python server.py              -> UI ruye http://127.0.0.1:8080
    python server.py check x.com  -> natije dar terminal (JSON)

Faghat az kitabkhane-ye estandard-e Python estefade mikone.
"""
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST, PORT = "127.0.0.1", 8080
TIMEOUT = 6
CONTROL_SNI = "www.example.com"

# IP-haye safhe-ye filtering (peyvandha) dar Iran
BLOCK_NETS = [ipaddress.ip_network("10.10.34.0/24")]
BLOCK_MARKERS = ("peyvandha", "10.10.34.34", "10.10.34.35", "10.10.34.36", "internet.ir/403")

# DoH ruye IP ta khod-e DNS-e system dar resolve dakhalat nakone
DOH_PROVIDERS = [
    ("Cloudflare", "https://1.1.1.1/dns-query?name={}&type=A", {"accept": "application/dns-json"}),
    ("Google", "https://8.8.8.8/resolve?name={}&type=A", {}),
    ("AdGuard", "https://94.140.14.14/resolve?name={}&type=A", {}),
    ("Cloudflare-2", "https://1.0.0.1/dns-query?name={}&type=A", {"accept": "application/dns-json"}),
]

ROOT = Path(__file__).parent
# File-haye app (PWA); faghat hamina serve mishan
STATIC = {
    "index.html": "text/html; charset=utf-8",
    "manifest.webmanifest": "application/manifest+json",
    "sw.js": "text/javascript; charset=utf-8",
    "icon.svg": "image/svg+xml",
    "icon-192.png": "image/png",
    "icon-512.png": "image/png",
    "icon-maskable-512.png": "image/png",
    "apple-touch-icon.png": "image/png",
}

# Vaghti panjere-ye cmd baste mishe, server ba baste shodan-e tab khamush mishe
IDLE_TIMEOUT = 90  # bishtar az 1 daghighe, chon browser timer-e tab-e background ro kond mikone
BYE_GRACE = 15     # bad az baste shodan-e tab; baraye refresh ya tab-e dige vaght mimune
last_seen = time.monotonic()


def normalize(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("empty domain")
    if "://" not in raw:
        raw = "http://" + raw
    host = urllib.parse.urlsplit(raw).hostname
    if not host:
        raise ValueError("invalid domain")
    return host.encode("idna").decode()


def classify_error(e: Exception) -> str:
    if isinstance(e, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(e, ConnectionResetError):
        return "reset"
    if isinstance(e, ConnectionRefusedError):
        return "refused"
    if isinstance(e, ssl.SSLError):
        if "EOF" in str(e) or "UNEXPECTED_EOF" in str(e):
            return "eof"
        return "tls-alert"
    if isinstance(e, socket.gaierror):
        return "nxdomain"
    return type(e).__name__


def is_bogus(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return (
        any(addr in net for net in BLOCK_NETS)
        or addr.is_private
        or addr.is_loopback
        or addr.is_unspecified
        or addr.is_reserved
        or addr.is_link_local
    )


def resolve_system(domain: str) -> dict:
    try:
        infos = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
        ips = sorted({i[4][0] for i in infos})
        return {"ok": True, "ips": ips, "bogus": [ip for ip in ips if is_bogus(ip)]}
    except Exception as e:
        return {"ok": False, "ips": [], "bogus": [], "error": classify_error(e)}


def _doh_query(url: str, headers: dict, verify: bool) -> dict:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=TIMEOUT, context=ctx) as r:
        return json.load(r)


def _doh_provider(domain: str, name: str, url: str, headers: dict) -> dict:
    url = url.format(urllib.parse.quote(domain))
    # Python ruye Windows gahi intermediate cert ro nadare; age verify fail shod bedune verify dobare
    for verify in (True, False):
        try:
            data = _doh_query(url, headers, verify)
            ips = sorted({a["data"] for a in data.get("Answer", []) if a.get("type") == 1})
            return {"ok": True, "provider": name, "verified": verify, "ips": ips,
                    "nxdomain": data.get("Status") == 3}
        except Exception as e:
            reason = getattr(e, "reason", e)
            if verify and isinstance(reason, ssl.SSLCertVerificationError):
                continue
            return {"ok": False, "error": f"{name}: {classify_error(reason)}"}


def resolve_doh(domain: str) -> dict:
    errors = []
    # Bedune "with" ta montazer-e provider-haye kond (filter shode) namunim
    pool = ThreadPoolExecutor(len(DOH_PROVIDERS))
    try:
        futures = [pool.submit(_doh_provider, domain, *p) for p in DOH_PROVIDERS]
        for f in as_completed(futures):
            r = f.result()
            if r["ok"]:
                return r
            errors.append(r["error"])
    finally:
        pool.shutdown(wait=False)
    return {"ok": False, "ips": [], "error": "; ".join(errors)}


def tcp_connect(ip: str, port: int = 443) -> dict:
    t = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT):
            return {"ok": True, "ms": round((time.perf_counter() - t) * 1000)}
    except Exception as e:
        return {"ok": False, "error": classify_error(e)}


def tls_handshake(ip: str, sni: str) -> dict:
    # Inja faghat dakhalat dar handshake ro check mikonim, na etebar-e certificate
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t = time.perf_counter()
    try:
        with socket.create_connection((ip, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                return {"ok": True, "ms": round((time.perf_counter() - t) * 1000), "version": tls.version()}
    except Exception as e:
        err = classify_error(e)
        # Alert az samt-e server yani handshake be server reside, pas dakhalat nist
        return {"ok": err == "tls-alert", "error": err}


def http_probe(domain: str, ip: str | None = None) -> dict:
    """GET http://domain/ - age ip bede, mostaghim be oon IP vasl mishe ba Host header."""
    try:
        conn = http.client.HTTPConnection(ip or domain, 80, timeout=TIMEOUT)
        conn.request("GET", "/", headers={"Host": domain, "User-Agent": "Mozilla/5.0"})
        resp = conn.getresponse()
        body = resp.read(65536).decode("utf-8", "ignore").lower()
        location = resp.getheader("Location", "") or ""
        conn.close()
        hay = body + " " + location.lower()
        return {
            "ok": True,
            "status": resp.status,
            "location": location,
            "blockpage": any(m in hay for m in BLOCK_MARKERS),
        }
    except Exception as e:
        return {"ok": False, "error": classify_error(e), "blockpage": False}


def check(raw_domain: str) -> dict:
    domain = normalize(raw_domain)
    started = time.perf_counter()

    with ThreadPoolExecutor(2) as pool:
        sys_f = pool.submit(resolve_system, domain)
        doh_f = pool.submit(resolve_doh, domain)
        dns_sys, dns_doh = sys_f.result(), doh_f.result()

    # IP-e "dorost": avval az DoH, age nashod az DNS-e system (faghat age salem bashe)
    trusted = [ip for ip in dns_doh["ips"] if not is_bogus(ip)] or [
        ip for ip in dns_sys["ips"] if not is_bogus(ip)
    ]
    trusted = trusted[:2]

    tcp, tls, tls_ctrl = {}, {}, {}
    with ThreadPoolExecutor(8) as pool:
        tcp_f = {ip: pool.submit(tcp_connect, ip) for ip in trusted}
        tls_f = {ip: pool.submit(tls_handshake, ip, domain) for ip in trusted}
        ctrl_f = {ip: pool.submit(tls_handshake, ip, CONTROL_SNI) for ip in trusted}
        http_sys_f = pool.submit(http_probe, domain)
        http_ip_f = pool.submit(http_probe, domain, trusted[0]) if trusted else None
        tcp = {ip: f.result() for ip, f in tcp_f.items()}
        tls = {ip: f.result() for ip, f in tls_f.items()}
        tls_ctrl = {ip: f.result() for ip, f in ctrl_f.items()}
        http_sys = http_sys_f.result()
        http_ip = http_ip_f.result() if http_ip_f else None

    # issues: dar kodum laye ekhtelal hast (layer) va be che shekl (how: timeout, reset, poison, ...)
    issues = []
    doh_has_answer = dns_doh["ok"] and dns_doh["ips"]
    if dns_sys["bogus"]:
        issues.append({"layer": "dns", "how": "poison", "detail": ", ".join(dns_sys["bogus"])})
    elif not dns_sys["ok"] and doh_has_answer:
        issues.append({"layer": "dns", "how": dns_sys["error"]})

    first_error = lambda results: next((r["error"] for r in results.values() if not r["ok"]), None)
    tcp_any = any(r["ok"] for r in tcp.values())
    tls_any = any(r["ok"] for r in tls.values())
    ctrl_any = any(r["ok"] for r in tls_ctrl.values())
    if trusted and not tcp_any:
        issues.append({"layer": "ip", "how": first_error(tcp)})
    elif trusted and not tls_any:
        # SNI-e control ham fail beshe yani kol-e TLS ruye in IP mokhtal e, na faghat esm-e site
        issues.append({"layer": "sni" if ctrl_any else "tls", "how": first_error(tls)})

    blockpage = next((h for h in (http_sys, http_ip) if h and h.get("blockpage")), None)
    if blockpage:
        issues.append({"layer": "http", "how": "blockpage", "detail": blockpage.get("location", "")})

    reasons = [i["layer"] for i in issues]
    if reasons:
        verdict = "blocked"
    elif not trusted:
        verdict = "nxdomain" if dns_doh.get("nxdomain") else "unknown"
    else:
        verdict = "open"

    return {
        "domain": domain,
        "verdict": verdict,
        "reasons": reasons,
        "issues": issues,
        "elapsed_ms": round((time.perf_counter() - started) * 1000),
        "dns": {"system": dns_sys, "doh": dns_doh},
        "trusted_ips": trusted,
        "tcp": tcp,
        "tls": tls,
        "tls_control": tls_ctrl,
        "http": {"system": http_sys, "direct_ip": http_ip},
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        global last_seen
        if urllib.parse.urlsplit(self.path).path == "/api/bye":
            last_seen = min(last_seen, time.monotonic() - IDLE_TIMEOUT + BYE_GRACE)
            self._send(204, b"", "text/plain")
        else:
            self._send(404, b"not found", "text/plain")

    def do_GET(self):
        global last_seen
        last_seen = time.monotonic()
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/api/ping":
            self._send(204, b"", "text/plain")
        elif (name := url.path.lstrip("/") or "index.html") in STATIC and (ROOT / name).exists():
            self._send(200, (ROOT / name).read_bytes(), STATIC[name])
        elif url.path == "/api/check":
            domain = urllib.parse.parse_qs(url.query).get("domain", [""])[0]
            try:
                result, code = check(domain), 200
            except ValueError as e:
                result, code = {"error": str(e)}, 400
            self._send(code, json.dumps(result).encode(), "application/json")
        else:
            self._send(404, b"not found", "text/plain")

    def log_message(self, fmt, *args):
        pass


def console_is_ours() -> bool:
    """True age panjere-ye cmd faghat male khod-e Python bashe (double-click), na terminal-e karbar."""
    if sys.platform != "win32":
        return False
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.windll.kernel32
    pids = (wintypes.DWORD * 16)()
    n = kernel32.GetConsoleProcessList(pids, 16)
    if not 0 < n <= 16:
        return False
    # Ba double-click py.exe (launcher) ham ruye hamun console e; age cmd/powershell bud, terminal-e karbar e
    for pid in pids[:n]:
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        buf, size = ctypes.create_unicode_buffer(260), wintypes.DWORD(260)
        ok = kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size))
        kernel32.CloseHandle(handle)
        if not ok or not re.fullmatch(r"py(thon[\d.]*)?w?\.exe", Path(buf.value).name, re.I):
            return False
    return True


def relaunch_hidden() -> bool:
    """Server ro ba pythonw (bedune panjere) dobare ejra mikone ta cmd baste beshe."""
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    if not pythonw.exists():
        return False
    subprocess.Popen(
        [str(pythonw), str(Path(__file__).resolve()), "--background"],
        creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
        close_fds=True,
    )
    return True


def exit_when_idle(server: ThreadingHTTPServer):
    while time.monotonic() - last_seen < IDLE_TIMEOUT:
        time.sleep(2)
    server.shutdown()


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "check":
        for d in sys.argv[2:]:
            print(json.dumps(check(d), indent=2, ensure_ascii=False))
        return
    background = "--background" in sys.argv
    if not background and console_is_ours() and relaunch_hidden():
        return
    if background:
        # pythonw stdout/stderr nadare; bedune in, khata-haye thread-ha crash mikonan
        sys.stdout = sys.stderr = open(os.devnull, "w")
    url = f"http://{HOST}:{PORT}"
    try:
        server = ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError:
        # Server az ghabl (bedune panjere) dare ejra mishe; faghat safhe ro baz kon
        webbrowser.open(url)
        return
    print(f"Filter Checker running at {url}  (Ctrl+C to quit)")
    webbrowser.open(url)
    if background:
        threading.Thread(target=exit_when_idle, args=(server,), daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
