"""Проверка Smart DNS-сервисов: что отдают для нейросетей и пускают ли сайты через их прокси.

python tools/probe_dns.py — таблица по всем кандидатам (запускать без VPN и туннелей, из России:
туннель перехватывает порт 53, и все серверы «отвечают» одинаково).

Адрес от сервиса сверяется с обычными DNS (CONTROL). Совпал — сервис сайт не подменяет, в таблице «напрямую»:
«ок 403» или «ок 200» в таком случае ничего не значат, человек идёт на сайт как без Smart DNS.
"""
import socket, struct, subprocess, sys

CANDIDATES = [
    ("Comss.one", "94.250.253.55"), ("Comss старый", "83.220.169.155"), ("Comss.one-2", "212.109.195.93"), ("Comss резерв", "195.133.25.16"),
    ("GeoHide-EU", "143.20.64.192"), ("GeoHide-EU-2", "45.13.237.213"), ("GeoHide-EU-3", "5.175.161.40"),
    ("MagicDNS", "109.120.177.170"), ("MagicDNS-2", "45.88.163.92"), ("Comss новый", "212.109.221.20"), ("Astracat", "135.106.217.200"),
    ("GeoHide RU", "159.194.200.33"), ("GeoHide RU-2", "193.233.112.67"),
    ("XyZ", "109.120.137.190"), ("Malw.link", "95.216.204.218"), ("DNS-AI", "194.87.196.13"), ("Mafioznik", "103.27.157.38"),
    ("Xbox DNS", "111.88.96.54"),
]
SITES = [("chatgpt.com", "https://chatgpt.com/"), ("claude.ai", "https://claude.ai/"),
         ("gemini.google.com", "https://gemini.google.com/app"), ("elevenlabs.io", "https://elevenlabs.io/"),
         ("grok.com", "https://grok.com/"), ("www.perplexity.ai", "https://www.perplexity.ai/")]
BLOCK = ("restrict", "unsupported", "unavailable", "not-available")
TRIES = 4   # сколько адресов из ответа сервиса пробуем, прежде чем писать «нет связи»
CONTROL = ("77.88.8.8", "8.8.8.8", "9.9.9.9")   # обычные DNS: Яндекс и Google отвечают как для России, Quad9 — как для заграницы


def query(name):
    q = struct.pack(">HHHHHH", 0x2a2a, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    return q + b"\x00" + struct.pack(">HH", 1, 1)


def skip(r, i):
    while True:
        if r[i] == 0: return i + 1
        if r[i] & 0xC0 == 0xC0: return i + 2
        i += r[i] + 1


def resolve_all(server, name):
    """Все адреса IPv4 из ответа; [] — адреса нет; None — сервер не ответил."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    try:
        s.sendto(query(name), (server, 53)); r = s.recv(4096)
    except OSError:
        return None
    finally:
        s.close()
    out = []
    try:
        if len(r) < 12 or r[:2] != b"\x2a\x2a" or not r[2] & 0x80: return None   # ответ не на наш запрос
        rcode = r[3] & 15
        if rcode == 3: return []           # такого имени нет
        if rcode != 0: return None         # сервер отказал
        qd, an = struct.unpack(">HH", r[4:8]); i = 12
        for _ in range(qd): i = skip(r, i) + 4
        for _ in range(an):
            i = skip(r, i)
            t, _, _, ln = struct.unpack(">HHIH", r[i:i + 10]); i += 10
            if t == 1 and ln == 4 and i + 4 <= len(r): out.append(socket.inet_ntoa(r[i:i + 4]))
            i += ln
    except (IndexError, struct.error):
        return out or None                 # ответ оборвался: что успели прочитать
    return out


def resolve(server, name):
    """Первый адрес; "" — адреса нет; None — сервер не ответил."""
    a = resolve_all(server, name)
    return None if a is None else (a[0] if a else "")


def real(name):
    """Настоящие адреса сайта: всё, что ответили обычные DNS."""
    found = set()
    for c in CONTROL: found.update(resolve_all(c, name) or [])
    return found


def is_real(ip, found):
    """Совпал с ответом обычного DNS или лежит с ним в одной сети /24 (у крупных сайтов адреса идут пачкой)."""
    net = ip.rsplit(".", 1)[0]
    return any(x.rsplit(".", 1)[0] == net for x in found)


def fetch(url, host, ip):
    out = subprocess.run(["curl.exe", "-s", "-o", "NUL", "--noproxy", "*", "-m", "12", "-A",
                          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128 Safari/537.36",
                          "--resolve", f"{host}:443:{ip}", "-w", "%{http_code} %{redirect_url}", url],
                         capture_output=True, text=True).stdout
    if out.startswith("000"): return "нет связи"
    if "/sorry/" in out: return "капча Google"
    if any(b in out for b in BLOCK): return "блок страны"
    return "ок " + out.split()[0]


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    REAL = {host: real(host) for host, _ in SITES}
    for host, found in REAL.items():
        if not found: print(f"! обычные DNS не ответили про {host}: «напрямую» для него определить нельзя", flush=True)
    for name, server in CANDIDATES:
        cells = []
        for host, url in SITES:
            ips = resolve_all(server, host)
            if ips is None: cells.append("DNS молчит"); continue
            if not ips or ips[0] == "0.0.0.0": cells.append("0.0.0.0"); continue
            # сервис отдаёт несколько адресов своих узлов, часть бывает мёртвой: как браузер, идём к следующему
            res, ip, dead = "нет связи", ips[0], 0
            for cand in ips[:TRIES]:
                r = fetch(url, host, cand)
                if r != "нет связи": res, ip = r, cand; break
                dead += 1
            if is_real(ip, REAL[host]) and res.startswith("ок"): res = "напрямую"
            cells.append(f"{res} ({ip}" + (f", до него молчали {dead}" if dead and res != "нет связи" else "") + ")")
        print(f"{name:12} {server:16} " + " | ".join(f"{h.split('.')[0]}: {c}" for (h, _), c in zip(SITES, cells)), flush=True)
