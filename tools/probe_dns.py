"""Проверка Smart DNS-сервисов: что отдают для нейросетей и пускают ли сайты через их прокси.

python tools/probe_dns.py — таблица по всем кандидатам (запускать без VPN и туннелей, из России:
туннель перехватывает порт 53, и все серверы «отвечают» одинаково).
"""
import socket, struct, subprocess, sys

CANDIDATES = [
    ("Comss.one", "94.250.253.55"), ("Comss старый", "83.220.169.155"), ("Comss.one-2", "212.109.195.93"), ("Comss резерв", "195.133.25.16"),
    ("GeoHide-EU", "143.20.64.192"), ("GeoHide-EU-2", "45.13.237.213"), ("GeoHide-EU-3", "5.175.161.40"),
    ("MagicDNS", "109.120.132.43"), ("MagicDNS-2", "94.249.177.102"), ("Astracat", "135.106.217.200"),
    ("GeoHide RU", "159.194.200.33"), ("GeoHide RU-2", "193.233.112.67"),
    ("XyZ", "109.120.137.190"), ("Malw.link", "95.216.204.218"), ("DNS-AI", "194.87.196.13"), ("Mafioznik", "103.27.157.38"),
    ("Xbox DNS", "111.88.96.54"),
]
SITES = [("chatgpt.com", "https://chatgpt.com/"), ("claude.ai", "https://claude.ai/"),
         ("gemini.google.com", "https://gemini.google.com/app"), ("elevenlabs.io", "https://elevenlabs.io/"),
         ("grok.com", "https://grok.com/"), ("www.perplexity.ai", "https://www.perplexity.ai/")]
BLOCK = ("restrict", "unsupported", "unavailable", "not-available")


def query(name):
    q = struct.pack(">HHHHHH", 0x2a2a, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    return q + b"\x00" + struct.pack(">HH", 1, 1)


def resolve(server, name):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    try:
        s.sendto(query(name), (server, 53)); r = s.recv(4096)
    except OSError:
        return None
    qd, an = struct.unpack(">HH", r[4:8]); i = 12
    for _ in range(qd):
        while r[i]: i += r[i] + 1
        i += 5
    for _ in range(an):
        if r[i] & 0xC0 == 0xC0: i += 2
        else:
            while r[i]: i += r[i] + 1
            i += 1
        t, _, _, ln = struct.unpack(">HHIH", r[i:i + 10]); i += 10
        if t == 1: return socket.inet_ntoa(r[i:i + 4])
        i += ln
    return ""


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
    for name, server in CANDIDATES:
        cells = []
        for host, url in SITES:
            ip = resolve(server, host)
            if ip is None: cells.append("DNS молчит"); continue
            if ip in ("", "0.0.0.0"): cells.append("0.0.0.0"); continue
            cells.append(f"{fetch(url, host, ip)} ({ip})")
        print(f"{name:12} {server:16} " + " | ".join(f"{h.split('.')[0]}: {c}" for (h, _), c in zip(SITES, cells)), flush=True)
