"""Куда на самом деле приводит сайт через каждый сервис: идём по переадресациям, каждое новое имя спрашиваем у DNS сервиса.

python tools/probe_chain.py — запускать без VPN и туннелей, из России. Только чтение: запросы DNS и HTTPS.

Зачем. Программа проверяет одно имя на сайт. Если главная страница уводит на другое имя, а сервис его не подменяет,
человек после переадресации окажется на сайте напрямую, хотя проверка по первому имени пишет «открывается».
Так было 14.11.2026 с Copilot: copilot.microsoft.com переадресует на copilot.com, а GeoHide подменял только
первое имя — поэтому в программе Copilot проверяется по copilot.com. Строки с «!!» — такие расхождения:
для них стоит поменять имя в списке сайтов (Probe.Host в XboxDns.cs, Probe.host в Probe.swift, SITES в probe_dns.py).
"""
import subprocess, sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit
import probe_dns as p

SERVICES = [("GeoHide EU", ["143.20.64.192", "5.175.161.40"]), ("MagicDNS", ["217.144.190.216", "109.120.187.249"]),
            ("Перевал", ["153.80.200.170"])]
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36"
REAL = {}


def real(host):
    if host not in REAL: REAL[host] = p.real(host)
    return REAL[host]


def get(url, host, ip):
    o = subprocess.run(["curl.exe", "-s", "-o", "NUL", "--noproxy", "*", "--connect-timeout", "6", "-m", "14", "-A", UA,
                        "--resolve", f"{host}:443:{ip}", "-w", "%{http_code} %{redirect_url}", url], capture_output=True, text=True).stdout.strip()
    return None if not o or o.startswith(("000", "5")) else o   # 5xx — узел не справился: как программа, идём к следующему адресу


def ask(servers, host):
    for s in servers:
        a = p.ask(s, host)
        if a is not None: return a
    return None


def word(o):
    low = o.lower()
    if low.startswith("5"): return "нет связи"   # 5xx — сайт или прокси не справился
    if "/sorry/" in low: return "капча Google"
    if low.startswith("451") or any(b in low for b in p.BLOCK): return "блок страны"
    return "открывается"


def hop(servers, url, proxy):
    """Один шаг: (как пришли, вердикт, код, куда дальше). servers None — напрямую, без сервиса."""
    host = urlsplit(url).hostname
    ips = sorted(real(host)) if servers is None else ask(servers, host)
    if ips is None: return "DNS молчит", "DNS молчит", "", None
    if not ips or ips[0] == "0.0.0.0": return "нет адреса", "не пускает", "", None
    o, used = None, ips[0]
    for ip in ips[:p.TRIES]:
        o = get(url, host, ip)
        if o is not None: used = ip; break
    # прокси — адрес из сетей, которые сервис отдаёт на сайты разных владельцев, и не названный обычными DNS
    how = "прокси" if p.net24(used) in proxy and not p.is_real(used, real(host)) else "напрямую"
    if o is None: return how, "нет связи", "", None
    code, _, nxt = o.partition(" ")
    return how, word(o), code, nxt or None


def chain(servers, host, proxy):
    url, steps = f"https://{host}/", []
    for _ in range(6):
        how, w, code, nxt = hop(servers, url, proxy)
        steps.append((urlsplit(url).hostname + (urlsplit(url).path[:40] if urlsplit(url).path != "/" else ""), how, code or w, w))
        if w != "открывается" or not nxt or nxt == url: break
        url = nxt
    end = lambda s: "напрямую" if s[1] == "напрямую" and s[3] == "открывается" else s[3]
    return end(steps[0]), end(steps[-1]), "  →  ".join(f"{s[0]} [{s[1]} {s[2]}]" for s in steps)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    hosts = [s[1] for s in p.SITES]
    with ThreadPoolExecutor(len(hosts)) as ex: list(ex.map(real, hosts))
    print("=== Напрямую из России, без сервиса", flush=True)
    with ThreadPoolExecutor(len(hosts)) as ex: rows = list(ex.map(lambda h: chain(None, h, set()), hosts))
    for (label, _, _), (first, last, text) in zip(p.SITES, rows): print(f"    {label:11} {last:13} {text}", flush=True)
    for name, servers in SERVICES:
        with ThreadPoolExecutor(len(hosts)) as ex:
            answers = list(ex.map(lambda h: ask(servers, h), hosts))
            proxy = p.shared(answers, [s[2] for s in p.SITES], [real(h) for h, a in zip(hosts, answers) if a and a[0] != "0.0.0.0"])
            rows = list(ex.map(lambda h: chain(servers, h, proxy), hosts))
        good = sum(last == "открывается" for _, last, _ in rows)
        print(f"\n=== {name} ({', '.join(servers)}): открывается {good} из {len(hosts)}; сети прокси: {', '.join(sorted(proxy)) or '—'}", flush=True)
        for (label, _, _), (first, last, text) in zip(p.SITES, rows):
            print(f" {'  ' if first == last else '!!'} {label:11} первое имя: {first:13} конец: {last:13} {text}", flush=True)
