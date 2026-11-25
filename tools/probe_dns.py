"""Проверка Smart DNS-сервисов: что отдают для сайтов из программы и пускают ли сайты через их прокси.

python tools/probe_dns.py — сводка по всем кандидатам (запускать без VPN и туннелей, из России:
туннель перехватывает порт 53, и все серверы «отвечают» одинаково).

Логика та же, что в программе (XboxDns.cs, класс Probe), с двумя отличиями, как у версии для Mac. Curl отдаёт только
код и адрес переадресации: отказ по стране, написанный только в теле ответа (так отвечают Grok и API OpenAI), скрипт
не видит. И curl проверяет сертификат целиком, а программа для Windows — только имя, на которое он выписан.
- адрес от сервиса сверяется с обычными DNS (CONTROL). Совпал — сервис сайт не подменяет, в сводке «напрямую»:
  ответ 403 или 200 в таком случае ничего не значит, человек идёт на сайт как без Smart DNS;
- прокси сервиса считается только сеть, которую он отдал на сайты разных владельцев (shared) и которую обычные DNS
  не назвали ни для одного сайта, на который сервис дал адрес. У Google адресов тысячи, и сервис, который его сайты не подменяет, отдаёт настоящий
  адрес из сети, которую обычные DNS не назвали; у Cloudflare для России одни адреса на сайты разных владельцев.

Сайты, которые с главной страницы уводят на другое имя, смотрит tools/probe_chain.py.
"""
import socket, struct, subprocess, sys
from concurrent.futures import ThreadPoolExecutor

# Первые пять — адреса из программы 1.26. Остальные — для сравнения и на случай, если сервис вернётся.
# Geodema и WebShift работают, но в программу не взяты: оба — бесплатное приложение к платному VPN того же оператора.
CANDIDATES = [
    ("GeoHide", "193.233.112.88"), ("GeoHide-2", "37.230.192.51"),
    ("Перевал", "153.80.200.170"), ("Xbox DNS", "111.88.96.54"),
    ("Geodema", "179.236.130.10"), ("Geodema-2", "179.236.130.11"),
    ("WebShift", "31.31.207.68"), ("Comss.one", "94.250.253.55"), ("Comss новый", "212.109.221.20"),
    ("MagicDNS 1.25", "217.144.190.216"), ("MagicDNS 1.25-2", "109.120.187.249"),
    ("GeoHide EU 1.25", "5.175.161.40"), ("GeoHide EU 1.25-2", "143.20.64.192"),
    ("MagicDNS до 14.11", "109.120.177.170"), ("GeoHide EU-3", "45.13.237.213"), ("GeoHide RU", "159.194.200.33"),
    ("Astracat", "135.106.217.200"), ("Malw.link", "179.254.166.171"), ("Dagami", "48.102.213.179"), ("DNS-AI", "194.87.196.13"),
]
# подпись, имя, владелец — как Label, Host и Owner в программе
SITES = [("ChatGPT", "chatgpt.com", "OpenAI"), ("Claude", "claude.ai", "Anthropic"), ("Gemini", "gemini.google.com", "Google"),
         ("ElevenLabs", "elevenlabs.io", "ElevenLabs"), ("Grok", "grok.com", "xAI"), ("Perplexity", "www.perplexity.ai", "Perplexity"),
         ("Copilot", "copilot.com", "Microsoft"), ("Sora", "sora.chatgpt.com", "OpenAI"), ("NotebookLM", "notebooklm.google.com", "Google"),
         ("AI Studio", "aistudio.google.com", "Google"), ("API Claude", "api.anthropic.com", "Anthropic"), ("API OpenAI", "api.openai.com", "OpenAI"),
         ("OpenRouter", "openrouter.ai", "OpenRouter"), ("Notion", "www.notion.so", "Notion"), ("Spotify", "open.spotify.com", "Spotify")]
BLOCK = ("restrict", "unsupported", "unavailable", "not-available")
TRIES = 4   # сколько адресов из ответа сервиса пробуем, прежде чем писать «нет связи»
CONTROL = ("77.88.8.8", "9.9.9.9", "94.140.14.14")   # Яндекс, Quad9 и AdGuard


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


def ask(server, name):
    """Как в программе: до двух попыток, UDP-пакет иногда теряется."""
    a = resolve_all(server, name)
    return a if a is not None else resolve_all(server, name)


def resolve(server, name):
    """Первый адрес; "" — адреса нет; None — сервер не ответил."""
    a = resolve_all(server, name)
    return None if a is None else (a[0] if a else "")


def real(name):
    """Настоящие адреса сайта: всё, что ответили обычные DNS."""
    found = set()
    for c in CONTROL: found.update(ask(c, name) or [])
    return found


def net24(ip):
    return ip.rsplit(".", 1)[0]


def is_real(ip, found):
    """Совпал с ответом обычного DNS или лежит с ним в одной сети /24 (у крупных сайтов адреса идут пачкой)."""
    return any(net24(x) == net24(ip) for x in found)


def shared(answers, owners, reals=()):
    """Сети /24, которые сервис отдал на сайты хотя бы двух разных владельцев, — так выглядит его прокси.
    Кроме сетей, которые обычные DNS назвали хоть для одного сайта, на который сервис дал адрес
    (reals — наборы настоящих адресов таких сайтов; так же считает Probe.Verdicts в программе):
    у Cloudflare для России одни и те же адреса на сайты разных владельцев."""
    seen = {}
    for ips, owner in zip(answers, owners):
        for ip in ips or []: seen.setdefault(net24(ip), set()).add(owner)
    named = {net24(ip) for found in reals for ip in found}
    return {n for n, o in seen.items() if len(o) > 1} - named


def known(found, ips, proxy):
    """Настоящие адреса сайта: ответы обычных DNS и адреса от сервиса, чьих сетей нет среди его прокси."""
    return set(found) | {ip for ip in ips or [] if net24(ip) not in proxy}


def fetch(url, host, ip):
    out = subprocess.run(["curl.exe", "-s", "-o", "NUL", "--noproxy", "*", "--connect-timeout", "6", "-m", "14", "-A",
                          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36",
                          "--resolve", f"{host}:443:{ip}", "-w", "%{http_code} %{redirect_url}", url],
                         capture_output=True, text=True).stdout
    if not out or out.startswith("000") or out.startswith("5"): return "нет связи"   # 5xx — сайт или прокси не справился
    if "/sorry/" in out: return "капча Google"
    if out.startswith("451") or any(b in out.lower() for b in BLOCK): return "блок страны"
    return "ок " + out.split()[0]


def verdict(host, ips, real_ips):
    """Итог по сайту, как Probe.Judge: адреса от сервиса ips, настоящие адреса real_ips (уже с учётом known)."""
    if ips is None: return "DNS молчит"
    if not ips or ips[0] == "0.0.0.0": return "не пускает"
    for ip in ips[:TRIES]:   # сервис отдаёт несколько адресов своих узлов, часть бывает мёртвой: как браузер, идём к следующему
        r = fetch(f"https://{host}/", host, ip)
        if r == "нет связи": continue
        return "напрямую" if r.startswith("ок") and is_real(ip, real_ips) else ("открывается" if r.startswith("ок") else r)
    return "нет связи"


def service(server, reals):
    """Вердикты по всем сайтам для одного адреса DNS."""
    with ThreadPoolExecutor(len(SITES)) as ex:
        answers = list(ex.map(lambda s: ask(server, s[1]), SITES))
        proxy = shared(answers, [s[2] for s in SITES], [reals[s[1]] for s, a in zip(SITES, answers) if a and a[0] != "0.0.0.0"])
        return list(ex.map(lambda p: verdict(p[0][1], p[1], known(reals[p[0][1]], p[1], proxy)), zip(SITES, answers))), proxy


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    with ThreadPoolExecutor(len(SITES)) as ex: REAL = dict(zip([s[1] for s in SITES], ex.map(real, [s[1] for s in SITES])))
    for host, found in REAL.items():
        if not found: print(f"! обычные DNS не ответили про {host}: «напрямую» для него определяется только по второй сверке", flush=True)
    for name, server in CANDIDATES:
        res, proxy = service(server, REAL)
        groups = {}
        for (label, _, _), r in zip(SITES, res): groups.setdefault(r, []).append(label)
        rest = " | ".join(f"{r}: {', '.join(labels)}" for r, labels in groups.items() if r != "открывается")
        print(f"{name:18} {server:16} открывается {len(groups.get('открывается', [])):2} из {len(SITES)}"
              + (": " + ", ".join(groups["открывается"]) if groups.get("открывается") else "") + (" | " + rest if rest else "")
              + (f" | сети прокси: {', '.join(sorted(proxy))}" if proxy else ""), flush=True)
