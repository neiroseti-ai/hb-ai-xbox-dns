"""Через какой адрес и страну каждый Smart DNS выводит запросы к claude.ai.

Берёт адрес, который сервис отдаёт для claude.ai, и запрашивает https://claude.ai/cdn-cgi/trace
через него (curl --resolve, мимо системного прокси). Cloudflare отвечает ip= и loc= — это то,
что видит Claude. Затем тип адреса (серверный/домашний) по ipwho.is.
"""
import json, subprocess, sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from probe_dns import CANDIDATES, resolve

def trace(ip):
    out = subprocess.run(["curl.exe", "-s", "--noproxy", "*", "-m", "12", "--resolve", f"claude.ai:443:{ip}",
                          "https://claude.ai/cdn-cgi/trace"], capture_output=True, text=True).stdout
    return dict(l.split("=", 1) for l in out.splitlines() if "=" in l)

def info(ip):
    out = subprocess.run(["curl.exe", "-s", "--noproxy", "*", "-m", "12", f"https://ipwho.is/{ip}"],
                         capture_output=True, text=True).stdout
    try:
        j = json.loads(out); c = j.get("connection", {})
        return f"{j.get('country','?')}, {j.get('city','?')}, {c.get('org') or c.get('isp','?')}"
    except Exception:
        return "?"

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    seen = {}
    for name, server in CANDIDATES:
        ip = resolve(server, "claude.ai")
        if not ip or ip == "0.0.0.0":
            print(f"{name:12} {server:16} DNS: {ip!r}"); continue
        t = trace(ip)
        exit_ip = t.get("ip", "?")
        if exit_ip not in seen: seen[exit_ip] = info(exit_ip) if exit_ip != "?" else "?"
        print(f"{name:12} {server:16} прокси {ip:16} → Claude видит {exit_ip} loc={t.get('loc','?')} ({seen[exit_ip]})", flush=True)
