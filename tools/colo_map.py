#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
colo_map.py : 摸清「哪个网段 → 哪个 Cloudflare 机房」

判定标准严格按 CF-RAY 响应头（不是只看 TLS 成功），避免假阳性。

用法:
    python colo_map.py --map 162.159.0.0/18 --per 25    # 逐 /24 摸整段
    python colo_map.py --hunt                            # 全域抽样找特定机房
"""
import argparse
import sys
import ipaddress
import json
import os
import random
import socket
import ssl
import statistics
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
WORKER_HOST = os.environ.get("CF_WORKER", "").strip()
if not WORKER_HOST:
    sys.exit("请先指定你的 Worker 域名(用于 TLS SNI / HTTP Host); Windows 用 set CF_WORKER=你的域名, macOS/Linux 用 export CF_WORKER=你的域名")
CTX = ssl.create_default_context()
CTX.set_alpn_protocols(["http/1.1"])


def probe(ip, timeout=4.0):
    """返回 (status, colo, ttfb)；colo 取自 CF-RAY 后缀"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 443))
        ss = CTX.wrap_socket(s, server_hostname=WORKER_HOST)
        t0 = time.perf_counter()
        ss.sendall(f"GET / HTTP/1.1\r\nHost: {WORKER_HOST}\r\n"
                   f"Connection: close\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = ss.recv(4096)
            if not c:
                break
            buf += c
            if len(buf) > 16384:
                break
        ttfb = (time.perf_counter() - t0) * 1000
        ss.close()
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
        if not head or not head[0].startswith("HTTP/"):
            return None, None, None
        status = int(head[0].split()[1])
        ray = None
        for l in head[1:]:
            if l.lower().startswith("cf-ray:"):
                ray = l.split(":", 1)[1].strip()
        colo = ray.rsplit("-", 1)[-1] if ray and "-" in ray else None
        return status, colo, ttfb
    except Exception:
        return None, None, None


def scan_full(ips, workers=150):
    out = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe, ip): ip for ip in ips}
        for fu in as_completed(futs):
            st, colo, t = fu.result()
            if st == 200 and colo:
                out.append({"ip": futs[fu], "colo": colo, "ttfb": t})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--map", default=None, help="要逐 /24 摸清的网段，如 162.159.0.0/18")
    ap.add_argument("--per", type=int, default=25, help="每个 /24 抽几个 IP")
    ap.add_argument("--hunt", action="store_true", help="全域抽样找机房")
    ap.add_argument("--hunt-n", type=int, default=1200)
    ap.add_argument("--workers", type=int, default=150)
    args = ap.parse_args()
    rng = random.Random(20261030)

    if args.map:
        net = ipaddress.ip_network(args.map)
        subs = list(net.subnets(new_prefix=24)) if net.prefixlen < 24 else [net]
        print(f"逐 /24 摸清 {args.map}（{len(subs)} 个 /24，每个抽 {args.per} 个）\n")
        print(f"{'网段':<20}{'有效':>5}{'主要机房':>10}{'命中率':>8}")
        print("-" * 46)
        summary = {}
        for sub in subs:
            base = int(sub.network_address)
            n = sub.num_addresses
            picks = rng.sample(range(1, n - 1), min(args.per, n - 2))
            ips = [str(ipaddress.IPv4Address(base + o)) for o in picks]
            res = scan_full(ips, args.workers)
            c = Counter(r["colo"] for r in res)
            top = c.most_common(1)[0] if c else ("-", 0)
            summary[str(sub)] = {"colo": top[0], "hits": top[1], "valid": len(res)}
            print(f"{str(sub):<20}{len(res):>5}{top[0]:>10}{len(res)/len(ips)*100:>7.0f}%")
        with open(os.path.join(HERE, "colo_map.json"), "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=1)
        allc = Counter(v["colo"] for v in summary.values())
        print(f"\n整段机房分布（按 /24 计）: {dict(allc)}")

    if args.hunt:
        print("\n" + "=" * 60)
        print("全域抽样，找所有出现过的机房")
        print("=" * 60)
        nets = []
        with open(os.path.join(HERE, "cidrs.txt"), "r", encoding="utf-8-sig") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                try:
                    n = ipaddress.ip_network(s, strict=False)
                except ValueError:
                    continue
                if n.version == 4 and n.prefixlen < 31:
                    nets.append(n)
        ips = []
        for _ in range(args.hunt_n):
            n = rng.choice(nets)
            base = int(n.network_address)
            ips.append(str(ipaddress.IPv4Address(base + rng.randint(1, max(1, n.num_addresses - 2)))))
        print(f"抽样 {len(ips)} 个 IP ...")
        res = scan_full(ips, args.workers)
        print(f"真实边缘 {len(res)} 个")
        print("\n机房分布:")
        for c, n in Counter(r["colo"] for r in res).most_common():
            sub = [r for r in res if r["colo"] == c]
            med = statistics.median([r["ttfb"] for r in sub])
            print(f"   {c:<6} {n:>4} 个   中位 {med:>5.0f}ms")
        want = {"HKG", "KIX", "ICN", "TPE", "SIN", "NRT", "NGO"}
        hit = [r for r in res if r["colo"] in want]
        print(f"\n亚洲机房命中: {len(hit)} 个")
        for r in sorted(hit, key=lambda x: x["ttfb"])[:15]:
            print(f"   {r['ip']:<18}{r['colo']:>5}{r['ttfb']:>7.0f}ms")
        if not any(r["colo"] == "HKG" for r in res):
            print("\n   >>> 本次抽样中 香港(HKG) 出现 0 次")


if __name__ == "__main__":
    main()
