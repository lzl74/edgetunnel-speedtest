#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ip_scan.py : 从 Cloudflare ASN 网段里抽样 IP，找出对你本地网络真正可用的优选 IP

关键点：ASN 网段里只有一部分是 anycast 边缘节点，其余的连上去 TLS 会失败
（证书不是你的 Worker 域名 / 根本不服务该 zone）。所以必须用真实 TLS 握手来筛。

流程:
  1. 读 cidrs.txt，每个网段随机抽 2-4 个 IP（保证跨网段多样性）
  2. 并发 TCP 探测 443
  3. 通过的做 TLS 握手（SNI = Worker 域名）+ HTTP 首字节
  4. 查 /cdn-cgi/trace 拿落点机房
  5. 汇总：有效率、机房分布、最优 IP、能出东京的网段

用法:
    python ip_scan.py
    python ip_scan.py --per-cidr 3 --workers 300
"""
import argparse
import csv
import importlib.util
import ipaddress
import json
import os
import random
import socket
import statistics
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("bt", os.path.join(HERE, "bulk_test.py"))
bt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bt)

WORKER_HOST = bt.WORKER_HOST
PORTS = bt.PORTS
TCP_TIMEOUT = 1.3


def load_cidrs(path):
    nets, seen = [], set()
    with open(path, "r", encoding="utf-8-sig") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            try:
                n = ipaddress.ip_network(s, strict=False)
            except ValueError:
                continue
            if n.version != 4 or n.prefixlen >= 31:
                continue
            if n in seen:
                continue
            seen.add(n)
            nets.append(n)
    # 去掉被更大网段完全包含的
    nets.sort(key=lambda n: n.prefixlen)
    out = []
    for n in nets:
        if not any(n.subnet_of(o) for o in out):
            out.append(n)
    return out


def sample_ips(nets, per_cidr, rng):
    ips = []
    for n in nets:
        size = n.num_addresses
        if n.prefixlen >= 24:
            k = per_cidr
        elif n.prefixlen >= 20:
            k = per_cidr + 1
        else:
            k = per_cidr + 2
        k = min(k, max(1, size - 2))
        base = int(n.network_address)
        picks = rng.sample(range(1, size - 1), k) if size - 2 > k else range(1, size - 1)
        for off in picks:
            ips.append((str(ipaddress.IPv4Address(base + off)), str(n)))
    return ips


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", "--file", default=os.path.join(HERE, "cidrs.txt"))
    ap.add_argument("--per-cidr", type=int, default=2)
    ap.add_argument("--workers", type=int, default=300)
    ap.add_argument("--seed", type=int, default=20261030)
    ap.add_argument("--speed-top", type=int, default=15)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    nets = load_cidrs(args.file)
    samples = sample_ips(nets, args.per_cidr, rng)
    print(f"网段 {len(nets)} 个 → 抽样 {len(samples)} 个 IP   Worker 域名(SNI): {WORKER_HOST}\n")

    # ---------- 1. TCP 443 ----------
    t0 = time.time()
    tcp_ok = []

    def probe(ip):
        r = bt.tcp_probe(ip, 443, TCP_TIMEOUT)
        return (ip, r) if r is not None else None

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(probe, ip) for ip, _ in samples]
        for i, fu in enumerate(as_completed(futs), 1):
            r = fu.result()
            if r:
                tcp_ok.append(r)
            if i % 500 == 0:
                print(f"       ... {i}/{len(futs)}  已通过 {len(tcp_ok)}")
    cidr_of = dict(samples)
    print(f"[1/4] TCP 443 完成 {time.time()-t0:.0f}s  "
          f"通过 {len(tcp_ok)}/{len(samples)} ({len(tcp_ok)/len(samples)*100:.1f}%)")

    # ---------- 2. TLS + TTFB ----------
    t0 = time.time()
    rows = []

    def tls_probe(item):
        ip, _ = item
        tls, ttfb, status = bt.tls_ttfb(ip, 443)
        if ttfb is None:
            return None
        return {"ip": ip, "cidr": cidr_of.get(ip, ""), "tls": round(tls, 1),
                "ttfb": round(ttfb, 1), "status": status}

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(tls_probe, it) for it in tcp_ok]
        for i, fu in enumerate(as_completed(futs), 1):
            r = fu.result()
            if r:
                rows.append(r)
            if i % 300 == 0:
                print(f"       ... {i}/{len(futs)}  已成功 {len(rows)}")
    print(f"[2/4] TLS 握手完成 {time.time()-t0:.0f}s  "
          f"可用 {len(rows)}/{len(tcp_ok)} ({len(rows)/max(len(tcp_ok),1)*100:.1f}%)")

    if not rows:
        print("\n没有任何 IP 通过 TLS 校验 —— 说明这批网段基本不是 anycast 边缘。")
        return

    # ---------- 3. 机房 ----------
    t0 = time.time()
    rows.sort(key=lambda r: r["ttfb"])
    top = rows[:200]

    def colo(r):
        c, _ = bt.cfopt.colo_probe(r["ip"], 443)
        return c

    with ThreadPoolExecutor(max_workers=40) as ex:
        futs = {ex.submit(colo, r): r for r in top}
        for fu in as_completed(futs):
            try:
                futs[fu]["colo"] = fu.result()
            except Exception:
                futs[fu]["colo"] = None
    for r in rows:
        r.setdefault("colo", None)
    print(f"[3/4] 机房归属完成 {time.time()-t0:.0f}s")

    # ---------- 4. 测速 ----------
    t0 = time.time()
    for r in rows[:args.speed_top]:
        r["mbps"] = bt.cfopt.speed_test(r["ip"], 443, 5_000_000, 20.0)
    for r in rows:
        r.setdefault("mbps", None)
    print(f"[4/4] 串行测速完成 {time.time()-t0:.0f}s\n")

    rows.sort(key=lambda r: r["ttfb"])
    print("=" * 82)
    print("【可用 IP 排名 前 30】")
    print("=" * 82)
    print(f'{"#":>3} {"IP":<18}{"机房":>5}{"tcp/tls":>9}{"ttfb":>7}{"Mbps":>8}  所属网段')
    print("-" * 82)
    for i, r in enumerate(rows[:30], 1):
        mb = "-" if r["mbps"] is None else f'{r["mbps"]:.1f}'
        print(f'{i:>3} {r["ip"]:<18}{str(r["colo"] or "-"):>5}{r["tls"]:>9.0f}'
              f'{r["ttfb"]:>7.0f}{mb:>8}  {r["cidr"]}')

    print("\n【机房分布（可用 IP）】")
    for c, n in Counter(r["colo"] or "未知" for r in rows).most_common():
        print(f"   {c:<6} {n:>4} 个  {n/len(rows)*100:>5.1f}%")

    nrt = [r for r in rows if r["colo"] == "NRT"]
    if nrt:
        print(f"\n【能出东京(NRT)的网段】共 {len(nrt)} 个 IP")
        for c, n in Counter(r["cidr"] for r in nrt).most_common(15):
            print(f"   {c:<22} {n} 个")

    with open(os.path.join(HERE, "ip_scan.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["ip", "colo", "cidr", "tls", "ttfb", "mbps", "status"],
                           extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(HERE, "ip_scan.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=1)
    print(f"\n结果: {os.path.join(HERE, 'ip_scan.csv')}  共 {len(rows)} 个可用 IP")


if __name__ == "__main__":
    main()
