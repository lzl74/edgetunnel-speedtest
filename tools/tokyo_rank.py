#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tokyo_rank.py : 对东京网段做深度排名

为什么不是测一次就排：单次采样误差可达 ±200ms，排名不可复现。
这里用「多轮 + 轮内随机顺序」采样，取中位数，并同时给出抖动。

用法:
    python tokyo_rank.py                 # 默认 8 轮
    python tokyo_rank.py --rounds 12 --pool 60
"""
import argparse
import sys
import importlib.util
import json
import os
import random
import socket
import ssl
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("bt", os.path.join(HERE, "bulk_test.py"))
bt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bt)

WORKER_HOST = os.environ.get("CF_WORKER", "").strip()
if not WORKER_HOST:
    sys.exit("请先指定你的 Worker 域名(用于 TLS SNI / HTTP Host); Windows 用 set CF_WORKER=你的域名, macOS/Linux 用 export CF_WORKER=你的域名")
CTX = ssl.create_default_context()
CTX.set_alpn_protocols(["http/1.1"])

# 已知 100% 落东京的网段（2026-10-30 实测）
TOKYO_NETS = ["162.159.38.0/24", "162.159.39.0/24", "162.159.44.0/24",
              "162.159.45.0/24", "108.162.198.0/24"]


def probe(ip, timeout=4.0):
    """返回 (ttfb, colo)；colo 取自 CF-RAY，确保是真边缘"""
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
            return None, None
        if int(head[0].split()[1]) != 200:
            return None, None
        ray = next((l.split(":", 1)[1].strip() for l in head[1:]
                    if l.lower().startswith("cf-ray:")), None)
        colo = ray.rsplit("-", 1)[-1] if ray and "-" in ray else None
        return (ttfb if colo else None), colo
    except Exception:
        return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=8)
    ap.add_argument("--pool", type=int, default=45, help="深度测试多少个 IP")
    ap.add_argument("--per-net", type=int, default=40, help="每个 /24 抽多少个")
    ap.add_argument("--speed-top", type=int, default=10)
    args = ap.parse_args()

    import ipaddress
    rng = random.Random(int(time.time()))
    cand = []
    for c in TOKYO_NETS:
        n = ipaddress.ip_network(c)
        base = int(n.network_address)
        for o in rng.sample(range(1, 255), args.per_net):
            cand.append(str(ipaddress.IPv4Address(base + o)))

    print(f"候选 {len(cand)} 个 IP（来自 {len(TOKYO_NETS)} 个东京网段）")
    t0 = time.time()
    alive = []
    with ThreadPoolExecutor(max_workers=120) as ex:
        futs = {ex.submit(probe, ip): ip for ip in cand}
        for fu in as_completed(futs):
            t, colo = fu.result()
            if t and colo == "NRT":
                alive.append(futs[fu])
    print(f"存活 {len(alive)} 个（{time.time()-t0:.0f}s），随机取 {args.pool} 个做深度测试\n")

    pool = rng.sample(alive, min(args.pool, len(alive)))
    samples = {ip: [] for ip in pool}
    for rd in range(args.rounds):
        order = pool[:]
        rng.shuffle(order)
        for ip in order:
            t, colo = probe(ip)
            if t and colo == "NRT":
                samples[ip].append(t)
        print(f"   第 {rd+1}/{args.rounds} 轮完成", flush=True)

    res = []
    for ip, v in samples.items():
        if len(v) < args.rounds // 2:
            continue
        sv = sorted(v)
        res.append({"ip": ip, "n": len(v), "med": statistics.median(v),
                    "p25": sv[len(sv) // 4], "min": min(v),
                    "p90": sv[min(len(sv) - 1, int(len(sv) * 0.9))],
                    "sd": statistics.pstdev(v)})
    res.sort(key=lambda r: r["med"])

    print(f"\n{'#':>3} {'IP':<18}{'中位':>7}{'P25':>7}{'最快':>7}{'P90':>7}{'抖动':>7}{'样本':>5}")
    print("-" * 62)
    for i, r in enumerate(res, 1):
        print(f'{i:>3} {r["ip"]:<18}{r["med"]:>7.0f}{r["p25"]:>7.0f}{r["min"]:>7.0f}'
              f'{r["p90"]:>7.0f}{r["sd"]:>7.1f}{r["n"]:>5}')

    # 带宽：串行测前 N 名
    print(f"\n串行测速 前 {args.speed_top} 名 ...")
    for r in res[:args.speed_top]:
        mb = bt.cfopt.speed_test(r["ip"], 443, 5_000_000, 20.0)
        r["mbps"] = mb
    for r in res:
        r.setdefault("mbps", None)

    print(f"\n{'#':>3} {'IP':<18}{'中位':>7}{'带宽':>9}")
    print("-" * 40)
    for i, r in enumerate(res[:args.speed_top], 1):
        mb = f'{r["mbps"]:.1f}' if r["mbps"] else "-"
        print(f'{i:>3} {r["ip"]:<18}{r["med"]:>7.0f}{mb:>9}')

    meds = [r["med"] for r in res]
    if len(meds) > 1:
        print(f"\n池内中位延迟极差 {max(meds)-min(meds):.0f}ms，"
              f"单 IP 抖动中位 {statistics.median([r['sd'] for r in res]):.0f}ms")
    with open(os.path.join(HERE, "tokyo_rank.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=1)
    print(f"结果: {os.path.join(HERE, 'tokyo_rank.json')}")


if __name__ == "__main__":
    main()
