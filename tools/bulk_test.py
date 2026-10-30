#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bulk_test.py : 批量测试一批 Cloudflare 优选域名在本地网络上的质量

流程:
  1. 并发解析 DNS,过滤掉不在 Cloudflare 网段内的 IP(被污染/非 CF 的直接淘汰)
  2. 对每个域名并发探测 443/2053/2083/2087/2096/8443 六个端口
  3. 在最通的端口上做 TLS 握手 + HTTP 首字节(SNI 固定为你的 Worker 域名)
  4. 查 /cdn-cgi/trace 拿到真实落点机房
  5. 对排名靠前的做真实下载测速

用法:
    python bulk_test.py                     # 全流程
    python bulk_test.py --speed-top 30      # 只给前 30 名测速
    python bulk_test.py --no-speed          # 不测速,只看延迟
"""
import argparse
import csv
import importlib.util
import ipaddress
import json
import os
import socket
import ssl
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))

# 复用单点测试里的测速 / 查机房函数
_spec = importlib.util.spec_from_file_location("cfopt", os.path.join(HERE, "cf_opt_test.py"))
cfopt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cfopt)

WORKER_HOST = os.environ.get("CF_WORKER", "").strip()
if not WORKER_HOST:
    sys.exit("请先指定你的 Worker 域名(用于 TLS SNI / HTTP Host); Windows 用 set CF_WORKER=你的域名, macOS/Linux 用 export CF_WORKER=你的域名")
PORTS = [443, 2053, 2083, 2087, 2096, 8443]

# Cloudflare 官方 IPv4 网段
CF_NETS = [ipaddress.ip_network(n) for n in [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]]

TCP_TIMEOUT = 1.5
TLS_TIMEOUT = 5.0
CTX = ssl.create_default_context()
CTX.set_alpn_protocols(["http/1.1"])


def is_cf(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in CF_NETS)


def resolve(domain, limit=2):
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
    except Exception:
        return [], "DNS 失败"
    ips, seen = [], set()
    for i in infos:
        ip = i[4][0]
        if ip in seen:
            continue
        seen.add(ip)
        ips.append(ip)
        if len(ips) >= limit:
            break
    if not ips:
        return [], "无 A 记录"
    if not any(is_cf(i) for i in ips):
        return [], f"非 CF ({ips[0]})"
    return [i for i in ips if is_cf(i)], None


def tcp_probe(ip, port, timeout=TCP_TIMEOUT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        s.connect((ip, port))
        dt = (time.perf_counter() - t0) * 1000
        return dt
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def tls_ttfb(ip, port):
    """返回 (tls_ms, ttfb_ms, status) 或 (None, None, None)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TLS_TIMEOUT)
        s.connect((ip, port))
        t0 = time.perf_counter()
        ss = CTX.wrap_socket(s, server_hostname=WORKER_HOST)
        tls = (time.perf_counter() - t0) * 1000
        req = (f"GET / HTTP/1.1\r\nHost: {WORKER_HOST}\r\n"
               f"User-Agent: bulk-test\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        t1 = time.perf_counter()
        ss.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = ss.recv(4096)
            if not c:
                break
            buf += c
            if len(buf) > 32768:
                break
        ttfb = (time.perf_counter() - t1) * 1000
        ss.close()
        status = 0
        first = buf.split(b"\r\n", 1)[0].decode("latin-1")
        if first.startswith("HTTP/"):
            try:
                status = int(first.split()[1])
            except Exception:
                pass
        return tls, ttfb, status
    except Exception:
        return None, None, None


def stage_ports(domain, ips):
    """测这个域名的所有 CF IP × 6 端口,返回可用端口 -> (ip, rtt)"""
    best = {}
    for ip in ips:
        for p in PORTS:
            rtt = tcp_probe(ip, p)
            if rtt is None:
                continue
            cur = best.get(p)
            if cur is None or rtt < cur[1]:
                best[p] = (ip, rtt)
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", "--file", default=os.path.join(HERE, "domains.txt"))
    ap.add_argument("--speed-top", type=int, default=25)
    ap.add_argument("--no-speed", action="store_true")
    ap.add_argument("--workers", type=int, default=160)
    args = ap.parse_args()

    with open(args.file, "r", encoding="utf-8-sig") as f:
        domains = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    seen, uniq = set(), []
    for d in domains:
        d = d.lower()
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    domains = uniq
    print(f"待测域名: {len(domains)} 个   Worker 域名(SNI): {WORKER_HOST}")
    print(f"端口: {PORTS}\n")

    # ---------- 1. DNS ----------
    t0 = time.time()
    dns_ok, dns_bad = {}, {}
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(resolve, d): d for d in domains}
        for fu in as_completed(futs):
            d = futs[fu]
            ips, err = fu.result()
            if ips:
                dns_ok[d] = ips
            else:
                dns_bad[d] = err
    print(f"[1/4] DNS 解析完成 {time.time()-t0:.0f}s  "
          f"CF 域名 {len(dns_ok)} 个,淘汰 {len(dns_bad)} 个")
    for d, e in list(dns_bad.items())[:6]:
        print(f"       淘汰 {d}: {e}")
    if not dns_ok:
        sys.exit("没有可用的 CF 域名")

    # ---------- 2. 端口 ----------
    t0 = time.time()
    port_map = {}
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(stage_ports, d, ips): d for d, ips in dns_ok.items()}
        for fu in as_completed(futs):
            port_map[futs[fu]] = fu.result()
    alive = {d: m for d, m in port_map.items() if m}
    print(f"[2/4] 端口探测完成 {time.time()-t0:.0f}s  可用域名 {len(alive)} 个")

    # ---------- 3. TLS + TTFB ----------
    t0 = time.time()

    def probe(d):
        m = alive[d]
        # 优先用 443,否则用 RTT 最低的端口
        port = 443 if 443 in m else min(m, key=lambda p: m[p][1])
        ip = m[port][0]
        tls, ttfb, status = tls_ttfb(ip, port)
        if ttfb is None:      # 换个端口再试一次
            for p2 in sorted(m, key=lambda p: m[p][1]):
                if p2 == port:
                    continue
                tls, ttfb, status = tls_ttfb(m[p2][0], p2)
                if ttfb is not None:
                    port, ip = p2, m[p2][0]
                    break
        return {"domain": d, "ip": ip, "port": port, "ports": sorted(m),
                "tcp": round(m[port][1], 1), "tls": round(tls, 1) if tls else None,
                "ttfb": round(ttfb, 1) if ttfb else None, "status": status}

    rows = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(probe, d) for d in alive]
        for i, fu in enumerate(as_completed(futs), 1):
            rows.append(fu.result())
            if i % 60 == 0:
                print(f"       ... {i}/{len(futs)}")
    ok = [r for r in rows if r["ttfb"]]
    print(f"[3/4] TLS/首字节完成 {time.time()-t0:.0f}s  成功 {len(ok)}/{len(rows)}")

    # ---------- 4. 机房 ----------
    t0 = time.time()
    ok.sort(key=lambda r: r["ttfb"])
    top = ok[:max(args.speed_top, 60)]
    with ThreadPoolExecutor(max_workers=40) as ex:
        futs = {ex.submit(cfopt.colo_probe, r["ip"], r["port"]): r for r in top}
        for fu in as_completed(futs):
            r = futs[fu]
            try:
                r["colo"], _ = fu.result()
            except Exception:
                r["colo"] = None
    print(f"[4/4] 机房归属完成 {time.time()-t0:.0f}s")

    # ---------- 5. 测速 ----------
    if not args.no_speed:
        t0 = time.time()
        cand = [r for r in ok[:args.speed_top]]
        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = {ex.submit(cfopt.speed_test, r["ip"], r["port"], 2_000_000, 12.0): r for r in cand}
            for fu in as_completed(futs):
                r = futs[fu]
                try:
                    r["mbps"] = fu.result()
                except Exception:
                    r["mbps"] = None
        print(f"[5/5] 下载测速完成 {time.time()-t0:.0f}s")

    for r in ok:
        r.setdefault("mbps", None)
        r.setdefault("colo", None)

    ok.sort(key=lambda r: r["ttfb"])

    # ---------- 输出 ----------
    print("\n" + "=" * 96)
    print("【按首字节延迟排序 前 45 名】  tcp=TCP握手ms  tls=TLS握手ms  ttfb=首字节ms")
    print("=" * 96)
    print(f'{"#":>3} {"域名":<38} {"机房":>5} {"端口":>6} {"tcp":>7} {"tls":>7} {"ttfb":>7} {"Mbps":>7}')
    print("-" * 96)
    for i, r in enumerate(ok[:45], 1):
        mb = "-" if r["mbps"] is None else f'{r["mbps"]:.1f}'
        print(f'{i:>3} {r["domain"][:38]:<38} {str(r["colo"] or "-"):>5} {r["port"]:>6} '
              f'{r["tcp"]:>7} {str(r["tls"] or "-"):>7} {r["ttfb"]:>7} {mb:>7}')

    # 按带宽排序
    speedy = [r for r in ok if r["mbps"]]
    if speedy:
        speedy.sort(key=lambda r: -r["mbps"])
        print("\n" + "=" * 96)
        print("【按实测带宽排序 前 20 名】")
        print("=" * 96)
        print(f'{"#":>3} {"域名":<38} {"机房":>5} {"端口":>6} {"ttfb":>7} {"Mbps":>8}')
        print("-" * 96)
        for i, r in enumerate(speedy[:20], 1):
            print(f'{i:>3} {r["domain"][:38]:<38} {str(r["colo"] or "-"):>5} {r["port"]:>6} '
                  f'{r["ttfb"]:>7} {r["mbps"]:>8.1f}')

    # 端口可用性统计
    from collections import Counter
    pc = Counter()
    for r in ok:
        for p in r["ports"]:
            pc[p] += 1
    print("\n【端口可用率】(成功完成 TLS 的域名中)")
    for p in PORTS:
        n = pc.get(p, 0)
        print(f"   {p:<6} {n:>4}/{len(ok)}  {n/max(len(ok),1)*100:>5.1f}%")

    csv_path = os.path.join(HERE, "bulk_result.csv")
    cols = ["domain", "ip", "colo", "port", "ports", "tcp", "tls", "ttfb", "mbps", "status"]
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in ok:
            rr = dict(r)
            rr["ports"] = "/".join(str(p) for p in r["ports"])
            w.writerow(rr)
    with open(os.path.join(HERE, "bulk_result.json"), "w", encoding="utf-8") as f:
        json.dump({"worker_host": WORKER_HOST, "ok": ok,
                   "rejected": dns_bad}, f, ensure_ascii=False, indent=1)
    print(f"\n完整结果: {csv_path}  ({len(ok)} 个可用域名)")


if __name__ == "__main__":
    main()
