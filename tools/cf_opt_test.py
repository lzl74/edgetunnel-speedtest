#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cf-opt-test : 测试 edgetunnel / Cloudflare Worker 优选地址在你本地网络上的真实质量

用法:
    python cf_opt_test.py                 # 测 TCP + TLS + HTTP 首字节
    python cf_opt_test.py --speed         # 额外测真实下载速度(2MB)
    python cf_opt_test.py -n 8            # 每个地址采样 8 次
    python cf_opt_test.py -f other.txt    # 指定节点列表文件

节点列表格式(直接粘贴订阅里的节点行即可):
    cdn.7zz.cn:2096#备注
    172.64.150.120:2053#备注
    你的域名#备注$socks5://user:pass@1.2.3.4:1080      <- 链式节点,会单独测出口服务器
"""
import argparse
import csv
import json
import os
import socket
import ssl
import statistics
import sys
import time
from urllib.parse import urlparse

# edgetunnel 的 Worker 域名: TLS 握手时的 SNI 必须是它,证书才对得上
WORKER_HOST = os.environ.get("CF_WORKER", "").strip()
if not WORKER_HOST:
    sys.exit("请先指定你的 Worker 域名(用于 TLS SNI / HTTP Host); Windows 用 set CF_WORKER=你的域名, macOS/Linux 用 export CF_WORKER=你的域名")
HTTP_PATH = "/"
TIMEOUT = 5.0


# ---------------------------------------------------------------- 解析节点列表
def parse_nodes(path):
    cdn, chains = [], []
    with open(path, "r", encoding="utf-8-sig") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # 格式: address#备注$scheme://user:pass@host:port   (注意 $ 在 # 之后)
            head, sep, chain = line.partition("$")
            addr, _, comment = head.partition("#")
            addr, comment = addr.strip(), comment.strip()

            if sep and chain.strip():
                u = urlparse(chain.strip())
                if u.hostname:
                    chains.append({
                        "kind": "chain",
                        "label": comment or chain,
                        "scheme": u.scheme,
                        "host": u.hostname,
                        "port": u.port or (443 if u.scheme in ("https", "sstp") else 1080),
                        "entry": addr,
                    })
                # 入口地址本身也是要测的 CF 边缘
                if addr:
                    h, p = split_host_port(addr)
                    cdn.append({"kind": "cdn", "label": comment or addr,
                                "host": h, "port": p, "raw": addr})
                continue

            h, p = split_host_port(addr)
            cdn.append({"kind": "cdn", "label": comment or addr,
                        "host": h, "port": p, "raw": addr})
    return cdn, chains


def split_host_port(s):
    host, port = s, 443
    if ":" in s:
        h, _, p = s.rpartition(":")
        if p.isdigit():
            host, port = h, int(p)
    return host, port


# ---------------------------------------------------------------- 测量原语
def resolve(host):
    try:
        socket.inet_aton(host)
        return host, 0.0
    except OSError:
        pass
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        ip = infos[0][4][0]
        return ip, (time.perf_counter() - t0) * 1000
    except Exception:
        return None, None


def tcp_connect(ip, port, timeout=TIMEOUT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    s.connect((ip, port))
    dt = (time.perf_counter() - t0) * 1000
    return s, dt


def tls_handshake(sock, sni, ip=None, port=None, timeout=TIMEOUT):
    """返回 (tls_sock, 握手毫秒, 证书是否有效, 协商协议)"""
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    sock.settimeout(timeout)
    verified = True
    t0 = time.perf_counter()
    try:
        ss = ctx.wrap_socket(sock, server_hostname=sni)
    except ssl.SSLCertVerificationError:
        verified = False
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        ctx2.set_alpn_protocols(["http/1.1"])
        try:
            sock.close()
        except Exception:
            pass
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.settimeout(timeout)
        s2.connect((ip, port))
        t0 = time.perf_counter()
        ss = ctx2.wrap_socket(s2, server_hostname=sni)
    dt = (time.perf_counter() - t0) * 1000
    return ss, dt, verified, ss.selected_alpn_protocol() or "http/1.1"


def http_probe(ss, host, path="/", timeout=TIMEOUT):
    """发一个 HTTP/1.1 请求,返回 (状态码, 首字节毫秒, 响应头dict, 已读body字节)"""
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: cf-opt-test\r\n"
           f"Accept: */*\r\nConnection: close\r\n\r\n")
    t0 = time.perf_counter()
    ss.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = ss.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    ttfb = (time.perf_counter() - t0) * 1000
    head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    lines = head.split("\r\n")
    status = 0
    if lines and lines[0].startswith("HTTP/"):
        try:
            status = int(lines[0].split()[1])
        except Exception:
            pass
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            headers[k.strip().lower()] = v.strip()
    body = buf.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in buf else b""
    return status, ttfb, headers, body


def drain(ss, already, timeout=TIMEOUT):
    """读完剩余 body,返回总字节数"""
    total = len(already)
    ss.settimeout(timeout)
    while True:
        try:
            chunk = ss.recv(65536)
        except (socket.timeout, ssl.SSLError, OSError):
            break
        if not chunk:
            break
        total += len(chunk)
    return total


def colo_probe(ip, port, timeout=6.0):
    """
    查这个 IP 实际把你送进了哪个 Cloudflare 机房。
    先试 Worker 域名的 /cdn-cgi/trace;拿不到就退回 speed.cloudflare.com
    (同一张边缘网络,colo 结论一致)。
    """
    for sni in (WORKER_HOST, "speed.cloudflare.com"):
        try:
            sock, _ = tcp_connect(ip, port, timeout=timeout)
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["http/1.1"])
            ss = ctx.wrap_socket(sock, server_hostname=sni)
            req = (f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {sni}\r\n"
                   f"User-Agent: cf-opt-test\r\nConnection: close\r\n\r\n")
            ss.sendall(req.encode())
            data = b""
            ss.settimeout(4.0)
            while True:
                try:
                    c = ss.recv(8192)
                except (socket.timeout, ssl.SSLError, OSError):
                    break
                if not c:
                    break
                data += c
                if len(data) > 65536:
                    break
            ss.close()
            txt = data.decode("utf-8", "ignore")
            colo = loc = None
            for line in txt.splitlines():
                if line.startswith("colo="):
                    colo = line.split("=", 1)[1].strip()
                elif line.startswith("loc="):
                    loc = line.split("=", 1)[1].strip()
            if colo:
                return colo, loc
        except Exception:
            continue
    return None, None


def speed_test(ip, port, nbytes=5_000_000, timeout=20.0):
    """
    用 speed.cloudflare.com 的下行接口测这个 IP 的真实吞吐。
    这是同一张 Cloudflare 边缘网络,测的是「这个 IP 到你家宽带」的管道宽度,
    跟你的 Worker 走的是同一条链路,所以排名可以直接参考。
    """
    try:
        sock, _ = tcp_connect(ip, port, timeout=timeout)
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["http/1.1"])
        ss = ctx.wrap_socket(sock, server_hostname="speed.cloudflare.com")
        req = (f"GET /__down?bytes={nbytes} HTTP/1.1\r\n"
               f"Host: speed.cloudflare.com\r\nUser-Agent: cf-opt-test\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n")
        t0 = time.perf_counter()
        ss.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = ss.recv(4096)
            if not c:
                break
            buf += c
        head, _, body = buf.partition(b"\r\n\r\n")
        total = len(body)
        ss.settimeout(4.0)
        while total < nbytes:
            try:
                c = ss.recv(262144)
            except (socket.timeout, ssl.SSLError, OSError):
                break
            if not c:
                break
            total += len(c)
        el = time.perf_counter() - t0
        ss.close()
        if total < 200_000:
            return None
        return round(total * 8 / el / 1_000_000, 2)
    except Exception:
        return None


# ---------------------------------------------------------------- 单项测试
def test_cdn(node, samples, do_speed):
    ip, dns_ms = resolve(node["host"])
    r = {
        "label": node["label"], "target": f'{node["host"]}:{node["port"]}',
        "ip": ip, "dns_ms": round(dns_ms, 1) if dns_ms is not None else None,
        "tcp_ms": [], "tls_ms": [], "ttfb_ms": [], "status": None,
        "cert_ok": None, "alpn": None, "loss": 0, "speed_mbps": None,
        "err": None,
    }
    if not ip:
        r["err"] = "DNS 解析失败"
        r["loss"] = samples
        return r

    ok = 0
    for _ in range(samples):
        try:
            sock, tcp = tcp_connect(ip, node["port"])
            r["tcp_ms"].append(tcp)
            try:
                ss, tls, verified, alpn = tls_handshake(sock, WORKER_HOST, ip, node["port"])
                r["tls_ms"].append(tls)
                r["cert_ok"], r["alpn"] = verified, alpn
                if ok == 0:      # 只在第一次做完整 HTTP 探测
                    st, ttfb, hdrs, body = http_probe(ss, WORKER_HOST, HTTP_PATH)
                    r["status"], r["ttfb_ms"] = st, [ttfb]
                    r["server"] = hdrs.get("server", "")
                    r["cf_ray"] = "cf-ray" in hdrs
                ss.close()
                ok += 1
            except Exception as e:
                r["err"] = r["err"] or f"TLS/HTTP: {type(e).__name__}: {e}"
                try:
                    sock.close()
                except Exception:
                    pass
        except Exception as e:
            r["loss"] += 1
            r["err"] = r["err"] or f"TCP: {type(e).__name__}: {e}"
        time.sleep(0.12)

    if do_speed and r["ttfb_ms"]:
        r["speed_mbps"] = speed_test(ip, node["port"])
    if r["ttfb_ms"]:
        r["colo"], r["loc"] = colo_probe(ip, node["port"])
    return r


def test_chain(node, samples):
    """链式节点的出口服务器:只测 TCP 可达性/延迟(它本身不是 CF 边缘)"""
    ip, dns_ms = resolve(node["host"])
    r = {"label": node["label"], "target": f'{node["host"]}:{node["port"]}',
         "ip": ip, "dns_ms": round(dns_ms, 1) if dns_ms is not None else None,
         "tcp_ms": [], "tls_ms": [], "ttfb_ms": [], "status": None,
         "cert_ok": None, "alpn": None, "loss": 0, "speed_mbps": None,
         "err": None, "scheme": node["scheme"]}
    if not ip:
        r["err"] = "DNS 解析失败"
        r["loss"] = samples
        return r
    for _ in range(samples):
        try:
            sock, tcp = tcp_connect(ip, node["port"])
            r["tcp_ms"].append(tcp)
            sock.close()
        except Exception as e:
            r["loss"] += 1
            r["err"] = r["err"] or f"TCP: {type(e).__name__}"
        time.sleep(0.12)
    return r


# ---------------------------------------------------------------- 汇总打分
def summarize(r, samples):
    out = dict(r)
    tcp = r["tcp_ms"]
    if tcp:
        out["tcp_min"] = round(min(tcp), 1)
        out["tcp_med"] = round(statistics.median(tcp), 1)
        out["tcp_max"] = round(max(tcp), 1)
        out["tcp_jit"] = round(statistics.pstdev(tcp), 1) if len(tcp) > 1 else 0.0
    else:
        out["tcp_min"] = out["tcp_med"] = out["tcp_max"] = out["tcp_jit"] = None
    out["loss_pct"] = round(r["loss"] / samples * 100, 0) if samples else None
    out["tls_med"] = round(statistics.median(r["tls_ms"]), 1) if r["tls_ms"] else None
    out["ttfb"] = round(r["ttfb_ms"][0], 1) if r["ttfb_ms"] else None

    # 综合分:握手延迟为主(70%) + 抖动(30%),丢包/失败直接归零
    if out["tcp_med"] is None or out["loss_pct"] >= 50:
        out["score"] = 0.0
    else:
        base = out["ttfb"] if out["ttfb"] else (out["tcp_med"] + (out["tls_med"] or 0))
        score = 100.0 * (1 - min(base, 3000) / 3000) * 0.7 \
              + 100.0 * (1 - min(out["tcp_jit"] or 0, 200) / 200) * 0.3
        score *= (1 - out["loss_pct"] / 100)
        if r.get("cert_ok") is False:
            score *= 0.85
        out["score"] = round(score, 1)
    return out


def fmt(v, w=6):
    return "-" if v is None else str(v).rjust(w)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", "--file", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "nodes.txt"))
    ap.add_argument("-n", "--samples", type=int, default=5)
    ap.add_argument("--speed", action="store_true", help="额外测下载速度")
    ap.add_argument("--only", default=None, help="只测包含该关键字的节点")
    args = ap.parse_args()

    cdn, chains = parse_nodes(args.file)
    if args.only:
        cdn = [n for n in cdn if args.only in n["label"] or args.only in n["raw"]]
        chains = [n for n in chains if args.only in n["label"]]

    # 去重:同一 host:port 只测一次(链式节点入口都是同一个 Worker 域名,重复测没意义)
    seen, uniq = set(), []
    for n in cdn:
        key = (n["host"].lower(), n["port"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(n)

    print(f"Worker 域名(SNI/Host): {WORKER_HOST}")
    print(f"每个地址采样 {args.samples} 次,超时 {TIMEOUT}s\n")

    results = []
    for n in uniq:
        print(f"  测 {n['host']}:{n['port']} ...", end="", flush=True)
        r = summarize(test_cdn(n, args.samples, args.speed), args.samples)
        results.append(r)
        print(f" tcp={fmt(r['tcp_med'])}ms ttfb={fmt(r['ttfb'])}ms loss={r['loss_pct']:.0f}%")

    chain_res = []
    if chains:
        print()
        for n in chains:
            print(f"  测链式出口 {n['host']}:{n['port']} ({n['scheme']}) ...", end="", flush=True)
            r = summarize(test_chain(n, args.samples), args.samples)
            chain_res.append(r)
            print(f" tcp={fmt(r['tcp_med'])}ms loss={r['loss_pct']:.0f}%")

    results.sort(key=lambda x: -x["score"])
    chain_res.sort(key=lambda x: -(x["score"] or 0))

    # ---------------- 打印 CDN 排名
    print("\n" + "=" * 108)
    print("【CDN 优选地址排名】  综合分越高越好 | tcp=TCP握手 ms | tls=TLS握手 ms | ttfb=首字节 ms | jit=抖动 ms")
    print("=" * 108)
    hdr = f'{"#":>2} {"地址":<26} {"备注":<20} {"机房":>5} {"tcp":>7} {"tls":>7} {"ttfb":>7} {"jit":>6} {"丢包":>5} {"分":>5}'
    if args.speed:
        hdr += f' {"Mbps":>7}'
    print(hdr)
    print("-" * 108)
    for i, r in enumerate(results, 1):
        row = (f'{i:>2} {r["target"]:<26} {r["label"][:20]:<20} {str(r.get("colo") or "-"):>5} '
               f'{fmt(r["tcp_med"]):>7} {fmt(r["tls_med"]):>7} {fmt(r["ttfb"]):>7} '
               f'{fmt(r["tcp_jit"]):>6} {str(int(r["loss_pct"]))+"%":>5} {r["score"]:>5}')
        if args.speed:
            row += f' {fmt(r.get("speed_mbps")):>7}'
        print(row)

    if chain_res:
        print("\n" + "=" * 108)
        print("【链式代理出口服务器】  注意:这些节点入口都是同一个 Worker 域名,延迟差异来自出口服务器,必须端到端实测")
        print("=" * 108)
        print(f'{"#":>2} {"出口服务器":<40} {"类型":<8} {"tcp":>7} {"jit":>6} {"丢包":>5}')
        print("-" * 108)
        for i, r in enumerate(chain_res, 1):
            print(f'{i:>2} {r["target"]:<40} {r.get("scheme",""):<8} '
                  f'{fmt(r["tcp_med"]):>7} {fmt(r["tcp_jit"]):>6} {str(int(r["loss_pct"]))+"%":>5}')

    # ---------------- 落盘
    here = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(here, "result.csv")
    cols = ["label", "target", "ip", "colo", "tcp_min", "tcp_med", "tcp_max", "tcp_jit",
            "tls_med", "ttfb", "loss_pct", "cert_ok", "alpn", "status", "speed_mbps", "score", "err"]
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in results + chain_res:
            w.writerow(r)
    with open(os.path.join(here, "result.json"), "w", encoding="utf-8") as f:
        json.dump({"worker_host": WORKER_HOST, "cdn": results, "chain": chain_res},
                  f, ensure_ascii=False, indent=2)

    print(f"\n结果已保存: {csv_path}")
    if results:
        best = results[0]
        print(f"\n>>> 当前最优: {best['target']}  ({best['label']})  "
              f"ttfb {best['ttfb']}ms / 抖动 {best['tcp_jit']}ms")


if __name__ == "__main__":
    main()
