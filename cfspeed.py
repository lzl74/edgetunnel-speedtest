#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CF 优选测速器 (cfspeed)
========================
测 Cloudflare Worker / edgetunnel 的优选 IP 与优选域名在你本地网络上的真实质量。

为什么不用 ping:TCP 握手快不代表好用。真正的指标是
  TLS 握手 → HTTP 首字节 → 实际下载带宽 → 落点机房(CF-RAY)
本工具全部测,并且多轮采样取中位数,避免单次运气骗人。

用法:
    双击运行(交互式)     直接跑,按提示输入
    命令行:
        cfspeed.py --preset domains -w 你的域名
        cfspeed.py -t 1.2.3.4,example.com -w 你的域名.workers.dev
        cfspeed.py -f list.txt -r 8 -s
        cfspeed.py -c 162.159.38.0/24 -w 你的域名

内置预设(--preset):
    domains  优选域名列表(426 个)
    cidrs    Cloudflare 网段池(抽样扫描)

参数:
    -t, --targets   IP / 域名列表,逗号或空格分隔
    -f, --file      从文件读取(每行一个)
    -c, --cidr      扫描网段,如 162.159.38.0/24
    --preset        使用内置预设
    -w, --worker    Worker 域名(SNI 与 Host),必填
    -r, --rounds    采样轮数,默认 1
    -s, --speed     额外测下载带宽(交互模式会在测速后询问)
    -p, --ports     端口池,默认 all=每个目标随机 1 个端口
    -n, --threads   并发数,默认 60

交互模式流程:
    输入目标 → 测延迟/机房 → 出结果(可直接复制的 域名:端口 列表)
    → 询问是否测下载带宽 → 输入测前几名 → 输出带帽数值的最终结果
    结果同时保存 CSV 和 TXT 报告
"""
import argparse
import csv
import ipaddress
import json
import os
import random
import socket
import ssl
import statistics
import sys
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed

VERSION = "1.4"
DEFAULT_WORKER = ""          # 不预设任何域名，必须由使用者自己指定
TIMEOUT = 5.0

# Cloudflare 支持 HTTPS 的端口(全套);默认从中随机,每个目标 1 个
ALL_PORTS = [443, 2053, 2083, 2087, 2096, 8443]

# 本地配置(记录上次填的 Worker 域名,不进入版本库)
CFG_PATH = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "cfspeed.cfg")

try:
    import presets as P
except Exception:
    P = None

# 内置预设: 名称 -> (说明, 数据, 是否抽样扫描)
PRESETS = {}
if P is not None:
    if getattr(P, "DOMAINS", None):
        PRESETS["domains"] = (f"优选域名 ({len(P.DOMAINS)} 个)", P.DOMAINS, False)
    if getattr(P, "IPS", None):
        PRESETS["ips"] = (f"指定 IP ({len(P.IPS)} 个)", P.IPS, False)
    if getattr(P, "CIDRS", None):
        PRESETS["cidrs"] = (f"Cloudflare 网段 ({len(P.CIDRS)} 个,抽样扫描,较慢)", P.CIDRS, True)

# ---------- Cloudflare 官方 IPv4 网段(用于判断域名是否真的走 CF) ----------
CF_NETS = [ipaddress.ip_network(n) for n in [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]]

# ---------- 终端颜色 ----------
def _enable_ansi():
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
        return True
    except Exception:
        return False


USE_COLOR = _enable_ansi() and sys.stdout.isatty()


def c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def green(t):  return c(t, "32")
def yellow(t): return c(t, "33")
def red(t):    return c(t, "31")
def gray(t):   return c(t, "90")
def bold(t):   return c(t, "1")


# ---------- 中英混排对齐 ----------
def dwidth(s):
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in str(s))


def pad(s, width, align="<"):
    s = str(s)
    gap = max(0, width - dwidth(s))
    if align == ">":
        return " " * gap + s
    if align == "^":
        left = gap // 2
        return " " * left + s + " " * (gap - left)
    return s + " " * gap


def progress(text):
    """交互终端原地刷新;管道输出时逐行打印,避免 \\r 残留"""
    line = gray("          " + text)
    if sys.stdout.isatty():
        print(line, end="\r", flush=True)
    else:
        print(line, flush=True)


def clear_progress(width=60):
    if sys.stdout.isatty():
        print(" " * width, end="\r", flush=True)


# ---------- 网络探测 ----------
def is_cf(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in CF_NETS)


def resolve(host, limit=2):
    try:
        socket.inet_aton(host)
        return [host]
    except OSError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except Exception:
        return []
    out, seen = [], set()
    for i in infos:
        ip = i[4][0]
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
        if len(out) >= limit:
            break
    return out


def tcp_probe(ip, port, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        s.connect((ip, port))
        return (time.perf_counter() - t0) * 1000
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def http_probe(ip, port, worker, timeout=TIMEOUT):
    """
    一次完整探测。返回 dict:
        ok       是否真正可用(200 + 有 CF-RAY)
        status   HTTP 状态码
        colo     机房代码(取自 CF-RAY 后缀)
        tls      TLS 握手毫秒
        ttfb     首字节毫秒
        note     失败原因
    """
    r = {"ok": False, "status": None, "colo": None, "tls": None, "ttfb": None, "note": ""}
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
    except Exception as e:
        r["note"] = "连接失败"
        try:
            s.close()
        except Exception:
            pass
        return r

    try:
        t0 = time.perf_counter()
        try:
            ss = ctx.wrap_socket(s, server_hostname=worker)
        except ssl.SSLCertVerificationError:
            r["note"] = "证书不匹配(该 IP 不服务此域名)"
            return r
        r["tls"] = (time.perf_counter() - t0) * 1000

        t1 = time.perf_counter()
        ss.sendall(f"GET / HTTP/1.1\r\nHost: {worker}\r\nUser-Agent: cfspeed/{VERSION}\r\n"
                   f"Accept: */*\r\nConnection: close\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = ss.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 16384:
                break
        r["ttfb"] = (time.perf_counter() - t1) * 1000
        try:
            ss.close()
        except Exception:
            pass

        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
        if not head or not head[0].startswith("HTTP/"):
            r["note"] = "无 HTTP 响应"
            return r
        try:
            r["status"] = int(head[0].split()[1])
        except Exception:
            return r
        ray = None
        for line in head[1:]:
            if line.lower().startswith("cf-ray:"):
                ray = line.split(":", 1)[1].strip()
        if ray and "-" in ray:
            r["colo"] = ray.rsplit("-", 1)[-1]
        if r["status"] == 200 and r["colo"]:
            r["ok"] = True
        elif not r["colo"]:
            r["note"] = f"HTTP {r['status']} 且无 CF-RAY(不是有效边缘)"
        else:
            r["note"] = f"HTTP {r['status']}"
        return r
    except Exception as e:
        r["note"] = f"{type(e).__name__}"
        return r
    finally:
        try:
            s.close()
        except Exception:
            pass


def speed_test(ip, port, nbytes=5_000_000, timeout=20.0):
    """经 speed.cloudflare.com 测这个 IP 的真实下行带宽(Mbps)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["http/1.1"])
        ss = ctx.wrap_socket(s, server_hostname="speed.cloudflare.com")
        t0 = time.perf_counter()
        ss.sendall(f"GET /__down?bytes={nbytes} HTTP/1.1\r\n"
                   f"Host: speed.cloudflare.com\r\nUser-Agent: cfspeed/{VERSION}\r\n"
                   f"Connection: close\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            ch = ss.recv(4096)
            if not ch:
                break
            buf += ch
        body = buf.split(b"\r\n\r\n", 1)[-1]
        total = len(body)
        ss.settimeout(4.0)
        while total < nbytes:
            try:
                ch = ss.recv(262144)
            except Exception:
                break
            if not ch:
                break
            total += len(ch)
        el = time.perf_counter() - t0
        ss.close()
        if total < 200_000:
            return None
        return round(total * 8 / el / 1_000_000, 2)
    except Exception:
        return None


# ---------- 目标解析 ----------
def expand_cidr(spec, per_net=24):
    net = ipaddress.ip_network(spec, strict=False)
    if net.prefixlen >= 24:
        base, size = int(net.network_address), net.num_addresses
        return [str(ipaddress.IPv4Address(base + o)) for o in range(1, size - 1)]
    subs = list(net.subnets(new_prefix=24))
    out = []
    for sub in subs:
        base = int(sub.network_address)
        picks = random.sample(range(1, 255), min(per_net, 254))
        out.extend(str(ipaddress.IPv4Address(base + o)) for o in picks)
    return out


def sample_net(net, k):
    """从网段里随机取 k 个 IP"""
    size = net.num_addresses
    if size <= 2:
        return []
    k = min(k, size - 2)
    base = int(net.network_address)
    return [str(ipaddress.IPv4Address(base + o))
            for o in random.sample(range(1, size - 1), k)]


def build_targets(items, sample_cidr=False, per_net=1, cap=1200):
    """
    统一解析目标,返回 [(host, port 或 None), ...]
    支持: IP、域名、IP:端口、域名:端口、网段(CIDR)
    sample_cidr=True 时每个网段只随机抽 per_net 个 IP,总量不超过 cap
    """
    out, seen = [], set()
    src = list(items)
    if sample_cidr:
        random.shuffle(src)          # 打乱后取,保证各网段覆盖均匀

    for raw in src:
        s = str(raw).strip()
        if not s or s.startswith("#"):
            continue

        # 网段
        if "/" in s:
            try:
                net = ipaddress.ip_network(s, strict=False)
            except ValueError:
                net = None
            if net is not None:
                ips = sample_net(net, per_net) if sample_cidr else expand_cidr(s)
                for ip in ips:
                    if (ip, None) not in seen:
                        seen.add((ip, None))
                        out.append((ip, None))
                if sample_cidr and len(out) >= cap:
                    break
                continue

        if "://" in s:
            s = s.split("://", 1)[1]
        s = s.split("/")[0]

        port = None
        if s.count(":") == 1:
            h, _, p = s.rpartition(":")
            if p.isdigit():
                s, port = h, int(p)

        key = (s.lower(), port)
        if s and key not in seen:
            seen.add(key)
            out.append((s, port))
    return out


# ---------- 带宽测试 ----------
def run_speed_batch(good, topn):
    """串行测前 topn 名的下载带宽,直接修改 good 列表中的 mbps 字段"""
    if not good or topn <= 0:
        return
    topn = min(topn, len(good))
    print(gray(f"阶段 3/3  下载带宽,串行测前 {topn} 名 ..."))
    for i, r in enumerate(good[:topn], 1):
        r["mbps"] = speed_test(r["ip"], r["port"])
        progress(f"{i}/{topn}  {r['ip']}:{r['port']}  "
                 f"{(str(r['mbps'])+' Mbps') if r['mbps'] else '失败'}")
    clear_progress(60)


# ---------- 主流程 ----------
def run(targets, worker, rounds, ports, threads):
    t_start = time.time()
    print()
    print(bold(f"Worker 域名 (SNI/Host): {worker}"))
    print(bold(f"目标 {len(targets)} 个 | 采样 {rounds} 轮 | 端口池 {','.join(map(str, ports))}(每个目标随机1个)"))
    print()

    # 1. 解析
    items = []          # (显示名, ip, 端口)
    rejected = []
    n_total = len(targets)
    for idx, entry in enumerate(targets, 1):
        t, tport = entry if isinstance(entry, tuple) else (entry, None)
        progress(f"解析 {idx}/{n_total}  {t}")
        ips = resolve(t)
        if not ips:
            rejected.append((t, "DNS 解析失败"))
            continue
        good = [ip for ip in ips if is_cf(ip)]
        if not good:
            rejected.append((t, f"非 Cloudflare IP ({ips[0]})"))
            continue
        plist = [tport] if tport else [random.choice(ports)]
        for ip in good[:2]:
            for p in plist:
                items.append((t, ip, p))
    clear_progress()

    if rejected:
        print(gray(f"淘汰 {len(rejected)} 个目标:"))
        for t, why in rejected[:10]:
            print(gray(f"   {t}  —  {why}"))
        if len(rejected) > 10:
            print(gray(f"   ... 另有 {len(rejected)-10} 个"))
        print()

    if not items:
        print(red("没有可测试的目标。"))
        return None

    # 2. TCP 快筛
    print(gray(f"阶段 1/3  TCP 连通性 ({len(items)} 个) ..."))
    alive = []
    tcp_done = 0
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(tcp_probe, ip, p): (t, ip, p) for t, ip, p in items}
        for fu in as_completed(futs):
            r = fu.result()
            tcp_done += 1
            progress(f"TCP {tcp_done}/{len(items)}")
            if r is not None:
                alive.append(futs[fu])
    clear_progress()
    print(gray(f"          通过 {len(alive)}/{len(items)}\n"))

    if not alive:
        print(red("全部连不上。请检查网络,或确认端口没被封。"))
        return None

    # 3. 多轮采样(轮内随机顺序,消除位置偏差)
    n_alive = len(alive)
    print(gray(f"阶段 2/3  TLS + 首字节,共 {rounds} 轮 × {n_alive} 个 ..."))
    samples = {k: [] for k in alive}
    meta = {}
    rng = random.Random()
    par = min(24, max(1, n_alive))

    for rd in range(rounds):
        order = alive[:]
        rng.shuffle(order)
        done_rd = 0
        with ThreadPoolExecutor(max_workers=par) as ex:
            futs = {ex.submit(http_probe, ip, p, worker): key for key in order for t, ip, p in [key]}
            for fu in as_completed(futs):
                key = futs[fu]
                r = fu.result()
                done_rd += 1
                progress(f"轮 {rd+1}/{rounds}  {done_rd}/{n_alive}")
                meta[key] = r
                if r["ok"]:
                    samples[key].append(r["ttfb"])
        clear_progress()
        print(gray(f"          轮 {rd+1}/{rounds} 完成"))

    rows = []
    need = min(rounds, max(2, rounds // 3))
    for key, vals in samples.items():
        t, ip, p = key
        m = meta.get(key, {})
        if len(vals) < need:
            rows.append({"target": t, "ip": ip, "port": p, "ok": False,
                         "colo": m.get("colo"), "med": None, "min": None,
                         "sd": None, "mbps": None, "n": len(vals),
                         "note": m.get("note") or "可用次数太少"})
            continue
        rows.append({"target": t, "ip": ip, "port": p, "ok": True,
                     "colo": m.get("colo"), "med": statistics.median(vals),
                     "min": min(vals),
                     "sd": statistics.pstdev(vals) if len(vals) > 1 else 0.0,
                     "mbps": None, "n": len(vals), "note": ""})

    good = [r for r in rows if r["ok"]]
    good.sort(key=lambda r: r["med"])
    bad = [r for r in rows if not r["ok"]]
    return good, bad, rows, t_start


def show_results(good, bad, worker, rounds, ports, do_speed, t_start, out_dir):
    """打印结果表格、机房统计、可复制列表,并保存 CSV/TXT"""
    print()
    print("=" * 78)
    print(bold(" 结果(按首字节延迟排序)"))
    print("=" * 78)
    hdr = (pad("#", 3, ">") + " " + pad("目标", 24) + pad("IP", 17) +
           pad("机房", 6, ">") + pad("端口", 6, ">") + pad("中位", 8, ">") +
           pad("最快", 8, ">") + pad("抖动", 7, ">") + pad("带宽", 9, ">"))
    print(hdr)
    print("-" * 78)
    show = good[:40]
    for i, r in enumerate(show, 1):
        mb = f'{r["mbps"]:.1f}' if r["mbps"] else "-"
        line = (pad(i, 3, ">") + " " + pad(r["target"][:23], 24) + pad(r["ip"], 17) +
                pad(r["colo"] or "-", 6, ">") + pad(r["port"], 6, ">") +
                pad(f'{r["med"]:.0f}', 8, ">") + pad(f'{r["min"]:.0f}', 8, ">") +
                pad(f'{r["sd"]:.0f}', 7, ">") + pad(mb, 9, ">"))
        if r["med"] < 300:
            print(green(line))
        elif r["med"] < 600:
            print(line)
        else:
            print(yellow(line))
    if len(good) > len(show):
        print(gray(f"… 其余 {len(good)-len(show)} 个可用结果见 CSV"))

    if bad:
        print()
        print(gray(f"不可用 {len(bad)} 个:"))
        for r in bad[:8]:
            print(gray(f"   {r['target']} ({r['ip']}:{r['port']})  —  {r['note']}"))

    if good:
        colos = {}
        for r in good:
            colos[r["colo"]] = colos.get(r["colo"], 0) + 1
        print()
        print("机房分布: " + "  ".join(f"{k} {v}个" for k, v in
                                    sorted(colos.items(), key=lambda x: -x[1])))
        best = good[0]
        print(bold(f"最优: {best['ip']}:{best['port']}  ({best['colo']})  "
                   f"中位 {best['med']:.0f}ms"))
        if len(good) >= 3:
            print(gray("提示:前几名差距常在噪声范围内,建议挑 2~3 个轮换使用。"))

        # 可直接复制使用的地址列表
        print()
        print("-" * 78)
        print(bold(" 可直接复制使用(域名/IP:端口)"))
        print("-" * 78)
        for r in good[:20]:
            print(f"{r['target']}:{r['port']}")

    # ---------- 存盘 ----------
    out = os.path.join(out_dir, f"cfspeed_{time.strftime('%Y%m%d_%H%M%S')}.csv")
    try:
        with open(out, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["目标", "IP", "端口", "机房", "中位延迟ms", "最快ms",
                        "抖动ms", "带宽Mbps", "有效样本", "可用", "备注"])
            for r in good + bad:
                w.writerow([r["target"], r["ip"], r["port"], r["colo"] or "",
                            f'{r["med"]:.0f}' if r["med"] else "",
                            f'{r["min"]:.0f}' if r["min"] else "",
                            f'{r["sd"]:.0f}' if r["sd"] else "",
                            r["mbps"] or "", r["n"], "是" if r["ok"] else "否", r["note"]])
        print(gray(f"\n结果已保存: {out}"))
    except Exception as e:
        print(yellow(f"\n保存失败: {e}"))

    _save_txt(good, bad, worker, rounds, ports, do_speed, t_start, out_dir)

    print(gray(f"总耗时 {time.time()-t_start:.0f}s"))


def _save_txt(good, bad, worker, rounds, ports, do_speed, t_start, out_dir):
    """同时写一份人类可读的 txt 报告"""
    txt = os.path.join(out_dir, f"cfspeed_{time.strftime('%Y%m%d_%H%M%S')}.txt")
    lines = []
    lines.append("=" * 70)
    lines.append("  CF 优选测速结果")
    lines.append("=" * 70)
    lines.append(f"Worker:   {worker}")
    lines.append(f"目标:     {len(good) + len(bad)} 个")
    lines.append(f"端口池:   {','.join(map(str, ports))} (每个目标随机1个)")
    lines.append(f"采样轮数: {rounds}")
    lines.append(f"带宽测试: {'是' if do_speed else '否'}")
    lines.append("")

    if good:
        lines.append("-" * 70)
        lines.append(f"{'#':>3} {'目标':24} {'IP':17} {'机房':6} {'端口':>5} {'中位ms':>7} {'最快ms':>7} {'抖动ms':>7} {'带宽Mbps':>9}")
        lines.append("-" * 70)
        for i, r in enumerate(good, 1):
            mb = f'{r["mbps"]:.1f}' if r["mbps"] else "-"
            lines.append(
                f"{i:>3} {r['target'][:24]:24} {r['ip']:17} {r['colo'] or '-':6} "
                f"{r['port']:>5} {r['med']:>7.0f} {r['min']:>7.0f} {r['sd']:>7.0f} {mb:>9}"
            )
        lines.append("")

        colos = {}
        for r in good:
            colos[r["colo"]] = colos.get(r["colo"], 0) + 1
        lines.append("机房分布: " + "  ".join(f"{k} {v}个" for k, v in
                                            sorted(colos.items(), key=lambda x: -x[1])))
        best = good[0]
        lines.append(f"最优: {best['ip']}:{best['port']}  ({best['colo']})  中位 {best['med']:.0f}ms")
        lines.append("")

        lines.append("-" * 70)
        lines.append(" 可直接复制使用(域名/IP:端口)")
        lines.append("-" * 70)
        for r in good[:20]:
            lines.append(f"{r['target']}:{r['port']}")
        lines.append("")

    if bad:
        lines.append(f"不可用 {len(bad)} 个:")
        for r in bad[:20]:
            lines.append(f"   {r['target']} ({r['ip']}:{r['port']})  —  {r['note']}")
        lines.append("")

    lines.append(f"总耗时 {time.time()-t_start:.0f}s")
    lines.append("=" * 70)

    try:
        with open(txt, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(gray(f"文本报告: {txt}"))
    except Exception as e:
        print(yellow(f"文本报告保存失败: {e}"))


def split_text(text):
    return [x for x in text.replace(",", "\n").replace(";", "\n").split("\n") if x.strip()]


def load_cfg():
    try:
        with open(CFG_PATH, encoding="utf-8") as f:
            d = {}
            for line in f:
                if "=" in line:
                    k, v = line.split("=", 1)
                    d[k.strip()] = v.strip()
            return d
    except Exception:
        return {}


def save_cfg(d):
    try:
        with open(CFG_PATH, "w", encoding="utf-8") as f:
            for k, v in d.items():
                f.write(f"{k}={v}\n")
    except Exception:
        pass


def parse_ports(text):
    t = (text or "").strip().lower()
    if not t or t in ("all", "全部", "*", "a", "random", "rand", "r", "随机"):
        # 默认即随机:返回全部端口池,每个目标在 run() 里单独随机抽 1 个
        return list(ALL_PORTS)
    out = []
    for x in t.replace(",", " ").replace("，", " ").split():
        if x.isdigit() and int(x) not in out:
            out.append(int(x))
    return out or list(ALL_PORTS)


def expand_preset(name):
    label, data, sample = PRESETS[name]
    print(gray(f"已选: {label}"))
    return build_targets(data, sample_cidr=sample)


def choose_preset():
    keys = list(PRESETS)
    print()
    print("内置预设:")
    for i, k in enumerate(keys, 1):
        print(f"  [{i}] {PRESETS[k][0]}")
    sel = input(f"选择 [1]: ").strip() or "1"
    if not sel.isdigit() or not (1 <= int(sel) <= len(keys)):
        print(red("无效选择。"))
        return []
    return expand_preset(keys[int(sel) - 1])


def interactive():
    try:
        return _interactive()
    except KeyboardInterrupt:
        print(yellow("\n已取消。"))
        return 130
    except Exception:
        import traceback
        print(red("\n程序出错,详细信息:"))
        traceback.print_exc()
        return 1


def _interactive():
    print()
    print(bold("=" * 56))
    print(bold("  CF 优选测速器  v" + VERSION))
    print(bold("=" * 56))
    print(gray("测 IP / 域名在你当前网络下的真实质量"))
    print()

    cfg = load_cfg()
    saved = cfg.get("worker", "").strip()
    if saved:
        worker = input(f"Worker 域名(SNI/Host)[{saved}]: ").strip() or saved
    else:
        worker = ""
        while not worker:
            worker = input("Worker 域名(SNI/Host,必填,如 xxx.cfpages.dev): ").strip()
            if not worker:
                print(red("  必须填写你自己的 Worker 域名,例如 xxx.cfpages.dev"))
    if worker != saved:
        save_cfg({"worker": worker})
        print(gray(f"  已记住,下次直接回车即可(保存在 {os.path.basename(CFG_PATH)})"))

    print()
    print("输入方式:")
    if PRESETS:
        print("  [1] 使用内置预设")
    print("  [2] 直接粘贴 IP 或域名(多行,空行结束)")
    print("  [3] 从文件读取")
    print("  [4] 扫描网段(如 162.159.38.0/24)")
    mode = input("选择 [1]: ").strip() or "1"

    targets = []
    if mode == "1" and PRESETS:
        targets = choose_preset()
        if not targets:
            return 1
    elif mode == "3":
        path = input("文件路径: ").strip().strip('"')
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                targets = build_targets(split_text(f.read()))
        except Exception as e:
            print(red(f"读取失败: {e}"))
            return 1
    elif mode == "4":
        spec = input("网段: ").strip()
        try:
            targets = build_targets([spec])
        except Exception as e:
            print(red(f"网段格式不对: {e}"))
            return 1
    else:
        print(gray("粘贴 IP 或域名,每行一个,直接回车结束:"))
        lines = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if not line.strip():
                break
            lines.append(line)
        targets = build_targets(split_text("\n".join(lines)))

    if not targets:
        print(red("没有输入任何目标。"))
        return 1

    try:
        rounds = int(input("采样轮数 [1]: ").strip() or "1")
    except ValueError:
        rounds = 1
    rounds = max(1, min(rounds, 30))

    print(gray("端口池: " + " ".join(str(p) for p in ALL_PORTS) + " (默认随机:每个目标随机1个;可指定,如 443,2053)"))
    ports = parse_ports(input("端口 [随机]: "))

    out_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    result = run(targets, worker, rounds, ports, 60)
    if result is None:
        return 1
    good, bad, rows, t_start = result
    show_results(good, bad, worker, rounds, ports, False, t_start, out_dir)

    if good:
        ans = input("\n是否继续测下载带宽?[y/N]: ").strip().lower()
        if ans in ("y", "yes", "是"):
            try:
                topn = int(input(f"测前几名?(最多 {len(good)} 个)[10]: ").strip() or "10")
            except ValueError:
                topn = 10
            topn = max(1, min(topn, len(good)))
            run_speed_batch(good, topn)
            show_results(good, bad, worker, rounds, ports, True, t_start, out_dir)

    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Cloudflare 优选 IP/域名 测速器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="不带参数运行即为交互模式")
    ap.add_argument("-t", "--targets", help="IP/域名列表,逗号或空格分隔")
    ap.add_argument("-f", "--file", help="从文件读取目标")
    ap.add_argument("-c", "--cidr", help="扫描网段,如 162.159.38.0/24")
    ap.add_argument("--preset", choices=(list(PRESETS) if PRESETS else None),
                    help="使用内置预设: " + " / ".join(PRESETS) if PRESETS else "无预设")
    ap.add_argument("-w", "--worker", default=os.environ.get("CF_WORKER", ""),
                    help="Worker 域名(SNI/Host),必填,也可用环境变量 CF_WORKER")
    ap.add_argument("-r", "--rounds", type=int, default=1, help="采样轮数,默认 1")
    ap.add_argument("-s", "--speed", action="store_true", help="测下载带宽")
    ap.add_argument("-p", "--ports", default="all",
                    help="端口池,默认 all=每个目标随机 1 个: "
                         + " ".join(str(p) for p in ALL_PORTS))
    ap.add_argument("-n", "--threads", type=int, default=60, help="并发数")
    ap.add_argument("-v", "--version", action="version", version=f"cfspeed {VERSION}")
    args = ap.parse_args()

    # Windows 控制台编码兜底
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    try:
        if not (args.targets or args.file or args.cidr or args.preset):
            return interactive()

        if not args.worker:
            print(red("缺少 -w 参数:必须指定你自己的 Worker 域名。"))
            print(gray("  例如: cfspeed.py --preset domains -w abc.workers.dev"))
            return 1

        if args.preset:
            if not PRESETS:
                print(red("预设数据缺失。"))
                return 1
            print(gray(f"使用预设: {PRESETS[args.preset][0]}"))
            targets = build_targets(PRESETS[args.preset][1])
        elif args.file:
            with open(args.file, "r", encoding="utf-8-sig") as f:
                targets = build_targets(split_text(f.read()))
        elif args.cidr:
            targets = build_targets([args.cidr])
        else:
            targets = build_targets(split_text(args.targets))

        if not targets:
            print(red("没有有效目标。"))
            return 1
        ports = parse_ports(args.ports)
        out_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        result = run(targets, args.worker, max(1, args.rounds), ports, args.threads)
        if result is None:
            return 1
        good, bad, rows, t_start = result
        if args.speed and good:
            run_speed_batch(good, min(10, len(good)))
        show_results(good, bad, args.worker, args.rounds, ports, args.speed, t_start, out_dir)
        return 0
    except KeyboardInterrupt:
        print(yellow("\n已取消。"))
        return 130


if __name__ == "__main__":
    try:
        rc = main()
    except Exception as e:
        print(red(f"程序异常: {e}"))
        rc = 1
    # Windows 双击运行时窗口会立即关闭,加暂停让用户看到结果
    if os.name == "nt" and len(sys.argv) == 1:
        try:
            input("\n按回车键退出...")
        except (KeyboardInterrupt, EOFError):
            pass
    sys.exit(rc)
