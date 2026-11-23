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
        cfspeed.py --preset ips -w 你的域名
        cfspeed.py -t 1.2.3.4,example.com -w 你的域名.workers.dev
        cfspeed.py -f list.txt -r 8 -s
        cfspeed.py -c 162.159.38.0/24 -w 你的域名

内置预设(--preset):
    domains  优选域名 426 个
    tokyo    东京网段 5 个 /24
    ips      已实测可用的东京 IP
    nodes    原始订阅节点(含各自端口)

参数:
    -t, --targets   IP / 域名列表,逗号或空格分隔
    -f, --file      从文件读取(每行一个)
    -c, --cidr      扫描网段,如 162.159.38.0/24
    --preset        使用内置预设
    -w, --worker    Worker 域名(SNI 与 Host),必填,不填会提示输入
    -r, --rounds    采样轮数,默认 5
    -s, --speed     额外测下载带宽(耗时较长)
    -p, --ports     端口列表,默认 443
    -n, --threads   并发数,默认 60
    --all-ips       同一域名的多个 IP 各占一行(默认合并为一行,取最快 IP)
    --no-doh        关闭 DoH 兜底解析(默认开启,可绕过本地 DNS 污染)

v1.2 变化:
    · 同一域名的多个 A 记录合并成一行,取表现最好的 IP,其余记为备选
    · 目标去重按 (域名, IP, 端口),大小写 / 结尾点 / 域名:443 等写法归一
    · 本地解析拿不到 CF IP 时,自动用 DoH(1.1.1.1)复核,避免 DNS 污染误判
    · 淘汰原因区分:域名失效 / 确实不在 CF / 解析失败
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
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

VERSION = "1.4"
# 不内置任何 Worker 域名,运行时由用户输入或用 -w 指定
DEFAULT_WORKER = ""
TIMEOUT = 5.0

# 运行路径与结果输出目录
APP_DIR = (os.path.dirname(os.path.abspath(sys.executable))
           if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(APP_DIR, "results")
try:
    os.makedirs(RESULTS_DIR, exist_ok=True)
except Exception:
    RESULTS_DIR = APP_DIR

try:
    import presets as P
except Exception:
    P = None

# 内置预设: 名称 -> (说明, 数据)
PRESETS = {}
if P is not None:
    PRESETS = {
        "domains": (f"优选域名 ({len(P.DOMAINS)} 个)", P.DOMAINS),
        "tokyo":   (f"东京网段 ({len(P.TOKYO_NETS)} 个 /24)", P.TOKYO_NETS),
        "ips":     (f"已实测东京 IP ({len(P.TOKYO_IPS)} 个)", P.TOKYO_IPS),
        "nodes":   (f"原始订阅节点 ({len(P.NODES)} 个,含端口)", P.NODES),
    }

# ---------- Cloudflare 网段(用于判断域名是否真的走 CF) ----------
# 优先用 cf_ranges 的权威库(官网清单 ∪ AS13335, 约 475 块 / 1.9M 地址);
# 拿不到时退回官网公开的 15 段。
try:
    import cf_ranges as _R
    CF_NETS = _R.CF_NETS
    CF_RANGE_SRC = f"cf_ranges ({len(CF_NETS)} 块, 更新于 {_R.UPDATED})"

    def is_cf(ip):
        return _R.is_cf(ip)
except Exception:
    CF_NETS = [ipaddress.ip_network(n) for n in [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ]]
    CF_RANGE_SRC = f"官网 ips-v4 ({len(CF_NETS)} 块)"

    def is_cf(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in CF_NETS)

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
# is_cf 已在上方按 cf_ranges 定义(带官网 15 段兜底)


def normalize_host(h):
    """
    统一域名写法,避免同一个目标因写法不同被当成两个:
    " Example.COM. " / "EXAMPLE.com" / "https://example.com/x" → "example.com"
    """
    s = str(h).strip().strip('"').strip("'").lower()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/")[0]
    if s.startswith("[") and "]" in s:      # [IPv6]:port
        s = s[1:s.index("]")]
    s = s.rstrip(".")                        # FQDN 结尾点
    try:
        if any(ord(ch) > 127 for ch in s):   # 中文域名 → punycode,便于去重
            s = s.encode("idna").decode("ascii")
    except Exception:
        pass
    return s


def is_ip_literal(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def resolve(host, limit=None):
    """系统 DNS 解析。limit=None 表示取全部 A 记录(过滤前不截断)"""
    if is_ip_literal(host):
        return [host]
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
            if limit and len(out) >= limit:
                break
    return out


DOH_ENDPOINTS = [
    "https://223.5.5.5/resolve",            # 阿里公共 DNS (无需 SNI 依赖, 支持 IP 直连, 国内高可用)
    "https://dns.alidns.com/resolve",       # 阿里公共 DNS 域名入口
    "https://doh.pub/dns-query",            # 腾讯 DNSPod
    "https://cloudflare-dns.com/dns-query", # Cloudflare 官方 DoH (境外直连兜底)
]
_DOH_CACHE = {}


def doh_resolve(host, timeout=3.5):
    """
    DNS over HTTPS 解析, 绕过本地 DNS 污染。
    采用多源 DoH 策略(国内高可用源优先, 规避 1.1.1.1 在国内阻断),
    返回 A 记录列表; 全部失败返回 None(与"查到了但为空"区分开)。
    """
    if host in _DOH_CACHE:
        return _DOH_CACHE[host]
    got, ok = [], False
    for base in DOH_ENDPOINTS:
        try:
            url = f"{base}?name={urllib.parse.quote(host)}&type=A"
            req = urllib.request.Request(url, headers={
                "accept": "application/dns-json",
                "User-Agent": f"cfspeed/{VERSION}"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                j = json.load(r)
            ok = True
            for a in j.get("Answer", []):
                if a.get("type") == 1:
                    ip = str(a.get("data", "")).strip()
                    if ip and ip not in got:
                        got.append(ip)
            if got:
                break
        except Exception:
            continue
    res = got if ok else None
    _DOH_CACHE[host] = res
    return res


def resolve_cf(host, limit=2, use_doh=True):
    """
    拿到这个目标的 CF IP 列表。
    返回 (ips, via_doh, reason):
        ips      可用的 CF IP(已按 limit 截断)
        via_doh  是否靠 DoH 才拿到的(说明本地解析被污染)
        reason   拿不到时的原因
    """
    local = resolve(host)
    if not local:
        # 本地一条 A 记录都没有:可能是污染,也可能域名真挂了
        if use_doh and not is_ip_literal(host):
            alt = doh_resolve(host)
            if alt:
                cf = [ip for ip in alt if is_cf(ip)]
                if cf:
                    return cf[:limit], True, ""
                return [], False, f"非 Cloudflare IP ({alt[0]})"
        return [], False, "DNS 解析失败"

    cf = [ip for ip in local if is_cf(ip)]
    if cf:
        return cf[:limit], False, ""

    # 本地有解析但都不在 CF 段:先怀疑污染,用 DoH 复核
    if use_doh and not is_ip_literal(host):
        alt = doh_resolve(host)
        if alt:
            cf2 = [ip for ip in alt if is_cf(ip)]
            if cf2:
                return cf2[:limit], True, ""
            return [], False, f"不在 CF 段 (本地 {local[0]} / DoH {alt[0]})"
        return [], False, f"非 Cloudflare IP ({local[0]})"

    return [], False, f"非 Cloudflare IP ({local[0]})"


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


def speed_test(ip, port, nbytes=25_000_000, timeout=12.0, max_duration=5.0):
    """
    经 speed.cloudflare.com 测这个 IP 的真实下行带宽(Mbps)。
    采用时间窗口与自适应字节测速：
    - 高速连接充分利用数据量克服 TCP 慢启动
    - 慢速连接在达到 max_duration (默认 5s) 时自动截断，避免长时间卡死
    - 排除 TLS 握手时间，只计算纯数据传输阶段的真实速率
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["http/1.1"])
        ss = ctx.wrap_socket(s, server_hostname="speed.cloudflare.com")
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
        t0 = time.perf_counter()
        ss.settimeout(3.0)
        while total < nbytes:
            if time.perf_counter() - t0 >= max_duration:
                break
            try:
                ch = ss.recv(131072)
                if not ch:
                    break
                total += len(ch)
            except Exception:
                break
        el = time.perf_counter() - t0
        try:
            ss.close()
        except Exception:
            pass
        if total < 200_000 or el <= 0.05:
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


def build_targets(items):
    """
    统一解析目标,返回 [(host, port 或 None), ...]
    支持: IP、域名、IP:端口、域名:端口、网段(CIDR)
    写法归一 + 去重:大小写、结尾点、协议前缀、路径、域名:443 都视为同一目标
    """
    out, seen = [], set()
    for raw in items:
        s = str(raw).strip()
        if not s or s.startswith("#"):
            continue

        # 网段
        if "/" in s:
            spec = s
            if "://" in spec:
                spec = spec.split("://", 1)[1]
            try:
                ipaddress.ip_network(spec, strict=False)
                for ip in expand_cidr(spec):
                    if (ip, None) not in seen:
                        seen.add((ip, None))
                        out.append((ip, None))
                continue
            except ValueError:
                pass

        host, port = normalize_host(s), None
        if host.count(":") == 1:              # IPv4:port 或 域名:port
            h, _, p = host.rpartition(":")
            if p.isdigit():
                host, port = h, int(p)

        if not host:
            continue
        key = (host, port)
        if key not in seen:
            seen.add(key)
            out.append((host, port))
    return out


# ---------- 结果合并 ----------
def merge_rows(rows):
    """
    同一域名 + 同一端口可能解析出多个 CF IP,各测了一遍。
    这里合并成一行: 优先取丢包率低且延迟表现最好的 IP 作为主结果, 其余记入备选。
    返回 (合并后的行, {目标: [(ip, 中位, 丢包率), ...]})
    """
    groups = {}
    for r in rows:
        groups.setdefault((r["target"].lower(), r["port"]), []).append(r)

    out, alts = [], {}
    for grp in groups.values():
        grp.sort(key=lambda r: (not r["ok"],
                                r.get("loss_rate", 1.0),
                                r["med"] if r["med"] is not None else float("inf")))
        best = dict(grp[0])
        others = [(r["ip"], r["med"], r.get("loss_pct", 0)) for r in grp[1:]]
        best["alt_ips"] = others
        best["ip_count"] = len(grp)
        if others:
            alts[best["target"]] = others
        out.append(best)
    return out, alts


# ---------- 客户端配置生成与导出 ----------
def top_lines(good, n):
    """取前 n 名,生成 ip:port#机房 形式(可直接粘进客户端)"""
    return [f"{r['ip']}:{r['port']}#{r['colo'] or '-'}" for r in good[:n]]


def generate_clash_meta(rows, worker, uuid="11111111-1111-1111-1111-111111111111", ws_path="/"):
    uuid = str(uuid).strip() or "11111111-1111-1111-1111-111111111111"
    ws_path = str(ws_path).strip() or "/"
    if not ws_path.startswith("/"):
        ws_path = "/" + ws_path

    L = [
        "# ========================================================",
        "# 由 cfspeed 生成的 Clash.Meta / Mihomo 优选节点配置片段",
        f"# 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Worker 域名: {worker}",
        "# 可直接复制 proxies / proxy-groups 内容到你的 Clash 配置文件中",
        "# ========================================================",
        "",
        "proxies:",
    ]
    node_names = []
    for i, r in enumerate(rows, 1):
        colo = r.get("colo") or "CF"
        name = f"CF-{colo}-{i:02d}-{r['ip']}"
        node_names.append(f'"{name}"')
        L.append(f'  - name: "{name}"')
        L.append("    type: vless")
        L.append(f"    server: {r['ip']}")
        L.append(f"    port: {r['port']}")
        L.append(f'    uuid: "{uuid}"')
        L.append("    udp: true")
        L.append("    tls: true")
        L.append(f"    servername: {worker}")
        L.append("    client-fingerprint: chrome")
        L.append("    network: ws")
        L.append("    ws-opts:")
        L.append(f'      path: "{ws_path}"')
        L.append("      headers:")
        L.append(f"        Host: {worker}")
        L.append("")

    L.append("proxy-groups:")
    L.append("  - name: CF-AUTO")
    L.append("    type: url-test")
    L.append(f"    proxies: [{', '.join(node_names)}]")
    L.append("    url: https://www.gstatic.com/generate_204")
    L.append("    interval: 300")
    L.append("    tolerance: 50")
    L.append("")
    return "\n".join(L) + "\n"


def generate_sing_box(rows, worker, uuid="11111111-1111-1111-1111-111111111111", ws_path="/"):
    uuid = str(uuid).strip() or "11111111-1111-1111-1111-111111111111"
    ws_path = str(ws_path).strip() or "/"
    if not ws_path.startswith("/"):
        ws_path = "/" + ws_path

    outbounds = []
    tags = []
    for i, r in enumerate(rows, 1):
        colo = r.get("colo") or "CF"
        tag = f"CF-{colo}-{i:02d}-{r['ip']}"
        tags.append(tag)
        outbounds.append({
            "type": "vless",
            "tag": tag,
            "server": r["ip"],
            "server_port": r["port"],
            "uuid": uuid,
            "tls": {
                "enabled": True,
                "server_name": worker,
                "utls": {
                    "enabled": True,
                    "fingerprint": "chrome"
                }
            },
            "transport": {
                "type": "ws",
                "path": ws_path,
                "headers": {
                    "Host": worker
                }
            }
        })

    outbounds.append({
        "type": "urltest",
        "tag": "CF-AUTO",
        "outbounds": tags,
        "url": "https://www.gstatic.com/generate_204",
        "interval": "5m",
        "tolerance": 50
    })

    return json.dumps({"outbounds": outbounds}, ensure_ascii=False, indent=2) + "\n"


def generate_vless_links(rows, worker, uuid="11111111-1111-1111-1111-111111111111", ws_path="/"):
    uuid = str(uuid).strip() or "11111111-1111-1111-1111-111111111111"
    ws_path = str(ws_path).strip() or "/"
    if not ws_path.startswith("/"):
        ws_path = "/" + ws_path

    lines = []
    for i, r in enumerate(rows, 1):
        colo = r.get("colo") or "CF"
        tag = f"CF-{colo}-{i:02d}-{r['ip']}"
        q = urllib.parse.urlencode({
            "encryption": "none",
            "security": "tls",
            "sni": worker,
            "fp": "chrome",
            "type": "ws",
            "host": worker,
            "path": ws_path,
        })
        link = f"vless://{uuid}@{r['ip']}:{r['port']}?{q}#{urllib.parse.quote(tag)}"
        lines.append(link)
    return "\n".join(lines) + "\n"


def save_top(good, n, out_dir, worker="", uuid="", ws_path="/", export_all=True):
    ts = time.strftime('%Y%m%d_%H%M%S')
    files_saved = []

    # 1. 经典文本
    path_txt = os.path.join(out_dir, f"top{n}_{ts}.txt")
    lines = top_lines(good, n)
    with open(path_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    files_saved.append(("纯文本列表", path_txt))

    if export_all and worker:
        # 2. Clash.Meta / Mihomo
        path_clash = os.path.join(out_dir, f"clash_meta_top{n}_{ts}.yaml")
        with open(path_clash, "w", encoding="utf-8") as f:
            f.write(generate_clash_meta(good[:n], worker, uuid, ws_path))
        files_saved.append(("Clash.Meta配置", path_clash))

        # 3. Sing-box
        path_sb = os.path.join(out_dir, f"sing_box_top{n}_{ts}.json")
        with open(path_sb, "w", encoding="utf-8") as f:
            f.write(generate_sing_box(good[:n], worker, uuid, ws_path))
        files_saved.append(("Sing-box配置", path_sb))

        # 4. VLESS 直链
        path_vless = os.path.join(out_dir, f"vless_links_top{n}_{ts}.txt")
        with open(path_vless, "w", encoding="utf-8") as f:
            f.write(generate_vless_links(good[:n], worker, uuid, ws_path))
        files_saved.append(("VLESS直链列表", path_vless))

    return files_saved, lines


def run(targets, worker, rounds, do_speed, ports, threads,
        all_ips=False, use_doh=True, max_ips=2, export_n=0, uuid="", ws_path="/"):
    """
    do_speed:
        True  直接测带宽
        False 不测
        None  等连通性测完再问(交互模式用这个)
    """
    t_start = time.time()
    interactive_mode = (do_speed is None)
    print()
    print(bold(f"Worker 域名 (SNI/Host): {worker}"))
    speed_txt = (" | 含带宽测试" if do_speed else
                 (" | 带宽测试待定" if do_speed is None else ""))
    print(bold(f"目标 {len(targets)} 个 | 采样 {rounds} 轮 | 端口 {','.join(map(str, ports))}"
               + speed_txt
               + (" | 每个 IP 单列" if all_ips else " | 同域名合并")))
    print(gray(f"CF 网段库: {CF_RANGE_SRC}"))
    print()

    # 1. 解析(并发,避免几百个域名串行解析拖时间)
    items = []          # (显示名, ip, 端口)
    rejected = []
    fixed = []          # 靠 DoH 才救回来的
    seen_items = set()
    seen_rej = set()

    def _resolve_one(entry):
        t, tport = entry if isinstance(entry, tuple) else (entry, None)
        ips, via_doh, why = resolve_cf(t, limit=max_ips, use_doh=use_doh)
        return t, tport, ips, via_doh, why

    with ThreadPoolExecutor(max_workers=min(32, max(1, len(targets)))) as ex:
        resolved = list(ex.map(_resolve_one, targets))

    for t, tport, ips, via_doh, why in resolved:
        if not ips:
            if t not in seen_rej:
                seen_rej.add(t)
                rejected.append((t, why or "解析失败"))
            continue
        if via_doh:
            fixed.append(t)
        plist = [tport] if tport else ports
        for ip in ips:
            for p in plist:
                key = (t.lower(), ip, p)
                if key in seen_items:      # 同一 (域名, IP, 端口) 只测一次
                    continue
                seen_items.add(key)
                items.append((t, ip, p))

    if fixed:
        print(gray(f"DoH 复核救回 {len(fixed)} 个目标(本地 DNS 被污染):"))
        for t in fixed[:8]:
            print(gray(f"   {t}"))
        if len(fixed) > 8:
            print(gray(f"   ... 另有 {len(fixed)-8} 个"))
        print()

    if rejected:
        print(gray(f"淘汰 {len(rejected)} 个目标:"))
        for t, why in rejected[:10]:
            print(gray(f"   {t}  —  {why}"))
        if len(rejected) > 10:
            print(gray(f"   ... 另有 {len(rejected)-10} 个"))
        print()

    if not items:
        print(red("没有可测试的目标。"))
        return 1

    # 2. TCP 快筛
    print(gray("阶段 1  TCP 连通性 ..."))
    alive = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(tcp_probe, ip, p): (t, ip, p) for t, ip, p in items}
        for fu in as_completed(futs):
            r = fu.result()
            if r is not None:
                alive.append(futs[fu])
    print(gray(f"          通过 {len(alive)}/{len(items)}\n"))

    if not alive:
        print(red("全部连不上。请检查网络,或确认端口没被封。"))
        return 1

    # 3. 多轮采样(轮内随机顺序,消除位置偏差)
    print(gray(f"阶段 2  TLS + 首字节,共 {rounds} 轮 ..."))
    samples = {k: [] for k in alive}
    meta = {}
    rng = random.Random()
    par = min(24, max(1, len(alive)))

    def one(key):
        t, ip, p = key
        return key, http_probe(ip, p, worker)

    for rd in range(rounds):
        order = alive[:]
        rng.shuffle(order)
        with ThreadPoolExecutor(max_workers=par) as ex:
            for key, r in ex.map(one, order):
                meta[key] = r
                if r["ok"]:
                    samples[key].append(r["ttfb"])
        progress(f"{rd+1}/{rounds}")
    clear_progress()

    rows = []
    for key, vals in samples.items():
        t, ip, p = key
        m = meta.get(key, {})
        ok_n = len(vals)
        loss_rate = (rounds - ok_n) / rounds
        loss_pct = round(loss_rate * 100)

        # 丢包率判定规则:
        # 全部超时/失败
        if ok_n == 0:
            rows.append({"target": t, "ip": ip, "port": p, "ok": False,
                         "colo": m.get("colo"), "med": None, "min": None,
                         "sd": None, "mbps": None, "n": 0, "rounds": rounds,
                         "loss_rate": 1.0, "loss_pct": 100,
                         "note": m.get("note") or "全部请求超时/失败"})
            continue

        # 丢包率超过 50%: 视为不可用节点, 代理环境极其卡顿
        if loss_rate > 0.5:
            rows.append({"target": t, "ip": ip, "port": p, "ok": False,
                         "colo": m.get("colo"), "med": statistics.median(vals),
                         "min": min(vals),
                         "sd": statistics.pstdev(vals) if ok_n > 1 else 0.0,
                         "mbps": None, "n": ok_n, "rounds": rounds,
                         "loss_rate": loss_rate, "loss_pct": loss_pct,
                         "note": f"丢包率过高 ({loss_pct}%)"})
            continue

        # 正常可用节点
        rows.append({"target": t, "ip": ip, "port": p, "ok": True,
                     "colo": m.get("colo"), "med": statistics.median(vals),
                     "min": min(vals),
                     "sd": statistics.pstdev(vals) if ok_n > 1 else 0.0,
                     "mbps": None, "n": ok_n, "rounds": rounds,
                     "loss_rate": loss_rate, "loss_pct": loss_pct,
                     "note": ""})

    # 同一域名(同端口)可能解析出多个 CF IP:合并成一行,取丢包少且延迟低的 IP
    merged_alt = {}
    if not all_ips:
        rows, merged_alt = merge_rows(rows)

    good = [r for r in rows if r["ok"]]
    # 优先按丢包率升序, 其次按中位数延迟升序
    good.sort(key=lambda r: (r.get("loss_rate", 1.0), r["med"]))

    # 连通性与首字节都测完了,这时候才问要不要测带宽
    speed_top = 10
    if do_speed is None:
        if good:
            topn = min(10, len(good))
            print()
            print(gray(f"连通性测完:可用 {len(good)} 个,"
                       f"最多可以测前 {topn} 名的下载带宽(串行,每个约 3~6 秒)"))
            try:
                ans = input("是否测下载带宽?[y/N]: ").strip().lower()
            except EOFError:
                ans = ""
            do_speed = ans in ("y", "yes", "是")
            if do_speed and topn > 1:
                try:
                    t = input(f"测前几名(1~{topn})[{topn}]: ").strip()
                except EOFError:
                    t = ""
                if t.isdigit() and 1 <= int(t) <= topn:
                    speed_top = int(t)
                else:
                    speed_top = topn
        else:
            do_speed = False

    # 4. 带宽(只测前若干名,串行避免抢带宽)
    if do_speed and good:
        topn = min(speed_top, len(good))
        print()
        print(gray(f"阶段 3  下载带宽,串行测前 {topn} 名 ..."))
        for i, r in enumerate(good[:topn], 1):
            r["mbps"] = speed_test(r["ip"], r["port"])
            progress(f"{i}/{topn}  {r['ip']}  "
                     f"{(str(r['mbps'])+' Mbps') if r['mbps'] else '失败'}")
        clear_progress(60)

    # ---------- 输出 ----------
    print()
    print("=" * 82)
    print(bold(" 结果(按丢包率与首字节延迟排序)"))
    print("=" * 82)
    hdr = (pad("#", 3, ">") + " " + pad("目标", 22) + pad("IP", 16) +
           pad("机房", 5, ">") + pad("端口", 6, ">") + pad("丢包", 6, ">") +
           pad("中位", 7, ">") + pad("最快", 7, ">") + pad("抖动", 6, ">") +
           pad("带宽", 9, ">"))
    print(hdr)
    print("-" * 82)
    show = good[:40]
    for i, r in enumerate(show, 1):
        mb = f'{r["mbps"]:.1f}' if r["mbps"] else "-"
        loss_str = f"{r.get('loss_pct', 0)}%"
        line = (pad(i, 3, ">") + " " + pad(r["target"][:21], 22) + pad(r["ip"], 16) +
                pad(r["colo"] or "-", 5, ">") + pad(r["port"], 6, ">") +
                pad(loss_str, 6, ">") +
                pad(f'{r["med"]:.0f}', 7, ">") + pad(f'{r["min"]:.0f}', 7, ">") +
                pad(f'{r["sd"]:.0f}', 6, ">") + pad(mb, 9, ">"))
        if r["loss_pct"] == 0 and r["med"] < 300:
            print(green(line))
        elif r["loss_pct"] <= 20 and r["med"] < 600:
            print(line)
        else:
            print(yellow(line))
    if len(good) > len(show):
        print(gray(f"… 其余 {len(good)-len(show)} 个可用结果见 CSV"))

    if merged_alt:
        shown = [r for r in good if r["target"] in merged_alt][:6]
        if shown:
            print()
            print(gray(f"同名多 IP 已合并 {len(merged_alt)} 个(每行取丢包最少/最快 IP,其余为备选):"))
            for r in shown:
                alt = "  ".join(
                    f"{ip}({f'{med:.0f}ms' if med is not None else '不可用'}"
                    + (f",{loss}%丢包" if loss > 0 else "") + ")"
                    for ip, med, loss in r["alt_ips"][:3])
                print(gray(f"   {pad(r['target'][:21], 22)}{r['ip']}  ← 另 {alt}"))
            if len(merged_alt) > len(shown):
                print(gray(f"   ... 另有 {len(merged_alt)-len(shown)} 个,见 CSV 的备选 IP 列"))

    bad = [r for r in rows if not r["ok"]]
    if bad:
        print()
        print(gray(f"不可用 {len(bad)} 个:"))
        for r in bad[:8]:
            loss_note = f"丢包 {r.get('loss_pct', 100)}%, " if r.get("loss_pct", 0) > 0 else ""
            print(gray(f"   {r['target']} ({r['ip']}:{r['port']})  —  {loss_note}{r['note']}"))

    if good:
        colos = {}
        for r in good:
            colos[r["colo"]] = colos.get(r["colo"], 0) + 1
        print()
        print("机房分布: " + "  ".join(f"{k} {v}个" for k, v in
                                    sorted(colos.items(), key=lambda x: -x[1])))
        best = good[0]
        print(bold(f"最优: {best['ip']}:{best['port']}  ({best['colo']})  "
                   f"丢包 {best.get('loss_pct', 0)}%  中位 {best['med']:.0f}ms"))
        if len(good) >= 3:
            print(gray("提示:前几名差距常在噪声范围内,建议挑 2~3 个轮换使用。"))

    # ---------- 存盘 (自动保存至 results/ 目录) ----------
    out = os.path.join(RESULTS_DIR, f"cfspeed_{time.strftime('%Y%m%d_%H%M%S')}.csv")
    try:
        with open(out, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["目标", "IP", "端口", "机房", "丢包率", "中位延迟ms", "最快ms",
                        "抖动ms", "带宽Mbps", "有效样本", "总轮数", "可用", "备注",
                        "IP数", "备选IP"])
            for r in good + bad:
                alts = " ".join(
                    f"{ip}({f'{med:.0f}ms' if med is not None else '不可用'})"
                    for item in r.get("alt_ips", [])
                    for ip, med in [(item[0], item[1])])
                w.writerow([r["target"], r["ip"], r["port"], r["colo"] or "",
                            f"{r.get('loss_pct', 0)}%",
                            f'{r["med"]:.0f}' if r["med"] is not None else "",
                            f'{r["min"]:.0f}' if r["min"] is not None else "",
                            f'{r["sd"]:.0f}' if r["sd"] is not None else "",
                            r["mbps"] or "", r.get("n", 0), r.get("rounds", rounds),
                            "是" if r["ok"] else "否", r["note"],
                            r.get("ip_count", 1), alts])
        print(gray(f"\n结果已保存: {out}"))
    except Exception as e:
        print(yellow(f"\n保存失败: {e}"))

    print(gray(f"总耗时 {time.time()-t_start:.0f}s"))

    # 命令行自动导出配置
    if not interactive_mode and export_n > 0 and good:
        n = min(export_n, len(good))
        try:
            saved, lines = save_top(good, n, RESULTS_DIR, worker=worker, uuid=uuid, ws_path=ws_path, export_all=True)
            print(bold(f"\n已自动导出前 {n} 名客户端配置:"))
            for desc, fpath in saved:
                print(green(f"  √ {pad(desc, 14)}: {fpath}"))
        except Exception as e:
            print(red(f"\n自动导出配置失败: {e}"))

    # ---------- 交互模式收尾:导出前几名 ----------
    if interactive_mode:
        base = RESULTS_DIR
        while good:
            print()
            print(bold(f"可用 {len(good)} 个。要导出前几名?(直接回车结束)"))
            try:
                sel = input("前几名: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not sel:
                break
            if not sel.isdigit() or int(sel) <= 0:
                print(red("请输入正整数,例如 5"))
                continue
            n = min(int(sel), len(good))

            print(gray("导出选项: [1] 经典纯文本(ip:port#机房)  [2] 全套客户端配置(Clash.Meta + Sing-box + VLESS直链 + 文本)"))
            fmt = input("选择 [2]: ").strip() or "2"
            export_all = (fmt == "2")

            in_uuid = ""
            in_path = "/"
            if export_all:
                print(gray("提示: 可输入你的 Worker UUID (留空使用占位符 11111111-1111-1111-1111-111111111111):"))
                in_uuid = input("UUID: ").strip()
                in_path = input("WS Path [/]: ").strip() or "/"

            try:
                saved, lines = save_top(good, n, base, worker=worker, uuid=in_uuid, ws_path=in_path, export_all=export_all)
            except Exception as e:
                print(red(f"导出失败: {e}"))
                continue
            print()
            print(bold(f"前 {n} 名(ip:端口#机房):"))
            for i, ln in enumerate(lines, 1):
                print("  " + pad(i, 2, ">") + "  " + ln)
            print()
            for desc, fpath in saved:
                print(green(f"  √ {pad(desc, 14)}: {fpath}"))
        print()
        try:
            input(gray("按回车退出 ..."))
        except (EOFError, KeyboardInterrupt):
            pass

    return 0


def split_text(text):
    return [x for x in text.replace(",", "\n").replace(";", "\n").split("\n") if x.strip()]


def _host_of(item):
    """取出 'ip:port' / '域名:port' 里的主机部分"""
    s = str(item).strip()
    if s.count(":") == 1:
        h, _, p = s.rpartition(":")
        if p.isdigit():
            return h
    return s


def preset_groups():
    """
    交互模式只暴露两个大入口: 全部域名 / 全部 IP。
    返回 [(名称, 说明, 原始目标列表), ...]
    """
    if P is None:
        return []

    groups = [("全部域名", f"{len(P.DOMAINS)} 个优选域名", list(P.DOMAINS))]

    ips = list(P.TOKYO_IPS)
    for spec in P.TOKYO_NETS:
        try:
            ips.extend(expand_cidr(spec))
        except Exception:
            pass
    # 订阅节点里写成字面 IP 的,连自带端口一起带上
    node_ips = [x for x in P.NODES if is_ip_literal(_host_of(x))]
    ips.extend(node_ips)

    uniq = len(build_targets(ips))
    desc = (f"{uniq} 个唯一 IP(实测 {len(P.TOKYO_IPS)} + "
            f"网段 {len(P.TOKYO_NETS)}×254 + 节点 {len(node_ips)},已去重)")
    groups.append(("全部 IP", desc, ips))
    return groups


def choose_preset():
    groups = preset_groups()
    if not groups:
        print(red("预设数据缺失。"))
        return []
    print()
    print("预设内容:")
    for i, (name, desc, _) in enumerate(groups, 1):
        print(f"  [{i}] {pad(name, 10)}{gray(desc)}")
    sel = input("选择 [1]: ").strip() or "1"
    if not sel.isdigit() or not (1 <= int(sel) <= len(groups)):
        print(red("无效选择。"))
        return []
    name, desc, raw = groups[int(sel) - 1]
    print(gray(f"已选: {name} — {desc}"))
    targets = build_targets(raw)
    if len(targets) > 400:
        print(gray(f"提示: {len(targets)} 个目标偏多,采样轮数建议给 1~2,否则耗时较长。"))
    return targets


def interactive():
    print()
    print(bold("=" * 56))
    print(bold("  CF 优选测速器  v" + VERSION))
    print(bold("=" * 56))
    print(gray("测 IP / 域名在你当前网络下的真实质量"))
    print()

    print(gray("Worker 域名用于 TLS SNI 和 HTTP Host,必须填你自己的"))
    worker = input("Worker 域名(SNI/Host): ").strip()
    if not worker:
        print(red("必须填写 Worker 域名,否则无法验证该 IP 是否服务你的域名。"))
        return 1
    worker = normalize_host(worker)

    print()
    print("输入方式:")
    items = []
    if PRESETS:
        items.append(("预设", "使用内置预设(全部域名 / 全部 IP)"))
    items.append(("粘贴", "直接粘贴 IP 或域名,多行,空行结束"))
    items.append(("文件", "从文件读取,每行一个"))
    items.append(("网段", "扫描网段,如 162.159.38.0/24"))
    for i, (_, desc) in enumerate(items, 1):
        print(f"  [{i}] {desc}")
    sel = input("选择 [1]: ").strip() or "1"
    kind = items[int(sel) - 1][0] if (sel.isdigit() and 1 <= int(sel) <= len(items)) else items[0][0]

    targets = []
    if kind == "预设":
        targets = choose_preset()
        if not targets:
            return 1
    elif kind == "文件":
        path = input("文件路径: ").strip().strip('"')
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                targets = build_targets(split_text(f.read()))
        except Exception as e:
            print(red(f"读取失败: {e}"))
            return 1
    elif kind == "网段":
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
        rounds = int(input("采样轮数 [5]: ").strip() or "5")
    except ValueError:
        rounds = 5
    rounds = max(1, min(rounds, 30))

    ptxt = input("端口 [443]: ").strip() or "443"
    try:
        ports = [int(x) for x in ptxt.replace(",", " ").split() if x.isdigit()]
    except Exception:
        ports = [443]
    if not ports:
        ports = [443]

    # do_speed=None: 等连通性测完、看到有多少可用之后再问要不要测带宽
    return run(targets, worker, rounds, None, ports, 60)


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
    ap.add_argument("-w", "--worker", default=DEFAULT_WORKER, help="Worker 域名(SNI/Host)")
    ap.add_argument("-r", "--rounds", type=int, default=5, help="采样轮数")
    ap.add_argument("-s", "--speed", action="store_true", help="测下载带宽")
    ap.add_argument("-p", "--ports", default="443", help="端口,如 443,2096")
    ap.add_argument("-n", "--threads", type=int, default=60, help="并发数")
    ap.add_argument("--all-ips", action="store_true",
                    help="同一域名的多个 IP 各占一行(默认合并为一行)")
    ap.add_argument("--no-doh", action="store_true",
                    help="关闭 DoH 兜底解析(默认开启,可绕过本地 DNS 污染)")
    ap.add_argument("--max-ips", type=int, default=2,
                    help="每个目标最多测几个 IP,默认 2")
    ap.add_argument("--uuid", default="", help="Worker/VLESS 节点的 UUID (用于导出客户端配置)")
    ap.add_argument("--ws-path", default="/", help="WebSocket 路径, 默认 /")
    ap.add_argument("-e", "--export", type=int, default=0,
                    help="自动导出前 N 名的客户端配置文件到 results/ 目录")
    ap.add_argument("-v", "--version", action="version", version=f"cfspeed {VERSION}")
    args = ap.parse_args()

    # Windows 控制台编码兜底
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    try:
        if not (args.targets or args.file or args.cidr or args.preset):
            rc = interactive()
            if rc:
                # 双击运行时窗口不能一闪而过,出错也要停住让你看清原因
                print()
                try:
                    input(gray("按回车退出 ..."))
                except (EOFError, KeyboardInterrupt):
                    pass
            return rc

        if not args.worker:
            print(red("请用 -w 指定 Worker 域名(SNI/Host),例如 -w your-worker.workers.dev"))
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
        ports = [int(x) for x in args.ports.replace(",", " ").split() if x.isdigit()] or [443]
        return run(targets, args.worker, max(1, args.rounds), args.speed, ports, args.threads,
                   all_ips=args.all_ips, use_doh=not args.no_doh,
                   max_ips=max(1, args.max_ips),
                   export_n=args.export, uuid=args.uuid, ws_path=args.ws_path)
    except KeyboardInterrupt:
        print(yellow("\n已取消。"))
        return 130


if __name__ == "__main__":
    sys.exit(main())
