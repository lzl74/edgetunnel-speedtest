#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_variants.py : 把 edgetunnel 订阅里的同一个节点,按 nodes.txt 里的每个优选地址
                   展开成多个独立节点,方便在客户端里"一键测速"做端到端对比。

用法:
    python make_variants.py --sub https://你的域名/xxxx        # 直接给订阅链接
    python make_variants.py --sub sub.txt                       # 或给本地订阅文件
    python make_variants.py --sub sub.txt --nodes nodes.txt     # 指定优选列表

产出(同目录):
    variants_sub.txt    base64 订阅文件 -> v2rayN / NekoBox / Shadowrocket 导入
    variants_plain.txt  明文节点列表    -> 手动导入 / 转二维码
    clash.yaml          Clash / mihomo 配置,自带 url-test 分组
"""
import argparse
import base64
import os
import re
import sys
import urllib.request
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

HERE = os.path.dirname(os.path.abspath(__file__))


def load_sub(src):
    if src.startswith("http://") or src.startswith("https://"):
        req = urllib.request.Request(src, headers={"User-Agent": "clash-meta/1.0"})
        raw = urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "ignore")
    else:
        with open(src, "r", encoding="utf-8-sig") as f:
            raw = f.read()
    raw = raw.strip()
    if "://" not in raw:                       # 是 base64
        pad = "=" * (-len(raw) % 4)
        try:
            raw = base64.b64decode(raw + pad).decode("utf-8", "ignore")
        except Exception:
            pass
    links = [l.strip() for l in raw.splitlines() if l.strip().startswith("vless://")]
    if not links:
        sys.exit("订阅里没找到 vless:// 节点,请确认订阅内容")
    return links


def parse_link(link):
    u = urlparse(link)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    return {
        "uuid": u.username,
        "host": u.hostname,
        "port": u.port or 443,
        "params": q,
        "name": (u.fragment or "node"),
        "query": u.query,
    }


def build_link(tpl, host, port, name):
    q = tpl["params"].copy()
    q.setdefault("security", "tls")
    q.setdefault("sni", tpl["host"])          # SNI 必须保持 Worker 域名
    q.setdefault("host", tpl["host"])         # WS Host 同理
    query = urlencode(q, safe="")
    return f'vless://{tpl["uuid"]}@{host}:{port}?{query}#{name}'


def load_candidates(path):
    out = []
    with open(path, "r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            head = line.split("$")[0]
            addr, _, comment = head.partition("#")
            addr, comment = addr.strip(), comment.strip()
            if not addr:
                continue
            host, port = addr, 443
            if ":" in addr:
                h, _, p = addr.rpartition(":")
                if p.isdigit():
                    host, port = h, int(p)
            out.append((host, port, comment or addr))
    # 去重
    seen, uniq = set(), []
    for h, p, c in out:
        if (h.lower(), p) in seen:
            continue
        seen.add((h.lower(), p))
        uniq.append((h, p, c))
    return uniq


def clash_yaml(nodes, tpl):
    L = []
    L.append("# 由 make_variants.py 生成 —— 每个优选地址一个独立节点,可直接测速对比")
    L.append("mixed-port: 7890")
    L.append("allow-lan: false")
    L.append("mode: rule")
    L.append("log-level: info")
    L.append("")
    L.append("proxies:")
    for name, host, port in nodes:
        q = tpl["params"]
        path = q.get("path", "/")
        L.append(f"  - name: \"{name}\"")
        L.append("    type: vless")
        L.append(f"    server: {host}")
        L.append(f"    port: {port}")
        L.append(f"    uuid: {tpl['uuid']}")
        L.append("    udp: true")
        L.append("    tls: true")
        L.append(f"    servername: {tpl['host']}")
        L.append(f"    client-fingerprint: {q.get('fp', 'chrome')}")
        L.append("    network: ws")
        L.append("    ws-opts:")
        L.append(f"      path: \"{path}\"")
        L.append("      headers:")
        L.append(f"        Host: {q.get('host', tpl['host'])}")
    L.append("")
    names = ", ".join(f'"{n}"' for n, _, _ in nodes)
    L.append("proxy-groups:")
    L.append("  - name: AUTO")
    L.append("    type: url-test")
    L.append(f"    proxies: [{names}]")
    L.append("    url: https://www.gstatic.com/generate_204")
    L.append("    interval: 300")
    L.append("    tolerance: 50")
    L.append("  - name: PROXY")
    L.append("    type: select")
    L.append(f"    proxies: [{names}]")
    L.append("")
    L.append("rules:")
    L.append("  - MATCH,PROXY")
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sub", required=True, help="订阅链接或本地订阅文件")
    ap.add_argument("--nodes", default=os.path.join(HERE, "nodes.txt"))
    ap.add_argument("--tag", default="", help="节点名前缀")
    args = ap.parse_args()

    links = load_sub(args.sub)
    # 优先选 ws + tls 的节点做模板
    tpl = None
    for l in links:
        p = parse_link(l)
        if p["params"].get("type") == "ws":
            tpl = p
            break
    tpl = tpl or parse_link(links[0])
    print(f"模板节点: {tpl['name']}  uuid={tpl['uuid'][:8]}...  ws path={tpl['params'].get('path')}")

    cands = load_candidates(args.nodes)
    print(f"优选地址: {len(cands)} 个\n")

    plain, nodes = [], []
    for host, port, comment in cands:
        short = re.sub(r"\[.*?\]", "", comment).strip() or f"{host}:{port}"
        name = f'{args.tag}{short} [{host}:{port}]'
        plain.append(build_link(tpl, host, port, name))
        nodes.append((name, host, port))
        print(f"  + {name}")

    with open(os.path.join(HERE, "variants_plain.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(plain) + "\n")
    b64 = base64.b64encode("\n".join(plain).encode()).decode()
    with open(os.path.join(HERE, "variants_sub.txt"), "w", encoding="utf-8") as f:
        f.write(b64)
    with open(os.path.join(HERE, "clash.yaml"), "w", encoding="utf-8") as f:
        f.write(clash_yaml(nodes, tpl))

    print(f"\n已生成:")
    print(f"  {os.path.join(HERE, 'variants_sub.txt')}    <- 客户端导入这个(base64 订阅)")
    print(f"  {os.path.join(HERE, 'variants_plain.txt')}  <- 明文节点列表")
    print(f"  {os.path.join(HERE, 'clash.yaml')}          <- Clash / mihomo 配置")


if __name__ == "__main__":
    main()
