#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cf_ranges.py : Cloudflare 权威 IPv4/IPv6 网段库 + 网段校验 / 清洗工具
=====================================================================
为什么需要它:
    只认 Cloudflare 官网 ips-v4 的 15 个段是不够的 —— 那只是 anycast 边缘的
    公开清单。CF 实际以 AS13335 宣告的地址空间约 1.9M 个 IPv4 地址、475 个
    collapse 后的网段, 多出来的部分(如 104.28.0.0/16、1.1.1.0/24、203.168.x)
    确实是 CF 的, 但不在官网清单里。
    反过来, 网上流传的 CIDR 清单(如本目录 cidrs.txt)又混进了大量与 CF 无关的
    VPS 网段。两头都会出错, 所以统一以 "官网清单 ∪ AS13335 宣告" 为准。

数据来源:
    1. https://www.cloudflare.com/ips-v4  /  ips-v6
    2. https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS13335
    两者取并集后 collapse, 结果缓存在同目录 cf_ranges.json。

用法:
    python cf_ranges.py --update                  # 联网刷新网段库
    python cf_ranges.py --check 104.28.1.1        # 查单个 IP / 网段
    python cf_ranges.py --clean cidrs.txt         # 清洗网段清单(默认备份原文件)
    python cf_ranges.py --clean cidrs.txt --dry   # 只看统计, 不落盘

作为库使用:
    import cf_ranges
    cf_ranges.is_cf("104.28.1.1")        # True
    cf_ranges.cf_only(ip_network("8.20.124.0/22"))   # 裁剪出其中属于 CF 的部分
"""
import argparse
import bisect
import ipaddress
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))

# PyInstaller 打包后优先检查内嵌临时目录 _MEIPASS，再检查可执行文件同级目录
if getattr(sys, "frozen", False):
    _meipass = getattr(sys, "_MEIPASS", "")
    if _meipass and os.path.exists(os.path.join(_meipass, "cf_ranges.json")):
        _BASE = _meipass
    else:
        _BASE = os.path.dirname(os.path.abspath(sys.executable))
else:
    _BASE = HERE
CACHE = os.path.join(_BASE, "cf_ranges.json")

# 兜底: 官网公开清单。cf_ranges.json 缺失时至少还能工作
OFFICIAL_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
OFFICIAL_V6 = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]

SRC_V4 = "https://www.cloudflare.com/ips-v4"
SRC_V6 = "https://www.cloudflare.com/ips-v6"
SRC_ASN = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS13335"


# ---------- 数据加载 ----------
def _load_cache():
    if not os.path.exists(CACHE):
        return None
    try:
        with open(CACHE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _fetch(url, timeout=25):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "cf_ranges/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def fetch_ranges(timeout=25):
    """联网拉取 官网清单 ∪ AS13335, 返回 (v4 列表, v6 列表, 元信息)"""
    v4, v6, src = [], [], []

    try:
        v4 += [x.strip() for x in _fetch(SRC_V4, timeout).split() if x.strip()]
        src.append(SRC_V4)
    except Exception as e:
        print(f"  ! 官网 ips-v4 拉取失败: {type(e).__name__}")

    try:
        v6 += [x.strip() for x in _fetch(SRC_V6, timeout).split() if x.strip()]
        src.append(SRC_V6)
    except Exception as e:
        print(f"  ! 官网 ips-v6 拉取失败: {type(e).__name__}")

    try:
        j = json.loads(_fetch(SRC_ASN, timeout))
        for p in j["data"]["prefixes"]:
            pre = p["prefix"]
            (v6 if ":" in pre else v4).append(pre)
        src.append(SRC_ASN)
    except Exception as e:
        print(f"  ! RIPEstat AS13335 拉取失败: {type(e).__name__}")

    return v4, v6, src


def collapse(v4, v6):
    """去重 + 合并相邻网段, 得到最小等价集合"""
    def _c(items, ver):
        nets = []
        for x in items:
            try:
                n = ipaddress.ip_network(x, strict=False)
            except ValueError:
                continue
            if n.version == ver:
                nets.append(n)
        return [str(n) for n in ipaddress.collapse_addresses(nets)]
    return _c(v4, 4), _c(v6, 6)


def update(timeout=25, quiet=False):
    """联网刷新 cf_ranges.json"""
    if not quiet:
        print("拉取 Cloudflare 网段 ...")
    v4, v6, src = fetch_ranges(timeout)
    if not v4:
        print("  × 一个 IPv4 段都没拿到, 保持原样")
        return False
    c4, c6 = collapse(v4, v6)
    data = {
        "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "sources": src,
        "asn": "AS13335",
        "v4": c4,
        "v6": c6,
        "stats": {
            "v4_blocks": len(c4),
            "v4_addresses": sum(ipaddress.ip_network(n).num_addresses for n in c4),
            "v6_blocks": len(c6),
        },
    }
    with open(CACHE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    if not quiet:
        s = data["stats"]
        print(f"  √ 已写入 {os.path.basename(CACHE)}")
        print(f"    IPv4 {s['v4_blocks']} 块 / {s['v4_addresses']:,} 个地址")
        print(f"    IPv6 {s['v6_blocks']} 块")
    return True


# ---------- 加载并建立索引 ----------
_cache = _load_cache()
if _cache and _cache.get("v4"):
    CF_V4 = _cache["v4"]
    CF_V6 = _cache.get("v6", OFFICIAL_V6)
    UPDATED = _cache.get("updated", "未知")
    SOURCE = "cf_ranges.json (官网 ∪ AS13335)"
else:
    CF_V4 = OFFICIAL_V4
    CF_V6 = OFFICIAL_V6
    UPDATED = "内置兜底(仅官网 15 段)"
    SOURCE = "内置 OFFICIAL_V4"

CF_NETS = [ipaddress.ip_network(n) for n in CF_V4]
CF_NETS_V6 = [ipaddress.ip_network(n) for n in CF_V6]

# 预计算整数区间, 用二分查找替代逐段 any() 判断
_IV4 = sorted((int(n.network_address), int(n.broadcast_address)) for n in CF_NETS)
_STARTS4 = [a for a, _ in _IV4]
_IV6 = sorted((int(n.network_address), int(n.broadcast_address)) for n in CF_NETS_V6)
_STARTS6 = [a for a, _ in _IV6]


def _in(iv, starts, addr):
    i = bisect.bisect_right(starts, addr) - 1
    return i >= 0 and addr <= iv[i][1]


def is_cf(ip):
    """这个 IP 是否属于 Cloudflare 地址空间(官方清单 ∪ AS13335)"""
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if a.version == 4:
        return _in(_IV4, _STARTS4, int(a))
    return _in(_IV6, _STARTS6, int(a))


def net_is_cf(net):
    """整个网段是否完全落在 CF 空间内"""
    n = ipaddress.ip_network(str(net), strict=False)
    iv, st = (_IV4, _STARTS4) if n.version == 4 else (_IV6, _STARTS6)
    s, e = int(n.network_address), int(n.broadcast_address)
    i = bisect.bisect_right(st, s) - 1
    return i >= 0 and iv[i][0] <= s and e <= iv[i][1]


def cf_only(net):
    """
    返回 net 中属于 CF 的那部分(可能为空/可能被拆成多块)。
    用于把 "部分重叠" 的网段裁干净。
    """
    n = ipaddress.ip_network(str(net), strict=False)
    iv = _IV4 if n.version == 4 else _IV6
    s, e = int(n.network_address), int(n.broadcast_address)
    cls = ipaddress.IPv4Address if n.version == 4 else ipaddress.IPv6Address
    out = []
    for a, b in iv:
        if b < s:
            continue
        if a > e:
            break
        lo, hi = max(a, s), min(b, e)
        out.extend(ipaddress.summarize_address_range(cls(lo), cls(hi)))
    return out


def _subtract(iv, holes):
    """从区间集合 iv 里挖掉 holes, 返回剩余区间"""
    out = []
    for a, b in iv:
        segs = [(a, b)]
        for ha, hb in holes:
            nxt = []
            for x, y in segs:
                if hb < x or ha > y:
                    nxt.append((x, y))
                    continue
                if x < ha:
                    nxt.append((x, ha - 1))
                if hb < y:
                    nxt.append((hb + 1, y))
            segs = nxt
        out.extend(segs)
    return out


def uncovered_cf(nets):
    """CF 空间里, 这批网段还没覆盖到的部分(拆成 CIDR)"""
    holes = []
    for n in nets:
        try:
            net = ipaddress.ip_network(str(n), strict=False)
        except ValueError:
            continue
        if net.version != 4:
            continue
        for p in cf_only(net):
            holes.append((int(p.network_address), int(p.broadcast_address)))
    holes.sort()
    merged = []
    for a, b in holes:
        if merged and a <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    rest = _subtract(_IV4, merged)
    out = []
    for a, b in rest:
        out.extend(ipaddress.summarize_address_range(
            ipaddress.IPv4Address(a), ipaddress.IPv4Address(b)))
    return out


def _drop_subsets(nets):
    """去掉被其他条目完整包含的冗余网段(保留粗粒度条目, 不打散成 /24)"""
    ordered = sorted(set(nets), key=lambda n: (n.prefixlen, int(n.network_address)))
    kept = []
    for n in ordered:
        s, e = int(n.network_address), int(n.broadcast_address)
        covered = False
        for k in kept:
            if int(k.network_address) <= s and e <= int(k.broadcast_address):
                covered = True
                break
        if not covered:
            kept.append(n)
    return kept


# ---------- 清洗清单 ----------
def clean_file(path, dry=False, add_missing=True, backup=True):
    """清洗一个 CIDR 清单: 剔除非 CF 段、裁剪部分重叠、补齐缺失的 CF 段"""
    if not os.path.exists(path):
        print(f"× 文件不存在: {path}")
        return False

    raw, bad_lines = [], 0
    with open(path, "r", encoding="utf-8-sig") as f:
        for line in f:
            s = line.split("#", 1)[0].strip()
            if not s:
                continue
            try:
                raw.append(ipaddress.ip_network(s, strict=False))
            except ValueError:
                bad_lines += 1

    kept, trimmed, dropped = [], [], []
    for n in raw:
        parts = cf_only(n)
        if not parts:
            dropped.append(n)
        elif len(parts) == 1 and parts[0] == n:
            kept.append(n)
        else:
            trimmed.append((n, parts))
            kept.extend(parts)

    extra = uncovered_cf(kept) if add_missing else []

    before_dedup = len(set(kept) | set(extra))
    final = _drop_subsets(list(set(kept) | set(extra)))
    final.sort(key=lambda n: (int(n.network_address), n.prefixlen))
    redundant = before_dedup - len(final)

    print(f"清单 {os.path.basename(path)}")
    print(f"  原始条目        {len(raw)}" + (f"  (另有 {bad_lines} 行无法解析已跳过)" if bad_lines else ""))
    print(f"  完全属于 CF     {len([1 for n in raw if net_is_cf(n)])}")
    print(f"  部分重叠已裁剪  {len(trimmed)}" + (f"  {[str(t[0]) for t in trimmed[:5]]}" if trimmed else ""))
    print(f"  与 CF 无关剔除  {len(dropped)}" + (f"  {[str(d) for d in dropped[:5]]}" if dropped else ""))
    print(f"  补齐缺失的 CF 段 {len(extra)}" + (f"  {[str(e) for e in extra[:5]]}" if extra else ""))
    print(f"  冗余子集合并    -{redundant}")
    print(f"  → 清洗后        {len(final)} 条")

    if dry:
        print("  (--dry 模式, 未写入)")
        return True

    if backup and os.path.exists(path):
        bak = path + ".bak"
        shutil.copy2(path, bak)
        print(f"  已备份原文件 → {os.path.basename(bak)}")

    head = (f"# Cloudflare 网段清单 (由 cf_ranges.py 清洗生成)\n"
            f"# 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"# 依据: 官网 ips-v4 ∪ {SOURCE}\n"
            f"# 网段库更新于: {UPDATED}\n"
            f"# 条目数: {len(final)}  (原始 {len(raw)} / 剔除 {len(dropped)} / 补齐 {len(extra)})\n")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(head)
        for n in final:
            f.write(f"{n}\n")
    print(f"  √ 已写入 {os.path.basename(path)}")
    return True


def main():
    ap = argparse.ArgumentParser(
        description="Cloudflare 网段库: 刷新 / 校验 / 清洗清单",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="例:\n  python cf_ranges.py --update\n"
               "  python cf_ranges.py --check 104.28.1.1\n"
               "  python cf_ranges.py --clean cidrs.txt")
    ap.add_argument("--update", action="store_true", help="联网刷新网段库")
    ap.add_argument("--check", metavar="IP/CIDR", help="检查 IP 或网段是否属于 CF")
    ap.add_argument("--clean", metavar="FILE", help="清洗 CIDR 清单文件")
    ap.add_argument("--dry", action="store_true", help="配合 --clean, 只统计不写入")
    ap.add_argument("--no-add", action="store_true", help="配合 --clean, 不补齐缺失的 CF 段")
    ap.add_argument("--no-backup", action="store_true", help="配合 --clean, 不备份原文件")
    ap.add_argument("--info", action="store_true", help="显示当前网段库概况")
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    if args.update:
        return 0 if update() else 1

    if args.check:
        t = args.check.strip()
        if "/" in t:
            try:
                n = ipaddress.ip_network(t, strict=False)
            except ValueError:
                print(f"× 不是合法网段: {t}")
                return 1
            full = net_is_cf(n)
            parts = cf_only(n)
            print(f"{n}")
            print(f"  完全属于 CF : {'是' if full else '否'}")
            if not full:
                print(f"  其中属于 CF : {len(parts)} 块" +
                      (f"  {', '.join(str(p) for p in parts[:8])}" if parts else "  (无)"))
        else:
            ok = is_cf(t)
            print(f"{t}  →  {'属于 Cloudflare' if ok else '不属于 Cloudflare'}")
        return 0

    if args.clean:
        return 0 if clean_file(args.clean, dry=args.dry,
                               add_missing=not args.no_add,
                               backup=not args.no_backup) else 1

    s4 = sum(n.num_addresses for n in CF_NETS)
    print("Cloudflare 网段库")
    print(f"  数据来源 : {SOURCE}")
    print(f"  更新于   : {UPDATED}")
    print(f"  IPv4     : {len(CF_V4)} 块 / {s4:,} 个地址")
    print(f"  IPv6     : {len(CF_V6)} 块")
    print()
    print("  常用命令: --update 刷新 / --check 校验 / --clean 清洗清单")
    return 0


if __name__ == "__main__":
    sys.exit(main())
