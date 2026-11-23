# Cloudflare 优选测速器 (cfspeed v1.4)

> 测 Cloudflare Worker / edgetunnel (VLESS over WS+TLS) 的优选 IP 与优选域名在当前网络下的真实质量，一键导出 Sing-box、Clash.Meta (Mihomo) 及 VLESS 节点配置。

---

## 🌟 核心特性

- **拒绝 Ping 假阳性**：
  物理层与协议层多维验证：`TCP 连通性` $\to$ `真实 TLS 握手 (SNI=Worker)` $\to$ `HTTP 首字节 (TTFB)` $\to$ `CF-RAY 边缘校验` $\to$ `真实下载带宽`。
- **丢包率（Packet Loss）精确追踪**：
  多轮采样统计握手失败率，丢包率 $>50\%$ 的节点直接淘汰，排序优先推荐 0% 零丢包稳定节点，告别断流假象。
- **国内高可用 DoH 智能防污染**：
  集成阿里公共 DNS（无需递归的 IP 直连 `223.5.5.5`）与腾讯 DNSPod，解决本地 DNS 污染及境外 DoH 被阻断问题。
- **权威网段库与二分匹配 (`cf_ranges.py`)**：
  聚合 Cloudflare 官方公布清单与 **AS13335 宣告前缀**（475 个 CIDR 块，约 190 万地址空间），利用整数区间二分查找 ($O(\log N)$) 极速匹配。
- **全套现代代理客户端一键导出**：
  测试完成后一键生成：
  - **Sing-box (1.8+)**：出站 JSON 配置（含 `urltest` 自动优选分组）
  - **Clash.Meta (Mihomo)**：`proxies` 与 `proxy-groups` YAML 配置
  - **VLESS 直链**：标准 `vless://` 链接（兼容 v2rayN、NekoBox、Shadowrocket 等）
  - **经典纯文本**：`ip:port#机房`
- **单文件独立绿色运行**：
  网段库与预设全量内嵌打包，仅需单个 `cfspeed.exe` 即可在任意 Windows 电脑即开即测。

---

## 🚀 快速上手

### 方式 A：双击运行（交互模式，推荐）

1. 下载或解压后直接双击运行 `cfspeed.exe`（或执行 `python cfspeed.py`）；
2. 按照终端提示输入你的 **Worker 域名**（用于 TLS SNI 和 HTTP Host）；
3. 选择测试目标来源：
   - `[1] 预设`：内置优选域名清单（426 个）或实测 IP 清单；
   - `[2] 粘贴`：直接多行粘贴 IP、域名或 CIDR 网段；
   - `[3] 文件`：从本地文本文件读取；
   - `[4] 网段`：扫描指定 CIDR（如 `162.159.38.0/24`）。
4. 连通性与首字节测完后，根据提示选择是否对 Top N 测真实下载带宽；
5. 选择导出前几名，程序会自动生成全套客户端配置保存至 `results/` 目录。

### 方式 B：命令行调用

```bash
# 使用内置东京实测 IP 预设, 采样 5 轮
cfspeed.exe --preset ips -w your-worker.workers.dev -r 5

# 测试指定 IP/域名列表并测速
cfspeed.exe -t 1.2.3.4,example.com -w your-worker.workers.dev -s

# 扫描指定网段, 自动导出前 3 名全套客户端配置到 results/
cfspeed.exe -c 162.159.38.0/24 -w your-worker.workers.dev -e 3 --uuid "你的UUID"

# 从文件读取候选列表并指定多端口探测
cfspeed.exe -f nodes.txt -w your-worker.workers.dev -p 443,2053,2083
```

---

## ⚙️ 常用命令行参数

| 参数 | 说明 | 默认值 |
| :--- | :--- | :--- |
| `-w, --worker` | **【必填】** Worker 域名 (TLS SNI 与 Host) | 无 |
| `-t, --targets` | 目标列表（IP 或域名，逗号/空格分隔） | 无 |
| `-f, --file` | 从文本文件读取目标（每行一个） | 无 |
| `-c, --cidr` | 扫描指定网段（如 `162.159.38.0/24`） | 无 |
| `--preset` | 内置预设：`domains` / `tokyo` / `ips` / `nodes` | 无 |
| `-r, --rounds` | 采样轮数（多轮随机乱序取中位） | `5` |
| `-s, --speed` | 额外测试真实下载带宽（串行测试） | 关闭 |
| `-p, --ports` | 探测端口列表（如 `443,2053,2096`） | `443` |
| `-n, --threads` | 并发线程数 | `60` |
| `-e, --export` | 自动导出前 N 名的客户端配置文件 | 关闭 |
| `--uuid` | 导出节点时填入的 Worker UUID | 通用占位符 |
| `--ws-path` | 导出节点时填入的 WebSocket Path | `/` |
| `--all-ips` | 同一域名的多个 IP 各占一行（默认合并取最优） | 关闭 |
| `--no-doh` | 关闭 DoH 防污染复核解析 | 开启 |

---

## 📁 目录结构说明

```text
cf-test/
├── cfspeed.py          # 测速主程序入口
├── cf_ranges.py        # 权威网段库与 CIDR 清洗工具
├── cf_ranges.json      # 缓存的 AS13335 与官网 IPv4/IPv6 网段库
├── presets.py          # 内置预设候选数据 (域名、IP、节点)
├── make_variants.py    # 订阅转多优选节点/配置展开工具
├── build.py            # PyInstaller 单文件绿色打包脚本
├── dist/
│   ├── cfspeed.exe     # 编译就绪的单文件独立绿色运行程序
│   └── 使用说明.txt     # 纯文本快速上手文档
└── results/            # 测速 CSV 结果与导出的客户端配置保存目录
```

---

## 🛠️ 自行打包构建

如果修改了源码并希望重新打包绿色单文件 exe：

```bash
python build.py
```

构建完成后产物将自动生成于 `dist/cfspeed.exe`，无需携带外部 json 或 txt 文件即可运行。
