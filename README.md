# edgetunnel-speedtest

> 测 Cloudflare 优选 IP / 优选域名的**真实可用性**，而不是 ping。

为 [edgetunnel](https://github.com/cmliu/edgetunnel) 这类基于 Cloudflare Worker 的部署而写：帮你在自己的网络环境下，从一堆"优选"地址里找出真正能用的那几个。

```
  # 目标                    IP                 机房  端口    中位    最快   抖动     带宽
  1 example.com             104.16.x.x         NRT   443     193     176   112     57.3
  2 example.net             172.64.x.x         SIN   443     688     665    42     62.6
```

---

## 为什么不能只看 ping

网上流传的优选 IP 列表几乎都用 ping 或 TCP 握手来排序，但这个指标会骗人：

| 现象 | 后果 |
|---|---|
| TCP 握手很快，但 TLS 握手慢一个数量级 | 你以为很快，实际每次打开网页都要多等 |
| 延迟看着还行，带宽却只有几 Mbps | 网页转圈，视频卡成 PPT |
| 能连上、证书也对，但返回 403 | 根本不服务你的域名，白测 |
| 单次测出来很快，多测几次就露馅 | 排名纯属运气 |

这个工具测四个指标，并且**多轮采样取中位数**，避免"测一次就下结论"。

---

## 快速开始

### 方式一：直接跑 exe（Windows，无需 Python）

到 [Releases](https://github.com/lzl74/edgetunnel-speedtest/releases) 下载 `cfspeed.exe`，双击即可。

### 方式二：源码运行（跨平台）

```bash
git clone https://github.com/lzl74/edgetunnel-speedtest.git
cd edgetunnel-speedtest
python cfspeed.py
```

纯标准库，**没有任何第三方依赖**，Python 3.8+ 即可（在 3.13 上测试）。

### 方式三：自己打包成 exe

```bash
pip install pyinstaller
pyinstaller --onefile --console --name cfspeed cfspeed.py
```

或者直接双击 `build.bat`。

---

## 用法

### 交互式

直接运行（双击 exe 或 `python cfspeed.py`），按提示走：

```
Worker 域名(SNI/Host,必填,如 xxx.cfpages.dev):

输入方式:
  [1] 使用内置预设
  [2] 直接粘贴 IP 或域名(多行,空行结束)
  [3] 从文件读取
  [4] 扫描网段(如 162.159.38.0/24)

采样轮数 [1]:
可选端口池: 443 2053 2083 2087 2096 8443 (每个目标随机1个,回车=443)
端口 [443]:
```

测速结束后会输出一个**可直接复制使用**的 `域名/IP:端口` 列表，并询问是否继续测下载带宽、测前几名。结果同时保存为 CSV 和 TXT 报告。

### 命令行

```bash
# 用内置预设（最省事）
cfspeed.py --preset domains -w 你的域名

# 测指定的 IP / 域名
cfspeed.py -t 1.2.3.4,example.com -w 你的域名
cfspeed.py -t cdn.example.org:2096 -w 你的域名     # 可带端口

# 扫网段
cfspeed.py -c 162.159.38.0/24 -w 你的域名

# 从文件读
cfspeed.py -f list.txt -r 8 -s
```

### 参数

| 参数 | 说明 |
|---|---|
| `-t, --targets` | 目标列表，逗号或空格分隔，IP 和域名都行，可带端口 |
| `-f, --file` | 从文件读取，每行一个 |
| `-c, --cidr` | 扫描网段，如 `162.159.38.0/24` |
| `--preset` | 内置预设：`domains` / `cidrs` |
| `-w, --worker` | **Worker 域名**（SNI 与 Host），**必填**，也可用环境变量 `CF_WORKER` |
| `-r, --rounds` | 采样轮数，默认 1 |
| `-s, --speed` | 额外测下载带宽（交互模式会在出结果后询问） |
| `-p, --ports` | 端口池，默认 443；`all` = 全部 6 个端口，每个目标随机用 1 个 |
| `-n, --threads` | 并发数，默认 60 |

### 内置预设

| 预设 | 内容 |
|---|---|
| `domains` | 一批常用的优选域名（见 `presets.py`） |
| `cidrs` | Cloudflare 网段池，抽样扫描（较慢） |

预设只是**候选清单**，具体哪个好还是要在你的网络下实测。

---

## ⚠️ 最重要的参数：`-w`

**必须填你自己的 Worker 域名，不是优选 IP 的域名。**

优选 IP 只是"进 Cloudflare 的门"。TLS 握手的 SNI 和 HTTP 请求的 Host 都必须是你自己的 Worker 域名，否则证书对不上，直接连不上。

```bash
# 你的 Worker 是 abc.workers.dev
cfspeed.py --preset domains -w abc.workers.dev

# 也可以用环境变量，避免每次都写
export CF_WORKER=abc.workers.dev
cfspeed.py --preset domains
```

填错了所有结果都会显示"证书不匹配"或直接连接被重置。

---

## 结果怎么看

| 列 | 含义 |
|---|---|
| 机房 | Cloudflare 落点，取自 `CF-RAY` 响应头后缀 |
| 中位 | 多轮采样的中位数，**主要看这个** |
| 最快 | 所有采样里最快的一次，代表这条线路的物理下限 |
| 抖动 | 标准差，越小越稳 |
| 带宽 | Mbps，串行测量（并发会互相抢带宽，数值失真） |

常用机房代码：

| 代码 | 位置 | 代码 | 位置 |
|---|---|---|---|
| NRT | 东京 | LAX | 洛杉矶 |
| SIN | 新加坡 | SJC | 圣何塞 |
| HKG | 香港 | AMS | 阿姆斯特丹 |
| ICN | 首尔 | LHR | 伦敦 |
| KIX | 大阪 | CDG | 巴黎 |

判断标准（经验值，因线路而异）：

- 中位 < 300ms 且带宽 > 30 Mbps → 好用
- 中位 300~600ms 且带宽 > 30 Mbps → 能用
- 带宽 < 10 Mbps → 基本不能用，别选

**别追求"最优"。** 同一批地址里，前几名的差距往往和它们自身的抖动是同一个量级，属于噪声。挑 2~3 个轮换更实际。

---

## 原理

### 1. 判定标准是 `CF-RAY`，不是"TLS 握手成功"

这是最容易踩的坑。有些 IP 能完成 TLS 握手、证书也确实是你域名的，但返回 403 且**没有 `CF-RAY` 响应头**——它们不是服务你 zone 的边缘节点。

只看 TLS 成功会严重高估可用数量。本工具要求 **HTTP 200 + 存在 `CF-RAY`** 才算可用。

### 2. 多轮采样 + 轮内随机顺序

同一批地址连测两轮，排名可以完全不同。单次采样误差可达上百毫秒。

工具默认 5 轮，轮内随机打乱顺序，消除"先测的占便宜"的位置偏差。

### 3. 带宽必须串行测

多个 IP 并发测速时，会互相抢带宽，结果全部偏低——那是假数据。所以带宽测试是串行的。

---

## 分析脚本

`tools/` 下是研究阶段用的脚本，比主程序更底层，适合做批量分析：

| 脚本 | 用途 |
|---|---|
| `cf_opt_test.py` | 单点测试：TCP / TLS / TTFB / 抖动 / 带宽 / 机房 |
| `bulk_test.py` | 批量测一批域名，六端口并发探测 |
| `colo_map.py` | 摸清"哪个网段 → 哪个机房"，支持逐 /24 扫描 |
| `ip_scan.py` | 从 ASN 网段抽样 IP，按 CF-RAY 判定真伪 |
| `tokyo_rank.py` | 对指定网段做多轮深度排名 |
| `make_variants.py` | 把订阅按优选地址展开成多个节点，便于客户端端到端对比 |

这些脚本通过环境变量 `CF_WORKER` 读取你的 Worker 域名：

```bash
cd tools
export CF_WORKER=你的域名        # Windows: set CF_WORKER=你的域名
python colo_map.py --map 162.159.0.0/18 --per 22
python ip_scan.py
```

`cidrs.txt` 里是 Cloudflare 的 ASN 网段，`domains.txt` 是优选域名清单，都可以自行增删。

---

## 常见问题

**全部显示"证书不匹配"或连接被重置？**
`-w` 填错了。要填你自己的 Worker 域名，不是优选 IP 的域名。

**全部返回 403？**
同样是 `-w` 不对，或者你的 Worker 没有正确部署。

**每次跑结果都不一样？**
正常。线路本身就在波动，这也是为什么要多轮采样。建议 `-r` 至少 5。

**为什么扫不到香港节点？**
Cloudflare 在香港有机房，但你能否落到那里完全取决于运营商的 BGP 路由。有些线路的 anycast 路由根本不经过香港，换端口也解决不了。

需要特定地区出口的话，用链式代理（出口走对应地区的服务器），而不是指望优选 IP。

**不同时段差别很大？**
是的，而且时段的影响往往比"选哪个 IP"大得多。晚高峰时同一条线路可能慢一倍以上。建议在不同时段各测一次。

---

## 免责声明

本项目仅用于网络质量测试与学习研究。请在符合当地法律法规及 Cloudflare 服务条款的前提下使用。使用者需自行承担使用后果，作者不对任何滥用行为负责。

本项目与 Cloudflare、edgetunnel 均无关联。

## License

[MIT](LICENSE)
