# 🚀 免费 V2Ray 配置 — by [@Raydikalx](https://t.me/Raydikalx)

[![Aggregate](https://github.com/0xRadikal/Free-v2ray-Configs/actions/workflows/aggregate.yml/badge.svg)](https://github.com/0xRadikal/Free-v2ray-Configs/actions/workflows/aggregate.yml)
![Update](https://img.shields.io/badge/update-every%2015%20min-blue)
![Validated](https://img.shields.io/badge/validated-sing--box%20%2B%20mihomo-success)
![License](https://img.shields.io/github/license/0xRadikal/Free-v2ray-Configs)

> 🇬🇧 [English version](README.md) · 🇮🇷 [نسخهٔ فارسی](README_FA.md) · 🇷🇺 [Русская версия](README_RU.md)

自动聚合、**去重**、**统一命名**并经**真实客户端校验**的免费 V2Ray / Xray 配置。
采集自 **21 个源**（7 个精选 + 14 个大量源），使用**支持 CDN 识别**的去重引擎清洗，
并通过 GitHub Actions **约每 15 分钟**更新一次。

所有备注都会被重写为：`{CC} {flag} | @Raydikalx | {id}` —— 其中 `{id}` 是一个由
**内容派生**的短指纹，而不是计数器。同一台服务器永远得到同一个标签，因此更新后
客户端里的节点名称保持稳定。

### ✅ 每一次发布都经过真实客户端校验

只要有一条格式错误的记录，客户端就会拒绝**整个文件** —— 所以"大部分有效"的输出
毫无价值。在发布任何内容之前，每个 `clash.yaml` 和 `singbox.json` 都会用你自己
运行的同一批二进制文件进行检查：

```
sing-box check -c <file>      # sing-box 1.13.14
mihomo -t -f <file>           # mihomo v1.19.29
```

如果任何文件校验失败，**本次运行中止，不提交任何内容**。上一个正常的发布保持不变。

> ⚠️ 结构上有效并不等于能用。结构上损坏的记录（假 UUID、`App not supported`、
> 不支持的加密方式、格式错误的 REALITY 密钥）会被丢弃，但一个语法完美的配置
> 仍然可能是死的。那是另一个问题，下面单独回答。

<a name="-does-it-actually-work"></a>

### 🧪 它真的能用吗？

大多数免费配置仓库只公布一个配置数量，然后让你自己猜。这里给出的是经过**实测**
而非估计的、并不好听的答案：**任何免费配置池在任何时刻都有绝大多数是死的。**
这是免费配置本身的属性，而不是本仓库的问题 —— 所以与其掩盖它，本流程选择测量它
并据此排序。

每个配置都会经过四个阶段。每个阶段都足够便宜，可以跑遍整个池子，并且都会丢掉
下一阶段本来会白费的工作：

| 阶段 | 它在问什么 | 代价 |
|---|---|---|
| **L0/L1** | 能否解析？端点是否唯一且可路由？ | 不走网络 |
| **L2** | TCP 端口是否真的接受连接？ | 每个端点一次连接 |
| **L3** | **经由该代理的真实 HTTP 请求**能否成功？ | 完整握手，重复多轮 |
| **buckets** | 哪些通过了*每一*轮 L3？ | 仅排序 |

只有通过了**每一**轮 L3（而不只是它最好的一轮）的配置才会进入 `verified/`。
这个区别并非装饰：在一次 5 轮实验中，单轮成功数介于 363 到 501 之间，而
**五轮全部通过的只有 224 个**。若发布最好的那一轮，结果会被高估约 **2 倍**。

**一个实测例子。** 一次 5 轮实验，运行于**美国**主机、且链路明显劣化 —— 五轮
分别耗时 45 秒、54 秒、345 秒、615 秒和 404 秒，这本身就是征兆。（每轮的原始
CSV 约 10 MB，**故意不提交**；可用
`python scripts/pipeline.py all/configs.txt --rounds 5` 复现。）

| 阶段 | 配置数 | 占池比例 |
|---|---|---|
| 去重后采集到 | 8,158 | 100% |
| TCP 端口开放 (L2) | 3,845 | 47.1% |
| 至少成功一次 (L3) | 626 | 7.7% |
| **全部 5 轮**都成功 → `verified/` | 224 | **2.7%** |

> ⚠️ **引用这个百分比之前请先读这段。** 2.7% 不是一个常数，也不是对**你的**网络
> 的判断。它是*在一台主机上、某一天、一条糟糕的链路上*测得的。同样的代码在链路
> 健康的欧洲主机上，每轮存活的配置明显更多。一个从弗吉尼亚的 GitHub runner
> 连不上的配置，可能从德黑兰完全可用，反之亦然。
>
> 所以：**`verified/` 的含义是"这个配置回应了来自运行测试那台机器的真实请求"
> —— 而不是"这个配置对你也能用"。** 你正在下载的那一次发布的实际数字，以及测试
> 所在的国家，都记录在 [`health.json`](#-source-health--healthjson) 的 `cascade`
> 块中。请相信那个文件，而不是本 README 里的任何数字 —— 后者只是一个示例。

---

## 📥 快速订阅（把链接复制到客户端）

> **请使用下面的 `raw.githubusercontent.com` 链接。** 它们是主源，也是最新的。
> 下方另列了 jsDelivr 镜像，供无法直连 GitHub 的用户使用。
>
> **为什么用 raw 而不是 CDN？** 在本仓库上实测：
>
> | | 缓存指令 | 实际过期程度 |
> |---|---|---|
> | `raw.githubusercontent.com` | `max-age=300` | 最多 **5 分钟** |
> | `cdn.jsdelivr.net`（分支引用） | `s-maxage=43200` | 最多 **12 小时** |
>
> jsDelivr 自己的文档说明分支引用会被缓存 12 小时。在一次实际检查中，CDN 正在
> 提供一份 **12 小时 45 分钟**前的快照（4,353 个配置），而 raw 提供的是当前的
> （8,168 个配置）—— 那是 15 分钟更新间隔的 **51 倍**。现在每次运行都会清除
> CDN 缓存，但清除只作用于边缘节点；jsDelivr 自身的源站在重新解析分支名时仍可能
> 滞后。raw 没有这一层。
>
> 📌 **所有内容都在默认分支（`main`）上。** 打开仓库就能直接看到配置文件 ——
> 无需切换分支，没有隐藏位置。你几个月前复制的链接依然有效。参见
> [发布为何依然廉价](#-how-publishing-stays-cheap)。

### 🌐 ALL 全部配置（精选 + 大量）
| 格式 | URL（主源 — raw） |
|---|---|
| 纯文本 (v2ray) | `https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt` |
| **Base64**（订阅） | `https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs_base64.txt` |
| Clash YAML | `https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/clash.yaml` |
| Sing-box JSON | `https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/singbox.json` |

### ⭐ LIGHT 精选（来自经过测速的上游）
- 纯文本: `…/main/light/configs.txt`
- Base64: `…/main/light/configs_base64.txt`
- Clash: `…/main/light/clash.yaml` · Sing-box: `…/main/light/singbox.json`

### 📦 HEAVY 大量（数量大、来源多样）
- 纯文本: `…/main/heavy/configs.txt`
- Base64: `…/main/heavy/configs_base64.txt`
- Clash: `…/main/heavy/clash.yaml` · Sing-box: `…/main/heavy/singbox.json`

### 🎯 按协议分类（从 ALL 拆分）

通常都有内容：`vless` · `vmess` · `shadowsocks` · `trojan` · `hysteria2` ·
`shadowsocksr` · `tuic`

同样受支持（只有当上游确实发布了该协议时文件才会出现 —— 空文件永远不会被发布，
所以文件缺失意味着"本轮没有"）：`hysteria` · `wireguard` · `juicity` · `anytls` ·
`snell` · `mieru` · `socks`

```
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vless.txt
https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vless_base64.txt
…其他协议以此类推
```

`index.json` 会列出当前确实存在哪些协议文件，你不需要猜。

### 🪞 镜像（jsDelivr）—— 仅在无法访问 raw 时使用

把前缀替换为
`https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/…`

镜像每次运行都会被清除，但仍可能落后于主源。如果你需要通过 CDN 获得一份保证
完全一致的副本，请固定某个 commit 而不是分支（`@<commit-sha>/…`）—— 已验证与
raw 逐字节相同。

---

## 🗂️ 仓库结构

**只有一个分支 —— `main`。** 源代码与发布出来的产物并列放在默认分支上，这正是
访客打开仓库时看到的内容。

机器生成的产物，每次运行都会刷新：

```
all/        configs.txt · configs_base64.txt · clash.yaml · singbox.json   (精选 + 大量)
heavy/      configs.txt · configs_base64.txt · clash.yaml · singbox.json   (14 个大量源)
light/      configs.txt · configs_base64.txt · clash.yaml · singbox.json   (7 个精选源)
protocols/  vless.txt · vmess.txt · trojan.txt · … (+ *_base64.txt)         (从 ALL 拆分)
archive/    <cat>_broken.txt (+ _base64)                                   (被拒绝的配置)
index.json  完整元数据：数量、时间戳、协议分布、全部 URL
health.json 每个源的健康报告：ok/empty/fail、HTTP 状态码、延迟、错误
```

人工编写的源码，具有正常的 git 历史与 blame：

```
scripts/    流水线 (core.py · converters.py · sources.py · aggregate.py · validate.py)
.github/    定时工作流 · Dependabot 配置 · issue 模板
docs/       静态状态面板（运行时读取 index.json / health.json）
README.md · README_FA.md · README_ZH.md · README_RU.md
SECURITY.md · CONTRIBUTING.md · LICENSE
```

说明：

- `protocols/` 与 `archive/` 中的文件**只在非空时出现**。文件缺失意味着"本轮
  该类别没有内容" —— 空文件比 404 更糟，因为订阅了它的客户端会用"空"替换掉
  自己正在工作的列表，而 404 会让客户端保留上一份列表。
- `index.json` 只公布确实存在的文件，因此它的 URL 列表永远不是仓库无法兑现的
  承诺。

<a name="-how-publishing-stays-cheap"></a>
## 🌿 发布为何依然廉价（以及为什么文件放在 `main` 上）

Git 永远不会忘记一个 blob。每次定时运行都会重新生成同一批大文件，而以常规方式
把它们追加到分支上，会让每个变更过的文件在历史里**永久**多出一份副本。这样
发布成本是 **O(提交数)**，没有上界。

这在本仓库不是假设。它曾达到 **约 3.55 GB、约 5,649 个提交**。在两个连续的真实
机器人提交上实测：每个产物提交为永久历史增加 **604 KB** —— 按每天约 96 次运行
计算是 **约 56.6 MB/天**，即 **约 20 GB/年**。

### 错误的修法（以及为何被回退）

第一次尝试是把产物移到一个**孤立分支（orphan branch）**，并以单个提交强制推送。
发布成本确实降到了 O(1) —— 同时项目悄悄坏掉了：

- **此前复制过的每个订阅链接都返回 HTTP 404。** 客户端指向
  `…/main/all/configs.txt` 的用户不会看到错误提示；订阅只是无声地变空了。
- **访客打开仓库根本看不到任何配置** —— 只有代码。大多数来找配置的人并不知道
  git 分支是什么，更不会想到要切到第二个分支再看一次。
- **可发现性崩塌。** GitHub 搜索、仓库首页和搜索引擎索引的都是默认分支。把产物
  藏到非默认分支，等于让最有价值的内容变得不可见。
- **这个领域里没有任何一个成功的仓库这么做。** 直接核查过：
  Epodonios/v2ray-configs（⭐ 3,166 —— 24.7 GB，产物在 `main`）、
  mahdibland/V2RayAggregator（⭐ 4,003 —— 产物在 `master`）、
  Pawdroid/Free-servers（⭐ 18,420 —— 产物在 `main`）。

如果没人能找到文件，廉价的历史一文不值。

### 正确的修法 —— 在 `main` 上做滚动压缩（rolling squash）

产物**发布到默认分支**，但该分支始终保持为
**源码历史 + 恰好一个产物提交**：

1. 找到最新的、*没有*标记 `[auto-output]` 的提交 —— 即**锚点（anchor）**
   （最后一个人工/源码提交）。
2. 构建一棵树 = *锚点的树* + *本轮新产物*。
3. `git commit-tree <tree> -p <anchor>`，然后带 lease 强制推送。

上一个产物提交变为不可达并被垃圾回收，因此历史永远不会累积快照。发布成本是
**O(1)** —— 同时每个文件都仍然停在用户（和爬虫）已经在找的位置上。

在 25 个连续轮次中实测，每轮都从一个新的 shallow clone 开始：仓库体积始终
**保持 172 KB**，增长 **0 KB/轮**。

安全性质，每一条都有可执行的测试来验证：

- **`--force-with-lease`，绝不用裸 `--force`。** 因为发布现在指向的是人类也会
  提交的同一个分支，一次天真的强制推送会删除他们的工作。作为反向对照实验：使用
  普通 `--force` 时，远端上属主的提交数掉到了 **0**。使用 lease 时，真正发生
  竞争的推送会被拒绝，该步骤会重新取锚，属主的提交和新产物**都**得以保留。
- **源码回退防护。** 锚点与分支顶端之间每一个有差异的路径都会被分类；如果产物
  集合之外的任何东西发生了变化，该步骤会拒绝发布，而不是回退别人的代码。
- **感知 shallow checkout。** `actions/checkout` 默认只取深度 1，所以通常唯一
  可见的提交就是一个产物提交，锚点搜索会找不到东西 —— 从而永久停止发布。该步骤
  会逐级加深（2 → 4 → 8 → 32）直到锚点出现。（`fetch-depth: 0` 被否决了：那意味着
  一天克隆 96 次 3.55 GB。）
- **处处 fail-closed。** 产物缺失、配置文件小得可疑、或计算出的树为空，都会中止
  发布并保留上一个正常发布。
- **不会递归。** 使用 `GITHUB_TOKEN` 发出的推送不会触发新的工作流运行（GitHub
  的既有行为），并且 `push` 触发器还额外限定在 `scripts/**` —— 机器人从不写入
  该路径。

### 产物刻意保持确定性

滚动压缩限制了历史体积；确定性则让每一轮的 diff 真正保持很小。通过测量发现并
消除了三种无意义的抖动来源：

| 曾经 | 现在 |
|---|---|
| 国家标签取自最先抓到的那个上游 —— 同一台服务器在两次运行间 `RU 🇷🇺` ⇄ `US 🇺🇸` 来回跳 | 标签锁定到**端点**；第一次决定性的判定胜出并被冻结 |
| 备注标签是**按位置的计数器** —— 插入一个配置就会重命名它之后的每一行 | 标签为 `sha256(dedup-key)[:6]` —— 由内容派生，与位置无关 |
| 行顺序跟随网络响应顺序 | 按去重键排序 —— 同一组配置 ⇒ 同一个文件，逐字节相同 |

效果：连续两次运行现在产生 **34 个文件中 32 个逐字节相同**；唯一的差异是
`index.json` / `health.json` 里的时间戳。

### 一个诚实的保留问题

历史中已有的约 3.55 GB **没有**被重写。由于 GitHub 在 fork 网络内共享对象，
重写几乎回收不到什么空间，却会破坏所有既有的 clone 和全部 3 个 fork。流血是从
现在起止住了；旧的伤疤是刻意留着的。

## 📊 实时元数据 —— `index.json`

`https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/index.json`

包含各类别的数量（唯一 / 重复 / 损坏）、协议分布、最后更新时间戳、下次更新
预计时间，以及每个文件的 URL（raw 主源 + CDN 镜像），另有一个 `link_policy`
块说明应优先使用哪一个以及为什么。

<a name="-source-health--healthjson"></a>
## 🩺 源健康状况 —— `health.json`

`https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/health.json`

每次运行都会重新生成的逐源健康报告：对 21 个源中的每一个，记录 `status`
（`ok` / `empty` / `fail`）、HTTP 状态码、尝试次数、延迟、产出的配置数量，以及
最后一次错误（如果有）。这让失效或改动过的上游立刻可见。摘要（`healthy` /
`unhealthy`）也会嵌入 `index.json`。

同一个文件还带有一个 **`cascade`** 块，描述校验运行实际做了什么 —— 因此这些数字
来自生产这次发布的那台机器，而不是来自本 README：

```jsonc
"cascade": {
  "exit_country": { "colo": "IAD", "loc": "US",   // 测试是从哪里跑的
                    "source": "https://cp.cloudflare.com/cdn-cgi/trace" },
  "layers": {
    "l0_l1": { "in": 300, "out": 295, "seconds": 0.01,
               "endpoints_unique": 258, "dedup_saving_pct": 12.54,
               "dropped": { "unparsable": 5, "invalid_port": 0, "invalid_uuid": 0,
                            "unroutable_server": 0, "invalid_server": 0 } },
    "l2":    { "in": 295, "out": 69, "open_pct": 23.39,
               "open_pct_of_raw_input": 23.0, "dns_failed": 4,
               "dns_seconds": 0.6, "tcp_seconds": 3.06, "seconds": 3.68 },
    "l3":    { "in": 69, "rounds": 2, "per_run_ok": [25, 25], "ever_ok": 25,
               "stable": 25, "flaky_pct": 0.0, "seconds": 8.77 }
  },
  "buckets": { "verified": 25, "fast": 25, "secure": 6, "top": 25,
               "top_short_by": 75, "fast_threshold_ms": 800 },
  "total_seconds": 12.55
}
```

（上面的数值来自一次为示例而特意跑短的真实运行；完整运行会报告整个池子。）
三个值得知道的细节：

- **`exit_country`** 是*测试*所在的国家 —— 这是解读任何成功率时最重要的保留
  条件。只记录 `loc` 和 `colo`；runner 的 IP 地址刻意从不公布。
- **`dropped`** 说明每个配置被拒绝的原因，因此某个源开始输出垃圾时会立刻可见，
  而不是让产出无声地缩水。
- **`per_run_ok` 与 `stable` 的对比**直接展示抖动程度：`stable` 只统计通过了
  *每一*轮的配置，而 `verified/` 正是由它构建的。

---

## ⚙️ 工作原理

1. **抓取** —— 并发下载 21 个源（自动识别 base64/直文本）。遇到瞬时错误会重试，
   但对 4xx 快速失败，这样一个失效的 URL 会被报告出来，而不是被反复重试。
2. **清洗** —— 丢弃假的/损坏的（全零 UUID、`App not supported`、空 proxies）。
3. **去重** —— 支持 CDN 识别的服务器身份指纹（轮换的 CDN IP 会收敛为一个）。
4. **命名** —— 每个备注都被重写为 `{CC} {flag} | @Raydikalx | {id}`，其中 `{id}`
   是 `sha256(dedup-key)[:6]`。它由配置自身派生，所以列表变长时它不会移位。国家
   标签锁定到**端点**，而不是最先被抓到的那个上游，因此也不会在两次运行间跳变。
5. **转换** —— 按客户端做 schema 翻译，并严格校验字段：加密方式白名单、SS-2022
   密钥长度、REALITY 的 uTLS、`short-id`/公钥格式检查，以及完整的传输层输出
   （`ws` / `grpc` / `h2` / `http` / `httpupgrade` / `xhttp`）。客户端无法表达的
   条目会被丢弃，而不是被无声降级 —— 降级后的配置看起来有效，却永远连不上。
6. **校验** —— 对全部六个生成文件执行 `sing-box check` + `mihomo -t`。**任何
   失败都会中止本次运行**，所以损坏的发布永远不可能覆盖正常的发布。
7. **发布** —— GitHub Actions 约每 15 分钟提交结果；并经由 jsDelivr CDN 分发。

### ⏱️ 可靠的约 15 分钟调度

GitHub 的 `schedule:` cron 是尽力而为的，在繁忙时段经常被延迟或跳过。为了保证
稳定的节奏，本仓库采用**三层**方案：

1. **高频 cron**（`*/5 * * * *`）—— 让真正触发的机会更多。
2. **新鲜度闸门** —— 如果 `index.json` 在 13 分钟内更新过，本次触发就提前退出，
   因此重活大约每 15 分钟才真正执行一次（不浪费运行，也不会重复更新）。
3. **`repository_dispatch` 兜底** —— 常开的机器人服务器每 15 分钟发送一个
   `aggregate-now` 事件，即使 cron 被丢弃也能保证有一次运行。同时也支持手动
   `workflow_dispatch`（可带 `force`）。

## 🙌 数据来源

感谢所有上游维护者（mahdibland、peasoft、mahsanet、barry-far、roosterkid、
4n0nymou3、ALIILAPRO、Epodonios、V2RAYCONFIGSPOOL、ShadowException、
w1770946466 等）。本仓库只做聚合、校验与清洗，处理的都是公开可得的配置。

## 📜 免责声明

仅用于教育与研究目的。不保证可用性或质量。请自行负责、合理使用。

---

**频道：** [@Raydikalx](https://t.me/Raydikalx) · **机器人：** [@RaydikalxBot](https://t.me/RaydikalxBot)
