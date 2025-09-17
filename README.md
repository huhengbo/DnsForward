# DnsForward

DnsForward 是一个轻量级的本地 DNS 转发与重写服务，适用于需要在内网精准控制域名解析、对特定域名自定义出口线路或提供高速缓存的场景。项目基于 Go 语言编写，启动后可同时监听 UDP/TCP 53 端口，向多个上游 DNS 并发查询并返回最快响应，并支持通过规则集进行域名重写。

## 核心特性
- **多上游并发回源**：并行查询多个上游 DNS，优先采用最先返回的应答，提高解析稳定性与速度。
- **本地缓存**：针对域名、记录类型和类构造缓存键，缓存来自上游和本地重写的响应，有效降低重复查询的延迟。
- **TTL 感知缓存**：自动根据应答 TTL/权威数据的最小值确定缓存周期，并支持最小/最大 TTL 以及 NXDOMAIN 负缓存控制。
- **灵活的重写规则**：支持 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD` 等多种匹配方式，并可同时处理 IPv4/IPv6 重写。
- **远程规则集订阅**：启动时自动下载并解析远程规则，可配置超时与重试策略，结合本地规则实现统一的策略管理。
- **彩色日志与文件输出**：支持标准输出彩色日志以及可选的文件记录，方便排查与审计。
- **Prometheus 指标**：内置 `/metrics` 与 `/healthz`，便于接入监控平台，观测缓存命中率、上游延迟、热加载次数等指标。
- **热加载能力**：支持通过 `SIGHUP` 快速重新加载配置与规则，缓存会自动刷新。
- **多平台构建脚本**：提供 `build.sh` 脚本，一键交叉编译并打包发布版本。

## 项目结构
```
.
├── README.md              # 使用说明
├── config.yaml            # 默认配置示例
├── go.mod / go.sum        # Go 模块依赖
├── build.sh               # 打包脚本
├── main.go                # 启动入口，仅负责组装与启动服务
├── cache.go               # TTL 感知缓存与负缓存策略
├── config.go              # 配置结构、加载与运行态构建
├── handler.go             # DNS 查询处理逻辑
├── logging.go             # 日志与 fatal 封装
├── metrics.go             # Prometheus 指标注册与 HTTP 服务
├── rules.go               # 规则解析、索引与匹配
├── runtime.go             # 运行态容器（缓存、匹配器、上游配置等）
├── upstream.go            # 上游节点解析与并发回源
├── main_test.go           # 核心逻辑单元测试
└── Releases/              # 预构建产物
```

## 工作原理概述
1. 程序启动后读取 `config.yaml`，初始化监听地址、缓存策略、上游列表与重写规则。
2. 对于 `RULE-SET` 类型规则，会先下载或加载外部文件（支持可配置超时/重试），解析为可执行的规则条目后与本地规则合并并构建规则索引。
3. DNS 查询到来时，优先计算缓存键（域名 + 记录类型 + 记录类）并尝试命中缓存；命中后复制缓存的报文并返回，并更新命中计数。
4. 若无缓存，则先匹配重写规则：命中后生成对应 A/AAAA 记录并缓存；未命中则并行向多个上游 DNS（支持 UDP/TCP/TLS）发起查询，返回最先得到的有效响应并写入缓存。
5. 日志通过 `serviceLogger` 输出，可选择打开调试模式或写入到文件。同时指标端点会暴露缓存命中率、上游耗时、热加载次数等信息。

## 快速上手
### 环境准备
- Go 1.23 或以上版本
- Linux/macOS/Windows（若监听 53 端口需具备相应权限，Linux 通常需要 root 或 `setcap`）

### 本地运行
```bash
# 下载依赖
go mod tidy

# 启动服务
go run . -c config.yaml -d
```
可使用 `-l dns.log` 将日志写入文件，`-d` 开启调试日志。

### 作为守护进程
可结合 `systemd`、`supervisord` 或容器化方式部署，确保开放 UDP/TCP 53 端口并放行访问。

## 配置说明（config.yaml）
```yaml
server:
  address: ":53"              # 监听地址及端口
  cache_expiration: 5m         # 缓存失效时间（Go duration 格式）
  negative_cache_ttl: 1m       # NXDOMAIN 等负缓存时长
  min_ttl: 10s                 # 缓存最短存活时间
  max_ttl: 1h                  # 缓存最长存活时间
  metrics_address: ":9090"     # Prometheus 指标 & 健康检查监听地址

upstream:
  dns_servers:
    - 221.6.4.66
    - 58.240.57.33
    - "8.8.8.8:53"
    - "8.8.4.4:53"
    - "tls://1.1.1.1@cloudflare-dns.com" # 显式启用 DoT，可附带 SNI
  timeout: 2s                  # 上游 DNS 请求超时
  protocol: udp                # 默认协议（当条目未指定时生效，支持 udp/tcp/tls)

fetch:
  timeout: 10s                 # 下载 RULE-SET 的超时
  retry: 3                     # 失败后重试次数

rewrite:
  rules:
    - type: "DOMAIN-SUFFIX"
      value: "ytimg.com"
      target: "192.168.100.6"
    - type: "RULE-SET"
      value: https://...
      target: "192.168.100.6"
```
- `server.address`：监听的 IP:端口，可设置为 `0.0.0.0:53` 或内部网卡地址。
- `server.cache_expiration`：缓存默认 TTL，作为应答缓存的基准值。
- `server.negative_cache_ttl`：对 NXDOMAIN 等响应的负缓存时长，避免频繁回源。
- `server.min_ttl` / `server.max_ttl`：缓存 TTL 的下限与上限，用于平衡频繁回源与缓存陈旧。
- `server.metrics_address`：Prometheus 指标监听地址，留空则不启动指标服务。
- `upstream.dns_servers`：上游 DNS 列表，支持纯 IP（默认 53 端口）或 `ip:port`。
- `upstream.timeout`：并发查询上游 DNS 的超时时间，支持 Go duration 格式。
- `upstream.protocol`：未显式声明协议的条目将使用该默认协议（可选 udp/tcp/tls）。
- `fetch.timeout` / `fetch.retry`：远程 RULE-SET 抓取的超时与重试次数，可结合镜像站点提升稳定性。
- `rewrite.rules`：规则数组。
  - `DOMAIN`：完整域名匹配。
  - `DOMAIN-SUFFIX`：后缀匹配，适合整站域名。
  - `DOMAIN-KEYWORD`：关键字匹配。
  - `RULE-SET`：引用外部规则文件，文件按逗号分隔类型与匹配值，例如 `DOMAIN,google.com`。
  - `target`：重写后的目标 IPv4 地址（当前版本主要针对 A 记录）。

> **提示**：如需频繁更新远程规则，可定期重启服务或扩展热更新机制。

## 运维与调试
- `-d`：开启调试模式，将缓存命中、上游请求等细节写入日志。
- `-l <file>`：将日志同时写入指定文件。
- 日志格式：`YYYY/MM/DD HH:MM:SS <消息>`，附带彩色等级区分。
- 指标接口：开启 `metrics_address` 后，可访问 `http://<addr>/metrics` 获取 Prometheus 指标，`/healthz` 返回 200 代表存活。
- 配置热加载：向进程发送 `SIGHUP` 即可重新读取 `config.yaml` 并刷新规则与缓存，无需重启。

## 构建与发布
使用内置的 `build.sh` 可在 Linux 环境下交叉编译并打包：
```bash
chmod +x build.sh
./build.sh
```
脚本默认构建 `linux-amd64` 版本，产物存放在 `Releases/` 目录，包含可执行文件与配置示例，可按需扩展 `platforms` 数组生成多平台包。

## 测试与验证建议
- 本地测试：可使用 `dig @127.0.0.1 example.com` 验证解析效果。
- 缓存命中：连续查询同一域名，观察日志或抓包确认返回速度。
- 重写规则：添加自定义规则后查询目标域名，确认返回目标 IP。
- 上游容灾：临时关闭部分上游 DNS，验证并发回源的容错能力。

## 开发与扩展方向
- **DoH 支持**：进一步扩展上游协议（当前支持 UDP/TCP/DoT），实现基于 HTTPS 的 DNS 查询。
- **规则自定义 TTL**：允许单条规则配置独立 TTL，满足不同域名的缓存需求。
- **访问控制**：接入 ACL/QPS 限制等安全措施，对异常流量进行审计。
- **规则优化**：引入后缀树/AC 自动机等结构提升匹配性能。

欢迎提交 Issue 或 PR 共同完善本项目，如需更多指导可联系维护者讨论需求细节。
