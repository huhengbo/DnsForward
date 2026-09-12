# DnsForward

[![CI](https://github.com/huhengbo/DnsForward/actions/workflows/ci.yml/badge.svg)](https://github.com/huhengbo/DnsForward/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

DnsForward 是一个轻量级 DNS 转发与重写服务，面向本机或内网使用。它支持 UDP/TCP DNS、多个上游并发查询、本地缓存、域名重写、远程规则集、DoT、Prometheus 指标和配置热加载。

## 特性

- 多上游 DNS 并发查询
- A / AAAA 域名重写
- `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD` 和 `RULE-SET` 规则
- TTL 感知缓存和 NXDOMAIN/NODATA 负缓存
- UDP、TCP、DoT 上游
- CIDR 客户端访问控制，默认仅允许本机访问
- 全局并发查询限制
- Prometheus `/metrics` 和 `/healthz`
- Unix `SIGHUP` 配置热加载
- Linux、macOS、Windows 构建验证

## 快速开始

要求 Go 1.26 或更高版本。

```bash
git clone https://github.com/huhengbo/DnsForward.git
cd DnsForward

cp configs/config.example.yaml config.yaml
go run ./cmd/dnsforward -c config.yaml
```

`config.yaml` 是本地运行配置，默认不会提交到 Git。仓库只跟踪中性的示例配置 `configs/config.example.yaml`。

默认示例配置只监听本机：

- DNS: `127.0.0.1:53`
- Metrics: `127.0.0.1:9090`

验证 DNS：

```bash
dig @127.0.0.1 example.com
```

如果不希望直接使用 53 端口，可以把 `server.address` 改为例如 `127.0.0.1:5353`。

### 预编译版本

带 `v` 前缀的 tag 会自动发布 Linux、macOS、Windows 的 amd64/arm64 压缩包。每个压缩包包含可执行文件和 `config.example.yaml`，Release 同时提供 `checksums.txt` 用于 SHA256 校验。

## Linux 一键安装

当前一键安装与服务管理支持 **Linux + systemd**，支持 amd64 / arm64。安装脚本会从最新 GitHub Release 下载对应架构的程序，并使用 `checksums.txt` 校验 SHA256。

```bash
curl -fsSL https://raw.githubusercontent.com/huhengbo/DnsForward/master/scripts/install.sh | sudo bash
```

也可以安装指定版本：

```bash
curl -fsSL https://raw.githubusercontent.com/huhengbo/DnsForward/master/scripts/install.sh | sudo bash -s -- install v1.1.0
```

安装后文件位置：

```text
/usr/local/bin/dnsforward
/usr/local/bin/dnsforwardctl
/etc/dnsforward/config.yaml
/etc/systemd/system/dnsforward.service
```

常用管理命令：

```bash
sudo dnsforwardctl start
sudo dnsforwardctl stop
sudo dnsforwardctl restart
sudo dnsforwardctl status
sudo dnsforwardctl logs
sudo dnsforwardctl uninstall
```

`uninstall` 会移除 systemd 服务、`dnsforward` 和 `dnsforwardctl`，但会保留 `/etc/dnsforward/config.yaml`，便于后续重新安装时继续使用原配置。

修改 `/etc/dnsforward/config.yaml` 后，可直接重启服务：

```bash
sudo dnsforwardctl restart
```

## 配置

完整示例见 [`configs/config.example.yaml`](configs/config.example.yaml)。配置使用严格 YAML 解析，无法识别的字段会在启动时直接报错。

核心配置示例：

```yaml
server:
  address: "127.0.0.1:53"
  metrics_address: "127.0.0.1:9090"
  allow_cidrs:
    - "127.0.0.0/8"
    - "::1/128"
  max_concurrent_queries: 256
  cache_expiration: 5m
  negative_cache_ttl: 1m
  min_ttl: 10s
  max_ttl: 1h

upstream:
  dns_servers:
    - "8.8.8.8:53"
    - "tls://1.1.1.1@cloudflare-dns.com"
  timeout: 2s
  protocol: udp

rewrite:
  default_ttl: 10m
  rules:
    - type: "DOMAIN"
      value: "example.com"
      target: "192.0.2.10"
```

### server

- `address`: DNS UDP/TCP 监听地址。
- `metrics_address`: Prometheus 与健康检查监听地址；留空可关闭。
- `allow_cidrs`: 允许访问 DNS 服务的客户端网段。省略时默认只允许 loopback。
- `max_concurrent_queries`: 同时处理的查询上限，默认 256。
- `cache_expiration`: 无可用 RR TTL 时使用的默认本地缓存时间。
- `negative_cache_ttl`: 负缓存时间上限/兜底值。
- `min_ttl` / `max_ttl`: 本地缓存保留时间边界，不修改返回给客户端的 RR TTL。

### upstream

`dns_servers` 支持：

```text
8.8.8.8
8.8.8.8:53
tcp://1.1.1.1:53
tls://cloudflare-dns.com
tls://1.1.1.1@cloudflare-dns.com
```

使用 IP 地址作为 DoT 上游时，必须通过 `@hostname` 指定 TLS 校验名称；DnsForward 不会自动跳过证书校验。

### rewrite

支持以下规则：

- `DOMAIN`: 精确域名
- `DOMAIN-SUFFIX`: 域名及其子域
- `DOMAIN-KEYWORD`: 域名关键字
- `RULE-SET`: 本地文件或 HTTP(S) 规则集

每条重写规则必须提供非空 `value` 和有效 IP `target`。A 查询只会使用 IPv4 target，AAAA 查询只会使用 IPv6 target；其他记录类型继续查询上游。

## 安全说明

DnsForward 默认按本地服务使用，不应直接暴露为公网开放递归 DNS。

如果需要对局域网开放，请同时修改监听地址和 `allow_cidrs`，只允许需要的网段。例如：

```yaml
server:
  address: "0.0.0.0:53"
  allow_cidrs:
    - "192.168.1.0/24"
```

未授权客户端会收到 `REFUSED`，达到并发上限时返回 `SERVFAIL`，两者都不会继续访问上游。

不要把 metrics 端口无保护地暴露到公网。

## 指标与健康检查

启用 `metrics_address` 后：

```text
GET /metrics
GET /healthz
```

指标包含缓存命中、规则重写、上游请求与延迟、配置重载、ACL 拒绝和并发限制拒绝等数据。

## 热加载

Unix 系统可以向进程发送 `SIGHUP` 重新读取配置：

```bash
kill -HUP <pid>
```

## 开发

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/dnsforward
bash -n scripts/install.sh
```

GitHub Actions 还会执行格式检查、安装脚本语法检查、`staticcheck`、`govulncheck`，并验证 Linux/macOS/Windows 的 amd64/arm64 构建。

## 项目结构

```text
.
├── cmd/
│   └── dnsforward/       # DNS 服务实现、入口与测试
├── configs/
│   └── config.example.yaml
├── scripts/
│   └── install.sh        # Linux 一键安装与 systemd 管理
├── .github/              # CI、Release、Issue/PR 模板、Dependabot
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
├── go.mod
├── go.sum
└── README.md
```

当前项目只有一个可执行程序，因此代码保持在单个 `cmd/dnsforward` 包中；只有在出现明确复用边界时再拆分 `internal` 包。

## 贡献

提交修改前请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题请参考 [SECURITY.md](SECURITY.md)。

## License

本项目使用 [MIT License](LICENSE)。
