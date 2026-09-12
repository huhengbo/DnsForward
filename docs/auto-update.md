# DnsForward 自动升级

Linux + systemd 安装方式提供 `dnsforwardctl` 版本管理能力。

## 检查更新

```bash
dnsforwardctl check-update
```

命令会显示当前安装版本和 GitHub 最新正式 Release。`latest` 只指向正式 Release，不跟随 prerelease。

## 手动升级

升级到最新正式版：

```bash
sudo dnsforwardctl upgrade
```

升级到指定版本：

```bash
sudo dnsforwardctl upgrade v1.2.0
```

升级过程会：

1. 根据当前 Linux 架构选择 amd64 / arm64 Release 包。
2. 下载 Release 包和 `checksums.txt`。
3. 校验 SHA256。
4. 验证包内二进制报告的版本号与目标版本一致。
5. 备份当前 `/usr/local/bin/dnsforward`。
6. 替换二进制并同步更新 `/usr/local/bin/dnsforwardctl`。
7. 重启 `dnsforward.service`。
8. 如果新版本无法保持 active，恢复旧二进制并重新启动服务。

升级不会覆盖 `/etc/dnsforward/config.yaml`。

## 自动升级

自动升级默认关闭。

启用：

```bash
sudo dnsforwardctl auto-update enable
```

状态：

```bash
sudo dnsforwardctl auto-update status
```

关闭：

```bash
sudo dnsforwardctl auto-update disable
```

启用后会安装 `dnsforward-update.timer`。timer 每天触发一次，并加入最多 1 小时随机延迟，执行：

```bash
/usr/local/bin/dnsforwardctl upgrade
```

因此只有显式执行 `auto-update enable` 后才会无人值守安装新版本。

## 查看自动升级记录

```bash
journalctl -u dnsforward-update.service
systemctl list-timers dnsforward-update.timer
```

## 卸载

```bash
sudo dnsforwardctl uninstall
```

卸载会同时移除 `dnsforward-update.timer` / `dnsforward-update.service`，但保留 `/etc/dnsforward/config.yaml`。
