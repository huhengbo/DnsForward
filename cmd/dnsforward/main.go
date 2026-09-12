package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/miekg/dns"
)

var (
	version string // 编译时写入版本号

	ConfigFilePath string // 配置文件路径
	LogFilePath    string // 日志文件路径
	EnableDebug    bool   // 调试模式开关
	printVersion   bool

	cfg Config // 当前生效的配置
)

func init() {
	help := `
DnsForward ` + version + `
https://github.com/huhengbo/DnsForward

参数：
    -c config.yaml
        配置文件 (默认 config.yaml)
    -l dns.log
        日志文件 (默认 无)
    -d
        调试模式 (默认 关)
    -v
        程序版本
    -h
        帮助说明
`
	flag.StringVar(&ConfigFilePath, "c", "config.yaml", "配置文件")
	flag.StringVar(&LogFilePath, "l", "", "日志文件")
	flag.BoolVar(&EnableDebug, "d", false, "调试模式")
	flag.BoolVar(&printVersion, "v", false, "程序版本")
	flag.Usage = func() { fmt.Print(help) }
}

func main() {
	flag.Parse()
	if printVersion {
		fmt.Printf("huhengbo/DnsForward %s\n", version)
		return
	}

	ensureMetricsRegistered()

	loadedCfg, err := loadConfigFromFile(ConfigFilePath)
	if err != nil {
		fatalf("配置文件读取失败: %v", err)
	}
	if err := applyRuntimeConfig(loadedCfg); err != nil {
		fatalf("应用配置失败: %v", err)
	}

	serviceLogger(fmt.Sprintf("调试模式: %v", EnableDebug), 32, false)

	if metricsAddr := strings.TrimSpace(cfg.Server.MetricsAddress); metricsAddr != "" {
		startMetricsServer(metricsAddr)
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP)
	go func() {
		for range signalChan {
			serviceLogger("收到 SIGHUP，开始重新加载配置", 0, false)
			newCfg, err := loadConfigFromFile(ConfigFilePath)
			if err != nil {
				serviceLogger(fmt.Sprintf("配置重载失败（读取）: %v", err), 31, false)
				continue
			}
			if err := applyRuntimeConfig(newCfg); err != nil {
				serviceLogger(fmt.Sprintf("配置重载失败（应用）: %v", err), 31, false)
				continue
			}
			serviceLogger("配置热加载完成", 32, false)
		}
	}()

	runtime := currentRuntime()
	if runtime == nil {
		fatalf("运行时配置初始化失败")
	}

	dnsAddr := strings.TrimSpace(cfg.Server.Address)
	if dnsAddr == "" {
		fatalf("server.address 未配置")
	}

	dns.HandleFunc(".", handleDNSRequest)
	serviceLogger(fmt.Sprintf("开始监听: %v", dnsAddr), 0, false)

	udpServer := &dns.Server{Addr: dnsAddr, Net: "udp"}
	go func() {
		if err := udpServer.ListenAndServe(); err != nil {
			serviceLogger(fmt.Sprintf("启动UDP服务失败: %v", err), 31, false)
		}
	}()

	tcpServer := &dns.Server{Addr: dnsAddr, Net: "tcp"}
	if err := tcpServer.ListenAndServe(); err != nil {
		serviceLogger(fmt.Sprintf("启动TCP服务失败: %v", err), 31, false)
	}
}
