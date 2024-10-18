package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"gopkg.in/yaml.v2"
)

var (
	version string // 编译时写入版本号

	ConfigFilePath string // 配置文件
	LogFilePath    string // 日志文件
	EnableDebug    bool   // 调试模式（详细日志）

	cfg Config // 配置文件结构
)

type Config struct {
	Server struct {
		Address         string `yaml:"address"`
		CacheExpiration string `yaml:"cache_expiration"`
	} `yaml:"server"`

	Upstream struct {
		DNSServers []string `yaml:"dns_servers"`
	} `yaml:"upstream"`

	Rewrite struct {
		Rules []Rule `yaml:"rules"`
	} `yaml:"rewrite"`
}

type Rule struct {
	Type   string `yaml:"type"`
	Value  string `yaml:"value"`
	Target string `yaml:"target"`
}

var upstreamDNS []string
var mergedRules []Rule // 存储合并后的所有规则
var dnsCache *cache.Cache

func init() {
	var printVersion bool
	var help = `
SNIProxy ` + version + `
https://github.com/huhengbo/dnsForward

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
	flag.Parse()
	if printVersion {
		fmt.Printf("huhengbo/dnsForward %s\n", version)
		os.Exit(0)
	}
}

// 下载在线规则集
func downloadRuleSet(url string) ([]string, error) {
	serviceLogger(fmt.Sprintf("下载远程规则文件: %v", url), 32, false)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("下载远程规则文件失败，状态码: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var rules []string
	for scanner.Scan() {
		rules = append(rules, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return rules, nil
}

// 读取本地规则集
func loadLocalRuleSet(path string) ([]string, error) {
	serviceLogger(fmt.Sprintf("加载本地配置文件: %s", path), 0, false)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var rules []string
	for scanner.Scan() {
		rules = append(rules, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return rules, nil
}

// 解析规则集文件内容
func parseRuleSetContent(lines []string, target string) []Rule {
	var parsedRules []Rule
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			// 跳过空行和注释
			continue
		}

		// 分割规则类型和内容
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			// 无效的规则格式，跳过
			continue
		}

		ruleType := strings.TrimSpace(parts[0])
		ruleValue := strings.TrimSpace(parts[1])

		// 根据规则类型处理
		switch ruleType {
		case "DOMAIN":
			// 完整域名匹配
			parsedRules = append(parsedRules, Rule{
				Type:   "DOMAIN",
				Value:  ruleValue,
				Target: target, // 默认目标 IP，可根据需要调整
			})
		case "DOMAIN-SUFFIX":
			// 域名后缀匹配
			parsedRules = append(parsedRules, Rule{
				Type:   "DOMAIN-SUFFIX",
				Value:  ruleValue,
				Target: target, // 默认目标 IP
			})
		case "DOMAIN-KEYWORD":
			// 关键字匹配
			parsedRules = append(parsedRules, Rule{
				Type:   "DOMAIN-KEYWORD",
				Value:  ruleValue,
				Target: target, // 默认目标 IP
			})
		// 忽略不处理的规则类型
		case "USER-AGENT", "IP-CIDR", "SRC-IP-CIDR", "SRC-PORT", "DST-PORT", "PROCESS-NAME":
			continue
		default:
			serviceLogger(fmt.Sprintf("不支持的规则类型！: %s", ruleType), 31, false)
		}
	}
	return parsedRules
}

// 从本地文件或在线地址加载规则集
func loadRuleSet(rule Rule) ([]Rule, error) {
	var lines []string
	var err error

	// 判断是在线文件还是本地文件
	if strings.HasPrefix(rule.Value, "http://") || strings.HasPrefix(rule.Value, "https://") {
		// 在线规则集
		lines, err = downloadRuleSet(rule.Value)
	} else {
		// 本地规则集
		lines, err = loadLocalRuleSet(rule.Value)
	}

	if err != nil {
		return nil, err
	}

	// 解析规则集内容
	return parseRuleSetContent(lines, rule.Target), nil
}

// 在程序启动时预加载并合并所有规则
func loadAndMergeRules(rules []Rule) []Rule {
	var merged []Rule

	for _, rule := range rules {
		if rule.Type == "RULE-SET" {
			// 加载 RULE-SET 并解析为规则
			parsedRules, err := loadRuleSet(rule)
			if err != nil {
				serviceLogger(fmt.Sprintf("加载规则文件失败！: %v", err), 31, false)
				continue
			}
			// 合并解析后的规则
			merged = append(merged, parsedRules...)
		} else {
			// 普通规则直接添加
			merged = append(merged, rule)
		}
	}

	return merged
}

// 处理 DNS 请求的函数
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	msg.Authoritative = true

	if len(r.Question) > 0 {
		question := r.Question[0]
		domain := question.Name

		// 先检查缓存
		if cachedMsg, found := dnsCache.Get(domain); found {
			resp := cachedMsg.(*dns.Msg)
			resp.Id = r.Id // 更新 ID 以匹配请求
			serviceLogger(fmt.Sprintf("缓存命中！: %s -> %v", domain, extractRecords(resp.Answer)), 32, true)
			w.WriteMsg(resp)
			serviceLogger(fmt.Sprintf("DNS解析：%s%s", strings.TrimSuffix(domain, "."), extractRecords(resp.Answer)), 1, true)
			return
		}

		// 检查是否有重写规则
		if ip := matchRule(domain); ip != "" {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600}
			rr.A = net.ParseIP(ip)
			msg.Answer = append(msg.Answer, rr)
			dnsCache.Set(domain, &msg, cache.DefaultExpiration) // 缓存重写的结果
			serviceLogger(fmt.Sprintf("DNS重写：%s%s", strings.TrimSuffix(domain, "."), extractRecords(msg.Answer)), 1, true)
		} else {
			// 上游查询
			resp := forwardToUpstreamParallel(r)
			if resp != nil {
				serviceLogger(fmt.Sprintf("上游DNS解析！: %s -> %v", domain, extractRecords(resp.Answer)), 32, true)
				// 缓存上游查询结果
				dnsCache.Set(domain, resp, cache.DefaultExpiration)
				w.WriteMsg(resp)
			} else {
				dns.HandleFailed(w, r)
			}
			serviceLogger(fmt.Sprintf("DNS解析：%s%s", strings.TrimSuffix(domain, "."), extractRecords(resp.Answer)), 1, true)
			return
		}

	}
	w.WriteMsg(&msg)
}

// 从 DNS 响应中提取所有记录信息
func extractRecords(answers []dns.RR) []string {
	var records []string
	for _, ans := range answers {
		switch v := ans.(type) {
		case *dns.A:
			records = append(records, v.A.String())
		case *dns.CNAME:
			records = append(records, v.Target)
		default:
			records = append(records, v.String())
		}
	}
	return records
}

// 匹配 DNS 请求的规则
func matchRule(domain string) string {
	domain = strings.TrimSuffix(domain, ".")

	// 遍历所有合并后的规则进行匹配
	for _, rule := range mergedRules {
		if match := matchSingleRule(domain, rule); match != "" {
			return match
		}
	}
	return ""
}

// 匹配单个规则
func matchSingleRule(domain string, rule Rule) string {
	switch rule.Type {
	case "DOMAIN":
		if domain == rule.Value {
			return rule.Target
		}
	case "DOMAIN-SUFFIX":
		if strings.HasSuffix(domain, rule.Value) {
			return rule.Target
		}
	case "DOMAIN-KEYWORD":
		if strings.Contains(domain, rule.Value) {
			return rule.Target
		}
	}
	return ""
}

// 并行查询多个上游 DNS 服务器，返回最快的响应
func forwardToUpstreamParallel(r *dns.Msg) *dns.Msg {
	var wg sync.WaitGroup
	respChan := make(chan *dns.Msg, 1)

	// 并行查询每个上游 DNS
	for _, dnsServer := range upstreamDNS {
		wg.Add(1)
		go func(dnsServer string) {
			defer wg.Done()
			client := &dns.Client{SingleInflight: true}
			query := r.Copy() // 避免 ID mismatch
			resp, _, err := client.Exchange(query, dnsServer)
			if err == nil && resp != nil && len(resp.Answer) > 0 {
				select {
				case respChan <- resp:
					serviceLogger(fmt.Sprintf("上游响应成功: %s", dnsServer), 32, true)
				default:
				}
			}
		}(dnsServer)
	}

	// 等待最快的响应，或者超时返回 nil
	go func() {
		wg.Wait()
		close(respChan)
	}()

	select {
	case resp := <-respChan:
		return resp
	case <-time.After(2 * time.Second):
		serviceLogger(fmt.Sprintf("获取上游DNS响应超时"), 31, false)
		return nil
	}
}

func main() {
	data, err := os.ReadFile(ConfigFilePath) // 读取配置文件
	if err != nil {
		serviceLogger(fmt.Sprintf("配置文件读取失败: %v", err), 31, false)
		os.Exit(1)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		serviceLogger(fmt.Sprintf("配置文件解析失败: %v", err), 31, false)
		os.Exit(1)
	}
	if len(cfg.Upstream.DNSServers) <= 0 { // 如果 rules 为空且 allow_all_hosts 不等于 true
		serviceLogger("配置文件中 dns_servers 不能为空!", 31, false)
		os.Exit(1)
	}
	serviceLogger(fmt.Sprintf("调试模式: %v", EnableDebug), 32, false)
	// 初始化上游 DNS 服务器
	upstreamDNS = cfg.Upstream.DNSServers
	// 解析缓存过期时间
	cacheExpiration, err := time.ParseDuration(cfg.Server.CacheExpiration)
	if err != nil {
		log.Fatalf("Invalid cache expiration format: %v\n", err)
	}
	// 初始化缓存
	dnsCache = cache.New(cacheExpiration, 10*time.Minute)
	// 预加载并合并所有规则
	mergedRules = loadAndMergeRules(cfg.Rewrite.Rules)
	// 设置 DNS 服务的地址和端口
	dnsAddr := cfg.Server.Address
	// 设置 DNS 服务器处理器
	dns.HandleFunc(".", handleDNSRequest)
	serviceLogger(fmt.Sprintf("开始监听: %v", dnsAddr), 0, false)
	// 启动 UDP 监听
	udpServer := &dns.Server{Addr: dnsAddr, Net: "udp"}
	go func() {
		if err := udpServer.ListenAndServe(); err != nil {
			serviceLogger(fmt.Sprintf("启动UDP服务失败: %v", err), 31, false)
		}
	}()

	// 启动 TCP 监听
	tcpServer := &dns.Server{Addr: dnsAddr, Net: "tcp"}
	if err := tcpServer.ListenAndServe(); err != nil {
		serviceLogger(fmt.Sprintf("启动TCP服务失败: %v", err), 31, false)
	}
}

// 输出日志
func serviceLogger(log string, color int, isDebug bool) {
	if isDebug && !EnableDebug {
		return
	}
	log = strings.Replace(log, "\n", "", -1)
	log = strings.Join([]string{time.Now().Format("2006/01/02 15:04:05"), " ", log}, "")
	if color == 0 {
		fmt.Printf("%s\n", log)
	} else {
		fmt.Printf("%c[1;0;%dm%s%c[0m\n", 0x1B, color, log, 0x1B)
	}
	if LogFilePath != "" {
		fd, _ := os.OpenFile(LogFilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		fdContent := strings.Join([]string{log, "\n"}, "")
		buf := []byte(fdContent)
		fd.Write(buf)
		fd.Close()
	}
}
