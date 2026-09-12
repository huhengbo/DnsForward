package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type Rule struct {
	Type   string `yaml:"type"`
	Value  string `yaml:"value"`
	Target string `yaml:"target"`
}

type compiledRule struct {
	value  string
	target string
}

type ruleMatcher struct {
	domain  map[string]string
	suffix  map[string][]compiledRule
	keyword []compiledRule
}

func downloadRuleSet(url string, client *http.Client, attempts int) ([]string, error) {
	if attempts <= 0 {
		attempts = 1
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		serviceLogger(fmt.Sprintf("下载远程规则文件: %v (尝试 %d/%d)", url, i+1, attempts), 32, false)
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
		} else {
			if resp.StatusCode != http.StatusOK {
				lastErr = fmt.Errorf("下载远程规则文件失败，状态码: %d", resp.StatusCode)
				resp.Body.Close()
			} else {
				scanner := bufio.NewScanner(resp.Body)
				var rules []string
				for scanner.Scan() {
					rules = append(rules, scanner.Text())
				}
				err = scanner.Err()
				resp.Body.Close()
				if err != nil {
					lastErr = err
				} else {
					return rules, nil
				}
			}
		}
		if i < attempts-1 {
			time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
		}
	}
	if lastErr == nil {
		return nil, fmt.Errorf("下载远程规则文件失败")
	}
	return nil, fmt.Errorf("下载远程规则文件失败: %w", lastErr)
}

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

func parseRuleSetContent(lines []string, target string) []Rule {
	var parsedRules []Rule
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		ruleType := strings.TrimSpace(parts[0])
		ruleValue := strings.TrimSpace(parts[1])
		switch ruleType {
		case "DOMAIN":
			parsedRules = append(parsedRules, Rule{Type: "DOMAIN", Value: ruleValue, Target: target})
		case "DOMAIN-SUFFIX":
			parsedRules = append(parsedRules, Rule{Type: "DOMAIN-SUFFIX", Value: ruleValue, Target: target})
		case "DOMAIN-KEYWORD":
			parsedRules = append(parsedRules, Rule{Type: "DOMAIN-KEYWORD", Value: ruleValue, Target: target})
		case "USER-AGENT", "IP-CIDR", "SRC-IP-CIDR", "SRC-PORT", "DST-PORT", "PROCESS-NAME", "IP-CIDR6":
			continue
		default:
			serviceLogger(fmt.Sprintf("不支持的规则类型！: %s", ruleType), 31, false)
		}
	}
	return parsedRules
}

func loadRuleSet(rule Rule, client *http.Client, attempts int) ([]Rule, error) {
	var lines []string
	var err error
	if strings.HasPrefix(rule.Value, "http://") || strings.HasPrefix(rule.Value, "https://") {
		lines, err = downloadRuleSet(rule.Value, client, attempts)
	} else {
		lines, err = loadLocalRuleSet(rule.Value)
	}
	if err != nil {
		return nil, err
	}
	return parseRuleSetContent(lines, rule.Target), nil
}

func loadAndMergeRules(rules []Rule, client *http.Client, attempts int) []Rule {
	var merged []Rule
	for _, rule := range rules {
		if rule.Type == "RULE-SET" {
			parsedRules, err := loadRuleSet(rule, client, attempts)
			if err != nil {
				serviceLogger(fmt.Sprintf("加载规则文件失败！: %v", err), 31, false)
				continue
			}
			merged = append(merged, parsedRules...)
		} else {
			merged = append(merged, rule)
		}
	}
	return merged
}

func buildRuleMatcher(rules []Rule) ruleMatcher {
	m := ruleMatcher{
		domain: make(map[string]string),
		suffix: make(map[string][]compiledRule),
	}
	for _, rule := range rules {
		value := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rule.Value), "."))
		if value == "" {
			continue
		}
		switch rule.Type {
		case "DOMAIN":
			m.domain[value] = rule.Target
		case "DOMAIN-SUFFIX":
			label := lastLabel(value)
			m.suffix[label] = append(m.suffix[label], compiledRule{value: value, target: rule.Target})
		case "DOMAIN-KEYWORD":
			m.keyword = append(m.keyword, compiledRule{value: value, target: rule.Target})
		}
	}
	return m
}

func lastLabel(domain string) string {
	if idx := strings.LastIndex(domain, "."); idx >= 0 {
		return domain[idx+1:]
	}
	return domain
}

func matchRule(domain string, matcher ruleMatcher) string {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return ""
	}
	value := strings.ToLower(domain)
	if target, ok := matcher.domain[value]; ok {
		return target
	}
	label := lastLabel(value)
	if rules, ok := matcher.suffix[label]; ok {
		for _, rule := range rules {
			if value == rule.value || strings.HasSuffix(value, "."+rule.value) {
				return rule.target
			}
		}
	}
	for _, rule := range matcher.keyword {
		if strings.Contains(value, rule.value) {
			return rule.target
		}
	}
	return ""
}
