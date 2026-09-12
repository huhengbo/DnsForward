package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

const webPage = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DnsForward</title>
<style>
:root{color-scheme:light dark;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}body{max-width:980px;margin:0 auto;padding:24px}header{display:flex;justify-content:space-between;align-items:center;gap:16px}h1{margin:0}small{opacity:.7}.card{border:1px solid #7776;border-radius:12px;padding:16px;margin-top:18px}textarea{width:100%;min-height:520px;box-sizing:border-box;font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;padding:12px;border-radius:8px;border:1px solid #7778}button,a.button{display:inline-block;padding:9px 14px;border:0;border-radius:8px;text-decoration:none;cursor:pointer;margin-right:8px}button.primary{background:#2563eb;color:white}.row{display:flex;gap:12px;flex-wrap:wrap}.status{font-weight:600}.ok{color:#16a34a}.error{color:#dc2626}pre{white-space:pre-wrap;max-height:280px;overflow:auto}</style>
</head>
<body>
<header><div><h1>DnsForward</h1><small id="version"></small></div><div class="status" id="status">加载中…</div></header>
<div class="card"><strong>服务状态</strong><p id="summary"></p><div class="row"><a class="button" href="/healthz" target="_blank">Health</a><a class="button" href="/metrics" target="_blank">Metrics</a></div></div>
<div class="card"><strong>配置</strong><p><small>直接编辑 YAML，可管理 upstream、Rewrite 和 RULE-SET。保存前会完整校验，成功后立即 reload。修改 web_address 后需重启进程才能切换监听地址。</small></p><textarea id="config"></textarea><p><button onclick="validateConfig()">校验</button><button class="primary" onclick="saveConfig()">保存并重载</button> <span id="configResult"></span></p></div>
<div class="card"><strong>最近日志</strong><p><button onclick="loadLogs()">刷新</button></p><pre id="logs"></pre></div>
<script>
const $=id=>document.getElementById(id);
async function request(url,options){const r=await fetch(url,options);const text=await r.text();if(!r.ok)throw new Error(text||r.statusText);return text}
async function loadStatus(){try{const s=JSON.parse(await request('/api/status'));$('version').textContent=s.version||'dev';$('status').textContent='运行中';$('status').className='status ok';$('summary').textContent='DNS: '+s.dns_address+' · Web: '+(s.web_address||'关闭')+' · 配置: '+s.config_file}catch(e){$('status').textContent='状态获取失败';$('status').className='status error'}}
async function loadConfig(){try{$('config').value=await request('/api/config')}catch(e){$('configResult').textContent=e.message;$('configResult').className='error'}}
async function validateConfig(){try{await request('/api/config/validate',{method:'POST',headers:{'Content-Type':'text/yaml'},body:$('config').value});$('configResult').textContent='配置有效';$('configResult').className='ok'}catch(e){$('configResult').textContent=e.message;$('configResult').className='error'}}
async function saveConfig(){try{await request('/api/config',{method:'PUT',headers:{'Content-Type':'text/yaml'},body:$('config').value});$('configResult').textContent='已保存并重载';$('configResult').className='ok';loadStatus()}catch(e){$('configResult').textContent=e.message;$('configResult').className='error'}}
async function loadLogs(){try{$('logs').textContent=await request('/api/logs')}catch(e){$('logs').textContent=e.message}}
loadStatus();loadConfig();loadLogs();
</script>
</body></html>`

func startWebServer(addr string) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", webIndexHandler)
	mux.HandleFunc("/api/status", webStatusHandler)
	mux.HandleFunc("/api/config", webConfigHandler)
	mux.HandleFunc("/api/config/validate", webConfigValidateHandler)
	mux.HandleFunc("/api/logs", webLogsHandler)
	mux.Handle("/metrics", metricsHandler())
	mux.HandleFunc("/healthz", healthHandler)

	go func() {
		serviceLogger(fmt.Sprintf("Web 管理监听: %s", addr), 0, false)
		if err := http.ListenAndServe(addr, mux); err != nil {
			serviceLogger(fmt.Sprintf("Web 管理服务失败: %v", err), 31, false)
		}
	}()
}

func webIndexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, webPage)
}

func webStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]interface{}{
		"version":     version,
		"dns_address": cfg.Server.Address,
		"web_address": cfg.Server.WebAddress,
		"config_file": ConfigFilePath,
		"started":     currentRuntime() != nil,
	})
}

func webConfigHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(ConfigFilePath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		_, _ = w.Write(data)
	case http.MethodPut:
		data, err := readConfigBody(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		newCfg, err := parseAndValidateConfig(data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, err := buildRuntimeFromConfig(newCfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := writeConfigAtomically(ConfigFilePath, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := applyRuntimeConfig(newCfg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		serviceLogger("Web 管理已保存并重载配置", 32, false)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func webConfigValidateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := readConfigBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	newCfg, err := parseAndValidateConfig(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := buildRuntimeFromConfig(newCfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func webLogsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, strings.Join(recentLogLines(), "\n"))
}

func readConfigBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, fmt.Errorf("配置不能为空")
	}
	return data, nil
}

func parseAndValidateConfig(data []byte) (Config, error) {
	var newCfg Config
	if err := yaml.UnmarshalStrict(data, &newCfg); err != nil {
		return Config{}, err
	}
	if err := validateConfig(&newCfg); err != nil {
		return Config{}, err
	}
	return newCfg, nil
}

func writeConfigAtomically(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".dnsforward-config-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func writeJSON(w http.ResponseWriter, value interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(value)
}
