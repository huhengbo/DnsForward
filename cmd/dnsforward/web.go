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

const webLoginPage = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 · DnsForward</title>
<style>
:root{font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#172033;background:#f4f7fb}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px}.panel{width:min(420px,100%);background:#fff;border:1px solid #e4e9f2;border-radius:20px;padding:28px;box-shadow:0 18px 50px #233b6b18}.logo{width:48px;height:48px;border-radius:14px;background:#2563eb;color:#fff;display:grid;place-items:center;font-weight:800;font-size:20px;margin-bottom:18px}h1{margin:0 0 8px;font-size:24px}.muted{color:#70809a;font-size:14px;line-height:1.6}label{display:block;margin:22px 0 8px;font-size:13px;font-weight:700}input{width:100%;padding:12px 14px;border:1px solid #d6deea;border-radius:10px;font:inherit;outline:none}input:focus{border-color:#2563eb;box-shadow:0 0 0 3px #2563eb18}button{width:100%;margin-top:16px;padding:12px;border:0;border-radius:10px;background:#2563eb;color:#fff;font:inherit;font-weight:700;cursor:pointer}.error{margin-top:14px;padding:10px 12px;border-radius:10px;background:#fff1f2;color:#be123c;font-size:13px}@media(prefers-color-scheme:dark){:root{color:#e8edf6;background:#0f1520}.panel{background:#171f2d;border-color:#273247;box-shadow:none}.muted{color:#91a0b8}input{background:#111827;color:#eef2f7;border-color:#344158}.error{background:#3a1820;color:#fda4af}}
</style>
</head>
<body>
<form class="panel" method="post" action="/login">
<div class="logo">DF</div>
<h1>DnsForward 管理</h1>
<div class="muted">请输入管理密码。登录会话仅保存在当前进程内，服务重启后会自动失效。</div>
<label for="password">管理密码</label>
<input id="password" name="password" type="password" autocomplete="current-password" autofocus required>
<button type="submit">登录</button>
{{ERROR}}
</form>
</body>
</html>`

const webPage = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DnsForward</title>
<style>
:root{font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#172033;background:#f4f7fb;--panel:#fff;--line:#e4e9f2;--muted:#70809a;--primary:#2563eb;--good:#159447;--bad:#c43d4d;--code:#0f172a}*{box-sizing:border-box}body{margin:0}.shell{max-width:1280px;margin:auto;padding:24px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:20px}.brand{display:flex;align-items:center;gap:12px}.logo{width:42px;height:42px;border-radius:12px;background:var(--primary);color:#fff;display:grid;place-items:center;font-weight:800}.brand h1{font-size:20px;margin:0}.sub{font-size:12px;color:var(--muted);margin-top:2px}.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.btn,.tab{border:1px solid var(--line);background:var(--panel);color:inherit;border-radius:9px;padding:9px 12px;font:inherit;font-size:13px;cursor:pointer;text-decoration:none}.btn.primary{background:var(--primary);border-color:var(--primary);color:#fff}.btn.danger{color:var(--bad)}.status-dot{width:9px;height:9px;border-radius:50%;background:var(--good);display:inline-block;margin-right:7px}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px}.metric-label{color:var(--muted);font-size:12px}.metric-value{font-weight:700;margin-top:8px;overflow-wrap:anywhere}.nav{display:flex;gap:8px;margin:20px 0 12px;overflow:auto}.tab.active{background:#eaf1ff;border-color:#c8d8ff;color:#174db8}.section{display:none}.section.active{display:block}.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}.section-title{font-size:16px;font-weight:800}.hint{font-size:12px;color:var(--muted);line-height:1.6}.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.editor{width:100%;min-height:560px;resize:vertical;background:var(--code);color:#dbeafe;border:0;border-radius:12px;padding:16px;font:13px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;outline:none}.editor:focus{box-shadow:0 0 0 3px #2563eb22}.result{font-size:12px;color:var(--muted)}.ok{color:var(--good)}.error{color:var(--bad)}pre.logs{margin:0;min-height:360px;max-height:600px;overflow:auto;background:var(--code);color:#cbd5e1;border-radius:12px;padding:16px;font:12px/1.65 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap}.link-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.link-card{display:block;padding:18px;border:1px solid var(--line);border-radius:12px;text-decoration:none;color:inherit;background:var(--panel)}.link-card strong{display:block;margin-bottom:6px}.link-card span{color:var(--muted);font-size:12px}.notice{padding:12px 14px;border-radius:10px;background:#fff8e7;color:#8a5b00;font-size:12px;margin-bottom:12px}@media(max-width:800px){.shell{padding:16px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.topbar{align-items:flex-start}.editor{min-height:440px}}@media(max-width:520px){.grid{grid-template-columns:1fr}.actions .status-text{display:none}.link-grid{grid-template-columns:1fr}.section-head{align-items:flex-start;flex-direction:column}.toolbar{width:100%}.toolbar .btn{flex:1}.topbar{flex-direction:column}.actions{width:100%}}
@media(prefers-color-scheme:dark){:root{color:#e8edf6;background:#0f1520;--panel:#171f2d;--line:#2a3549;--muted:#91a0b8;--code:#0a101a}.tab.active{background:#1b315f;border-color:#345a9d;color:#bcd2ff}.notice{background:#332a15;color:#f4cd78}}
</style>
</head>
<body>
<div class="shell">
<div class="topbar"><div class="brand"><div class="logo">DF</div><div><h1>DnsForward</h1><div class="sub" id="version">加载中</div></div></div><div class="actions"><span class="status-text"><span class="status-dot"></span>运行中</span><button class="btn" onclick="refreshAll()">刷新</button><a class="btn danger" href="/logout">退出</a></div></div>
<div class="grid">
<div class="card"><div class="metric-label">版本</div><div class="metric-value" id="cardVersion">-</div></div>
<div class="card"><div class="metric-label">DNS 监听</div><div class="metric-value" id="cardDNS">-</div></div>
<div class="card"><div class="metric-label">Web 管理</div><div class="metric-value" id="cardWeb">-</div></div>
<div class="card"><div class="metric-label">认证</div><div class="metric-value" id="cardAuth">-</div></div>
</div>
<div class="nav"><button class="tab active" data-section="config">配置</button><button class="tab" data-section="logs">日志</button><button class="tab" data-section="observe">观测</button></div>
<section class="section active" id="section-config"><div class="card"><div class="section-head"><div><div class="section-title">运行配置</div><div class="hint">编辑完整 YAML，可管理 Upstream、Rewrite、RULE-SET。保存前会校验并在成功后热重载；web_address 变更仍需重启。</div></div><div class="toolbar"><button class="btn" onclick="validateConfig()">校验</button><button class="btn primary" onclick="saveConfig()">保存并重载</button></div></div><div class="notice">修改 web_password_hash 会立即使现有登录会话失效，需要使用新密码重新登录。</div><textarea class="editor" id="config" spellcheck="false"></textarea><div class="result" id="configResult">配置文件：<span id="configPath">-</span></div></div></section>
<section class="section" id="section-logs"><div class="card"><div class="section-head"><div><div class="section-title">最近日志</div><div class="hint">显示进程内最近 200 条日志，不依赖文件日志配置。</div></div><button class="btn" onclick="loadLogs()">刷新日志</button></div><pre class="logs" id="logs">加载中…</pre></div></section>
<section class="section" id="section-observe"><div class="link-grid"><a class="link-card" href="/healthz" target="_blank"><strong>Health</strong><span>查看当前服务健康状态</span></a><a class="link-card" href="/metrics" target="_blank"><strong>Prometheus Metrics</strong><span>查看缓存、重写、上游、ACL 与并发指标</span></a></div></section>
</div>
<script>
const $=id=>document.getElementById(id);
async function request(url,options){const r=await fetch(url,options);if(r.status===401){location.href='/login';throw new Error('unauthorized')}const text=await r.text();if(!r.ok)throw new Error(text||r.statusText);return text}
function showResult(text,kind){$('configResult').textContent=text;$('configResult').className='result '+(kind||'')}
async function loadStatus(){try{const s=JSON.parse(await request('/api/status'));$('version').textContent=s.version||'dev';$('cardVersion').textContent=s.version||'dev';$('cardDNS').textContent=s.dns_address||'-';$('cardWeb').textContent=s.web_address||'关闭';$('cardAuth').textContent=s.auth_enabled?'已启用':'未配置';$('configPath').textContent=s.config_file||'-'}catch(e){showResult('状态获取失败: '+e.message,'error')}}
async function loadConfig(){try{$('config').value=await request('/api/config')}catch(e){showResult(e.message,'error')}}
async function validateConfig(){try{await request('/api/config/validate',{method:'POST',headers:{'Content-Type':'text/yaml'},body:$('config').value});showResult('配置校验通过','ok')}catch(e){showResult(e.message,'error')}}
async function saveConfig(){try{await request('/api/config',{method:'PUT',headers:{'Content-Type':'text/yaml'},body:$('config').value});showResult('已保存并重载','ok');await loadStatus()}catch(e){if(e.message!=='unauthorized')showResult(e.message,'error')}}
async function loadLogs(){try{$('logs').textContent=await request('/api/logs')}catch(e){$('logs').textContent=e.message}}
async function refreshAll(){await Promise.all([loadStatus(),loadConfig(),loadLogs()])}
document.querySelectorAll('.tab').forEach(btn=>btn.addEventListener('click',()=>{document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.section').forEach(x=>x.classList.remove('active'));btn.classList.add('active');$('section-'+btn.dataset.section).classList.add('active')}));
refreshAll();
</script>
</body></html>`

func startWebServer(addr string) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", webLoginHandler)
	mux.HandleFunc("/logout", webLogoutHandler)
	mux.Handle("/", requireWebAuth(http.HandlerFunc(webIndexHandler)))
	mux.Handle("/api/status", requireWebAuth(http.HandlerFunc(webStatusHandler)))
	mux.Handle("/api/config", requireWebAuth(http.HandlerFunc(webConfigHandler)))
	mux.Handle("/api/config/validate", requireWebAuth(http.HandlerFunc(webConfigValidateHandler)))
	mux.Handle("/api/logs", requireWebAuth(http.HandlerFunc(webLogsHandler)))
	mux.Handle("/metrics", requireWebAuth(metricsHandler()))
	mux.Handle("/healthz", requireWebAuth(http.HandlerFunc(healthHandler)))

	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * 1000000000}
	go func() {
		serviceLogger(fmt.Sprintf("Web 管理监听: %s", addr), 0, false)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serviceLogger(fmt.Sprintf("Web 管理服务失败: %v", err), 31, false)
		}
	}()
}

func webLoginHandler(w http.ResponseWriter, r *http.Request) {
	if !webAuthEnabled() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if validWebSession(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	errorHTML := ""
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil {
			errorHTML = `<div class="error">请求无效</div>`
		} else if !verifyPasswordHash(cfg.Server.WebPasswordHash, r.FormValue("password")) {
			serviceLogger("Web 管理登录失败", 33, false)
			errorHTML = `<div class="error">密码错误</div>`
		} else {
			token, err := createWebSession()
			if err != nil {
				http.Error(w, "session create failed", http.StatusInternalServerError)
				return
			}
			setWebSessionCookie(w, token)
			serviceLogger("Web 管理登录成功", 32, false)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	} else if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, strings.Replace(webLoginPage, "{{ERROR}}", errorHTML, 1))
}

func webLogoutHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		deleteWebSession(cookie.Value)
	}
	clearWebSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
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
		"version":      version,
		"dns_address":  cfg.Server.Address,
		"web_address":  cfg.Server.WebAddress,
		"config_file":  ConfigFilePath,
		"auth_enabled": webAuthEnabled(),
		"started":      currentRuntime() != nil,
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
