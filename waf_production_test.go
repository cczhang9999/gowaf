package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestConcurrentConfigUpdates 验证并发读写 Config 不会触发 data race。
// 这是生产环境的关键场景:运行中的 WAF 在处理用户请求时,
// 管理 API 可能同时修改配置。
func TestConcurrentConfigUpdates(t *testing.T) {
	w := newTestWAF(nil)
	h := w.Handler(echoUpstream)

	var wg sync.WaitGroup

	// 并发写:通过 SetConfig 修改配置
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			w.SetConfig(Config{Mode: ModeBlock, MaxBody: 1024, BanStrikes: i})
		}
	}()

	// 并发读:发送 HTTP 请求(Handler 内部读 Config)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := do(h, "GET", "/?q=hello", "", nil, "")
			if rec.Code != 200 {
				t.Errorf("unexpected status %d", rec.Code)
			}
		}()
	}

	wg.Wait()
}

// TestUpdateConfigPersists 验证 PUT /api/config 能真正修改 WAF 配置。
// 这是生产环境关键:早先的实现 silently 丢弃所有配置更改。
func TestUpdateConfigPersists(t *testing.T) {
	s := newTestAPIServer()
	h := s.handleConfig()

	// PUT 新配置
	body := `{"mode":"detect","maxBody":524288,"rps":5,"burst":10,"banStrikes":3,"banFor":"5m","allow":["10.0.0.0/8"],"deny":["1.2.3.4"]}`
	rec := doReqDirect(h, "PUT", "/api/config", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/config = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}

	var resp map[string]bool
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || !resp["success"] {
		t.Fatalf("expected success=true, got: %s", rec.Body.String())
	}

	// GET 读取,验证配置已生效
	rec2 := doReqDirect(h, "GET", "/api/config", "")
	if rec2.Code != http.StatusOK {
		t.Fatalf("GET /api/config = %d", rec2.Code)
	}
	var cfg configResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("parse config: %v (%s)", err, rec2.Body.String())
	}
	if cfg.Mode != "detect" {
		t.Errorf("Mode = %q, want detect", cfg.Mode)
	}
	if cfg.MaxBody != 524288 {
		t.Errorf("MaxBody = %d, want 524288", cfg.MaxBody)
	}
	if cfg.RPS != 5 {
		t.Errorf("RPS = %v, want 5", cfg.RPS)
	}
	if cfg.BanStrikes != 3 {
		t.Errorf("BanStrikes = %d, want 3", cfg.BanStrikes)
	}
	if cfg.BanFor != "5m0s" {
		t.Errorf("BanFor = %q, want 5m0s", cfg.BanFor)
	}
	if len(cfg.Allow) != 1 || cfg.Allow[0] != "10.0.0.0/8" {
		t.Errorf("Allow = %v, want [10.0.0.0/8]", cfg.Allow)
	}
	if len(cfg.Deny) != 1 || cfg.Deny[0] != "1.2.3.4/32" {
		t.Errorf("Deny = %v, want [1.2.3.4/32]", cfg.Deny)
	}
}

// TestUpdateConfigInvalidMode 验证配置验证:无效的 mode 应返回 400。
func TestUpdateConfigInvalidMode(t *testing.T) {
	s := newTestAPIServer()
	h := s.handleConfig()

	rec := doReqDirect(h, "PUT", "/api/config", `{"mode":"invalid"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with invalid mode = %d, want 400", rec.Code)
	}
}

// TestUpdateConfigInvalidBanFor 验证无效的 BanFor duration 应返回 400。
func TestUpdateConfigInvalidBanFor(t *testing.T) {
	s := newTestAPIServer()
	h := s.handleConfig()

	rec := doReqDirect(h, "PUT", "/api/config", `{"banFor":"not-a-duration"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with invalid banFor = %d, want 400", rec.Code)
	}
}

// TestPrometheusMetrics 验证 Prometheus 格式的指标输出。
func TestPrometheusMetrics(t *testing.T) {
	w := newTestWAF(nil)
	rec := do(w.Handler(echoUpstream), "GET", "/__waf/metrics?format=prometheus", "", nil, "127.0.0.1:1234")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "gowaf_requests_total") {
		t.Errorf("missing gowaf_requests_total in prometheus output")
	}
	if !strings.Contains(body, "gowaf_blocked_total") {
		t.Errorf("missing gowaf_blocked_total in prometheus output")
	}
	if !strings.Contains(body, "gowaf_mode") {
		t.Errorf("missing gowaf_mode in prometheus output")
	}
}

// TestMetricsRequireLoopback 验证非本机 IP 不能访问指标。
func TestMetricsRequireLoopback(t *testing.T) {
	w := newTestWAF(nil)
	rec := do(w.Handler(echoUpstream), "GET", "/__waf/metrics", "", nil, "203.0.113.7:1234")
	if rec.Code != http.StatusNotFound {
		t.Errorf("non-loopback metrics = %d, want 404", rec.Code)
	}
}

// TestAPITokenAuthMiddleware 验证 authToken 中间件的行为。
func TestAPITokenAuthMiddleware(t *testing.T) {
	w := New(Config{Mode: ModeBlock}, DefaultRules(), quiet)
	api := NewAPIServerWithBastion(w, ":0", "secret-token-123", "http://127.0.0.1:9000", nil, quiet)

	inner := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("ok"))
	})
	protected := api.authToken("secret-token-123")(inner)

	tests := []struct {
		name       string
		authHeader string
		path       string
		wantStatus int
	}{
		{"no auth", "", "/api/config", http.StatusUnauthorized},
		{"wrong scheme", "Basic token", "/api/config", http.StatusUnauthorized},
		{"wrong token", "Bearer wrong", "/api/config", http.StatusForbidden},
		{"correct token", "Bearer secret-token-123", "/api/config", http.StatusOK},
		{"healthz bypasses auth", "", "/api/healthz", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rec := httptest.NewRecorder()
			protected.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body=%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

// TestHealthCheckWithUpstream 验证健康检查会探活上游。
func TestHealthCheckWithUpstream(t *testing.T) {
	// 启动一个上游服务器
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	w := newTestWAF(nil)
	api := NewAPIServerWithBastion(w, ":0", "", upstream.URL, nil, quiet)

	h := api.handleHealth()

	// 上游可达 -> 200
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("health with reachable upstream = %d, want 200", rec.Code)
	}

	// 关闭上游 -> 503
	upstream.Close()
	time.Sleep(100 * time.Millisecond)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest("GET", "/api/healthz", nil))
	if rec2.Code != http.StatusServiceUnavailable {
		t.Errorf("health with unreachable upstream = %d, want 503", rec.Code)
	}

	// 无上游配置 -> 200(跳过上游探活)
	apiNoUpstream := NewAPIServerWithBastion(w, ":0", "", "", nil, quiet)
	rec3 := httptest.NewRecorder()
	apiNoUpstream.handleHealth().ServeHTTP(rec3, httptest.NewRequest("GET", "/api/healthz", nil))
	if rec3.Code != http.StatusOK {
		t.Errorf("health without upstream = %d, want 200", rec3.Code)
	}
}

// doReqDirect is a helper that sends a request directly to a handler.
func doReqDirect(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
