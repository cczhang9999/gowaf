package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestAPIServer() *APIServer {
	log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	w := New(Config{Mode: ModeBlock}, DefaultRules(), log)
	return NewAPIServer(w, ":0", log)
}

func doReq(s *APIServer, method, path, body string, t *testing.T) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.handleAllowList().ServeHTTP(rr, req)
	return rr
}

func TestAddAllowListValid(t *testing.T) {
	s := newTestAPIServer()
	rr := doReq(s, "POST", "/api/allow", `{"ips":["192.168.1.5","10.0.0.0/8","2001:db8::1"]}`, t)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("not json: %v body=%s", err, rr.Body.String())
	}
	if resp["success"] != true {
		t.Fatalf("success != true: %v", resp)
	}
	// 列表应已更新
	rr2 := doReq(s, "GET", "/api/allow", "", t)
	if rr2.Code != http.StatusOK {
		t.Fatalf("get status=%d", rr2.Code)
	}
	var list ipListResponse
	_ = json.Unmarshal(rr2.Body.Bytes(), &list)
	found := false
	for _, p := range list.IPs {
		if p == "10.0.0.0/8" {
			found = true
		}
	}
	if !found {
		t.Fatalf("10.0.0.0/8 not in list: %v", list.IPs)
	}
}

func TestAddAllowListInvalidReturnsJSON(t *testing.T) {
	s := newTestAPIServer()
	rr := doReq(s, "POST", "/api/allow", `{"ips":["not-an-ip","10.0.0.0/8"]}`, t)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("expected json content-type, got %s", rr.Header().Get("Content-Type"))
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("expected json error body, got: %s", rr.Body.String())
	}
	if resp["success"] != false {
		t.Fatalf("success should be false: %v", resp)
	}
	if resp["error"] == nil {
		t.Fatalf("error field missing: %v", resp)
	}
	// 无效条目不应部分写入
	if len(s.waf.getConfig().Allow) != 0 {
		t.Fatalf("partial write on invalid input: %v", s.waf.getConfig().Allow)
	}
}

func TestAddAllowListEmpty(t *testing.T) {
	s := newTestAPIServer()
	rr := doReq(s, "POST", "/api/allow", `{"ips":[]}`, t)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rr.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] == nil {
		t.Fatalf("error field missing: %v", resp)
	}
}
