package bastion

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func newTestAdminAPI(t *testing.T) (*AdminAPI, *SSHServer) {
	t.Helper()

	dir := t.TempDir()
	cfg := &BastionConfig{
		SSHListenAddr: "127.0.0.1:0",
		APIListenAddr: "127.0.0.1:0",
		HostKeyPath:   filepath.Join(dir, "ssh_host_key"),
		RecordingDir:  filepath.Join(dir, "recordings"),
		AuditLogPath:  filepath.Join(dir, "audit.log"),
		DefaultUser:   "root",
		DefaultPort:   22,
		MaxSessions:   10,
		BannerMsg:     "test",
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := NewSSHServer(cfg, log)
	if err != nil {
		t.Fatalf("NewSSHServer: %v", err)
	}
	return NewAdminAPI(srv, log), srv
}

func doRequest(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, reader))
	return rec
}

func listUsersBody(t *testing.T, rec *httptest.ResponseRecorder) usersResponse {
	t.Helper()
	var got usersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode users response %q: %v", rec.Body.String(), err)
	}
	return got
}

// TestAdminAPIUsersCRUD 走完整 HTTP 路径验证 /api/bastion/users 的增删改查
// （内存后端；MySQL 后端见 TestDatabaseAuthStoreCRUD）。
func TestAdminAPIUsersCRUD(t *testing.T) {
	api, srv := newTestAdminAPI(t)
	h := api.Handler()

	// 初始为空
	if rec := doRequest(t, h, http.MethodGet, "/users", ""); rec.Code != http.StatusOK {
		t.Fatalf("GET /users = %d, want 200 (%s)", rec.Code, rec.Body.String())
	} else if got := listUsersBody(t, rec); got.Count != 0 {
		t.Fatalf("expected 0 users, got %d", got.Count)
	}

	// 建
	createBody := `{"username":"alice","password":"secret-pass-123","role":"user","assets":["asset-1"],"comment":"from test"}`
	rec := doRequest(t, h, http.MethodPost, "/users", createBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /users = %d, want 201 (%s)", rec.Code, rec.Body.String())
	}

	// 重复建 -> 409
	if rec := doRequest(t, h, http.MethodPost, "/users", createBody); rec.Code != http.StatusConflict {
		t.Errorf("POST duplicate = %d, want 409", rec.Code)
	}

	// 弱密码 / 非法角色 -> 400
	if rec := doRequest(t, h, http.MethodPost, "/users", `{"username":"bob","password":"short"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("POST short password = %d, want 400", rec.Code)
	}
	if rec := doRequest(t, h, http.MethodPost, "/users", `{"username":"bob","password":"long-enough-pass","role":"root"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("POST invalid role = %d, want 400", rec.Code)
	}

	// 列表里能看到，且不泄露密码
	rec = doRequest(t, h, http.MethodGet, "/users", "")
	got := listUsersBody(t, rec)
	if got.Count != 1 || len(got.Users) != 1 || got.Users[0].Username != "alice" {
		t.Fatalf("unexpected user list: %s", rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, "secret-pass-123") || strings.Contains(body, "$2a$") {
		t.Errorf("password material leaked in list response: %s", body)
	}

	// 按用户名查
	rec = doRequest(t, h, http.MethodGet, "/users/alice", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /users/alice = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}

	// 不存在 -> 404
	if rec := doRequest(t, h, http.MethodGet, "/users/nobody", ""); rec.Code != http.StatusNotFound {
		t.Errorf("GET /users/nobody = %d, want 404", rec.Code)
	}

	// 改角色/备注（不带密码）：密码必须保留，否则编辑一次就登录不上了
	rec = doRequest(t, h, http.MethodPut, "/users/alice", `{"role":"auditor","comment":"promoted"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /users/alice = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if _, err := srv.authStore.Authenticate("alice", "secret-pass-123"); err != nil {
		t.Errorf("password must survive a role-only update: %v", err)
	}
	rec = doRequest(t, h, http.MethodGet, "/users/alice", "")
	var alice User
	if err := json.Unmarshal(rec.Body.Bytes(), &alice); err != nil {
		t.Fatalf("decode user: %v", err)
	}
	if alice.Role != RoleAuditor || alice.Comment != "promoted" {
		t.Errorf("update not applied: %+v", alice)
	}

	// 非法角色 -> 400，且不改动已存数据
	if rec := doRequest(t, h, http.MethodPut, "/users/alice", `{"role":"root"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("PUT invalid role = %d, want 400", rec.Code)
	}

	// 删
	if rec := doRequest(t, h, http.MethodDelete, "/users/alice", ""); rec.Code != http.StatusOK {
		t.Fatalf("DELETE /users/alice = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if rec := doRequest(t, h, http.MethodGet, "/users", ""); listUsersBody(t, rec).Count != 0 {
		t.Error("user should be gone after DELETE")
	}
	if rec := doRequest(t, h, http.MethodDelete, "/users/alice", ""); rec.Code != http.StatusNotFound {
		t.Errorf("DELETE missing user = %d, want 404", rec.Code)
	}
}

// TestAdminAPIUserAuthStillWorks 确认走 API 建出来的用户能用密码登录
// （旧实现落库时忘了哈希，建出来的用户永远登录不上）。
func TestAdminAPIUserAuthStillWorks(t *testing.T) {
	api, srv := newTestAdminAPI(t)
	h := api.Handler()

	rec := doRequest(t, h, http.MethodPost, "/users",
		`{"username":"carol","password":"secret-pass-123","role":"user"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /users = %d (%s)", rec.Code, rec.Body.String())
	}
	if _, err := srv.authStore.Authenticate("carol", "secret-pass-123"); err != nil {
		t.Fatalf("user created through the API cannot log in: %v", err)
	}
}

func TestAdminAPIHealthReportsUserStore(t *testing.T) {
	api, _ := newTestAdminAPI(t)
	rec := doRequest(t, api.Handler(), http.MethodGet, "/healthz", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if body["user_store"] != "memory" {
		t.Errorf("user_store = %v, want memory (no DSN configured)", body["user_store"])
	}
}
