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

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
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

// newTestAdminAPIWithDB creates a bastion server backed by an in-memory SQLite
// database, so both dbAuthStore (users1) and dbAuthStore1 (user1) are active.
// This lets us verify that the /api/bastion/users CRUD endpoint consistently
// reads from and writes to the user1 table.
//
// SQLite (unlike MySQL) requires index names to be unique across the entire
// database, so we pre-create both tables with distinct index names before
// handing the DB to NewSSHServerWithDB — which will then call EnsureUserTable
// / EnsureUser1Table, find the tables already present, and skip CreateTable.
func newTestAdminAPIWithDB(t *testing.T) (*AdminAPI, *SSHServer) {
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

	db, err := gorm.Open(sqlite.Open("file:test?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	// Pre-create both tables with SQLite-compatible DDL and unique index names.
	// The column layout mirrors models.User / models.User1 exactly so that
	// GORM's query operations (Where/First/Create/Updates/Delete) work
	// transparently through the repository layer.  SQLite requires index
	// names to be unique per-database (unlike MySQL), so each table gets its
	// own idx_role_<table> index.
	createTable := func(table string) error {
		if err := db.Exec(`CREATE TABLE IF NOT EXISTS ` + table + ` (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			username      VARCHAR(64) NOT NULL UNIQUE,
			password      VARCHAR(255) NOT NULL,
			role          VARCHAR(20) DEFAULT 'user' NOT NULL,
			public_key    TEXT,
			assets        TEXT,
			comment       VARCHAR(255),
			created_at    DATETIME,
			updated_at    DATETIME
		)`).Error; err != nil {
			return err
		}
		return db.Exec(`CREATE INDEX IF NOT EXISTS idx_role_` + table + ` ON ` + table + ` (role)`).Error
	}
	if err := createTable("users1"); err != nil {
		t.Fatalf("create users1 table: %v", err)
	}
	if err := createTable("user1"); err != nil {
		t.Fatalf("create user1 table: %v", err)
	}

	srv, err := NewSSHServerWithDB(cfg, log, db)
	if err != nil {
		t.Fatalf("NewSSHServerWithDB: %v", err)
	}
	return NewAdminAPI(srv, log), srv
}

// TestAdminAPIUsers1TableConsistency verifies that the /api/bastion/users
// endpoint writes to and reads from the user1 table consistently.
//
// Before the fix, createUser saved to user1 (via Register1) but listUsers
// read from users1 (via ListUsers), so newly created users were invisible.
// This test uses a real SQLite DB (both stores active) to catch that
// inconsistency.
func TestAdminAPIUsers1TableConsistency(t *testing.T) {
	api, srv := newTestAdminAPIWithDB(t)
	h := api.Handler()

	// --- POST /users: createUser -> Register1 -> user1 table ---
	createBody := `{"username":"alice","password":"secret-pass-123","role":"user","assets":["asset-1"],"comment":"integration test"}`
	rec := doRequest(t, h, http.MethodPost, "/users", createBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /users = %d, want 201 (%s)", rec.Code, rec.Body.String())
	}

	// user1 表里有这一行
	if !srv.dbAuthStore1.HasUser1("alice") {
		t.Error("expected alice in user1 table after POST /users")
	}
	// users1 表里没有同名行 (createUser 不应该写 users1)
	if srv.dbAuthStore.HasUser("alice") {
		t.Error("alice should not be in users1 table; POST /users must not write users1")
	}

	// --- GET /users: listUsers -> ListUsers1 -> user1 table ---
	// 修复前这里读的是 users1，列表为空，alice 看不见
	rec = doRequest(t, h, http.MethodGet, "/users", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /users = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	got := listUsersBody(t, rec)
	if got.Count != 1 || len(got.Users) != 1 || got.Users[0].Username != "alice" {
		t.Fatalf("expected to see alice in user1 list, got: %s", rec.Body.String())
	}

	// --- GET /users/alice: resolveUser -> GetUser1 -> user1 table ---
	rec = doRequest(t, h, http.MethodGet, "/users/alice", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /users/alice = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var fetched User
	if err := json.Unmarshal(rec.Body.Bytes(), &fetched); err != nil {
		t.Fatalf("decode user: %v", err)
	}
	if fetched.Username != "alice" || fetched.Role != RoleUser {
		t.Errorf("unexpected user: %+v", fetched)
	}

	// --- PUT /users/alice: resolveUser + UpdateUser1 -> user1 table ---
	rec = doRequest(t, h, http.MethodPut, "/users/alice", `{"role":"auditor","comment":"promoted"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /users/alice = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	// 密码必须保留
	if _, err := srv.dbAuthStore1.Authenticate1("alice", "secret-pass-123"); err != nil {
		t.Errorf("password must survive a role-only update: %v", err)
	}
	updated, ok := srv.dbAuthStore1.GetUser1("alice")
	if !ok || updated.Role != RoleAuditor || updated.Comment != "promoted" {
		t.Errorf("update not applied: %+v (ok=%v)", updated, ok)
	}

	// --- DELETE /users/alice: resolveUser + Unregister1 -> user1 table ---
	rec = doRequest(t, h, http.MethodDelete, "/users/alice", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /users/alice = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if srv.dbAuthStore1.HasUser1("alice") {
		t.Error("alice should be gone from user1 after DELETE")
	}

	// 列表应为空
	rec = doRequest(t, h, http.MethodGet, "/users", "")
	got = listUsersBody(t, rec)
	if got.Count != 0 {
		t.Errorf("expected 0 users after delete, got %d", got.Count)
	}
}
