package bastion

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"gowaf/models"
)

func TestStringSliceJSONRoundTrip(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, "[]"},
		{[]string{}, "[]"},
		{[]string{"a"}, `["a"]`},
		{[]string{"a", "b"}, `["a","b"]`},
	}
	for _, c := range cases {
		got := StringSliceToJSON(c.in)
		if got != c.want {
			t.Errorf("StringSliceToJSON(%v) = %q, want %q", c.in, got, c.want)
		}
	}

	// 数据库里可能存着 NULL / 空串 / 非法 JSON，都不能 panic 或报错到上层。
	for _, raw := range []string{"", "null", "[]", `["x","y"]`, "not-json"} {
		_ = JSONToStringSlice(raw)
	}
	if got := JSONToStringSlice(`["x","y"]`); len(got) != 2 || got[0] != "x" || got[1] != "y" {
		t.Errorf(`JSONToStringSlice(["x","y"]) = %v`, got)
	}
	if got := JSONToStringSlice(""); got != nil {
		t.Errorf("JSONToStringSlice(\"\") = %v, want nil", got)
	}
}

func TestCanAccessAssetRules(t *testing.T) {
	admin := &User{Username: "root", Role: RoleAdmin}
	auditor := &User{Username: "audit", Role: RoleAuditor}
	limited := &User{Username: "dev", Role: RoleUser, Assets: []string{"asset-1"}}
	unlimited := &User{Username: "ops", Role: RoleUser}

	if !canAccessAsset(admin, "anything") {
		t.Error("admin should reach every asset")
	}
	if !canAccessAsset(auditor, "anything") {
		t.Error("auditor should reach every asset")
	}
	if !canAccessAsset(limited, "asset-1") {
		t.Error("user should reach an assigned asset")
	}
	if canAccessAsset(limited, "asset-2") {
		t.Error("user should not reach an unassigned asset")
	}
	if !canAccessAsset(unlimited, "asset-9") {
		t.Error("user with no explicit assets should reach all assets")
	}
}

// TestDatabaseAuthStoreCRUD 是针对真实 MySQL 的集成测试，默认跳过：
//
//	BASTION_TEST_DSN='user:pass@tcp(127.0.0.1:3306)/myapp?charset=utf8mb4&parseTime=True&loc=Local' \
//	  go test ./bastion -run TestDatabaseAuthStoreCRUD -v
//
// 测试数据用带时间戳的用户名，结束时会删除。
func TestDatabaseAuthStoreCRUD(t *testing.T) {
	dsn := os.Getenv("BASTION_TEST_DSN")
	if dsn == "" {
		t.Skip("set BASTION_TEST_DSN to run the MySQL-backed users1 integration test")
	}

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("connect to MySQL: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sql.DB: %v", err)
	}
	defer sqlDB.Close()

	users, err := NewDatabaseAuthStore(db)
	if err != nil {
		t.Fatalf("NewDatabaseAuthStore: %v", err)
	}

	username := fmt.Sprintf("itest-%d", time.Now().UnixNano())
	defer func() {
		if err := users.Unregister(username); err != nil {
			t.Logf("cleanup %s: %v", username, err)
		}
	}()

	// --- 建 ---
	err = users.Register(&User{
		Username:      username,
		PasswordPlain: "secret-pass-123",
		Role:          RoleUser,
		Assets:        []string{"asset-1"},
		Comment:       "integration test",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	var row models.User
	if err := db.Where("username = ?", username).First(&row).Error; err != nil {
		t.Fatalf("row not found in %s: %v", models.UserTableName, err)
	}
	if row.ID == 0 {
		t.Error("id should be assigned by the database")
	}
	if row.Password == "" || row.Password == "secret-pass-123" {
		t.Fatalf("password column must hold a bcrypt hash, got %q", row.Password)
	}
	if row.Role != string(RoleUser) {
		t.Errorf("role = %q, want %q", row.Role, RoleUser)
	}

	// --- 查(按主键) ---
	byID, ok := users.GetUserByID(row.ID)
	if !ok || byID.Username != username {
		t.Fatalf("GetUserByID(%d) = %+v, ok=%v", row.ID, byID, ok)
	}
	if len(byID.Assets) != 1 || byID.Assets[0] != "asset-1" {
		t.Errorf("assets = %v, want [asset-1]", byID.Assets)
	}

	// --- 列表必须包含刚写入的行(旧实现读内存缓存会漏掉) ---
	found := false
	for _, u := range users.ListUsers() {
		if u.Username == username {
			found = true
		}
	}
	if !found {
		t.Fatalf("ListUsers() did not include %q", username)
	}

	// --- 认证 ---
	if _, err := users.Authenticate(username, "secret-pass-123"); err != nil {
		t.Fatalf("Authenticate with correct password: %v", err)
	}
	if _, err := users.Authenticate(username, "wrong-pass"); err == nil {
		t.Error("Authenticate should fail for a wrong password")
	}

	// --- 只改角色/备注，密码不能被清掉 ---
	byID.Role = RoleAuditor
	byID.Comment = "updated"
	if err := users.UpdateUser(byID); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if _, err := users.Authenticate(username, "secret-pass-123"); err != nil {
		t.Fatalf("password must survive a role-only update: %v", err)
	}
	updated, ok := users.GetUser(username)
	if !ok || updated.Role != RoleAuditor || updated.Comment != "updated" {
		t.Fatalf("update not applied: %+v (ok=%v)", updated, ok)
	}

	// --- 改密码 ---
	hash, err := bcrypt.GenerateFromPassword([]byte("new-secret-456"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash new password: %v", err)
	}
	updated.PasswordHash = hash
	if err := users.UpdateUser(updated); err != nil {
		t.Fatalf("UpdateUser (password): %v", err)
	}
	if _, err := users.Authenticate(username, "new-secret-456"); err != nil {
		t.Fatalf("Authenticate with new password: %v", err)
	}
	if _, err := users.Authenticate(username, "secret-pass-123"); err == nil {
		t.Error("old password should no longer work")
	}

	// --- 删 ---
	if err := users.Unregister(username); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if users.HasUser(username) {
		t.Error("user should be gone from the database")
	}
	var count int64
	if err := db.Model(&models.User{}).Where("username = ?", username).Count(&count).Error; err != nil {
		t.Fatalf("count after delete: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 rows for %q after delete, got %d", username, count)
	}
}

// TestUserJSONShape 锁定接口返回的字段名，前端 web/src/stores/bastion.ts 依赖这些名字。
func TestUserJSONShape(t *testing.T) {
	u := User{
		ID:        7,
		Username:  "alice",
		PublicKey: "ssh-ed25519 AAAA",
		Role:      RoleUser,
		Assets:    []string{"asset-1"},
		Comment:   "hi",
		CreatedAt: time.Unix(0, 0).UTC(),
	}
	raw, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{"id", "username", "public_key", "role", "assets", "comment", "created_at"} {
		if _, ok := got[key]; !ok {
			t.Errorf("JSON output is missing %q: %s", key, raw)
		}
	}
	if _, leaked := got["password"]; leaked {
		t.Errorf("password must never be serialized: %s", raw)
	}
}
