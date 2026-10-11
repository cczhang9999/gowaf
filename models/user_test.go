package models

import "testing"

// users1 是堡垒机用户表。写成 users 会打到同库里业务方的另一张表
// （id/name/email），AutoMigrate 会往那张表上加列 —— 这里锁死表名。
func TestUserTableNameIsUsers1(t *testing.T) {
	if got := (User{}).TableName(); got != "users1" {
		t.Fatalf("User.TableName() = %q, want users1", got)
	}
	if UserTableName != "users1" {
		t.Fatalf("UserTableName = %q, want users1", UserTableName)
	}
}

func TestHashAndCheckPassword(t *testing.T) {
	const plain = "secret-pass-123"

	hash, err := HashPassword(plain)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == plain {
		t.Fatal("password must not be stored in plain text")
	}
	if err := CheckPassword(plain, hash); err != nil {
		t.Errorf("CheckPassword with correct password: %v", err)
	}
	if err := CheckPassword("wrong-pass", hash); err == nil {
		t.Error("CheckPassword should fail for a wrong password")
	}
}

func TestHashPasswordIfPlain(t *testing.T) {
	u := &User{Username: "alice", Password: "secret-pass-123"}
	if err := u.hashPasswordIfPlain(); err != nil {
		t.Fatalf("hashPasswordIfPlain: %v", err)
	}
	hashed := u.Password
	if hashed == "secret-pass-123" || hashed == "" {
		t.Fatalf("password should have been hashed, got %q", hashed)
	}

	// 已经是 hash 的再跑一遍必须原样返回，不能二次加密。
	if err := u.hashPasswordIfPlain(); err != nil {
		t.Fatalf("hashPasswordIfPlain (second pass): %v", err)
	}
	if u.Password != hashed {
		t.Errorf("hashing an existing hash must be a no-op")
	}

	// 公钥登录的用户没有密码，保持为空。
	keyOnly := &User{Username: "bob"}
	if err := keyOnly.hashPasswordIfPlain(); err != nil {
		t.Fatalf("hashPasswordIfPlain (empty): %v", err)
	}
	if keyOnly.Password != "" {
		t.Errorf("empty password must stay empty, got %q", keyOnly.Password)
	}
}
