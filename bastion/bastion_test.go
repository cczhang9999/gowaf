package bastion

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- AuthStore tests ---

func TestAuthStore(t *testing.T) {
	s := NewAuthStore()

	// Register a user with password
	u := &User{
		Username:      "testuser",
		PasswordPlain: "password123",
		Role:          RoleUser,
		Assets:        []string{"asset-001"},
	}
	if err := s.Register(u); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Verify user was created (GetUser strips secrets, so check the internal map)
	s.mu.RLock()
	internal := s.users["testuser"]
	s.mu.RUnlock()
	if internal == nil {
		t.Fatal("user not found in store after register")
	}
	if internal.Role != RoleUser {
		t.Errorf("role = %s, want %s", internal.Role, RoleUser)
	}
	if internal.PasswordHash == nil {
		t.Error("password hash should be set after register")
	}
	if internal.PasswordPlain != "" {
		t.Error("password plain should be cleared after register")
	}

	// Test authentication
	auth, err := s.Authenticate("testuser", "password123")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if auth.Username != "testuser" {
		t.Error("authenticated user name mismatch")
	}

	// Test wrong password
	if _, err := s.Authenticate("testuser", "wrong"); err == nil {
		t.Error("should fail with wrong password")
	}

	// Test unknown user
	if _, err := s.Authenticate("nobody", "pass"); err == nil {
		t.Error("should fail for unknown user")
	}

	// Test RBAC
	if !s.CanAccessAsset(internal, "asset-001") {
		t.Error("user should access asset-001")
	}
	if s.CanAccessAsset(internal, "asset-999") {
		t.Error("user should NOT access asset-999")
	}

	// Test admin has access to all
	admin := &User{Username: "admin", Role: RoleAdmin, PasswordHash: []byte{}}
	if !s.CanAccessAsset(admin, "anything") {
		t.Error("admin should access all assets")
	}

	// Test delete user
	s.Unregister("testuser")
	if s.HasUser("testuser") {
		t.Error("user should be deleted")
	}
}

func TestAuthStoreListUsers(t *testing.T) {
	s := NewAuthStore()

	// Add multiple users
	for _, name := range []string{"alice", "bob", "charlie"} {
		u := &User{
			Username:      name,
			PasswordPlain: "pass",
			Role:          RoleUser,
		}
		if err := s.Register(u); err != nil {
			t.Fatalf("Register %s: %v", name, err)
		}
	}

	users := s.ListUsers()
	if len(users) != 3 {
		t.Fatalf("expected 3 users, got %d", len(users))
	}

	for _, u := range users {
		if u.PasswordHash != nil {
			t.Errorf("ListUsers should strip password hash for %s", u.Username)
		}
	}
}

// --- AssetStore tests ---

func TestAssetStore(t *testing.T) {
	s := NewAssetStore()

	// Add assets
	assets := []Asset{
		{ID: "a-001", Name: "web-01", Hostname: "192.168.1.1", Port: 22},
		{ID: "a-002", Name: "db-01", Hostname: "192.168.1.2", Port: 22},
	}
	s.Set(assets)

	// Test Get
	a, ok := s.Get("a-001")
	if !ok || a.Name != "web-01" {
		t.Fatalf("Get(a-001) = %+v, ok=%v", a, ok)
	}

	// Test add
	if err := s.Add(Asset{ID: "a-003", Name: "web-02", Hostname: "192.168.1.3", Port: 22}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if len(s.All()) != 3 {
		t.Fatalf("expected 3 assets, got %d", len(s.All()))
	}

	// Test duplicate add
	if err := s.Add(Asset{ID: "a-001", Name: "dup", Hostname: "x"}); err == nil {
		t.Error("should fail on duplicate ID")
	}

	// Test update
	a.Hostname = "10.0.0.1"
	if err := s.Update(a); err != nil {
		t.Fatalf("Update: %v", err)
	}
	updated, _ := s.Get("a-001")
	if updated.Hostname != "10.0.0.1" {
		t.Error("update did not apply")
	}

	// Test delete
	if err := s.Delete("a-002"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(s.All()) != 2 {
		t.Fatalf("expected 2 assets after delete, got %d", len(s.All()))
	}

	// Test delete non-existent
	if err := s.Delete("nonexistent"); err == nil {
		t.Error("should fail on non-existent ID")
	}

	// Test atomic update (concurrent safety)
	s.Set([]Asset{})
	for i := 0; i < 10; i++ {
		_ = s.Add(Asset{ID: fmt.Sprintf("a-%d", i), Name: "host"})
	}
}

// --- AuditStore tests ---

func TestAuditStore(t *testing.T) {
	s := NewAuditStore(100)

	// Add events
	for i := 0; i < 5; i++ {
		s.Append(AuditEvent{
			Username:  "testuser",
			SessionID: "sess-001",
			Action:    ActionCommand,
			Command:   "ls -la",
		})
	}

	events := s.List()
	if len(events) != 5 {
		t.Fatalf("expected 5 events, got %d", len(events))
	}

	// Test filtering by user
	byUser := s.ListByUser("testuser")
	if len(byUser) != 5 {
		t.Fatalf("expected 5 events for testuser, got %d", len(byUser))
	}

	// Test filtering by session
	bySession := s.ListBySession("sess-001")
	if len(bySession) != 5 {
		t.Fatalf("expected 5 events for sess-001, got %d", len(bySession))
	}

	// Test count by action
	counts := s.CountByAction()
	if counts["command"] != 5 {
		t.Errorf("expected 5 command events, got %d", counts["command"])
	}
}

func TestBannedCommands(t *testing.T) {
	s := NewAuditStore(100)

	// Add banned command
	s.AddBannedCommand(BannedCommand{
		ID:      "ban-001",
		Pattern: "rm -rf /",
		Reason:  "destructive command",
		Enabled: true,
	})

	// Test command checking
	cmd, blocked := s.CheckCommand("rm -rf /home")
	if !blocked {
		t.Error("should block 'rm -rf /home'")
	}
	if cmd.ID != "ban-001" {
		t.Errorf("expected ban-001, got %s", cmd.ID)
	}

	// Test non-matching command
	_, blocked = s.CheckCommand("ls -la")
	if blocked {
		t.Error("should not block 'ls -la'")
	}

	// Test disabled rule
	s.AddBannedCommand(BannedCommand{
		ID:      "ban-002",
		Pattern: "mkfs.ext4",
		Reason:  "format",
		Enabled: false,
	})
	_, blocked = s.CheckCommand("mkfs.ext4 /dev/sda1")
	if blocked {
		t.Error("disabled rule should not block")
	}

	// Test case insensitivity
	_, blocked = s.CheckCommand("RM -RF /")
	if !blocked {
		t.Error("should block case-insensitive match")
	}
}

func TestBannedCommandsList(t *testing.T) {
	s := NewAuditStore(100)
	s.AddBannedCommand(BannedCommand{ID: "ban-001", Pattern: "rm", Reason: "test", Enabled: true})
	s.AddBannedCommand(BannedCommand{ID: "ban-002", Pattern: "mkfs", Reason: "test", Enabled: true})

	rules := s.ListBannedCommands()
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
}

func TestParseCommand(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"ls -la\n", "ls -la"},
		{"  cat /etc/passwd\n", "cat /etc/passwd"},
		{"echo hello && rm -rf /\n", "rm -rf /"},
		{"", ""},
		{"echo 'hello world'\n", "echo 'hello world'"},
	}
	for _, c := range cases {
		got := ParseCommand(c.input)
		if got != c.want {
			t.Errorf("ParseCommand(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

// --- Recording tests ---

func TestSessionRecord(t *testing.T) {
	dir := t.TempDir()
	recorder := NewSessionRecorder(dir)

	rec, err := recorder.StartSession("sess-test", "testuser", "asset-001", "web-01")
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	// Record some events
	rec.RecordOutput([]byte("Welcome to the server\n"), 0)
	rec.RecordInput([]byte("ls -la\n"), 1500*time.Millisecond)
	rec.RecordOutput([]byte("total 8\ndrwxr-xr-x\n"), 2*time.Second)

	// Verify the file exists
	if _, err := os.Stat(rec.Path()); os.IsNotExist(err) {
		t.Fatalf("recording file not created: %s", rec.Path())
	}

	// Verify file is in date subdirectory
	dateDir := filepath.Dir(rec.Path())
	if dateDir == dir {
		t.Error("recording should be in date subdirectory")
	}

	// Stop recording
	rec.Stop()
	if rec.EndTime.IsZero() {
		t.Error("EndTime should be set after Stop")
	}
}

func TestSessionRecordConcurrent(t *testing.T) {
	dir := t.TempDir()
	recorder := NewSessionRecorder(dir)

	rec, err := recorder.StartSession("sess-concurrent", "user", "asset-1", "host-1")
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	// Concurrent writes
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			rec.RecordOutput([]byte("output line\n"), 0)
		}
		done <- struct{}{}
	}()
	go func() {
		for i := 0; i < 100; i++ {
			rec.RecordInput([]byte("input\n"), 0)
		}
		done <- struct{}{}
	}()

	<-done
	<-done
	rec.Stop()
}

// --- RecordingIndex tests ---

func TestRecordingIndex(t *testing.T) {
	idx := NewRecordingIndex()

	r1 := &SessionRecord{ID: "sess-001", Username: "alice", AssetID: "asset-a"}
	r2 := &SessionRecord{ID: "sess-002", Username: "bob", AssetID: "asset-b"}
	r3 := &SessionRecord{ID: "sess-003", Username: "alice", AssetID: "asset-c"}

	idx.Register(r1)
	idx.Register(r2)
	idx.Register(r3)

	// Test Get
	r, ok := idx.Get("sess-002")
	if !ok || r.AssetID != "asset-b" {
		t.Errorf("Get(sess-002) = %+v, ok=%v", r, ok)
	}

	// Test ListByUser
	aliceSessions := idx.ListByUser("alice")
	if len(aliceSessions) != 2 {
		t.Errorf("ListByUser(alice) = %d, want 2", len(aliceSessions))
	}

	// Test ListByAsset
	assetARecords := idx.ListByAsset("asset-a")
	if len(assetARecords) != 1 {
		t.Errorf("ListByAsset(asset-a) = %d, want 1", len(assetARecords))
	}

	// Test List
	all := idx.List()
	if len(all) != 3 {
		t.Errorf("List() = %d, want 3", len(all))
	}
}

// --- Terminal size helpers ---

func TestDecodeTerminalSize(t *testing.T) {
	// 80 columns, 24 rows in network byte order
	data := []byte{0x00, 0x50, 0x00, 0x18}
	w, h := decodeTerminalSize(data)
	if w != 80 || h != 24 {
		t.Errorf("decodeTerminalSize = (%d, %d), want (80, 24)", w, h)
	}

	// Empty data
	w, h = decodeTerminalSize([]byte{})
	if w != 80 || h != 24 {
		t.Errorf("decodeTerminalSize(empty) = (%d, %d), want (80, 24)", w, h)
	}
}

// --- Asset helpers ---

func TestAssetPort(t *testing.T) {
	if assetPort(Asset{Port: 2222}) != 2222 {
		t.Error("should return custom port")
	}
	if assetPort(Asset{Port: 0}) != 22 {
		t.Error("should return default port 22")
	}
}

func TestAssetID(t *testing.T) {
	id1 := assetID("192.168.1.1", 22)
	id2 := assetID("192.168.1.1", 22)
	id3 := assetID("192.168.1.2", 22)

	if id1 != id2 {
		t.Error("same host:port should produce same ID")
	}
	if id1 == id3 {
		t.Error("different host:port should produce different ID")
	}
}

// --- Session ID generation ---

func TestSessionID(t *testing.T) {
	id1 := generateSessionID()
	id2 := generateSessionID()
	if id1 == id2 {
		t.Error("session IDs should be unique")
	}
	if !strings.HasPrefix(id1, "sess-") {
		t.Error("session ID should start with 'sess-'")
	}
}

// --- MarshalJSON for Asset ---

func TestAssetMarshalJSON(t *testing.T) {
	a := Asset{
		ID:         "test-001",
		Name:       "test-host",
		Hostname:   "192.168.1.1",
		Port:       22,
		Password:   "secret",  // should be hidden
		PrivateKey: "private", // should be hidden
	}

	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	s := string(data)
	if strings.Contains(s, "secret") {
		t.Error("password should not appear in JSON output")
	}
	if strings.Contains(s, "private") {
		t.Error("private key should not appear in JSON output")
	}
	if !strings.Contains(s, "test-host") {
		t.Error("name should appear in JSON output")
	}
}
