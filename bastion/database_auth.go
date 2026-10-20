package bastion

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"gowaf/internal/store"
	"gowaf/models"
)

// StringSliceToJSON 将字符串切片转换为 JSON 字符串
func StringSliceToJSON(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(ss)
	return string(b)
}

// JSONToStringSlice 将 JSON 字符串转换为字符串切片
func JSONToStringSlice(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	if err := json.Unmarshal([]byte(s), &result); err != nil {
		return nil
	}
	return result
}

// DatabaseAuthStore 把堡垒机用户持久化到 MySQL 的 users1 表。
//
// 与早先的实现相比有一处关键区别：读取（ListUsers/GetUser/HasUser）全部直接
// 查表，不再依赖那个启动时永远为空的内存缓存 —— 否则 GET /api/bastion/users
// 看不到表里已有的行，接口表面上「操作数据库」实际读的是内存。
type DatabaseAuthStore struct {
	repo store.UserRepository
}

// NewDatabaseAuthStore 创建基于数据库的认证存储，并确保 users1 表存在
// （表已存在时不会改动它）。
func NewDatabaseAuthStore(db *gorm.DB) (*DatabaseAuthStore, error) {
	if err := store.EnsureUserTable(db); err != nil {
		return nil, err
	}
	return &DatabaseAuthStore{repo: store.NewUserRepository(db)}, nil
}

// --- models.User <-> bastion.User 映射 ---

func userToModel(u *User) *models.User {
	return &models.User{
		ID:        u.ID,
		Username:  u.Username,
		Password:  string(u.PasswordHash),
		Role:      string(u.Role),
		PublicKey: u.PublicKey,
		Assets:    StringSliceToJSON(u.Assets),
		Comment:   u.Comment,
		CreatedAt: u.CreatedAt,
	}
}

// userFromModel 把数据库行转成 API/SSH 层使用的 User（不含密码哈希）。
func userFromModel(m *models.User) *User {
	return &User{
		ID:        m.ID,
		Username:  m.Username,
		Role:      UserRole(m.Role),
		PublicKey: m.PublicKey,
		Assets:    JSONToStringSlice(m.Assets),
		Comment:   m.Comment,
		CreatedAt: m.CreatedAt,
	}
}

// Register 添加或更新用户，写入前完成 bcrypt 哈希。
// 旧实现直接落库 u.PasswordHash（此时还是空的），导致通过 API 建的用户
// 密码栏是空的、永远登录不上。
func (s *DatabaseAuthStore) Register(u *User) error {
	if u == nil || u.Username == "" {
		return errors.New("register user: username required")
	}
	if u.PasswordPlain != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(u.PasswordPlain), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
		u.PasswordHash = hash
		u.PasswordPlain = ""
	}

	m := userToModel(u)
	if err := s.repo.UpsertUser(context.Background(), m); err != nil {
		return fmt.Errorf("save user to %s: %w", models.UserTableName, err)
	}
	u.ID = m.ID
	u.CreatedAt = m.CreatedAt
	return nil
}

// UpdateUser 更新 users1 中的用户记录。
// PasswordHash 为空表示只改角色/公钥/资产/备注，不动密码。
func (s *DatabaseAuthStore) UpdateUser(u *User) error {
	if u == nil || u.Username == "" {
		return errors.New("update user: username required")
	}

	ctx := context.Background()
	m := userToModel(u)
	if m.ID == 0 {
		existing, err := s.repo.GetUserByUsername(ctx, u.Username)
		if err != nil {
			return fmt.Errorf("update user %q: %w", u.Username, err)
		}
		m.ID = existing.ID
	}
	if err := s.repo.UpdateUser(ctx, m); err != nil {
		return fmt.Errorf("update user %q in %s: %w", u.Username, models.UserTableName, err)
	}
	u.ID = m.ID
	return nil
}

// Unregister 从 users1 中删除用户。
func (s *DatabaseAuthStore) Unregister(username string) error {
	if err := s.repo.DeleteUser(context.Background(), username); err != nil {
		return fmt.Errorf("delete user %q from %s: %w", username, models.UserTableName, err)
	}
	return nil
}

// Authenticate 通过用户名和密码验证。
func (s *DatabaseAuthStore) Authenticate(username, password string) (*User, error) {
	m, err := s.repo.GetUserByUsername(context.Background(), username)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			return nil, fmt.Errorf("user %q not found", username)
		}
		return nil, fmt.Errorf("query user from %s: %w", models.UserTableName, err)
	}
	if m.Password == "" {
		return nil, fmt.Errorf("user %q has no password set", username)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(m.Password), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid password for user %q", username)
	}
	return userFromModel(m), nil
}

// AuthenticatePublicKey 通过 SSH 公钥验证。
func (s *DatabaseAuthStore) AuthenticatePublicKey(username string, pubKey ssh.PublicKey) (*User, error) {
	m, err := s.repo.GetUserByUsername(context.Background(), username)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			return nil, fmt.Errorf("user %q not found", username)
		}
		return nil, fmt.Errorf("query user from %s: %w", models.UserTableName, err)
	}
	if m.PublicKey == "" {
		return nil, fmt.Errorf("user %q has no public key configured", username)
	}

	configuredKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(m.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("invalid configured public key: %w", err)
	}
	// 使用常量时间比较
	if subtle.ConstantTimeCompare(pubKey.Marshal(), configuredKey.Marshal()) != 1 {
		return nil, fmt.Errorf("public key mismatch for user %q", username)
	}
	return userFromModel(m), nil
}

// GetUser 按用户名获取用户（不含敏感信息）。
func (s *DatabaseAuthStore) GetUser(username string) (*User, bool) {
	m, err := s.repo.GetUserByUsername(context.Background(), username)
	if err != nil {
		return nil, false
	}
	return userFromModel(m), true
}

// GetUserByID 按主键获取用户（不含敏感信息）。
func (s *DatabaseAuthStore) GetUserByID(id uint) (*User, bool) {
	m, err := s.repo.GetUserByID(context.Background(), id)
	if err != nil {
		return nil, false
	}
	return userFromModel(m), true
}

// ListUsers 返回 users1 中的全部用户（不含敏感信息）。
func (s *DatabaseAuthStore) ListUsers() []*User {
	users, err := s.ListUsersWithErr()
	if err != nil {
		return []*User{}
	}
	return users
}

// ListUsersWithErr 与 ListUsers 相同,但把数据库错误透传给调用方。
// 管理 API 用它区分「表里确实没有用户」和「数据库连不上/查询失败」——
// 后者不该被静默伪装成空列表。
func (s *DatabaseAuthStore) ListUsersWithErr() ([]*User, error) {
	ms, err := s.repo.ListUsers(context.Background())
	if err != nil {
		return nil, err
	}
	users := make([]*User, 0, len(ms))
	for _, m := range ms {
		users = append(users, userFromModel(m))
	}
	return users, nil
}

// HasUser 检查用户是否存在。
//
// 注意:它把「查询失败」也当成「不存在」。写路径(创建用户、初始化管理员)
// 必须改用 HasUserErr,否则数据库抖动时会误判用户不存在,进而走
// AddUser → UpsertUser 的更新分支,静默覆盖已有用户的密码/角色/资产。
func (s *DatabaseAuthStore) HasUser(username string) bool {
	ok, _ := s.HasUserErr(username)
	return ok
}

// HasUserErr 区分「用户不存在」(false, nil)和「数据库查询失败」(_, err)。
func (s *DatabaseAuthStore) HasUserErr(username string) (bool, error) {
	_, err := s.repo.GetUserByUsername(context.Background(), username)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, store.ErrUserNotFound):
		return false, nil
	default:
		return false, err
	}
}

// CanAccessAsset 检查用户是否可以访问指定资产。
func (s *DatabaseAuthStore) CanAccessAsset(u *User, assetID string) bool {
	return canAccessAsset(u, assetID)
}

// DatabaseAuthStore1 把堡垒机用户持久化到 MySQL 的 user1 表。
// 这是 DatabaseAuthStore 的变体，使用 user1 表而非 users1 表。
type DatabaseAuthStore1 struct {
	repo store.User1Repository
}

// NewDatabaseAuthStore1 创建基于数据库的认证存储，使用 user1 表。
func NewDatabaseAuthStore1(db *gorm.DB) (*DatabaseAuthStore1, error) {
	if err := store.EnsureUser1Table(db); err != nil {
		return nil, err
	}
	return &DatabaseAuthStore1{repo: store.NewUser1Repository(db)}, nil
}

// user1ToModel 把 bastion.User 转换为 models.User1。
func user1ToModel(u *User) *models.User1 {
	return &models.User1{
		ID:        u.ID,
		Username:  u.Username,
		Password:  string(u.PasswordHash),
		Role:      string(u.Role),
		PublicKey: u.PublicKey,
		Assets:    StringSliceToJSON(u.Assets),
		Comment:   u.Comment,
		CreatedAt: u.CreatedAt,
	}
}

// user1FromModel 把 models.User1 转成 bastion.User。
func user1FromModel(m *models.User1) *User {
	return &User{
		ID:        m.ID,
		Username:  m.Username,
		Role:      UserRole(m.Role),
		PublicKey: m.PublicKey,
		Assets:    JSONToStringSlice(m.Assets),
		Comment:   m.Comment,
		CreatedAt: m.CreatedAt,
	}
}

// Register1 添加用户到 user1 表，写入前完成 bcrypt 哈希。
func (s *DatabaseAuthStore1) Register1(u *User) error {
	if u == nil || u.Username == "" {
		return errors.New("register user: username required")
	}
	if u.PasswordPlain != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(u.PasswordPlain), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
		u.PasswordHash = hash
		u.PasswordPlain = ""
	}

	m := user1ToModel(u)
	if err := s.repo.UpsertUser1(context.Background(), m); err != nil {
		return fmt.Errorf("save user to %s: %w", models.User1TableName, err)
	}
	u.ID = m.ID
	u.CreatedAt = m.CreatedAt
	return nil
}

// UpdateUser1 更新 user1 表中的用户记录。
func (s *DatabaseAuthStore1) UpdateUser1(u *User) error {
	if u == nil || u.Username == "" {
		return errors.New("update user: username required")
	}

	ctx := context.Background()
	m := user1ToModel(u)
	if m.ID == 0 {
		existing, err := s.repo.GetUser1ByUsername(ctx, u.Username)
		if err != nil {
			return fmt.Errorf("update user %q: %w", u.Username, err)
		}
		m.ID = existing.ID
	}
	if err := s.repo.UpdateUser1(ctx, m); err != nil {
		return fmt.Errorf("update user %q in %s: %w", u.Username, models.User1TableName, err)
	}
	u.ID = m.ID
	return nil
}

// Unregister1 从 user1 表中删除用户。
func (s *DatabaseAuthStore1) Unregister1(username string) error {
	if err := s.repo.DeleteUser1(context.Background(), username); err != nil {
		return fmt.Errorf("delete user %q from %s: %w", username, models.User1TableName, err)
	}
	return nil
}

// Authenticate1 通过用户名和密码验证。
func (s *DatabaseAuthStore1) Authenticate1(username, password string) (*User, error) {
	m, err := s.repo.GetUser1ByUsername(context.Background(), username)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			return nil, fmt.Errorf("user %q not found", username)
		}
		return nil, fmt.Errorf("query user from %s: %w", models.User1TableName, err)
	}
	if m.Password == "" {
		return nil, fmt.Errorf("user %q has no password set", username)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(m.Password), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid password for user %q", username)
	}
	return user1FromModel(m), nil
}

// AuthenticatePublicKey1 通过 SSH 公钥验证。
func (s *DatabaseAuthStore1) AuthenticatePublicKey1(username string, pubKey ssh.PublicKey) (*User, error) {
	m, err := s.repo.GetUser1ByUsername(context.Background(), username)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			return nil, fmt.Errorf("user %q not found", username)
		}
		return nil, fmt.Errorf("query user from %s: %w", models.User1TableName, err)
	}
	if m.PublicKey == "" {
		return nil, fmt.Errorf("user %q has no public key configured", username)
	}

	configuredKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(m.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("invalid configured public key: %w", err)
	}
	if subtle.ConstantTimeCompare(pubKey.Marshal(), configuredKey.Marshal()) != 1 {
		return nil, fmt.Errorf("public key mismatch for user %q", username)
	}
	return user1FromModel(m), nil
}

// GetUser1 按用户名获取用户。
func (s *DatabaseAuthStore1) GetUser1(username string) (*User, bool) {
	m, err := s.repo.GetUser1ByUsername(context.Background(), username)
	if err != nil {
		return nil, false
	}
	return user1FromModel(m), true
}

// GetUser1ByID 按主键获取用户。
func (s *DatabaseAuthStore1) GetUser1ByID(id uint) (*User, bool) {
	m, err := s.repo.GetUser1ByID(context.Background(), id)
	if err != nil {
		return nil, false
	}
	return user1FromModel(m), true
}

// ListUsers1 返回 user1 表中的全部用户。
func (s *DatabaseAuthStore1) ListUsers1() []*User {
	users, err := s.ListUsers1WithErr()
	if err != nil {
		return []*User{}
	}
	return users
}

// ListUsers1WithErr 与 ListUsers1 相同,但把数据库错误透传给调用方。
// 管理 API 用它区分「表里确实没有用户」和「数据库连不上/查询失败」——
// 后者不该被静默伪装成空列表。
func (s *DatabaseAuthStore1) ListUsers1WithErr() ([]*User, error) {
	ms, err := s.repo.ListUsers1(context.Background())
	if err != nil {
		return nil, err
	}
	users := make([]*User, 0, len(ms))
	for _, m := range ms {
		users = append(users, user1FromModel(m))
	}
	return users, nil
}

// HasUser1 检查用户是否存在。
func (s *DatabaseAuthStore1) HasUser1(username string) bool {
	if _, err := s.repo.GetUser1ByUsername(context.Background(), username); err != nil {
		return false
	}
	return true
}

// CanAccessAsset1 检查用户是否可以访问指定资产。
func (s *DatabaseAuthStore1) CanAccessAsset1(u *User, assetID string) bool {
	return canAccessAsset(u, assetID)
}
