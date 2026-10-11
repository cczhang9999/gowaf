// Package store 提供 gowaf/bastion 用户数据的持久化访问。
//
// 用户表固定为 models.User 指向的 users1，本包只做数据访问，
// 不包含密码哈希、角色校验等业务规则（这些在 bastion 层）。
package store

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"gowaf/models"
)

// ErrUserNotFound 在按主键/用户名找不到用户时返回，供上层翻译成 404。
var ErrUserNotFound = errors.New("user not found")

// UserRepository 定义 users1 表的数据访问接口。
type UserRepository interface {
	// CreateUser 插入一条用户记录；用户名重复时返回唯一索引错误。
	CreateUser(ctx context.Context, user *models.User) error
	// UpsertUser 按 username 新增或更新：不存在则插入，已存在则更新其余字段。
	UpsertUser(ctx context.Context, user *models.User) error
	// GetUserByUsername 按用户名查询。
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	// GetUserByID 按主键查询。
	GetUserByID(ctx context.Context, id uint) (*models.User, error)
	// ListUsers 返回全部用户，按 id 升序，保证接口输出稳定。
	ListUsers(ctx context.Context) ([]*models.User, error)
	// UpdateUser 按主键更新；Password 为空表示保持原密码不变。
	UpdateUser(ctx context.Context, user *models.User) error
	// DeleteUser 按用户名删除。
	DeleteUser(ctx context.Context, username string) error
}

type userRepository struct {
	db *gorm.DB
}

// NewUserRepository 基于已连接的 *gorm.DB 构造仓储。
func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) CreateUser(ctx context.Context, user *models.User) error {
	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		return fmt.Errorf("insert into %s: %w", models.UserTableName, err)
	}
	return nil
}

func (r *userRepository) UpsertUser(ctx context.Context, user *models.User) error {
	var existing models.User
	err := r.db.WithContext(ctx).Select("id", "created_at").
		Where("username = ?", user.Username).First(&existing).Error

	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return r.CreateUser(ctx, user)
	case err != nil:
		return fmt.Errorf("query %s by username: %w", models.UserTableName, err)
	}

	// 已存在：按主键更新，同时保留原来的创建时间。
	user.ID = existing.ID
	if user.CreatedAt.IsZero() {
		user.CreatedAt = existing.CreatedAt
	}
	return r.UpdateUser(ctx, user)
}

func (r *userRepository) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("username = ?", username).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query %s by username: %w", models.UserTableName, err)
	}
	return &user, nil
}

func (r *userRepository) GetUserByID(ctx context.Context, id uint) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query %s by id: %w", models.UserTableName, err)
	}
	return &user, nil
}

func (r *userRepository) ListUsers(ctx context.Context) ([]*models.User, error) {
	var users []*models.User
	if err := r.db.WithContext(ctx).Order("id ASC").Find(&users).Error; err != nil {
		return nil, fmt.Errorf("list %s: %w", models.UserTableName, err)
	}
	return users, nil
}

func (r *userRepository) UpdateUser(ctx context.Context, user *models.User) error {
	if user.ID == 0 {
		return fmt.Errorf("update %s: user %q has no id", models.UserTableName, user.Username)
	}

	// 先确认行存在：MySQL 在「值没变化」时 RowsAffected 也是 0，不能靠它判断。
	var existing models.User
	err := r.db.WithContext(ctx).Select("id").Where("id = ?", user.ID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrUserNotFound
	}
	if err != nil {
		return fmt.Errorf("query %s by id: %w", models.UserTableName, err)
	}

	updates := map[string]any{
		"role":       user.Role,
		"public_key": user.PublicKey,
		"assets":     user.Assets,
		"comment":    user.Comment,
	}
	// 空密码表示「这次不改密码」，避免只改角色顺手把密码清空。
	if user.Password != "" {
		updates["password"] = user.Password
	}

	if err := r.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", user.ID).Updates(updates).Error; err != nil {
		return fmt.Errorf("update %s: %w", models.UserTableName, err)
	}
	return nil
}

func (r *userRepository) DeleteUser(ctx context.Context, username string) error {
	res := r.db.WithContext(ctx).Where("username = ?", username).Delete(&models.User{})
	if res.Error != nil {
		return fmt.Errorf("delete from %s: %w", models.UserTableName, res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrUserNotFound
	}
	return nil
}
