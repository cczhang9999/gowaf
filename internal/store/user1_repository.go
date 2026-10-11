package store

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"gowaf/models"
)

// User1Repository 定义 user1 表的数据访问接口。
type User1Repository interface {
	// CreateUser1 插入一条用户记录；用户名重复时返回唯一索引错误。
	CreateUser1(ctx context.Context, user *models.User1) error
	// UpsertUser1 按 username 新增或更新：不存在则插入，已存在则更新其余字段。
	UpsertUser1(ctx context.Context, user *models.User1) error
	// GetUser1ByUsername 按用户名查询。
	GetUser1ByUsername(ctx context.Context, username string) (*models.User1, error)
	// GetUser1ByID 按主键查询。
	GetUser1ByID(ctx context.Context, id uint) (*models.User1, error)
	// ListUsers1 返回全部用户，按 id 升序。
	ListUsers1(ctx context.Context) ([]*models.User1, error)
	// UpdateUser1 按主键更新。
	UpdateUser1(ctx context.Context, user *models.User1) error
	// DeleteUser1 按用户名删除。
	DeleteUser1(ctx context.Context, username string) error
}

type user1Repository struct {
	db *gorm.DB
}

// NewUser1Repository 基于已连接的 *gorm.DB 构造仓储。
func NewUser1Repository(db *gorm.DB) User1Repository {
	return &user1Repository{db: db}
}

func (r *user1Repository) CreateUser1(ctx context.Context, user *models.User1) error {
	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		return fmt.Errorf("insert into %s: %w", models.User1TableName, err)
	}
	return nil
}

func (r *user1Repository) UpsertUser1(ctx context.Context, user *models.User1) error {
	var existing models.User1
	err := r.db.WithContext(ctx).Select("id", "created_at").
		Where("username = ?", user.Username).First(&existing).Error

	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return r.CreateUser1(ctx, user)
	case err != nil:
		return fmt.Errorf("query %s by username: %w", models.User1TableName, err)
	}

	// 已存在：按主键更新，同时保留原来的创建时间。
	user.ID = existing.ID
	if user.CreatedAt.IsZero() {
		user.CreatedAt = existing.CreatedAt
	}
	return r.UpdateUser1(ctx, user)
}

func (r *user1Repository) GetUser1ByUsername(ctx context.Context, username string) (*models.User1, error) {
	var user models.User1
	err := r.db.WithContext(ctx).Where("username = ?", username).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query %s by username: %w", models.User1TableName, err)
	}
	return &user, nil
}

func (r *user1Repository) GetUser1ByID(ctx context.Context, id uint) (*models.User1, error) {
	var user models.User1
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query %s by id: %w", models.User1TableName, err)
	}
	return &user, nil
}

func (r *user1Repository) ListUsers1(ctx context.Context) ([]*models.User1, error) {
	var users []*models.User1
	if err := r.db.WithContext(ctx).Order("id ASC").Find(&users).Error; err != nil {
		return nil, fmt.Errorf("list %s: %w", models.User1TableName, err)
	}
	return users, nil
}

func (r *user1Repository) UpdateUser1(ctx context.Context, user *models.User1) error {
	if user.ID == 0 {
		return fmt.Errorf("update %s: user %q has no id", models.User1TableName, user.Username)
	}

	// 先确认行存在
	var existing models.User1
	err := r.db.WithContext(ctx).Select("id").Where("id = ?", user.ID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrUserNotFound
	}
	if err != nil {
		return fmt.Errorf("query %s by id: %w", models.User1TableName, err)
	}

	updates := map[string]any{
		"role":       user.Role,
		"public_key": user.PublicKey,
		"assets":     user.Assets,
		"comment":    user.Comment,
	}
	if user.Password != "" {
		updates["password"] = user.Password
	}

	if err := r.db.WithContext(ctx).Model(&models.User1{}).
		Where("id = ?", user.ID).Updates(updates).Error; err != nil {
		return fmt.Errorf("update %s: %w", models.User1TableName, err)
	}
	return nil
}

func (r *user1Repository) DeleteUser1(ctx context.Context, username string) error {
	res := r.db.WithContext(ctx).Where("username = ?", username).Delete(&models.User1{})
	if res.Error != nil {
		return fmt.Errorf("delete from %s: %w", models.User1TableName, res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrUserNotFound
	}
	return nil
}