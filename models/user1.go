package models

import (
	"time"

	"gorm.io/gorm"
)

// User1 对应数据库 user1 表（堡垒机用户管理表）。
// 表结构类似于 User，但表名为 user1（不带 's'）。
// 表结构由 sql/init_users.sql 创建，这里的 GORM 标签与该表严格对齐
type User1 struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Username  string    `gorm:"size:64;uniqueIndex:username;not null" json:"username"`
	Password  string    `gorm:"size:255;not null" json:"-"` // bcrypt hash
	Role      string    `gorm:"size:20;default:'user';not null;index:idx_role" json:"role"`
	PublicKey string    `gorm:"type:text" json:"public_key,omitempty"`
	Assets    string    `gorm:"type:longtext" json:"assets,omitempty"` // JSON 数组文本
	Comment   string    `gorm:"size:255" json:"comment,omitempty"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

// User1TableName 是堡垒机用户表的表名，供错误信息与文档统一引用。
const User1TableName = "user1"

// TableName 指定表名
func (User1) TableName() string {
	return User1TableName
}

// BeforeCreate GORM 钩子：创建前检查密码是否为 bcrypt hash
func (u *User1) BeforeCreate(tx *gorm.DB) (err error) {
	return u.hashPasswordIfPlain()
}

// BeforeUpdate GORM 钩子：更新时同步处理密码
func (u *User1) BeforeUpdate(tx *gorm.DB) (err error) {
	return u.hashPasswordIfPlain()
}

// hashPasswordIfPlain 把明文密码替换成 bcrypt hash
func (u *User1) hashPasswordIfPlain() error {
	if len(u.Password) == 0 {
		return nil
	}
	// 已经是 bcrypt hash（以 $2a$, $2b$, $2y$ 开头）则不再处理
	if u.Password[0] == '$' && len(u.Password) >= 60 {
		return nil
	}
	hashed, err := HashPassword(u.Password)
	if err != nil {
		return err
	}
	u.Password = hashed
	return nil
}