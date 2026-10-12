package models

import (
	"time"

	"gorm.io/gorm"
)

// User 对应数据库 users1 表（堡垒机用户管理表）。
//
// 表结构由 sql/init_users.sql 创建，这里的 GORM 标签与该表严格对齐
// （列类型、索引名都一致），这样 AutoMigrate 不会对线上表反复 ALTER。
// 表名不是 "users"：同一库里的 users 表是业务方的其它数据（id/name/email），
// 早先这里错写成 users，AutoMigrate 会往那张无关表上加列。
type User struct {
	ID        uint      `gorm:"primarykey;autoIncrement" json:"id"`
	Username  string    `gorm:"size:64;unique;not null" json:"username"`
	Password  string    `gorm:"size:255" json:"-"` // bcrypt hash, can be empty for pubkey-only users
	Role      string    `gorm:"size:20;default:'user';not null" json:"role"`
	PublicKey string    `gorm:"type:text" json:"public_key,omitempty"`
	Assets    string    `gorm:"type:longtext" json:"assets,omitempty"` // JSON 数组文本
	Comment   string    `gorm:"size:255" json:"comment,omitempty"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

// UserTableName 是堡垒机用户表的表名，供错误信息与文档统一引用。
const UserTableName = "users1"

// TableName 指定表名
func (User) TableName() string {
	return UserTableName
}

// BeforeCreate GORM 钩子：创建前检查密码是否为 bcrypt hash
// 若非 hash 则进行加密（仓储层也会做，这里再保险一层）
func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
	return u.hashPasswordIfPlain()
}

// BeforeUpdate GORM 钩子：更新时同步处理密码
func (u *User) BeforeUpdate(tx *gorm.DB) (err error) {
	return u.hashPasswordIfPlain()
}

// hashPasswordIfPlain 把明文密码替换成 bcrypt hash；已经是 hash 或为空则不动。
func (u *User) hashPasswordIfPlain() error {
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
