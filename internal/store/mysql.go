package store

import (
	"fmt"
	"log"
	"os"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"gowaf/models"
)

// gormLogger 压低日志噪音：远端 MySQL 单次查询常常超过 GORM 默认的 200ms
// 慢查询阈值，而「记录不存在」在仓储层是预期内的正常分支（由上层翻译成 404）。
func gormLogger() logger.Interface {
	return logger.New(log.New(os.Stderr, "", log.LstdFlags), logger.Config{
		SlowThreshold:             2 * time.Second,
		LogLevel:                  logger.Warn,
		IgnoreRecordNotFoundError: true,
	})
}

type DBClient struct {
	DB *gorm.DB
}

// NewDBClient 创建并初始化数据库连接。
//
// 用户表（users1）已存在时不会被改动，只在缺失时创建；
// 迁移策略见 EnsureUserTable。
func NewDBClient(dsn string) (*DBClient, error) {
	db, err := gorm.Open(mysql.New(mysql.Config{DSN: dsn}), &gorm.Config{Logger: gormLogger()})
	if err != nil {
		return nil, fmt.Errorf("gorm open: %w", err)
	}
	if err := EnsureUserTable(db); err != nil {
		return nil, err
	}
	return &DBClient{DB: db}, nil
}

// EnsureUserTable 在 users1 不存在时建表，已存在则原样保留。
//
// 这里刻意不用 db.AutoMigrate：users1 通常是线上已有的表（结构见
// sql/init_users.sql），AutoMigrate 会按 Go struct 去「对齐」列类型/注释，
// 每次启动都 ALTER 甚至生成跑不通的 DROP FOREIGN KEY 语句。
// 建表交给 sql/init_users.sql 或下面的 CreateTable，改表交给人。
func EnsureUserTable(db *gorm.DB) error {
	migrator := db.Migrator()
	if migrator.HasTable(&models.User{}) {
		return nil
	}
	if err := migrator.CreateTable(&models.User{}); err != nil {
		return fmt.Errorf("create %s table: %w", models.UserTableName, err)
	}
	return nil
}
