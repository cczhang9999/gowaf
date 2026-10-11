package main

import (
	"fmt"
	"os"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const dsn = "hobart:123456@tcp(78.154.103.23:9257)/myapp?charset=utf8mb4&parseTime=True&loc=Local"

// One-off repair: restore the users1.username column COMMENT that a failed
// GORM AutoMigrate dropped, returning the table to its original definition.
func main() {
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		fmt.Println("open error:", err)
		os.Exit(1)
	}
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	if err := db.Exec("ALTER TABLE `users1` MODIFY COLUMN `username` VARCHAR(64) NOT NULL COMMENT '用户名'").Error; err != nil {
		fmt.Println("repair error:", err)
		os.Exit(1)
	}
	fmt.Println("users1.username comment restored")
}
