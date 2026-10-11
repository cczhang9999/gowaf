package main

import (
	"fmt"
	"os"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const dsn = "hobart:123456@tcp(78.154.103.23:9257)/myapp?charset=utf8mb4&parseTime=True&loc=Local"

// Snapshot users1: DDL + row count + usernames only (no secrets printed).
func main() {
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		fmt.Println("open error:", err)
		os.Exit(1)
	}
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	var tbl, ddl string
	if err := db.Raw("SHOW CREATE TABLE `users1`").Row().Scan(&tbl, &ddl); err != nil {
		fmt.Println("users1 DDL error:", err)
		os.Exit(1)
	}
	fmt.Println("=== users1 DDL ===")
	fmt.Println(ddl)

	var cnt int64
	if err := db.Raw("SELECT COUNT(*) FROM `users1`").Scan(&cnt).Error; err != nil {
		fmt.Println("count error:", err)
	}
	fmt.Printf("=== users1 ROW COUNT: %d ===\n", cnt)

	var names []string
	if err := db.Raw("SELECT username FROM `users1` ORDER BY id").Scan(&names).Error; err == nil {
		fmt.Printf("=== users1 USERNAMES: %v ===\n", names)
	}

	// Guard: the unrelated business table must be untouched.
	var cols []struct {
		Field string
		Type  string
	}
	if err := db.Raw("SHOW COLUMNS FROM `users`").Scan(&cols).Error; err == nil {
		fmt.Print("=== users (business table) COLUMNS: ")
		for i, c := range cols {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Printf("%s %s", c.Field, c.Type)
		}
		fmt.Println(" ===")
	}
}
