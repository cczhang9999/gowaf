package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const dsn = "hobart:123456@tcp(78.154.103.23:9257)/myapp?charset=utf8mb4&parseTime=True&loc=Local"

// usage: go run ./.dbsql "SELECT username, role FROM users1 ORDER BY id"
func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: dbsql <sql>")
		os.Exit(2)
	}
	statement := strings.Join(os.Args[1:], " ")

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		fmt.Println("open error:", err)
		os.Exit(1)
	}
	sqlDB, _ := db.DB()
	defer sqlDB.Close()

	upper := strings.ToUpper(strings.TrimSpace(statement))
	if strings.HasPrefix(upper, "SELECT") || strings.HasPrefix(upper, "SHOW") {
		var rows []map[string]any
		if err := db.Raw(statement).Scan(&rows).Error; err != nil {
			fmt.Println("query error:", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(rows, "", "  ")
		fmt.Println(string(out))
		return
	}

	res := db.Exec(statement)
	if res.Error != nil {
		fmt.Println("exec error:", res.Error)
		os.Exit(1)
	}
	fmt.Printf("ok, rows affected: %d\n", res.RowsAffected)
}
