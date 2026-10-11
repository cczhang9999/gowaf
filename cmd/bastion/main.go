package main

// Standalone bastion host entry point.
//
// Runs a full bastion host (SSH jump server) with:
//   - SSH server with password + public key authentication
//   - SSH proxy to backend assets
//   - Session recording (asciinema v2 format)
//   - Command audit logging (JSON Lines)
//   - RBAC-based asset access control
//   - REST API for management (users, assets, sessions, audit)
//
// Usage:
//
//	go run ./cmd/bastion \
//	  -ssh-listen :2222 \
//	  -api-listen :8081 \
//	  -host-key ssh_host_ed25519 \
//	  -recordings ./recordings \
//	  -audit-log ./audit.log
//
// Or build as a standalone binary:
//
//	go build -o bastion ./cmd/bastion
//	./bastion -ssh-listen :2222

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gorm.io/gorm"

	"gowaf/bastion"
	"gowaf/internal/store"
	"gowaf/models"
)

func main() {
	var (
		// Bastion SSH settings
		sshListen    = flag.String("ssh-listen", ":2222", "SSH 监听地址")
		hostKeyPath  = flag.String("host-key", "ssh_host_key", "SSH 主机密钥文件路径(不存在则自动生成)")
		recordDir    = flag.String("recordings", "recordings", "会话录像存储目录")
		auditLogPath = flag.String("audit-log", "audit.log", "审计日志文件路径")
		defaultUser  = flag.String("default-user", "root", "默认的后端 SSH 用户名")
		defaultPort  = flag.Int("default-port", 22, "默认的后驿 SSH 端口")
		maxSessions  = flag.Int("max-sessions", 10, "每个用户的最大会话数")
		idleTimeout  = flag.Duration("idle-timeout", 30*time.Minute, "空闲会话超时,0 表示不超时")

		// API settings
		apiListen = flag.String("api-listen", ":8081", "管理 API 监听地址,0 表示禁用")

		// Admin credentials (for initial setup)
		adminUser = flag.String("admin-user", "admin", "初始管理员用户名")
		adminPass = flag.String("admin-pass", "ChangeMe!2024", "初始管理员密码")

		// Banner
		banner = flag.String("banner", "=== GoWAF Bastion Host ===\nAuthorized access only.\n", "登录横幅")

		// MySQL database settings for user persistence.
		// 设置后 /api/bastion/users 读写 users1 表;留空则用户只存在内存里。
		mysqlDSN = flag.String("mysql-dsn", "", "MySQL DSN,例如 user:pass@tcp(127.0.0.1:3306)/myapp?charset=utf8mb4&parseTime=True&loc=Local")
	)
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Build bastion config
	cfg := &bastion.BastionConfig{
		SSHListenAddr:      *sshListen,
		APIListenAddr:      *apiListen,
		HostKeyPath:        *hostKeyPath,
		RecordingDir:       *recordDir,
		AuditLogPath:       *auditLogPath,
		DefaultUser:        *defaultUser,
		DefaultPort:        *defaultPort,
		MaxSessions:        *maxSessions,
		SessionIdleTimeout: *idleTimeout,
		BannerMsg:          *banner,
		MySQLDSN:           *mysqlDSN,
	}

	// Optional: Create MySQL database connection if DSN provided.
	// Users are then persisted in the users1 table instead of memory.
	var db *gorm.DB
	if *mysqlDSN != "" {
		log.Info("connecting to MySQL database")
		client, err := store.NewDBClient(*mysqlDSN)
		if err != nil {
			fatal(log, "connect to MySQL", err)
		}
		db = client.DB
		log.Info("MySQL database connected", "user_table", models.UserTableName)
	}

	// Create SSH server
	srv, err := bastion.NewSSHServerWithDB(cfg, log, db)
	if err != nil {
		fatal(log, "create bastion server", err)
	}

	// Add default admin user (only when it does not exist yet, so a password
	// change or role edit made through /api/bastion/users survives restarts).
	admin := &bastion.User{
		Username:      *adminUser,
		PasswordPlain: *adminPass,
		Role:          bastion.RoleAdmin,
		Comment:       "Initial admin user",
		CreatedAt:     time.Now(),
	}
	if srv.HasUser(*adminUser) {
		log.Info("admin user already exists, keeping stored credentials", "username", *adminUser)
	} else if err := srv.AddUser(admin); err != nil {
		fatal(log, "create admin user", err)
	} else {
		log.Info("admin user created", "username", *adminUser)
	}

	// Add default banned commands
	defaultBanned := []bastion.BannedCommand{
		{ID: "ban-001", Pattern: "rm -rf /", Reason: "destructive command", Enabled: true},
		{ID: "ban-002", Pattern: "mkfs", Reason: "filesystem format", Enabled: true},
		{ID: "ban-003", Pattern: "dd if=", Reason: "disk overwrite", Enabled: true},
		{ID: "ban-004", Pattern: ":(){:|:&};:", Reason: "fork bomb", Enabled: true},
		{ID: "ban-005", Pattern: "chmod 777 /", Reason: "dangerous permission change", Enabled: true},
	}
	for _, bc := range defaultBanned {
		srv.AuditStore().AddBannedCommand(bc)
	}

	log.Info("default banned commands loaded", "count", len(defaultBanned))

	// Start services with graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start SSH server
	go func() {
		if err := srv.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatal(log, "bastion ssh server", err)
		}
	}()

	// Start management API
	if *apiListen != "0" {
		adminAPI := bastion.NewAdminAPI(srv, log)
		apiHandler := adminAPI.Handler()

		// Wrap admin API under /api/ prefix so the web frontend can reach it
		// at the same URLs it expects from the main gowaf binary:
		//   /api/bastion/*  -> bastion management API
		//   /api/healthz    -> bastion health (also serves as WAF healthz)
		//   /api/metrics    -> bastion metrics (also serves as WAF metrics)
		apiMux := http.NewServeMux()
		apiMux.Handle("/api/bastion/", http.StripPrefix("/api/bastion", apiHandler))
		apiMux.Handle("/api/healthz", http.StripPrefix("/api", apiHandler))
		apiMux.Handle("/api/metrics", http.StripPrefix("/api", apiHandler))

		apiServer := &http.Server{
			Addr:              *apiListen,
			Handler:           apiMux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       60 * time.Second,
		}

		go func() {
			log.Info("bastion API server starting", "addr", *apiListen)
			if err := apiServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fatal(log, "api server", err)
			}
		}()

		// Graceful shutdown of API server
		go func() {
			<-ctx.Done()
			sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = apiServer.Shutdown(sctx)
		}()
	}

	log.Info("bastion host started",
		"ssh", *sshListen,
		"api", *apiListen,
		"recordings", *recordDir,
		"audit_log", *auditLogPath,
	)

	<-ctx.Done()
	log.Info("bastion host stopped")
}

func fatal(log *slog.Logger, msg string, err error) {
	log.Error(msg, "err", err)
	os.Exit(1)
}

// initHostKey creates a host key file if it doesn't exist.
func initHostKey(path string, log *slog.Logger) {
	if _, err := os.Stat(path); err == nil {
		return // file exists
	}
	// Generate and save an Ed25519 key
	log.Info("generating new host key", "path", path)
	// The actual key generation happens in bastion.Server.Start()
	// This is just a placeholder for the file check
	_ = fmt.Sprintf("%s", path)
}
