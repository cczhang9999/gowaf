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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
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
	"gowaf/internal/middleware"
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
		apiListen = flag.String("api-listen", "127.0.0.1:8081", "管理 API 监听地址,0 表示禁用")
		// apiToken 保护管理 API。留空且 API 启用时进程拒绝启动(fail-closed),
		// 除非显式声明 -insecure-no-auth。
		apiToken = flag.String("api-token", "", "管理 API 的 Bearer Token(也可用 GOWAF_API_TOKEN 环境变量)")
		// insecureNoAuth 是给本地开发用的显式逃生舱:允许无认证暴露管理 API。
		insecureNoAuth = flag.Bool("insecure-no-auth", false,
			"危险:允许管理 API 在无认证的情况下运行(仅限本机开发)")

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

	// Token 解析优先级:显式 flag > 环境变量。
	if *apiToken == "" {
		*apiToken = os.Getenv("GOWAF_API_TOKEN")
	}
	if *mysqlDSN == "" {
		*mysqlDSN = os.Getenv("GOWAF_MYSQL_DSN")
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Fail-closed:管理 API 默认必须带 Token 才能启动。
	// 之前这个二进制完全没有认证中间件,任何能访问 :8081 的人都能
	// 创建/删除用户、提权、改配置、下载会话录像。
	if *apiListen != "0" && *apiToken == "" && !*insecureNoAuth {
		fatal(log, "refusing to start: management API has no authentication. "+
			"Pass -api-token (or set GOWAF_API_TOKEN), or explicitly accept the risk "+
			"with -insecure-no-auth, or disable the API with -api-listen 0",
			errors.New("empty api token"))
	}

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
	// Without a DSN, /api/bastion/users still returns 201 (Created) but data
	// is held only in memory — it is NOT written to any table, and no SQL
	// logs are emitted. This is the #1 cause of "POST /api/bastion/users
	// returns 201 but users1 is empty" reports.
	var db *gorm.DB
	if *mysqlDSN != "" {
		log.Info("connecting to MySQL database")
		client, err := store.NewDBClient(*mysqlDSN, log)
		if err != nil {
			fatal(log, "connect to MySQL", err)
		}
		db = client.DB
		log.Info("MySQL database connected", "tables", []string{models.UserTableName, models.User1TableName})
	} else {
		log.Warn("no -mysql-dsn provided: bastion users are kept in memory only — "+
			"POST /api/bastion/users returns 201 but data is NOT persisted to the "+
			"user1/users1 tables. Pass -mysql-dsn to enable database persistence "+
			"and SQL/query logging", "tables", []string{models.UserTableName, models.User1TableName})
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
	adminExists, err := srv.HasUserErr(*adminUser)
	if err != nil {
		// 数据库不可用时不能把「查不到」当成「不存在」并覆盖已有管理员。
		fatal(log, "check admin user existence", err)
	}
	if adminExists {
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

		// 管理 API 必须经过 Bearer Token 认证。/api/healthz 豁免,
		// 以便负载均衡器/容器探针在不持有 Token 的情况下探活。
		var handler http.Handler = middleware.Logging(log)(apiMux)
		if *apiToken != "" {
			handler = middleware.BearerToken(*apiToken, "/api/healthz")(handler)
		}

		apiServer := &http.Server{
			Addr:              *apiListen,
			Handler:           handler,
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
// Generates an Ed25519 key and saves it in OpenSSH PEM format.
func initHostKey(path string, log *slog.Logger) {
	if _, err := os.Stat(path); err == nil {
		return // file exists
	}
	log.Info("generating new SSH host key", "path", path)
	if err := generateAndSaveHostKey(path); err != nil {
		log.Error("failed to generate host key, will use ephemeral key at runtime", "err", err)
	}
}

// generateAndSaveHostKey generates a new Ed25519 key and saves it in
// OpenSSH PEM format so that loadHostKey can read it on the next start.
func generateAndSaveHostKey(path string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519 key: %w", err)
	}
	// Marshal to PKCS8 (binary), then PEM-encode so loadHostKey can parse it.
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	return os.WriteFile(path, pemBytes, 0600)
}
