package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gorm.io/gorm"

	"gowaf/bastion"
	"gowaf/internal/store"
	"gowaf/models"
)

var (
	// apiAddr 指定 API 服务器监听地址,默认为 :8081
	apiAddr = flag.String("api-addr", ":8081", "API 服务器监听地址,0 表示禁用")
)

func parsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := netip.ParsePrefix(part); err == nil {
			out = append(out, p)
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid ip/cidr %q", part)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// defaultBannedCommands returns a set of commonly dangerous commands to block.
func defaultBannedCommands() []bastion.BannedCommand {
	return []bastion.BannedCommand{
		{ID: "ban-001", Pattern: "rm -rf /", Reason: "destructive command", Enabled: true},
		{ID: "ban-002", Pattern: "mkfs", Reason: "filesystem format", Enabled: true},
		{ID: "ban-003", Pattern: "dd if=/dev/zero", Reason: "disk overwrite", Enabled: true},
		{ID: "ban-004", Pattern: ":(){:|:&};:", Reason: "fork bomb", Enabled: true},
		{ID: "ban-005", Pattern: "chmod 777 /", Reason: "dangerous permission change", Enabled: true},
		{ID: "ban-006", Pattern: "shutdown", Reason: "system shutdown", Enabled: true},
		{ID: "ban-007", Pattern: "reboot", Reason: "system reboot", Enabled: true},
		{ID: "ban-008", Pattern: "init 0", Reason: "system halt", Enabled: true},
	}
}

// buildProxy 构造反向代理,负责把 WAF 放行的请求转发到源站。
func buildProxy(target *url.URL, log *slog.Logger) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded() // 覆盖客户端自带的 XFF,防止伪造
		},
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
		ErrorHandler: func(rw http.ResponseWriter, r *http.Request, err error) {
			log.Error("upstream error", "err", err, "path", trunc(r.URL.Path, 200))
			http.Error(rw, "bad gateway", http.StatusBadGateway)
		},
	}
}

// buildServer 构造 HTTP 服务器,带防慢速攻击的超时设置。
func buildServer(listen string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second, // 抵御 slowloris
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
}

func main() {
	var (
		listen    = flag.String("listen", ":8080", "WAF 监听地址")
		upstream  = flag.String("upstream", "http://127.0.0.1:9000", "被保护的源站地址")
		mode      = flag.String("mode", ModeBlock, "block | detect")
		rps       = flag.Float64("rps", 20, "每 IP 每秒请求数,0 关闭限流")
		burst     = flag.Int("burst", 40, "令牌桶突发容量")
		rulesPath = flag.String("rules", "", "自定义规则 JSON(留空用内置规则),SIGHUP 热加载")
		maxBody   = flag.Int64("max-body", 1<<20, "最大检查的请求体字节数")
		trustXFF  = flag.Bool("trust-xff", false, "信任 X-Forwarded-For(仅当前面有可信代理)")
		allow     = flag.String("allow", "", "白名单 IP/CIDR,逗号分隔")
		deny      = flag.String("deny", "", "黑名单 IP/CIDR,逗号分隔")
		banStrike = flag.Int("ban-strikes", 5, "1 分钟内违规多少次自动封禁,0 关闭")
		banFor    = flag.Duration("ban-for", 10*time.Minute, "自动封禁时长")

		// 堡垒机(SSH)模式:当 -ssh 启用时,同时运行 SSH 堡垒机
		sshEnable      = flag.Bool("ssh", false, "启用 SSH 堰垒机模式(在 WAF 之外同时监听 SSH)")
		sshListen      = flag.String("ssh-listen", ":2222", "SSH 堰垒机监听地址")
		sshHostKey     = flag.String("ssh-host-key", "ssh_host_key", "SSH 主机密钥文件路径(不存在则自动生成)")
		sshRecordDir   = flag.String("ssh-recordings", "recordings", "SSH 会话录像存储目录")
		sshAuditLog    = flag.String("ssh-audit-log", "audit.log", "SSH 审计日志路径")
		sshDefaultUser = flag.String("ssh-default-user", "root", "默认后端 SSH 用户名")
		sshDefaultPort = flag.Int("ssh-default-port", 22, "默认后端 SSH 端口")
		sshAdminUser   = flag.String("ssh-admin-user", "admin", "初始管理员用户名")
		sshAdminPass   = flag.String("ssh-admin-pass", "ChangeMe!2024", "初始管理员密码")
		// 堡垒机用户持久化:/api/bastion/users 读写 MySQL 的 users1 表。
		// 留空则用户只存在内存里(重启丢失)。
		mysqlDSN = flag.String("mysql-dsn", "", "MySQL DSN,例如 user:pass@tcp(127.0.0.1:3306)/myapp?charset=utf8mb4&parseTime=True&loc=Local")
	)
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	fatal := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(1)
	}

	target, err := url.Parse(*upstream)
	if err != nil || target.Host == "" {
		fatal("invalid -upstream", fmt.Errorf("%q", *upstream))
	}
	allowList, err := parsePrefixes(*allow)
	if err != nil {
		fatal("invalid -allow", err)
	}
	denyList, err := parsePrefixes(*deny)
	if err != nil {
		fatal("invalid -deny", err)
	}

	rules := DefaultRules()
	if *rulesPath != "" {
		if rules, err = LoadRules(*rulesPath); err != nil {
			fatal("load rules", err)
		}
	}

	w := New(Config{
		Mode: *mode, MaxBody: *maxBody, RPS: *rps, Burst: *burst,
		Allow: allowList, Deny: denyList, TrustXFF: *trustXFF,
		BanStrikes: *banStrike, BanFor: *banFor,
	}, rules, log)

	proxy := buildProxy(target, log)
	srv := buildServer(*listen, w.Handler(proxy))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go w.Run(ctx)

	// SIGHUP 热加载规则:编译失败则保留旧规则,不影响线上流量
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if *rulesPath == "" {
					log.Info("SIGHUP ignored: using built-in rules")
					continue
				}
				rs, err := LoadRules(*rulesPath)
				if err != nil {
					log.Error("reload failed, keeping old rules", "err", err)
					continue
				}
				w.SetRules(rs)
				log.Info("rules reloaded", "count", len(rs))
			}
		}
	}()

	// 优雅退出:停止接收新连接,等在途请求处理完
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	// 堡垒机管理面始终创建,这样 /api/bastion/users 等管理接口在未加 -ssh
	// 时也能返回数据(默认管理员)。-ssh 只控制是否监听 SSH 端口。
	bastionCfg := &bastion.BastionConfig{
		SSHListenAddr:      *sshListen,
		APIListenAddr:      *apiAddr,
		HostKeyPath:        *sshHostKey,
		RecordingDir:       *sshRecordDir,
		AuditLogPath:       *sshAuditLog,
		DefaultUser:        *sshDefaultUser,
		DefaultPort:        *sshDefaultPort,
		MaxSessions:        100,
		SessionIdleTimeout: 30 * time.Minute,
		BannerMsg:          "=== GoWAF Bastion Host ===\nAuthorized access only.\n",
	}
	// 堡垒机用户表:配置了 -mysql-dsn 时,用户读写落到 users1 表和 user1 表。
	var userDB *gorm.DB
	if *mysqlDSN != "" {
		client, err := store.NewDBClient(*mysqlDSN, log)
		if err != nil {
			fatal("connect to MySQL", err)
		}
		userDB = client.DB
		log.Info("bastion users persisted to MySQL", "table", models.UserTableName, "table1", models.User1TableName)
	} else {
		log.Warn("bastion users kept in memory: POST /api/bastion/users returns 201 but data is NOT persisted to the user1/users1 tables — pass -mysql-dsn to enable database persistence and SQL logging")
	}

	bastionSrv, bErr := bastion.NewSSHServerWithDB(bastionCfg, log, userDB)
	if bErr != nil {
		fatal("create bastion server", bErr)
	}

	adminUser := &bastion.User{
		Username:      *sshAdminUser,
		PasswordPlain: *sshAdminPass,
		Role:          bastion.RoleAdmin,
		Comment:       "Initial admin user",
		CreatedAt:     time.Now(),
	}
	// 只在首次创建:否则每次重启都会把管理员密码重置回默认值。
	if bastionSrv.HasUser(*sshAdminUser) {
		log.Info("admin user already exists, keeping stored credentials", "username", *sshAdminUser)
	} else if err := bastionSrv.AddUser(adminUser); err != nil {
		fatal("create admin user", err)
	}

	for _, bc := range defaultBannedCommands() {
		bastionSrv.AuditStore().AddBannedCommand(bc)
	}

	if *sshEnable {
		go func() {
			if err := bastionSrv.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("bastion ssh server error", "err", err)
			}
		}()
	}

	// 启动 API 服务器(带 WAF + 堰垒机管理接口)
	var apiServer *APIServer
	if *apiAddr != "0" {
		apiServer = NewAPIServerWithBastion(w, *apiAddr, bastionSrv, log)
		go func() {
			if err := apiServer.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("api server error", "err", err)
			}
		}()
	}

	log.Info("waf started", "listen", *listen, "upstream", target.String(), "mode", *mode, "rules", len(rules),
		"bastion", *sshEnable)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal("server", err)
	}

	// 停止 API 服务器
	if apiServer != nil {
		_ = apiServer.Stop()
	}
	log.Info("waf stopped")
}
