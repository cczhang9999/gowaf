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
	"gowaf/config"
	"gowaf/internal/store"
	"gowaf/models"
)

var (
	// WAF 服务器标志
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

	// API 服务器标志
	apiAddr  = flag.String("api-addr", ":8081", "API 服务器监听地址,0 表示禁用")
	apiToken = flag.String("api-token", "", "API 服务器身份认证 Token(也可通过 GOWAF_API_TOKEN 环境变量设置)")

	// 配置文件
	// 未显式传 -config 时,main() 会自动尝试加载当前目录下的 config.yaml。
	configPath = flag.String("config", "", "YAML 配置文件路径(留空则自动尝试加载当前目录的 config.yaml,CLI 参数优先于配置文件)")

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

// resolvedConfig 保存从 CLI 标志和 YAML 配置文件合并后的最终配置。
// 优先级:显式设置的 CLI 标志 > YAML 配置文件 > CLI 默认值。
type resolvedConfig struct {
	Listen, UpstreamURL, Mode, RulesPath string
	RPS                                  float64
	Burst                                int
	MaxBody                              int64
	TrustXFF                             bool
	Allow, Deny                          string
	BanStrikes                           int
	BanFor, BanWindow                    time.Duration
	APIAddr                              string
	SSHEnable                            bool
	// 堡垒机
	SSHListen, SSHHostKey, SSHRecordDir, SSHAuditLog string
	SSHDefaultUser                                   string
	SSHDefaultPort                                   int
	SSHCustMaxSessions                               int
	SSHAdminUser, SSHAdminPass                       string
	MySQLDSN                                         string
	APIToken                                         string
}

// buildWAFConfig 合并 YAML 配置和 CLI 标志。
// 规则:如果 CLI 标志被显式设置(使用 flag.Visit 检测),则覆盖 YAML 值。
// 否则使用 YAML 值(如果已加载),最终回退到 CLI 默认值。
func buildWAFConfig(yamlCfg *config.Config) *resolvedConfig {
	// 收集显式设置的 CLI 标志
	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })

	cfg := &resolvedConfig{}

	// --- WAF 基础配置 ---
	cfg.Listen = *listen
	cfg.UpstreamURL = *upstream
	cfg.Mode = *mode
	cfg.RPS = *rps
	cfg.Burst = *burst
	cfg.RulesPath = *rulesPath
	cfg.MaxBody = *maxBody
	cfg.TrustXFF = *trustXFF
	cfg.Allow = *allow
	cfg.Deny = *deny
	cfg.BanStrikes = *banStrike
	cfg.BanFor = *banFor
	cfg.BanWindow = time.Minute

	// --- API 配置 ---
	cfg.APIAddr = *apiAddr
	cfg.APIToken = *apiToken
	if cfg.APIToken == "" {
		cfg.APIToken = os.Getenv("GOWAF_API_TOKEN")
	}

	// --- 堡垒机配置 ---
	cfg.SSHEnable = *sshEnable
	cfg.SSHListen = *sshListen
	cfg.SSHHostKey = *sshHostKey
	cfg.SSHRecordDir = *sshRecordDir
	cfg.SSHAuditLog = *sshAuditLog
	cfg.SSHDefaultUser = *sshDefaultUser
	cfg.SSHDefaultPort = *sshDefaultPort
	cfg.SSHCustMaxSessions = 100
	cfg.SSHAdminUser = *sshAdminUser
	cfg.SSHAdminPass = *sshAdminPass
	cfg.MySQLDSN = *mysqlDSN

	// 从 YAML 覆盖默认值(CLI 未显式设置时)
	if yamlCfg != nil {
		if !setFlags["listen"] {
			cfg.Listen = yamlCfg.Server.Listen
		}
		if !setFlags["upstream"] {
			cfg.UpstreamURL = yamlCfg.Upstream.URL
		}
		if !setFlags["mode"] {
			cfg.Mode = yamlCfg.WAF.Mode
		}
		if !setFlags["rps"] {
			cfg.RPS = yamlCfg.RateLimit.RPS
		}
		if !setFlags["burst"] {
			cfg.Burst = yamlCfg.RateLimit.Burst
		}
		if !setFlags["rules"] {
			cfg.RulesPath = yamlCfg.Rules.Path
		}
		if !setFlags["max-body"] {
			cfg.MaxBody = yamlCfg.WAF.MaxBody
		}
		if !setFlags["trust-xff"] {
			cfg.TrustXFF = yamlCfg.WAF.TrustXFF
		}
		if !setFlags["allow"] {
			cfg.Allow = strings.Join(yamlCfg.IP.Allow, ",")
		}
		if !setFlags["deny"] {
			cfg.Deny = strings.Join(yamlCfg.IP.Deny, ",")
		}
		if !setFlags["ban-strikes"] {
			cfg.BanStrikes = yamlCfg.RateLimit.AutoBan.Strikes
		}
		if !setFlags["ban-for"] {
			cfg.BanFor = yamlCfg.RateLimit.AutoBan.Duration
		}
		cfg.BanWindow = yamlCfg.RateLimit.AutoBan.Window

		if !setFlags["api-addr"] {
			cfg.APIAddr = yamlCfg.Server.APIAddr
		}
		// API token: YAML > env > CLI
		if yamlCfg.Security.APIAuth.Enabled && yamlCfg.Security.APIAuth.Token != "" && !setFlags["api-token"] {
			cfg.APIToken = yamlCfg.Security.APIAuth.Token
		}

		if !setFlags["ssh-listen"] {
			cfg.SSHListen = yamlCfg.Bastion.SSHListen
		}
		if !setFlags["ssh-host-key"] {
			cfg.SSHHostKey = yamlCfg.Bastion.HostKeyPath
		}
		if !setFlags["ssh-recordings"] {
			cfg.SSHRecordDir = yamlCfg.Bastion.RecordingDir
		}
		if !setFlags["ssh-audit-log"] {
			cfg.SSHAuditLog = yamlCfg.Bastion.AuditLogPath
		}
		if !setFlags["ssh-default-user"] {
			cfg.SSHDefaultUser = yamlCfg.Bastion.DefaultUser
		}
		if !setFlags["ssh-default-port"] {
			cfg.SSHDefaultPort = yamlCfg.Bastion.DefaultPort
		}
		if !setFlags["max-sessions"] {
			cfg.SSHCustMaxSessions = yamlCfg.Bastion.MaxSessions
		}
		if !setFlags["ssh-admin-user"] {
			cfg.SSHAdminUser = yamlCfg.Bastion.AdminUser
		}
		if !setFlags["ssh-admin-pass"] {
			cfg.SSHAdminPass = yamlCfg.Bastion.AdminPass
		}
		if !setFlags["mysql-dsn"] {
			cfg.MySQLDSN = yamlCfg.Database.MySQLDSN
		}
	}

	return cfg
}

// newLogger 根据配置创建结构化 JSON logger。
// 支持日志级别和输出目标(file|stdout)配置。
func newLogger(yamlCfg *config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if yamlCfg != nil {
		switch strings.ToLower(yamlCfg.Logging.Level) {
		case "debug":
			opts.Level = slog.LevelDebug
		case "warn":
			opts.Level = slog.LevelWarn
		case "error":
			opts.Level = slog.LevelError
		}
		if strings.ToLower(yamlCfg.Logging.Format) == "text" {
			return slog.New(slog.NewTextHandler(os.Stderr, opts))
		}
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
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
	flag.Parse()

	// 加载配置文件。
	// 优先级:
	//   1. 显式 -config <path> → 加载该文件(解析失败则回落到纯 CLI 参数,并打印告警)
	//   2. 未指定 -config     → 自动尝试当前目录的 config.yaml;
	//                          存在则加载(解析失败回落 CLI),不存在则使用纯 CLI 默认值(不报错)。
	// 这样 `./gowaf` 即可直接读取仓库里的 config.yaml,无需手动传 -config。
	var yamlCfg *config.Config
	loadPath := *configPath
	if loadPath == "" {
		loadPath = "config.yaml"
	}
	if _, statErr := os.Stat(loadPath); statErr == nil {
		cfg, err := config.Load(loadPath)
		if err != nil {
			// 解析失败:不退出,回落到 CLI 参数(保留原行为)
			log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
			log.Error("failed to load config file, falling back to CLI flags", "path", loadPath, "err", err)
			yamlCfg = nil
		} else {
			yamlCfg = cfg
			log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
			log.Info("loaded config file", "path", loadPath)
		}
	} else if *configPath != "" {
		// 显式指定的文件不存在:这是配置错误,直接退出
		log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
		log.Error("config file not found", "path", loadPath)
		os.Exit(1)
	}

	log := newLogger(yamlCfg)
	fatal := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(1)
	}

	cfg := buildWAFConfig(yamlCfg)
	target, err := url.Parse(cfg.UpstreamURL)
	if err != nil || target.Host == "" {
		fatal("invalid -upstream", fmt.Errorf("%q", cfg.UpstreamURL))
	}
	allowList, err := parsePrefixes(cfg.Allow)
	if err != nil {
		fatal("invalid -allow", err)
	}
	denyList, err := parsePrefixes(cfg.Deny)
	if err != nil {
		fatal("invalid -deny", err)
	}

	rules := DefaultRules()
	if cfg.RulesPath != "" {
		if rules, err = LoadRules(cfg.RulesPath); err != nil {
			fatal("load rules", err)
		}
	}

	w := New(Config{
		Mode: cfg.Mode, MaxBody: cfg.MaxBody, RPS: cfg.RPS, Burst: cfg.Burst,
		Allow: allowList, Deny: denyList, TrustXFF: cfg.TrustXFF,
		BanStrikes: cfg.BanStrikes, BanFor: cfg.BanFor, BanWindow: cfg.BanWindow,
	}, rules, log)

	proxy := buildProxy(target, log)
	srv := buildServer(cfg.Listen, w.Handler(proxy))

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
				if cfg.RulesPath == "" {
					log.Info("SIGHUP ignored: using built-in rules")
					continue
				}
				rs, err := LoadRules(cfg.RulesPath)
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
		SSHListenAddr:      cfg.SSHListen,
		APIListenAddr:      cfg.APIAddr,
		HostKeyPath:        cfg.SSHHostKey,
		RecordingDir:       cfg.SSHRecordDir,
		AuditLogPath:       cfg.SSHAuditLog,
		DefaultUser:        cfg.SSHDefaultUser,
		DefaultPort:        cfg.SSHDefaultPort,
		MaxSessions:        cfg.SSHCustMaxSessions,
		SessionIdleTimeout: 30 * time.Minute,
		MySQLDSN:           cfg.MySQLDSN,
		BannerMsg:          "=== GoWAF Bastion Host ===\nAuthorized access only.\n",
	}
	// 堡垒机用户表:配置了 -mysql-dsn 时,用户读写落到 users1 表和 user1 表。
	var userDB *gorm.DB
	if cfg.MySQLDSN != "" {
		// 注意:必须用 cfg.MySQLDSN(已合并 YAML + CLI),不能直接用 *mysqlDSN,
		// 否则仅通过 -config 提供 DSN 时这里会传空串,gorm 会回落到
		// 127.0.0.1:3306 并连接失败。
		client, err := store.NewDBClient(cfg.MySQLDSN, log)
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
		Username:      cfg.SSHAdminUser,
		PasswordPlain: cfg.SSHAdminPass,
		Role:          bastion.RoleAdmin,
		Comment:       "Initial admin user",
		CreatedAt:     time.Now(),
	}
	// 只在首次创建:否则每次重启都会把管理员密码重置回默认值。
	if bastionSrv.HasUser(cfg.SSHAdminUser) {
		log.Info("admin user already exists, keeping stored credentials", "username", cfg.SSHAdminUser)
	} else if err := bastionSrv.AddUser(adminUser); err != nil {
		fatal("create admin user", err)
	}

	for _, bc := range defaultBannedCommands() {
		bastionSrv.AuditStore().AddBannedCommand(bc)
	}

	if cfg.SSHEnable {
		go func() {
			if err := bastionSrv.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("bastion ssh server error", "err", err)
			}
		}()
	}

	// 启动 API 服务器(带 WAF + 堰垒机管理接口)
	var apiServer *APIServer
	if cfg.APIAddr != "0" {
		apiServer = NewAPIServerWithBastion(w, cfg.APIAddr, cfg.APIToken, cfg.UpstreamURL, bastionSrv, log)
		apiServer.SetAPIRateLimit(100, 200) // 管理 API: 100 RPS, 200 burst
		go func() {
			if err := apiServer.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("api server error", "err", err)
			}
		}()
	}

	log.Info("waf started", "listen", cfg.Listen, "upstream", target.String(), "mode", cfg.Mode, "rules", len(rules),
		"bastion", cfg.SSHEnable, "api_token", len(cfg.APIToken) > 0)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal("server", err)
	}

	// 停止 API 服务器
	if apiServer != nil {
		_ = apiServer.Stop()
	}
	log.Info("waf stopped")
}
