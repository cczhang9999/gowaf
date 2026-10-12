package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 是 gowaf 的完整配置结构
type Config struct {
	WAF       WAFConfig       `yaml:"waf"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	IP        IPConfig        `yaml:"ip"`
	Upstream  UpstreamConfig  `yaml:"upstream"`
	Server    ServerConfig    `yaml:"server"`
	Rules     RulesConfig     `yaml:"rules"`
	Bastion   BastionConfig   `yaml:"bastion"`
	Database  DatabaseConfig  `yaml:"database"`
	Logging   LoggingConfig   `yaml:"logging"`
	Security  SecurityConfig  `yaml:"security"`
}

// WAFConfig WAF 基础配置
type WAFConfig struct {
	Mode     string `yaml:"mode"`      // block / detect
	MaxBody  int64  `yaml:"max_body"`  // 最大检查的请求体字节数
	TrustXFF bool   `yaml:"trust_xff"` // 是否信任 X-Forwarded-For
}

// RateLimitConfig 限流配置
type RateLimitConfig struct {
	Enabled       bool            `yaml:"enabled"`        // 是否启用限流
	RPS           float64         `yaml:"rps"`            // 每 IP 每秒请求数
	Burst         int             `yaml:"burst"`          // 令牌桶突发容量
	Strategy      string          `yaml:"strategy"`       // per_ip / per_path / per_user
	PathWhitelist []string        `yaml:"path_whitelist"` // 限流例外路径
	PathRules     []PathRateLimit `yaml:"path_rules"`     // 按路径的限流规则
	AutoBan       AutoBanConfig   `yaml:"auto_ban"`       // 自动封禁配置
}

// PathRateLimit 按路径的限流规则
type PathRateLimit struct {
	Path  string  `yaml:"path"`  // 路径模式 (支持通配符 *)
	RPS   float64 `yaml:"rps"`   // 该路径的 RPS
	Burst int     `yaml:"burst"` // 该路径的 burst
}

// AutoBanConfig 自动封禁配置
type AutoBanConfig struct {
	Enabled  bool          `yaml:"enabled"`  // 是否启用自动封禁
	Strikes  int           `yaml:"strikes"`  // 窗口内违规次数
	Window   time.Duration `yaml:"window"`   // 时间窗口
	Duration time.Duration `yaml:"duration"` // 封禁时长
}

// IPConfig IP 管理配置
type IPConfig struct {
	Allow []string `yaml:"allow"` // 白名单 IP/CIDR
	Deny  []string `yaml:"deny"`  // 黑名单 IP/CIDR
}

// UpstreamConfig 上游服务器配置
type UpstreamConfig struct {
	URL          string `yaml:"url"`            // 被保护的源站地址
	DialTimeout  int    `yaml:"dial_timeout"`   // 连接超时 (秒)
	IdleTimeout  int    `yaml:"idle_timeout"`   // 空闲连接超时 (秒)
	MaxIdleConns int    `yaml:"max_idle_conns"` // 最大空闲连接数
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Listen            string        `yaml:"listen"`              // WAF 监听地址
	APIAddr           string        `yaml:"api_addr"`            // API 服务器地址
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"` // 读请求头超时
	ReadTimeout       time.Duration `yaml:"read_timeout"`        // 读请求超时
	WriteTimeout      time.Duration `yaml:"write_timeout"`       // 写响应超时
	IdleTimeout       time.Duration `yaml:"idle_timeout"`        // 空闲连接超时
	MaxHeaderBytes    int           `yaml:"max_header_bytes"`    // 最大请求头字节数
}

// RulesConfig 规则配置
type RulesConfig struct {
	Path         string       `yaml:"path"`          // 自定义规则文件路径
	BuiltinRules BuiltinRules `yaml:"builtin_rules"` // 内置规则开关
}

// BuiltinRules 内置规则开关
type BuiltinRules struct {
	SQLInjection     bool `yaml:"sql_injection"`
	XSS              bool `yaml:"xss"`
	PathTraversal    bool `yaml:"path_traversal"`
	CommandInjection bool `yaml:"command_injection"`
	Log4Shell        bool `yaml:"log4shell"`
	ScannerDetection bool `yaml:"scanner_detection"`
}

// BastionConfig SSH 堡垒机配置
type BastionConfig struct {
	Enabled            bool          `yaml:"enabled"`              // 是否启用
	SSHListen          string        `yaml:"ssh_listen"`           // SSH 监听地址
	HostKeyPath        string        `yaml:"host_key_path"`        // SSH 主机密钥文件
	RecordingDir       string        `yaml:"recording_dir"`        // 会话录像存储目录
	AuditLogPath       string        `yaml:"audit_log_path"`       // 审计日志路径
	DefaultUser        string        `yaml:"default_user"`         // 默认后端 SSH 用户名
	DefaultPort        int           `yaml:"default_port"`         // 默认后端 SSH 端口
	MaxSessions        int           `yaml:"max_sessions"`         // 最大并发会话数
	SessionIdleTimeout time.Duration `yaml:"session_idle_timeout"` // 会话空闲超时
	Banner             string        `yaml:"banner"`               // 欢迎横幅
	AdminUser          string        `yaml:"admin_user"`           // 初始管理员用户名
	AdminPass          string        `yaml:"admin_pass"`           // 初始管理员密码
}

// DatabaseConfig 数据库配置
type DatabaseConfig struct {
	MySQLDSN   string `yaml:"mysql_dsn"`   // MySQL DSN
	SQLitePath string `yaml:"sqlite_path"` // SQLite 路径 (仅测试用)
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	Level    string `yaml:"level"`     // debug / info / warn / error
	Format   string `yaml:"format"`    // json / text
	Output   string `yaml:"output"`    // stdout / file
	FilePath string `yaml:"file_path"` // 日志文件路径
}

// SecurityConfig 安全加固配置
type SecurityConfig struct {
	CORS        CORSConfig    `yaml:"cors"`         // CORS 配置
	APIAuth     APIAuthConfig `yaml:"api_auth"`     // API 认证配置
	HideVersion bool          `yaml:"hide_version"` // 隐藏版本信息
}

// CORSConfig CORS 配置
type CORSConfig struct {
	Enabled        bool     `yaml:"enabled"`         // 是否启用
	AllowedOrigins []string `yaml:"allowed_origins"` // 允许的源
	AllowedMethods []string `yaml:"allowed_methods"` // 允许的方法
	AllowedHeaders []string `yaml:"allowed_headers"` // 允许的头
}

// APIAuthConfig API 认证配置
type APIAuthConfig struct {
	Enabled bool   `yaml:"enabled"` // 是否启用
	Type    string `yaml:"type"`    // none / basic / token
}

// Load 加载配置文件
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	// 解析 YAML
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 设置默认值
	setDefaults(&cfg)

	// 验证配置
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("配置验证失败: %w", err)
	}

	return &cfg, nil
}

// setDefaults 设置默认值
func setDefaults(cfg *Config) {
	// WAF 默认值
	if cfg.WAF.Mode == "" {
		cfg.WAF.Mode = "block"
	}
	if cfg.WAF.MaxBody == 0 {
		cfg.WAF.MaxBody = 1 << 20 // 1MB
	}

	// 限流默认值
	if cfg.RateLimit.RPS == 0 {
		cfg.RateLimit.RPS = 20
	}
	if cfg.RateLimit.Burst == 0 {
		cfg.RateLimit.Burst = 40
	}
	if cfg.RateLimit.Strategy == "" {
		cfg.RateLimit.Strategy = "per_ip"
	}
	if cfg.RateLimit.AutoBan.Window == 0 {
		cfg.RateLimit.AutoBan.Window = time.Minute
	}
	if cfg.RateLimit.AutoBan.Duration == 0 {
		cfg.RateLimit.AutoBan.Duration = 10 * time.Minute
	}

	// 服务器默认值
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":8080"
	}
	if cfg.Server.APIAddr == "" {
		cfg.Server.APIAddr = ":8081"
	}
	if cfg.Server.ReadHeaderTimeout == 0 {
		cfg.Server.ReadHeaderTimeout = 5 * time.Second
	}
	if cfg.Server.ReadTimeout == 0 {
		cfg.Server.ReadTimeout = 15 * time.Second
	}
	if cfg.Server.WriteTimeout == 0 {
		cfg.Server.WriteTimeout = 60 * time.Second
	}
	if cfg.Server.IdleTimeout == 0 {
		cfg.Server.IdleTimeout = 60 * time.Second
	}
	if cfg.Server.MaxHeaderBytes == 0 {
		cfg.Server.MaxHeaderBytes = 1 << 16
	}

	// 上游默认值
	if cfg.Upstream.URL == "" {
		cfg.Upstream.URL = "http://127.0.0.1:9000"
	}
	if cfg.Upstream.DialTimeout == 0 {
		cfg.Upstream.DialTimeout = 3
	}
	if cfg.Upstream.IdleTimeout == 0 {
		cfg.Upstream.IdleTimeout = 90
	}
	if cfg.Upstream.MaxIdleConns == 0 {
		cfg.Upstream.MaxIdleConns = 100
	}

	// 堡垒机默认值
	if cfg.Bastion.SSHListen == "" {
		cfg.Bastion.SSHListen = ":2222"
	}
	if cfg.Bastion.HostKeyPath == "" {
		cfg.Bastion.HostKeyPath = "ssh_host_key"
	}
	if cfg.Bastion.RecordingDir == "" {
		cfg.Bastion.RecordingDir = "recordings"
	}
	if cfg.Bastion.AuditLogPath == "" {
		cfg.Bastion.AuditLogPath = "audit.log"
	}
	if cfg.Bastion.DefaultUser == "" {
		cfg.Bastion.DefaultUser = "root"
	}
	if cfg.Bastion.DefaultPort == 0 {
		cfg.Bastion.DefaultPort = 22
	}
	if cfg.Bastion.MaxSessions == 0 {
		cfg.Bastion.MaxSessions = 100
	}
	if cfg.Bastion.SessionIdleTimeout == 0 {
		cfg.Bastion.SessionIdleTimeout = 30 * time.Minute
	}
	if cfg.Bastion.Banner == "" {
		cfg.Bastion.Banner = "=== GoWAF Bastion Host ===\nAuthorized access only.\n"
	}
	if cfg.Bastion.AdminUser == "" {
		cfg.Bastion.AdminUser = "admin"
	}
	if cfg.Bastion.AdminPass == "" {
		cfg.Bastion.AdminPass = "ChangeMe!2024"
	}

	// 日志默认值
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}
	if cfg.Logging.Output == "" {
		cfg.Logging.Output = "stdout"
	}

	// 内置规则默认值 (全部开启)
	if !cfg.Rules.BuiltinRules.SQLInjection &&
		!cfg.Rules.BuiltinRules.XSS &&
		!cfg.Rules.BuiltinRules.PathTraversal &&
		!cfg.Rules.BuiltinRules.CommandInjection &&
		!cfg.Rules.BuiltinRules.Log4Shell &&
		!cfg.Rules.BuiltinRules.ScannerDetection {
		cfg.Rules.BuiltinRules.SQLInjection = true
		cfg.Rules.BuiltinRules.XSS = true
		cfg.Rules.BuiltinRules.PathTraversal = true
		cfg.Rules.BuiltinRules.CommandInjection = true
		cfg.Rules.BuiltinRules.Log4Shell = true
		cfg.Rules.BuiltinRules.ScannerDetection = true
	}
}

// Validate 验证配置
func (c *Config) Validate() error {
	// 验证 WAF 模式
	if c.WAF.Mode != "block" && c.WAF.Mode != "detect" {
		return fmt.Errorf("waf.mode 必须是 'block' 或 'detect', 当前值: %s", c.WAF.Mode)
	}

	// 验证限流策略
	if c.RateLimit.Strategy != "per_ip" && c.RateLimit.Strategy != "per_path" && c.RateLimit.Strategy != "per_user" {
		return fmt.Errorf("rate_limit.strategy 必须是 'per_ip', 'per_path' 或 'per_user', 当前值: %s", c.RateLimit.Strategy)
	}

	// 验证限流参数
	if c.RateLimit.RPS < 0 {
		return fmt.Errorf("rate_limit.rps 不能为负数")
	}
	if c.RateLimit.Burst < 0 {
		return fmt.Errorf("rate_limit.burst 不能为负数")
	}

	// 验证自动封禁参数
	if c.RateLimit.AutoBan.Strikes < 0 {
		return fmt.Errorf("rate_limit.auto_ban.strikes 不能为负数")
	}

	// 验证日志格式
	if c.Logging.Format != "json" && c.Logging.Format != "text" {
		return fmt.Errorf("logging.format 必须是 'json' 或 'text', 当前值: %s", c.Logging.Format)
	}

	// 验证日志级别
	level := strings.ToLower(c.Logging.Level)
	if level != "debug" && level != "info" && level != "warn" && level != "error" {
		return fmt.Errorf("logging.level 必须是 'debug', 'info', 'warn' 或 'error', 当前值: %s", c.Logging.Level)
	}

	return nil
}

// IsPathWhitelisted 检查路径是否在限流例外列表中
func (c *Config) IsPathWhitelisted(path string) bool {
	for _, p := range c.RateLimit.PathWhitelist {
		if p == path {
			return true
		}
		// 支持简单的通配符匹配 (如 /api/*)
		if strings.HasSuffix(p, "*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}
	}
	return false
}

// GetPathRateLimit 获取路径特定的限流配置
func (c *Config) GetPathRateLimit(path string) (rps float64, burst int, found bool) {
	for _, rule := range c.RateLimit.PathRules {
		// 支持简单的通配符匹配
		if rule.Path == "*" || rule.Path == path {
			return rule.RPS, rule.Burst, true
		}
		if strings.HasSuffix(rule.Path, "*") {
			prefix := strings.TrimSuffix(rule.Path, "*")
			if strings.HasPrefix(path, prefix) {
				return rule.RPS, rule.Burst, true
			}
		}
	}
	return 0, 0, false
}
