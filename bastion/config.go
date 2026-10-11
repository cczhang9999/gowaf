package bastion

import (
	"time"
)

// BastionConfig holds all runtime configuration for the bastion host.
// It uses value semantics and is stored atomically in the SSHServer,
// so it can be swapped at runtime (e.g., via SIGHUP or API PUT) without
// locking on the hot path — mirroring the pattern in gowaf's waf.go.
type BastionConfig struct {
	// SSHListenAddr is the address the bastion SSH server listens on.
	SSHListenAddr string `json:"ssh_listen_addr"`

	// APIListenAddr is the address for the management HTTP API.
	APIListenAddr string `json:"api_listen_addr"`

	// HostKeyPath is the path to the SSH server's private host key.
	HostKeyPath string `json:"host_key_path"`

	// RecordingDir is where session recordings are saved.
	RecordingDir string `json:"recording_dir"`

	// AuditLogPath is the path for the structured command audit log.
	AuditLogPath string `json:"audit_log_path"`

	// DefaultUser is the SSH user used when connecting to backend assets
	// (can be overridden per-asset).
	DefaultUser string `json:"default_user"`

	// DefaultPort is the SSH port for backend assets (default 22).
	DefaultPort int `json:"default_port"`

	// MaxSessions limits concurrent SSH sessions per user.
	MaxSessions int `json:"max_sessions"`

	// SessionIdleTimeout disconnects idle sessions after this duration.
	SessionIdleTimeout time.Duration `json:"session_idle_timeout"`

	// BannerMsg is sent to clients after authentication.
	BannerMsg string `json:"banner_msg"`

	// MySQLDSN is the MySQL data source name for user persistence.
	// If empty, users are stored in memory (lost on restart).
	MySQLDSN string `json:"mysql_dsn,omitempty"`
}

// DefaultConfig returns a sensible default BastionConfig for development.
func DefaultConfig() *BastionConfig {
	return &BastionConfig{
		SSHListenAddr:      ":2222",
		APIListenAddr:      ":8081",
		HostKeyPath:        "ssh_host_key",
		RecordingDir:       "recordings",
		AuditLogPath:       "audit.log",
		DefaultUser:        "root",
		DefaultPort:        22,
		MaxSessions:        10,
		SessionIdleTimeout: 30 * time.Minute,
		BannerMsg:          "Welcome to GoWAF Bastion Host\nAuthorized access only.\n",
	}
}
