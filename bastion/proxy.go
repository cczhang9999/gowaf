package bastion

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// ProxyConfig holds configuration for connecting to a backend SSH server.
type ProxyConfig struct {
	// TargetAddr is the "host:port" of the backend SSH server.
	TargetAddr string
	// Username is the SSH user for the backend connection.
	Username string
	// Password is the SSH password (optional; use with key auth).
	Password string
	// PrivateKey is the SSH signer for key-based auth (optional; use with password).
	PrivateKey ssh.Signer
	// Logger for proxy operations.
	Logger *slog.Logger
	// Timeout for the connection attempt.
	Timeout time.Duration
}

// SSHProxy is a simple SSH client wrapper for proxying connections to backend hosts.
type SSHProxy struct {
	cfg *ProxyConfig
}

// NewSSHProxy creates a new SSH proxy from the given configuration.
func NewSSHProxy(cfg *ProxyConfig) *SSHProxy {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &SSHProxy{cfg: cfg}
}

// Connect establishes an SSH connection to the backend server.
func (p *SSHProxy) Connect(ctx context.Context) (*ssh.Client, error) {
	authMethods := make([]ssh.AuthMethod, 0, 2)

	if p.cfg.Password != "" {
		authMethods = append(authMethods, ssh.Password(p.cfg.Password))
	}
	if p.cfg.PrivateKey != nil {
		authMethods = append(authMethods, ssh.PublicKeys(p.cfg.PrivateKey))
	}
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no authentication method configured (need password or private key)")
	}

	sshCfg := &ssh.ClientConfig{
		User:            p.cfg.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // NOTE: in production, verify host keys
		Timeout:         p.cfg.Timeout,
	}

	d := net.Dialer{Timeout: p.cfg.Timeout}
	conn, err := d.DialContext(ctx, "tcp", p.cfg.TargetAddr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", p.cfg.TargetAddr, err)
	}

	// ssh.NewClientConn returns (conn, chans, reqs, err)
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, p.cfg.TargetAddr, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh handshake with %s: %w", p.cfg.TargetAddr, err)
	}

	client := ssh.NewClient(sshConn, chans, reqs)
	p.cfg.Logger.Info("ssh proxy connected", "target", p.cfg.TargetAddr, "user", p.cfg.Username)
	return client, nil
}

// CreateSession creates a new session on the given SSH client.
func (p *SSHProxy) CreateSession(ctx context.Context, client *ssh.Client) (*ssh.Session, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return session, nil
}

// CloseClient cleanly closes an SSH client connection.
func (p *SSHProxy) CloseClient(client *ssh.Client) {
	if client != nil {
		client.Close()
	}
}

// --- ProxyConfig builder helpers ---

// NewProxyConfigFromAsset creates a ProxyConfig from an Asset and server config.
func NewProxyConfigFromAsset(s *SSHServer, a Asset) (*ProxyConfig, error) {
	var signer ssh.Signer
	if a.PrivateKeyFile != "" {
		signer, _ = parsePrivateKeyFile(a.PrivateKeyFile)
	} else if a.PrivateKey != "" {
		signer, _ = parsePrivateKey([]byte(a.PrivateKey))
	}

	return &ProxyConfig{
		TargetAddr: fmt.Sprintf("%s:%d", a.Hostname, assetPort(a)),
		Username:   assetUsername(a, &SessionContext{}, s),
		Password:   a.Password,
		PrivateKey: signer,
		Logger:     s.logger,
		Timeout:    10 * time.Second,
	}, nil
}
