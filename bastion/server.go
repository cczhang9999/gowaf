package bastion

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"gowaf/models"
)

// SessionEvent is emitted for every notable session lifecycle event.
type SessionEvent struct {
	Type      string // "login", "logout", "command", "blocked", "resize"
	SessionID string
	Username  string
	AssetID   string
	Data      []byte
	Time      time.Time
}

// SSHServer is the bastion host SSH server.
// It accepts SSH connections, authenticates users, and proxies them
// to backend assets with full session recording and command audit.
//
// Architecture mirrors gowaf's design principles:
//   - atomic config swaps for hot reload (like gowaf's rules)
//   - structured JSON logging via slog
//   - graceful shutdown via context cancellation
//   - per-connection goroutines with proper cleanup
type SSHServer struct {
	config atomic.Pointer[BastionConfig]
	logger *slog.Logger

	sshConfig *ssh.ServerConfig

	authStore    *AuthStore
	dbAuthStore  *DatabaseAuthStore  // Option for MySQL-based user persistence (users1 table)
	dbAuthStore1 *DatabaseAuthStore1 // Option for MySQL-based user persistence (user1 table)
	assetStore   *AssetStore
	auditLogger  *AuditLogger
	auditStore   *AuditStore
	recorder     *SessionRecorder
	recordingIdx *RecordingIndex

	listener net.Listener

	// Active sessions tracking
	sessionsMu sync.Mutex
	sessions   map[string]*SessionContext

	// activeConns tracks concurrent SSH connections for MaxSessions enforcement
	activeConns atomic.Int64

	// Event channel for async audit logging
	events chan SessionEvent

	// Host key signer
	signer ssh.Signer

	// startTime for uptime reporting (set once at construction, before any goroutines)
	startTime time.Time
}

// SessionContext holds per-session state during an SSH connection.
type SessionContext struct {
	ID        string
	User      *User
	Asset     *Asset
	StartTime time.Time

	recording *SessionRecord
	logger    *AuditLogger
	audit     *AuditStore

	termWidth  int
	termHeight int
	ptyReq     *PtyRequest

	// Channel is the client SSH channel (for writing messages to the user).
	Channel ssh.Channel
}

// PtyRequest holds parsed PTY request parameters.
type PtyRequest struct {
	Term    string
	Columns int
	Rows    int
	Width   int
	Height  int
}

// NewSSHServer creates a new bastion SSH server.
func NewSSHServer(cfg *BastionConfig, log *slog.Logger) (*SSHServer, error) {
	return NewSSHServerWithDB(cfg, log, nil)
}

// NewSSHServerWithDB creates a new bastion SSH server with optional MySQL database for user persistence.
// If db is provided, users will be stored in the database; otherwise, they are stored in memory.
func NewSSHServerWithDB(cfg *BastionConfig, log *slog.Logger, db *gorm.DB) (*SSHServer, error) {
	authStore := NewAuthStore()
	assetStore := NewAssetStore()
	recorder := NewSessionRecorder(cfg.RecordingDir)
	recordingIdx := NewRecordingIndex()
	auditStore := NewAuditStore(10000)

	srv := &SSHServer{
		logger:       log,
		authStore:    authStore,
		assetStore:   assetStore,
		auditStore:   auditStore,
		recorder:     recorder,
		recordingIdx: recordingIdx,
		sessions:     make(map[string]*SessionContext),
		events:       make(chan SessionEvent, 1000),
	}
	srv.config.Store(cfg)
	srv.startTime = time.Now()

	// Initialize audit logger
	auditLogger, err := NewAuditLogger(cfg.AuditLogPath)
	if err != nil {
		log.Warn("failed to open audit log, file audit disabled", "err", err)
	} else {
		srv.auditLogger = auditLogger
	}

	// Initialize database-backed auth store if MySQL DSN is configured
	if db != nil {
		dbAuthStore, err := NewDatabaseAuthStore(db)
		if err != nil {
			return nil, fmt.Errorf("create database auth store: %w", err)
		}
		srv.dbAuthStore = dbAuthStore
		log.Info("database-backed user persistence enabled (users1 table)")

		dbAuthStore1, err := NewDatabaseAuthStore1(db)
		if err != nil {
			return nil, fmt.Errorf("create database auth store1: %w", err)
		}
		srv.dbAuthStore1 = dbAuthStore1
		log.Info("database-backed user persistence enabled (user1 table)")
	} else {
		// No database configured: Register1/AddUser/HasUser1/etc. all fall
		// back to the in-memory AuthStore. POST /api/bastion/users will
		// still return 201 but data lives only in RAM (lost on restart)
		// and no SQL is logged — this is the #1 cause of "user1 table
		// stays empty" bug reports.
		log.Warn("database not configured: bastion users stored in memory only — " +
			"data will NOT be persisted to the user1/users1 tables, and no SQL query logs will be emitted. " +
			"Pass a MySQL DSN (e.g. -mysql-dsn) to enable database persistence.")
	}

	return srv, nil
}

// SetConfig atomically updates the server configuration.
func (s *SSHServer) SetConfig(cfg *BastionConfig) {
	s.config.Store(cfg)
}

// getConfig atomically reads the current configuration.
func (s *SSHServer) getConfig() *BastionConfig {
	return s.config.Load()
}

// StartTime returns when the server was started.
func (s *SSHServer) StartTime() time.Time {
	return s.startTime
}

// SetAssets atomically updates the backend asset list.
func (s *SSHServer) SetAssets(assets []Asset) {
	s.assetStore.Set(assets)
}

// SetUsers replaces all users (used by API management).
func (s *SSHServer) SetUsers(users []*User) {
	if s.dbAuthStore != nil {
		// Upsert into users1; rows that are absent from the list are left alone
		// so a bulk load cannot silently drop users that were added elsewhere.
		for _, u := range users {
			if err := s.dbAuthStore.Register(u); err != nil {
				s.logger.Warn("failed to set user in database", "user", u.Username, "err", err)
			}
		}
		return
	}

	s.authStore.mu.Lock()
	defer s.authStore.mu.Unlock()
	s.authStore.users = make(map[string]*User, len(users))
	for _, u := range users {
		s.authStore.users[u.Username] = u
	}
}

// AddUser adds a single user.
func (s *SSHServer) AddUser(u *User) error {
	if s.dbAuthStore != nil {
		return s.dbAuthStore.Register(u)
	}
	return s.authStore.Register(u)
}

// RemoveUser removes a user.
func (s *SSHServer) RemoveUser(username string) error {
	if s.dbAuthStore != nil {
		return s.dbAuthStore.Unregister(username)
	}
	s.authStore.Unregister(username)
	return nil
}

// UpdateUser updates an existing user.
func (s *SSHServer) UpdateUser(u *User) error {
	if s.dbAuthStore != nil {
		return s.dbAuthStore.UpdateUser(u)
	}
	return s.authStore.UpdateUser(u)
}

// AddAsset adds a single asset.
func (s *SSHServer) AddAsset(a Asset) error {
	return s.assetStore.Add(a)
}

// Events returns the read-only event channel.
func (s *SSHServer) Events() <-chan SessionEvent {
	return s.events
}

// ActiveSessions returns a list of active session contexts.
func (s *SSHServer) ActiveSessions() []*SessionContext {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	result := make([]*SessionContext, 0, len(s.sessions))
	for _, sc := range s.sessions {
		result = append(result, sc)
	}
	return result
}

// AuthStore returns the in-memory authentication store.
// When a MySQL DSN is configured this store is NOT the source of truth for
// users; use GetUser/GetUserByID/ListUsers/HasUser/UpdateUser instead, which
// dispatch to the users1 table.
func (s *SSHServer) AuthStore() *AuthStore {
	return s.authStore
}

// GetUser returns a user by username.
func (s *SSHServer) GetUser(username string) (*User, bool) {
	if s.dbAuthStore != nil {
		return s.dbAuthStore.GetUser(username)
	}
	return s.authStore.GetUser(username)
}

// GetUserByID returns a user by primary key (users1.id).
func (s *SSHServer) GetUserByID(id uint) (*User, bool) {
	if s.dbAuthStore != nil {
		return s.dbAuthStore.GetUserByID(id)
	}
	return s.authStore.GetUserByID(id)
}

// UserStoreName reports where the user-management API persists users.
//
// /api/bastion/users (the console 用户管理 page) reads and writes the users1
// table — the same table SSH authentication uses — so that is the store
// reported here. The legacy /users1 endpoints still target the user1 table.
func (s *SSHServer) UserStoreName() string {
	if s.dbAuthStore != nil {
		return "mysql(" + models.UserTableName + ")"
	}
	return "memory"
}

// ListUsers returns all users from the users1 table (or memory without a DSN).
func (s *SSHServer) ListUsers() []*User {
	if s.dbAuthStore != nil {
		return s.dbAuthStore.ListUsers()
	}
	return s.authStore.ListUsers()
}

// ListUsersWithErr 与 ListUsers 相同,但把数据库错误透传给调用方,
// 便于管理 API 在数据库不可用时返回 5xx 而不是空列表。
func (s *SSHServer) ListUsersWithErr() ([]*User, error) {
	if s.dbAuthStore != nil {
		return s.dbAuthStore.ListUsersWithErr()
	}
	return s.authStore.ListUsers(), nil
}

// HasUser checks if a user exists. It reports false on database errors too,
// so write paths must use HasUserErr instead.
func (s *SSHServer) HasUser(username string) bool {
	ok, _ := s.HasUserErr(username)
	return ok
}

// HasUserErr 与 HasUser 相同,但把数据库错误透传给调用方。
// 创建用户/初始化管理员等写路径必须用它:数据库不可用时返回错误,
// 而不是把「查不到」误当成「不存在」并覆盖已有用户。
func (s *SSHServer) HasUserErr(username string) (bool, error) {
	if s.dbAuthStore != nil {
		return s.dbAuthStore.HasUserErr(username)
	}
	return s.authStore.HasUser(username), nil
}

// CanAccessAsset checks if a user can access a specific asset.
func (s *SSHServer) CanAccessAsset(u *User, assetID string) bool {
	if s.dbAuthStore != nil {
		return s.dbAuthStore.CanAccessAsset(u, assetID)
	}
	return s.authStore.CanAccessAsset(u, assetID)
}

// --- User1 operations (for user1 table) ---

// Register1 adds or updates a user in the user1 table.
func (s *SSHServer) Register1(u *User) error {
	if s.dbAuthStore1 != nil {
		return s.dbAuthStore1.Register1(u)
	}
	return s.authStore.Register(u)
}

// UpdateUser1 updates an existing user in the user1 table.
func (s *SSHServer) UpdateUser1(u *User) error {
	if s.dbAuthStore1 != nil {
		return s.dbAuthStore1.UpdateUser1(u)
	}
	return s.authStore.UpdateUser(u)
}

// Unregister1 removes a user from the user1 table.
func (s *SSHServer) Unregister1(username string) error {
	if s.dbAuthStore1 != nil {
		return s.dbAuthStore1.Unregister1(username)
	}
	s.authStore.Unregister(username)
	return nil
}

// GetUser1 returns a user by username from the user1 table.
func (s *SSHServer) GetUser1(username string) (*User, bool) {
	if s.dbAuthStore1 != nil {
		return s.dbAuthStore1.GetUser1(username)
	}
	return s.authStore.GetUser(username)
}

// GetUser1ByID returns a user by primary key from the user1 table.
func (s *SSHServer) GetUser1ByID(id uint) (*User, bool) {
	if s.dbAuthStore1 != nil {
		return s.dbAuthStore1.GetUser1ByID(id)
	}
	return s.authStore.GetUserByID(id)
}

// ListUsers1 returns all users from the user1 table.
func (s *SSHServer) ListUsers1() []*User {
	if s.dbAuthStore1 != nil {
		return s.dbAuthStore1.ListUsers1()
	}
	return s.authStore.ListUsers()
}

// ListUsers1WithErr 与 ListUsers1 相同,但把数据库错误返回给调用方,
// 便于管理 API 在数据库不可用时返回 5xx 而不是空列表。
func (s *SSHServer) ListUsers1WithErr() ([]*User, error) {
	if s.dbAuthStore1 != nil {
		return s.dbAuthStore1.ListUsers1WithErr()
	}
	return s.authStore.ListUsers(), nil
}

// HasUser1 checks if a user exists in the user1 table.
func (s *SSHServer) HasUser1(username string) bool {
	if s.dbAuthStore1 != nil {
		return s.dbAuthStore1.HasUser1(username)
	}
	return s.authStore.HasUser(username)
}

// CanAccessAsset1 checks if a user can access a specific asset in the user1 table.
func (s *SSHServer) CanAccessAsset1(u *User, assetID string) bool {
	if s.dbAuthStore1 != nil {
		return s.dbAuthStore1.CanAccessAsset1(u, assetID)
	}
	return s.authStore.CanAccessAsset(u, assetID)
}

// AssetStore returns the asset store.
func (s *SSHServer) AssetStore() *AssetStore {
	return s.assetStore
}

// AuditStore returns the audit event store.
func (s *SSHServer) AuditStore() *AuditStore {
	return s.auditStore
}

// RecordingIndex returns the recording index.
func (s *SSHServer) RecordingIndex() *RecordingIndex {
	return s.recordingIdx
}

// Start starts the SSH server and blocks until the listener errors or context is cancelled.
func (s *SSHServer) Start(ctx context.Context) error {
	// Load or generate host key
	hostKeyPath := s.getConfig().HostKeyPath
	signer, err := loadHostKey(hostKeyPath)
	if err != nil {
		s.logger.Warn("failed to load host key, generating new key", "err", err)
		signer, err = generateHostKey()
		if err != nil {
			return fmt.Errorf("generate host key: %w", err)
		}
		// Persist the generated key so clients don't see key mismatch on next restart
		if persistErr := saveHostKey(hostKeyPath, signer); persistErr != nil {
			s.logger.Warn("failed to persist host key (will be ephemeral)", "err", persistErr)
		} else {
			s.logger.Info("host key saved", "path", hostKeyPath)
		}
	}
	s.signer = signer

	sshConfig := &ssh.ServerConfig{
		NoClientAuth: false,
		BannerCallback: func(conn ssh.ConnMetadata) string {
			return s.getConfig().BannerMsg
		},
	}
	sshConfig.AddHostKey(signer)
	sshConfig.PasswordCallback = s.passwordCallback
	sshConfig.PublicKeyCallback = s.publicKeyCallback

	s.sshConfig = sshConfig

	// Start event processing loop
	go s.processEvents()

	// Start the listener
	cfg := s.getConfig()
	s.logger.Info("bastion SSH server starting", "addr", cfg.SSHListenAddr)
	listener, err := net.Listen("tcp", cfg.SSHListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.SSHListenAddr, err)
	}
	s.listener = listener

	// Accept connections in background
	go s.acceptLoop(ctx)

	// Wait for shutdown
	<-ctx.Done()
	s.logger.Info("bastion SSH server shutting down")
	listener.Close()

	if s.auditLogger != nil {
		s.auditLogger.Close()
	}
	return nil
}

// passwordCallback authenticates users via SSH password auth.
func (s *SSHServer) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	username := conn.User()

	// Use database-backed auth store if available
	var user *User
	var err error
	if s.dbAuthStore != nil {
		user, err = s.dbAuthStore.Authenticate(username, string(password))
	} else {
		user, err = s.authStore.Authenticate(username, string(password))
	}

	if err != nil {
		s.logger.Warn("password auth failed", "user", username, "client", conn.RemoteAddr().String())
		return nil, fmt.Errorf("access denied")
	}
	return &ssh.Permissions{
		Extensions: map[string]string{
			"username": user.Username,
			"role":     string(user.Role),
		},
	}, nil
}

// publicKeyCallback authenticates users via SSH public key auth.
func (s *SSHServer) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	username := conn.User()

	// Use database-backed auth store if available
	var user *User
	var err error
	if s.dbAuthStore != nil {
		user, err = s.dbAuthStore.AuthenticatePublicKey(username, key)
	} else {
		user, err = s.authStore.AuthenticatePublicKey(username, key)
	}

	if err != nil {
		s.logger.Warn("public key auth failed", "user", username, "client", conn.RemoteAddr().String())
		return nil, fmt.Errorf("access denied")
	}
	return &ssh.Permissions{
		Extensions: map[string]string{
			"username": user.Username,
			"role":     string(user.Role),
		},
	}, nil
}

// acceptLoop accepts incoming SSH connections.
func (s *SSHServer) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.logger.Error("accept error", "err", err)
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

// handleConn processes a single SSH connection.
func (s *SSHServer) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()

	// Enforce MaxSessions: increment counter, close if exceeded
	cfg := s.getConfig()
	if cfg.MaxSessions > 0 {
		if s.activeConns.Add(1) > int64(cfg.MaxSessions) {
			s.activeConns.Add(-1)
			s.logger.Warn("max sessions reached, rejecting connection",
				"client", clientAddr, "max", cfg.MaxSessions)
			conn.Close()
			return
		}
		defer s.activeConns.Add(-1)
	}

	// SSH handshake (auth happens inside)
	newConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		s.logger.Warn("ssh handshake failed", "client", clientAddr, "err", err)
		return
	}

	username := newConn.User()

	// Get user from appropriate store
	var user *User
	var ok bool
	if s.dbAuthStore != nil {
		user, ok = s.dbAuthStore.GetUser(username)
	} else {
		user, ok = s.authStore.GetUser(username)
	}

	if !ok {
		s.logger.Warn("authenticated user not in store", "username", username)
		return
	}

	s.logger.Info("ssh connection accepted", "user", username, "client", clientAddr)

	sessionID := generateSessionID()

	// Emit login event
	s.emitEvent(SessionEvent{
		Type:      "login",
		SessionID: sessionID,
		Username:  username,
		Data:      []byte(clientAddr),
		Time:      time.Now(),
	})

	// Register session
	sc := &SessionContext{
		ID:        sessionID,
		User:      user,
		StartTime: time.Now(),
		logger:    s.auditLogger,
		audit:     s.auditStore,
	}
	s.registerSession(sc)
	defer s.unregisterSession(sessionID)

	// Close the connection when context is done
	go func() {
		<-ctx.Done()
		newConn.Close()
	}()

	// Handle global requests (keepalive, etc.)
	go ssh.DiscardRequests(reqs)

	// Handle the first channel (typically a session channel).
	// chans is closed when the client disconnects without opening one
	// (e.g. a bare handshake or a port scanner); a closed channel yields a
	// nil interface, which must not reach handleSessionChannel.
	select {
	case ch, ok := <-chans:
		if !ok {
			s.logger.Info("client disconnected before opening a session channel", "user", username, "client", clientAddr)
			return
		}
		s.handleSessionChannel(ctx, ch, sc, newConn, clientAddr)
	default:
		// No channels in the first few ms; wait briefly
		select {
		case ch, ok := <-chans:
			if !ok {
				s.logger.Info("client disconnected before opening a session channel", "user", username, "client", clientAddr)
				return
			}
			s.handleSessionChannel(ctx, ch, sc, newConn, clientAddr)
		case <-time.After(5 * time.Second):
			s.logger.Warn("no session channel received, closing connection", "user", username)
		}
	}
}

// registerSession adds a session to the active set.
func (s *SSHServer) registerSession(sc *SessionContext) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	s.sessions[sc.ID] = sc
}

// unregisterSession removes a session from the active set and emits a logout event.
func (s *SSHServer) unregisterSession(id string) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	delete(s.sessions, id)

	s.emitEvent(SessionEvent{
		Type:      "logout",
		SessionID: id,
		Time:      time.Now(),
	})
}

// handleSessionChannel processes a session channel from the authenticated connection.
func (s *SSHServer) handleSessionChannel(ctx context.Context, ch ssh.NewChannel, sc *SessionContext, conn *ssh.ServerConn, clientAddr string) {
	if ch == nil || sc == nil {
		// The client went away before offering a channel.
		return
	}
	if ch.ChannelType() != "session" {
		ch.Reject(ssh.UnknownChannelType, "unknown channel type")
		return
	}

	channel, requests, err := ch.Accept()
	if err != nil {
		s.logger.Error("failed to accept session channel", "err", err)
		return
	}
	defer channel.Close()
	sc.Channel = channel

	// Determine the target asset
	assets := s.assetStore.All()
	var accessible []Asset
	for i := range assets {
		var canAccess bool
		if s.dbAuthStore != nil {
			canAccess = s.dbAuthStore.CanAccessAsset(sc.User, assets[i].ID)
		} else {
			canAccess = s.authStore.CanAccessAsset(sc.User, assets[i].ID)
		}
		if canAccess {
			accessible = append(accessible, assets[i])
		}
	}

	if len(accessible) == 0 {
		fmt.Fprintln(channel, "No assets available for your account.")
		return
	}

	// If exactly one asset, connect directly; otherwise present menu.
	if len(accessible) == 1 {
		sc.Asset = &accessible[0]
	} else {
		selected, cancelled := s.presentAssetMenu(channel, accessible, sc.User.Username, string(sc.User.Role))
		if cancelled {
			fmt.Fprintln(channel, "Session cancelled.")
			return
		}
		sc.Asset = selected
	}

	if sc.Asset == nil {
		return
	}

	// Log the connection
	if s.auditLogger != nil {
		s.auditLogger.Log(&AuditEvent{
			Username:  sc.User.Username,
			SessionID: sc.ID,
			AssetID:   sc.Asset.ID,
			AssetName: sc.Asset.Name,
			Action:    ActionLogin,
			ClientIP:  clientAddr,
		})
	}
	s.auditStore.Append(AuditEvent{
		Username:  sc.User.Username,
		SessionID: sc.ID,
		AssetID:   sc.Asset.ID,
		AssetName: sc.Asset.Name,
		Action:    ActionLogin,
		ClientIP:  clientAddr,
	})

	// Start session recording
	rec, recErr := s.recorder.StartSession(sc.ID, sc.User.Username, sc.Asset.ID, sc.Asset.Name)
	if recErr != nil {
		s.logger.Error("failed to start recording", "err", recErr, "session", sc.ID)
	}
	sc.recording = rec
	if rec != nil {
		s.recordingIdx.Register(rec)
	}

	// Start the SSH proxy session (handles PTY, resize, and I/O proxying)
	s.handleProxySession(ctx, sc, channel, requests, clientAddr)

	// Clean up recording
	if rec != nil {
		rec.Stop()
	}
}

// presentAssetMenu shows an interactive menu and returns the selected asset.
func (s *SSHServer) presentAssetMenu(channel ssh.Channel, assets []Asset, username string, role string) (*Asset, bool) {
	fmt.Fprintln(channel, "=== Bastion Host - Asset Menu ===")
	fmt.Fprintf(channel, "Welcome, %s (role: %s)\n", username, role)
	fmt.Fprintln(channel)
	fmt.Fprintln(channel, "Available assets:")
	for i, a := range assets {
		port := a.Port
		if port == 0 {
			port = s.getConfig().DefaultPort
		}
		fmt.Fprintf(channel, "  [%d] %s (%s:%d)\n", i+1, a.Name, a.Hostname, port)
	}
	fmt.Fprintln(channel)
	fmt.Fprintln(channel, "Enter selection number (or 'q' to quit): ")

	// Read user input
	buf := make([]byte, 256)
	n, err := channel.Read(buf)
	if err != nil {
		return nil, false
	}
	input := strings.TrimSpace(string(buf[:n]))
	if input == "q" || input == "quit" {
		return nil, true
	}

	idx, err := strconv.Atoi(input)
	if err != nil || idx < 1 || idx > len(assets) {
		fmt.Fprintln(channel, "Invalid selection.")
		return nil, true
	}

	return &assets[idx-1], false
}

// handleProxySession establishes a connection to the target asset and
// proxies all I/O between the user and the target, with session recording
// and command audit.
func (s *SSHServer) handleProxySession(ctx context.Context, sc *SessionContext, channel ssh.Channel, requests <-chan *ssh.Request, clientAddr string) {
	asset := sc.Asset
	if asset == nil {
		return
	}

	// Prepare proxy config
	signer, signerErr := s.assetSigner(asset)
	proxyCfg := &ProxyConfig{
		TargetAddr: fmt.Sprintf("%s:%d", asset.Hostname, assetPort(*asset)),
		Username:   assetUsername(*asset, sc, s),
		Password:   asset.Password,
		PrivateKey: signer,
		Logger:     s.logger,
	}
	if signerErr != nil {
		s.logger.Warn("failed to load asset private key", "asset", asset.ID, "err", signerErr)
	}

	proxy := NewSSHProxy(proxyCfg)

	// Connect to backend
	sshConn, err := proxy.Connect(ctx)
	if err != nil {
		msg := fmt.Sprintf("Failed to connect to %s: %v\n", asset.Name, err)
		channel.Write([]byte(msg))
		if sc.recording != nil {
			sc.recording.RecordOutput([]byte(msg), time.Since(sc.StartTime))
		}
		return
	}
	defer sshConn.Close()

	s.logger.Info("proxy connected", "user", sc.User.Username, "asset", asset.Name, "target", proxyCfg.TargetAddr)

	// Create session on target
	session, err := proxy.CreateSession(ctx, sshConn)
	if err != nil {
		msg := fmt.Sprintf("Failed to create session: %v\n", err)
		channel.Write([]byte(msg))
		return
	}
	defer session.Close()

	// PTY setup
	termWidth, termHeight := 80, 24
	termType := "xterm-256color"
	modes := ssh.TerminalModes{}
	if sc.ptyReq != nil {
		termType = sc.ptyReq.Term
		termWidth = sc.ptyReq.Columns
		termHeight = sc.ptyReq.Rows
		if termWidth == 0 {
			termWidth = 80
		}
		if termHeight == 0 {
			termHeight = 24
		}
	}

	err = session.RequestPty(termType, termHeight, termWidth, modes)
	if err != nil {
		s.logger.Warn("failed to request PTY on target", "err", err)
	}

	// Set up pipes
	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()

	// Start shell on target
	err = session.Start("/bin/bash")
	if err != nil {
		err = session.Start("/bin/sh")
		if err != nil {
			msg := fmt.Sprintf("Failed to start shell: %v\n", err)
			channel.Write([]byte(msg))
			return
		}
	}

	// Start I/O proxying with recording and audit
	cmdScanner := newCommandScanner()
	done := make(chan struct{})

	// User -> Target (stdin)
	go func() {
		defer func() {
			stdin.Close()
		}()
		for {
			buf := make([]byte, 4096)
			n, err := channel.Read(buf)
			if n > 0 {
				data := buf[:n]
				if sc.recording != nil {
					sc.recording.RecordInput(data, time.Since(sc.StartTime))
				}
				cmdScanner.Feed(data, sc, s)
				stdin.Write(data)
			}
			if err != nil {
				break
			}
		}
	}()

	// Target -> User (stdout)
	go func() {
		for {
			buf := make([]byte, 4096)
			n, err := stdout.Read(buf)
			if n > 0 {
				data := buf[:n]
				if sc.recording != nil {
					sc.recording.RecordOutput(data, time.Since(sc.StartTime))
				}
				channel.Write(data)
			}
			if err != nil {
				break
			}
		}
	}()

	// Target -> User (stderr)
	go func() {
		for {
			buf := make([]byte, 4096)
			n, err := stderr.Read(buf)
			if n > 0 {
				channel.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}()

	// Wait for session to complete
	go func() {
		session.Wait()
		close(done)
	}()

	// Handle PTY and resize requests from the client
	go func() {
		for req := range requests {
			switch req.Type {
			case "pty-req":
				ptyReq := parsePtyRequest(req.Payload)
				if ptyReq != nil {
					sc.ptyReq = ptyReq
					if ptyReq.Columns > 0 && ptyReq.Rows > 0 {
						session.WindowChange(ptyReq.Rows, ptyReq.Columns)
					}
				}
				req.Reply(true, nil)
			case "window-change":
				w, h := decodeTerminalSize(req.Payload)
				sc.termWidth = w
				sc.termHeight = h
				session.WindowChange(h, w)
				req.Reply(true, nil)
			default:
				req.Reply(false, nil)
			}
		}
	}()

	// Wait for session to end (or context cancellation)
	select {
	case <-done:
	case <-ctx.Done():
		session.Signal(ssh.SIGKILL)
	}
}

// assetSigner loads the SSH signer for an asset's private key (if configured).
func (s *SSHServer) assetSigner(a *Asset) (ssh.Signer, error) {
	if a.PrivateKeyFile != "" {
		return parsePrivateKeyFile(a.PrivateKeyFile)
	}
	if a.PrivateKey != "" {
		return parsePrivateKey([]byte(a.PrivateKey))
	}
	return nil, fmt.Errorf("no private key configured for asset %q", a.ID)
}

// --- Event handling ---

func (s *SSHServer) emitEvent(e SessionEvent) {
	select {
	case s.events <- e:
	default:
		s.logger.Warn("event channel full, dropping event", "type", e.Type)
	}
}

func (s *SSHServer) processEvents() {
	for ev := range s.events {
		if s.auditLogger != nil {
			s.auditLogger.Log(&AuditEvent{
				Username:  ev.Username,
				SessionID: ev.SessionID,
				AssetID:   ev.AssetID,
				Action:    CommandAction(ev.Type),
				RawInput:  string(ev.Data),
			})
		}
	}
}

// --- Helpers ---

// parsePtyRequest parses an SSH "pty-req" request payload.
func parsePtyRequest(payload []byte) *PtyRequest {
	if len(payload) < 6 {
		return nil
	}
	termLen := int(payload[0])<<8 | int(payload[1])
	if 2+termLen+1 > len(payload) {
		return nil
	}
	term := string(payload[2 : 2+termLen])
	rest := payload[2+termLen:]
	if len(rest) < 16 {
		return &PtyRequest{Term: term}
	}
	width := int(rest[0])<<24 | int(rest[1])<<16 | int(rest[2])<<8 | int(rest[3])
	height := int(rest[4])<<24 | int(rest[5])<<16 | int(rest[6])<<8 | int(rest[7])
	return &PtyRequest{
		Term:    term,
		Columns: width,
		Rows:    height,
	}
}

// assetPort returns the effective port for an asset.
func assetPort(a Asset) int {
	if a.Port > 0 {
		return a.Port
	}
	return 22
}

// assetUsername returns the username for connecting to an asset.
func assetUsername(a Asset, sc *SessionContext, s *SSHServer) string {
	if a.Username != "" {
		return a.Username
	}
	return s.getConfig().DefaultUser
}

// generateSessionID generates a unique session identifier.
func generateSessionID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "sess-" + hex.EncodeToString(b)
}

// loadHostKey loads an SSH host key from a PEM file.
func loadHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

// generateHostKey generates a new ephemeral Ed25519 host key.
func generateHostKey() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return ssh.NewSignerFromKey(priv)
}

// saveHostKey persists an SSH signer's private key to path in PEM format.
func saveHostKey(path string, signer ssh.Signer) error {
	// Extract the underlying private key from the signer.
	// ssh.Signer doesn't expose the key directly, so we re-derive it.
	type keyer interface {
		PrivateKey() interface{}
	}
	if k, ok := signer.(keyer); ok {
		der, err := x509.MarshalPKCS8PrivateKey(k.PrivateKey())
		if err != nil {
			return fmt.Errorf("marshal host key: %w", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		})
		return os.WriteFile(path, pemBytes, 0600)
	}
	return fmt.Errorf("signer does not expose private key for persistence")
}

// indexByte is a simple byte search helper.
func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

// --- Command scanner for command audit ---

// commandScanner buffers stdin and extracts complete command lines (terminated by newline).
type commandScanner struct {
	buf []byte
}

func newCommandScanner() *commandScanner {
	return &commandScanner{}
}

// Feed feeds data into the scanner and processes any complete command lines.
func (cs *commandScanner) Feed(data []byte, sc *SessionContext, s *SSHServer) {
	cs.buf = append(cs.buf, data...)
	for {
		idx := indexByte(cs.buf, '\n')
		if idx < 0 {
			break
		}
		line := strings.TrimSpace(string(cs.buf[:idx]))
		cs.buf = cs.buf[idx+1:]
		if line == "" {
			continue
		}
		cmd := ParseCommand(line)
		if cmd == "" {
			continue
		}
		// Check against banned commands
		if bc, blocked := s.auditStore.CheckCommand(cmd); blocked {
			s.emitEvent(SessionEvent{
				Type:      "blocked",
				SessionID: sc.ID,
				Username:  sc.User.Username,
				Data:      []byte(cmd),
			})
			if s.auditLogger != nil {
				s.auditLogger.Log(&AuditEvent{
					Username:  sc.User.Username,
					SessionID: sc.ID,
					AssetID:   sc.Asset.ID,
					Action:    ActionBlocked,
					Command:   cmd,
					Blocked:   true,
					RuleID:    bc.ID,
					ClientIP:  "",
				})
			}
			// Notify user
			msg := fmt.Sprintf("[BLOCKED] Command '%s' is not allowed: %s\n", cmd, bc.Reason)
			if sc.recording != nil {
				sc.recording.RecordOutput([]byte(msg), time.Since(sc.StartTime))
			}
			if sc.Channel != nil {
				sc.Channel.Write([]byte(msg))
			}
		} else {
			s.emitEvent(SessionEvent{
				Type:      "command",
				SessionID: sc.ID,
				Username:  sc.User.Username,
				Data:      []byte(cmd),
			})
			if s.auditLogger != nil {
				s.auditLogger.Log(&AuditEvent{
					Username:  sc.User.Username,
					SessionID: sc.ID,
					AssetID:   sc.Asset.ID,
					Action:    ActionCommand,
					Command:   cmd,
				})
			}
		}
	}
}
