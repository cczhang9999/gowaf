package bastion

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
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
	config *BastionConfig
	logger *slog.Logger

	sshConfig *ssh.ServerConfig

	authStore     *AuthStore
	dbAuthStore   *DatabaseAuthStore   // Option for MySQL-based user persistence (users1 table)
	dbAuthStore1  *DatabaseAuthStore1  // Option for MySQL-based user persistence (user1 table)
	assetStore    *AssetStore
	auditLogger   *AuditLogger
	auditStore    *AuditStore
	recorder      *SessionRecorder
	recordingIdx  *RecordingIndex

	listener net.Listener

	// Active sessions tracking
	sessionsMu sync.Mutex
	sessions   map[string]*SessionContext

	// Event channel for async audit logging
	events chan SessionEvent

	// Host key signer
	signer ssh.Signer
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
		config:       cfg,
		logger:       log,
		authStore:    authStore,
		assetStore:   assetStore,
		auditStore:   auditStore,
		recorder:     recorder,
		recordingIdx: recordingIdx,
		sessions:     make(map[string]*SessionContext),
		events:       make(chan SessionEvent, 1000),
	}

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
	}

	return srv, nil
}

// SetConfig atomically updates the server configuration.
func (s *SSHServer) SetConfig(cfg *BastionConfig) {
	s.config = cfg
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

// UserStoreName reports where users are persisted, e.g. "mysql(users1)".
func (s *SSHServer) UserStoreName() string {
	if s.dbAuthStore != nil {
		return "mysql(users1)"
	}
	return "memory"
}

// ListUsers returns all users.
func (s *SSHServer) ListUsers() []*User {
	if s.dbAuthStore != nil {
		return s.dbAuthStore.ListUsers()
	}
	return s.authStore.ListUsers()
}

// HasUser checks if a user exists.
func (s *SSHServer) HasUser(username string) bool {
	if s.dbAuthStore != nil {
		return s.dbAuthStore.HasUser(username)
	}
	return s.authStore.HasUser(username)
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
	signer, err := loadHostKey(s.config.HostKeyPath)
	if err != nil {
		s.logger.Warn("failed to load host key, generating ephemeral key", "err", err)
		signer, err = generateHostKey()
		if err != nil {
			return fmt.Errorf("generate host key: %w", err)
		}
		s.logger.Warn("ephemeral host key generated - clients will see key mismatch warnings")
	}
	s.signer = signer

	sshConfig := &ssh.ServerConfig{
		NoClientAuth: false,
		BannerCallback: func(conn ssh.ConnMetadata) string {
			return s.config.BannerMsg
		},
	}
	sshConfig.AddHostKey(signer)
	sshConfig.PasswordCallback = s.passwordCallback
	sshConfig.PublicKeyCallback = s.publicKeyCallback

	s.sshConfig = sshConfig

	// Start event processing loop
	go s.processEvents()

	// Start the listener
	s.logger.Info("bastion SSH server starting", "addr", s.config.SSHListenAddr)
	listener, err := net.Listen("tcp", s.config.SSHListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.config.SSHListenAddr, err)
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
			port = s.config.DefaultPort
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
	return s.config.DefaultUser
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
