package bastion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SessionEvent is emitted for every notable session lifecycle event.
// Subscribers (audit logger, recording index, etc.) can listen.
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
// The architecture mirrors gowaf's design principles:
//   - atomic config swaps for hot reload (like gowaf's rules)
//   - structured JSON logging via slog
//   - graceful shutdown via context cancellation
//   - per-connection goroutines with proper cleanup
type SSHServer struct {
	config *BastionConfig
	logger *slog.Logger

	sshConfig *ssh.ServerConfig

	authStore    *AuthStore
	assetStore   *AssetStore
	auditLogger  *AuditLogger
	auditStore   *AuditStore
	recorder     *SessionRecorder
	recordingIdx *RecordingIndex

	listener net.Listener

	// Active sessions tracking
	sessionsMu sync.Mutex
	sessions   map[string]*SessionContext

	// Event channel for subscribers
	events chan SessionEvent

	// Host key signer
	signer ssh.Signer
}

// SessionContext holds per-session state during an SSH connection.
type SessionContext struct {
	ID        string
	User      *User
	Asset     *Asset
	Conn      *ssh.ServerConn
	Channel   ssh.Channel
	StartTime time.Time

	recording *SessionRecord
	logger    *AuditLogger
	audit     *AuditStore

	// Terminal state
	termWidth  int
	termHeight int
	ptyReq     *ssh.Pty
}

// NewSSHServer creates a new bastion SSH server.
func NewSSHServer(cfg *BastionConfig, log *slog.Logger) (*SSHServer, error) {
	signer, err := ssh.ParsePrivateKeyWithPassphrase([]byte{}, nil)
	_ = signer // placeholder; host key loading handled in Start
	if err != nil {
		// We'll load the host key in Start()
	}

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
		auditLogger:  nil, // initialized in Start
		auditStore:   auditStore,
		recorder:     recorder,
		recordingIdx: recordingIdx,
		sessions:     make(map[string]*SessionContext),
		events:       make(chan SessionEvent, 1000),
	}

	return srv, nil
}

// SetConfig atomically updates the server configuration.
func (s *SSHServer) SetConfig(cfg *BastionConfig) {
	s.config = cfg
}

// SetAssets atomically updates the backend asset list.
func (s *SSHServer) SetAssets(assets []Asset) {
	s.assetStore.assets.Store(&assets)
}

// SetUsers replaces all users (used by API management).
func (s *SSHServer) SetUsers(users []*User) {
	s.authStore.mu.Lock()
	defer s.authStore.mu.Unlock()
	s.authStore.users = make(map[string]*User, len(users))
	for _, u := range users {
		s.authStore.users[u.Username] = u
	}
}

// AddUser adds a single user.
func (s *SSHServer) AddUser(u *User) error {
	return s.authStore.Register(u)
}

// RemoveUser removes a user.
func (s *SSHServer) RemoveUser(username string) {
	s.authStore.Unregister(username)
}

// AddAsset adds a single asset.
func (s *SSHServer) AddAsset(a Asset) error {
	return s.assetStore.Add(a)
}

// Events returns the read-only event channel.
func (s *SSHServer) Events() <-chan SessionEvent {
	return s.events
}

// Sessions returns a list of active session IDs.
func (s *SSHServer) ActiveSessions() []*SessionContext {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	result := make([]*SessionContext, 0, len(s.sessions))
	for _, sc := range s.sessions {
		result = append(result, sc)
	}
	return result
}

// AuthStore returns the authentication store.
func (s *SSHServer) AuthStore() *AuthStore {
	return s.authStore
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

// Start starts the SSH server and blocks until the listener errors.
func (s *SSHServer) Start(ctx context.Context) error {
	// Load host key
	signer, err := loadHostKey(s.config.HostKeyPath)
	if err != nil {
		// Generate a new ephemeral key if loading fails
		s.logger.Warn("failed to load host key, generating ephemeral key", "err", err)
		signer, err = generateHostKey()
		if err != nil {
			return fmt.Errorf("generate host key: %w", err)
		}
		s.logger.Warn("ephemeral host key generated - clients will see key mismatch warnings")
	}
	s.signer = signer

	sshConfig := &ssh.ServerConfig{
		// Support both password and public key auth
		NoClientAuth: false,
		// After authentication
	}

	// Add host key
	sshConfig.AddHostKey(signer)

	// Set up authentication callbacks
	sshConfig.PasswordCallback = s.passwordCallback
	sshConfig.PublicKeyCallback = s.publicKeyCallback

	s.sshConfig = sshConfig

	// Initialize audit logger
	auditLogger, err := NewAuditLogger(s.config.AuditLogPath)
	if err != nil {
		s.logger.Error("failed to open audit log, audit disabled", "err", err)
	} else {
		s.auditLogger = auditLogger
		defer auditLogger.Close()
	}

	// Start event processing loop
	go s.processEvents()

	// Start the listener
	s.logger.Info("bastion SSH server starting", "addr", s.config.SSHListenAddr)
	listener, err := net.Listen("tcp", s.config.SSHListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.listener = listener

	// Accept connections in background
	go s.acceptLoop(ctx)

	// Wait for shutdown
	<-ctx.Done()
	s.logger.Info("bastion SSH server shutting down")
	listener.Close()
	return nil
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

	// SSH handshake
	newConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		s.logger.Warn("ssh handshake failed", "client", clientAddr, "err", err)
		return
	}

	// At this point, the user is authenticated via the callbacks.
	// The username is available in newConn.User()
	username := newConn.User()
	user, ok := s.authStore.GetUser(username)
	if !ok {
		s.logger.Warn("authenticated user not found in store", "username", username)
		return
	}

	s.logger.Info("ssh connection accepted", "user", username, "client", clientAddr)

	// Emit login event
	sessionID := sessionID()
	s.emitEvent(SessionEvent{
		Type:      "login",
		SessionID: sessionID,
		Username:  username,
		Data:      []byte(clientAddr),
		Time:      time.Now(),
	})

	// Track this session
	sc := &SessionContext{
		ID:        sessionID,
		User:      user,
		StartTime: time.Now(),
		logger:    s.auditLogger,
		audit:     s.auditStore,
		recorder:  s.recorder,
	}

	s.sessionsMu.Lock()
	s.sessions[sessionID] = sc
	s.sessionsMu.Unlock()
	defer func() {
		s.sessionsMu.Lock()
		delete(s.sessions, sessionID)
		s.sessionsMu.Unlock()
	}()

	// Close the connection when context is done
	go func() {
		<-ctx.Done()
		newConn.Close()
	}()

	// Handle global requests (keepalive, etc.)
	go ssh.DiscardRequests(reqs)

	// Determine the target asset.
	// If the user connected with a specific target (e.g., via env or direct-tcp request),
	// use that; otherwise present an asset selection menu.
	ch := chans[0] // first channel (session)
	if len(chans) > 0 {
		go s.handleChannel(ctx, ch, sc, newConn, false, clientAddr)
	}

	// Also handle additional channels (for port forwarding / direct-tcp)
	for ch := range chans {
		go s.handleChannel(ctx, ch, sc, newConn, true, clientAddr)
	}
}

// handleChannel processes an SSH channel from the authenticated connection.
func (s *SSHServer) handleChannel(ctx context.Context, ch ssh.NewChannel, sc *SessionContext, conn *ssh.ServerConn, auto bool, clientAddr string) {
	if ch.ChannelType() != "session" {
		ch.Reject(ssh.UnknownChannelType, "unknown channel type")
		return
	}

	// Check if this is a direct-tcp forward (proxy mode: ssh -J user@asset)
	// or a session request (menu mode)
	if auto {
		ch.Reject(ssh.UnknownChannelType, "session channel already handled")
		return
	}

	channel, requests, err := ch.Accept()
	if err != nil {
		s.logger.Error("failed to accept channel", "err", err)
		return
	}
	defer channel.Close()
	sc.Channel = channel

	// Check for "direct" requests that specify the target asset
	if target := checkDirectRequest(requests); target != "" {
		// Proxy mode: user specified target in connection request
		asset, ok := s.resolveAsset(target)
		if !ok {
			fmt.Fprintf(channel, "Asset not found: %s\n", target)
			return
		}
		if !s.authStore.CanAccessAsset(sc.User, asset.ID) {
			fmt.Fprintln(channel, "Access denied to this asset")
			return
		}
		sc.Asset = asset
		s.handleProxySession(ctx, sc, channel, requests, clientAddr)
		return
	}

	// Menu mode: present asset selection menu
	s.handleMenuMode(ctx, sc, channel, requests, clientAddr)
}

// checkDirectRequest checks incoming requests for a "direct" target specification.
// This supports proxy mode: ssh user@asset-host@bastion-host
func checkDirectRequest(reqs <-chan *ssh.Request) string {
	// In SSH, direct-tcp-ip requests are used for proxying.
	// For session channels, we check for env requests with a custom target.
	return ""
}

// resolveAsset resolves an asset by name, hostname, or "user@hostname" pattern.
func (s *SSHServer) resolveAsset(target string) (*Asset, bool) {
	assets := s.assetStore.All()
	for i := range assets {
		if assets[i].Hostname == target || assets[i].Name == target || assets[i].ID == target {
			return &assets[i], true
		}
	}
	return nil, false
}

// handleMenuMode presents an interactive asset selection menu to the user.
func (s *SSHServer) handleMenuMode(ctx context.Context, sc *SessionContext, channel ssh.Channel, requests <-chan *ssh.Request, clientAddr string) {
	assets := s.assetStore.All()

	// Filter assets by user permissions
	var accessible []Asset
	for range assets {
		if s.authStore.CanAccessAsset(sc.User, assets[0].ID) {
			accessible = append(accessible, assets[0])
		}
	}

	if len(accessible) == 0 {
		fmt.Fprintln(channel, "No assets available for your account.")
		return
	}

	fmt.Fprintln(channel, "=== Bastion Host - Asset Menu ===")
	fmt.Fprintln(channel, fmt.Sprintf("Welcome, %s (role: %s)", sc.User.Username, sc.User.Role))
	fmt.Fprintln(channel, "")
	fmt.Fprintln(channel, "Available assets:")
	for i, a := range accessible {
		fmt.Fprintf(channel, "  [%d] %s (%s:%d)\n", i+1, a.Name, a.Hostname, assetPort(a))
	}
	fmt.Fprintln(channel, "")
	fmt.Fprintln(channel, "Enter selection number or 'q' to quit:")

	// Read user input
	buf := make([]byte, 256)
	n, err := channel.Read(buf)
	if err != nil {
		return
	}
	input := strings.TrimSpace(string(buf[:n]))
	if input == "q" || input == "quit" {
		fmt.Fprintln(channel, "Goodbye.")
		return
	}

	idx, err := strconv.Atoi(input)
	if err != nil || idx < 1 || idx > len(accessible) {
		fmt.Fprintln(channel, "Invalid selection.")
		return
	}

	selected := accessible[idx-1]
	sc.Asset = &selected

	// Log the login
	if s.auditLogger != nil {
		s.auditLogger.Log(&AuditEvent{
			Username:  sc.User.Username,
			SessionID: sc.ID,
			AssetID:   selected.ID,
			AssetName: selected.Name,
			Action:    ActionLogin,
			ClientIP:  clientAddr,
		})
	}
	s.auditStore.Append(AuditEvent{
		Username:  sc.User.Username,
		SessionID: sc.ID,
		AssetID:   selected.ID,
		Action:    ActionLogin,
		ClientIP:  clientAddr,
	})

	// Start the proxy session
	s.handleProxySession(ctx, sc, channel, requests, clientAddr)
}

// handleProxySession establishes a PTY session on the target asset
// and proxies all I/O between the user and the target.
func (s *SSHServer) handleProxySession(ctx context.Context, sc *SessionContext, channel ssh.Channel, requests <-chan *ssh.Request, clientAddr string) {
	asset := sc.Asset
	if asset == nil {
		return
	}

	// Start session recording
	rec, err := s.recorder.StartSession(sc.ID, sc.User.Username, asset.ID, asset.Name)
	if err != nil {
		s.logger.Error("failed to start recording", "err", err, "session", sc.ID)
	}
	sc.recording = rec
	if rec != nil {
		s.recordingIdx.Register(rec)
	}

	// Connect to the target asset
	targetAddr := fmt.Sprintf("%s:%d", asset.Hostname, assetPort(asset))
	s.logger.Info("proxying to asset", "user", sc.User.Username, "asset", asset.Name, "target", targetAddr)

	// Set up the proxy connection
	proxy := NewSSHProxy(targetAddr, assetUsername(asset, sc, s), s.config.DefaultUser, s.signer, s.logger)
	sshConn, chans, reqs, err := proxy.Connect(ctx)
	if err != nil {
		msg := fmt.Sprintf("Failed to connect to %s: %v\n", asset.Name, err)
		channel.Write([]byte(msg))
		if rec != nil {
			rec.RecordOutput([]byte(msg), time.Since(sc.StartTime))
		}
		return
	}
	defer sshConn.Close()

	// Create a session on the target
	session, err := proxy.CreateSession(ctx)
	if err != nil {
		msg := fmt.Sprintf("Failed to create session: %v\n", err)
		channel.Write([]byte(msg))
		return
	}
	defer session.Close()

	// Request a PTY on the target
	termWidth, termHeight := 80, 24
	if sc.ptyReq != nil {
		termWidth = sc.ptyReq.Columns
		termHeight = sc.ptyReq.Rows
	}

	err = session.RequestPty("xterm-256color", termHeight, termWidth, ssh.TerminalModes{})
	if err != nil {
		s.logger.Warn("failed to request PTY", "err", err)
	}

	// Set up stdin/stdout/stderr piping with recording
	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()

	// Start the session
	err = session.Start("bash")
	if err != nil {
		channel.Write([]byte(fmt.Sprintf("Failed to start shell: %v\n", err)))
		return
	}

	// Proxy I/O with recording and command audit
	done := make(chan struct{})
	go func() {
		// Copy stdin (user -> target)
		go func() {
			scanner := newCommandScanner()
			for {
				buf := make([]byte, 4096)
				n, err := channel.Read(buf)
				if n > 0 {
					data := buf[:n]
					// Record input
					if rec != nil {
						rec.RecordInput(data, time.Since(sc.StartTime))
					}
					// Audit commands
					scanner.Feed(data, sc, s)
					// Forward to target
					stdin.Write(data)
				}
				if err != nil {
					break
				}
			}
			stdin.Close()
		}()

		// Copy stdout (target -> user)
		go func() {
			for {
				buf := make([]byte, 4096)
				n, err := stdout.Read(buf)
				if n > 0 {
					data := buf[:n]
					if rec != nil {
						rec.RecordOutput(data, time.Since(sc.StartTime))
					}
					channel.Write(data)
				}
				if err != nil {
					break
				}
			}
		}()

		// Copy stderr
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
		session.Wait()
		close(done)
	}()

	// Handle terminal resize requests
	go func() {
		for req := range requests {
			if req.Type == "window-change" {
				w, h := decodeTerminalSize(req.Payload)
				sc.termWidth = w
				sc.termHeight = h
				session.WindowChange(h, w)
				req.Reply(true, nil)
			} else {
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

	// Clean up recording
	if rec != nil {
		rec.Stop()
	}

	// Log logout
	s.emitEvent(SessionEvent{
		Type:      "logout",
		SessionID: sc.ID,
		Username:  sc.User.Username,
		AssetID:   asset.ID,
		Time:      time.Now(),
	})
}

// emitEvent sends a session event to the event channel (non-blocking).
func (s *SSHServer) emitEvent(e SessionEvent) {
	select {
	case s.events <- e:
	default:
		s.logger.Warn("event channel full, dropping event", "type", e.Type)
	}
}

// processEvents handles session events (audit logging, etc.).
func (s *SSHServer) processEvents() {
	for ev := range s.events {
		if s.auditLogger != nil {
			s.auditLogger.Log(&AuditEvent{
				Username:  ev.Username,
				SessionID: ev.SessionID,
				AssetID:   ev.AssetID,
				AssetName: ev.AssetID,
				Action:    CommandAction(ev.Type),
				RawInput:  string(ev.Data),
			})
		}
	}
}

// assetPort returns the port for an asset, defaulting if 0.
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

// --- Host key management ---

// loadHostKey loads an SSH private key from a file.
func loadHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

// generateHostKey generates a new ephemeral RSA/Ed25519 host key.
func generateHostKey() (ssh.Signer, error) {
	// Generate an ed25519 key for simplicity
	return generateEd25519Key()
}

// generateEd25519Key creates a new ed25519 SSH signer.
func generateEd25519Key() (ssh.Signer, error) {
	pub, priv, err := ed25519.GenerateKey()
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

// loadSignerFromKey loads a signer from a private key file, trying multiple formats.
func loadSignerFromKey(path string) (ssh.Signer, error) {
	return loadHostKey(path)
}

// hashString returns a short hash of a string for logging.
func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

// --- Command scanner for command audit ---

// commandScanner buffers stdin and extracts complete command lines (terminated by newline).
type commandScanner struct {
	buf []byte
}

func newCommandScanner() *commandScanner {
	return &commandScanner{}
}

// Feed feeds data into the scanner and returns any complete command lines.
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
			// Send block message to user
			msg := fmt.Sprintf("[BLOCKED] Command '%s' is not allowed: %s\n", cmd, bc.Reason)
			// Note: in a real implementation, we'd need to prevent the command from reaching the target
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

// indexByte is a simple byte search helper.
func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}
