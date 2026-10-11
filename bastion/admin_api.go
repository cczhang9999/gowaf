package bastion

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// AdminAPI provides a REST API for managing the bastion host.
// It follows the same REST patterns as gowaf's api.go:
//   - /api/bastion/users, /api/bastion/assets, /api/bastion/sessions, etc.
//   - JSON request/response
//   - Standard HTTP methods (GET, POST, PUT, DELETE)
type AdminAPI struct {
	Server *SSHServer
	Log    *slog.Logger
}

// NewAdminAPI creates a new AdminAPI.
func NewAdminAPI(srv *SSHServer, log *slog.Logger) *AdminAPI {
	return &AdminAPI{Server: srv, Log: log}
}

// Handler returns the HTTP handler for the admin API.
func (a *AdminAPI) Handler() http.Handler {
	mux := http.NewServeMux()

	// User management
	mux.HandleFunc("/users", a.handleUsers())
	mux.HandleFunc("/users/", a.handleUserByID())

	// Asset management
	mux.HandleFunc("/assets", a.handleAssets())
	mux.HandleFunc("/assets/", a.handleAssetByID())

	// Session management
	mux.HandleFunc("/sessions", a.handleSessions())
	mux.HandleFunc("/sessions/", a.handleSessionByID())

	// Audit log
	mux.HandleFunc("/audit", a.handleAudit())

	// Banned commands
	mux.HandleFunc("/banned", a.handleBannedCommands())

	// Config
	mux.HandleFunc("/config", a.handleConfig())

	// Health check
	mux.HandleFunc("/healthz", a.handleHealth)

	// Metrics
	mux.HandleFunc("/metrics", a.handleMetrics)

	return mux
}

// --- User management ---

func (a *AdminAPI) handleUsers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			a.listUsers(w, r)
		case http.MethodPost:
			a.createUser(w, r)
		case http.MethodOptions:
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (a *AdminAPI) listUsers(w http.ResponseWriter, r *http.Request) {
	users := a.Server.ListUsers()
	a.json(w, http.StatusOK, usersResponse{Users: users, Count: len(users)})
}

type usersResponse struct {
	Users []*User `json:"users"`
	Count int     `json:"count"`
}

// UserCreateRequest is the request body for creating a user.
type UserCreateRequest struct {
	Username  string   `json:"username"`
	Password  string   `json:"password"`
	PublicKey string   `json:"public_key,omitempty"`
	Role      string   `json:"role"`
	Assets    []string `json:"assets,omitempty"`
	Comment   string   `json:"comment,omitempty"`
}

func (a *AdminAPI) createUser(w http.ResponseWriter, r *http.Request) {
	var req UserCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}
	if req.Password == "" && req.PublicKey == "" {
		http.Error(w, "password or public_key required", http.StatusBadRequest)
		return
	}
	if req.Password != "" && len(req.Password) < 8 {
		http.Error(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	if req.PublicKey != "" {
		if _, err := parseSSHPublicKey(req.PublicKey); err != nil {
			http.Error(w, "invalid public_key: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	role := UserRole(req.Role)
	if role == "" {
		role = RoleUser
	} else if !validRole(role) {
		http.Error(w, "invalid role; must be admin, user or auditor", http.StatusBadRequest)
		return
	}
	if a.Server.HasUser(req.Username) {
		http.Error(w, "user already exists", http.StatusConflict)
		return
	}

	u := &User{
		Username:      req.Username,
		PasswordPlain: req.Password,
		PublicKey:     req.PublicKey,
		Role:          role,
		Assets:        req.Assets,
		Comment:       req.Comment,
		CreatedAt:     time.Now(),
	}
	if err := a.Server.AddUser(u); err != nil {
		http.Error(w, "create user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.json(w, http.StatusCreated, map[string]any{"success": true, "id": u.ID, "username": req.Username})
}

func (a *AdminAPI) handleUserByID() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/users/")
		if id == "" {
			http.Error(w, "user id required", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			a.getUser(w, r, id)
		case http.MethodPut:
			a.updateUser(w, r, id)
		case http.MethodDelete:
			a.deleteUser(w, r, id)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (a *AdminAPI) getUser(w http.ResponseWriter, r *http.Request, id string) {
	u, ok := a.resolveUser(id)
	if !ok {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	a.json(w, http.StatusOK, u)
}

// resolveUser looks a user up by username first, then by the numeric users1
// primary key, so /api/bastion/users/{id} accepts both forms.
func (a *AdminAPI) resolveUser(idOrName string) (*User, bool) {
	if u, ok := a.Server.GetUser(idOrName); ok {
		return u, true
	}
	if n, err := strconv.ParseUint(idOrName, 10, 64); err == nil {
		return a.Server.GetUserByID(uint(n))
	}
	return nil, false
}

// hashPassword hashes a password using bcrypt.
func hashPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

type UserUpdateRequest struct {
	Password  *string  `json:"password,omitempty"`
	PublicKey *string  `json:"public_key,omitempty"`
	Role      *string  `json:"role,omitempty"`
	Assets    []string `json:"assets,omitempty"`
	Comment   *string  `json:"comment,omitempty"`
}

func validRole(r UserRole) bool {
	switch r {
	case RoleAdmin, RoleUser, RoleAuditor:
		return true
	}
	return false
}

func (a *AdminAPI) updateUser(w http.ResponseWriter, r *http.Request, id string) {
	// Get existing user (by username or users1 primary key)
	actual, ok := a.resolveUser(id)
	if !ok {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	var req UserUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Update password if provided
	if req.Password != nil {
		if *req.Password == "" {
			http.Error(w, "password cannot be empty when changing it", http.StatusBadRequest)
			return
		}
		if len(*req.Password) < 8 {
			http.Error(w, "password must be at least 8 characters", http.StatusBadRequest)
			return
		}
		hash, err := hashPassword(*req.Password)
		if err != nil {
			http.Error(w, "hash password: "+err.Error(), http.StatusInternalServerError)
			return
		}
		actual.PasswordHash = hash
	}
	if req.PublicKey != nil {
		if *req.PublicKey == "" {
			// Explicitly clear the key.
			actual.PublicKey = ""
		} else if _, err := parseSSHPublicKey(*req.PublicKey); err != nil {
			http.Error(w, "invalid public_key: "+err.Error(), http.StatusBadRequest)
			return
		} else {
			actual.PublicKey = *req.PublicKey
		}
	}
	if req.Role != nil {
		if !validRole(UserRole(*req.Role)) {
			http.Error(w, "invalid role; must be admin, user or auditor", http.StatusBadRequest)
			return
		}
		actual.Role = UserRole(*req.Role)
	}
	if req.Assets != nil {
		actual.Assets = req.Assets
	}
	if req.Comment != nil {
		// Comment is a pointer so an empty string clears the field.
		actual.Comment = *req.Comment
	}

	// Save updated user
	if err := a.Server.UpdateUser(actual); err != nil {
		http.Error(w, "update user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.json(w, http.StatusOK, map[string]any{"success": true})
}

func (a *AdminAPI) deleteUser(w http.ResponseWriter, r *http.Request, id string) {
	actual, ok := a.resolveUser(id)
	if !ok {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	if err := a.Server.RemoveUser(actual.Username); err != nil {
		http.Error(w, "delete user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.json(w, http.StatusOK, map[string]any{"success": true, "username": actual.Username})
}

// --- Asset management ---

func (a *AdminAPI) handleAssets() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.enableCORS(w)
		switch r.Method {
		case http.MethodGet:
			a.listAssets(w, r)
		case http.MethodPost:
			a.createAsset(w, r)
		case http.MethodOptions:
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (a *AdminAPI) listAssets(w http.ResponseWriter, r *http.Request) {
	assets := a.Server.AssetStore().All()
	a.json(w, http.StatusOK, assetsResponse{Assets: assets, Count: len(assets)})
}

type assetsResponse struct {
	Assets []Asset `json:"assets"`
	Count  int     `json:"count"`
}

type AssetCreateRequest struct {
	Name           string `json:"name"`
	Hostname       string `json:"hostname"`
	Port           int    `json:"port,omitempty"`
	Username       string `json:"username,omitempty"`
	Password       string `json:"password,omitempty"`
	PrivateKeyFile string `json:"private_key_file,omitempty"`
	PrivateKey     string `json:"private_key,omitempty"`
	Comment        string `json:"comment,omitempty"`
}

func (a *AdminAPI) createAsset(w http.ResponseWriter, r *http.Request) {
	var req AssetCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Hostname == "" {
		http.Error(w, "hostname required", http.StatusBadRequest)
		return
	}

	id := assetID(req.Hostname, req.Port)
	if req.Port == 0 {
		req.Port = a.Server.config.DefaultPort
	}

	asset := Asset{
		ID:             id,
		Name:           req.Name,
		Hostname:       req.Hostname,
		Port:           req.Port,
		Username:       req.Username,
		Password:       req.Password,
		PrivateKeyFile: req.PrivateKeyFile,
		PrivateKey:     req.PrivateKey,
		Comment:        req.Comment,
		CreatedAt:      time.Now(),
	}

	// If no explicit ID provided via name, generate one
	if asset.Name == "" {
		asset.Name = req.Hostname
	}

	if err := a.Server.AddAsset(asset); err != nil {
		http.Error(w, "add asset: "+err.Error(), http.StatusConflict)
		return
	}
	a.json(w, http.StatusCreated, map[string]any{"success": true, "id": id})
}

func (a *AdminAPI) handleAssetByID() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/assets/")
		if id == "" {
			http.Error(w, "asset id required", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			a.getAsset(w, r, id)
		case http.MethodPut:
			a.updateAsset(w, r, id)
		case http.MethodDelete:
			a.deleteAsset(w, r, id)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (a *AdminAPI) getAsset(w http.ResponseWriter, r *http.Request, id string) {
	asset, ok := a.Server.AssetStore().Get(id)
	if !ok {
		http.Error(w, "asset not found", http.StatusNotFound)
		return
	}
	a.json(w, http.StatusOK, asset)
}

func (a *AdminAPI) updateAsset(w http.ResponseWriter, r *http.Request, id string) {
	asset, ok := a.Server.AssetStore().Get(id)
	if !ok {
		http.Error(w, "asset not found", http.StatusNotFound)
		return
	}
	var req AssetCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name != "" {
		asset.Name = req.Name
	}
	if req.Hostname != "" {
		asset.Hostname = req.Hostname
	}
	if req.Port > 0 {
		asset.Port = req.Port
	}
	if req.Username != "" {
		asset.Username = req.Username
	}
	if req.Password != "" {
		asset.Password = req.Password
	}
	if req.PrivateKeyFile != "" {
		asset.PrivateKeyFile = req.PrivateKeyFile
	}
	asset.Comment = req.Comment

	if err := a.Server.AssetStore().Update(asset); err != nil {
		http.Error(w, "update asset: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.json(w, http.StatusOK, map[string]any{"success": true})
}

func (a *AdminAPI) deleteAsset(w http.ResponseWriter, r *http.Request, id string) {
	if err := a.Server.AssetStore().Delete(id); err != nil {
		http.Error(w, "delete asset: "+err.Error(), http.StatusNotFound)
		return
	}
	a.json(w, http.StatusOK, map[string]any{"success": true})
}

// --- Session management ---

func (a *AdminAPI) handleSessions() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.enableCORS(w)
		switch r.Method {
		case http.MethodGet:
			a.listSessions(w, r)
		case http.MethodOptions:
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (a *AdminAPI) listSessions(w http.ResponseWriter, r *http.Request) {
	active := a.Server.ActiveSessions()
	records := a.Server.RecordingIndex().List()

	// Build response
	type sessionInfo struct {
		ID        string    `json:"id"`
		Username  string    `json:"username"`
		AssetID   string    `json:"asset_id"`
		AssetName string    `json:"asset_name"`
		StartTime time.Time `json:"start_time"`
		EndTime   time.Time `json:"end_time"`
		Duration  string    `json:"duration"`
		Status    string    `json:"status"`
		Recording string    `json:"recording_path,omitempty"`
	}

	result := make([]sessionInfo, 0, len(records)+len(active))

	// Add active sessions
	for _, sc := range active {
		info := sessionInfo{
			ID:        sc.ID,
			Username:  sc.User.Username,
			StartTime: sc.StartTime,
			Status:    "active",
		}
		if sc.Asset != nil {
			info.AssetID = sc.Asset.ID
			info.AssetName = sc.Asset.Name
		}
		result = append(result, info)
	}

	// Add completed sessions from recording index
	for _, rec := range records {
		// Skip if already in active
		found := false
		for _, sc := range active {
			if sc.ID == rec.ID {
				found = true
				break
			}
		}
		if found {
			continue
		}

		info := sessionInfo{
			ID:        rec.ID,
			Username:  rec.Username,
			AssetID:   rec.AssetID,
			AssetName: rec.AssetName,
			StartTime: rec.StartTime,
			EndTime:   rec.EndTime,
			Status:    "closed",
			Recording: rec.Path(),
		}
		if !rec.EndTime.IsZero() {
			info.Duration = rec.Duration.String()
		}
		result = append(result, info)
	}

	a.json(w, http.StatusOK, map[string]any{
		"sessions": result,
		"count":    len(result),
		"active":   len(active),
	})
}

func (a *AdminAPI) handleSessionByID() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.enableCORS(w)
		rest := strings.TrimPrefix(r.URL.Path, "/sessions/")
		parts := strings.SplitN(rest, "/", 2)
		sessionID := parts[0]
		if sessionID == "" {
			http.Error(w, "session id required", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			if len(parts) > 1 && parts[1] == "recording" {
				a.getSessionRecording(w, r, sessionID)
			} else {
				a.getSession(w, r, sessionID)
			}
		case http.MethodOptions:
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (a *AdminAPI) getSession(w http.ResponseWriter, r *http.Request, id string) {
	// Check active sessions first
	for _, sc := range a.Server.ActiveSessions() {
		if sc.ID == id {
			info := map[string]any{
				"id":         sc.ID,
				"username":   sc.User.Username,
				"asset_id":   "",
				"asset_name": "",
				"start_time": sc.StartTime,
				"status":     "active",
			}
			if sc.Asset != nil {
				info["asset_id"] = sc.Asset.ID
				info["asset_name"] = sc.Asset.Name
			}
			a.json(w, http.StatusOK, info)
			return
		}
	}
	// Check recording index
	rec, ok := a.Server.RecordingIndex().Get(id)
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	a.json(w, http.StatusOK, map[string]any{
		"id":         rec.ID,
		"username":   rec.Username,
		"asset_id":   rec.AssetID,
		"asset_name": rec.AssetName,
		"start_time": rec.StartTime,
		"end_time":   rec.EndTime,
		"status":     "closed",
	})
}

func (a *AdminAPI) getSessionRecording(w http.ResponseWriter, r *http.Request, id string) {
	rec, ok := a.Server.RecordingIndex().Get(id)
	if !ok {
		http.Error(w, "recording not found", http.StatusNotFound)
		return
	}
	path := rec.Path()
	if path == "" {
		http.Error(w, "recording not available", http.StatusNotFound)
		return
	}
	// Serve the recording file (asciicast .cast format)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.cast\"", id))
	http.ServeFile(w, r, path)
}

// --- Audit log ---

func (a *AdminAPI) handleAudit() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.enableCORS(w)
		switch r.Method {
		case http.MethodGet:
			a.listAudit(w, r)
		case http.MethodOptions:
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (a *AdminAPI) listAudit(w http.ResponseWriter, r *http.Request) {
	events := a.Server.AuditStore().List()
	user := r.URL.Query().Get("user")
	sessionID := r.URL.Query().Get("session")

	if user != "" {
		events = a.Server.AuditStore().ListByUser(user)
	} else if sessionID != "" {
		events = a.Server.AuditStore().ListBySession(sessionID)
	}

	a.json(w, http.StatusOK, map[string]any{
		"events": events,
		"count":  len(events),
	})
}

func (a *AdminAPI) handleBannedCommands() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.enableCORS(w)
		switch r.Method {
		case http.MethodGet:
			a.listBanned(w, r)
		case http.MethodPost:
			a.addBanned(w, r)
		case http.MethodOptions:
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (a *AdminAPI) listBanned(w http.ResponseWriter, r *http.Request) {
	rules := a.Server.AuditStore().ListBannedCommands()
	a.json(w, http.StatusOK, map[string]any{"rules": rules, "count": len(rules)})
}

type BannedCommandRequest struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
	Reason  string `json:"reason"`
	Enabled bool   `json:"enabled"`
}

func (a *AdminAPI) addBanned(w http.ResponseWriter, r *http.Request) {
	var req BannedCommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	bc := BannedCommand{
		ID:      req.ID,
		Pattern: req.Pattern,
		Reason:  req.Reason,
		Enabled: req.Enabled,
	}
	if bc.ID == "" {
		bc.ID = "ban-" + strconv.Itoa(int(time.Now().UnixNano()%100000))
	}
	a.Server.AuditStore().AddBannedCommand(bc)
	a.json(w, http.StatusCreated, map[string]any{"success": true, "id": bc.ID})
}

// --- Config ---

func (a *AdminAPI) handleConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.enableCORS(w)
		switch r.Method {
		case http.MethodGet:
			a.getConfig(w, r)
		case http.MethodPut:
			a.updateConfig(w, r)
		case http.MethodOptions:
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (a *AdminAPI) getConfig(w http.ResponseWriter, r *http.Request) {
	cfg := a.Server.config
	a.json(w, http.StatusOK, map[string]any{
		"ssh_listen_addr": cfg.SSHListenAddr,
		"api_listen_addr": cfg.APIListenAddr,
		"host_key_path":   cfg.HostKeyPath,
		"recording_dir":   cfg.RecordingDir,
		"audit_log_path":  cfg.AuditLogPath,
		"default_user":    cfg.DefaultUser,
		"default_port":    cfg.DefaultPort,
		"max_sessions":    cfg.MaxSessions,
		"banner_msg":      cfg.BannerMsg,
	})
}

func (a *AdminAPI) updateConfig(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	cfg := a.Server.config
	if v, ok := req["default_user"].(string); ok {
		cfg.DefaultUser = v
	}
	if v, ok := req["default_port"].(float64); ok {
		cfg.DefaultPort = int(v)
	}
	if v, ok := req["max_sessions"].(float64); ok {
		cfg.MaxSessions = int(v)
	}
	if v, ok := req["banner_msg"].(string); ok {
		cfg.BannerMsg = v
	}
	if v, ok := req["recording_dir"].(string); ok {
		cfg.RecordingDir = v
	}
	a.Server.SetConfig(cfg)
	a.json(w, http.StatusOK, map[string]any{"success": true})
}

// --- Health & Metrics ---

func (a *AdminAPI) handleHealth(w http.ResponseWriter, r *http.Request) {
	a.json(w, http.StatusOK, map[string]any{
		"status":          "ok",
		"ssh_listen":      a.Server.config.SSHListenAddr,
		"user_store":      a.Server.UserStoreName(),
		"uptime":          time.Since(time.Now()).String(),
		"active_sessions": len(a.Server.ActiveSessions()),
	})
}

func (a *AdminAPI) handleMetrics(w http.ResponseWriter, r *http.Request) {
	a.enableCORS(w)
	events := a.Server.AuditStore().List()
	counts := a.Server.AuditStore().CountByAction()
	a.json(w, http.StatusOK, map[string]any{
		"active_sessions": len(a.Server.ActiveSessions()),
		"total_events":    len(events),
		"by_action":       counts,
		"total_assets":    len(a.Server.AssetStore().All()),
		"total_users":     len(a.Server.ListUsers()),
		"user_store":      a.Server.UserStoreName(),
	})
}

// --- Helpers ---

func (a *AdminAPI) enableCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func (a *AdminAPI) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
