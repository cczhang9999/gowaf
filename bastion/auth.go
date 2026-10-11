package bastion

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

// UserRole defines what a user can do.
type UserRole string

const (
	RoleAdmin   UserRole = "admin"   // can manage users, assets, and connect to all assets
	RoleUser    UserRole = "user"    // can connect to assigned assets
	RoleAuditor UserRole = "auditor" // read-only access to audit logs and recordings
)

// User is a bastion host user.
type User struct {
	// ID is the users1 primary key; 0 when the user only exists in memory.
	ID            uint      `json:"id"`
	Username      string    `json:"username"`
	PasswordHash  []byte    `json:"-"`                    // bcrypt hash of password
	PasswordPlain string    `json:"password,omitempty"`   // set on create/update, then hashed
	PublicKey     string    `json:"public_key,omitempty"` // SSH public key for key-based auth
	Role          UserRole  `json:"role"`
	Assets        []string  `json:"assets,omitempty"` // asset IDs this user can access; empty = all
	Comment       string    `json:"comment,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// AuthStore manages users and their permissions in a thread-safe manner.
// It is the in-memory fallback used when no MySQL DSN is configured;
// DatabaseAuthStore persists the same users into the users1 table.
type AuthStore struct {
	mu    sync.RWMutex
	users map[string]*User
}

// NewAuthStore creates an empty AuthStore.
func NewAuthStore() *AuthStore {
	return &AuthStore{users: make(map[string]*User)}
}

// Register adds or updates a user, hashing the password if provided.
func (s *AuthStore) Register(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u.PasswordPlain != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(u.PasswordPlain), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
		u.PasswordHash = hash
	}
	u.PasswordPlain = ""
	s.users[u.Username] = u
	return nil
}

// Unregister removes a user.
func (s *AuthStore) Unregister(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, username)
}

// Authenticate checks a username/password against the user store.
func (s *AuthStore) Authenticate(username, password string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return nil, fmt.Errorf("user %q not found", username)
	}
	if len(u.PasswordHash) == 0 {
		return nil, fmt.Errorf("user %q has no password set", username)
	}
	if err := bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid password for user %q", username)
	}
	return u, nil
}

// AuthenticatePublicKey checks a username and SSH public key.
func (s *AuthStore) AuthenticatePublicKey(username string, pubKey ssh.PublicKey) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return nil, fmt.Errorf("user %q not found", username)
	}
	if u.PublicKey == "" {
		return nil, fmt.Errorf("user %q has no public key configured", username)
	}
	configuredKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(u.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("invalid configured public key: %w", err)
	}
	// Use constant-time comparison
	if subtle.ConstantTimeCompare(pubKey.Marshal(), configuredKey.Marshal()) != 1 {
		return nil, fmt.Errorf("public key mismatch for user %q", username)
	}
	return u, nil
}

// CanAccessAsset checks if a user can access a given asset ID.
func (s *AuthStore) CanAccessAsset(u *User, assetID string) bool {
	return canAccessAsset(u, assetID)
}

// canAccessAsset is the shared RBAC rule for both the in-memory and the
// database-backed stores. Admin and auditor roles can access all assets.
func canAccessAsset(u *User, assetID string) bool {
	if u.Role == RoleAdmin || u.Role == RoleAuditor {
		return true
	}
	if len(u.Assets) == 0 {
		return true
	}
	for _, a := range u.Assets {
		if a == assetID {
			return true
		}
	}
	return false
}

// ListUsers returns all users (secrets stripped).
func (s *AuthStore) ListUsers() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	users := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		copy := *u
		copy.PasswordHash = nil
		copy.PasswordPlain = ""
		users = append(users, &copy)
	}
	return users
}

// GetUser retrieves a user by username (secrets stripped).
func (s *AuthStore) GetUser(username string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return nil, false
	}
	copy := *u
	copy.PasswordHash = nil
	copy.PasswordPlain = ""
	return &copy, true
}

// GetUserByID retrieves a user by primary key (secrets stripped).
// The in-memory store has no real IDs, so this falls back to a scan over
// the stored users, which is only meaningful for users loaded from users1.
func (s *AuthStore) GetUserByID(id uint) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.ID == id {
			copy := *u
			copy.PasswordHash = nil
			copy.PasswordPlain = ""
			return &copy, true
		}
	}
	return nil, false
}

// HasUser checks if a user exists.
func (s *AuthStore) HasUser(username string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.users[username]
	return ok
}

// UpdateUser updates an existing user in the store.
func (s *AuthStore) UpdateUser(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.users[u.Username]
	if !ok {
		return fmt.Errorf("user %q not found", u.Username)
	}
	// Keep the stored password when the caller only edits other fields.
	if len(u.PasswordHash) == 0 && existing != nil {
		u.PasswordHash = existing.PasswordHash
	}
	if u.ID == 0 && existing != nil {
		u.ID = existing.ID
	}
	if u.CreatedAt.IsZero() && existing != nil {
		u.CreatedAt = existing.CreatedAt
	}
	s.users[u.Username] = u
	return nil
}

// --- SSH key helpers ---

// parseSSHPublicKey parses an SSH public key string from authorized_keys format.
func parseSSHPublicKey(keyStr string) (ssh.PublicKey, error) {
	keyStr = strings.TrimSpace(keyStr)
	if keyStr == "" {
		return nil, fmt.Errorf("empty public key")
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyStr))
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return pubKey, nil
}

// parsePrivateKey parses a PEM-encoded private key.
func parsePrivateKey(keyBytes []byte) (ssh.Signer, error) {
	// ssh.ParsePrivateKey handles most formats directly
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		// Try wrapping in PEM
		key, _ := pem.Decode(keyBytes)
		if key != nil {
			// Handle PKCS8
			if x509Key, e := x509.ParsePKCS8PrivateKey(key.Bytes); e == nil {
				return ssh.NewSignerFromKey(x509Key)
			}
			// Handle PKCS1 (RSA)
			if x509Key, e := x509.ParsePKCS1PrivateKey(key.Bytes); e == nil {
				return ssh.NewSignerFromKey(x509Key)
			}
			// Handle EC
			if x509Key, e := x509.ParseECPrivateKey(key.Bytes); e == nil {
				return ssh.NewSignerFromKey(x509Key)
			}
		}
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return signer, nil
}

// parsePrivateKeyFile reads and parses a private key from a file path.
func parsePrivateKeyFile(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file %q: %w", path, err)
	}
	return parsePrivateKey(data)
}

// generateKeyToken derives an 8-byte token for internal use.
func generateKeyToken() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// sha256Sum returns a hex-encoded SHA-256 hash of the input.
func sha256Sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
