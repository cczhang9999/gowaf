package bastion

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"
)

// Asset represents a backend server that users can connect to through the bastion.
type Asset struct {
	ID          string `json:"id"`          // unique identifier, e.g. "asset-001"
	Name        string `json:"name"`        // human-readable label
	Hostname    string `json:"hostname"`    // IP or DNS name
	Port        int    `json:"port"`        // SSH port, 0 means use config default
	Username    string `json:"username"`    // SSH user, empty means use config default
	// Password is the backend SSH password (for password auth to the asset).
	// In production this should be encrypted or fetched from a vault.
	Password string `json:"-"` // never serialize
	// PrivateKeyFile is the path to a private key for key-based auth to the asset.
	PrivateKeyFile string `json:"private_key_file,omitempty"`
	// PrivateKey is the raw private key content (alternative to PrivateKeyFile).
	PrivateKey string `json:"-"` // never serialize
	// Comment is an optional description.
	Comment string `json:"comment,omitempty"`
	// CreatedAt is when the asset was added.
	CreatedAt time.Time `json:"created_at"`
}

// AssetStore is a thread-safe store of assets using atomic pointer swaps
// for lock-free reads on the hot path, following the same pattern as
// gowaf's rules storage in waf.go.
type AssetStore struct {
	assets atomic.Pointer[[]Asset]
}

// NewAssetStore creates an empty AssetStore.
func NewAssetStore() *AssetStore {
	as := &AssetStore{}
	as.assets.Store(&[]Asset{})
	return as
}

// All returns a snapshot of all assets. The returned slice should not be modified.
func (s *AssetStore) All() []Asset {
	return *s.assets.Load()
}

// Get retrieves an asset by ID.
func (s *AssetStore) Get(id string) (Asset, bool) {
	for _, a := range s.All() {
		if a.ID == id {
			return a, true
		}
	}
	return Asset{}, false
}

// Set replaces the entire asset list atomically.
func (s *AssetStore) Set(assets []Asset) {
	s.assets.Store(&assets)
}

// Add appends a new asset. If an asset with the same ID exists, it returns an error.
func (s *AssetStore) Add(a Asset) error {
	current := s.All()
	for _, existing := range current {
		if existing.ID == a.ID {
			return fmt.Errorf("asset %q already exists", a.ID)
		}
	}
	updated := make([]Asset, len(current)+1)
	copy(updated, current)
	updated[len(current)] = a
	s.assets.Store(&updated)
	return nil
}

// Update replaces an existing asset by ID.
func (s *AssetStore) Update(a Asset) error {
	current := s.All()
	updated := make([]Asset, len(current))
	found := false
	for i, existing := range current {
		if existing.ID == a.ID {
			updated[i] = a
			found = true
		} else {
			updated[i] = existing
		}
	}
	if !found {
		return fmt.Errorf("asset %q not found", a.ID)
	}
	s.assets.Store(&updated)
	return nil
}

// Delete removes an asset by ID.
func (s *AssetStore) Delete(id string) error {
	current := s.All()
	updated := make([]Asset, 0, len(current))
	found := false
	for _, a := range current {
		if a.ID == id {
			found = true
			continue
		}
		updated = append(updated, a)
	}
	if !found {
		return fmt.Errorf("asset %q not found", a.ID)
	}
	s.assets.Store(&updated)
	return nil
}

// assetID generates a deterministic ID for an asset based on its hostname and port.
func assetID(host string, port int) string {
	h := md5.Sum([]byte(fmt.Sprintf("%s:%d", host, port)))
	return fmt.Sprintf("asset-%x", h[:8])
}

// MarshalJSON implements json.Marshaler for Asset (hides secrets).
func (a Asset) MarshalJSON() ([]byte, error) {
	type Alias Asset
	return json.Marshal(&struct {
		Alias
		Password     string `json:"-"`
		PrivateKey   string `json:"-"`
	}{
		Alias:      (Alias)(a),
		Password:   "",
		PrivateKey: "",
	})
}
