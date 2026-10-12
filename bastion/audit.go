package bastion

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// CommandAction represents a command execution event.
type CommandAction string

const (
	ActionCommand CommandAction = "command" // a command was executed
	ActionLogin   CommandAction = "login"   // session login
	ActionLogout  CommandAction = "logout"  // session logout
	ActionBlocked CommandAction = "blocked" // dangerous command blocked
	ActionRename  CommandAction = "rename"  // terminal renamed (e.g., window title)
)

// AuditEvent represents a single audited action.
type AuditEvent struct {
	Timestamp  time.Time     `json:"timestamp"`
	Username   string        `json:"username"`
	SessionID  string        `json:"session_id"`
	AssetID    string        `json:"asset_id"`
	AssetName  string        `json:"asset_name"`
	Action     CommandAction `json:"action"`
	Command    string        `json:"command,omitempty"`     // the command (for command events)
	WorkingDir string        `json:"working_dir,omitempty"` // working directory at time of command
	ExitCode   int           `json:"exit_code,omitempty"`   // exit code (for command events)
	Blocked    bool          `json:"blocked,omitempty"`     // whether the command was blocked
	RuleID     string        `json:"rule_id,omitempty"`     // if blocked, which rule triggered
	RawInput   string        `json:"raw_input,omitempty"`   // raw input line
	ClientIP   string        `json:"client_ip,omitempty"`   // SSH client IP
}

// AuditLogger writes structured audit events to a file in JSON Lines format.
// This mirrors gowaf's use of slog JSON for structured logging.
type AuditLogger struct {
	mu     sync.Mutex
	file   *os.File
	writer *json.Encoder
	path   string
}

// NewAuditLogger creates an audit logger that writes to the given file path.
func NewAuditLogger(path string) (*AuditLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &AuditLogger{
		file:   f,
		writer: json.NewEncoder(f),
		path:   path,
	}, nil
}

// Log writes an audit event as a JSON line.
func (a *AuditLogger) Log(e *AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e.Timestamp = time.Now()
	_ = a.writer.Encode(e)
}

// Close closes the audit log file.
func (a *AuditLogger) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.file.Close()
}

// Path returns the audit log file path.
func (a *AuditLogger) Path() string {
	return a.path
}

// --- In-memory audit event store (for API listing) ---

// AuditStore keeps the last N audit events in memory for querying.
type AuditStore struct {
	mu      sync.RWMutex
	events  []AuditEvent
	maxSize int
	banned  []BannedCommand
}

// NewAuditStore creates an in-memory audit store that keeps the last maxSize events.
func NewAuditStore(maxSize int) *AuditStore {
	if maxSize <= 0 {
		maxSize = 10000
	}
	return &AuditStore{
		events:  make([]AuditEvent, 0, maxSize),
		maxSize: maxSize,
		banned:  make([]BannedCommand, 0),
	}
}

// Append adds an event to the in-memory store (evicting oldest if over limit).
func (s *AuditStore) Append(e AuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) >= s.maxSize {
		// Drop oldest 10%
		drop := s.maxSize / 10
		if drop < 1 {
			drop = 1
		}
		s.events = append([]AuditEvent{}, s.events[drop:]...)
	}
	s.events = append(s.events, e)
}

// List returns all stored events (most recent last).
func (s *AuditStore) List() []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]AuditEvent, len(s.events))
	copy(result, s.events)
	return result
}

// ListByUser returns events for a specific username.
func (s *AuditStore) ListByUser(username string) []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]AuditEvent, 0)
	for _, e := range s.events {
		if e.Username == username {
			result = append(result, e)
		}
	}
	return result
}

// ListBySession returns events for a specific session ID.
func (s *AuditStore) ListBySession(sessionID string) []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]AuditEvent, 0)
	for _, e := range s.events {
		if e.SessionID == sessionID {
			result = append(result, e)
		}
	}
	return result
}

// CountByAction returns counts of events grouped by action type.
func (s *AuditStore) CountByAction() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	counts := make(map[string]int)
	for _, e := range s.events {
		key := string(e.Action)
		counts[key]++
	}
	return counts
}

// --- Command filtering ---

// BannedCommand represents a pattern for blocking commands.
type BannedCommand struct {
	ID      string `json:"id"`      // unique identifier
	Pattern string `json:"pattern"` // substring or regex to match
	Reason  string `json:"reason"`  // why this command is blocked
	Enabled bool   `json:"enabled"` // whether this rule is active
}

// AddBannedCommand adds a new command blocking rule.
func (s *AuditStore) AddBannedCommand(bc BannedCommand) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.banned = append(s.banned, bc)
}

// ListBannedCommands returns all banned command rules.
func (s *AuditStore) ListBannedCommands() []BannedCommand {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]BannedCommand, len(s.banned))
	copy(result, s.banned)
	return result
}

// CheckCommand checks if a command matches any banned pattern.
// Returns the matched BannedCommand and true if blocked, or false if allowed.
func (s *AuditStore) CheckCommand(cmd string) (BannedCommand, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	lowerCmd := strings.ToLower(cmd)
	for _, bc := range s.banned {
		if !bc.Enabled {
			continue
		}
		if strings.Contains(lowerCmd, strings.ToLower(bc.Pattern)) {
			return bc, true
		}
	}
	return BannedCommand{}, false
}

// ParseCommand extracts the command from a raw terminal input line.
// It strips leading whitespace and control characters.
func ParseCommand(input string) string {
	// Remove control characters like backspace, etc.
	input = strings.Map(func(r rune) rune {
		if r >= 32 || r == '\t' {
			return r
		}
		return -1
	}, input)
	input = strings.TrimSpace(input)
	// Remove common shell prompt prefixes if present
	// This is a simple heuristic; real bastion hosts handle this more carefully
	if idx := strings.LastIndex(input, ";"); idx >= 0 {
		input = input[idx+1:]
	}
	if idx := strings.LastIndex(input, "&&"); idx >= 0 {
		input = input[idx+2:]
	}
	return strings.TrimSpace(input)
}

// ExtractCommands reads a recording file and extracts all commands.
// This is used for replay/audit purposes.
func ExtractCommands(recordingPath string) ([]string, error) {
	f, err := os.Open(recordingPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var commands []string
	scanner := bufio.NewScanner(f)
	// Skip the asciicast header (first line)
	if scanner.Scan() {
		// First line is the header
	}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "[") {
			var event []string
			if err := json.Unmarshal([]byte(line), &event); err == nil && len(event) >= 2 {
				// Check if this is user input
				// In asciicast v2, events are: [time, type, data]
				// We look for input events with newlines (completed commands)
				data := event[1]
				if strings.Contains(data, "\n") {
					for _, cmd := range strings.Split(data, "\n") {
						if cmd = strings.TrimSpace(cmd); cmd != "" {
							commands = append(commands, cmd)
						}
					}
				}
			}
		}
	}
	return commands, scanner.Err()
}
