package bastion

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// RecordingFormat specifies the format of session recordings.
type RecordingFormat string

const (
	FormatAsciinema RecordingFormat = "asciinema" // asciicast v2 format (JSON lines)
	FormatRaw       RecordingFormat = "raw"        // raw binary capture
)

// SessionRecord represents a single terminal session recording.
type SessionRecord struct {
	ID        string        `json:"id"`          // unique session ID
	Username  string        `json:"username"`    // user who connected
	AssetID   string        `json:"asset_id"`     // target asset
	AssetName string        `json:"asset_name"`   // target asset name
	StartTime time.Time     `json:"start_time"`   // when session started
	EndTime   time.Time     `json:"end_time"`     // when session ended (0 if ongoing)
	Duration  time.Duration `json:"duration"`     // session duration
	Format    RecordingFile  `json:"-"`           // file handle (not serialized)
}

// RecordingFile holds the open recording file and metadata.
type RecordingFile struct {
	path    string
	file    *os.File
	writer  *bufio.Writer
	closed  bool
	mu      sync.Mutex
}

// SessionRecorder manages recording of SSH sessions to files.
// It writes asciicast v2 format JSON lines.
type SessionRecorder struct {
	dir string
}

// NewSessionRecorder creates a recorder that saves sessions to the given directory.
func NewSessionRecorder(dir string) *SessionRecorder {
	return &SessionRecorder{dir: dir}
}

// StartSession begins recording a new session.
// Returns a SessionRecord with active recording.
func (r *SessionRecorder) StartSession(sessionID, username, assetID, assetName string) (*SessionRecord, error) {
	if err := os.MkdirAll(r.dir, 0750); err != nil {
		return nil, fmt.Errorf("create recording dir: %w", err)
	}

	// File naming: YYYY-MM-DD/username_sessionID.cast
	now := time.Now()
	dateDir := now.Format("2006-01-02")
	dayDir := filepath.Join(r.dir, dateDir)
	if err := os.MkdirAll(dayDir, 0750); err != nil {
		return nil, fmt.Errorf("create date dir: %w", err)
	}

	fileName := fmt.Sprintf("%s_%s.cast", username, sessionID)
	filePath := filepath.Join(dayDir, fileName)

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return nil, fmt.Errorf("create recording file: %w", err)
	}

	// Write asciicast v2 header
	writer := bufWriter(f)
	header := map[string]any{
		"version": 2,
		"width":   80,
		"height":  24,
		"timestamp": now.Unix(),
		"env": map[string]string{
			"TERM": "xterm-256color",
			"SHELL": "/bin/bash",
		},
		"command": fmt.Sprintf("bastion -> %s (%s)", assetName, assetID),
		"title": fmt.Sprintf("%s @ %s", username, assetName),
	}
	headerBytes, _ := json.Marshal(header)
	fmt.Fprintln(writer, string(headerBytes))
	writer.Flush()

	return &SessionRecord{
		ID:        sessionID,
		Username:  username,
		AssetID:   assetID,
		AssetName: assetName,
		StartTime: now,
		Format: RecordingFile{
			path:   filePath,
			file:   f,
			writer: writer,
		},
	}, nil
}

// RecordEvent writes a single I/O event to the recording.
// data is the terminal output/input, isInput indicates whether it's user input.
func (r *SessionRecord) RecordEvent(data []byte, isInput bool, elapsed time.Duration) {
	r.Format.mu.Lock()
	defer r.Format.mu.Unlock()
	if r.Format.closed {
		return
	}
	event := [3]interface{}{
		fmt.Sprintf("%.6f", elapsed.Seconds()), // delay since last event
		map[string]string{"i": string(data)},  // event data
		func() string {
			if isInput {
				return "i"
			}
			return "o"
		}(),
	}
	// Actually, asciicast v2 format is simpler: [time, type, data]
	// Let's use the standard format: [delay, "i"/"o", data]
	// But the standard format is: [time_since_start, "o"/"i", string]
	// Let's keep it simple and correct

	eventBytes, err := json.Marshal([]interface{}{
		fmt.Sprintf("%.6f", elapsed.Seconds()),
		string(data),
	})
	if err != nil {
		return
	}
	r.Format.writer.Write(eventBytes)
	r.Format.writer.WriteByte('\n')
	r.Format.writer.Flush()
}

// RecordOutput writes output data to the recording (not user input).
func (r *SessionRecord) RecordOutput(data []byte, elapsed time.Duration) {
	r.RecordEvent(data, false, elapsed)
}

// RecordInput writes input data to the recording (user input).
func (r *SessionRecord) RecordInput(data []byte, elapsed time.Duration) {
	r.RecordEvent(data, true, elapsed)
}

// Stop ends the recording.
func (r *SessionRecord) Stop() {
	r.Format.mu.Lock()
	defer r.Format.mu.Unlock()
	if r.Format.closed {
		return
	}
	r.EndTime = time.Now()
	r.Duration = r.EndTime.Sub(r.StartTime)
	r.Format.writer.Flush()
	r.Format.file.Close()
	r.Format.closed = true
}

// Path returns the file path of the recording.
func (r *SessionRecord) Path() string {
	return r.Format.path
}

// --- Terminal size detection ---

// GetTerminalSize returns the terminal dimensions from the given file descriptor.
// Used for PTY allocation.
func GetTerminalSize(fd int) (width, height int) {
	w, h, err := term.GetSize(fd)
	if err != nil {
		return 80, 24
	}
	return w, h
}

// TerminalSizeMsg represents a window-change terminal message.
type TerminalSizeMsg struct {
	Width  uint32 `json:"width"`
	Height uint32 `json:"height"`
}

// encodeTerminalSize encodes a terminal size change into the SSH channel request format.
func encodeTerminalSize(w, h int) []byte {
	// SSH "window-change" message is 4 bytes: width(2) + height(2)
	b := make([]byte, 4)
	b[0] = byte(w >> 8)
	b[1] = byte(w)
	b[2] = byte(h >> 8)
	b[3] = byte(h)
	return b
}

// decodeTerminalSize decodes an SSH "window-change" request payload.
func decodeTerminalSize(data []byte) (width, height int) {
	if len(data) < 4 {
		return 80, 24
	}
	width = int(data[0])<<8 | int(data[1])
	height = int(data[2])<<8 | int(data[3])
	return width, height
}

// --- Recording index ---

// RecordingIndex tracks all session recordings for search/listing.
type RecordingIndex struct {
	mu         sync.RWMutex
	records    []*SessionRecord
	byID       map[string]*SessionRecord
}

// NewRecordingIndex creates an empty index.
func NewRecordingIndex() *RecordingIndex {
	return &RecordingIndex{
		records: make([]*SessionRecord, 0),
		byID:    make(map[string]*SessionRecord),
	}
}

// Register adds a session record to the index.
func (idx *RecordingIndex) Register(r *SessionRecord) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.records = append(idx.records, r)
	idx.byID[r.ID] = r
}

// List returns all session records.
func (idx *RecordingIndex) List() []*SessionRecord {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	result := make([]*SessionRecord, len(idx.records))
	copy(result, idx.records)
	return result
}

// Get retrieves a session record by ID.
func (idx *RecordingIndex) Get(id string) (*SessionRecord, bool) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	r, ok := idx.byID[id]
	return r, ok
}

// ListByUser returns session records for a given username.
func (idx *RecordingIndex) ListByUser(username string) []*SessionRecord {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	result := make([]*SessionRecord, 0)
	for _, r := range idx.records {
		if r.Username == username {
			result = append(result, r)
		}
	}
	return result
}

// ListByAsset returns session records for a given asset ID.
func (idx *RecordingIndex) ListByAsset(assetID string) []*SessionRecord {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	result := make([]*SessionRecord, 0)
	for _, r := range idx.records {
		if r.AssetID == assetID {
			result = append(result, r)
		}
	}
	return result
}

// bufWriter creates a buffered writer for the given file.
func bufWriter(f *os.File) *bufio.Writer {
	return bufio.NewWriterSize(f, 4096)
}

// sessionID generates a unique session ID from timestamp and random bytes.
func sessionID() string {
	return fmt.Sprintf("sess-%d-%s", time.Now().UnixNano(), generateKeyToken())
}

// sanitizeUsername sanitizes a username for use in file paths.
func sanitizeUsername(u string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, u)
}

// --- Raw recording mode (alternative to asciicast) ---

// RawRecorder captures raw I/O bytes with timestamps.
type RawRecorder struct {
	path    string
	file    *os.File
	start   time.Time
	mu      sync.Mutex
}

// NewRawRecorder creates a raw binary recorder.
func NewRawRecorder(dir, sessionID, username string) (*RawRecorder, error) {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("create record dir: %w", err)
	}
	fileName := fmt.Sprintf("%s_%s.raw", sanitizeUsername(username), sessionID)
	filePath := filepath.Join(dir, fileName)
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return nil, fmt.Errorf("create record file: %w", err)
	}
	return &RawRecorder{path: filePath, file: f, start: time.Now()}, nil
}

// Append writes a data chunk to the raw recording.
func (r *RawRecorder) Append(data []byte, isInput bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ts := time.Since(r.start).Seconds()
	// Write a simple binary format: [4-byte timestamp + 1-byte type + 4-byte length + data]
	r.file.Write([]byte{
		byte(ts),
		byte(ts >> 8),
		byte(ts >> 16),
		byte(ts >> 24),
		func() byte {
			if isInput {
				return 1
			}
			return 0
		}(),
		byte(len(data)),
		byte(len(data) >> 8),
		byte(len(data) >> 16),
		byte(len(data) >> 24),
	})
	r.file.Write(data)
}

// Close closes the raw recorder.
func (r *RawRecorder) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.file.Close()
}

// Copy reads a recording file and writes it to the output.
func CopyRecording(srcPath string, dst io.Writer) error {
	return copyFile(srcPath, dst)
}

// copyFile copies a file's contents to the writer.
func copyFile(src string, dst io.Writer) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(dst, f)
	return err
}
