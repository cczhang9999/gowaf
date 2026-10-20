package bastion

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeUsername(t *testing.T) {
	cases := map[string]string{
		"alice":            "alice",
		"a-b_c":            "a-b_c",
		"../../etc/passwd": "______etc_passwd", // 每个 . 和 / 都被替换为 _,不含路径分隔符
		"a/b":              "a_b",
		"a\\b":             "a_b",
		"":                 "",
		"用户":               "__",
	}
	for in, want := range cases {
		if got := sanitizeUsername(in); got != want {
			t.Errorf("sanitizeUsername(%q) = %q, want %q", in, got, want)
		}
	}

	// 无论输入多恶意,输出都不能含路径分隔符或点号。
	for _, in := range []string{"../../x", `..\..\x`, "/etc/passwd", "a/../../b"} {
		got := sanitizeUsername(in)
		if strings.ContainsAny(got, `/\`) || strings.Contains(got, "..") {
			t.Errorf("sanitizeUsername(%q) = %q, still contains traversal characters", in, got)
		}
	}
}

// 用户名来自管理 API,可能包含路径分隔符。录像文件必须始终落在录像根目录内,
// 否则可以借助用户名把 attacker 可控内容写到任意路径。
func TestStartSessionCannotEscapeRecordingDir(t *testing.T) {
	root := t.TempDir()
	recorder := NewSessionRecorder(filepath.Join(root, "recordings"))

	rec, err := recorder.StartSession("sess-1", "../../../../tmp/pwned", "asset-1", "host")
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	defer rec.Stop()

	base := filepath.Join(root, "recordings")
	got := filepath.Clean(rec.Path())
	if !strings.HasPrefix(got, base+string(os.PathSeparator)) {
		t.Fatalf("recording escaped the recording dir: got %q, want a path under %q", got, base)
	}
	if _, err := os.Stat(got); err != nil {
		t.Fatalf("recording file was not created at %q: %v", got, err)
	}

	// 恶意用户名不能生成任何逃逸到 root 之外的文件。
	escaped := filepath.Join(root, "..", "tmp", "pwned")
	if _, err := os.Stat(escaped); err == nil {
		t.Fatalf("path traversal succeeded, wrote %q", escaped)
	}
}

// 空用户名必须有确定性的回退值,不能生成 "_sess-1.cast" 这类无归属文件。
func TestStartSessionEmptyUsernameFallsBack(t *testing.T) {
	root := t.TempDir()
	recorder := NewSessionRecorder(root)

	rec, err := recorder.StartSession("sess-2", "", "asset-1", "host")
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	defer rec.Stop()

	if name := filepath.Base(rec.Path()); !strings.HasPrefix(name, "unknown_") {
		t.Fatalf("recording file name = %q, want prefix %q", name, "unknown_")
	}
}
