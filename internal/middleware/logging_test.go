package middleware

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoggingMiddleware(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPartialContent) // 206 - should be Warn
		w.Write([]byte("hello"))
	})

	wrapped := Logging(log)(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusPartialContent)
	}

	output := buf.String()
	if !strings.Contains(output, `"method":"GET"`) {
		t.Errorf("log output missing method: %s", output)
	}
	if !strings.Contains(output, `"path":"/api/rules"`) {
		t.Errorf("log output missing path: %s", output)
	}
	if !strings.Contains(output, `"status":206`) {
		t.Errorf("log output missing status: %s", output)
	}
	if !strings.Contains(output, `"remote":"192.168.1.1:1234"`) {
		t.Errorf("log output missing remote: %s", output)
	}
	if !strings.Contains(output, `"size":5`) {
		t.Errorf("log output missing size: %s", output)
	}
}

func TestLoggingMiddlewareLevels(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		wantLevel string
	}{
		{"200 OK", http.StatusOK, `"level":"INFO"`},
		{"404 Not Found", http.StatusNotFound, `"level":"WARN"`},
		{"500 Internal Server Error", http.StatusInternalServerError, `"level":"ERROR"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&buf, nil))

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
			})

			wrapped := Logging(log)(handler)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)

			output := buf.String()
			if !strings.Contains(output, tc.wantLevel) {
				t.Errorf("expected level %s in output: %s", tc.wantLevel, output)
			}
		})
	}
}

func TestLoggingMiddlewareNilLogger(t *testing.T) {
	// Should not panic when logger is nil
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	wrapped := Logging(nil)(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req) // should not panic
}
