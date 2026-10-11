// Package middleware provides reusable HTTP middleware for gowaf.
package middleware

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

// responseWriter wraps http.ResponseWriter to capture the status code and
// response body size, which are otherwise inaccessible after the handler runs.
type responseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.size += n
	return n, err
}

// Logging returns an http.Handler that wraps next with structured request
// logging. Every request is logged with its method, path, remote address,
// response status, duration, and body size via the provided slog logger.
func Logging(log *slog.Logger) func(http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rw := &responseWriter{
				ResponseWriter: w,
				status:         http.StatusOK,
			}

			start := time.Now()
			next.ServeHTTP(rw, r)
			duration := time.Since(start)

			attrs := []any{
				"method", r.Method,
				"path", r.URL.Path,
				"remote", r.RemoteAddr,
				"status", rw.status,
				"duration_ms", strconv.FormatInt(duration.Milliseconds(), 10),
			}
			if rw.size > 0 {
				attrs = append(attrs, "size", rw.size)
			}

			// Log 5xx at Error level, 4xx at Warn, everything else at Info.
			switch {
			case rw.status >= http.StatusInternalServerError:
				log.Error("request", attrs...)
			case rw.status >= http.StatusMultipleChoices:
				log.Warn("request", attrs...)
			default:
				log.Info("request", attrs...)
			}
		})
	}
}
