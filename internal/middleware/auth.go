// Package middleware provides reusable HTTP middleware for gowaf.
package middleware

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
)

// BearerToken returns middleware that requires a valid
// "Authorization: Bearer <token>" header on every request.
//
// Paths listed in exempt are served without authentication. Only use that for
// liveness/readiness probes that a load balancer must reach unauthenticated.
//
// The token comparison is constant-time so an attacker cannot recover the
// secret byte by byte from response timing. An empty token disables nothing:
// callers must reject empty tokens at startup (fail-closed) rather than rely on
// this middleware to no-op.
func BearerToken(token string, exempt ...string) func(http.Handler) http.Handler {
	// 空 token 是配置错误,必须拒绝一切请求而不是放行。
	// 否则 "Authorization: Bearer " (空凭证) 会与空 secret 常量时间相等而通过认证。
	// 调用方还应在启动期就 fail-closed;这里是第二道防线。
	if token == "" {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeAuthError(w, http.StatusInternalServerError,
					"authentication is misconfigured: empty API token")
			})
		}
	}

	exemptPaths := make(map[string]struct{}, len(exempt))
	for _, p := range exempt {
		exemptPaths[p] = struct{}{}
	}
	secret := []byte(token)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := exemptPaths[r.URL.Path]; ok {
				next.ServeHTTP(w, r)
				return
			}

			auth := r.Header.Get("Authorization")
			if auth == "" {
				writeAuthError(w, http.StatusUnauthorized, "missing Authorization header")
				return
			}
			scheme, credential, found := strings.Cut(auth, " ")
			if !found || !strings.EqualFold(scheme, "bearer") {
				writeAuthError(w, http.StatusUnauthorized,
					"invalid Authorization header format, expected 'Bearer <token>'")
				return
			}
			if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(credential)), secret) != 1 {
				writeAuthError(w, http.StatusForbidden, "invalid API token")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// writeAuthError mirrors the {"success":false,"error":...} shape used by the
// management API so clients get one consistent error format.
func writeAuthError(w http.ResponseWriter, status int, msg string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="gowaf-api"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": msg})
}
