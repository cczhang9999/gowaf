package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestBearerToken(t *testing.T) {
	const token = "s3cr3t-token"
	handler := BearerToken(token, "/api/healthz")(okHandler())

	tests := []struct {
		name       string
		path       string
		authHeader string
		wantStatus int
	}{
		{"missing header", "/api/rules", "", http.StatusUnauthorized},
		{"wrong scheme", "/api/rules", "Basic " + token, http.StatusUnauthorized},
		{"no credential", "/api/rules", "Bearer", http.StatusUnauthorized},
		{"wrong token", "/api/rules", "Bearer nope", http.StatusForbidden},
		{"correct token", "/api/rules", "Bearer " + token, http.StatusOK},
		{"lowercase scheme", "/api/rules", "bearer " + token, http.StatusOK},
		{"exempt path needs no header", "/api/healthz", "", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusUnauthorized {
				if got := rec.Header().Get("WWW-Authenticate"); got == "" {
					t.Errorf("401 response is missing WWW-Authenticate header")
				}
			}
		})
	}
}

// 认证中间件不能因为 token 为空就放行——空配置必须拒绝一切请求。
// 特别地,"Bearer " (空凭证) 曾与空 secret 常量时间相等而通过认证。
func TestBearerTokenEmptyTokenRejects(t *testing.T) {
	handler := BearerToken("")(okHandler())

	for _, header := range []string{"", "Bearer ", "Bearer anything"} {
		req := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("empty configured token with header %q: status = %d, want %d",
				header, rec.Code, http.StatusInternalServerError)
		}
	}
}
