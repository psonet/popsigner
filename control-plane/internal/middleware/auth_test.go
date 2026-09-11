package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireScope(t *testing.T) {
	tests := []struct {
		name       string
		scopes     []string
		hasScopes  bool
		wantStatus int
	}{
		{
			name:       "session auth carries no scopes",
			wantStatus: http.StatusOK,
		},
		{
			name:       "required scope present",
			scopes:     []string{"keys:read", "keys:sign"},
			hasScopes:  true,
			wantStatus: http.StatusOK,
		},
		{
			name:       "wildcard scope grants everything",
			scopes:     []string{"*"},
			hasScopes:  true,
			wantStatus: http.StatusOK,
		},
		{
			name:       "required scope missing",
			scopes:     []string{"keys:read"},
			hasScopes:  true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "no scopes at all",
			scopes:     []string{},
			hasScopes:  true,
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var served bool
			handler := RequireScope("keys:sign")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				served = true
			}))

			r := httptest.NewRequest("POST", "/v1/keys/sign", nil)
			if tt.hasScopes {
				r = r.WithContext(context.WithValue(r.Context(), contextKey("scopes"), tt.scopes))
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			if tt.wantStatus == http.StatusOK {
				if !served {
					t.Errorf("request was rejected with %d", w.Code)
				}
				return
			}
			if served {
				t.Error("request reached the handler")
			}
			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}
