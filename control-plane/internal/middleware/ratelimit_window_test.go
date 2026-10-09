package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"

	"github.com/Bidon15/popsigner/control-plane/internal/config"
	"github.com/Bidon15/popsigner/control-plane/internal/database"
)

func newLimitedHandler(t *testing.T) (*miniredis.Miniredis, http.Handler) {
	t.Helper()
	srv := miniredis.RunT(t)
	r, err := database.NewRedis(config.RedisConfig{Host: srv.Host(), Port: srv.Server().Addr().Port})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return srv, RateLimit(r, DefaultRateLimitConfig())(ok)
}

func call(h http.Handler) int {
	return callRecorded(h).Code
}

func callRecorded(h http.Handler) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/keys/k/sign", nil)
	req.Header.Set("Authorization", "Bearer bbr_live_steady")
	req.RemoteAddr = "10.0.0.7:4242"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// A caller signing every 16 seconds stays far under 60 requests a minute and must never be
// rejected, however long it keeps going.
func TestRateLimit_SteadyCallerUnderTheLimitIsNeverRejected(t *testing.T) {
	srv, h := newLimitedHandler(t)
	for i := 0; i < 400; i++ {
		require.Equal(t, http.StatusOK, call(h), "request %d", i)
		srv.FastForward(16 * time.Second)
	}
}

func TestRateLimit_BurstOverTheLimitIsRejectedUntilTheWindowEnds(t *testing.T) {
	srv, h := newLimitedHandler(t)
	cfg := DefaultRateLimitConfig()
	for i := 0; i < cfg.RequestsPerMinute+cfg.BurstSize; i++ {
		require.Equal(t, http.StatusOK, call(h), "request %d", i)
	}
	srv.FastForward(20 * time.Second)
	rec := callRecorded(h)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	// The window opened with the first request, so 40 s of it remain, not a fresh minute.
	require.Equal(t, "40", rec.Header().Get("Retry-After"))

	srv.FastForward(41 * time.Second)
	require.Equal(t, http.StatusOK, call(h))
}
