package database

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"

	"github.com/Bidon15/popsigner/control-plane/internal/config"
)

func newTestRedis(t *testing.T) (*miniredis.Miniredis, *Redis) {
	t.Helper()
	srv := miniredis.RunT(t)
	r, err := NewRedis(config.RedisConfig{Host: srv.Host(), Port: srv.Server().Addr().Port})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	return srv, r
}

func TestIncrWithExpire_StartsTheWindowOnce(t *testing.T) {
	srv, r := newTestRedis(t)
	ctx := context.Background()

	n, resetIn, err := r.IncrWithExpire(ctx, "ratelimit:test", time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
	require.Equal(t, time.Minute, resetIn)
	require.Equal(t, time.Minute, srv.TTL("ratelimit:test"))

	// A hit halfway through the window must not push the window's end out again.
	srv.FastForward(30 * time.Second)
	n, resetIn, err = r.IncrWithExpire(ctx, "ratelimit:test", time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(2), n)
	require.Equal(t, 30*time.Second, resetIn)
	require.Equal(t, 30*time.Second, srv.TTL("ratelimit:test"))

	// Once the window has passed the count starts over.
	srv.FastForward(31 * time.Second)
	n, resetIn, err = r.IncrWithExpire(ctx, "ratelimit:test", time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
	require.Equal(t, time.Minute, resetIn)
}

func TestIncrWithExpire_KeepsSubSecondWindows(t *testing.T) {
	srv, r := newTestRedis(t)
	n, resetIn, err := r.IncrWithExpire(context.Background(), "ratelimit:fast", 500*time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
	require.Equal(t, 500*time.Millisecond, resetIn)
	require.Equal(t, 500*time.Millisecond, srv.TTL("ratelimit:fast"))
}

func TestIncrWithExpire_RepairsAKeyWithoutExpiry(t *testing.T) {
	srv, r := newTestRedis(t)
	require.NoError(t, srv.Set("ratelimit:stuck", "500"))

	n, resetIn, err := r.IncrWithExpire(context.Background(), "ratelimit:stuck", time.Minute)
	require.NoError(t, err)
	require.Equal(t, int64(501), n)
	require.Equal(t, time.Minute, resetIn)
	require.Equal(t, time.Minute, srv.TTL("ratelimit:stuck"))
}
