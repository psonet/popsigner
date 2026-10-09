package database

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Bidon15/popsigner/control-plane/internal/config"
)

// Redis wraps a Redis client.
type Redis struct {
	client *redis.Client
}

// NewRedis creates a new Redis client.
func NewRedis(cfg config.RedisConfig) (*Redis, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr(),
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Verify connection
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	return &Redis{client: client}, nil
}

// Client returns the underlying Redis client.
func (r *Redis) Client() *redis.Client {
	return r.client
}

// Close closes the Redis connection.
func (r *Redis) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

// Ping verifies the Redis connection is alive.
func (r *Redis) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// Set stores a key-value pair with optional expiration.
func (r *Redis) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(ctx, key, value, expiration).Err()
}

// Get retrieves a value by key.
func (r *Redis) Get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key).Result()
}

// Delete removes a key.
func (r *Redis) Delete(ctx context.Context, keys ...string) error {
	return r.client.Del(ctx, keys...).Err()
}

// Exists checks if a key exists.
func (r *Redis) Exists(ctx context.Context, keys ...string) (int64, error) {
	return r.client.Exists(ctx, keys...).Result()
}

// Incr increments a key's value.
func (r *Redis) Incr(ctx context.Context, key string) (int64, error) {
	return r.client.Incr(ctx, key).Result()
}

// incrWindow counts a hit and starts the key's expiry only when the key is created (or has
// lost its expiry), so a steady caller cannot keep one window alive by re-arming the TTL.
var incrWindow = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
if n == 1 or redis.call('PTTL', KEYS[1]) < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return {n, redis.call('PTTL', KEYS[1])}
`)

// IncrWithExpire increments a key within a fixed window of the given length and reports the
// count and how long the current window still has to run.
func (r *Redis) IncrWithExpire(ctx context.Context, key string, expiration time.Duration) (int64, time.Duration, error) {
	res, err := incrWindow.Run(ctx, r.client, []string{key}, expiration.Milliseconds()).Int64Slice()
	if err != nil {
		return 0, 0, err
	}
	if len(res) != 2 {
		return 0, 0, fmt.Errorf("unexpected reply from the window script: %v", res)
	}
	return res[0], time.Duration(res[1]) * time.Millisecond, nil
}

// SetNX sets a key only if it doesn't exist.
func (r *Redis) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	return r.client.SetNX(ctx, key, value, expiration).Result()
}
