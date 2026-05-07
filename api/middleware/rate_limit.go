package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimiter provides Redis-backed sliding-window rate limiting.
type RateLimiter struct {
	Redis *redis.Client
}

// NewRateLimiter creates a rate limiter.
func NewRateLimiter(rdb *redis.Client) *RateLimiter {
	return &RateLimiter{Redis: rdb}
}

// Limit returns a middleware that allows `maxRequests` per `window` per client IP.
func (rl *RateLimiter) Limit(maxRequests int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
				ip = xf
			}
			key := fmt.Sprintf("ratelimit:%s:%s", r.URL.Path, ip)

			ctx := r.Context()
			now := time.Now().Unix()
			windowStart := now - int64(window.Seconds())

			// Use Redis sorted set for sliding window
			pipe := rl.Redis.Pipeline()
			pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", windowStart))
			pipe.ZCard(ctx, key)
			pipe.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: now})
			pipe.Expire(ctx, key, window)
			cmds, err := pipe.Exec(ctx)
			if err != nil {
				// Fail open: allow request on Redis error
				next.ServeHTTP(w, r)
				return
			}

			countCmd := cmds[1].(*redis.IntCmd)
			count := int(countCmd.Val())

			if count >= maxRequests {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(window.Seconds())))
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"rate limit exceeded"}`))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
