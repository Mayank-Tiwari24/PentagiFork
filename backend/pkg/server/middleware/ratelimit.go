package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// ============================================================================
// Rate Limiting Middleware
//
// Token bucket rate limiter per client IP. Configurable per-route-group
// with different limits for different API tiers:
//   - API requests: 1000/min (general)
//   - LLM calls (flow creation): 10/min (expensive)
//   - Auth endpoints: 20/min (brute-force protection)
//   - GraphQL: 500/min
//
// Uses an efficient in-memory token bucket with automatic cleanup of stale
// entries via a background goroutine.
// ============================================================================

// RateLimitConfig defines the rate limit parameters.
type RateLimitConfig struct {
	// RequestsPerMinute is the sustained rate (bucket refill rate).
	RequestsPerMinute int

	// BurstSize is the max tokens in the bucket (allows short bursts).
	// If 0, defaults to RequestsPerMinute.
	BurstSize int

	// KeyFunc extracts the rate limit key from the request.
	// Defaults to client IP if nil.
	KeyFunc func(*gin.Context) string

	// ExcludeFunc returns true for requests that should skip rate limiting.
	ExcludeFunc func(*gin.Context) bool
}

// tokenBucket implements a simple token bucket for a single key.
type tokenBucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

func (b *tokenBucket) allow() bool {
	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.lastRefill = now

	// Refill tokens based on elapsed time
	b.tokens += elapsed * b.refillRate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}

	if b.tokens < 1 {
		return false
	}

	b.tokens--
	return true
}

// RateLimiter manages per-key token buckets.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*tokenBucket
	config   RateLimitConfig
	stopCh   chan struct{}
	logger   *logrus.Entry
}

// NewRateLimiter creates a rate limiter with the given config.
func NewRateLimiter(cfg RateLimitConfig) *RateLimiter {
	if cfg.BurstSize <= 0 {
		cfg.BurstSize = cfg.RequestsPerMinute
	}

	rl := &RateLimiter{
		buckets: make(map[string]*tokenBucket),
		config:  cfg,
		stopCh:  make(chan struct{}),
		logger:  logrus.WithField("component", "rate-limiter"),
	}

	// Cleanup stale buckets every 5 minutes
	go rl.cleanup()

	return rl
}

// Middleware returns a Gin middleware that enforces the rate limit.
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check exclusion
		if rl.config.ExcludeFunc != nil && rl.config.ExcludeFunc(c) {
			c.Next()
			return
		}

		// Extract key
		key := c.ClientIP()
		if rl.config.KeyFunc != nil {
			key = rl.config.KeyFunc(c)
		}

		if !rl.Allow(key) {
			rl.logger.WithFields(logrus.Fields{
				"key":    key,
				"path":   c.Request.URL.Path,
				"method": c.Request.Method,
			}).Warn("rate limit exceeded")

			c.Header("Retry-After", "60")
			c.Header("X-RateLimit-Limit", formatInt(rl.config.RequestsPerMinute))
			c.Header("X-RateLimit-Remaining", "0")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate limit exceeded",
				"message": "Too many requests. Please try again later.",
			})
			return
		}

		// Set rate limit headers
		c.Header("X-RateLimit-Limit", formatInt(rl.config.RequestsPerMinute))
		c.Next()
	}
}

// Allow checks whether a request from the given key should be allowed.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, exists := rl.buckets[key]
	if !exists {
		bucket = &tokenBucket{
			tokens:     float64(rl.config.BurstSize),
			maxTokens:  float64(rl.config.BurstSize),
			refillRate: float64(rl.config.RequestsPerMinute) / 60.0,
			lastRefill: time.Now(),
		}
		rl.buckets[key] = bucket
	}

	return bucket.allow()
}

// Stop shuts down the cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
}

// cleanup removes stale buckets every 5 minutes.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for key, bucket := range rl.buckets {
				// Remove buckets that haven't been used in 10 minutes
				if now.Sub(bucket.lastRefill) > 10*time.Minute {
					delete(rl.buckets, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}

func formatInt(n int) string {
	return fmt.Sprintf("%d", n)
}

// ============================================================================
// Preset Rate Limiters for different API tiers
// ============================================================================

// NewAPIRateLimiter creates a limiter for general API requests (1000/min).
func NewAPIRateLimiter() *RateLimiter {
	return NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 1000,
		BurstSize:         100,
	})
}

// NewFlowRateLimiter creates a limiter for flow creation (10/min, expensive).
func NewFlowRateLimiter() *RateLimiter {
	return NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 10,
		BurstSize:         5,
	})
}

// NewAuthRateLimiter creates a limiter for auth endpoints (20/min, brute-force protection).
func NewAuthRateLimiter() *RateLimiter {
	return NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 20,
		BurstSize:         10,
	})
}

// NewGraphQLRateLimiter creates a limiter for GraphQL queries (500/min).
func NewGraphQLRateLimiter() *RateLimiter {
	return NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 500,
		BurstSize:         50,
	})
}
