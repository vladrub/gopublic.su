package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimiterConfig configures the rate limiter behavior.
type RateLimiterConfig struct {
	// RequestsPerSecond is the allowed requests per second per client.
	RequestsPerSecond float64
	// BurstSize is the maximum burst of requests allowed.
	BurstSize int
	// CleanupInterval is how often to clean up stale limiters.
	CleanupInterval time.Duration
	// MaxAge is how long to keep a limiter after last access.
	MaxAge time.Duration
}

// DefaultRateLimiterConfig returns sensible defaults for a web dashboard.
func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		RequestsPerSecond: 10,
		BurstSize:         20,
		CleanupInterval:   time.Minute,
		MaxAge:            5 * time.Minute,
	}
}

// IPRateLimiter implements per-IP rate limiting.
type IPRateLimiter struct {
	limiters map[string]*limiterEntry
	mu       sync.RWMutex
	cfg      RateLimiterConfig
	stopCh   chan struct{}
}

type limiterEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// NewIPRateLimiter creates a new per-IP rate limiter.
func NewIPRateLimiter(cfg RateLimiterConfig) *IPRateLimiter {
	rl := &IPRateLimiter{
		limiters: make(map[string]*limiterEntry),
		cfg:      cfg,
		stopCh:   make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// Allow checks if the IP is allowed to make a request.
func (rl *IPRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, exists := rl.limiters[ip]
	if !exists {
		entry = &limiterEntry{
			limiter: rate.NewLimiter(rate.Limit(rl.cfg.RequestsPerSecond), rl.cfg.BurstSize),
		}
		rl.limiters[ip] = entry
	}

	entry.lastAccess = time.Now()
	return entry.limiter.Allow()
}

// cleanup removes stale limiters periodically.
func (rl *IPRateLimiter) cleanup() {
	ticker := time.NewTicker(rl.cfg.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, entry := range rl.limiters {
				if now.Sub(entry.lastAccess) > rl.cfg.MaxAge {
					delete(rl.limiters, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// Stop stops the cleanup goroutine.
func (rl *IPRateLimiter) Stop() {
	close(rl.stopCh)
}

// RateLimitMiddleware creates a Gin middleware for rate limiting.
func RateLimitMiddleware(limiter *IPRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		if !limiter.Allow(ip) {
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
				"code":  "RATE_LIMIT_EXCEEDED",
			})
			return
		}

		c.Next()
	}
}

// ConnectionLimiter limits concurrent connections per user/domain.
type ConnectionLimiter struct {
	connections map[string]int
	maxPerKey   int
	mu          sync.Mutex
}

// NewConnectionLimiter creates a new connection limiter.
func NewConnectionLimiter(maxPerKey int) *ConnectionLimiter {
	return &ConnectionLimiter{
		connections: make(map[string]int),
		maxPerKey:   maxPerKey,
	}
}

// Acquire tries to acquire a connection slot for the given key.
// Returns true if allowed, false if limit reached.
func (cl *ConnectionLimiter) Acquire(key string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if cl.connections[key] >= cl.maxPerKey {
		return false
	}
	cl.connections[key]++
	return true
}

// Release releases a connection slot for the given key.
func (cl *ConnectionLimiter) Release(key string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if cl.connections[key] > 0 {
		cl.connections[key]--
		if cl.connections[key] == 0 {
			delete(cl.connections, key)
		}
	}
}

// Count returns the current connection count for a key.
func (cl *ConnectionLimiter) Count(key string) int {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return cl.connections[key]
}
