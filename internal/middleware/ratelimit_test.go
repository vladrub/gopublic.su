package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestIPRateLimiter_Allow(t *testing.T) {
	cfg := RateLimiterConfig{
		RequestsPerSecond: 2,
		BurstSize:         2,
		CleanupInterval:   time.Minute,
		MaxAge:            time.Minute,
	}

	limiter := NewIPRateLimiter(cfg)
	defer limiter.Stop()

	ip := "192.168.1.1"

	// First 2 requests should be allowed (burst)
	for i := 0; i < 2; i++ {
		if !limiter.Allow(ip) {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// Third request should be rate limited
	if limiter.Allow(ip) {
		t.Error("Third request should be rate limited")
	}

	// Different IP should be allowed
	if !limiter.Allow("10.0.0.1") {
		t.Error("Different IP should be allowed")
	}
}

func TestIPRateLimiter_Cleanup(t *testing.T) {
	cfg := RateLimiterConfig{
		RequestsPerSecond: 10,
		BurstSize:         10,
		CleanupInterval:   50 * time.Millisecond,
		MaxAge:            100 * time.Millisecond,
	}

	limiter := NewIPRateLimiter(cfg)
	defer limiter.Stop()

	limiter.Allow("192.168.1.1")

	// Wait for cleanup
	time.Sleep(200 * time.Millisecond)

	limiter.mu.RLock()
	count := len(limiter.limiters)
	limiter.mu.RUnlock()

	if count != 0 {
		t.Errorf("Expected 0 limiters after cleanup, got %d", count)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := RateLimiterConfig{
		RequestsPerSecond: 1,
		BurstSize:         1,
		CleanupInterval:   time.Minute,
		MaxAge:            time.Minute,
	}

	limiter := NewIPRateLimiter(cfg)
	defer limiter.Stop()

	r := gin.New()
	r.Use(RateLimitMiddleware(limiter))
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	// First request should succeed
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Second request should be rate limited
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status %d, got %d", http.StatusTooManyRequests, w.Code)
	}

	if w.Header().Get("Retry-After") != "1" {
		t.Error("Expected Retry-After header")
	}
}

func TestConnectionLimiter(t *testing.T) {
	limiter := NewConnectionLimiter(2)

	// Acquire 2 slots
	if !limiter.Acquire("user1") {
		t.Error("First acquire should succeed")
	}
	if !limiter.Acquire("user1") {
		t.Error("Second acquire should succeed")
	}

	// Third should fail
	if limiter.Acquire("user1") {
		t.Error("Third acquire should fail")
	}

	// Different user should succeed
	if !limiter.Acquire("user2") {
		t.Error("Different user should succeed")
	}

	// Release one slot
	limiter.Release("user1")

	// Now should succeed
	if !limiter.Acquire("user1") {
		t.Error("Should succeed after release")
	}

	if limiter.Count("user1") != 2 {
		t.Errorf("Expected count 2, got %d", limiter.Count("user1"))
	}
}

func TestConnectionLimiter_Concurrent(t *testing.T) {
	limiter := NewConnectionLimiter(100)

	var wg sync.WaitGroup
	key := "test-key"

	// Spawn 200 goroutines trying to acquire
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if limiter.Acquire(key) {
				// Hold for a bit
				time.Sleep(time.Millisecond)
				limiter.Release(key)
			}
		}()
	}

	wg.Wait()

	// All should be released
	if limiter.Count(key) != 0 {
		t.Errorf("Expected count 0 after all releases, got %d", limiter.Count(key))
	}
}
