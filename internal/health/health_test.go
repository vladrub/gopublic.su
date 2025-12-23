package health

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestLiveHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	checker := NewChecker()
	r := gin.New()
	checker.RegisterRoutes(r)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health/live", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp HealthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.Status != "ok" {
		t.Errorf("Expected status 'ok', got %q", resp.Status)
	}
}

func TestReadyHandler_Ready(t *testing.T) {
	gin.SetMode(gin.TestMode)

	checker := NewChecker()
	r := gin.New()
	checker.RegisterRoutes(r)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health/ready", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp HealthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.Status != "ok" {
		t.Errorf("Expected status 'ok', got %q", resp.Status)
	}
}

func TestReadyHandler_NotReady(t *testing.T) {
	gin.SetMode(gin.TestMode)

	checker := NewChecker()
	checker.SetReady(false)
	r := gin.New()
	checker.RegisterRoutes(r)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health/ready", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", w.Code)
	}

	var resp HealthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.Status != "not_ready" {
		t.Errorf("Expected status 'not_ready', got %q", resp.Status)
	}
}

func TestReadyHandler_WithChecks(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// All checks pass
	passingCheck := func() error { return nil }
	checker := NewChecker(passingCheck, passingCheck)
	r := gin.New()
	checker.RegisterRoutes(r)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health/ready", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp HealthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.Status != "ok" {
		t.Errorf("Expected status 'ok', got %q", resp.Status)
	}

	if len(resp.Checks) != 2 {
		t.Errorf("Expected 2 checks, got %d", len(resp.Checks))
	}
}

func TestReadyHandler_FailingCheck(t *testing.T) {
	gin.SetMode(gin.TestMode)

	passingCheck := func() error { return nil }
	failingCheck := func() error { return errors.New("db connection failed") }
	checker := NewChecker(passingCheck, failingCheck)
	r := gin.New()
	checker.RegisterRoutes(r)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health/ready", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", w.Code)
	}

	var resp HealthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.Status != "degraded" {
		t.Errorf("Expected status 'degraded', got %q", resp.Status)
	}

	// First check should pass, second should fail
	if resp.Checks[0].Status != "ok" {
		t.Errorf("First check should pass")
	}
	if resp.Checks[1].Status != "error" {
		t.Errorf("Second check should fail")
	}
	if resp.Checks[1].Error != "db connection failed" {
		t.Errorf("Expected error message, got %q", resp.Checks[1].Error)
	}
}

func TestSetReady(t *testing.T) {
	checker := NewChecker()

	if !checker.IsReady() {
		t.Error("Should be ready by default")
	}

	checker.SetReady(false)
	if checker.IsReady() {
		t.Error("Should not be ready after SetReady(false)")
	}

	checker.SetReady(true)
	if !checker.IsReady() {
		t.Error("Should be ready after SetReady(true)")
	}
}
