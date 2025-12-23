package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSetCSRFToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(SetCSRFToken(&CSRFConfig{Secure: false}))
	r.GET("/test", func(c *gin.Context) {
		token := GetCSRFToken(c)
		c.String(http.StatusOK, token)
	})

	// First request - should set cookie
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	cookies := w.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "csrf_token" {
			csrfCookie = c
			break
		}
	}

	if csrfCookie == nil {
		t.Fatal("CSRF cookie not set")
	}

	if len(csrfCookie.Value) < 32 {
		t.Error("CSRF token too short")
	}

	// Token should be returned in body too
	if w.Body.String() != csrfCookie.Value {
		t.Error("Token in context doesn't match cookie")
	}

	// Second request with cookie - should not regenerate
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.AddCookie(csrfCookie)
	r.ServeHTTP(w2, req2)

	// Should return same token
	if w2.Body.String() != csrfCookie.Value {
		t.Error("Token should persist across requests")
	}
}

func TestValidateCSRF_SafeMethods(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(ValidateCSRF())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})
	r.HEAD("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})
	r.OPTIONS("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	methods := []string{"GET", "HEAD", "OPTIONS"}
	for _, method := range methods {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(method, "/test", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("%s should pass without CSRF token, got %d", method, w.Code)
		}
	}
}

func TestValidateCSRF_UnsafeMethods(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(ValidateCSRF())
	r.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	// Without cookie - should fail
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}

	// With cookie but no token in request - should fail
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/test", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "test-token"})
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}

	// With mismatched tokens - should fail
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/test", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "cookie-token"})
	req.Header.Set("X-CSRF-Token", "different-token")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}

	// With matching tokens via header - should pass
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/test", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "matching-token"})
	req.Header.Set("X-CSRF-Token", "matching-token")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// With matching tokens via form - should pass
	w = httptest.NewRecorder()
	form := url.Values{}
	form.Add("csrf_token", "form-token")
	req, _ = http.NewRequest("POST", "/test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "form-token"})
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestSecureCompare(t *testing.T) {
	tests := []struct {
		a, b     string
		expected bool
	}{
		{"same", "same", true},
		{"different", "tokens", false},
		{"", "", true},
		{"a", "", false},
		{"", "b", false},
		{"abc", "abcd", false},
	}

	for _, tt := range tests {
		if got := secureCompare(tt.a, tt.b); got != tt.expected {
			t.Errorf("secureCompare(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.expected)
		}
	}
}

func TestGenerateCSRFToken(t *testing.T) {
	token1 := generateCSRFToken()
	token2 := generateCSRFToken()

	if token1 == "" {
		t.Error("Token should not be empty")
	}

	if token1 == token2 {
		t.Error("Tokens should be unique")
	}

	// Token should be base64 encoded 32 bytes = ~43 chars
	if len(token1) < 40 {
		t.Errorf("Token too short: %d chars", len(token1))
	}
}
