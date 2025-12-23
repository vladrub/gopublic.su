package ingress

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"gopublic/internal/server"
)

func TestParseAndValidateHost(t *testing.T) {
	ingress := &Ingress{
		RootDomain: "example.com",
	}

	tests := []struct {
		name      string
		input     string
		wantHost  string
		wantValid bool
	}{
		// Valid cases
		{"simple host", "example.com", "example.com", true},
		{"subdomain", "sub.example.com", "sub.example.com", true},
		{"with port", "example.com:8080", "example.com", true},
		{"localhost", "localhost", "localhost", true},
		{"ip address", "192.168.1.1", "192.168.1.1", true},
		{"hyphen in subdomain", "my-app.example.com", "my-app.example.com", true},
		{"multiple subdomains", "a.b.c.example.com", "a.b.c.example.com", true},
		{"uppercase", "Example.COM", "example.com", true},

		// Invalid cases
		{"empty", "", "", false},
		{"only port", ":8080", "", false},
		{"too long", string(make([]byte, 300)), "", false},
		{"underscore", "my_app.example.com", "", false},
		{"starts with hyphen", "-example.com", "", false},
		{"ends with hyphen", "example-.com", "", false},
		{"special chars", "example$.com", "", false},
		{"spaces", "example .com", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHost, gotValid := ingress.parseAndValidateHost(tt.input)
			if gotValid != tt.wantValid {
				t.Errorf("parseAndValidateHost(%q) valid = %v, want %v", tt.input, gotValid, tt.wantValid)
			}
			if gotValid && gotHost != tt.wantHost {
				t.Errorf("parseAndValidateHost(%q) host = %q, want %q", tt.input, gotHost, tt.wantHost)
			}
		})
	}
}

func TestIsLocalDev(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
	}{
		{"", true},
		{"localhost", true},
		{"127.0.0.1", true},
		{"example.com", false},
		{"app.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			ingress := &Ingress{RootDomain: tt.domain}
			if got := ingress.isLocalDev(); got != tt.expected {
				t.Errorf("isLocalDev() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsLandingPage(t *testing.T) {
	tests := []struct {
		name       string
		rootDomain string
		host       string
		expected   bool
	}{
		{"root domain match", "example.com", "example.com", true},
		{"subdomain no match", "example.com", "app.example.com", false},
		{"localhost not landing", "localhost", "localhost", false},
		{"empty domain not landing", "", "anything", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingress := &Ingress{RootDomain: tt.rootDomain}
			if got := ingress.isLandingPage(tt.host); got != tt.expected {
				t.Errorf("isLandingPage(%q) = %v, want %v", tt.host, got, tt.expected)
			}
		})
	}
}

func TestIsDashboardHost(t *testing.T) {
	tests := []struct {
		name       string
		rootDomain string
		host       string
		expected   bool
	}{
		{"app subdomain", "example.com", "app.example.com", true},
		{"root domain", "example.com", "example.com", false},
		{"other subdomain", "example.com", "other.example.com", false},
		{"localhost match", "localhost", "localhost", true},
		{"127.0.0.1 match", "127.0.0.1", "127.0.0.1", true},
		{"empty domain", "", "anything", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingress := &Ingress{RootDomain: tt.rootDomain}
			if got := ingress.isDashboardHost(tt.host); got != tt.expected {
				t.Errorf("isDashboardHost(%q) = %v, want %v", tt.host, got, tt.expected)
			}
		})
	}
}

func TestHandleRequest_InvalidHost(t *testing.T) {
	gin.SetMode(gin.TestMode)

	registry := server.NewTunnelRegistry()
	ingress := &Ingress{
		Registry:   registry,
		RootDomain: "example.com",
	}

	r := gin.New()
	r.NoRoute(ingress.handleRequest)

	// Invalid host header
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Host = "invalid_host!@#"
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestHandleRequest_TunnelNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	registry := server.NewTunnelRegistry()
	ingress := &Ingress{
		Registry:   registry,
		RootDomain: "example.com",
	}

	r := gin.New()
	r.NoRoute(ingress.handleRequest)

	// Valid host but no tunnel registered
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Host = "myapp.example.com"
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}
