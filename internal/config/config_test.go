package config

import (
	"os"
	"testing"
)

func TestLoadFromEnv(t *testing.T) {
	// Save and restore environment
	origDomain := os.Getenv("DOMAIN_NAME")
	origInsecure := os.Getenv("INSECURE_HTTP")
	defer func() {
		os.Setenv("DOMAIN_NAME", origDomain)
		os.Setenv("INSECURE_HTTP", origInsecure)
	}()

	t.Run("loads domain from env", func(t *testing.T) {
		os.Setenv("DOMAIN_NAME", "test.example.com")
		os.Setenv("INSECURE_HTTP", "")

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv failed: %v", err)
		}

		if cfg.Domain != "test.example.com" {
			t.Errorf("Domain = %q, want %q", cfg.Domain, "test.example.com")
		}
	})

	t.Run("loads insecure mode", func(t *testing.T) {
		os.Setenv("DOMAIN_NAME", "example.com")
		os.Setenv("INSECURE_HTTP", "true")

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv failed: %v", err)
		}

		if !cfg.InsecureMode {
			t.Error("InsecureMode should be true")
		}
	})

	t.Run("default db path", func(t *testing.T) {
		os.Setenv("DB_PATH", "")

		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv failed: %v", err)
		}

		if cfg.DBPath != "gopublic.db" {
			t.Errorf("DBPath = %q, want %q", cfg.DBPath, "gopublic.db")
		}
	})
}

func TestConfig_IsLocalDev(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
	}{
		{"", true},
		{"localhost", true},
		{"127.0.0.1", true},
		{"example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			cfg := &Config{Domain: tt.domain}
			if got := cfg.IsLocalDev(); got != tt.expected {
				t.Errorf("IsLocalDev() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConfig_IsSecure(t *testing.T) {
	tests := []struct {
		name         string
		domain       string
		insecureMode bool
		expected     bool
	}{
		{"production with domain", "example.com", false, true},
		{"insecure mode", "example.com", true, false},
		{"local dev", "localhost", false, false},
		{"empty domain", "", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Domain:       tt.domain,
				InsecureMode: tt.insecureMode,
			}
			if got := cfg.IsSecure(); got != tt.expected {
				t.Errorf("IsSecure() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConfig_IngressPort(t *testing.T) {
	tests := []struct {
		name         string
		insecureMode bool
		expected     string
	}{
		{"insecure mode", true, ":80"},
		{"secure mode", false, ":8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{InsecureMode: tt.insecureMode}
			if got := cfg.IngressPort(); got != tt.expected {
				t.Errorf("IngressPort() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	t.Run("production requires session keys", func(t *testing.T) {
		cfg := &Config{
			Domain:          "example.com", // Non-local domain
			InsecureMode:    false,
			SessionHashKey:  nil, // Missing session keys
			SessionBlockKey: nil,
		}

		// Missing session keys should fail in production mode
		err := cfg.Validate()
		if err == nil {
			t.Error("Expected error for missing session keys in production mode")
		}
	})

	t.Run("local dev does not require domain", func(t *testing.T) {
		cfg := &Config{
			Domain:       "localhost",
			InsecureMode: false,
		}

		err := cfg.Validate()
		if err != nil {
			t.Errorf("Unexpected error for localhost: %v", err)
		}
	})

	t.Run("insecure mode does not require session keys", func(t *testing.T) {
		cfg := &Config{
			Domain:       "example.com",
			InsecureMode: true,
		}

		err := cfg.Validate()
		if err != nil {
			t.Errorf("Unexpected error in insecure mode: %v", err)
		}
	})
}
