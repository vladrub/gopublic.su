package ingress

import (
	"net/http"
	"testing"
)

func TestIsUpgradeRequest(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name:     "WebSocket upgrade",
			headers:  map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"},
			expected: true,
		},
		{
			name:     "WebSocket upgrade with mixed case",
			headers:  map[string]string{"Connection": "upgrade", "Upgrade": "websocket"},
			expected: true,
		},
		{
			name:     "WebSocket upgrade with multiple connection values",
			headers:  map[string]string{"Connection": "keep-alive, Upgrade", "Upgrade": "websocket"},
			expected: true,
		},
		{
			name:     "H2C upgrade",
			headers:  map[string]string{"Connection": "Upgrade, HTTP2-Settings", "Upgrade": "h2c"},
			expected: true,
		},
		{
			name:     "Normal HTTP request with keep-alive",
			headers:  map[string]string{"Connection": "keep-alive"},
			expected: false,
		},
		{
			name:     "Normal HTTP request with close",
			headers:  map[string]string{"Connection": "close"},
			expected: false,
		},
		{
			name:     "No connection header",
			headers:  map[string]string{},
			expected: false,
		},
		{
			name:     "Empty connection header",
			headers:  map[string]string{"Connection": ""},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "http://example.com/", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			result := isUpgradeRequest(req)
			if result != tt.expected {
				t.Errorf("isUpgradeRequest() = %v, want %v (headers: %v)", result, tt.expected, tt.headers)
			}
		})
	}
}
