package metrics

import (
	"strings"
	"testing"
	"time"
)

func TestCounter(t *testing.T) {
	m := New()
	c := m.NewCounter("test_counter", "A test counter", nil)

	if c.Value() != 0 {
		t.Errorf("Expected initial value 0, got %d", c.Value())
	}

	c.Inc()
	if c.Value() != 1 {
		t.Errorf("Expected value 1 after Inc, got %d", c.Value())
	}

	c.Add(5)
	if c.Value() != 6 {
		t.Errorf("Expected value 6 after Add(5), got %d", c.Value())
	}
}

func TestCounterWithLabels(t *testing.T) {
	m := New()
	c := m.NewCounter("test_counter", "A test counter", map[string]string{"method": "GET"})

	c.Inc()

	output := m.String()
	if !strings.Contains(output, `test_counter{method="GET"} 1`) {
		t.Errorf("Expected labeled output, got: %s", output)
	}
}

func TestGauge(t *testing.T) {
	m := New()
	g := m.NewGauge("test_gauge", "A test gauge", nil)

	if g.Value() != 0 {
		t.Errorf("Expected initial value 0, got %v", g.Value())
	}

	g.Set(42.5)
	if g.Value() != 42 { // truncated to int
		t.Errorf("Expected value 42, got %v", g.Value())
	}

	g.Inc()
	if g.Value() != 43 {
		t.Errorf("Expected value 43 after Inc, got %v", g.Value())
	}

	g.Dec()
	if g.Value() != 42 {
		t.Errorf("Expected value 42 after Dec, got %v", g.Value())
	}
}

func TestHistogram(t *testing.T) {
	m := New()
	h := m.NewHistogram("test_histogram", "A test histogram", []float64{0.1, 0.5, 1.0}, nil)

	h.Observe(0.05) // Should be in 0.1 bucket
	h.Observe(0.3)  // Should be in 0.5 bucket
	h.Observe(0.8)  // Should be in 1.0 bucket
	h.Observe(2.0)  // Should only be in +Inf bucket

	output := m.String()

	// Check buckets
	if !strings.Contains(output, `test_histogram_bucket{le="0.1"} 1`) {
		t.Errorf("Expected 0.1 bucket count 1, got: %s", output)
	}
	if !strings.Contains(output, `test_histogram_bucket{le="0.5"} 2`) {
		t.Errorf("Expected 0.5 bucket count 2, got: %s", output)
	}
	if !strings.Contains(output, `test_histogram_bucket{le="1"} 3`) {
		t.Errorf("Expected 1.0 bucket count 3, got: %s", output)
	}
	if !strings.Contains(output, `test_histogram_bucket{le="+Inf"} 4`) {
		t.Errorf("Expected +Inf bucket count 4, got: %s", output)
	}

	// Check count
	if !strings.Contains(output, "test_histogram_count 4") {
		t.Errorf("Expected count 4, got: %s", output)
	}
}

func TestHistogramObserveDuration(t *testing.T) {
	m := New()
	h := m.NewHistogram("test_duration", "Test duration", DefaultBuckets, nil)

	start := time.Now()
	time.Sleep(10 * time.Millisecond)
	h.ObserveDuration(start)

	output := m.String()
	if !strings.Contains(output, "test_duration_count 1") {
		t.Errorf("Expected count 1, got: %s", output)
	}
}

func TestMetricsString(t *testing.T) {
	m := New()
	m.NewCounter("requests_total", "Total requests", nil)
	m.NewGauge("active_connections", "Active connections", nil)

	output := m.String()

	if !strings.Contains(output, "# HELP requests_total Total requests") {
		t.Error("Missing HELP for counter")
	}
	if !strings.Contains(output, "# TYPE requests_total counter") {
		t.Error("Missing TYPE for counter")
	}
	if !strings.Contains(output, "# HELP active_connections Active connections") {
		t.Error("Missing HELP for gauge")
	}
	if !strings.Contains(output, "# TYPE active_connections gauge") {
		t.Error("Missing TYPE for gauge")
	}
}

func TestFormatLabels(t *testing.T) {
	tests := []struct {
		labels   map[string]string
		expected string
	}{
		{nil, ""},
		{map[string]string{}, ""},
		{map[string]string{"a": "1"}, `{a="1"}`},
		{map[string]string{"a": "1", "b": "2"}, `{a="1",b="2"}`},
	}

	for _, tt := range tests {
		result := formatLabels(tt.labels)
		if result != tt.expected {
			t.Errorf("formatLabels(%v) = %q, want %q", tt.labels, result, tt.expected)
		}
	}
}

func TestAppMetrics(t *testing.T) {
	am := NewAppMetrics()

	am.TunnelConnected()
	if am.ActiveTunnels.Value() != 1 {
		t.Errorf("Expected 1 active tunnel, got %v", am.ActiveTunnels.Value())
	}
	if am.TunnelConnections.Value() != 1 {
		t.Errorf("Expected 1 total connection, got %d", am.TunnelConnections.Value())
	}

	am.TunnelDisconnected()
	if am.ActiveTunnels.Value() != 0 {
		t.Errorf("Expected 0 active tunnels, got %v", am.ActiveTunnels.Value())
	}

	am.TunnelError()
	if am.TunnelErrors.Value() != 1 {
		t.Errorf("Expected 1 error, got %d", am.TunnelErrors.Value())
	}
}
