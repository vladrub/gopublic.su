package metrics

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// Metrics holds all application metrics.
type Metrics struct {
	// counters stores counter metrics
	counters map[string]*Counter
	// gauges stores gauge metrics
	gauges map[string]*Gauge
	// histograms stores histogram metrics
	histograms map[string]*Histogram
	mu         sync.RWMutex
}

// Counter is a monotonically increasing counter.
type Counter struct {
	name   string
	help   string
	value  atomic.Int64
	labels map[string]string
}

// Gauge is a metric that can go up or down.
type Gauge struct {
	name   string
	help   string
	value  atomic.Int64 // stores float64 as int64 bits
	labels map[string]string
}

// Histogram tracks value distributions.
type Histogram struct {
	name    string
	help    string
	buckets []float64
	counts  []atomic.Uint64 // one per bucket + inf
	sum     atomic.Uint64   // stores float64 as uint64 bits
	count   atomic.Uint64
	labels  map[string]string
	mu      sync.Mutex
}

// New creates a new Metrics instance.
func New() *Metrics {
	return &Metrics{
		counters:   make(map[string]*Counter),
		gauges:     make(map[string]*Gauge),
		histograms: make(map[string]*Histogram),
	}
}

// Counter operations

// NewCounter creates and registers a new counter.
func (m *Metrics) NewCounter(name, help string, labels map[string]string) *Counter {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := metricKey(name, labels)
	c := &Counter{name: name, help: help, labels: labels}
	m.counters[key] = c
	return c
}

// Inc increments the counter by 1.
func (c *Counter) Inc() {
	c.value.Add(1)
}

// Add adds the given value to the counter.
func (c *Counter) Add(v int64) {
	c.value.Add(v)
}

// Value returns the current counter value.
func (c *Counter) Value() int64 {
	return c.value.Load()
}

// Gauge operations

// NewGauge creates and registers a new gauge.
func (m *Metrics) NewGauge(name, help string, labels map[string]string) *Gauge {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := metricKey(name, labels)
	g := &Gauge{name: name, help: help, labels: labels}
	m.gauges[key] = g
	return g
}

// Set sets the gauge to the given value.
func (g *Gauge) Set(v float64) {
	g.value.Store(int64(v))
}

// Inc increments the gauge by 1.
func (g *Gauge) Inc() {
	g.value.Add(1)
}

// Dec decrements the gauge by 1.
func (g *Gauge) Dec() {
	g.value.Add(-1)
}

// Value returns the current gauge value.
func (g *Gauge) Value() float64 {
	return float64(g.value.Load())
}

// Histogram operations

// DefaultBuckets are the default histogram buckets for request durations.
var DefaultBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// NewHistogram creates and registers a new histogram.
func (m *Metrics) NewHistogram(name, help string, buckets []float64, labels map[string]string) *Histogram {
	m.mu.Lock()
	defer m.mu.Unlock()

	if buckets == nil {
		buckets = DefaultBuckets
	}

	key := metricKey(name, labels)
	h := &Histogram{
		name:    name,
		help:    help,
		buckets: buckets,
		counts:  make([]atomic.Uint64, len(buckets)+1), // +1 for +Inf
		labels:  labels,
	}
	m.histograms[key] = h
	return h
}

// Observe adds a single observation to the histogram.
func (h *Histogram) Observe(v float64) {
	h.count.Add(1)

	// Add to sum (using uint64 bit representation of float64)
	for {
		oldBits := h.sum.Load()
		oldVal := float64FromBits(oldBits)
		newVal := oldVal + v
		newBits := float64ToBits(newVal)
		if h.sum.CompareAndSwap(oldBits, newBits) {
			break
		}
	}

	// Increment bucket counts
	for i, bucket := range h.buckets {
		if v <= bucket {
			h.counts[i].Add(1)
		}
	}
	// Always increment +Inf bucket
	h.counts[len(h.buckets)].Add(1)
}

// ObserveDuration is a helper to observe request duration.
func (h *Histogram) ObserveDuration(start time.Time) {
	h.Observe(time.Since(start).Seconds())
}

// Handler returns an HTTP handler that serves metrics in Prometheus format.
func (m *Metrics) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Type", "text/plain; version=0.0.4")
		c.String(http.StatusOK, m.String())
	}
}

// String returns all metrics in Prometheus exposition format.
func (m *Metrics) String() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var b strings.Builder

	// Output counters
	for _, c := range m.counters {
		fmt.Fprintf(&b, "# HELP %s %s\n", c.name, c.help)
		fmt.Fprintf(&b, "# TYPE %s counter\n", c.name)
		fmt.Fprintf(&b, "%s%s %d\n", c.name, formatLabels(c.labels), c.value.Load())
	}

	// Output gauges
	for _, g := range m.gauges {
		fmt.Fprintf(&b, "# HELP %s %s\n", g.name, g.help)
		fmt.Fprintf(&b, "# TYPE %s gauge\n", g.name)
		fmt.Fprintf(&b, "%s%s %v\n", g.name, formatLabels(g.labels), g.Value())
	}

	// Output histograms
	for _, h := range m.histograms {
		fmt.Fprintf(&b, "# HELP %s %s\n", h.name, h.help)
		fmt.Fprintf(&b, "# TYPE %s histogram\n", h.name)

		labels := formatLabels(h.labels)

		// Bucket counts
		for i, bucket := range h.buckets {
			bucketLabels := addLabel(h.labels, "le", fmt.Sprintf("%v", bucket))
			fmt.Fprintf(&b, "%s_bucket%s %d\n", h.name, formatLabels(bucketLabels), h.counts[i].Load())
		}
		// +Inf bucket
		infLabels := addLabel(h.labels, "le", "+Inf")
		fmt.Fprintf(&b, "%s_bucket%s %d\n", h.name, formatLabels(infLabels), h.counts[len(h.buckets)].Load())

		// Sum and count
		fmt.Fprintf(&b, "%s_sum%s %v\n", h.name, labels, float64FromBits(h.sum.Load()))
		fmt.Fprintf(&b, "%s_count%s %d\n", h.name, labels, h.count.Load())
	}

	return b.String()
}

// Helper functions

func metricKey(name string, labels map[string]string) string {
	return name + formatLabels(labels)
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}

	// Sort keys for consistent output
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%q", k, labels[k]))
	}

	return "{" + strings.Join(parts, ",") + "}"
}

func addLabel(labels map[string]string, key, value string) map[string]string {
	result := make(map[string]string, len(labels)+1)
	for k, v := range labels {
		result[k] = v
	}
	result[key] = value
	return result
}

func float64ToBits(f float64) uint64 {
	return math.Float64bits(f)
}

func float64FromBits(b uint64) float64 {
	return math.Float64frombits(b)
}
