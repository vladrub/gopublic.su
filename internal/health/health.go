package health

import (
	"net/http"
	"sync/atomic"

	"github.com/gin-gonic/gin"
)

// Checker provides health check endpoints for Kubernetes/load balancers.
type Checker struct {
	// ready indicates if the service is ready to receive traffic
	ready atomic.Bool
	// checks are the readiness checks to run
	checks []ReadinessCheck
}

// ReadinessCheck is a function that returns an error if the check fails.
type ReadinessCheck func() error

// CheckResult represents the result of a health check.
type CheckResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// HealthResponse is the response format for health endpoints.
type HealthResponse struct {
	Status string        `json:"status"`
	Checks []CheckResult `json:"checks,omitempty"`
}

// NewChecker creates a new health checker with the given readiness checks.
func NewChecker(checks ...ReadinessCheck) *Checker {
	c := &Checker{
		checks: checks,
	}
	c.ready.Store(true)
	return c
}

// SetReady sets the ready state of the checker.
func (c *Checker) SetReady(ready bool) {
	c.ready.Store(ready)
}

// IsReady returns whether the service is ready.
func (c *Checker) IsReady() bool {
	return c.ready.Load()
}

// RegisterRoutes registers health check endpoints on the given router.
func (c *Checker) RegisterRoutes(r *gin.Engine) {
	health := r.Group("/health")
	{
		health.GET("/live", c.LiveHandler)
		health.GET("/ready", c.ReadyHandler)
	}
}

// LiveHandler returns 200 if the process is alive.
// Used by Kubernetes liveness probe.
func (c *Checker) LiveHandler(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, HealthResponse{
		Status: "ok",
	})
}

// ReadyHandler returns 200 if the service is ready to receive traffic.
// Used by Kubernetes readiness probe.
func (c *Checker) ReadyHandler(ctx *gin.Context) {
	if !c.ready.Load() {
		ctx.JSON(http.StatusServiceUnavailable, HealthResponse{
			Status: "not_ready",
		})
		return
	}

	// Run all readiness checks
	var results []CheckResult
	allOk := true

	for i, check := range c.checks {
		result := CheckResult{
			Name:   checkName(i),
			Status: "ok",
		}

		if err := check(); err != nil {
			result.Status = "error"
			result.Error = err.Error()
			allOk = false
		}

		results = append(results, result)
	}

	status := "ok"
	statusCode := http.StatusOK
	if !allOk {
		status = "degraded"
		statusCode = http.StatusServiceUnavailable
	}

	ctx.JSON(statusCode, HealthResponse{
		Status: status,
		Checks: results,
	})
}

// checkName returns a name for check at index i.
func checkName(i int) string {
	names := []string{"database", "registry", "config"}
	if i < len(names) {
		return names[i]
	}
	return "check"
}

// DBCheck creates a readiness check for database connectivity.
// The pingFunc should return nil if the database is reachable.
func DBCheck(pingFunc func() error) ReadinessCheck {
	return pingFunc
}
