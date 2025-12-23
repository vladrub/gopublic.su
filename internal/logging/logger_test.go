package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNewLogger_JSON(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:  slog.LevelInfo,
		Format: "json",
		Output: &buf,
	}

	logger := NewLogger(cfg)
	logger.Info("test message", slog.String("key", "value"))

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse JSON log: %v", err)
	}

	if entry["msg"] != "test message" {
		t.Errorf("Expected msg 'test message', got %v", entry["msg"])
	}
	if entry["key"] != "value" {
		t.Errorf("Expected key 'value', got %v", entry["key"])
	}
}

func TestNewLogger_Text(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:  slog.LevelInfo,
		Format: "text",
		Output: &buf,
	}

	logger := NewLogger(cfg)
	logger.Info("test message", slog.String("key", "value"))

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("Expected 'test message' in output, got: %s", output)
	}
	if !strings.Contains(output, "key=value") {
		t.Errorf("Expected 'key=value' in output, got: %s", output)
	}
}

func TestNewLogger_Levels(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:  slog.LevelWarn,
		Format: "text",
		Output: &buf,
	}

	logger := NewLogger(cfg)

	// Info should not be logged
	logger.Info("should not appear")
	if buf.Len() > 0 {
		t.Errorf("Info should not be logged at Warn level: %s", buf.String())
	}

	// Warn should be logged
	logger.Warn("should appear")
	if !strings.Contains(buf.String(), "should appear") {
		t.Errorf("Warn should be logged: %s", buf.String())
	}
}

func TestWithRequestID(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:  slog.LevelInfo,
		Format: "json",
		Output: &buf,
	}

	// Reset the default logger for this test
	defaultLogger = NewLogger(cfg)

	ctx := context.WithValue(context.Background(), RequestIDKey, "test-request-123")
	WithRequestID(ctx).Info("test with request id")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse JSON log: %v", err)
	}

	if entry["request_id"] != "test-request-123" {
		t.Errorf("Expected request_id 'test-request-123', got %v", entry["request_id"])
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Level != slog.LevelInfo {
		t.Errorf("Expected Info level, got %v", cfg.Level)
	}
	if cfg.Format != "json" {
		t.Errorf("Expected json format, got %s", cfg.Format)
	}
}

func TestDevConfig(t *testing.T) {
	cfg := DevConfig()

	if cfg.Level != slog.LevelDebug {
		t.Errorf("Expected Debug level, got %v", cfg.Level)
	}
	if cfg.Format != "text" {
		t.Errorf("Expected text format, got %s", cfg.Format)
	}
	if !cfg.AddSource {
		t.Error("Expected AddSource to be true")
	}
}
