package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
)

// contextKey is a private type for context keys.
type contextKey string

const (
	// RequestIDKey is the context key for request ID.
	RequestIDKey contextKey = "request_id"
)

var (
	// defaultLogger is the global logger instance.
	defaultLogger *slog.Logger
	once          sync.Once
)

// Config holds logging configuration.
type Config struct {
	// Level is the minimum log level to output.
	Level slog.Level
	// Format is the output format: "json" or "text".
	Format string
	// Output is where logs are written. Defaults to os.Stderr.
	Output io.Writer
	// AddSource adds source file and line to log entries.
	AddSource bool
}

// DefaultConfig returns sensible defaults for production.
func DefaultConfig() Config {
	return Config{
		Level:     slog.LevelInfo,
		Format:    "json",
		Output:    os.Stderr,
		AddSource: false,
	}
}

// DevConfig returns defaults optimized for development.
func DevConfig() Config {
	return Config{
		Level:     slog.LevelDebug,
		Format:    "text",
		Output:    os.Stderr,
		AddSource: true,
	}
}

// Init initializes the global logger with the given configuration.
// Safe to call multiple times; only the first call takes effect.
func Init(cfg Config) {
	once.Do(func() {
		defaultLogger = NewLogger(cfg)
		slog.SetDefault(defaultLogger)
	})
}

// NewLogger creates a new slog.Logger with the given configuration.
func NewLogger(cfg Config) *slog.Logger {
	if cfg.Output == nil {
		cfg.Output = os.Stderr
	}

	opts := &slog.HandlerOptions{
		Level:     cfg.Level,
		AddSource: cfg.AddSource,
	}

	var handler slog.Handler
	if cfg.Format == "json" {
		handler = slog.NewJSONHandler(cfg.Output, opts)
	} else {
		handler = slog.NewTextHandler(cfg.Output, opts)
	}

	return slog.New(handler)
}

// L returns the default logger.
func L() *slog.Logger {
	if defaultLogger == nil {
		Init(DefaultConfig())
	}
	return defaultLogger
}

// WithRequestID returns a logger with the request ID attached.
func WithRequestID(ctx context.Context) *slog.Logger {
	logger := L()
	if reqID, ok := ctx.Value(RequestIDKey).(string); ok {
		return logger.With(slog.String("request_id", reqID))
	}
	return logger
}

// WithFields returns a logger with the given fields attached.
func WithFields(fields ...any) *slog.Logger {
	return L().With(fields...)
}

// Debug logs a debug message.
func Debug(msg string, args ...any) {
	L().Debug(msg, args...)
}

// Info logs an info message.
func Info(msg string, args ...any) {
	L().Info(msg, args...)
}

// Warn logs a warning message.
func Warn(msg string, args ...any) {
	L().Warn(msg, args...)
}

// Error logs an error message.
func Error(msg string, args ...any) {
	L().Error(msg, args...)
}

// DebugContext logs a debug message with context.
func DebugContext(ctx context.Context, msg string, args ...any) {
	WithRequestID(ctx).DebugContext(ctx, msg, args...)
}

// InfoContext logs an info message with context.
func InfoContext(ctx context.Context, msg string, args ...any) {
	WithRequestID(ctx).InfoContext(ctx, msg, args...)
}

// WarnContext logs a warning message with context.
func WarnContext(ctx context.Context, msg string, args ...any) {
	WithRequestID(ctx).WarnContext(ctx, msg, args...)
}

// ErrorContext logs an error message with context.
func ErrorContext(ctx context.Context, msg string, args ...any) {
	WithRequestID(ctx).ErrorContext(ctx, msg, args...)
}
