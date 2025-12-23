package errors

import (
	"errors"
	"testing"
)

func TestAppError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *AppError
		expected string
	}{
		{
			name:     "without cause",
			err:      New(CodeNotFound, "user not found"),
			expected: "NOT_FOUND: user not found",
		},
		{
			name:     "with cause",
			err:      Wrap(ErrNotFound, CodeNotFound, "user not found"),
			expected: "NOT_FOUND: user not found (not found)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestAppError_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	appErr := Wrap(cause, CodeInternal, "wrapped")

	if !errors.Is(appErr, cause) {
		t.Error("errors.Is should return true for wrapped cause")
	}
}

func TestNotFound(t *testing.T) {
	err := NotFound("user")

	if err.Code != CodeNotFound {
		t.Errorf("Code = %q, want %q", err.Code, CodeNotFound)
	}
	if err.Message != "user not found" {
		t.Errorf("Message = %q, want %q", err.Message, "user not found")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Error("should wrap ErrNotFound")
	}
}

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"ErrNotFound", ErrNotFound, true},
		{"wrapped ErrNotFound", NotFound("test"), true},
		{"different error", ErrUnauthorized, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFound(tt.err); got != tt.expected {
				t.Errorf("IsNotFound() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"AppError", New(CodeNotFound, "test"), CodeNotFound},
		{"regular error", errors.New("test"), CodeInternal},
		{"wrapped AppError", Wrap(ErrNotFound, CodeUnauthorized, "test"), CodeUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetCode(tt.err); got != tt.expected {
				t.Errorf("GetCode() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestDBError(t *testing.T) {
	cause := errors.New("connection failed")
	err := DBError("query", cause)

	if err.Code != CodeDBError {
		t.Errorf("Code = %q, want %q", err.Code, CodeDBError)
	}
	if err.Message != "database error during query" {
		t.Errorf("Message = %q, want %q", err.Message, "database error during query")
	}
	if !errors.Is(err, cause) {
		t.Error("should wrap cause")
	}
}
