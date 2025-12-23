package errors

import (
	"errors"
	"fmt"
)

// Sentinel errors - common across packages
var (
	ErrNotFound       = errors.New("not found")
	ErrUnauthorized   = errors.New("unauthorized")
	ErrForbidden      = errors.New("forbidden")
	ErrInvalidInput   = errors.New("invalid input")
	ErrInternal       = errors.New("internal error")
	ErrSessionExpired = errors.New("session expired")
	ErrDuplicateKey   = errors.New("duplicate key")
)

// Error codes for structured error responses
const (
	CodeNotFound       = "NOT_FOUND"
	CodeUnauthorized   = "UNAUTHORIZED"
	CodeForbidden      = "FORBIDDEN"
	CodeInvalidInput   = "INVALID_INPUT"
	CodeInternal       = "INTERNAL_ERROR"
	CodeSessionExpired = "SESSION_EXPIRED"
	CodeDuplicateKey   = "DUPLICATE_KEY"
	CodeDBError        = "DATABASE_ERROR"
	CodeConfigError    = "CONFIG_ERROR"
)

// AppError provides structured error information for API responses and logging.
type AppError struct {
	Code    string // Machine-readable error code
	Message string // Human-readable message
	Cause   error  // Underlying error (optional)
}

// Error implements the error interface.
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *AppError) Unwrap() error {
	return e.Cause
}

// New creates a new AppError.
func New(code, message string) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
	}
}

// Wrap creates a new AppError wrapping an existing error.
func Wrap(cause error, code, message string) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// Wrapf creates a new AppError with a formatted message.
func Wrapf(cause error, code, format string, args ...interface{}) *AppError {
	return &AppError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
		Cause:   cause,
	}
}

// NotFound creates a not found error.
func NotFound(resource string) *AppError {
	return &AppError{
		Code:    CodeNotFound,
		Message: fmt.Sprintf("%s not found", resource),
		Cause:   ErrNotFound,
	}
}

// Unauthorized creates an unauthorized error.
func Unauthorized(message string) *AppError {
	return &AppError{
		Code:    CodeUnauthorized,
		Message: message,
		Cause:   ErrUnauthorized,
	}
}

// Forbidden creates a forbidden error.
func Forbidden(message string) *AppError {
	return &AppError{
		Code:    CodeForbidden,
		Message: message,
		Cause:   ErrForbidden,
	}
}

// InvalidInput creates an invalid input error.
func InvalidInput(message string) *AppError {
	return &AppError{
		Code:    CodeInvalidInput,
		Message: message,
		Cause:   ErrInvalidInput,
	}
}

// Internal creates an internal error.
func Internal(message string, cause error) *AppError {
	return &AppError{
		Code:    CodeInternal,
		Message: message,
		Cause:   cause,
	}
}

// DBError creates a database error.
func DBError(operation string, cause error) *AppError {
	return &AppError{
		Code:    CodeDBError,
		Message: fmt.Sprintf("database error during %s", operation),
		Cause:   cause,
	}
}

// IsNotFound checks if an error is a not found error.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// IsUnauthorized checks if an error is an unauthorized error.
func IsUnauthorized(err error) bool {
	return errors.Is(err, ErrUnauthorized)
}

// IsForbidden checks if an error is a forbidden error.
func IsForbidden(err error) bool {
	return errors.Is(err, ErrForbidden)
}

// GetCode extracts the error code from an error.
// Returns CodeInternal if the error is not an AppError.
func GetCode(err error) string {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code
	}
	return CodeInternal
}

// GetMessage extracts the message from an error.
func GetMessage(err error) string {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Message
	}
	return err.Error()
}
