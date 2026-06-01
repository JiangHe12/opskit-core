// Package apperrors defines shared error codes and exit-code mapping.
package apperrors

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ErrorCode is a stable machine-readable error code.
type ErrorCode string

const (
	CodeUsageError             ErrorCode = "USAGE_ERROR"
	CodeLocalIOError           ErrorCode = "LOCAL_IO_ERROR"
	CodeBackendUnreachable     ErrorCode = "BACKEND_UNREACHABLE"
	CodeBackendError           ErrorCode = "BACKEND_ERROR"
	CodeAuthorizationRequired  ErrorCode = "AUTHORIZATION_REQUIRED"
	CodeValidationFailed       ErrorCode = "VALIDATION_FAILED"
	CodeNoChangeRequired       ErrorCode = "NO_CHANGE_REQUIRED"
	CodeUnsupportedProtocol    ErrorCode = "UNSUPPORTED_PROTOCOL"
	CodeNotImplemented         ErrorCode = "NOT_IMPLEMENTED"
	CodeCredentialStoreError   ErrorCode = "CREDENTIAL_STORE_ERROR"   //nolint:gosec // Error code constant, not a credential.
	CodeCredentialStoreMissing ErrorCode = "CREDENTIAL_STORE_MISSING" //nolint:gosec // Error code constant, not a credential.
)

// Options configures package-level error rendering defaults.
type Options struct {
	APIVersion  string
	Suggestions map[ErrorCode]string
}

var options = Options{APIVersion: "opskit-core.io/v1"}

// Configure sets package-level error rendering defaults for a consumer CLI.
func Configure(next Options) {
	if next.APIVersion != "" {
		options.APIVersion = next.APIVersion
	}
	if next.Suggestions != nil {
		options.Suggestions = make(map[ErrorCode]string, len(next.Suggestions))
		for code, suggestion := range next.Suggestions {
			options.Suggestions[code] = suggestion
		}
	}
}

// AppError carries structured error information for humans and JSON consumers.
type AppError struct {
	Code       ErrorCode `json:"code"`
	Message    string    `json:"message"`
	Suggestion string    `json:"suggestion,omitempty"`
	Cause      string    `json:"cause,omitempty"`
	Err        error     `json:"-"`
}

// Error returns the human-readable message with wrapped cause when present.
func (e *AppError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap returns the underlying cause.
func (e *AppError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// New creates an AppError.
func New(code ErrorCode, message string, cause error) *AppError {
	appErr := &AppError{Code: code, Message: message, Suggestion: defaultSuggestion(code), Err: cause}
	if cause != nil {
		appErr.Cause = cause.Error()
	}
	return appErr
}

// WithSuggestion overrides the default recovery hint.
func (e *AppError) WithSuggestion(suggestion string) *AppError {
	if e == nil {
		return e //nolint:nilerr // method chaining guard
	}
	e.Suggestion = suggestion
	return e
}

// AsAppError converts arbitrary errors to AppError.
func AsAppError(err error) *AppError {
	if err == nil {
		return nil
	}
	var appErr *AppError
	if stderrors.As(err, &appErr) {
		return appErr
	}
	if stderrors.Is(err, context.Canceled) {
		return New(CodeUsageError, "operation canceled", err)
	}
	if stderrors.Is(err, context.DeadlineExceeded) {
		return New(CodeBackendUnreachable, "operation timed out", err)
	}
	if os.IsNotExist(err) {
		return New(CodeLocalIOError, "local file not found", err)
	}
	return New(CodeLocalIOError, strings.TrimSpace(err.Error()), nil)
}

// ExitCode returns the process exit code for an error.
func ExitCode(err error) int {
	appErr := AsAppError(err)
	if appErr == nil {
		return 0
	}
	if appErr.Code == CodeNoChangeRequired {
		return 13
	}
	return 1
}

// WriteJSON writes a standard JSON error object.
func WriteJSON(w io.Writer, err error) error {
	response := struct {
		APIVersion string    `json:"apiVersion"`
		Kind       string    `json:"kind"`
		Success    bool      `json:"success"`
		Error      *AppError `json:"error"`
	}{
		APIVersion: options.APIVersion,
		Kind:       "Error",
		Success:    false,
		Error:      AsAppError(err),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(response)
}

// AllCodes returns all defined error codes in declaration order.
func AllCodes() []ErrorCode {
	return []ErrorCode{
		CodeUsageError,
		CodeLocalIOError,
		CodeBackendUnreachable,
		CodeBackendError,
		CodeAuthorizationRequired,
		CodeValidationFailed,
		CodeNoChangeRequired,
		CodeUnsupportedProtocol,
		CodeNotImplemented,
		CodeCredentialStoreError,
		CodeCredentialStoreMissing,
	}
}

func defaultSuggestion(code ErrorCode) string {
	if options.Suggestions == nil {
		return ""
	}
	return options.Suggestions[code]
}
