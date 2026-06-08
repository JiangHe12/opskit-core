// Package apperrors defines shared error codes and exit-code mapping.
package apperrors

import (
	"bytes"
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
)

// ErrorCode is a stable machine-readable error code.
type ErrorCode string

// Code is kept as a short alias for consumers that name error codes tersely.
type Code = ErrorCode

const (
	CodeUsageError             ErrorCode = "USAGE_ERROR"
	CodeNetworkError           ErrorCode = "NETWORK_ERROR"
	CodeAuthFailed             ErrorCode = "AUTH_FAILED"
	CodeResourceNotFound       ErrorCode = "RESOURCE_NOT_FOUND"
	CodeResourceAlreadyExists  ErrorCode = "RESOURCE_ALREADY_EXISTS"
	CodeLocalIOError           ErrorCode = "LOCAL_IO_ERROR"
	CodeServerError            ErrorCode = "SERVER_ERROR"
	CodeBackendUnreachable     ErrorCode = "BACKEND_UNREACHABLE"
	CodeBackendError           ErrorCode = "BACKEND_ERROR"
	CodeAuthorizationRequired  ErrorCode = "AUTHORIZATION_REQUIRED"
	CodeValidationFailed       ErrorCode = "VALIDATION_FAILED"
	CodeConflict               ErrorCode = "CONFLICT"
	CodePartialFailure         ErrorCode = "PARTIAL_FAILURE"
	CodeNoChangeRequired       ErrorCode = "NO_CHANGE_REQUIRED"
	CodeUnsupportedProtocol    ErrorCode = "UNSUPPORTED_PROTOCOL"
	CodeNotImplemented         ErrorCode = "NOT_IMPLEMENTED"
	CodeCredentialStoreError   ErrorCode = "CREDENTIAL_STORE_ERROR"   //nolint:gosec // Error code constant, not a credential.
	CodeCredentialStoreMissing ErrorCode = "CREDENTIAL_STORE_MISSING" //nolint:gosec // Error code constant, not a credential.
)

// Options configures package-level error rendering defaults.
type Options struct {
	APIVersion                 string
	Suggestions                map[ErrorCode]string
	Codes                      []ErrorCode
	ResourceNotFoundSubstrings []string
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
	if next.Codes != nil {
		options.Codes = append([]ErrorCode(nil), next.Codes...)
	}
	if next.ResourceNotFoundSubstrings != nil {
		options.ResourceNotFoundSubstrings = append([]string(nil), next.ResourceNotFoundSubstrings...)
	}
}

// ErrorCause is diagnostic-only. Machine consumers MUST use Code, not Cause.
type ErrorCause struct {
	Layer  string `json:"layer"`
	Detail string `json:"detail"`
}

// AppError carries structured error information for humans and JSON consumers.
type AppError struct {
	Code            ErrorCode   `json:"code"`
	Message         string      `json:"message"`
	Suggestion      string      `json:"suggestion,omitempty"`
	Cause           string      `json:"cause,omitempty"`
	StructuredCause *ErrorCause `json:"-"`
	HTTPStatus      int         `json:"-"`
	Retryable       bool        `json:"-"`
	Err             error       `json:"-"`
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
	appErr := &AppError{
		Code:       code,
		Message:    message,
		Suggestion: defaultSuggestion(code),
		Retryable:  code == CodeNetworkError || code == CodeServerError || code == CodeBackendUnreachable || code == CodeBackendError,
		Err:        cause,
	}
	if cause != nil {
		appErr.Cause = cause.Error()
	}
	return appErr
}

// MarshalJSON writes the stable public error shape. StructuredCause lets tools
// that need diagnostic subfields emit the same "cause" key without changing
// the string Cause field used by existing consumers.
func (e *AppError) MarshalJSON() ([]byte, error) {
	type appErrorJSON struct {
		Code       ErrorCode `json:"code"`
		Message    string    `json:"message"`
		Suggestion string    `json:"suggestion,omitempty"`
		Cause      any       `json:"cause,omitempty"`
	}
	if e == nil {
		return []byte("null"), nil
	}
	var cause any
	if e.StructuredCause != nil {
		cause = e.StructuredCause
	} else if e.Cause != "" {
		cause = e.Cause
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(appErrorJSON{
		Code:       e.Code,
		Message:    e.Message,
		Suggestion: e.Suggestion,
		Cause:      cause,
	}); err != nil {
		return nil, err
	}
	return bytes.TrimRight(out.Bytes(), "\n"), nil
}

// WithSuggestion overrides the default recovery hint.
func (e *AppError) WithSuggestion(suggestion string) *AppError {
	if e == nil {
		return e //nolint:nilerr // method chaining guard
	}
	e.Suggestion = suggestion
	return e
}

// FromHTTP maps an HTTP status to a structured AppError.
func FromHTTP(statusCode int, message string) *AppError {
	var err *AppError
	switch {
	case statusCode == 401 || statusCode == 403:
		err = New(CodeAuthFailed, message, nil)
	case statusCode == 404:
		err = New(CodeResourceNotFound, message, nil)
	case statusCode >= 500 && isKnownResourceNotFound(strings.ToLower(message)):
		err = New(CodeResourceNotFound, message, nil)
	case statusCode >= 500:
		err = New(CodeServerError, message, nil)
	default:
		err = New(CodeUsageError, message, nil)
	}
	err.HTTPStatus = statusCode
	return err
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
		return New(CodeNetworkError, "operation timed out", err)
	}
	if os.IsNotExist(err) {
		return New(CodeLocalIOError, "local file not found", err)
	}
	if isCobraParserError(err) {
		return New(CodeUsageError, strings.TrimSpace(err.Error()), nil)
	}
	if isNetworkError(err) {
		return New(CodeNetworkError, "network error", err)
	}
	return New(CodeLocalIOError, strings.TrimSpace(err.Error()), nil)
}

// ExitCode returns the process exit code for an error.
func ExitCode(err error) int {
	appErr := AsAppError(err)
	if appErr == nil {
		return 0
	}
	switch appErr.Code {
	case CodeUsageError:
		return 1
	case CodeNetworkError, CodeBackendUnreachable:
		return 2
	case CodeAuthFailed:
		return 3
	case CodeResourceNotFound:
		return 4
	case CodeResourceAlreadyExists:
		return 5
	case CodeLocalIOError, CodeCredentialStoreError, CodeCredentialStoreMissing:
		return 6
	case CodeServerError, CodeBackendError:
		return 7
	case CodeAuthorizationRequired:
		return 8
	case CodeValidationFailed:
		return 9
	case CodeConflict:
		return 10
	case CodePartialFailure:
		return 11
	case CodeUnsupportedProtocol, CodeNotImplemented:
		return 12
	case CodeNoChangeRequired:
		return 13
	default:
		return 1
	}
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
	if options.Codes != nil {
		return append([]ErrorCode(nil), options.Codes...)
	}
	return []ErrorCode{
		CodeUsageError,
		CodeNetworkError,
		CodeAuthFailed,
		CodeResourceNotFound,
		CodeResourceAlreadyExists,
		CodeLocalIOError,
		CodeServerError,
		CodeBackendUnreachable,
		CodeBackendError,
		CodeAuthorizationRequired,
		CodeValidationFailed,
		CodeConflict,
		CodePartialFailure,
		CodeUnsupportedProtocol,
		CodeNotImplemented,
		CodeNoChangeRequired,
		CodeCredentialStoreError,
		CodeCredentialStoreMissing,
	}
}

// AllExitCodes returns every possible process exit code, including success.
func AllExitCodes() []int {
	codes := make([]int, 0, 14)
	codes = append(codes, 0)
	seen := make(map[int]bool)
	for _, code := range AllCodes() {
		exit := ExitCode(&AppError{Code: code})
		if !seen[exit] {
			codes = append(codes, exit)
			seen[exit] = true
		}
	}
	return codes
}

func isNetworkError(err error) bool {
	var netErr net.Error
	if stderrors.As(err, &netErr) {
		return true
	}
	var urlErr *url.Error
	if stderrors.As(err, &urlErr) {
		return true
	}
	var opErr *net.OpError
	if stderrors.As(err, &opErr) {
		return true
	}
	var dnsErr *net.DNSError
	if stderrors.As(err, &dnsErr) {
		return true
	}
	var sysErr syscall.Errno
	if stderrors.As(err, &sysErr) {
		switch sysErr {
		case syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.EHOSTUNREACH,
			syscall.ENETUNREACH, syscall.ETIMEDOUT, syscall.EPIPE:
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "dial tcp") ||
		strings.Contains(msg, "tls handshake") ||
		strings.Contains(msg, "i/o timeout")
}

func isCobraParserError(err error) bool {
	msg := err.Error()
	return strings.HasPrefix(msg, "unknown command") ||
		strings.HasPrefix(msg, "unknown flag") ||
		strings.HasPrefix(msg, "unknown shorthand flag") ||
		strings.HasPrefix(msg, "required flag(s)") ||
		strings.HasPrefix(msg, "flag needs an argument") ||
		strings.HasPrefix(msg, "invalid argument") ||
		strings.HasPrefix(msg, "bad flag syntax") ||
		strings.HasPrefix(msg, "requires at least ") ||
		strings.HasPrefix(msg, "accepts ")
}

func isKnownResourceNotFound(msg string) bool {
	for _, substring := range options.ResourceNotFoundSubstrings {
		if strings.Contains(msg, substring) {
			return true
		}
	}
	return false
}

func defaultSuggestion(code ErrorCode) string {
	if options.Suggestions == nil {
		return ""
	}
	return options.Suggestions[code]
}
