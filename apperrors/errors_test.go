package apperrors

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"testing"
)

func TestAppErrorExitCodeAndSuggestion(t *testing.T) {
	err := New(CodeNoChangeRequired, "no changes", nil).WithSuggestion("remove --strict-no-change")

	if got := ExitCode(err); got != 13 {
		t.Fatalf("ExitCode() = %d, want 13", got)
	}
	if err.Suggestion != "remove --strict-no-change" {
		t.Fatalf("Suggestion = %q", err.Suggestion)
	}
}

func TestCanonicalExitCodes(t *testing.T) {
	tests := []struct {
		code ErrorCode
		want int
	}{
		{CodeUsageError, 1},
		{CodeNetworkError, 2},
		{CodeBackendUnreachable, 2},
		{CodeAuthFailed, 3},
		{CodeResourceNotFound, 4},
		{CodeResourceAlreadyExists, 5},
		{CodeLocalIOError, 6},
		{CodeCredentialStoreError, 6},
		{CodeCredentialStoreMissing, 6},
		{CodeServerError, 7},
		{CodeBackendError, 7},
		{CodeAuthorizationRequired, 8},
		{CodeValidationFailed, 9},
		{CodeConflict, 10},
		{CodePartialFailure, 11},
		{CodeUnsupportedProtocol, 12},
		{CodeNotImplemented, 12},
		{CodeNoChangeRequired, 13},
	}
	for _, tt := range tests {
		t.Run(string(tt.code), func(t *testing.T) {
			if got := ExitCode(&AppError{Code: tt.code}); got != tt.want {
				t.Fatalf("ExitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestAllExitCodes(t *testing.T) {
	want := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
	if got := AllExitCodes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("AllExitCodes() = %#v, want %#v", got, want)
	}
}

func TestAllCodesIncludesNacosCodes(t *testing.T) {
	want := []ErrorCode{
		CodeNetworkError,
		CodeAuthFailed,
		CodeResourceNotFound,
		CodeResourceAlreadyExists,
		CodeServerError,
		CodeConflict,
		CodePartialFailure,
	}
	got := map[ErrorCode]bool{}
	for _, code := range AllCodes() {
		got[code] = true
	}
	for _, code := range want {
		if !got[code] {
			t.Fatalf("AllCodes() missing %s", code)
		}
	}
}

func TestNewSetsRetryableForNetworkAndServerErrors(t *testing.T) {
	for _, code := range []ErrorCode{CodeNetworkError, CodeServerError} {
		if err := New(code, "msg", nil); !err.Retryable {
			t.Fatalf("New(%s).Retryable = false, want true", code)
		}
	}
	for _, code := range []ErrorCode{CodeUsageError, CodeAuthFailed, CodeResourceNotFound} {
		if err := New(code, "msg", nil); err.Retryable {
			t.Fatalf("New(%s).Retryable = true, want false", code)
		}
	}
}

func TestFromHTTP(t *testing.T) {
	tests := []struct {
		status int
		msg    string
		want   ErrorCode
	}{
		{401, "unauthorized", CodeAuthFailed},
		{403, "forbidden", CodeAuthFailed},
		{404, "not found", CodeResourceNotFound},
		{500, "internal error", CodeServerError},
		{502, "bad gateway", CodeServerError},
		{400, "bad request", CodeUsageError},
	}
	for _, tt := range tests {
		t.Run(tt.msg, func(t *testing.T) {
			err := FromHTTP(tt.status, tt.msg)
			if err.Code != tt.want {
				t.Fatalf("Code = %s, want %s", err.Code, tt.want)
			}
			if err.HTTPStatus != tt.status {
				t.Fatalf("HTTPStatus = %d, want %d", err.HTTPStatus, tt.status)
			}
		})
	}
}

func TestFromHTTPUsesConfiguredResourceNotFoundSubstrings(t *testing.T) {
	Configure(Options{ResourceNotFoundSubstrings: []string{"resource missing"}})
	err := FromHTTP(500, "resource missing")
	if err.Code != CodeResourceNotFound {
		t.Fatalf("Code = %s, want %s", err.Code, CodeResourceNotFound)
	}
	Configure(Options{ResourceNotFoundSubstrings: []string{}})
}

func TestAsAppErrorFromNetworkError(t *testing.T) {
	err := &net.DNSError{Err: "no such host", Name: "example.com"}
	got := AsAppError(err)
	if got.Code != CodeNetworkError {
		t.Fatalf("Code = %s, want %s", got.Code, CodeNetworkError)
	}
	if !got.Retryable {
		t.Fatal("network errors should be retryable")
	}
}

func TestAsAppErrorFromCobraParserError(t *testing.T) {
	got := AsAppError(errors.New(`unknown flag: --bad`))
	if got.Code != CodeUsageError {
		t.Fatalf("Code = %s, want %s", got.Code, CodeUsageError)
	}
	if got.Error() != `unknown flag: --bad` {
		t.Fatalf("Error() = %q", got.Error())
	}
}

func TestStructuredCauseJSON(t *testing.T) {
	var out bytes.Buffer
	err := New(CodeAuthorizationRequired, "denied", nil)
	err.StructuredCause = &ErrorCause{Layer: "external-validator", Detail: "rejected"}
	if writeErr := WriteJSON(&out, err); writeErr != nil {
		t.Fatalf("WriteJSON() error = %v", writeErr)
	}

	var payload struct {
		Error struct {
			Cause *ErrorCause `json:"cause"`
		} `json:"error"`
	}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Error.Cause == nil || payload.Error.Cause.Layer != "external-validator" || payload.Error.Cause.Detail != "rejected" {
		t.Fatalf("unexpected structured cause: %+v", payload.Error.Cause)
	}
}

func TestAsAppErrorNoDuplicateWrap(t *testing.T) {
	err := AsAppError(errors.New("unknown command \"rul\" for \"tool-cli\""))
	if err == nil {
		t.Fatal("AsAppError() = nil")
	}
	if got := err.Error(); got != `unknown command "rul" for "tool-cli"` {
		t.Fatalf("Error() = %q", got)
	}
}

func TestWriteJSON(t *testing.T) {
	var out bytes.Buffer
	err := WriteJSON(&out, New(CodeValidationFailed, "invalid config", errors.New("bad json")))
	if err != nil {
		t.Fatalf("WriteJSON() error = %v", err)
	}

	var payload struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Success    bool   `json:"success"`
		Error      struct {
			Code    ErrorCode `json:"code"`
			Message string    `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.APIVersion != "opskit-core.io/v1" || payload.Kind != "Error" || payload.Success {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	if payload.Error.Code != CodeValidationFailed || payload.Error.Message != "invalid config" {
		t.Fatalf("unexpected error payload: %+v", payload.Error)
	}
}
