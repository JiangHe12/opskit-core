package apperrors

import (
	"bytes"
	"encoding/json"
	"errors"
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
