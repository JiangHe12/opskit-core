package safety

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/apperrors"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv("TEST_VALIDATOR_MODE"); mode != "" {
		runValidatorHelper(mode)
		return
	}
	os.Exit(m.Run())
}

func TestExternalValidatorAcceptsExitZero(t *testing.T) {
	validator := newTestExternalValidator(t, "accept", "")
	if err := validator.Validate("OPS-1"); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestExternalValidatorRejectsNonZero(t *testing.T) {
	validator := newTestExternalValidator(t, "reject", "")
	err := validator.Validate("OPS-1")
	if err == nil {
		t.Fatal("Validate() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "ticket OPS-9999 not found in JIRA") {
		t.Fatalf("Validate() error = %v", err)
	}
	if apperrors.AsAppError(err).Code != apperrors.CodeAuthorizationRequired {
		t.Fatalf("error code = %s", apperrors.AsAppError(err).Code)
	}
}

func TestExternalValidatorTimesOut(t *testing.T) {
	validator := newTestExternalValidator(t, "sleep", "")
	validator.timeout = 20 * time.Millisecond
	start := time.Now()
	err := validator.Validate("OPS-1")
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "ticket validator timed out after 10s") {
		t.Fatalf("Validate() error = %v, want timeout", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Validate() elapsed = %s, want prompt timeout", elapsed)
	}
}

func TestExternalValidatorPathNotFound(t *testing.T) {
	validator := NewExternalValidator(filepath.Join(t.TempDir(), "missing-validator"), "prod", "alice")
	err := validator.Validate("OPS-1")
	if err == nil || !strings.Contains(err.Error(), "ticket validator not found") {
		t.Fatalf("Validate() error = %v, want not found", err)
	}
}

func TestExternalValidatorPassesPayloadOnStdin(t *testing.T) {
	payloadPath := filepath.Join(t.TempDir(), "payload.json")
	validator := newTestExternalValidator(t, "capture", payloadPath)
	if err := validator.Validate("OPS-1234"); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	data, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var payload map[string]string
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if payload["ticket"] != "OPS-1234" || payload["context"] != "prod" || payload["operator"] != "alice" {
		t.Fatalf("payload = %+v", payload)
	}
}

func newTestExternalValidator(t *testing.T, mode string, payloadPath string) *externalValidator {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("Executable() error = %v", err)
	}
	validator, ok := NewExternalValidator(exe, "prod", "alice").(*externalValidator)
	if !ok {
		t.Fatalf("validator type = %T", validator)
	}
	validator.env = append(os.Environ(), "TEST_VALIDATOR_MODE="+mode, "TEST_VALIDATOR_PAYLOAD="+payloadPath)
	return validator
}

func runValidatorHelper(mode string) {
	switch mode {
	case "accept":
		os.Exit(0)
	case "reject":
		_, _ = fmt.Fprint(os.Stderr, "ticket OPS-9999 not found in JIRA")
		os.Exit(2)
	case "sleep":
		time.Sleep(time.Second)
		os.Exit(0)
	case "capture":
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			_, _ = fmt.Fprint(os.Stderr, err)
			os.Exit(1)
		}
		path := os.Getenv("TEST_VALIDATOR_PAYLOAD")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			_, _ = fmt.Fprint(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	default:
		_, _ = fmt.Fprintf(os.Stderr, "unknown mode %s", mode)
		os.Exit(1)
	}
}

type mockTicketValidator struct {
	called bool
	err    error
}

func (m *mockTicketValidator) Validate(string) error {
	m.called = true
	return m.err
}

func TestAuthorizeCallsValidatorAfterRegex(t *testing.T) {
	validator := &mockTicketValidator{err: errors.New("validator denied")}
	err := Authorize(R2, Options{
		Yes:            true,
		NonInteractive: true,
		Ticket:         "OPS-1",
		TicketPattern:  `^OPS-\d+$`,
		Validator:      validator,
	})
	if err == nil || !validator.called {
		t.Fatalf("Authorize() error = %v called=%t", err, validator.called)
	}

	validator = &mockTicketValidator{}
	err = Authorize(R2, Options{
		Yes:            true,
		NonInteractive: true,
		Ticket:         "BAD",
		TicketPattern:  `^OPS-\d+$`,
		Validator:      validator,
	})
	if err == nil {
		t.Fatal("Authorize() error = nil, want regex failure")
	}
	if validator.called {
		t.Fatal("validator called before regex passed")
	}
}
