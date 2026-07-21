package safety

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

const externalValidatorTimeout = 10 * time.Second

type externalValidator struct {
	path     string
	ctxName  string
	operator string
	timeout  time.Duration
	env      []string
}

type validatorPayload struct {
	Ticket   string `json:"ticket"`
	Context  string `json:"context"`
	Operator string `json:"operator,omitempty"`
}

// NewExternalValidator returns a TicketValidator backed by an external executable.
// The executable receives a single-line JSON payload on stdin:
//
//	{"ticket":"...","context":"...","operator":"..."}
//
// Exit code 0 = valid, anything else = rejected.
func NewExternalValidator(path, contextName, operator string) TicketValidator {
	return &externalValidator{path: path, ctxName: contextName, operator: operator, timeout: externalValidatorTimeout}
}

func (e *externalValidator) Validate(ticket string) error {
	executable, err := e.resolvePath()
	if err != nil {
		return err
	}
	timeout := e.timeout
	if timeout <= 0 {
		timeout = externalValidatorTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	payload, err := json.Marshal(validatorPayload{Ticket: ticket, Context: e.ctxName, Operator: e.operator})
	if err != nil {
		return apperrors.New(apperrors.CodeAuthorizationRequired, "failed to build ticket validator payload", err)
	}
	payload = append(payload, '\n')
	//nolint:gosec // User-configured validator path is resolved without shell expansion and run without args.
	cmd := exec.CommandContext(ctx, executable)
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
	if len(e.env) > 0 {
		cmd.Env = e.env
	}
	cmd.Stdin = bytes.NewReader(payload)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return apperrors.New(apperrors.CodeAuthorizationRequired, "ticket validator timed out after 10s", nil)
		}
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = "ticket validator rejected ticket"
		}
		return apperrors.New(apperrors.CodeAuthorizationRequired, message, err)
	}
	return nil
}

func (e *externalValidator) resolvePath() (string, error) {
	if e.path == "" {
		return "", apperrors.New(apperrors.CodeAuthorizationRequired, "ticket validator not found", nil)
	}
	if filepath.IsAbs(e.path) {
		if _, err := os.Stat(e.path); err != nil {
			return "", apperrors.New(apperrors.CodeAuthorizationRequired, fmt.Sprintf("ticket validator not found: %s", e.path), err)
		}
		return e.path, nil
	}
	found, err := exec.LookPath(e.path)
	if err != nil {
		return "", apperrors.New(apperrors.CodeAuthorizationRequired, fmt.Sprintf("ticket validator not found: %s", e.path), err)
	}
	return found, nil
}
