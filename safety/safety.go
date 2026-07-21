// Package safety evaluates write risk and authorization requirements.
package safety

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/mattn/go-isatty"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

// Risk is the authorization risk level.
type Risk int

const (
	R0 Risk = iota
	R1
	R2
	R3
)

// Role constants for RBAC. When a context has Roles configured, every
// operator must appear in the map; operators absent from the map are denied.
const (
	RoleReader = "reader" // read-only: up to R0
	RoleWriter = "writer" // write: up to R2
	RoleAdmin  = "admin"  // destructive batch: up to R3
)

// AllowFlag identifies explicit R3 overrides.
type AllowFlag string

// ContextMeta carries context attributes that affect risk.
type ContextMeta struct {
	Name            string
	Env             string
	Protected       bool
	TicketPattern   string
	TicketValidator string
	Roles           map[string]string // operator → role; nil disables RBAC
}

// TicketValidator validates a change ticket.
type TicketValidator interface {
	Validate(ticket string) error
}

// Options controls authorization.
type Options struct {
	Yes                bool
	NonInteractive     bool
	Ticket             string
	TicketPattern      string
	Validator          TicketValidator
	RequiredAllowFlags []AllowFlag
	GrantedAllowFlags  map[AllowFlag]bool
	Stdin              io.Reader
	Stdout             io.Writer
	Roles              map[string]string // from ContextMeta.Roles
	Operator           string            // current operator identity
}

// Config controls package-level text and environment defaults.
type Config struct {
	Prompt                   string
	OperatorEnvVar           string // Deprecated: environment variables are not trusted authorization identities.
	RoleAssignmentHintFormat string
}

var config = Config{
	Prompt:                   "Proceed with write? [y/N] ",
	OperatorEnvVar:           "OPSKIT_OPERATOR",
	RoleAssignmentHintFormat: "assign an operator role for this context",
}

// Configure sets package-level text and environment defaults for a consumer CLI.
func Configure(next Config) {
	if next.Prompt != "" {
		config.Prompt = next.Prompt
	}
	if next.OperatorEnvVar != "" {
		config.OperatorEnvVar = next.OperatorEnvVar
	}
	if next.RoleAssignmentHintFormat != "" {
		config.RoleAssignmentHintFormat = next.RoleAssignmentHintFormat
	}
}

// EffectiveRisk raises the base risk for protected contexts.
func EffectiveRisk(base Risk, meta ContextMeta) Risk {
	if !meta.Protected {
		return base
	}
	switch base {
	case R0:
		return R0
	case R1:
		return R2
	case R2, R3:
		return R3
	default:
		return base
	}
}

// Authorize verifies the required ticket, yes confirmation, and R3 allow flag.
// If the context has Roles configured, the operator's role is also checked.
func Authorize(risk Risk, opts Options) error {
	if risk < R0 || risk > R3 {
		return authorizationError(fmt.Sprintf("invalid risk level %d", risk))
	}
	if err := checkRole(risk, opts); err != nil {
		return err
	}
	if risk == R0 {
		return nil
	}
	if risk >= R2 {
		if err := validateTicketChain(opts); err != nil {
			return err
		}
		if opts.Ticket == "" {
			return authorizationError("authorization requires --ticket and --yes")
		}
	}
	if risk == R3 {
		if len(opts.RequiredAllowFlags) == 0 {
			return authorizationError("R3 authorization requires an allow flag")
		}
		for _, flag := range opts.RequiredAllowFlags {
			if !opts.GrantedAllowFlags[flag] {
				return authorizationError(fmt.Sprintf("authorization requires --%s", flag))
			}
		}
	}
	if opts.Yes {
		return nil
	}
	if opts.NonInteractive || !isInteractive(opts.Stdin) {
		return authorizationError("authorization requires --yes in non-interactive mode")
	}
	return promptYes(opts)
}

func validateTicketChain(opts Options) error {
	if opts.TicketPattern != "" && opts.Ticket != "" {
		if err := validateTicket(opts.TicketPattern, opts.Ticket); err != nil {
			return err
		}
	}
	if opts.Validator != nil && opts.Ticket != "" {
		if err := opts.Validator.Validate(opts.Ticket); err != nil {
			return err
		}
	}
	return nil
}

func validateTicket(pattern, ticket string) error {
	ok, err := regexp.MatchString(pattern, ticket)
	if err != nil {
		return apperrors.New(apperrors.CodeUsageError, "invalid ticket pattern", err)
	}
	if !ok {
		return authorizationError("ticket does not match context ticket pattern")
	}
	return nil
}

func promptYes(opts Options) error {
	out := opts.Stdout
	if out == nil {
		out = os.Stdout
	}
	in := opts.Stdin
	if in == nil {
		in = os.Stdin
	}
	_, _ = fmt.Fprint(out, config.Prompt)
	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		return authorizationError("authorization canceled")
	}
	answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
	if answer != "y" && answer != "yes" {
		return authorizationError("authorization canceled")
	}
	return nil
}

func isInteractive(in io.Reader) bool {
	if in == nil {
		return isatty.IsTerminal(os.Stdin.Fd())
	}
	file, ok := in.(*os.File)
	return ok && isatty.IsTerminal(file.Fd())
}

func authorizationError(message string) *apperrors.AppError {
	return apperrors.New(apperrors.CodeAuthorizationRequired, message, nil)
}

// ValidateBackupPolicy enforces explicit backup choices for write operations.
func ValidateBackupPolicy(nonInteractive, backup, noBackup, protected bool) error {
	if protected && noBackup {
		return apperrors.New(apperrors.CodeUsageError, "--no-backup is not allowed in protected production contexts", nil)
	}
	if nonInteractive && !backup && !noBackup {
		return apperrors.New(apperrors.CodeUsageError, "non-interactive mode requires explicit --backup or --no-backup for write operations", nil)
	}
	return nil
}

// checkRole enforces RBAC when Roles are configured on the context.
// Operators absent from the map are denied. Operators whose role does not
// permit the requested risk level are denied.
func checkRole(risk Risk, opts Options) error {
	if len(opts.Roles) == 0 {
		return nil
	}
	if opts.Operator == "" {
		return authorizationError("trusted operator identity required when roles are configured")
	}
	role, ok := opts.Roles[opts.Operator]
	if !ok {
		return authorizationError(fmt.Sprintf(
			"operator %q has no role in this context; %s",
			opts.Operator, roleAssignmentHint(opts.Operator, requiredRole(risk))))
	}
	maxRisk, ok := maxRiskForRole(role)
	if !ok {
		return authorizationError(fmt.Sprintf(
			"operator %q has unrecognized role %q",
			opts.Operator, role))
	}
	if risk > maxRisk {
		return authorizationError(fmt.Sprintf(
			"operator %q (role: %s) is not authorized for this operation (requires role: %s)",
			opts.Operator, role, requiredRole(risk)))
	}
	return nil
}

func roleAssignmentHint(operator, role string) string {
	return fmt.Sprintf(config.RoleAssignmentHintFormat, operator, role)
}

func maxRiskForRole(role string) (Risk, bool) {
	switch role {
	case RoleReader:
		return R0, true
	case RoleWriter:
		return R2, true
	case RoleAdmin:
		return R3, true
	default:
		return R0, false
	}
}

func requiredRole(risk Risk) string {
	switch {
	case risk >= R3:
		return RoleAdmin
	case risk >= R1:
		return RoleWriter
	default:
		return RoleReader
	}
}
