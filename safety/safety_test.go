package safety

import (
	"strings"
	"testing"
)

const (
	allowProductionDelete AllowFlag = "allow-production-delete"
	allowProductionPrune  AllowFlag = "allow-production-prune"
)

func TestEffectiveRiskProtectedContext(t *testing.T) {
	if got := EffectiveRisk(R1, ContextMeta{Protected: true}); got != R2 {
		t.Fatalf("EffectiveRisk(R1 protected) = %v, want R2", got)
	}
	if got := EffectiveRisk(R2, ContextMeta{Protected: true}); got != R3 {
		t.Fatalf("EffectiveRisk(R2 protected) = %v, want R3", got)
	}
}

func TestAuthorizeNonInteractiveAndTicket(t *testing.T) {
	if err := Authorize(R1, Options{NonInteractive: true}); err == nil {
		t.Fatal("Authorize(R1 noninteractive without yes) error = nil, want error")
	}
	if err := Authorize(R1, Options{NonInteractive: true, Yes: true}); err != nil {
		t.Fatalf("Authorize(R1 noninteractive with yes) error = %v", err)
	}
	if err := Authorize(R2, Options{NonInteractive: true, Yes: true, Ticket: "OPS-1", TicketPattern: `^OPS-\d+$`}); err != nil {
		t.Fatalf("Authorize(R2) error = %v", err)
	}
	if err := Authorize(R2, Options{NonInteractive: true, Yes: true, Ticket: "BAD", TicketPattern: `^OPS-\d+$`}); err == nil {
		t.Fatal("Authorize(R2 bad ticket) error = nil, want error")
	}
}

func TestAuthorizeR3RequiresAllowFlag(t *testing.T) {
	opts := Options{NonInteractive: true, Yes: true, Ticket: "OPS-1", RequiredAllowFlags: []AllowFlag{allowProductionDelete}}
	if err := Authorize(R3, opts); err == nil {
		t.Fatal("Authorize(R3 missing flag) error = nil, want error")
	}
	opts.GrantedAllowFlags = map[AllowFlag]bool{allowProductionDelete: true}
	if err := Authorize(R3, opts); err != nil {
		t.Fatalf("Authorize(R3) error = %v", err)
	}
}

func TestAuthorizeR3RequiresAllAllowFlags(t *testing.T) {
	opts := Options{
		NonInteractive:     true,
		Yes:                true,
		Ticket:             "OPS-1",
		RequiredAllowFlags: []AllowFlag{allowProductionDelete, allowProductionPrune},
		GrantedAllowFlags:  map[AllowFlag]bool{allowProductionDelete: true},
	}
	err := Authorize(R3, opts)
	if err == nil {
		t.Fatal("Authorize(R3 missing one of multiple flags) error = nil, want error")
	}
	if !strings.Contains(err.Error(), "authorization requires --allow-production-prune") {
		t.Fatalf("Authorize(R3) error = %v, want missing prune allow flag", err)
	}
	opts.GrantedAllowFlags[allowProductionPrune] = true
	if err := Authorize(R3, opts); err != nil {
		t.Fatalf("Authorize(R3 all flags) error = %v", err)
	}
}

func TestAuthorizeRBACNoRolesConfigured(t *testing.T) {
	// No roles → behaves exactly like before (backward compatible).
	if err := Authorize(R0, Options{Operator: "alice", Roles: nil}); err != nil {
		t.Fatalf("R0 no roles: %v", err)
	}
	if err := Authorize(R1, Options{Operator: "alice", Roles: nil, Yes: true, NonInteractive: true}); err != nil {
		t.Fatalf("R1 no roles: %v", err)
	}
}

func TestAuthorizeRBACOperatorNotInRoles(t *testing.T) {
	roles := map[string]string{"bob": RoleAdmin}
	if err := Authorize(R0, Options{Operator: "alice", Roles: roles}); err == nil {
		t.Fatal("operator not in roles should be denied for R0")
	}
}

func TestAuthorizeRBACReaderCannotWrite(t *testing.T) {
	roles := map[string]string{"alice": RoleReader}
	// Reader can do R0.
	if err := Authorize(R0, Options{Operator: "alice", Roles: roles}); err != nil {
		t.Fatalf("reader R0 should pass: %v", err)
	}
	// Reader cannot do R1 (write).
	if err := Authorize(R1, Options{Operator: "alice", Roles: roles}); err == nil {
		t.Fatal("reader R1 should be denied")
	}
}

func TestAuthorizeRBACWriterCannotDoR3(t *testing.T) {
	roles := map[string]string{"alice": RoleWriter}
	if err := Authorize(R1, Options{Operator: "alice", Roles: roles, Yes: true, NonInteractive: true}); err != nil {
		t.Fatalf("writer R1 should pass: %v", err)
	}
	// Writer cannot do R3.
	writerR3 := Options{
		Operator:           "alice",
		Roles:              roles,
		Yes:                true,
		NonInteractive:     true,
		Ticket:             "OPS-1",
		RequiredAllowFlags: []AllowFlag{allowProductionDelete},
		GrantedAllowFlags:  map[AllowFlag]bool{allowProductionDelete: true},
	}
	if err := Authorize(R3, writerR3); err == nil {
		t.Fatal("writer R3 should be denied")
	}
}

func TestAuthorizeRBACAdminCanDoR3(t *testing.T) {
	roles := map[string]string{"alice": RoleAdmin}
	if err := Authorize(R3, Options{
		Operator:           "alice",
		Roles:              roles,
		Yes:                true,
		NonInteractive:     true,
		Ticket:             "OPS-1",
		RequiredAllowFlags: []AllowFlag{allowProductionDelete},
		GrantedAllowFlags:  map[AllowFlag]bool{allowProductionDelete: true},
	}); err != nil {
		t.Fatalf("admin R3 should pass: %v", err)
	}
}

func TestAuthorizeRBACRejectsUnknownRole(t *testing.T) {
	roles := map[string]string{"alice": "admn"}
	for _, risk := range []Risk{R0, R1, R2, R3} {
		err := Authorize(risk, Options{
			Operator:           "alice",
			Roles:              roles,
			Yes:                true,
			NonInteractive:     true,
			Ticket:             "OPS-1",
			RequiredAllowFlags: []AllowFlag{allowProductionDelete},
			GrantedAllowFlags:  map[AllowFlag]bool{allowProductionDelete: true},
		})
		if err == nil {
			t.Errorf("Authorize(%v) with unknown role error = nil, want error", risk)
			continue
		}
		if !strings.Contains(err.Error(), "unrecognized role") {
			t.Errorf("Authorize(%v) error = %q, want unrecognized role", risk, err)
		}
	}
}

func TestAuthorizeRejectsInvalidRisk(t *testing.T) {
	for _, risk := range []Risk{-1, R3 + 1} {
		err := Authorize(risk, Options{
			Yes:                true,
			NonInteractive:     true,
			Ticket:             "OPS-1",
			RequiredAllowFlags: []AllowFlag{allowProductionDelete},
			GrantedAllowFlags:  map[AllowFlag]bool{allowProductionDelete: true},
		})
		if err == nil {
			t.Errorf("Authorize(%v) error = nil, want invalid risk error", risk)
			continue
		}
		if !strings.Contains(err.Error(), "invalid risk level") {
			t.Errorf("Authorize(%v) error = %q, want invalid risk level", risk, err)
		}
	}
}

func TestRBACRejectsEmptyOperatorWhenRolesConfigured(t *testing.T) {
	roles := map[string]string{"alice": RoleAdmin}
	err := Authorize(R0, Options{Operator: "", Roles: roles})
	if err == nil {
		t.Fatal("empty operator with roles configured should be denied")
	}
	if !strings.Contains(err.Error(), "operator identity required") {
		t.Fatalf("Authorize() error = %v", err)
	}
}

func TestRBACDoesNotTrustOperatorEnvironmentFallback(t *testing.T) {
	Configure(Config{OperatorEnvVar: "OPSKIT_OPERATOR"})
	t.Setenv("OPSKIT_OPERATOR", "alice")

	err := Authorize(R0, Options{
		Operator: "",
		Roles:    map[string]string{"alice": RoleAdmin},
	})
	if err == nil {
		t.Fatal("environment operator bypassed the required trusted identity")
	}
	if !strings.Contains(err.Error(), "trusted operator identity required") {
		t.Fatalf("Authorize() error = %v, want trusted identity requirement", err)
	}
}

func TestAuthorizeR3RequiresYesAfterAllowFlag(t *testing.T) {
	base := Options{
		Ticket:             "OPS-1",
		RequiredAllowFlags: []AllowFlag{allowProductionDelete},
		GrantedAllowFlags:  map[AllowFlag]bool{allowProductionDelete: true},
	}

	noYesNonInteractive := base
	noYesNonInteractive.NonInteractive = true
	if err := Authorize(R3, noYesNonInteractive); err == nil {
		t.Fatal("R3 with allow flag but no --yes in non-interactive should be denied")
	}

	noYesNonTTY := base
	noYesNonTTY.Stdin = strings.NewReader("")
	if err := Authorize(R3, noYesNonTTY); err == nil {
		t.Fatal("R3 with allow flag but no --yes on non-tty stdin should be denied")
	}

	withYes := base
	withYes.Yes = true
	withYes.NonInteractive = true
	if err := Authorize(R3, withYes); err != nil {
		t.Fatalf("R3 with allow flag and --yes should pass, got %v", err)
	}
}

// Regression for v0.6.1 evaluation finding S-2: requiredRole(R1) previously
// returned reader, causing RBAC rejection messages for R1 operations to say
// "requires role: reader" — misleading because reader cannot perform R1.
func TestRequiredRoleBoundaries(t *testing.T) {
	cases := []struct {
		risk Risk
		want string
	}{
		{R0, RoleReader},
		{R1, RoleWriter},
		{R2, RoleWriter},
		{R3, RoleAdmin},
	}
	for _, c := range cases {
		if got := requiredRole(c.risk); got != c.want {
			t.Errorf("requiredRole(%v) = %q, want %q", c.risk, got, c.want)
		}
	}
}

// Regression for v0.6.1 evaluation finding S-2: reader rejected for R1 must
// receive a message naming writer as the required role, not reader.
func TestRBACReaderRejectionMessageNamesWriter(t *testing.T) {
	roles := map[string]string{"alice": RoleReader}
	err := Authorize(R1, Options{Operator: "alice", Roles: roles, NonInteractive: true})
	if err == nil {
		t.Fatal("reader R1 should be denied")
	}
	if !strings.Contains(err.Error(), "requires role: writer") {
		t.Fatalf("error = %q, want it to contain 'requires role: writer'", err.Error())
	}
}

func TestValidateBackupPolicyRejectsNoBackupInProtectedContext(t *testing.T) {
	err := ValidateBackupPolicy(false, false, true, true)
	if err == nil {
		t.Fatal("ValidateBackupPolicy() error = nil, want protected no-backup rejection")
	}
	if !strings.Contains(err.Error(), "--no-backup is not allowed") {
		t.Fatalf("ValidateBackupPolicy() error = %v", err)
	}
}

func TestValidateBackupPolicyRequiresExplicitBackupChoiceInNonInteractive(t *testing.T) {
	err := ValidateBackupPolicy(true, false, false, false)
	if err == nil {
		t.Fatal("ValidateBackupPolicy() error = nil, want explicit backup choice rejection")
	}
	if !strings.Contains(err.Error(), "non-interactive mode requires explicit --backup or --no-backup") {
		t.Fatalf("ValidateBackupPolicy() error = %v", err)
	}
}

func TestValidateBackupPolicyAllowsExplicitChoices(t *testing.T) {
	if err := ValidateBackupPolicy(true, true, false, true); err != nil {
		t.Fatalf("ValidateBackupPolicy(nonInteractive backup protected) error = %v", err)
	}
	if err := ValidateBackupPolicy(true, false, true, false); err != nil {
		t.Fatalf("ValidateBackupPolicy(nonInteractive noBackup unprotected) error = %v", err)
	}
}
