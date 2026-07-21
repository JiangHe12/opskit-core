//go:build !windows

package audit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const auditRecipientFIFOTestEnv = "OPSKIT_AUDIT_RECIPIENT_FIFO_TEST_PATH"

func TestLoadAgeRecipientRejectsFIFOWithoutBlocking(t *testing.T) {
	if path := os.Getenv(auditRecipientFIFOTestEnv); path != "" {
		if _, err := loadAgeRecipient(path); err == nil {
			t.Fatal("loadAgeRecipient() accepted a FIFO")
		}
		return
	}

	path := filepath.Join(t.TempDir(), "recipient.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestLoadAgeRecipientRejectsFIFOWithoutBlocking$",
		"-test.count=1",
	)
	command.Env = append(os.Environ(), auditRecipientFIFOTestEnv+"="+path)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("loadAgeRecipient() blocked on a FIFO: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("FIFO rejection subprocess failed: %v\n%s", err, output)
	}
}
