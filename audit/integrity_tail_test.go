package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLastStoredLineUsesActiveBeforeEnumeratingRotations(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit[.log")
	const activeLine = `{"active":true}`
	if err := os.WriteFile(path, []byte(activeLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= 256; index++ {
		rotated := fmt.Sprintf("%s.20260720-010203.%d.log", path, index)
		if err := os.WriteFile(rotated, []byte(`{"rotated":true}`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := RotatedFiles(path); err == nil {
		t.Fatal("test path must make rotation enumeration fail")
	}

	line, found, err := lastStoredLine(path)
	if err != nil {
		t.Fatalf("lastStoredLine() enumerated rotations before reading active: %v", err)
	}
	if !found || line != activeLine {
		t.Fatalf("lastStoredLine() = (%q, %t), want (%q, true)", line, found, activeLine)
	}
}

func TestLastStoredLineFallsBackToNewestNonEmptyRotation(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	older := path + ".20260720-010203.log"
	newer := path + ".20260720-010204.log"
	if err := os.WriteFile(older, []byte(`{"older":true}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newer, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	line, found, err := lastStoredLine(path)
	if err != nil {
		t.Fatalf("lastStoredLine() error = %v", err)
	}
	if !found || line != `{"older":true}` {
		t.Fatalf("lastStoredLine() = (%q, %t), want newest non-empty rotated line", line, found)
	}
}

func BenchmarkLastStoredLineActiveWithManyRotations(b *testing.B) {
	path := filepath.Join(privateTestDir(b), "audit.log")
	const activeLine = `{"active":true}`
	if err := os.WriteFile(path, []byte(activeLine+"\n"), 0o600); err != nil {
		b.Fatal(err)
	}
	for index := 1; index <= 1_000; index++ {
		rotated := fmt.Sprintf("%s.20260720-010203.%d.log", path, index)
		if err := os.WriteFile(rotated, []byte(`{"rotated":true}`+"\n"), 0o600); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		line, found, err := lastStoredLine(path)
		if err != nil {
			b.Fatal(err)
		}
		if !found || line != activeLine {
			b.Fatalf("lastStoredLine() = (%q, %t), want (%q, true)", line, found, activeLine)
		}
	}
}
