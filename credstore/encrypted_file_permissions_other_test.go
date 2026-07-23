//go:build !windows

package credstore

import "testing"

func secureCredstoreTestRoot(*testing.T, string) {}
