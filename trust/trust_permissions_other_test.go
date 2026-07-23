//go:build !windows

package trust

import "testing"

func secureTrustTestRoot(*testing.T, string) {}
