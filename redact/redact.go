// Package redact removes secrets from command output before it is returned or audited.
package redact

import (
	"regexp"
	"strings"
)

const replacement = "[REDACTED]"

var patterns = []struct {
	re          *regexp.Regexp
	replacement string
}{
	{
		re:          regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
		replacement: "[REDACTED PRIVATE KEY]",
	},
	{
		re:          regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		replacement: replacement,
	},
	{
		re:          regexp.MustCompile(`\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+`),
		replacement: replacement,
	},
	{
		re: regexp.MustCompile(
			`(?i)(^|\s)(--(?:password|passwd|requirepass|token|secret|api[-_]?key|access[-_]?key|passphrase)|-p)(=+|\s+)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`,
		),
		replacement: `${1}${2}${3}` + replacement,
	},
}

var assignmentRE = regexp.MustCompile(
	`(^|[^A-Za-z0-9_.-])([A-Za-z0-9_.-]+)(\s*[:=]\s*)("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`,
)

var harmlessKeyNames = map[string]bool{
	"key":             true,
	"primary_key":     true,
	"foreign_key":     true,
	"sort_key":        true,
	"partition_key":   true,
	"composite_key":   true,
	"candidate_key":   true,
	"surrogate_key":   true,
	"natural_key":     true,
	"range_key":       true,
	"hash_key":        true,
	"shard_key":       true,
	"cluster_key":     true,
	"clustering_key":  true,
	"routing_key":     true,
	"cache_key":       true,
	"group_key":       true,
	"dedup_key":       true,
	"public_key":      true,
	"idempotency_key": true,
	"key_name":        true,
}

// String returns value with recognized secrets replaced. It is intentionally
// context-free so the same function can guard caller output and audit records.
// Bearer tokens and opaque API keys such as sk-/ghp_ are known gaps for a later extension.
func String(value string) string {
	for _, pattern := range patterns {
		value = pattern.re.ReplaceAllString(value, pattern.replacement)
	}
	return assignmentRE.ReplaceAllStringFunc(value, redactAssignment)
}

func redactAssignment(candidate string) string {
	parts := assignmentRE.FindStringSubmatch(candidate)
	if len(parts) != 5 {
		return candidate
	}
	if isSensitiveKey(parts[2]) {
		return parts[1] + parts[2] + parts[3] + replacement
	}
	return parts[1] + parts[2] + parts[3] + String(parts[4])
}

func isSensitiveKey(key string) bool {
	words := splitKeyWords(key)
	hasKey := false
	normalizedWords := make([]string, 0, len(words))
	for _, rawWord := range words {
		word := strings.ToLower(rawWord)
		normalizedWords = append(normalizedWords, word)
		switch word {
		case "password", "passwd", "pwd", "secret", "token", "credential", "credentials",
			"passphrase", "apikey", "privatekey", "accesskey", "secretkey", "authtoken",
			"clientsecret", "cookie", "sessionid":
			return true
		case "key":
			hasKey = true
		}
	}
	if !hasKey {
		return false
	}
	return !harmlessKeyNames[strings.Join(normalizedWords, "_")]
}

func splitKeyWords(key string) []string {
	var words []string
	for _, part := range strings.FieldsFunc(key, func(r rune) bool {
		return r == '_' || r == '.' || r == '-'
	}) {
		start := 0
		for i := 1; i < len(part); i++ {
			if isCamelBoundary(part, i) {
				words = append(words, part[start:i])
				start = i
			}
		}
		if start < len(part) {
			words = append(words, part[start:])
		}
	}
	return words
}

func isCamelBoundary(value string, index int) bool {
	current := value[index]
	if !isUpperASCII(current) {
		return false
	}
	previous := value[index-1]
	if isLowerASCII(previous) || isDigitASCII(previous) {
		return true
	}
	return isUpperASCII(previous) && index+1 < len(value) && isLowerASCII(value[index+1])
}

func isUpperASCII(value byte) bool {
	return value >= 'A' && value <= 'Z'
}

func isLowerASCII(value byte) bool {
	return value >= 'a' && value <= 'z'
}

func isDigitASCII(value byte) bool {
	return value >= '0' && value <= '9'
}
