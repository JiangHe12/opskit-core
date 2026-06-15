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
		re:          regexp.MustCompile(`\bASIA[0-9A-Z]{16}\b`),
		replacement: replacement,
	},
	{
		re:          regexp.MustCompile(`\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+`),
		replacement: replacement,
	},
	{
		re:          regexp.MustCompile(`\bsk-(?:[a-z]+-)?[A-Za-z0-9]{20,}`),
		replacement: replacement,
	},
	{
		re:          regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}`),
		replacement: replacement,
	},
	{
		re:          regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{40,}`),
		replacement: replacement,
	},
	{
		re:          regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`),
		replacement: replacement,
	},
	{
		re:          regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
		replacement: replacement,
	},
	{
		re:          regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`),
		replacement: replacement,
	},
	{
		re:          regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://[^:/?#\s@]*:)([^@/?#\s]+)(@)`),
		replacement: `${1}` + replacement + `${3}`,
	},
	{
		re:          regexp.MustCompile(`(?i)(\bBearer\s+)[A-Za-z0-9._~+/\-]{16,}=*`),
		replacement: `${1}` + replacement,
	},
	{
		re: regexp.MustCompile(
			`(?i)(^|\s)(--(?:password|passwd|requirepass|token|secret|api[-_]?key|access[-_]?key|passphrase)|-p)(=+|\s+)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`,
		),
		replacement: `${1}${2}${3}` + replacement,
	},
}

var assignmentRE = regexp.MustCompile(
	`(^|[^A-Za-z0-9_.-])([A-Za-z0-9_.-]+)(\s*[:=]\s*)((?i:(?:Bearer|Basic)\s+(?:\[REDACTED\]|[^\s,;]+))|"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`,
)

var atomicSensitiveKeyWords = map[string]bool{
	"password":      true,
	"passwd":        true,
	"pwd":           true,
	"secret":        true,
	"token":         true,
	"credential":    true,
	"credentials":   true,
	"passphrase":    true,
	"apikey":        true,
	"privatekey":    true,
	"accesskey":     true,
	"secretkey":     true,
	"authtoken":     true,
	"clientsecret":  true,
	"cookie":        true,
	"sessionid":     true,
	"authorization": true,
	"jsessionid":    true,
	"phpsessid":     true,
}

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
		if strings.EqualFold(strings.TrimSpace(parts[4]), "Bearer "+replacement) {
			return candidate
		}
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
		if atomicSensitiveKeyWords[word] {
			return true
		}
		if word == "key" {
			hasKey = true
		}
	}
	if atomicSensitiveKeyWords[strings.Join(normalizedWords, "")] {
		return true
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
