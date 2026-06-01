package credstore

import "strings"

const refPrefix = "credstore:"

// CredentialRef is a parsed credential reference.
type CredentialRef struct {
	IsRef       bool
	BackendName string
	Literal     string
}

// ParseRef interprets a password string.
func ParseRef(value string) CredentialRef {
	if strings.HasPrefix(value, refPrefix) {
		return CredentialRef{IsRef: true, BackendName: strings.TrimPrefix(value, refPrefix)}
	}
	return CredentialRef{Literal: value}
}

// EncodeRef returns a credstore reference.
func EncodeRef(backendName string) string {
	return refPrefix + backendName
}
