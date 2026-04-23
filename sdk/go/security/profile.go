package security

import (
	"strings"

	"github.com/loxar/hsp/sdk/go/protocol"
)

type Profile struct {
	AuthorityProfile          string
	E2EERequired              bool
	StorageEncryptionRequired bool
	CryptoSuite               string
	KeyWrappingSuite          string
	TenantIsolationProfile    string
}

func PublicMultiTenantProfile() Profile {
	info := protocol.PublicMultiTenantInfoResponse()

	return Profile{
		AuthorityProfile:          info.AuthorityProfile,
		E2EERequired:              info.E2EERequired,
		StorageEncryptionRequired: info.StorageEncryptionRequired,
		CryptoSuite:               strings.Join(info.CryptoSuite, "+"),
		KeyWrappingSuite:          info.KeyWrappingSuite,
		TenantIsolationProfile:    info.TenantIsolationProfile,
	}
}

func SegmentPrefixMatches(prefix string, candidate string) bool {
	prefixParts := splitSegments(prefix)
	candidateParts := splitSegments(candidate)

	if len(prefixParts) > len(candidateParts) {
		return false
	}

	for i := range prefixParts {
		if prefixParts[i] != candidateParts[i] {
			return false
		}
	}

	return true
}

func splitSegments(path string) []string {
	if path == "" {
		return []string{""}
	}

	parts := make([]string, 0, 8)
	current := ""
	for _, r := range path {
		if r == '/' {
			parts = append(parts, current)
			current = ""
			continue
		}
		current += string(r)
	}
	parts = append(parts, current)

	return parts
}
