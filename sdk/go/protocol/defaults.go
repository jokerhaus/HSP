package protocol

import "encoding/json"

func DefaultLimits() ServiceLimits {
	return ServiceLimits{
		MaxChunkSize:            4 * 1024 * 1024,
		MaxManifestSize:         8 * 1024 * 1024,
		MaxObjectSize:           4 * 1024 * 1024 * 1024,
		MaxParallelChunkStreams: 8,
	}
}

func DefaultSupportedChunkers() []string {
	return []string{"fixed-1m"}
}

func DefaultSupportedContentEncodings() []string {
	return []string{"identity"}
}

func PublicMultiTenantCryptoSuite() []string {
	return []string{
		"Ed25519",
		"COSE_Sign1",
		"XChaCha20-Poly1305",
		"AES-256-GCM",
		"SHA-256",
	}
}

func PublicMultiTenantBootstrapDocument(authority string, baseURL string) BootstrapDocument {
	return BootstrapDocument{
		Version:   1,
		Authority: authority,
		Native: BootstrapNativeEndpoint{
			ALPN: "hsp/1",
			Host: authority,
			Port: 443,
		},
		Gateway: BootstrapGatewayEndpoint{
			BaseURL: baseURL,
		},
		E2EERequired:              true,
		StorageEncryptionRequired: true,
		CryptoSuite:               PublicMultiTenantCryptoSuite(),
		KeyWrappingSuite:          "HPKE/X25519",
		TenantIsolationProfile:    "strict-per-tenant-key-domain",
		SupportedTokenProfiles:    []string{"cose-sign1"},
		SupportedExtensions: []string{
			"encrypted-store-alpha",
			"native-beta",
			"gateway-http3-beta",
		},
		LimitsRevision: 1,
		Limits:         DefaultLimits(),
	}
}

func PublicMultiTenantInfoResponse() InfoResponse {
	return InfoResponse{
		Version:                   1,
		AuthorityProfile:          "public-multi-tenant",
		E2EERequired:              true,
		StorageEncryptionRequired: true,
		CryptoSuite:               PublicMultiTenantCryptoSuite(),
		KeyWrappingSuite:          "HPKE/X25519",
		TenantIsolationProfile:    "strict-per-tenant-key-domain",
		SupportedTokenProfiles:    []string{"cose-sign1"},
		SupportedExtensions: []string{
			"encrypted-store-alpha",
			"native-beta",
			"gateway-http3-beta",
		},
		LimitsRevision: 1,
		Limits:         DefaultLimits(),
	}
}

func PublicMultiTenantSettingsFrame(serverInstanceID string) SettingsFrame {
	return SettingsFrame{
		MaxChunkSize:              DefaultLimits().MaxChunkSize,
		MaxManifestSize:           DefaultLimits().MaxManifestSize,
		MaxObjectSize:             DefaultLimits().MaxObjectSize,
		MaxParallelStreams:        DefaultLimits().MaxParallelChunkStreams,
		SupportedChunkers:         DefaultSupportedChunkers(),
		SupportedContentEncodings: DefaultSupportedContentEncodings(),
		SupportedTokenProfiles:    []string{"cose-sign1"},
		SupportedExtensions: []string{
			"encrypted-store-alpha",
			"native-beta",
			"gateway-http3-beta",
		},
		ServerInstanceID:     serverInstanceID,
		EventReplayWindowSec: 3600,
		LimitsRevision:       1,
	}
}

func ParseBootstrapDocument(data []byte) (BootstrapDocument, error) {
	var doc BootstrapDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return BootstrapDocument{}, err
	}

	if doc.Authority == "" || doc.Native.ALPN == "" || doc.Gateway.BaseURL == "" {
		return BootstrapDocument{}, &APIError{
			Category: ErrorCategoryValidation,
			Code:     "invalid_bootstrap_document",
			Message:  "bootstrap document is missing required fields",
		}
	}

	return doc, nil
}

func ValidateManifest(manifest Manifest) error {
	if manifest.StoredSize == 0 || manifest.LogicalSize == 0 {
		return &APIError{
			Category: ErrorCategoryValidation,
			Code:     "zero_sized_manifest",
			Message:  "logical_size and stored_size must be non-zero",
		}
	}

	if len(manifest.ChunkRefs) == 0 {
		return &APIError{
			Category: ErrorCategoryValidation,
			Code:     "empty_chunk_refs",
			Message:  "manifest must include chunk references",
		}
	}

	if manifest.EncryptionDescriptor.ContentEncryptionSuite == "" ||
		manifest.EncryptionDescriptor.KeyWrappingSuite == "" ||
		len(manifest.EncryptionDescriptor.WrappedObjectKeys) == 0 {
		return &APIError{
			Category: ErrorCategoryValidation,
			Code:     "invalid_encryption_descriptor",
			Message:  "manifest encryption descriptor is incomplete",
		}
	}

	return nil
}
