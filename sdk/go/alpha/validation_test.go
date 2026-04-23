package alpha

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/loxar/hsp/sdk/go/protocol"
)

func validClaims() protocol.CapabilityClaims {
	nbf := uint64(time.Now().Add(-time.Minute).UnixMilli())
	maxSize := uint64(4096)
	visibility := protocol.VisibilityModeSplit

	return protocol.CapabilityClaims{
		ISS:                "issuer",
		SUB:                "subject",
		AUD:                "hsp",
		EXP:                uint64(time.Now().Add(time.Minute).UnixMilli()),
		NBF:                &nbf,
		JTI:                "jti-1",
		OPS:                []protocol.CapabilityScope{protocol.CapabilityScopeRead, protocol.CapabilityScopeWrite},
		TenantID:           protocol.TenantID("tenant-alpha"),
		PathPrefix:         "tenant/a",
		MaxObjectSize:      &maxSize,
		StorageClasses:     []string{"hot"},
		KeyPolicyID:        "policy-default",
		MetadataVisibility: &visibility,
	}
}

func TestValidateMutationContextHappyPath(t *testing.T) {
	path := "tenant/a/file"
	size := uint64(1024)
	keyPolicy := protocol.KeyPolicyID("policy-default")
	encryptionProfile := protocol.EncryptionProfileID("public-e2ee-v1")
	idempotencyKey := "idem-1"

	err := ValidateMutationContext(
		validClaims(),
		&protocol.ChannelBindingProof{
			BindingKind: "tls-exporter",
			ProofBase64: "ZmFrZQ",
			Nonce:       "nonce-1",
		},
		protocol.TenantID("tenant-alpha"),
		protocol.OperationPutInit,
		&path,
		&size,
		&keyPolicy,
		&encryptionProfile,
		&idempotencyKey,
	)
	if err != nil {
		t.Fatalf("expected happy path validation, got %v", err)
	}
}

func TestValidateMutationContextRejectsMissingBinding(t *testing.T) {
	path := "tenant/a/file"
	size := uint64(1024)
	keyPolicy := protocol.KeyPolicyID("policy-default")
	encryptionProfile := protocol.EncryptionProfileID("public-e2ee-v1")
	idempotencyKey := "idem-1"

	err := ValidateMutationContext(
		validClaims(),
		nil,
		protocol.TenantID("tenant-alpha"),
		protocol.OperationPutInit,
		&path,
		&size,
		&keyPolicy,
		&encryptionProfile,
		&idempotencyKey,
	)
	if err == nil {
		t.Fatal("expected missing channel binding to fail")
	}
}

func TestParseBootstrapDocument(t *testing.T) {
	data, err := json.Marshal(protocol.PublicMultiTenantBootstrapDocument("localhost", "https://localhost/v1/"))
	if err != nil {
		t.Fatalf("marshal bootstrap: %v", err)
	}

	doc, err := protocol.ParseBootstrapDocument(data)
	if err != nil {
		t.Fatalf("parse bootstrap: %v", err)
	}

	if !doc.E2EERequired || !doc.StorageEncryptionRequired {
		t.Fatal("expected bootstrap to require encryption")
	}
}

func TestValidateHeadResponseRedaction(t *testing.T) {
	err := ValidateHeadResponse(protocol.HeadResponse{
		ObjectCID:                       "sha256-example",
		ManifestCID:                     "sha256-example",
		StorageClass:                    "hot",
		LogicalSize:                     1,
		StoredSize:                      1,
		ContentType:                     "application/octet-stream",
		MetadataVisibility:              protocol.VisibilityModeSplit,
		ServerVisibleMetadata:           map[string]string{"content-language": "ru"},
		EncryptedClientMetadataRedacted: true,
	})
	if err != nil {
		t.Fatalf("expected valid redaction behavior, got %v", err)
	}
}

func TestValidateGetResponseMetaRedaction(t *testing.T) {
	err := ValidateGetResponseMeta(protocol.GetResponseMeta{
		ObjectCID:                       "sha256-example",
		ManifestCID:                     "sha256-example",
		StorageClass:                    "hot",
		LogicalSize:                     1,
		StoredSize:                      1,
		ContentType:                     "application/octet-stream",
		MetadataVisibility:              protocol.VisibilityModeSplit,
		ServerVisibleMetadata:           map[string]string{"content-language": "ru"},
		EncryptedClientMetadataRedacted: true,
		Preference:                      protocol.GetPreferenceChunkStream,
		ChunkDescriptors:                []protocol.GetChunkDescriptor{},
	})
	if err != nil {
		t.Fatalf("expected valid get redaction behavior, got %v", err)
	}
}

func TestValidateSettingsFrame(t *testing.T) {
	err := ValidateSettingsFrame(protocol.PublicMultiTenantSettingsFrame("server-1"))
	if err != nil {
		t.Fatalf("expected valid settings frame, got %v", err)
	}
}
