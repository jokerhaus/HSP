package alpha

import (
	"fmt"
	"strings"
	"time"

	"github.com/loxar/hsp/sdk/go/protocol"
	security "github.com/loxar/hsp/sdk/go/security"
)

func ValidateMutationContext(
	claims protocol.CapabilityClaims,
	binding *protocol.ChannelBindingProof,
	tenantID protocol.TenantID,
	operation protocol.OperationName,
	path *string,
	contentSize *uint64,
	keyPolicyID *protocol.KeyPolicyID,
	encryptionProfileID *protocol.EncryptionProfileID,
	idempotencyKey *string,
) error {
	now := uint64(time.Now().UnixMilli())
	if claims.EXP < now {
		return &protocol.APIError{Category: protocol.ErrorCategoryAuth, Code: "token_expired", Message: "capability token expired"}
	}

	if claims.NBF != nil && *claims.NBF > now {
		return &protocol.APIError{Category: protocol.ErrorCategoryAuth, Code: "token_not_yet_valid", Message: "capability token not yet valid"}
	}

	if claims.TenantID != tenantID {
		return &protocol.APIError{Category: protocol.ErrorCategoryAuth, Code: "tenant_mismatch", Message: "tenant mismatch"}
	}

	if operation == protocol.OperationPutInit || operation == protocol.OperationPutChunk || operation == protocol.OperationPutCommit ||
		operation == protocol.OperationBind || operation == protocol.OperationUnbind {
		if binding == nil || binding.ProofBase64 == "" {
			return &protocol.APIError{Category: protocol.ErrorCategoryAuth, Code: "missing_channel_binding", Message: "channel binding proof is required"}
		}

		if claims.JTI == "" {
			return &protocol.APIError{Category: protocol.ErrorCategoryAuth, Code: "missing_jti", Message: "mutation tokens require jti"}
		}
	}

	if operation == protocol.OperationPutInit || operation == protocol.OperationPutChunk || operation == protocol.OperationPutCommit {
		if keyPolicyID == nil || *keyPolicyID == "" {
			return &protocol.APIError{Category: protocol.ErrorCategoryPolicy, Code: "missing_key_policy_id", Message: "key_policy_id is required"}
		}

		if encryptionProfileID == nil || *encryptionProfileID == "" {
			return &protocol.APIError{Category: protocol.ErrorCategoryPolicy, Code: "missing_encryption_profile_id", Message: "encryption_profile_id is required"}
		}

		if idempotencyKey == nil || *idempotencyKey == "" {
			return &protocol.APIError{Category: protocol.ErrorCategoryValidation, Code: "missing_idempotency_key", Message: "idempotency_key is required"}
		}
	}

	if claims.PathPrefix != "" {
		if path == nil || !security.SegmentPrefixMatches(claims.PathPrefix, *path) {
			return &protocol.APIError{Category: protocol.ErrorCategoryPolicy, Code: "path_scope_mismatch", Message: "path is outside capability scope"}
		}
	}

	if claims.NamespacePrefix != "" {
		if path == nil || !security.SegmentPrefixMatches(claims.NamespacePrefix, *path) {
			return &protocol.APIError{Category: protocol.ErrorCategoryPolicy, Code: "namespace_scope_mismatch", Message: "namespace is outside capability scope"}
		}
	}

	if claims.MaxObjectSize != nil && contentSize != nil && *contentSize > *claims.MaxObjectSize {
		return &protocol.APIError{Category: protocol.ErrorCategoryValidation, Code: "object_too_large", Message: "object exceeds max_object_size"}
	}

	if len(claims.OPS) > 0 {
		required := requiredScope(operation)
		if !hasScope(claims.OPS, required) {
			return &protocol.APIError{Category: protocol.ErrorCategoryAuth, Code: "operation_not_allowed", Message: fmt.Sprintf("operation %s is not permitted", operation)}
		}
	}

	return nil
}

func ValidateHeadResponse(response protocol.HeadResponse) error {
	if response.EncryptedClientMetadataRedacted == false &&
		response.MetadataVisibility != protocol.VisibilityModeServerVisible {
		return &protocol.APIError{
			Category: protocol.ErrorCategoryValidation,
			Code:     "metadata_redaction_violation",
			Message:  "encrypted client metadata must remain redacted in public profile",
		}
	}

	return nil
}

func ValidateGetResponseMeta(response protocol.GetResponseMeta) error {
	if response.EncryptedClientMetadataRedacted == false &&
		response.MetadataVisibility != protocol.VisibilityModeServerVisible {
		return &protocol.APIError{
			Category: protocol.ErrorCategoryValidation,
			Code:     "metadata_redaction_violation",
			Message:  "encrypted client metadata must remain redacted in public profile",
		}
	}

	return nil
}

func ValidateSettingsFrame(settings protocol.SettingsFrame) error {
	if settings.MaxChunkSize == 0 ||
		settings.MaxManifestSize == 0 ||
		settings.MaxObjectSize == 0 ||
		settings.MaxParallelStreams == 0 {
		return &protocol.APIError{
			Category: protocol.ErrorCategoryValidation,
			Code:     "invalid_settings_limits",
			Message:  "settings frame must publish non-zero transport limits",
		}
	}

	if settings.ServerInstanceID == "" {
		return &protocol.APIError{
			Category: protocol.ErrorCategoryValidation,
			Code:     "missing_server_instance_id",
			Message:  "settings frame must include server_instance_id",
		}
	}

	return nil
}

func SecurityDiagnostics() map[string]any {
	return map[string]any{
		"authority_profile":           protocol.PublicMultiTenantInfoResponse().AuthorityProfile,
		"e2ee_required":               true,
		"storage_encryption_required": true,
		"key_wrapping_suite":          "HPKE/X25519",
		"channel_binding_kind":        "tls-exporter",
		"chunk_stream_first":          true,
		"granular_admin_scopes": []string{
			string(protocol.CapabilityScopeAdminMetricsRead),
			string(protocol.CapabilityScopeAdminAuditRead),
			string(protocol.CapabilityScopeAdminRepair),
			string(protocol.CapabilityScopeAdminKeyRotate),
			string(protocol.CapabilityScopeAdminPolicyWrite),
		},
		"cross_tenant_plaintext_dedup": false,
	}
}

func requiredScope(operation protocol.OperationName) protocol.CapabilityScope {
	switch operation {
	case protocol.OperationInfo, protocol.OperationHead, protocol.OperationGet, protocol.OperationResolve:
		return protocol.CapabilityScopeRead
	case protocol.OperationBind:
		return protocol.CapabilityScopeBind
	case protocol.OperationUnbind:
		return protocol.CapabilityScopeUnbind
	case protocol.OperationList:
		return protocol.CapabilityScopeList
	case protocol.OperationSubscribe:
		return protocol.CapabilityScopeSubscribe
	default:
		return protocol.CapabilityScopeWrite
	}
}

func hasScope(scopes []protocol.CapabilityScope, required protocol.CapabilityScope) bool {
	for _, scope := range scopes {
		if strings.EqualFold(string(scope), string(required)) {
			return true
		}
	}

	return false
}
