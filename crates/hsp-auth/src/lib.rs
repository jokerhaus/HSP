use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ciborium::de::from_reader;
use coset::{CborSerializable, CoseSign1};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hsp_core::{
    ApiError, ApiErrorCategory, CapabilityClaims, CapabilityScope, ChannelBindingProof,
    EncryptionProfileId, KeyPolicyId, NamespaceMutationRecord, OperationName, TenantId,
    VisibilityMode,
};
use hsp_path::segment_prefix_matches;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    pub claims: CapabilityClaims,
    pub channel_binding: Option<ChannelBindingProof>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayStatus {
    Fresh,
    IdempotentRetry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationDecision {
    pub replay_status: ReplayStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequestMeta<'a> {
    pub operation: OperationName,
    pub tenant_id: &'a TenantId,
    pub subject: &'a str,
    pub namespace: Option<&'a str>,
    pub path: Option<&'a str>,
    pub content_size: Option<u64>,
    pub key_policy_id: Option<&'a KeyPolicyId>,
    pub encryption_profile_id: Option<&'a EncryptionProfileId>,
    pub metadata_visibility: Option<VisibilityMode>,
    pub idempotency_key: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerRecord {
    pub issuer: String,
    pub key_id: String,
    pub algorithm: String,
    pub public_key_b64: String,
    pub audiences: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerRegistry {
    pub issuers: Vec<IssuerRecord>,
}

#[derive(Debug, Default)]
pub struct ReplayCache {
    seen: Mutex<HashMap<String, String>>,
}

#[derive(Debug, Default)]
pub struct PolicyEngine {
    replay_cache: ReplayCache,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialReason {
    TenantMismatch,
    OperationNotAllowed,
    MissingChannelBinding,
    MissingJti,
    MissingKeyPolicyId,
    MissingEncryptionProfileId,
    KeyPolicyMismatch,
    MetadataVisibilityMismatch,
    NamespaceScopeMismatch,
    PathScopeMismatch,
    ObjectTooLarge,
    ExpiredToken,
    NotYetValid,
    ReplayDetected,
    InvalidSignedRecord,
}

impl Display for DenialReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TenantMismatch => f.write_str("tenant mismatch"),
            Self::OperationNotAllowed => f.write_str("operation not allowed"),
            Self::MissingChannelBinding => f.write_str("missing channel binding"),
            Self::MissingJti => f.write_str("missing jti"),
            Self::MissingKeyPolicyId => f.write_str("missing key policy id"),
            Self::MissingEncryptionProfileId => f.write_str("missing encryption profile id"),
            Self::KeyPolicyMismatch => f.write_str("key policy mismatch"),
            Self::MetadataVisibilityMismatch => f.write_str("metadata visibility mismatch"),
            Self::NamespaceScopeMismatch => f.write_str("namespace scope mismatch"),
            Self::PathScopeMismatch => f.write_str("path scope mismatch"),
            Self::ObjectTooLarge => f.write_str("object too large"),
            Self::ExpiredToken => f.write_str("expired token"),
            Self::NotYetValid => f.write_str("token not yet valid"),
            Self::ReplayDetected => f.write_str("replay detected"),
            Self::InvalidSignedRecord => f.write_str("invalid signed record"),
        }
    }
}

impl std::error::Error for DenialReason {}

pub fn public_profile_requires_channel_binding() -> bool {
    true
}

pub fn mutation_requires_jti(operation: OperationName) -> bool {
    operation.is_mutation()
}

pub fn granular_admin_scopes() -> &'static [CapabilityScope] {
    &[
        CapabilityScope::AdminMetricsRead,
        CapabilityScope::AdminAuditRead,
        CapabilityScope::AdminRepair,
        CapabilityScope::AdminKeyRotate,
        CapabilityScope::AdminPolicyWrite,
    ]
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn authorize(
        &self,
        auth: &AuthContext,
        meta: &AuthRequestMeta<'_>,
    ) -> Result<AuthorizationDecision, DenialReason> {
        self.validate_time_window(&auth.claims)?;

        if auth.claims.tenant_id != *meta.tenant_id {
            return Err(DenialReason::TenantMismatch);
        }

        if !auth
            .claims
            .ops
            .iter()
            .any(|scope| scope_matches_operation(*scope, meta.operation))
        {
            return Err(DenialReason::OperationNotAllowed);
        }

        if meta.operation.is_mutation()
            && public_profile_requires_channel_binding()
            && auth.channel_binding.is_none()
        {
            return Err(DenialReason::MissingChannelBinding);
        }

        if operation_requires_object_crypto(meta.operation) && meta.key_policy_id.is_none() {
            return Err(DenialReason::MissingKeyPolicyId);
        }

        if operation_requires_object_crypto(meta.operation) && meta.encryption_profile_id.is_none()
        {
            return Err(DenialReason::MissingEncryptionProfileId);
        }

        if meta.operation.is_mutation() && auth.claims.jti.is_none() {
            return Err(DenialReason::MissingJti);
        }

        if let (Some(expected), Some(actual)) = (&auth.claims.key_policy_id, meta.key_policy_id) {
            if actual != expected {
                return Err(DenialReason::KeyPolicyMismatch);
            }
        }

        if let (Some(expected), Some(actual)) =
            (auth.claims.metadata_visibility, meta.metadata_visibility)
        {
            if actual != expected {
                return Err(DenialReason::MetadataVisibilityMismatch);
            }
        }

        if let Some(path_prefix) = &auth.claims.path_prefix {
            let path = meta.path.ok_or(DenialReason::PathScopeMismatch)?;
            if !segment_prefix_matches(path_prefix, path) {
                return Err(DenialReason::PathScopeMismatch);
            }
        }

        if let Some(namespace_prefix) = &auth.claims.namespace_prefix {
            let namespace = meta.namespace.ok_or(DenialReason::NamespaceScopeMismatch)?;
            if !segment_prefix_matches(namespace_prefix, namespace) {
                return Err(DenialReason::NamespaceScopeMismatch);
            }
        }

        if let (Some(max_object_size), Some(content_size)) =
            (auth.claims.max_object_size, meta.content_size)
        {
            if content_size > max_object_size {
                return Err(DenialReason::ObjectTooLarge);
            }
        }

        let replay_status = if let Some(jti) = &auth.claims.jti {
            self.replay_cache.observe(
                meta.tenant_id,
                jti,
                meta.operation,
                meta.subject,
                meta.idempotency_key,
            )?
        } else {
            ReplayStatus::Fresh
        };

        Ok(AuthorizationDecision { replay_status })
    }

    fn validate_time_window(&self, claims: &CapabilityClaims) -> Result<(), DenialReason> {
        let now = now_ms();

        if now > claims.exp {
            return Err(DenialReason::ExpiredToken);
        }

        if let Some(nbf) = claims.nbf {
            if now < nbf {
                return Err(DenialReason::NotYetValid);
            }
        }

        Ok(())
    }
}

impl ReplayCache {
    fn observe(
        &self,
        tenant_id: &TenantId,
        jti: &str,
        operation: OperationName,
        subject: &str,
        idempotency_key: Option<&str>,
    ) -> Result<ReplayStatus, DenialReason> {
        if !operation.is_mutation() {
            return Ok(ReplayStatus::Fresh);
        }

        let replay_key = format!("{tenant_id}|{jti}|{}|{subject}", operation.as_str());
        let mut guard = self.seen.lock().expect("replay cache lock poisoned");

        if let Some(existing_idempotency_key) = guard.get(&replay_key) {
            return if idempotency_key == Some(existing_idempotency_key.as_str()) {
                Ok(ReplayStatus::IdempotentRetry)
            } else {
                Err(DenialReason::ReplayDetected)
            };
        }

        guard.insert(replay_key, idempotency_key.unwrap_or_default().to_string());

        Ok(ReplayStatus::Fresh)
    }
}

pub fn denial_to_api_error(reason: DenialReason) -> ApiError {
    let (category, code) = match reason {
        DenialReason::ReplayDetected => (ApiErrorCategory::Replay, "replay_detected"),
        DenialReason::MissingChannelBinding => (ApiErrorCategory::Auth, "missing_channel_binding"),
        DenialReason::MissingJti => (ApiErrorCategory::Auth, "missing_jti"),
        DenialReason::TenantMismatch => (ApiErrorCategory::Auth, "tenant_mismatch"),
        DenialReason::OperationNotAllowed => (ApiErrorCategory::Auth, "operation_not_allowed"),
        DenialReason::MissingKeyPolicyId => (ApiErrorCategory::Policy, "missing_key_policy_id"),
        DenialReason::MissingEncryptionProfileId => {
            (ApiErrorCategory::Policy, "missing_encryption_profile_id")
        }
        DenialReason::KeyPolicyMismatch => (ApiErrorCategory::Policy, "key_policy_mismatch"),
        DenialReason::MetadataVisibilityMismatch => {
            (ApiErrorCategory::Policy, "metadata_visibility_mismatch")
        }
        DenialReason::NamespaceScopeMismatch => {
            (ApiErrorCategory::Policy, "namespace_scope_mismatch")
        }
        DenialReason::PathScopeMismatch => (ApiErrorCategory::Policy, "path_scope_mismatch"),
        DenialReason::ObjectTooLarge => (ApiErrorCategory::Validation, "object_too_large"),
        DenialReason::ExpiredToken => (ApiErrorCategory::Auth, "token_expired"),
        DenialReason::NotYetValid => (ApiErrorCategory::Auth, "token_not_yet_valid"),
        DenialReason::InvalidSignedRecord => (ApiErrorCategory::Auth, "invalid_signed_record"),
    };

    ApiError::new(category, code, reason.to_string())
}

fn scope_matches_operation(scope: CapabilityScope, operation: OperationName) -> bool {
    match operation {
        OperationName::Info | OperationName::Head | OperationName::Get | OperationName::Resolve => {
            scope == CapabilityScope::Read
        }
        OperationName::Bind => {
            matches!(scope, CapabilityScope::Bind | CapabilityScope::Write)
        }
        OperationName::Unbind => {
            matches!(
                scope,
                CapabilityScope::Unbind | CapabilityScope::Bind | CapabilityScope::Write
            )
        }
        OperationName::List => matches!(scope, CapabilityScope::List | CapabilityScope::Read),
        OperationName::Subscribe => {
            matches!(scope, CapabilityScope::Subscribe | CapabilityScope::Read)
        }
        OperationName::PutInit | OperationName::PutChunk | OperationName::PutCommit => {
            scope == CapabilityScope::Write
        }
    }
}

fn operation_requires_object_crypto(operation: OperationName) -> bool {
    matches!(
        operation,
        OperationName::PutInit | OperationName::PutChunk | OperationName::PutCommit
    )
}

impl IssuerRegistry {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ApiError> {
        let bytes = fs::read(path).map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Policy,
                "issuer_registry_read_failed",
                error.to_string(),
            )
        })?;
        serde_json::from_slice(&bytes).map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Policy,
                "issuer_registry_invalid",
                error.to_string(),
            )
        })
    }

    pub fn resolve(&self, issuer: &str) -> Option<&IssuerRecord> {
        self.issuers
            .iter()
            .find(|candidate| candidate.issuer == issuer)
    }

    pub fn resolve_key_id(&self, key_id: &[u8]) -> Option<&IssuerRecord> {
        let key_id = std::str::from_utf8(key_id).ok()?;
        self.issuers
            .iter()
            .find(|candidate| candidate.key_id == key_id)
    }
}

pub fn verify_cose_sign1_token(
    token_b64: &str,
    registry: &IssuerRegistry,
) -> Result<CapabilityClaims, ApiError> {
    verify_cose_sign1_payload(token_b64, registry, "capability token")
}

pub fn verify_signed_namespace_record(
    token_b64: &str,
    registry: &IssuerRegistry,
) -> Result<NamespaceMutationRecord, ApiError> {
    verify_cose_sign1_payload(token_b64, registry, "namespace mutation")
}

fn verify_cose_sign1_payload<T: DeserializeOwned + Serialize>(
    token_b64: &str,
    registry: &IssuerRegistry,
    payload_name: &str,
) -> Result<T, ApiError> {
    let token_bytes = URL_SAFE_NO_PAD.decode(token_b64.as_bytes()).map_err(|_| {
        ApiError::new(
            ApiErrorCategory::Auth,
            "invalid_token_base64",
            format!("invalid {payload_name} encoding"),
        )
    })?;
    let token = CoseSign1::from_slice(&token_bytes).map_err(|_| {
        ApiError::new(
            ApiErrorCategory::Auth,
            "invalid_token_format",
            format!("invalid COSE_Sign1 {payload_name}"),
        )
    })?;
    let payload = token.payload.as_deref().ok_or_else(|| {
        ApiError::new(
            ApiErrorCategory::Auth,
            "missing_token_payload",
            format!("{payload_name} payload is missing"),
        )
    })?;

    let claims: T = from_reader(payload).map_err(|_| {
        ApiError::new(
            ApiErrorCategory::Auth,
            "invalid_token_claims",
            format!("{payload_name} payload is not valid CBOR"),
        )
    })?;

    let claims_value = serde_json::to_value(&claims).ok();
    let issuer_name = claims_value.as_ref().and_then(|value| {
        value
            .get("iss")
            .and_then(|iss| iss.as_str())
            .map(ToString::to_string)
    });
    let audience = claims_value.as_ref().and_then(|value| {
        value
            .get("aud")
            .and_then(|aud| aud.as_str())
            .map(ToString::to_string)
    });

    let issuer = if let Some(issuer_name) = issuer_name {
        registry.resolve(&issuer_name)
    } else if !token.protected.header.key_id.is_empty() {
        registry.resolve_key_id(&token.protected.header.key_id)
    } else {
        None
    }
    .ok_or_else(|| {
        ApiError::new(
            ApiErrorCategory::Auth,
            "unknown_issuer",
            format!("{payload_name} signer is not trusted"),
        )
    })?;

    if issuer.algorithm != "Ed25519" {
        return Err(ApiError::new(
            ApiErrorCategory::Auth,
            "unsupported_token_algorithm",
            "issuer algorithm is not supported",
        ));
    }

    if !issuer.audiences.is_empty()
        && audience.as_ref().is_some_and(|audience| {
            !issuer
                .audiences
                .iter()
                .any(|candidate| candidate == audience)
        })
    {
        return Err(ApiError::new(
            ApiErrorCategory::Auth,
            "invalid_token_audience",
            format!("{payload_name} audience is not allowed by issuer registry"),
        ));
    }

    let public_key_bytes = URL_SAFE_NO_PAD
        .decode(issuer.public_key_b64.as_bytes())
        .map_err(|_| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_issuer_key",
                "issuer public key encoding is invalid",
            )
        })?;
    let verifying_key =
        VerifyingKey::from_bytes(public_key_bytes.as_slice().try_into().map_err(|_| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_issuer_key",
                "issuer public key must be 32 bytes",
            )
        })?)
        .map_err(|_| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_issuer_key",
                "issuer public key is invalid",
            )
        })?;

    token.verify_signature(b"", |signature_bytes, signing_input| {
        let signature = Signature::try_from(signature_bytes).map_err(|_| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_token_signature",
                "token signature is malformed",
            )
        })?;
        verifying_key
            .verify(signing_input, &signature)
            .map_err(|_| {
                ApiError::new(
                    ApiErrorCategory::Auth,
                    "invalid_token_signature",
                    "token signature verification failed",
                )
            })
    })?;

    Ok(claims)
}

pub fn verify_tls_exporter_binding(
    exported_key_material: &[u8],
    binding: &ChannelBindingProof,
) -> Result<(), ApiError> {
    if binding.binding_kind != "tls-exporter" {
        return Err(ApiError::new(
            ApiErrorCategory::Auth,
            "invalid_channel_binding",
            "unsupported channel binding kind",
        ));
    }

    let expected = URL_SAFE_NO_PAD.encode(exported_key_material);
    if binding.proof_b64 != expected {
        return Err(ApiError::new(
            ApiErrorCategory::Auth,
            "invalid_channel_binding",
            "channel binding proof verification failed",
        ));
    }

    Ok(())
}

pub fn tls_exporter_label() -> &'static [u8] {
    b"EXPORTER-HSP-Channel-Binding-v1"
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
    use ed25519_dalek::{Signer, SigningKey};
    use hsp_core::NamespaceMutationKind;

    fn auth_context() -> AuthContext {
        AuthContext {
            claims: CapabilityClaims {
                iss: "issuer".to_string(),
                sub: "subject".to_string(),
                aud: "hsp".to_string(),
                exp: now_ms() + 60_000,
                nbf: Some(now_ms() - 60_000),
                jti: Some("jti-1".to_string()),
                ops: vec![CapabilityScope::Read, CapabilityScope::Write],
                tenant_id: TenantId("tenant-alpha".to_string()),
                namespace_prefix: None,
                path_prefix: Some("tenant/a".to_string()),
                max_object_size: Some(4096),
                storage_classes: vec!["hot".to_string()],
                key_policy_id: Some(KeyPolicyId("policy-default".to_string())),
                metadata_visibility: Some(VisibilityMode::Split),
            },
            channel_binding: Some(ChannelBindingProof {
                binding_kind: "tls-exporter".to_string(),
                proof_b64: "ZmFrZQ".to_string(),
                nonce: "nonce-1".to_string(),
            }),
        }
    }

    #[test]
    fn public_profile_does_not_use_broad_admin_scope() {
        let scopes = granular_admin_scopes();
        assert!(scopes.contains(&CapabilityScope::AdminMetricsRead));
        assert!(!scopes.contains(&CapabilityScope::Read));
    }

    #[test]
    fn mutation_operations_require_jti() {
        assert!(mutation_requires_jti(OperationName::PutInit));
        assert!(!mutation_requires_jti(OperationName::Head));
    }

    #[test]
    fn public_profile_uses_channel_binding() {
        assert!(public_profile_requires_channel_binding());
    }

    #[test]
    fn authorize_mutation_happy_path() {
        let engine = PolicyEngine::new();
        let auth = auth_context();
        let tenant = TenantId("tenant-alpha".to_string());
        let key_policy = KeyPolicyId("policy-default".to_string());
        let encryption_profile = EncryptionProfileId("public-e2ee-v1".to_string());
        let meta = AuthRequestMeta {
            operation: OperationName::PutInit,
            tenant_id: &tenant,
            subject: "manifest-cid",
            namespace: None,
            path: Some("tenant/a/file"),
            content_size: Some(1024),
            key_policy_id: Some(&key_policy),
            encryption_profile_id: Some(&encryption_profile),
            metadata_visibility: Some(VisibilityMode::Split),
            idempotency_key: Some("idem-1"),
        };

        let decision = engine.authorize(&auth, &meta).unwrap();
        assert_eq!(decision.replay_status, ReplayStatus::Fresh);
    }

    #[test]
    fn head_does_not_require_key_policy_meta() {
        let engine = PolicyEngine::new();
        let auth = auth_context();
        let tenant = TenantId("tenant-alpha".to_string());
        let meta = AuthRequestMeta {
            operation: OperationName::Head,
            tenant_id: &tenant,
            subject: "manifest-cid",
            namespace: None,
            path: Some("tenant/a/file"),
            content_size: None,
            key_policy_id: None,
            encryption_profile_id: None,
            metadata_visibility: None,
            idempotency_key: None,
        };

        let decision = engine.authorize(&auth, &meta).unwrap();
        assert_eq!(decision.replay_status, ReplayStatus::Fresh);
    }

    #[test]
    fn duplicate_jti_with_same_idempotency_key_is_retry() {
        let engine = PolicyEngine::new();
        let auth = auth_context();
        let tenant = TenantId("tenant-alpha".to_string());
        let key_policy = KeyPolicyId("policy-default".to_string());
        let encryption_profile = EncryptionProfileId("public-e2ee-v1".to_string());
        let meta = AuthRequestMeta {
            operation: OperationName::PutCommit,
            tenant_id: &tenant,
            subject: "session-1",
            namespace: None,
            path: Some("tenant/a/file"),
            content_size: None,
            key_policy_id: Some(&key_policy),
            encryption_profile_id: Some(&encryption_profile),
            metadata_visibility: None,
            idempotency_key: Some("idem-1"),
        };

        assert_eq!(
            engine.authorize(&auth, &meta).unwrap().replay_status,
            ReplayStatus::Fresh
        );
        assert_eq!(
            engine.authorize(&auth, &meta).unwrap().replay_status,
            ReplayStatus::IdempotentRetry
        );
    }

    #[test]
    fn duplicate_jti_with_different_idempotency_key_is_replay() {
        let engine = PolicyEngine::new();
        let auth = auth_context();
        let tenant = TenantId("tenant-alpha".to_string());
        let key_policy = KeyPolicyId("policy-default".to_string());
        let encryption_profile = EncryptionProfileId("public-e2ee-v1".to_string());
        let first = AuthRequestMeta {
            operation: OperationName::PutCommit,
            tenant_id: &tenant,
            subject: "session-1",
            namespace: None,
            path: Some("tenant/a/file"),
            content_size: None,
            key_policy_id: Some(&key_policy),
            encryption_profile_id: Some(&encryption_profile),
            metadata_visibility: None,
            idempotency_key: Some("idem-1"),
        };
        let second = AuthRequestMeta {
            idempotency_key: Some("idem-2"),
            ..first.clone()
        };

        engine.authorize(&auth, &first).unwrap();
        assert_eq!(
            engine.authorize(&auth, &second),
            Err(DenialReason::ReplayDetected)
        );
    }

    #[test]
    fn signed_namespace_record_can_resolve_issuer_by_key_id() {
        let signing_key = SigningKey::from_bytes(&[13u8; 32]);
        let registry = IssuerRegistry {
            issuers: vec![IssuerRecord {
                issuer: "issuer".to_string(),
                key_id: "test-key".to_string(),
                algorithm: "Ed25519".to_string(),
                public_key_b64: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
                audiences: vec!["hsp".to_string()],
            }],
        };
        let record = NamespaceMutationRecord {
            version: 1,
            tenant_id: TenantId("tenant-alpha".to_string()),
            namespace: "docs".to_string(),
            path: "reports/q1".to_string(),
            kind: NamespaceMutationKind::Bind,
            target_cid: Some("sha256-manifest".to_string()),
            if_revision: None,
            ttl_ms: None,
            metadata: BTreeMap::new(),
            issued_at_ms: now_ms(),
        };
        let mut payload = Vec::new();
        ciborium::into_writer(&record, &mut payload).unwrap();
        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::EdDSA)
            .key_id(b"test-key".to_vec())
            .build();
        let cose = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(b"", |message| signing_key.sign(message).to_bytes().to_vec())
            .build();
        let token_b64 = URL_SAFE_NO_PAD.encode(cose.to_vec().unwrap());

        let verified = verify_signed_namespace_record(&token_b64, &registry).unwrap();
        assert_eq!(verified.path, "reports/q1");
        assert_eq!(verified.kind, NamespaceMutationKind::Bind);
    }
}
