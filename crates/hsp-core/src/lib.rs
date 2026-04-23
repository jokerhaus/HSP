use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ciborium::value::Value as CiboriumValue;
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(pub String);

impl Display for TenantId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyPolicyId(pub String);

impl Display for KeyPolicyId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionProfileId(pub String);

impl Display for EncryptionProfileId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VisibilityMode {
    ServerVisible,
    EncryptedOnly,
    Split,
}

impl VisibilityMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ServerVisible => "server_visible",
            Self::EncryptedOnly => "encrypted_only",
            Self::Split => "split",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityScope {
    Read,
    Write,
    Bind,
    Unbind,
    List,
    Subscribe,
    Pin,
    Replicate,
    AdminMetricsRead,
    AdminAuditRead,
    AdminRepair,
    AdminKeyRotate,
    AdminPolicyWrite,
}

impl CapabilityScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Bind => "bind",
            Self::Unbind => "unbind",
            Self::List => "list",
            Self::Subscribe => "subscribe",
            Self::Pin => "pin",
            Self::Replicate => "replicate",
            Self::AdminMetricsRead => "admin.metrics.read",
            Self::AdminAuditRead => "admin.audit.read",
            Self::AdminRepair => "admin.repair",
            Self::AdminKeyRotate => "admin.key.rotate",
            Self::AdminPolicyWrite => "admin.policy.write",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationName {
    Info,
    Head,
    Get,
    Resolve,
    Bind,
    Unbind,
    List,
    Subscribe,
    PutInit,
    PutChunk,
    PutCommit,
}

impl OperationName {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Head => "HEAD",
            Self::Get => "GET",
            Self::Resolve => "RESOLVE",
            Self::Bind => "BIND",
            Self::Unbind => "UNBIND",
            Self::List => "LIST",
            Self::Subscribe => "SUBSCRIBE",
            Self::PutInit => "PUT_INIT",
            Self::PutChunk => "PUT_CHUNK",
            Self::PutCommit => "PUT_COMMIT",
        }
    }

    pub fn is_mutation(self) -> bool {
        matches!(
            self,
            Self::Bind | Self::Unbind | Self::PutInit | Self::PutChunk | Self::PutCommit
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApiErrorCategory {
    Auth,
    Replay,
    Policy,
    Validation,
    Unsupported,
    NotFound,
    Conflict,
    Storage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub category: ApiErrorCategory,
    pub code: String,
    pub message: String,
}

impl ApiError {
    pub fn new(
        category: ApiErrorCategory,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            category,
            code: code.into(),
            message: message.into(),
        }
    }
}

impl Display for ApiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceLimits {
    pub max_chunk_size: u64,
    pub max_manifest_size: u64,
    pub max_object_size: u64,
    pub max_parallel_chunk_streams: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapNativeEndpoint {
    pub alpn: String,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapGatewayEndpoint {
    pub base_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapDocument {
    pub version: u8,
    pub authority: String,
    pub native: BootstrapNativeEndpoint,
    pub gateway: BootstrapGatewayEndpoint,
    pub e2ee_required: bool,
    pub storage_encryption_required: bool,
    pub crypto_suite: Vec<String>,
    pub key_wrapping_suite: String,
    pub tenant_isolation_profile: String,
    pub supported_token_profiles: Vec<String>,
    pub supported_extensions: Vec<String>,
    pub limits_revision: u64,
    pub limits: ServiceLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfoResponse {
    pub version: u8,
    pub authority_profile: String,
    pub e2ee_required: bool,
    pub storage_encryption_required: bool,
    pub crypto_suite: Vec<String>,
    pub key_wrapping_suite: String,
    pub tenant_isolation_profile: String,
    pub supported_token_profiles: Vec<String>,
    pub supported_extensions: Vec<String>,
    pub limits_revision: u64,
    pub limits: ServiceLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedObjectKeyRecord {
    pub recipient_key_id: String,
    pub wrapping_suite: String,
    pub wrapped_key_b64: String,
    pub key_version: u32,
    pub encapsulated_key_b64: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionDescriptor {
    pub encryption_profile_id: EncryptionProfileId,
    pub key_policy_id: KeyPolicyId,
    pub content_encryption_suite: String,
    pub key_wrapping_suite: String,
    pub metadata_visibility: VisibilityMode,
    pub wrapped_object_keys: Vec<WrappedObjectKeyRecord>,
    pub server_visible_metadata: BTreeMap<String, String>,
    pub encrypted_client_metadata: BTreeMap<String, String>,
}

impl EncryptionDescriptor {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.content_encryption_suite.trim().is_empty() {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "missing_content_encryption_suite",
                "content_encryption_suite must be set",
            ));
        }

        if self.key_wrapping_suite.trim().is_empty() {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "missing_key_wrapping_suite",
                "key_wrapping_suite must be set",
            ));
        }

        if self.wrapped_object_keys.is_empty() {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "missing_wrapped_object_keys",
                "at least one wrapped object key record is required",
            ));
        }

        Ok(())
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            1,
            CanonicalValue::Text(self.encryption_profile_id.0.clone()),
        );
        map.insert(2, CanonicalValue::Text(self.key_policy_id.0.clone()));
        map.insert(
            3,
            CanonicalValue::Text(self.content_encryption_suite.clone()),
        );
        map.insert(4, CanonicalValue::Text(self.key_wrapping_suite.clone()));
        map.insert(
            5,
            CanonicalValue::Text(self.metadata_visibility.as_str().to_string()),
        );
        map.insert(
            6,
            CanonicalValue::Array(
                self.wrapped_object_keys
                    .iter()
                    .map(WrappedObjectKeyRecord::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            7,
            metadata_map_to_canonical_value(&self.server_visible_metadata),
        );
        map.insert(
            8,
            metadata_map_to_canonical_value(&self.encrypted_client_metadata),
        );

        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRef {
    pub chunk_index: u32,
    pub cid: String,
    pub offset: u64,
    pub logical_len: u64,
    pub stored_len: u64,
    pub content_encoding: String,
}

impl ChunkRef {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(1, CanonicalValue::Text(self.cid.clone()));
        map.insert(2, CanonicalValue::Unsigned(self.chunk_index as u64));
        map.insert(3, CanonicalValue::Unsigned(self.offset));
        map.insert(4, CanonicalValue::Unsigned(self.logical_len));
        map.insert(5, CanonicalValue::Unsigned(self.stored_len));
        map.insert(6, CanonicalValue::Text(self.content_encoding.clone()));

        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u8,
    pub tenant_id: TenantId,
    pub logical_size: u64,
    pub stored_size: u64,
    pub chunker: String,
    pub chunk_refs: Vec<ChunkRef>,
    pub content_type: String,
    pub created_at_ms: u64,
    pub encryption_descriptor: EncryptionDescriptor,
}

impl Manifest {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.chunk_refs.is_empty() {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "empty_chunk_refs",
                "manifest must contain at least one chunk reference",
            ));
        }

        if self.stored_size == 0 || self.logical_size == 0 {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "zero_sized_manifest",
                "logical_size and stored_size must be non-zero",
            ));
        }

        self.encryption_descriptor.validate()
    }

    pub fn canonical_cbor_bytes(&self) -> Vec<u8> {
        encode_canonical_cbor(&self.canonical_value())
    }

    pub fn manifest_cid(&self) -> String {
        cid_from_bytes(&self.canonical_cbor_bytes())
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(1, CanonicalValue::Unsigned(self.version as u64));
        map.insert(2, CanonicalValue::Text(self.tenant_id.0.clone()));
        map.insert(3, CanonicalValue::Unsigned(self.logical_size));
        map.insert(4, CanonicalValue::Unsigned(self.stored_size));
        map.insert(5, CanonicalValue::Text(self.chunker.clone()));
        map.insert(
            6,
            CanonicalValue::Array(
                self.chunk_refs
                    .iter()
                    .map(ChunkRef::canonical_value)
                    .collect(),
            ),
        );
        map.insert(7, CanonicalValue::Text(self.content_type.clone()));
        map.insert(8, CanonicalValue::Unsigned(self.created_at_ms));
        map.insert(9, self.encryption_descriptor.canonical_value());

        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelBindingProof {
    pub binding_kind: String,
    pub proof_b64: String,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: u64,
    pub nbf: Option<u64>,
    pub jti: Option<String>,
    pub ops: Vec<CapabilityScope>,
    pub tenant_id: TenantId,
    pub namespace_prefix: Option<String>,
    pub path_prefix: Option<String>,
    pub max_object_size: Option<u64>,
    pub storage_classes: Vec<String>,
    pub key_policy_id: Option<KeyPolicyId>,
    pub metadata_visibility: Option<VisibilityMode>,
}

impl CapabilityClaims {
    pub fn canonical_cbor_bytes(&self) -> Vec<u8> {
        encode_canonical_cbor(&self.canonical_value())
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(1, CanonicalValue::Text(self.iss.clone()));
        map.insert(2, CanonicalValue::Text(self.sub.clone()));
        map.insert(3, CanonicalValue::Text(self.aud.clone()));
        map.insert(4, CanonicalValue::Unsigned(self.exp));
        if let Some(nbf) = self.nbf {
            map.insert(5, CanonicalValue::Unsigned(nbf));
        }
        if let Some(jti) = &self.jti {
            map.insert(6, CanonicalValue::Text(jti.clone()));
        }
        map.insert(
            7,
            CanonicalValue::Array(
                self.ops
                    .iter()
                    .map(|scope| CanonicalValue::Text(scope.as_str().to_string()))
                    .collect(),
            ),
        );
        map.insert(8, CanonicalValue::Text(self.tenant_id.0.clone()));
        if let Some(namespace_prefix) = &self.namespace_prefix {
            map.insert(9, CanonicalValue::Text(namespace_prefix.clone()));
        }
        if let Some(path_prefix) = &self.path_prefix {
            map.insert(10, CanonicalValue::Text(path_prefix.clone()));
        }
        if let Some(max_object_size) = self.max_object_size {
            map.insert(11, CanonicalValue::Unsigned(max_object_size));
        }
        map.insert(
            12,
            CanonicalValue::Array(
                self.storage_classes
                    .iter()
                    .cloned()
                    .map(CanonicalValue::Text)
                    .collect(),
            ),
        );
        if let Some(key_policy_id) = &self.key_policy_id {
            map.insert(13, CanonicalValue::Text(key_policy_id.0.clone()));
        }
        if let Some(metadata_visibility) = self.metadata_visibility {
            map.insert(
                14,
                CanonicalValue::Text(metadata_visibility.as_str().to_string()),
            );
        }

        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectSelectorKind {
    Cid,
    Namespace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectSelector {
    pub kind: ObjectSelectorKind,
    pub cid: Option<String>,
    pub namespace: Option<String>,
    pub path: Option<String>,
}

impl ObjectSelector {
    pub fn cid(cid: impl Into<String>) -> Self {
        Self {
            kind: ObjectSelectorKind::Cid,
            cid: Some(cid.into()),
            namespace: None,
            path: None,
        }
    }

    pub fn namespace(namespace: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            kind: ObjectSelectorKind::Namespace,
            cid: None,
            namespace: Some(namespace.into()),
            path: Some(path.into()),
        }
    }

    pub fn validate(&self) -> Result<(), ApiError> {
        match self.kind {
            ObjectSelectorKind::Cid => {
                if self.cid.as_deref().unwrap_or_default().is_empty() {
                    return Err(ApiError::new(
                        ApiErrorCategory::Validation,
                        "missing_cid_selector",
                        "cid selector must include cid",
                    ));
                }
            }
            ObjectSelectorKind::Namespace => {
                if self.namespace.as_deref().unwrap_or_default().is_empty()
                    || self.path.as_deref().unwrap_or_default().is_empty()
                {
                    return Err(ApiError::new(
                        ApiErrorCategory::Validation,
                        "missing_namespace_selector",
                        "namespace selector must include namespace and path",
                    ));
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicBindRequest {
    pub namespace: String,
    pub path: String,
    pub if_revision: Option<u64>,
    pub metadata: BTreeMap<String, String>,
    pub ttl_ms: Option<u64>,
    pub signed_record_b64: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceMutationKind {
    Bind,
    Unbind,
    HardDelete,
}

impl NamespaceMutationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::Unbind => "unbind",
            Self::HardDelete => "hard_delete",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceMutationRecord {
    pub version: u8,
    pub tenant_id: TenantId,
    pub namespace: String,
    pub path: String,
    pub kind: NamespaceMutationKind,
    pub target_cid: Option<String>,
    pub if_revision: Option<u64>,
    pub ttl_ms: Option<u64>,
    pub metadata: BTreeMap<String, String>,
    pub issued_at_ms: u64,
}

impl NamespaceMutationRecord {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.namespace.trim().is_empty() {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "missing_namespace",
                "namespace mutation must include namespace",
            ));
        }

        if self.path.trim().is_empty() {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "missing_path",
                "namespace mutation must include path",
            ));
        }

        if self.kind == NamespaceMutationKind::Bind
            && self.target_cid.as_deref().unwrap_or_default().is_empty()
        {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "missing_target_cid",
                "bind mutation must include target_cid",
            ));
        }

        Ok(())
    }

    pub fn canonical_cbor_bytes(&self) -> Vec<u8> {
        encode_canonical_cbor(&self.canonical_value())
    }

    pub fn record_cid(&self) -> String {
        cid_from_bytes(&self.canonical_cbor_bytes())
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(1, CanonicalValue::Unsigned(self.version as u64));
        map.insert(2, CanonicalValue::Text(self.tenant_id.0.clone()));
        map.insert(3, CanonicalValue::Text(self.namespace.clone()));
        map.insert(4, CanonicalValue::Text(self.path.clone()));
        map.insert(5, CanonicalValue::Text(self.kind.as_str().to_string()));
        if let Some(target_cid) = &self.target_cid {
            map.insert(6, CanonicalValue::Text(target_cid.clone()));
        }
        if let Some(if_revision) = self.if_revision {
            map.insert(7, CanonicalValue::Unsigned(if_revision));
        }
        if let Some(ttl_ms) = self.ttl_ms {
            map.insert(8, CanonicalValue::Unsigned(ttl_ms));
        }
        map.insert(9, metadata_map_to_canonical_value(&self.metadata));
        map.insert(10, CanonicalValue::Unsigned(self.issued_at_ms));
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedNamespaceMutation {
    pub record: NamespaceMutationRecord,
    pub cose_sign1_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveRequest {
    pub tenant_id: TenantId,
    pub namespace: String,
    pub path: String,
    pub at_revision: Option<u64>,
    pub if_revision: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveResponse {
    pub revision: u64,
    pub target_cid: Option<String>,
    pub manifest_cid: Option<String>,
    pub record_cid: String,
    pub metadata: BTreeMap<String, String>,
    pub tombstone: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindRequest {
    pub tenant_id: TenantId,
    pub namespace: String,
    pub path: String,
    pub target_cid: String,
    pub if_revision: Option<u64>,
    pub if_absent: bool,
    pub metadata: BTreeMap<String, String>,
    pub ttl_ms: Option<u64>,
    pub idempotency_key: String,
    pub signed_record_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindResponse {
    pub revision: u64,
    pub record_cid: String,
    pub event_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnbindRequest {
    pub tenant_id: TenantId,
    pub namespace: String,
    pub path: String,
    pub if_revision: u64,
    pub hard_delete: bool,
    pub idempotency_key: String,
    pub signed_record_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnbindResponse {
    pub revision: u64,
    pub record_cid: String,
    pub event_seq: u64,
    pub tombstone: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListRequest {
    pub tenant_id: TenantId,
    pub namespace: String,
    pub prefix: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub recursive: bool,
    pub include_tombstones: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListItem {
    pub namespace: String,
    pub path: String,
    pub target_cid: Option<String>,
    pub manifest_cid: Option<String>,
    pub revision: u64,
    pub record_cid: String,
    pub metadata: BTreeMap<String, String>,
    pub tombstone: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListResponse {
    pub items: Vec<ListItem>,
    pub next_cursor: Option<String>,
    pub truncated: bool,
    pub namespace_revision_snapshot: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListCursor {
    pub tenant_id: TenantId,
    pub namespace: String,
    pub prefix: Option<String>,
    pub snapshot_revision: u64,
    pub last_path: String,
}

impl ListCursor {
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(encode_canonical_cbor(&self.canonical_value()))
    }

    pub fn decode(encoded: &str) -> Result<Self, ApiError> {
        let bytes = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| {
            ApiError::new(
                ApiErrorCategory::Validation,
                "invalid_cursor",
                "cursor is not valid base64url data",
            )
        })?;
        let value: CiboriumValue = ciborium::from_reader(bytes.as_slice()).map_err(|_| {
            ApiError::new(
                ApiErrorCategory::Validation,
                "invalid_cursor",
                "cursor is not valid CBOR",
            )
        })?;
        let CiboriumValue::Map(map) = value else {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "invalid_cursor",
                "cursor payload must be a CBOR map",
            ));
        };
        Ok(Self {
            tenant_id: TenantId(required_cbor_text(&map, 1, "tenant_id")?),
            namespace: required_cbor_text(&map, 2, "namespace")?,
            prefix: optional_cbor_text(&map, 3)?,
            snapshot_revision: required_cbor_u64(&map, 4, "snapshot_revision")?,
            last_path: required_cbor_text(&map, 5, "last_path")?,
        })
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(1, CanonicalValue::Text(self.tenant_id.0.clone()));
        map.insert(2, CanonicalValue::Text(self.namespace.clone()));
        if let Some(prefix) = &self.prefix {
            map.insert(3, CanonicalValue::Text(prefix.clone()));
        }
        map.insert(4, CanonicalValue::Unsigned(self.snapshot_revision));
        map.insert(5, CanonicalValue::Text(self.last_path.clone()));
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    #[serde(rename = "object.committed")]
    ObjectCommitted,
    #[serde(rename = "namespace.bound")]
    NamespaceBound,
    #[serde(rename = "namespace.unbound")]
    NamespaceUnbound,
    #[serde(rename = "namespace.tombstoned")]
    NamespaceTombstoned,
    #[serde(rename = "auth.denied")]
    AuthDenied,
    #[serde(rename = "pin.accepted")]
    PinAccepted,
}

impl EventType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ObjectCommitted => "object.committed",
            Self::NamespaceBound => "namespace.bound",
            Self::NamespaceUnbound => "namespace.unbound",
            Self::NamespaceTombstoned => "namespace.tombstoned",
            Self::AuthDenied => "auth.denied",
            Self::PinAccepted => "pin.accepted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    pub version: u8,
    pub seq: u64,
    pub at_ms: u64,
    pub event_type: EventType,
    pub subject_kind: String,
    pub namespace: Option<String>,
    pub path: Option<String>,
    pub cid: Option<String>,
    pub revision: Option<u64>,
    pub trace_id: Option<String>,
    pub payload: BTreeMap<String, String>,
}

impl EventRecord {
    pub fn canonical_cbor_bytes(&self) -> Vec<u8> {
        encode_canonical_cbor(&self.canonical_value())
    }

    pub fn event_cid(&self) -> String {
        cid_from_bytes(&self.canonical_cbor_bytes())
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(0, CanonicalValue::Unsigned(self.version as u64));
        map.insert(1, CanonicalValue::Unsigned(self.seq));
        map.insert(2, CanonicalValue::Unsigned(self.at_ms));
        map.insert(
            3,
            CanonicalValue::Text(self.event_type.as_str().to_string()),
        );
        map.insert(4, CanonicalValue::Text(self.subject_kind.clone()));
        if let Some(namespace) = &self.namespace {
            map.insert(5, CanonicalValue::Text(namespace.clone()));
        }
        if let Some(path) = &self.path {
            map.insert(6, CanonicalValue::Text(path.clone()));
        }
        if let Some(cid) = &self.cid {
            map.insert(7, CanonicalValue::Text(cid.clone()));
        }
        if let Some(revision) = self.revision {
            map.insert(8, CanonicalValue::Unsigned(revision));
        }
        if let Some(trace_id) = &self.trace_id {
            map.insert(9, CanonicalValue::Text(trace_id.clone()));
        }
        map.insert(10, metadata_map_to_canonical_value(&self.payload));
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventCursor {
    pub tenant_id: TenantId,
    pub next_seq: u64,
}

impl EventCursor {
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(encode_canonical_cbor(&self.canonical_value()))
    }

    pub fn decode(encoded: &str) -> Result<Self, ApiError> {
        let bytes = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| {
            ApiError::new(
                ApiErrorCategory::Validation,
                "invalid_cursor",
                "cursor is not valid base64url data",
            )
        })?;
        let value: CiboriumValue = ciborium::from_reader(bytes.as_slice()).map_err(|_| {
            ApiError::new(
                ApiErrorCategory::Validation,
                "invalid_cursor",
                "cursor is not valid CBOR",
            )
        })?;
        let CiboriumValue::Map(map) = value else {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "invalid_cursor",
                "cursor payload must be a CBOR map",
            ));
        };
        Ok(Self {
            tenant_id: TenantId(required_cbor_text(&map, 1, "tenant_id")?),
            next_seq: required_cbor_u64(&map, 2, "next_seq")?,
        })
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(1, CanonicalValue::Text(self.tenant_id.0.clone()));
        map.insert(2, CanonicalValue::Unsigned(self.next_seq));
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscribeFilter {
    pub namespace_prefix: Option<String>,
    pub path_exact: Option<String>,
    pub object_cid: Option<String>,
    pub event_type: Option<EventType>,
    pub tenant_scope: Option<TenantId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscribeRequest {
    pub tenant_id: TenantId,
    pub filters: Vec<SubscribeFilter>,
    pub cursor: Option<String>,
    pub from_seq: Option<u64>,
    pub heartbeat_ms: Option<u64>,
    pub batch_max: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoticeFrame {
    pub kind: String,
    pub message: Option<String>,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscribeEnvelopeKind {
    Event,
    Notice,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscribeEnvelope {
    pub kind: SubscribeEnvelopeKind,
    pub event: Option<EventRecord>,
    pub notice: Option<NoticeFrame>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutInitRequest {
    pub tenant_id: TenantId,
    pub manifest: Manifest,
    pub idempotency_key: String,
    pub encryption_profile_id: EncryptionProfileId,
    pub key_policy_id: KeyPolicyId,
    pub metadata_visibility: VisibilityMode,
    pub storage_class: String,
    pub atomic_bind: Option<AtomicBindRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutInitResponse {
    pub session_id: String,
    pub missing_chunks: Vec<u32>,
    pub accepted_manifest_cid: String,
    pub upload_deadline_ms: u64,
    pub max_parallel_chunk_streams: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutChunkRequest {
    pub tenant_id: TenantId,
    pub session_id: String,
    pub chunk_index: u32,
    pub chunk_cid: String,
    pub chunk_offset: u64,
    pub chunk_length: u64,
    pub content_encoding: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutChunkResponse {
    pub stored: bool,
    pub duplicate: bool,
    pub verified_cid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutCommitRequest {
    pub tenant_id: TenantId,
    pub session_id: String,
    pub manifest_cid: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutCommitResponse {
    pub object_cid: String,
    pub committed: bool,
    pub event_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GetPreference {
    Raw,
    ChunkStream,
    ManifestOnly,
}

impl GetPreference {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::ChunkStream => "chunk-stream",
            Self::ManifestOnly => "manifest-only",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeSpec {
    pub start: u64,
    pub end: u64,
}

impl RangeSpec {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.start > self.end {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "invalid_range",
                "range start must be less than or equal to end",
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadRequest {
    pub tenant_id: TenantId,
    pub selector: ObjectSelector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadResponse {
    pub object_cid: String,
    pub manifest_cid: String,
    pub storage_class: String,
    pub resolved_namespace: Option<String>,
    pub resolved_path: Option<String>,
    pub resolved_revision: Option<u64>,
    pub resolved_record_cid: Option<String>,
    pub logical_size: u64,
    pub stored_size: u64,
    pub content_type: String,
    pub metadata_visibility: VisibilityMode,
    pub server_visible_metadata: BTreeMap<String, String>,
    pub encrypted_client_metadata_redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetRequest {
    pub tenant_id: TenantId,
    pub selector: ObjectSelector,
    pub preference: Option<GetPreference>,
    pub range: Option<RangeSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetChunkDescriptor {
    pub chunk_index: u32,
    pub chunk_cid: String,
    pub chunk_offset: u64,
    pub logical_range_start: u64,
    pub logical_range_end: u64,
    pub fragment_offset: u64,
    pub fragment_length: u64,
    pub content_encoding: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetResponseMeta {
    pub object_cid: String,
    pub manifest_cid: String,
    pub storage_class: String,
    pub resolved_namespace: Option<String>,
    pub resolved_path: Option<String>,
    pub resolved_revision: Option<u64>,
    pub resolved_record_cid: Option<String>,
    pub logical_size: u64,
    pub stored_size: u64,
    pub content_type: String,
    pub metadata_visibility: VisibilityMode,
    pub server_visible_metadata: BTreeMap<String, String>,
    pub encrypted_client_metadata_redacted: bool,
    pub preference: GetPreference,
    pub manifest: Option<Manifest>,
    pub chunk_descriptors: Vec<GetChunkDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetChunk {
    pub descriptor: GetChunkDescriptor,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetResponse {
    pub meta: GetResponseMeta,
    pub chunks: Vec<GetChunk>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsFrame {
    pub max_chunk_size: u64,
    pub max_manifest_size: u64,
    pub max_object_size: u64,
    pub max_parallel_streams: u16,
    pub supported_chunkers: Vec<String>,
    pub supported_content_encodings: Vec<String>,
    pub supported_token_profiles: Vec<String>,
    pub supported_extensions: Vec<String>,
    pub server_instance_id: String,
    pub event_replay_window_sec: u64,
    pub limits_revision: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadMode {
    None,
    Json,
    Raw,
    ChunkStream,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReqHeader {
    pub version: u8,
    pub operation: OperationName,
    pub request_id: Option<u64>,
    pub payload_mode: Option<PayloadMode>,
    pub payload_length: Option<u64>,
    pub params: BTreeMap<String, JsonValue>,
    pub extensions: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResHeader {
    pub version: u8,
    pub status_code: u16,
    pub request_id: Option<u64>,
    pub payload_mode: Option<PayloadMode>,
    pub payload_length: Option<u64>,
    pub meta: BTreeMap<String, JsonValue>,
    pub extensions: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireErrorFrame {
    pub category: ApiErrorCategory,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoAwayFrame {
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthFrame {
    pub token_b64: String,
    pub channel_binding: ChannelBindingProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessReport {
    pub ready: bool,
    pub kms_provider: String,
    pub encrypted_store_roots: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestRequirements {
    pub encryption_descriptor_required: bool,
    pub metadata_hidden_by_default: bool,
    pub put_init_requires_key_policy: bool,
}

pub fn public_multitenant_manifest_requirements() -> ManifestRequirements {
    ManifestRequirements {
        encryption_descriptor_required: true,
        metadata_hidden_by_default: true,
        put_init_requires_key_policy: true,
    }
}

pub fn public_admin_scopes() -> &'static [CapabilityScope] {
    &[
        CapabilityScope::AdminMetricsRead,
        CapabilityScope::AdminAuditRead,
        CapabilityScope::AdminRepair,
        CapabilityScope::AdminKeyRotate,
        CapabilityScope::AdminPolicyWrite,
    ]
}

pub fn default_limits() -> ServiceLimits {
    ServiceLimits {
        max_chunk_size: 4 * 1024 * 1024,
        max_manifest_size: 8 * 1024 * 1024,
        max_object_size: 4 * 1024 * 1024 * 1024,
        max_parallel_chunk_streams: 8,
    }
}

pub fn default_supported_chunkers() -> Vec<String> {
    vec!["fixed-1m".to_string()]
}

pub fn default_supported_content_encodings() -> Vec<String> {
    vec!["identity".to_string()]
}

pub fn public_multitenant_crypto_suite() -> Vec<String> {
    vec![
        "Ed25519".to_string(),
        "COSE_Sign1".to_string(),
        "XChaCha20-Poly1305".to_string(),
        "AES-256-GCM".to_string(),
        "SHA-256".to_string(),
    ]
}

pub fn public_multitenant_bootstrap_document(authority: &str, base_url: &str) -> BootstrapDocument {
    BootstrapDocument {
        version: 1,
        authority: authority.to_string(),
        native: BootstrapNativeEndpoint {
            alpn: "hsp/1".to_string(),
            host: authority.to_string(),
            port: 443,
        },
        gateway: BootstrapGatewayEndpoint {
            base_url: base_url.to_string(),
        },
        e2ee_required: true,
        storage_encryption_required: true,
        crypto_suite: public_multitenant_crypto_suite(),
        key_wrapping_suite: "HPKE/X25519".to_string(),
        tenant_isolation_profile: "strict-per-tenant-key-domain".to_string(),
        supported_token_profiles: vec!["cose-sign1".to_string()],
        supported_extensions: vec![
            "encrypted-store-alpha".to_string(),
            "native-beta".to_string(),
            "gateway-http3-beta".to_string(),
        ],
        limits_revision: 1,
        limits: default_limits(),
    }
}

pub fn public_multitenant_info_response() -> InfoResponse {
    InfoResponse {
        version: 1,
        authority_profile: "public-multi-tenant".to_string(),
        e2ee_required: true,
        storage_encryption_required: true,
        crypto_suite: public_multitenant_crypto_suite(),
        key_wrapping_suite: "HPKE/X25519".to_string(),
        tenant_isolation_profile: "strict-per-tenant-key-domain".to_string(),
        supported_token_profiles: vec!["cose-sign1".to_string()],
        supported_extensions: vec![
            "encrypted-store-alpha".to_string(),
            "native-beta".to_string(),
            "gateway-http3-beta".to_string(),
        ],
        limits_revision: 1,
        limits: default_limits(),
    }
}

pub fn public_multitenant_settings_frame(server_instance_id: impl Into<String>) -> SettingsFrame {
    SettingsFrame {
        max_chunk_size: default_limits().max_chunk_size,
        max_manifest_size: default_limits().max_manifest_size,
        max_object_size: default_limits().max_object_size,
        max_parallel_streams: default_limits().max_parallel_chunk_streams,
        supported_chunkers: default_supported_chunkers(),
        supported_content_encodings: default_supported_content_encodings(),
        supported_token_profiles: vec!["cose-sign1".to_string()],
        supported_extensions: vec![
            "encrypted-store-alpha".to_string(),
            "native-beta".to_string(),
            "gateway-http3-beta".to_string(),
        ],
        server_instance_id: server_instance_id.into(),
        event_replay_window_sec: 3_600,
        limits_revision: 1,
    }
}

pub fn cid_from_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let encoded = BASE32_NOPAD.encode(digest.as_slice()).to_ascii_lowercase();
    format!("sha256-{encoded}")
}

pub fn metadata_map_to_canonical_value(metadata: &BTreeMap<String, String>) -> CanonicalValue {
    CanonicalValue::Array(
        metadata
            .iter()
            .map(|(key, value)| {
                CanonicalValue::Array(vec![
                    CanonicalValue::Text(key.clone()),
                    CanonicalValue::Text(value.clone()),
                ])
            })
            .collect(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalValue {
    Unsigned(u64),
    Text(String),
    Bytes(Vec<u8>),
    Bool(bool),
    Array(Vec<CanonicalValue>),
    Map(BTreeMap<u64, CanonicalValue>),
}

pub fn encode_canonical_cbor(value: &CanonicalValue) -> Vec<u8> {
    let mut output = Vec::new();
    encode_value(value, &mut output);
    output
}

fn encode_value(value: &CanonicalValue, output: &mut Vec<u8>) {
    match value {
        CanonicalValue::Unsigned(number) => encode_major(0, *number, output),
        CanonicalValue::Bytes(bytes) => {
            encode_major(2, bytes.len() as u64, output);
            output.extend_from_slice(bytes);
        }
        CanonicalValue::Text(text) => {
            encode_major(3, text.len() as u64, output);
            output.extend_from_slice(text.as_bytes());
        }
        CanonicalValue::Array(items) => {
            encode_major(4, items.len() as u64, output);
            for item in items {
                encode_value(item, output);
            }
        }
        CanonicalValue::Map(entries) => {
            encode_major(5, entries.len() as u64, output);
            for (key, value) in entries {
                encode_major(0, *key, output);
                encode_value(value, output);
            }
        }
        CanonicalValue::Bool(false) => output.push(0xf4),
        CanonicalValue::Bool(true) => output.push(0xf5),
    }
}

fn encode_major(major: u8, value: u64, output: &mut Vec<u8>) {
    match value {
        0..=23 => output.push((major << 5) | value as u8),
        24..=0xff => {
            output.push((major << 5) | 24);
            output.push(value as u8);
        }
        0x100..=0xffff => {
            output.push((major << 5) | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push((major << 5) | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push((major << 5) | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn required_cbor_text(
    entries: &[(CiboriumValue, CiboriumValue)],
    key: u64,
    field: &str,
) -> Result<String, ApiError> {
    match entries
        .iter()
        .find(|(candidate, _)| cbor_key_eq(candidate, key))
        .map(|(_, value)| value)
    {
        Some(CiboriumValue::Text(text)) if !text.is_empty() => Ok(text.clone()),
        _ => Err(ApiError::new(
            ApiErrorCategory::Validation,
            "invalid_cursor",
            format!("cursor field {field} is missing or invalid"),
        )),
    }
}

fn optional_cbor_text(
    entries: &[(CiboriumValue, CiboriumValue)],
    key: u64,
) -> Result<Option<String>, ApiError> {
    match entries
        .iter()
        .find(|(candidate, _)| cbor_key_eq(candidate, key))
        .map(|(_, value)| value)
    {
        Some(CiboriumValue::Text(text)) => Ok(Some(text.clone())),
        Some(_) => Err(ApiError::new(
            ApiErrorCategory::Validation,
            "invalid_cursor",
            "cursor text field is invalid",
        )),
        None => Ok(None),
    }
}

fn required_cbor_u64(
    entries: &[(CiboriumValue, CiboriumValue)],
    key: u64,
    field: &str,
) -> Result<u64, ApiError> {
    match entries
        .iter()
        .find(|(candidate, _)| cbor_key_eq(candidate, key))
        .map(|(_, value)| value)
    {
        Some(CiboriumValue::Integer(value)) => {
            let numeric: i128 = (*value).into();
            u64::try_from(numeric).map_err(|_| {
                ApiError::new(
                    ApiErrorCategory::Validation,
                    "invalid_cursor",
                    format!("cursor field {field} must be unsigned"),
                )
            })
        }
        _ => Err(ApiError::new(
            ApiErrorCategory::Validation,
            "invalid_cursor",
            format!("cursor field {field} is missing or invalid"),
        )),
    }
}

fn cbor_key_eq(value: &CiboriumValue, key: u64) -> bool {
    match value {
        CiboriumValue::Integer(integer) => {
            let candidate: i128 = (*integer).into();
            candidate == key as i128
        }
        _ => false,
    }
}

impl WrappedObjectKeyRecord {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(1, CanonicalValue::Text(self.recipient_key_id.clone()));
        map.insert(2, CanonicalValue::Text(self.wrapping_suite.clone()));
        map.insert(3, CanonicalValue::Text(self.wrapped_key_b64.clone()));
        map.insert(4, CanonicalValue::Unsigned(self.key_version as u64));
        if let Some(encapsulated_key_b64) = &self.encapsulated_key_b64 {
            map.insert(5, CanonicalValue::Text(encapsulated_key_b64.clone()));
        }

        CanonicalValue::Map(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> Manifest {
        let mut server_visible_metadata = BTreeMap::new();
        server_visible_metadata.insert("content-language".to_string(), "ru".to_string());

        let mut encrypted_client_metadata = BTreeMap::new();
        encrypted_client_metadata.insert("owner".to_string(), "alice".to_string());

        Manifest {
            version: 1,
            tenant_id: TenantId("tenant-alpha".to_string()),
            logical_size: 1024,
            stored_size: 1024,
            chunker: "fixed-1m".to_string(),
            chunk_refs: vec![ChunkRef {
                chunk_index: 0,
                cid: "sha256-example".to_string(),
                offset: 0,
                logical_len: 1024,
                stored_len: 1024,
                content_encoding: "identity".to_string(),
            }],
            content_type: "application/octet-stream".to_string(),
            created_at_ms: 1_713_632_400_000,
            encryption_descriptor: EncryptionDescriptor {
                encryption_profile_id: EncryptionProfileId("public-e2ee-v1".to_string()),
                key_policy_id: KeyPolicyId("policy-default".to_string()),
                content_encryption_suite: "XChaCha20-Poly1305".to_string(),
                key_wrapping_suite: "HPKE/X25519".to_string(),
                metadata_visibility: VisibilityMode::Split,
                wrapped_object_keys: vec![WrappedObjectKeyRecord {
                    recipient_key_id: "reader-1".to_string(),
                    wrapping_suite: "HPKE/X25519".to_string(),
                    wrapped_key_b64: "ZmFrZQ".to_string(),
                    key_version: 1,
                    encapsulated_key_b64: Some("ZW5jYXA".to_string()),
                }],
                server_visible_metadata,
                encrypted_client_metadata,
            },
        }
    }

    #[test]
    fn public_profile_requires_encryption() {
        let info = public_multitenant_info_response();
        assert!(info.e2ee_required);
        assert!(info.storage_encryption_required);
        assert_eq!(info.key_wrapping_suite, "HPKE/X25519");
    }

    #[test]
    fn manifest_requires_encryption_descriptor() {
        let manifest = public_multitenant_manifest_requirements();
        assert!(manifest.encryption_descriptor_required);
        assert!(manifest.metadata_hidden_by_default);
        assert!(manifest.put_init_requires_key_policy);
    }

    #[test]
    fn manifest_canonical_bytes_are_deterministic() {
        let manifest = sample_manifest();
        assert_eq!(
            manifest.canonical_cbor_bytes(),
            manifest.canonical_cbor_bytes()
        );
    }

    #[test]
    fn manifest_cid_is_stable() {
        let manifest = sample_manifest();
        let cid = manifest.manifest_cid();
        assert!(cid.starts_with("sha256-"));
        assert_eq!(cid, manifest.manifest_cid());
    }

    #[test]
    fn capability_claims_have_canonical_encoding() {
        let claims = CapabilityClaims {
            iss: "issuer".to_string(),
            sub: "subject".to_string(),
            aud: "hsp".to_string(),
            exp: 1_713_632_400_000,
            nbf: Some(1_713_632_300_000),
            jti: Some("jti-1".to_string()),
            ops: vec![CapabilityScope::Write, CapabilityScope::Read],
            tenant_id: TenantId("tenant-alpha".to_string()),
            namespace_prefix: None,
            path_prefix: Some("tenant/a".to_string()),
            max_object_size: Some(1024),
            storage_classes: vec!["hot".to_string()],
            key_policy_id: Some(KeyPolicyId("policy-default".to_string())),
            metadata_visibility: Some(VisibilityMode::Split),
        };

        let encoded = claims.canonical_cbor_bytes();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn settings_include_beta_transport_defaults() {
        let settings = public_multitenant_settings_frame("server-1");
        assert_eq!(
            settings.max_parallel_streams,
            default_limits().max_parallel_chunk_streams
        );
        assert!(settings
            .supported_content_encodings
            .contains(&"identity".to_string()));
    }
}
