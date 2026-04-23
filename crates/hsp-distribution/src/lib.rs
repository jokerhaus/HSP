use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ciborium::into_writer;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use hsp_auth::{verify_cose_sign1_token, AuthContext, IssuerRegistry};
use hsp_core::{
    cid_from_bytes, ApiError, ApiErrorCategory, AtomicBindRequest, BindRequest, CapabilityClaims,
    CapabilityScope, ChannelBindingProof, ChunkRef, EncryptionDescriptor, EncryptionProfileId,
    GetPreference, GetRequest, KeyPolicyId, ListRequest, Manifest, NamespaceMutationKind,
    NamespaceMutationRecord, ObjectSelector, PutChunkRequest, PutCommitRequest, PutInitRequest,
    RangeSpec, ResolveRequest, TenantId, UnbindRequest, VisibilityMode, WrappedObjectKeyRecord,
};
use hsp_crypto::{
    crypto_error_to_api, AwsKmsProvider, AwsKmsProviderConfig, KmsProvider, LocalDevKms,
    StoredEnvelope,
};
use hsp_path::canonical_path;
use hsp_service::{AlphaConfig, AlphaService};
use http::HeaderMap;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const BUCKET_REGISTRY_STORE: &str = "bucket-registry";
const DISTRIBUTION_METADATA_STORE: &str = "distribution-metadata";
const MULTIPART_SESSIONS_STORE: &str = "multipart-sessions";
const MULTIPART_PARTS_STORE: &str = "multipart-parts";
const PRESIGN_AUDIT_STORE: &str = "presign-audit";
const ACL_STORE: &str = "acl";
const LIFECYCLE_STORE: &str = "lifecycle";
const OBJECT_LOCK_STORE: &str = "object-lock";
const WEBSITE_STORE: &str = "website";
const REPLICATION_STORE: &str = "replication";
const WORKER_CURSOR_STORE: &str = "worker-cursor";
const DEFAULT_STORAGE_CLASS: &str = "hot";
const FIXED_CHUNK_SIZE: usize = 1024 * 1024;
const TRUSTED_EDGE_PROFILE: &str = "trusted-edge-v1";
const TRUSTED_EDGE_RECIPIENT_KEY_ID: &str = "trusted-edge";
const MAX_SIGV4_CLOCK_SKEW_MS: u64 = 5 * 60 * 1_000;
const MAX_PRESIGN_EXPIRES_SEC: u64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributionConfig {
    pub alpha: AlphaConfig,
    pub capability_audience: String,
    pub immutable_cid_ttl_sec: u64,
    pub namespace_ttl_sec: u64,
    pub plaintext_profile_enabled: bool,
    pub aws_kms: Option<AwsKmsProviderConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketRecord {
    pub tenant_id: TenantId,
    pub bucket: String,
    pub namespace: String,
    pub visibility_policy: String,
    pub namespace_cache_ttl_sec: u64,
    pub immutable_cid_cache_ttl_sec: u64,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessProfile {
    PublicCiphertext,
    TrustedEdgeV1,
}

impl AccessProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicCiphertext => "public-ciphertext",
            Self::TrustedEdgeV1 => TRUSTED_EDGE_PROFILE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CannedAcl {
    Private,
    PublicRead,
    AuthenticatedRead,
}

impl CannedAcl {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::PublicRead => "public-read",
            Self::AuthenticatedRead => "authenticated-read",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketAclRecord {
    pub tenant_id: TenantId,
    pub bucket: String,
    pub acl: CannedAcl,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectAclRecord {
    pub tenant_id: TenantId,
    pub bucket: String,
    pub key: String,
    pub acl: CannedAcl,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleRule {
    pub id: String,
    pub prefix: Option<String>,
    pub expire_after_days: Option<u32>,
    pub transition_after_days: Option<u32>,
    pub transition_storage_class: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleConfig {
    pub tenant_id: TenantId,
    pub bucket: String,
    pub rules: Vec<LifecycleRule>,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectLockRecord {
    pub tenant_id: TenantId,
    pub bucket: String,
    pub key: String,
    pub immutable_until_ms: Option<u64>,
    pub legal_hold: bool,
    pub mode: Option<String>,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebsiteConfig {
    pub tenant_id: TenantId,
    pub bucket: String,
    pub enabled: bool,
    pub index_document: String,
    pub error_document: String,
    pub access_profile: AccessProfile,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationConfig {
    pub tenant_id: TenantId,
    pub source_bucket: String,
    pub destination_bucket: String,
    pub prefix: Option<String>,
    pub enabled: bool,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationStatus {
    pub tenant_id: TenantId,
    pub source_bucket: String,
    pub destination_bucket: String,
    pub copied_objects: u64,
    pub failed_objects: u64,
    pub last_run_ms: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigV4AccessKeyRecord {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub tenant_id: TenantId,
    pub namespace_prefix: Option<String>,
    pub path_prefix: Option<String>,
    pub max_object_size: Option<u64>,
    pub storage_classes: Vec<String>,
    pub key_policy_id: KeyPolicyId,
    pub metadata_visibility: VisibilityMode,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributionMetadataRecord {
    pub tenant_id: TenantId,
    pub bucket: String,
    pub edge_token_policy: String,
    pub presign_enabled: bool,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MultipartSessionRecord {
    upload_id: String,
    tenant_id: TenantId,
    bucket: String,
    key: String,
    access_profile: AccessProfile,
    payload_plaintext: bool,
    content_type: String,
    encryption_profile_id: EncryptionProfileId,
    key_policy_id: KeyPolicyId,
    metadata_visibility: VisibilityMode,
    content_encryption_suite: String,
    key_wrapping_suite: String,
    wrapped_object_keys: Vec<WrappedObjectKeyRecord>,
    server_visible_metadata: BTreeMap<String, String>,
    encrypted_client_metadata: BTreeMap<String, String>,
    storage_class: String,
    initiated_at_ms: u64,
    idempotency_key: String,
    completed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MultipartPartRecord {
    upload_id: String,
    part_number: u32,
    etag: String,
    length: u64,
    created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PresignAuditRecord {
    token_id: String,
    tenant_id: TenantId,
    method: String,
    bucket: Option<String>,
    key: Option<String>,
    cid: Option<String>,
    expires_at_ms: u64,
    created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketSummary {
    pub bucket: String,
    pub namespace: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutObjectRequest {
    pub tenant_id: TenantId,
    pub bucket: String,
    pub key: String,
    pub access_profile: AccessProfile,
    pub payload_plaintext: bool,
    pub content_type: String,
    pub encryption_profile_id: EncryptionProfileId,
    pub key_policy_id: KeyPolicyId,
    pub metadata_visibility: VisibilityMode,
    pub content_encryption_suite: String,
    pub key_wrapping_suite: String,
    pub wrapped_object_keys: Vec<WrappedObjectKeyRecord>,
    pub server_visible_metadata: BTreeMap<String, String>,
    pub encrypted_client_metadata: BTreeMap<String, String>,
    pub storage_class: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutObjectResponse {
    pub bucket: String,
    pub key: String,
    pub object_cid: String,
    pub manifest_cid: String,
    pub etag: String,
    pub event_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadObjectRequest {
    pub tenant_id: TenantId,
    pub bucket: String,
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadObjectResponse {
    pub bucket: String,
    pub key: String,
    pub object_cid: String,
    pub manifest_cid: String,
    pub etag: String,
    pub content_length: u64,
    pub content_type: String,
    pub last_modified_ms: u64,
    pub server_visible_metadata: BTreeMap<String, String>,
    pub encrypted_client_metadata_redacted: bool,
    pub metadata_visibility: VisibilityMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetObjectRequest {
    pub tenant_id: TenantId,
    pub bucket: Option<String>,
    pub key: Option<String>,
    pub cid: Option<String>,
    pub access_profile: AccessProfile,
    pub prefer_plaintext: bool,
    pub range: Option<RangeSpec>,
    pub if_match: Option<String>,
    pub if_none_match: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetObjectResponse {
    pub head: HeadObjectResponse,
    pub body: Vec<u8>,
    pub immutable: bool,
    pub cache_control: String,
    pub content_range: Option<String>,
}

#[derive(Debug)]
struct ManifestBuildInput {
    tenant_id: TenantId,
    ciphertext: Vec<u8>,
    content_type: String,
    encryption_profile_id: EncryptionProfileId,
    key_policy_id: KeyPolicyId,
    metadata_visibility: VisibilityMode,
    content_encryption_suite: String,
    key_wrapping_suite: String,
    wrapped_object_keys: Vec<WrappedObjectKeyRecord>,
    server_visible_metadata: BTreeMap<String, String>,
    encrypted_client_metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteObjectRequest {
    pub tenant_id: TenantId,
    pub bucket: String,
    pub key: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteObjectResponse {
    pub bucket: String,
    pub key: String,
    pub tombstone: bool,
    pub revision: u64,
    pub record_cid: String,
    pub event_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListObjectsRequest {
    pub tenant_id: TenantId,
    pub bucket: String,
    pub prefix: Option<String>,
    pub continuation_token: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectListItem {
    pub key: String,
    pub etag: String,
    pub content_length: u64,
    pub content_type: String,
    pub last_modified_ms: u64,
    pub server_visible_metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListObjectsResponse {
    pub bucket: String,
    pub items: Vec<ObjectListItem>,
    pub next_continuation_token: Option<String>,
    pub is_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopyObjectRequest {
    pub tenant_id: TenantId,
    pub source_bucket: String,
    pub source_key: String,
    pub destination_bucket: String,
    pub destination_key: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopyObjectResponse {
    pub bucket: String,
    pub key: String,
    pub object_cid: String,
    pub revision: u64,
    pub record_cid: String,
    pub event_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateMultipartUploadRequest {
    pub tenant_id: TenantId,
    pub bucket: String,
    pub key: String,
    pub access_profile: AccessProfile,
    pub payload_plaintext: bool,
    pub content_type: String,
    pub encryption_profile_id: EncryptionProfileId,
    pub key_policy_id: KeyPolicyId,
    pub metadata_visibility: VisibilityMode,
    pub content_encryption_suite: String,
    pub key_wrapping_suite: String,
    pub wrapped_object_keys: Vec<WrappedObjectKeyRecord>,
    pub server_visible_metadata: BTreeMap<String, String>,
    pub encrypted_client_metadata: BTreeMap<String, String>,
    pub storage_class: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateMultipartUploadResponse {
    pub bucket: String,
    pub key: String,
    pub upload_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadPartRequest {
    pub tenant_id: TenantId,
    pub upload_id: String,
    pub part_number: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadPartResponse {
    pub upload_id: String,
    pub part_number: u32,
    pub etag: String,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletedMultipartPart {
    pub part_number: u32,
    pub etag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompleteMultipartUploadRequest {
    pub tenant_id: TenantId,
    pub upload_id: String,
    pub parts: Vec<CompletedMultipartPart>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbortMultipartUploadRequest {
    pub tenant_id: TenantId,
    pub upload_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeTokenClaims {
    pub tenant_id: TenantId,
    pub bucket: Option<String>,
    pub key: Option<String>,
    pub cid: Option<String>,
    pub access_profile: AccessProfile,
    pub method: String,
    pub exp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestBinding<'a> {
    pub method: &'a str,
    pub raw_path: &'a str,
    pub raw_query: &'a str,
    pub headers: &'a HeaderMap,
    pub body: &'a [u8],
}

#[derive(Debug)]
pub struct DistributionService {
    config: DistributionConfig,
    alpha: AlphaService,
    object_kms: LocalDevKms,
    store_kms: Box<dyn KmsProvider>,
    issuer_registry: IssuerRegistry,
    namespace_signing_key: SigningKey,
    namespace_signing_key_id: String,
    edge_signing_secret: Vec<u8>,
}

impl DistributionService {
    pub fn new(
        config: DistributionConfig,
        kms: LocalDevKms,
        issuer_registry: IssuerRegistry,
        namespace_signing_key: SigningKey,
        namespace_signing_key_id: impl Into<String>,
        edge_signing_secret: Vec<u8>,
    ) -> Result<Self, ApiError> {
        let namespace_signing_key_id = namespace_signing_key_id.into();
        if issuer_registry
            .resolve_key_id(namespace_signing_key_id.as_bytes())
            .is_none()
        {
            return Err(ApiError::new(
                ApiErrorCategory::Policy,
                "distribution_signer_missing_from_registry",
                "distribution namespace signer is not trusted by the issuer registry",
            ));
        }

        let alpha = AlphaService::new(config.alpha.clone(), kms.clone())?
            .with_issuer_registry(issuer_registry.clone());
        let store_kms: Box<dyn KmsProvider> = if let Some(aws) = config.aws_kms.clone() {
            Box::new(
                AwsKmsProvider::new(aws, b"hsp-aws-kms-fallback-seed").map_err(|error| {
                    crypto_error_to_api(error, "failed to initialize AWS KMS adapter")
                })?,
            )
        } else {
            Box::new(kms.clone())
        };
        let service = Self {
            config,
            alpha,
            object_kms: kms,
            store_kms,
            issuer_registry,
            namespace_signing_key,
            namespace_signing_key_id,
            edge_signing_secret,
        };
        service.ensure_store_roots()?;
        Ok(service)
    }

    pub fn alpha(&self) -> &AlphaService {
        &self.alpha
    }

    pub fn register_sigv4_access_key(&self, record: SigV4AccessKeyRecord) -> Result<(), ApiError> {
        if record.access_key_id.trim().is_empty() || record.secret_access_key.trim().is_empty() {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "invalid_sigv4_access_key",
                "access key id and secret must be non-empty",
            ));
        }
        self.write_encrypted_json(
            &record.tenant_id,
            DISTRIBUTION_METADATA_STORE,
            &format!("access-key-{}", record.access_key_id),
            &record,
        )
    }

    pub fn create_bucket(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
        bucket: impl Into<String>,
    ) -> Result<BucketRecord, ApiError> {
        self.ensure_bucket_mutation_scope(auth, &tenant_id)?;
        let bucket = self.canonical_bucket(bucket.into())?;
        if self.bucket_record(&tenant_id, &bucket)?.is_some() {
            return Err(ApiError::new(
                ApiErrorCategory::Conflict,
                "bucket_already_exists",
                "bucket already exists",
            ));
        }
        let record = BucketRecord {
            tenant_id: tenant_id.clone(),
            namespace: bucket.clone(),
            bucket: bucket.clone(),
            visibility_policy: "signed-only".to_string(),
            namespace_cache_ttl_sec: self.config.namespace_ttl_sec,
            immutable_cid_cache_ttl_sec: self.config.immutable_cid_ttl_sec,
            created_at_ms: now_ms(),
        };
        self.write_encrypted_json(&tenant_id, BUCKET_REGISTRY_STORE, &bucket, &record)?;
        self.write_encrypted_json(
            &tenant_id,
            DISTRIBUTION_METADATA_STORE,
            &format!("bucket-meta-{bucket}"),
            &DistributionMetadataRecord {
                tenant_id: tenant_id.clone(),
                bucket,
                edge_token_policy: "signed".to_string(),
                presign_enabled: true,
                updated_at_ms: now_ms(),
            },
        )?;
        Ok(record)
    }

    pub fn list_buckets(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
    ) -> Result<Vec<BucketSummary>, ApiError> {
        self.ensure_bucket_read_scope(auth, &tenant_id)?;
        let mut records = self
            .list_encrypted_json::<BucketRecord>(&tenant_id, BUCKET_REGISTRY_STORE)?
            .into_iter()
            .map(|record| BucketSummary {
                bucket: record.bucket,
                namespace: record.namespace,
                created_at_ms: record.created_at_ms,
            })
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.bucket.cmp(&right.bucket));
        Ok(records)
    }

    pub fn head_bucket(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
        bucket: impl Into<String>,
    ) -> Result<BucketRecord, ApiError> {
        let bucket = self.canonical_bucket(bucket.into())?;
        self.ensure_bucket_read_scope_for(auth, &tenant_id, &bucket, None)?;
        self.bucket_record(&tenant_id, &bucket)?.ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::NotFound,
                "bucket_not_found",
                "bucket not found",
            )
        })
    }

    pub fn delete_bucket(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
        bucket: impl Into<String>,
    ) -> Result<(), ApiError> {
        self.ensure_bucket_mutation_scope(auth, &tenant_id)?;
        let bucket = self.canonical_bucket(bucket.into())?;
        let _ = self.head_bucket(auth, tenant_id.clone(), bucket.clone())?;

        let objects = self.alpha.list(
            auth,
            ListRequest {
                tenant_id: tenant_id.clone(),
                namespace: bucket.clone(),
                prefix: None,
                cursor: None,
                limit: Some(1),
                recursive: true,
                include_tombstones: false,
            },
        )?;
        if !objects.items.is_empty() {
            return Err(ApiError::new(
                ApiErrorCategory::Conflict,
                "bucket_not_empty",
                "bucket namespace still contains objects",
            ));
        }

        if self.has_multipart_sessions(&tenant_id, &bucket)? {
            return Err(ApiError::new(
                ApiErrorCategory::Conflict,
                "bucket_not_empty",
                "bucket still has active multipart uploads",
            ));
        }

        self.delete_store_key(&tenant_id, BUCKET_REGISTRY_STORE, &bucket)?;
        self.delete_store_key(
            &tenant_id,
            DISTRIBUTION_METADATA_STORE,
            &format!("bucket-meta-{bucket}"),
        )?;
        Ok(())
    }

    pub fn put_bucket_acl(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
        bucket: impl Into<String>,
        acl: CannedAcl,
    ) -> Result<BucketAclRecord, ApiError> {
        self.ensure_bucket_mutation_scope(auth, &tenant_id)?;
        let bucket = self.canonical_bucket(bucket.into())?;
        let _ = self.require_bucket(&tenant_id, &bucket)?;
        let record = BucketAclRecord {
            tenant_id: tenant_id.clone(),
            bucket: bucket.clone(),
            acl,
            updated_at_ms: now_ms(),
        };
        self.write_encrypted_json(
            &tenant_id,
            ACL_STORE,
            &bucket_acl_store_key(&bucket),
            &record,
        )?;
        Ok(record)
    }

    pub fn get_bucket_acl(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
        bucket: impl Into<String>,
    ) -> Result<BucketAclRecord, ApiError> {
        self.ensure_bucket_read_scope(auth, &tenant_id)?;
        let bucket = self.canonical_bucket(bucket.into())?;
        let _ = self.require_bucket(&tenant_id, &bucket)?;
        Ok(self
            .read_encrypted_json::<BucketAclRecord>(
                &tenant_id,
                ACL_STORE,
                &bucket_acl_store_key(&bucket),
            )?
            .unwrap_or(BucketAclRecord {
                tenant_id,
                bucket,
                acl: CannedAcl::Private,
                updated_at_ms: now_ms(),
            }))
    }

    pub fn put_object_acl(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
        bucket: impl Into<String>,
        key: impl Into<String>,
        acl: CannedAcl,
    ) -> Result<ObjectAclRecord, ApiError> {
        self.ensure_bucket_mutation_scope(auth, &tenant_id)?;
        let bucket = self.canonical_bucket(bucket.into())?;
        let key = self.canonical_object_key(key.into())?;
        let _ = self.require_bucket(&tenant_id, &bucket)?;
        let record = ObjectAclRecord {
            tenant_id: tenant_id.clone(),
            bucket: bucket.clone(),
            key: key.clone(),
            acl,
            updated_at_ms: now_ms(),
        };
        self.write_encrypted_json(
            &tenant_id,
            ACL_STORE,
            &object_acl_store_key(&bucket, &key),
            &record,
        )?;
        Ok(record)
    }

    pub fn get_object_acl(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
        bucket: impl Into<String>,
        key: impl Into<String>,
    ) -> Result<ObjectAclRecord, ApiError> {
        self.ensure_bucket_read_scope(auth, &tenant_id)?;
        let bucket = self.canonical_bucket(bucket.into())?;
        let key = self.canonical_object_key(key.into())?;
        let _ = self.require_bucket(&tenant_id, &bucket)?;
        Ok(self
            .read_encrypted_json::<ObjectAclRecord>(
                &tenant_id,
                ACL_STORE,
                &object_acl_store_key(&bucket, &key),
            )?
            .unwrap_or(ObjectAclRecord {
                tenant_id,
                bucket,
                key,
                acl: CannedAcl::Private,
                updated_at_ms: now_ms(),
            }))
    }

    pub fn put_lifecycle_config(
        &self,
        auth: &AuthContext,
        mut config: LifecycleConfig,
    ) -> Result<LifecycleConfig, ApiError> {
        self.ensure_bucket_mutation_scope(auth, &config.tenant_id)?;
        let bucket = self.canonical_bucket(config.bucket.clone())?;
        let _ = self.require_bucket(&config.tenant_id, &bucket)?;
        if config.rules.iter().any(|rule| {
            rule.expire_after_days.is_none()
                && (rule.transition_after_days.is_none() || rule.transition_storage_class.is_none())
        }) {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "lifecycle_conflict",
                "lifecycle rule must define expiration or transition action",
            ));
        }
        config.bucket = bucket.clone();
        config.updated_at_ms = now_ms();
        self.write_encrypted_json(
            &config.tenant_id,
            LIFECYCLE_STORE,
            &lifecycle_store_key(&bucket),
            &config,
        )?;
        Ok(config)
    }

    pub fn get_lifecycle_config(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
        bucket: impl Into<String>,
    ) -> Result<LifecycleConfig, ApiError> {
        self.ensure_bucket_read_scope(auth, &tenant_id)?;
        let bucket = self.canonical_bucket(bucket.into())?;
        let _ = self.require_bucket(&tenant_id, &bucket)?;
        self.read_encrypted_json::<LifecycleConfig>(
            &tenant_id,
            LIFECYCLE_STORE,
            &lifecycle_store_key(&bucket),
        )?
        .ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::NotFound,
                "lifecycle_not_found",
                "bucket lifecycle configuration not found",
            )
        })
    }

    pub fn delete_lifecycle_config(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
        bucket: impl Into<String>,
    ) -> Result<(), ApiError> {
        self.ensure_bucket_mutation_scope(auth, &tenant_id)?;
        let bucket = self.canonical_bucket(bucket.into())?;
        self.delete_store_key(&tenant_id, LIFECYCLE_STORE, &lifecycle_store_key(&bucket))
    }

    pub fn put_object_retention(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
        bucket: impl Into<String>,
        key: impl Into<String>,
        immutable_until_ms: Option<u64>,
        mode: Option<String>,
    ) -> Result<ObjectLockRecord, ApiError> {
        self.ensure_bucket_mutation_scope(auth, &tenant_id)?;
        let bucket = self.canonical_bucket(bucket.into())?;
        let key = self.canonical_object_key(key.into())?;
        let _ = self.require_bucket(&tenant_id, &bucket)?;
        let mut record = self
            .read_encrypted_json::<ObjectLockRecord>(
                &tenant_id,
                OBJECT_LOCK_STORE,
                &object_lock_store_key(&bucket, &key),
            )?
            .unwrap_or(ObjectLockRecord {
                tenant_id: tenant_id.clone(),
                bucket: bucket.clone(),
                key: key.clone(),
                immutable_until_ms: None,
                legal_hold: false,
                mode: None,
                updated_at_ms: now_ms(),
            });
        record.immutable_until_ms = immutable_until_ms;
        record.mode = mode;
        record.updated_at_ms = now_ms();
        self.write_encrypted_json(
            &tenant_id,
            OBJECT_LOCK_STORE,
            &object_lock_store_key(&bucket, &key),
            &record,
        )?;
        Ok(record)
    }

    pub fn put_object_legal_hold(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
        bucket: impl Into<String>,
        key: impl Into<String>,
        legal_hold: bool,
    ) -> Result<ObjectLockRecord, ApiError> {
        self.ensure_bucket_mutation_scope(auth, &tenant_id)?;
        let bucket = self.canonical_bucket(bucket.into())?;
        let key = self.canonical_object_key(key.into())?;
        let _ = self.require_bucket(&tenant_id, &bucket)?;
        let mut record = self
            .read_encrypted_json::<ObjectLockRecord>(
                &tenant_id,
                OBJECT_LOCK_STORE,
                &object_lock_store_key(&bucket, &key),
            )?
            .unwrap_or(ObjectLockRecord {
                tenant_id,
                bucket,
                key,
                immutable_until_ms: None,
                legal_hold: false,
                mode: None,
                updated_at_ms: now_ms(),
            });
        record.legal_hold = legal_hold;
        record.updated_at_ms = now_ms();
        self.write_encrypted_json(
            &record.tenant_id,
            OBJECT_LOCK_STORE,
            &object_lock_store_key(&record.bucket, &record.key),
            &record,
        )?;
        Ok(record)
    }

    pub fn get_object_lock(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
        bucket: impl Into<String>,
        key: impl Into<String>,
    ) -> Result<ObjectLockRecord, ApiError> {
        self.ensure_bucket_read_scope(auth, &tenant_id)?;
        let bucket = self.canonical_bucket(bucket.into())?;
        let key = self.canonical_object_key(key.into())?;
        Ok(self
            .read_encrypted_json::<ObjectLockRecord>(
                &tenant_id,
                OBJECT_LOCK_STORE,
                &object_lock_store_key(&bucket, &key),
            )?
            .unwrap_or(ObjectLockRecord {
                tenant_id,
                bucket,
                key,
                immutable_until_ms: None,
                legal_hold: false,
                mode: None,
                updated_at_ms: now_ms(),
            }))
    }

    pub fn put_website_config(
        &self,
        auth: &AuthContext,
        mut config: WebsiteConfig,
    ) -> Result<WebsiteConfig, ApiError> {
        self.ensure_bucket_mutation_scope(auth, &config.tenant_id)?;
        let bucket = self.canonical_bucket(config.bucket.clone())?;
        let _ = self.require_bucket(&config.tenant_id, &bucket)?;
        if config.access_profile != AccessProfile::TrustedEdgeV1
            || !self.config.plaintext_profile_enabled
        {
            return Err(ApiError::new(
                ApiErrorCategory::Policy,
                "trusted_edge_required",
                "website hosting mode is allowed only for trusted-edge-v1 profile",
            ));
        }
        config.bucket = bucket.clone();
        config.updated_at_ms = now_ms();
        self.write_encrypted_json(
            &config.tenant_id,
            WEBSITE_STORE,
            &website_store_key(&bucket),
            &config,
        )?;
        Ok(config)
    }

    pub fn get_website_config(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
        bucket: impl Into<String>,
    ) -> Result<WebsiteConfig, ApiError> {
        self.ensure_bucket_read_scope(auth, &tenant_id)?;
        let bucket = self.canonical_bucket(bucket.into())?;
        self.read_encrypted_json::<WebsiteConfig>(
            &tenant_id,
            WEBSITE_STORE,
            &website_store_key(&bucket),
        )?
        .ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::NotFound,
                "website_config_not_found",
                "website configuration not found",
            )
        })
    }

    pub fn delete_website_config(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
        bucket: impl Into<String>,
    ) -> Result<(), ApiError> {
        self.ensure_bucket_mutation_scope(auth, &tenant_id)?;
        let bucket = self.canonical_bucket(bucket.into())?;
        self.delete_store_key(&tenant_id, WEBSITE_STORE, &website_store_key(&bucket))
    }

    pub fn put_replication_config(
        &self,
        auth: &AuthContext,
        mut config: ReplicationConfig,
    ) -> Result<ReplicationConfig, ApiError> {
        self.ensure_bucket_mutation_scope(auth, &config.tenant_id)?;
        let source_bucket = self.canonical_bucket(config.source_bucket.clone())?;
        let destination_bucket = self.canonical_bucket(config.destination_bucket.clone())?;
        if source_bucket == destination_bucket {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "lifecycle_conflict",
                "replication source and destination buckets must differ",
            ));
        }
        let _ = self.require_bucket(&config.tenant_id, &source_bucket)?;
        let _ = self.require_bucket(&config.tenant_id, &destination_bucket)?;
        config.source_bucket = source_bucket.clone();
        config.destination_bucket = destination_bucket;
        config.updated_at_ms = now_ms();
        self.write_encrypted_json(
            &config.tenant_id,
            REPLICATION_STORE,
            &replication_config_store_key(&source_bucket),
            &config,
        )?;
        Ok(config)
    }

    pub fn get_replication_config(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
        source_bucket: impl Into<String>,
    ) -> Result<ReplicationConfig, ApiError> {
        self.ensure_bucket_read_scope(auth, &tenant_id)?;
        let source_bucket = self.canonical_bucket(source_bucket.into())?;
        self.read_encrypted_json::<ReplicationConfig>(
            &tenant_id,
            REPLICATION_STORE,
            &replication_config_store_key(&source_bucket),
        )?
        .ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::NotFound,
                "replication_not_found",
                "replication configuration not found",
            )
        })
    }

    pub fn get_replication_status(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
        source_bucket: impl Into<String>,
    ) -> Result<ReplicationStatus, ApiError> {
        self.ensure_bucket_read_scope(auth, &tenant_id)?;
        let source_bucket = self.canonical_bucket(source_bucket.into())?;
        Ok(self
            .read_encrypted_json::<ReplicationStatus>(
                &tenant_id,
                REPLICATION_STORE,
                &replication_status_store_key(&source_bucket),
            )?
            .unwrap_or(ReplicationStatus {
                tenant_id,
                source_bucket,
                destination_bucket: String::new(),
                copied_objects: 0,
                failed_objects: 0,
                last_run_ms: 0,
                last_error: Some("replication_not_started".to_string()),
            }))
    }

    pub fn delete_replication_config(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
        source_bucket: impl Into<String>,
    ) -> Result<(), ApiError> {
        self.ensure_bucket_mutation_scope(auth, &tenant_id)?;
        let source_bucket = self.canonical_bucket(source_bucket.into())?;
        self.delete_store_key(
            &tenant_id,
            REPLICATION_STORE,
            &replication_config_store_key(&source_bucket),
        )?;
        self.delete_store_key(
            &tenant_id,
            REPLICATION_STORE,
            &replication_status_store_key(&source_bucket),
        )
    }

    pub fn run_replication_once(
        &self,
        auth: &AuthContext,
        tenant_id: TenantId,
        source_bucket: impl Into<String>,
    ) -> Result<ReplicationStatus, ApiError> {
        self.ensure_bucket_mutation_scope(auth, &tenant_id)?;
        let source_bucket = self.canonical_bucket(source_bucket.into())?;
        let config = self.get_replication_config(auth, tenant_id.clone(), source_bucket.clone())?;
        let mut copied_objects = 0u64;
        let mut failed_objects = 0u64;
        let mut last_error = None;

        if config.enabled {
            let listed = self.list_objects(
                auth,
                ListObjectsRequest {
                    tenant_id: tenant_id.clone(),
                    bucket: config.source_bucket.clone(),
                    prefix: config.prefix.clone(),
                    continuation_token: None,
                    limit: Some(10_000),
                },
            )?;
            for object in listed.items {
                let result = self.copy_object(
                    auth,
                    CopyObjectRequest {
                        tenant_id: tenant_id.clone(),
                        source_bucket: config.source_bucket.clone(),
                        source_key: object.key.clone(),
                        destination_bucket: config.destination_bucket.clone(),
                        destination_key: object.key.clone(),
                        idempotency_key: format!(
                            "replication-{}",
                            cid_from_bytes(
                                format!(
                                    "{}:{}:{}:{}",
                                    config.source_bucket,
                                    config.destination_bucket,
                                    object.key,
                                    now_ms()
                                )
                                .as_bytes()
                            )
                        ),
                    },
                );
                if let Err(error) = result {
                    failed_objects = failed_objects.saturating_add(1);
                    last_error = Some(error.code);
                } else {
                    copied_objects = copied_objects.saturating_add(1);
                }
            }
        } else {
            last_error = Some("replication_disabled".to_string());
        }

        let status = ReplicationStatus {
            tenant_id: tenant_id.clone(),
            source_bucket: config.source_bucket.clone(),
            destination_bucket: config.destination_bucket.clone(),
            copied_objects,
            failed_objects,
            last_run_ms: now_ms(),
            last_error,
        };
        self.write_encrypted_json(
            &tenant_id,
            REPLICATION_STORE,
            &replication_status_store_key(&source_bucket),
            &status,
        )?;
        Ok(status)
    }

    pub fn put_object(
        &self,
        auth: &AuthContext,
        request: PutObjectRequest,
        payload: &[u8],
    ) -> Result<PutObjectResponse, ApiError> {
        self.ensure_bucket_mutation_scope(auth, &request.tenant_id)?;
        self.validate_access_profile(request.access_profile, request.payload_plaintext)?;
        let bucket = self.require_bucket(&request.tenant_id, &request.bucket)?;
        let key = self.canonical_object_key(request.key.clone())?;
        let mut effective_ciphertext = payload.to_vec();
        let mut server_visible_metadata = request.server_visible_metadata.clone();
        let mut wrapped_object_keys = request.wrapped_object_keys.clone();
        let mut content_encryption_suite = request.content_encryption_suite.clone();
        let mut key_wrapping_suite = request.key_wrapping_suite.clone();

        if request.payload_plaintext {
            let object_key = self.object_kms.generate_object_data_key();
            let encrypted = self
                .object_kms
                .encrypt_client_chunk(&object_key, payload)
                .map_err(|error| {
                    crypto_error_to_api(error, "failed to encrypt trusted-edge plaintext payload")
                })?;
            effective_ciphertext = encrypted.ciphertext;
            server_visible_metadata.insert(
                "hsp-trusted-edge-nonce".to_string(),
                encrypted.nonce_b64.clone(),
            );
            if !wrapped_object_keys
                .iter()
                .any(|entry| entry.recipient_key_id == TRUSTED_EDGE_RECIPIENT_KEY_ID)
            {
                wrapped_object_keys.push(
                    self.store_kms
                        .wrap_object_key_for_recipient(
                            &request.tenant_id,
                            TRUSTED_EDGE_RECIPIENT_KEY_ID,
                            &object_key,
                        )
                        .map_err(|error| {
                            crypto_error_to_api(
                                error,
                                "failed to wrap trusted-edge object data key",
                            )
                        })?,
                );
            }
            if content_encryption_suite.trim().is_empty() {
                content_encryption_suite = "XChaCha20-Poly1305".to_string();
            }
            if key_wrapping_suite.trim().is_empty() {
                key_wrapping_suite = "HPKE/X25519".to_string();
            }
        }
        self.validate_ciphertext_manifest_input(&request, &effective_ciphertext)?;

        let existing = self
            .alpha
            .resolve(
                auth,
                ResolveRequest {
                    tenant_id: request.tenant_id.clone(),
                    namespace: bucket.namespace.clone(),
                    path: key.clone(),
                    at_revision: None,
                    if_revision: None,
                },
            )
            .ok()
            .filter(|resolved| !resolved.tombstone);
        if existing.is_some() {
            self.ensure_object_mutation_unlocked(
                &request.tenant_id,
                &bucket.bucket,
                &key,
                false,
                auth,
            )?;
        }
        let existing_revision = existing.as_ref().map(|resolved| resolved.revision);

        let manifest = build_manifest(ManifestBuildInput {
            tenant_id: request.tenant_id.clone(),
            ciphertext: effective_ciphertext.clone(),
            content_type: request.content_type.clone(),
            encryption_profile_id: request.encryption_profile_id.clone(),
            key_policy_id: request.key_policy_id.clone(),
            metadata_visibility: request.metadata_visibility,
            content_encryption_suite,
            key_wrapping_suite,
            wrapped_object_keys,
            server_visible_metadata: server_visible_metadata.clone(),
            encrypted_client_metadata: request.encrypted_client_metadata.clone(),
        })?;
        let manifest_cid = manifest.manifest_cid();
        let atomic_bind = Some(AtomicBindRequest {
            namespace: bucket.namespace.clone(),
            path: key.clone(),
            if_revision: existing_revision,
            metadata: server_visible_metadata.clone(),
            ttl_ms: None,
            signed_record_b64: self.sign_namespace_record(&NamespaceMutationRecord {
                version: 1,
                tenant_id: request.tenant_id.clone(),
                namespace: bucket.namespace.clone(),
                path: key.clone(),
                kind: NamespaceMutationKind::Bind,
                target_cid: Some(manifest_cid.clone()),
                if_revision: existing_revision,
                ttl_ms: None,
                metadata: server_visible_metadata.clone(),
                issued_at_ms: now_ms(),
            })?,
        });
        let init = self.alpha.put_init(
            auth,
            PutInitRequest {
                tenant_id: request.tenant_id.clone(),
                manifest: manifest.clone(),
                idempotency_key: request.idempotency_key.clone(),
                encryption_profile_id: request.encryption_profile_id.clone(),
                key_policy_id: request.key_policy_id.clone(),
                metadata_visibility: request.metadata_visibility,
                storage_class: if request.storage_class.trim().is_empty() {
                    DEFAULT_STORAGE_CLASS.to_string()
                } else {
                    request.storage_class.clone()
                },
                atomic_bind,
            },
        )?;
        let chunks = chunk_ciphertext(&effective_ciphertext);
        for chunk in &chunks {
            self.alpha.put_chunk(
                auth,
                PutChunkRequest {
                    tenant_id: request.tenant_id.clone(),
                    session_id: init.session_id.clone(),
                    chunk_index: chunk.chunk_index,
                    chunk_cid: chunk.cid.clone(),
                    chunk_offset: chunk.offset,
                    chunk_length: chunk.stored_len,
                    content_encoding: chunk.content_encoding.clone(),
                },
                &chunk.bytes,
            )?;
        }
        let committed = self.alpha.put_commit(
            auth,
            PutCommitRequest {
                tenant_id: request.tenant_id.clone(),
                session_id: init.session_id,
                manifest_cid: manifest_cid.clone(),
                idempotency_key: request.idempotency_key,
            },
        )?;
        Ok(PutObjectResponse {
            bucket: bucket.bucket,
            key,
            object_cid: committed.object_cid.clone(),
            manifest_cid,
            etag: committed.object_cid,
            event_seq: committed.event_seq,
        })
    }

    pub fn head_object(
        &self,
        auth: &AuthContext,
        request: HeadObjectRequest,
    ) -> Result<HeadObjectResponse, ApiError> {
        let bucket = self.require_bucket(&request.tenant_id, &request.bucket)?;
        let key = self.canonical_object_key(request.key)?;
        self.ensure_bucket_read_scope_for(auth, &request.tenant_id, &bucket.bucket, Some(&key))?;
        let manifest_only = self
            .alpha
            .get(
                auth,
                GetRequest {
                    tenant_id: request.tenant_id,
                    selector: ObjectSelector::namespace(bucket.namespace.clone(), key.clone()),
                    preference: Some(GetPreference::ManifestOnly),
                    range: None,
                },
            )
            .map_err(map_object_error)?;
        let manifest = manifest_only.meta.manifest.ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::Storage,
                "manifest_missing_from_response",
                "manifest-only read did not include a manifest",
            )
        })?;
        Ok(HeadObjectResponse {
            bucket: bucket.bucket,
            key,
            object_cid: manifest_only.meta.object_cid.clone(),
            manifest_cid: manifest_only.meta.manifest_cid.clone(),
            etag: manifest_only.meta.object_cid,
            content_length: manifest_only.meta.stored_size,
            content_type: manifest_only.meta.content_type,
            last_modified_ms: manifest.created_at_ms,
            server_visible_metadata: manifest_only.meta.server_visible_metadata,
            encrypted_client_metadata_redacted: manifest_only
                .meta
                .encrypted_client_metadata_redacted,
            metadata_visibility: manifest_only.meta.metadata_visibility,
        })
    }

    pub fn get_object(
        &self,
        auth: &AuthContext,
        request: GetObjectRequest,
    ) -> Result<GetObjectResponse, ApiError> {
        self.validate_access_profile(request.access_profile, request.prefer_plaintext)?;
        if auth.claims.tenant_id != request.tenant_id {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "tenant_mismatch",
                "tenant does not match the authenticated principal",
            ));
        }
        let (head, selector, immutable) = if let Some(cid) = request.cid.clone() {
            self.ensure_bucket_read_scope(auth, &request.tenant_id)?;
            let manifest_only = self.alpha.get(
                auth,
                GetRequest {
                    tenant_id: request.tenant_id.clone(),
                    selector: ObjectSelector::cid(cid.clone()),
                    preference: Some(GetPreference::ManifestOnly),
                    range: None,
                },
            )?;
            let manifest = manifest_only.meta.manifest.clone().ok_or_else(|| {
                ApiError::new(
                    ApiErrorCategory::Storage,
                    "manifest_missing_from_response",
                    "manifest-only read did not include a manifest",
                )
            })?;
            (
                HeadObjectResponse {
                    bucket: request.bucket.clone().unwrap_or_default(),
                    key: request.key.clone().unwrap_or_else(|| cid.clone()),
                    object_cid: manifest_only.meta.object_cid.clone(),
                    manifest_cid: manifest_only.meta.manifest_cid.clone(),
                    etag: manifest_only.meta.object_cid.clone(),
                    content_length: manifest_only.meta.stored_size,
                    content_type: manifest_only.meta.content_type,
                    last_modified_ms: manifest.created_at_ms,
                    server_visible_metadata: manifest_only.meta.server_visible_metadata,
                    encrypted_client_metadata_redacted: manifest_only
                        .meta
                        .encrypted_client_metadata_redacted,
                    metadata_visibility: manifest_only.meta.metadata_visibility,
                },
                ObjectSelector::cid(cid),
                true,
            )
        } else {
            let bucket_name = request.bucket.clone().ok_or_else(|| {
                ApiError::new(
                    ApiErrorCategory::Validation,
                    "missing_bucket",
                    "bucket is required when cid is not provided",
                )
            })?;
            let key = request.key.clone().ok_or_else(|| {
                ApiError::new(
                    ApiErrorCategory::Validation,
                    "missing_object_key",
                    "object key is required when cid is not provided",
                )
            })?;
            let head = self.head_object(
                auth,
                HeadObjectRequest {
                    tenant_id: request.tenant_id.clone(),
                    bucket: bucket_name.clone(),
                    key: key.clone(),
                },
            )?;
            let bucket = self.require_bucket(&request.tenant_id, &bucket_name)?;
            (
                head,
                ObjectSelector::namespace(bucket.namespace, self.canonical_object_key(key)?),
                false,
            )
        };

        if let Some(if_match) = &request.if_match {
            if if_match != &head.etag {
                return Err(ApiError::new(
                    ApiErrorCategory::Conflict,
                    "precondition_failed",
                    "If-Match does not match the current ciphertext object identity",
                ));
            }
        }
        if let Some(if_none_match) = &request.if_none_match {
            if if_none_match == &head.etag {
                return Err(ApiError::new(
                    ApiErrorCategory::Conflict,
                    "not_modified",
                    "If-None-Match matches the current ciphertext object identity",
                ));
            }
        }

        let selector_for_manifest = selector.clone();
        let response = self.alpha.get(
            auth,
            GetRequest {
                tenant_id: request.tenant_id.clone(),
                selector,
                preference: Some(GetPreference::ChunkStream),
                range: request.range.clone(),
            },
        )?;
        let mut body = response
            .chunks
            .into_iter()
            .flat_map(|chunk| chunk.bytes)
            .collect::<Vec<_>>();
        let mut response_head = head;
        let mut content_range = request.range.as_ref().map(|range| {
            format!(
                "bytes {}-{}/{}",
                range.start, range.end, response_head.content_length
            )
        });
        let mut cache_control = if immutable {
            format!(
                "public, max-age={}, immutable",
                self.config.immutable_cid_ttl_sec
            )
        } else {
            format!("private, max-age={}", self.config.namespace_ttl_sec)
        };
        if request.prefer_plaintext {
            if request.range.is_some() {
                return Err(ApiError::new(
                    ApiErrorCategory::Unsupported,
                    "unsupported_preference",
                    "trusted-edge plaintext mode does not support range reads",
                ));
            }
            let manifest = match response.meta.manifest {
                Some(manifest) => manifest,
                None => self
                    .alpha
                    .get(
                        auth,
                        GetRequest {
                            tenant_id: request.tenant_id.clone(),
                            selector: selector_for_manifest,
                            preference: Some(GetPreference::ManifestOnly),
                            range: None,
                        },
                    )?
                    .meta
                    .manifest
                    .ok_or_else(|| {
                        ApiError::new(
                            ApiErrorCategory::Storage,
                            "manifest_missing_from_response",
                            "manifest-only read did not include a manifest",
                        )
                    })?,
            };
            let nonce_b64 = manifest
                .encryption_descriptor
                .server_visible_metadata
                .get("hsp-trusted-edge-nonce")
                .ok_or_else(|| {
                    ApiError::new(
                        ApiErrorCategory::Unsupported,
                        "unsupported_plaintext_mode",
                        "trusted-edge nonce metadata is missing for this object",
                    )
                })?;
            let wrapped_key = manifest
                .encryption_descriptor
                .wrapped_object_keys
                .iter()
                .find(|entry| entry.recipient_key_id == TRUSTED_EDGE_RECIPIENT_KEY_ID)
                .ok_or_else(|| {
                    ApiError::new(
                        ApiErrorCategory::Unsupported,
                        "unsupported_plaintext_mode",
                        "trusted-edge wrapped object key is missing",
                    )
                })?;
            let object_key = self
                .store_kms
                .unwrap_object_key_for_recipient(&request.tenant_id, wrapped_key)
                .map_err(|error| {
                    crypto_error_to_api(error, "failed to unwrap trusted-edge object key")
                })?;
            body = self
                .object_kms
                .decrypt_client_chunk(&object_key, nonce_b64, &body)
                .map_err(|error| {
                    crypto_error_to_api(error, "failed to decrypt trusted-edge object payload")
                })?;
            response_head.content_length = body.len() as u64;
            content_range = None;
            cache_control = "private, no-store".to_string();
        }
        Ok(GetObjectResponse {
            head: response_head,
            body,
            immutable,
            cache_control,
            content_range,
        })
    }

    pub fn delete_object(
        &self,
        auth: &AuthContext,
        request: DeleteObjectRequest,
    ) -> Result<DeleteObjectResponse, ApiError> {
        self.ensure_bucket_mutation_scope(auth, &request.tenant_id)?;
        let bucket = self.require_bucket(&request.tenant_id, &request.bucket)?;
        let key = self.canonical_object_key(request.key)?;
        let resolved = self
            .alpha
            .resolve(
                auth,
                ResolveRequest {
                    tenant_id: request.tenant_id.clone(),
                    namespace: bucket.namespace.clone(),
                    path: key.clone(),
                    at_revision: None,
                    if_revision: None,
                },
            )
            .map_err(map_object_error)?;
        if resolved.tombstone {
            return Err(ApiError::new(
                ApiErrorCategory::NotFound,
                "object_not_found",
                "object is already tombstoned",
            ));
        }
        self.ensure_object_mutation_unlocked(
            &request.tenant_id,
            &request.bucket,
            &key,
            true,
            auth,
        )?;
        let signed_record_b64 = self.sign_namespace_record(&NamespaceMutationRecord {
            version: 1,
            tenant_id: request.tenant_id.clone(),
            namespace: bucket.namespace.clone(),
            path: key.clone(),
            kind: NamespaceMutationKind::Unbind,
            target_cid: None,
            if_revision: Some(resolved.revision),
            ttl_ms: None,
            metadata: BTreeMap::new(),
            issued_at_ms: now_ms(),
        })?;
        let unbound = self.alpha.unbind(
            auth,
            UnbindRequest {
                tenant_id: request.tenant_id,
                namespace: bucket.namespace,
                path: key.clone(),
                if_revision: resolved.revision,
                hard_delete: false,
                idempotency_key: request.idempotency_key,
                signed_record_b64,
            },
        )?;
        Ok(DeleteObjectResponse {
            bucket: request.bucket,
            key,
            tombstone: unbound.tombstone,
            revision: unbound.revision,
            record_cid: unbound.record_cid,
            event_seq: unbound.event_seq,
        })
    }

    pub fn list_objects(
        &self,
        auth: &AuthContext,
        request: ListObjectsRequest,
    ) -> Result<ListObjectsResponse, ApiError> {
        self.ensure_bucket_read_scope_for(auth, &request.tenant_id, &request.bucket, None)?;
        let bucket = self.require_bucket(&request.tenant_id, &request.bucket)?;
        let listed = self.alpha.list(
            auth,
            ListRequest {
                tenant_id: request.tenant_id.clone(),
                namespace: bucket.namespace,
                prefix: request
                    .prefix
                    .as_ref()
                    .map(|prefix| self.canonical_object_key(prefix.clone()))
                    .transpose()?,
                cursor: request.continuation_token.clone(),
                limit: request.limit,
                recursive: true,
                include_tombstones: false,
            },
        )?;
        let mut items = Vec::new();
        for item in listed.items {
            let head = self.head_object(
                auth,
                HeadObjectRequest {
                    tenant_id: request.tenant_id.clone(),
                    bucket: request.bucket.clone(),
                    key: item.path.clone(),
                },
            )?;
            items.push(ObjectListItem {
                key: item.path,
                etag: head.etag,
                content_length: head.content_length,
                content_type: head.content_type,
                last_modified_ms: head.last_modified_ms,
                server_visible_metadata: head.server_visible_metadata,
            });
        }
        Ok(ListObjectsResponse {
            bucket: request.bucket,
            items,
            next_continuation_token: listed.next_cursor,
            is_truncated: listed.truncated,
        })
    }

    pub fn copy_object(
        &self,
        auth: &AuthContext,
        request: CopyObjectRequest,
    ) -> Result<CopyObjectResponse, ApiError> {
        self.ensure_bucket_mutation_scope(auth, &request.tenant_id)?;
        let source_bucket = self.require_bucket(&request.tenant_id, &request.source_bucket)?;
        let destination_bucket =
            self.require_bucket(&request.tenant_id, &request.destination_bucket)?;
        let source_key = self.canonical_object_key(request.source_key)?;
        let destination_key = self.canonical_object_key(request.destination_key)?;
        let source = self
            .alpha
            .resolve(
                auth,
                ResolveRequest {
                    tenant_id: request.tenant_id.clone(),
                    namespace: source_bucket.namespace,
                    path: source_key,
                    at_revision: None,
                    if_revision: None,
                },
            )
            .map_err(map_object_error)?;
        if source.tombstone {
            return Err(ApiError::new(
                ApiErrorCategory::NotFound,
                "object_not_found",
                "source object is tombstoned",
            ));
        }
        let target_revision = self
            .alpha
            .resolve(
                auth,
                ResolveRequest {
                    tenant_id: request.tenant_id.clone(),
                    namespace: destination_bucket.namespace.clone(),
                    path: destination_key.clone(),
                    at_revision: None,
                    if_revision: None,
                },
            )
            .ok()
            .filter(|resolved| !resolved.tombstone)
            .map(|resolved| resolved.revision);
        let target_cid = source.target_cid.ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::NotFound,
                "object_not_found",
                "source object does not resolve to a target CID",
            )
        })?;
        let bind_record = NamespaceMutationRecord {
            version: 1,
            tenant_id: request.tenant_id.clone(),
            namespace: destination_bucket.namespace.clone(),
            path: destination_key.clone(),
            kind: NamespaceMutationKind::Bind,
            target_cid: Some(target_cid.clone()),
            if_revision: target_revision,
            ttl_ms: None,
            metadata: BTreeMap::new(),
            issued_at_ms: now_ms(),
        };
        let response = self.alpha.bind(
            auth,
            BindRequest {
                tenant_id: request.tenant_id,
                namespace: destination_bucket.namespace,
                path: destination_key.clone(),
                target_cid: target_cid.clone(),
                if_revision: target_revision,
                if_absent: target_revision.is_none(),
                metadata: BTreeMap::new(),
                ttl_ms: None,
                idempotency_key: request.idempotency_key,
                signed_record_b64: self.sign_namespace_record(&bind_record)?,
            },
        )?;
        Ok(CopyObjectResponse {
            bucket: request.destination_bucket,
            key: destination_key,
            object_cid: target_cid,
            revision: response.revision,
            record_cid: response.record_cid,
            event_seq: response.event_seq,
        })
    }

    pub fn create_multipart_upload(
        &self,
        auth: &AuthContext,
        request: CreateMultipartUploadRequest,
    ) -> Result<CreateMultipartUploadResponse, ApiError> {
        self.ensure_bucket_mutation_scope(auth, &request.tenant_id)?;
        self.validate_access_profile(request.access_profile, request.payload_plaintext)?;
        let bucket = self.require_bucket(&request.tenant_id, &request.bucket)?;
        let key = self.canonical_object_key(request.key.clone())?;
        if !request.payload_plaintext && request.wrapped_object_keys.is_empty() {
            return Err(ApiError::new(
                ApiErrorCategory::Unsupported,
                "unsupported_plaintext_mode",
                "ciphertext object uploads require wrapped object keys",
            ));
        }
        let upload_id = format!(
            "multipart-{}",
            cid_from_bytes(format!("{}:{}:{}", bucket.bucket, key, now_ms()).as_bytes())
        );
        self.write_encrypted_json(
            &request.tenant_id,
            MULTIPART_SESSIONS_STORE,
            &upload_id,
            &MultipartSessionRecord {
                upload_id: upload_id.clone(),
                tenant_id: request.tenant_id.clone(),
                bucket: bucket.bucket.clone(),
                key,
                access_profile: request.access_profile,
                payload_plaintext: request.payload_plaintext,
                content_type: request.content_type,
                encryption_profile_id: request.encryption_profile_id,
                key_policy_id: request.key_policy_id,
                metadata_visibility: request.metadata_visibility,
                content_encryption_suite: request.content_encryption_suite,
                key_wrapping_suite: request.key_wrapping_suite,
                wrapped_object_keys: request.wrapped_object_keys,
                server_visible_metadata: request.server_visible_metadata,
                encrypted_client_metadata: request.encrypted_client_metadata,
                storage_class: if request.storage_class.trim().is_empty() {
                    DEFAULT_STORAGE_CLASS.to_string()
                } else {
                    request.storage_class
                },
                initiated_at_ms: now_ms(),
                idempotency_key: request.idempotency_key,
                completed: false,
            },
        )?;
        Ok(CreateMultipartUploadResponse {
            bucket: bucket.bucket,
            key: request.key,
            upload_id,
        })
    }

    pub fn upload_part(
        &self,
        auth: &AuthContext,
        request: UploadPartRequest,
        ciphertext_part: &[u8],
    ) -> Result<UploadPartResponse, ApiError> {
        self.ensure_bucket_mutation_scope(auth, &request.tenant_id)?;
        let session = self.multipart_session(&request.tenant_id, &request.upload_id)?;
        if session.completed {
            return Err(ApiError::new(
                ApiErrorCategory::Conflict,
                "multipart_conflict",
                "multipart upload is already completed",
            ));
        }
        let etag = cid_from_bytes(ciphertext_part);
        let part_key = multipart_part_store_key(&request.upload_id, request.part_number);
        self.write_encrypted_bytes(
            &request.tenant_id,
            MULTIPART_PARTS_STORE,
            &part_key,
            ciphertext_part,
        )?;
        self.write_encrypted_json(
            &request.tenant_id,
            MULTIPART_SESSIONS_STORE,
            &format!("part-meta-{part_key}"),
            &MultipartPartRecord {
                upload_id: request.upload_id.clone(),
                part_number: request.part_number,
                etag: etag.clone(),
                length: ciphertext_part.len() as u64,
                created_at_ms: now_ms(),
            },
        )?;
        Ok(UploadPartResponse {
            upload_id: request.upload_id,
            part_number: request.part_number,
            etag,
            length: ciphertext_part.len() as u64,
        })
    }

    pub fn complete_multipart_upload(
        &self,
        auth: &AuthContext,
        request: CompleteMultipartUploadRequest,
    ) -> Result<PutObjectResponse, ApiError> {
        self.ensure_bucket_mutation_scope(auth, &request.tenant_id)?;
        let mut session = self.multipart_session(&request.tenant_id, &request.upload_id)?;
        if session.completed {
            return Err(ApiError::new(
                ApiErrorCategory::Conflict,
                "multipart_conflict",
                "multipart upload is already completed",
            ));
        }
        if request.parts.is_empty() {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "multipart_not_found",
                "complete multipart requires at least one uploaded part",
            ));
        }

        let mut expected_numbers = BTreeSet::new();
        let mut assembled = Vec::new();
        for part in &request.parts {
            expected_numbers.insert(part.part_number);
            let meta = self
                .read_encrypted_json::<MultipartPartRecord>(
                    &request.tenant_id,
                    MULTIPART_SESSIONS_STORE,
                    &format!(
                        "part-meta-{}",
                        multipart_part_store_key(&request.upload_id, part.part_number)
                    ),
                )?
                .ok_or_else(|| {
                    ApiError::new(
                        ApiErrorCategory::NotFound,
                        "multipart_not_found",
                        "multipart part metadata not found",
                    )
                })?;
            if meta.etag != part.etag {
                return Err(ApiError::new(
                    ApiErrorCategory::Conflict,
                    "multipart_conflict",
                    "multipart part ETag does not match stored ciphertext part",
                ));
            }
            let bytes = self
                .read_encrypted_bytes(
                    &request.tenant_id,
                    MULTIPART_PARTS_STORE,
                    &multipart_part_store_key(&request.upload_id, part.part_number),
                )?
                .ok_or_else(|| {
                    ApiError::new(
                        ApiErrorCategory::NotFound,
                        "multipart_not_found",
                        "multipart part ciphertext not found",
                    )
                })?;
            assembled.extend_from_slice(&bytes);
        }

        session.completed = true;
        self.write_encrypted_json(
            &request.tenant_id,
            MULTIPART_SESSIONS_STORE,
            &request.upload_id,
            &session,
        )?;
        let response = self.put_object(
            auth,
            PutObjectRequest {
                tenant_id: request.tenant_id.clone(),
                bucket: session.bucket.clone(),
                key: session.key.clone(),
                access_profile: session.access_profile,
                payload_plaintext: session.payload_plaintext,
                content_type: session.content_type.clone(),
                encryption_profile_id: session.encryption_profile_id.clone(),
                key_policy_id: session.key_policy_id.clone(),
                metadata_visibility: session.metadata_visibility,
                content_encryption_suite: session.content_encryption_suite.clone(),
                key_wrapping_suite: session.key_wrapping_suite.clone(),
                wrapped_object_keys: session.wrapped_object_keys.clone(),
                server_visible_metadata: session.server_visible_metadata.clone(),
                encrypted_client_metadata: session.encrypted_client_metadata.clone(),
                storage_class: session.storage_class.clone(),
                idempotency_key: format!("complete-{}", session.idempotency_key),
            },
            &assembled,
        )?;
        self.cleanup_multipart(&request.tenant_id, &request.upload_id, &expected_numbers)?;
        Ok(response)
    }

    pub fn abort_multipart_upload(
        &self,
        auth: &AuthContext,
        request: AbortMultipartUploadRequest,
    ) -> Result<(), ApiError> {
        self.ensure_bucket_mutation_scope(auth, &request.tenant_id)?;
        let parts = self.multipart_parts(&request.tenant_id, &request.upload_id)?;
        let numbers = parts
            .into_iter()
            .map(|part| part.part_number)
            .collect::<BTreeSet<_>>();
        self.cleanup_multipart(&request.tenant_id, &request.upload_id, &numbers)?;
        self.delete_store_key(
            &request.tenant_id,
            MULTIPART_SESSIONS_STORE,
            &request.upload_id,
        )
    }

    pub fn authenticate_hsp_capability(
        &self,
        binding: &HttpRequestBinding<'_>,
    ) -> Result<AuthContext, ApiError> {
        let token_b64 = required_header(binding.headers, "x-hsp-capability")?;
        let nonce = required_header(binding.headers, "x-hsp-request-nonce")?;
        let proof_b64 = required_header(binding.headers, "x-hsp-request-proof")?;
        let claims = verify_cose_sign1_token(&token_b64, &self.issuer_registry)?;
        if claims.aud != self.config.capability_audience {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_token_audience",
                "capability token audience is not allowed for distribution surfaces",
            ));
        }
        let payload_hash = hex_sha256(binding.body);
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(
            format!(
                "{}\n{}\n{}\n{}\n{}\n{}",
                token_b64, binding.method, binding.raw_path, binding.raw_query, payload_hash, nonce
            )
            .as_bytes(),
        ));
        if proof_b64 != expected {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_request_binding",
                "request binding proof does not match the canonical request",
            ));
        }
        Ok(AuthContext {
            claims,
            channel_binding: Some(ChannelBindingProof {
                binding_kind: "request-signature".to_string(),
                proof_b64,
                nonce,
            }),
        })
    }

    pub fn authenticate_sigv4(
        &self,
        binding: &HttpRequestBinding<'_>,
    ) -> Result<AuthContext, ApiError> {
        if binding.raw_query.contains("X-Amz-Signature=") {
            self.authenticate_presigned_sigv4(binding)
        } else {
            self.authenticate_header_sigv4(binding)
        }
    }

    pub fn mint_edge_token(&self, claims: &EdgeTokenClaims) -> Result<String, ApiError> {
        let payload = serde_json::to_vec(claims).map_err(storage_serialize_error)?;
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
        let signature = self.edge_signature(&payload_b64)?;
        Ok(format!("{payload_b64}.{signature}"))
    }

    pub fn authenticate_edge_token(&self, token: &str) -> Result<AuthContext, ApiError> {
        let claims = self.decode_edge_token(token)?;
        Ok(AuthContext {
            claims: CapabilityClaims {
                iss: "hsp-cdn".to_string(),
                sub: "edge".to_string(),
                aud: "hsp-cdn".to_string(),
                exp: claims.exp,
                nbf: Some(now_ms().saturating_sub(1_000)),
                jti: Some(cid_from_bytes(token.as_bytes())),
                ops: vec![CapabilityScope::Read],
                tenant_id: claims.tenant_id,
                namespace_prefix: claims.bucket.clone(),
                path_prefix: claims.key.clone(),
                max_object_size: None,
                storage_classes: vec![DEFAULT_STORAGE_CLASS.to_string()],
                key_policy_id: None,
                metadata_visibility: None,
            },
            channel_binding: Some(ChannelBindingProof {
                binding_kind: "edge-token".to_string(),
                proof_b64: token
                    .rsplit_once('.')
                    .map(|(_, signature)| signature.to_string())
                    .unwrap_or_default(),
                nonce: token
                    .split_once('.')
                    .map(|(payload_b64, _)| payload_b64.to_string())
                    .unwrap_or_default(),
            }),
        })
    }

    pub fn decode_edge_token(&self, token: &str) -> Result<EdgeTokenClaims, ApiError> {
        let (payload_b64, signature) = token.split_once('.').ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "edge_token_malformed",
                "edge token must contain payload and signature",
            )
        })?;
        let expected = self.edge_signature(payload_b64)?;
        if expected != signature {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_edge_token",
                "edge token signature is invalid",
            ));
        }
        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64.as_bytes())
            .map_err(|_| {
                ApiError::new(
                    ApiErrorCategory::Auth,
                    "invalid_edge_token",
                    "edge token payload is not valid base64url",
                )
            })?;
        let claims: EdgeTokenClaims =
            serde_json::from_slice(&payload).map_err(storage_deserialize_error)?;
        if now_ms() > claims.exp {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "edge_token_expired",
                "edge token has expired",
            ));
        }
        Ok(claims)
    }

    fn authenticate_header_sigv4(
        &self,
        binding: &HttpRequestBinding<'_>,
    ) -> Result<AuthContext, ApiError> {
        let authorization = required_header(binding.headers, "authorization")?;
        let parsed = parse_sigv4_authorization(&authorization)?;
        let record = self.sigv4_access_key(&parsed.access_key_id)?;
        let request_date = required_header(binding.headers, "x-amz-date")?;
        let issued_at = parse_amz_date_with_code(&request_date, "invalid_sigv4")?;
        ensure_sigv4_time_window(issued_at, "invalid_sigv4", "header-based SigV4 request")?;
        if !request_date.starts_with(&parsed.date) {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_sigv4",
                "x-amz-date does not match credential scope date",
            ));
        }
        let payload_hash = binding
            .headers
            .get("x-amz-content-sha256")
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string)
            .unwrap_or_else(|| hex_sha256(binding.body));
        let canonical = canonical_sigv4_request(
            binding.method,
            binding.raw_path,
            binding.raw_query,
            binding.headers,
            &parsed.signed_headers,
            &payload_hash,
        )?;
        let string_to_sign =
            sigv4_string_to_sign(&request_date, &parsed.credential_scope, &canonical);
        let expected = sigv4_signature(
            &record.secret_access_key,
            &parsed.date,
            &parsed.region,
            &parsed.service,
            &string_to_sign,
        )?;
        if expected != parsed.signature {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_sigv4",
                "AWS Signature V4 verification failed",
            ));
        }
        Ok(self.sigv4_auth_context(record, binding.method, parsed.signature))
    }

    fn authenticate_presigned_sigv4(
        &self,
        binding: &HttpRequestBinding<'_>,
    ) -> Result<AuthContext, ApiError> {
        let params = parse_unique_query_pairs(binding.raw_query, "invalid_presign")?;
        let algorithm = params.get("X-Amz-Algorithm").cloned().unwrap_or_default();
        if algorithm != "AWS4-HMAC-SHA256" {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_presign",
                "unsupported presign algorithm",
            ));
        }
        let credential = params.get("X-Amz-Credential").cloned().ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_presign",
                "presigned URL is missing X-Amz-Credential",
            )
        })?;
        let signed_headers = params.get("X-Amz-SignedHeaders").cloned().ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_presign",
                "presigned URL is missing X-Amz-SignedHeaders",
            )
        })?;
        let signature = params.get("X-Amz-Signature").cloned().ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_presign",
                "presigned URL is missing X-Amz-Signature",
            )
        })?;
        let date = params.get("X-Amz-Date").cloned().ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_presign",
                "presigned URL is missing X-Amz-Date",
            )
        })?;
        let expires = params
            .get("X-Amz-Expires")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| {
                ApiError::new(
                    ApiErrorCategory::Auth,
                    "invalid_presign",
                    "presigned URL has invalid X-Amz-Expires",
                )
            })?;
        if expires > MAX_PRESIGN_EXPIRES_SEC {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_presign",
                "presigned URL exceeds the maximum allowed expiry window",
            ));
        }
        let issued_at = parse_amz_date_with_code(&date, "invalid_presign")?;
        ensure_sigv4_time_window(issued_at, "invalid_presign", "presigned URL")?;
        if now_ms() > issued_at.saturating_add(expires * 1_000) {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_presign",
                "presigned URL has expired",
            ));
        }
        let (access_key_id, date_scope, region, service) = parse_sigv4_credential(&credential)?;
        let record = self.sigv4_access_key(&access_key_id)?;
        let payload_hash = "UNSIGNED-PAYLOAD".to_string();
        let canonical_query = canonical_presign_query(&params);
        let canonical = canonical_sigv4_request(
            binding.method,
            binding.raw_path,
            &canonical_query,
            binding.headers,
            &split_signed_headers(&signed_headers),
            &payload_hash,
        )?;
        let scope = format!("{date_scope}/{region}/{service}/aws4_request");
        let string_to_sign = sigv4_string_to_sign(&date, &scope, &canonical);
        let expected = sigv4_signature(
            &record.secret_access_key,
            &date_scope,
            &region,
            &service,
            &string_to_sign,
        )?;
        if expected != signature {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_presign",
                "presigned URL verification failed",
            ));
        }
        self.write_encrypted_json(
            &record.tenant_id,
            PRESIGN_AUDIT_STORE,
            &cid_from_bytes(binding.raw_query.as_bytes()),
            &PresignAuditRecord {
                token_id: cid_from_bytes(binding.raw_query.as_bytes()),
                tenant_id: record.tenant_id.clone(),
                method: binding.method.to_string(),
                bucket: None,
                key: None,
                cid: None,
                expires_at_ms: issued_at.saturating_add(expires * 1_000),
                created_at_ms: now_ms(),
            },
        )?;
        Ok(self.sigv4_auth_context(record, binding.method, signature))
    }

    fn sigv4_auth_context(
        &self,
        record: SigV4AccessKeyRecord,
        method: &str,
        signature: String,
    ) -> AuthContext {
        AuthContext {
            claims: CapabilityClaims {
                iss: "sigv4".to_string(),
                sub: record.access_key_id.clone(),
                aud: "hsp-s3".to_string(),
                exp: now_ms().saturating_add(60_000),
                nbf: Some(now_ms().saturating_sub(1_000)),
                jti: Some(signature.clone()),
                ops: scopes_for_http_method(method),
                tenant_id: record.tenant_id,
                namespace_prefix: record.namespace_prefix,
                path_prefix: record.path_prefix,
                max_object_size: record.max_object_size,
                storage_classes: if record.storage_classes.is_empty() {
                    vec![DEFAULT_STORAGE_CLASS.to_string()]
                } else {
                    record.storage_classes
                },
                key_policy_id: Some(record.key_policy_id),
                metadata_visibility: Some(record.metadata_visibility),
            },
            channel_binding: Some(ChannelBindingProof {
                binding_kind: "sigv4".to_string(),
                proof_b64: signature.clone(),
                nonce: signature,
            }),
        }
    }

    fn sigv4_access_key(&self, access_key_id: &str) -> Result<SigV4AccessKeyRecord, ApiError> {
        let mut matches = Vec::new();
        for record in self.list_all_access_keys()? {
            if record.access_key_id == access_key_id && record.enabled {
                matches.push(record);
            }
        }
        matches.into_iter().next().ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_sigv4",
                "unknown SigV4 access key id",
            )
        })
    }

    fn list_all_access_keys(&self) -> Result<Vec<SigV4AccessKeyRecord>, ApiError> {
        let mut records = Vec::new();
        for tenant_dir in tenant_dirs(self.config.alpha.root_dir.join(DISTRIBUTION_METADATA_STORE))?
        {
            let tenant_id = TenantId(tenant_dir.0);
            records.extend(
                self.list_encrypted_json::<SigV4AccessKeyRecord>(
                    &tenant_id,
                    DISTRIBUTION_METADATA_STORE,
                )?
                .into_iter()
                .filter(|record| record.access_key_id.starts_with(|_: char| true)),
            );
        }
        Ok(records
            .into_iter()
            .filter(|record| !record.access_key_id.is_empty())
            .collect())
    }

    fn bucket_record(
        &self,
        tenant_id: &TenantId,
        bucket: &str,
    ) -> Result<Option<BucketRecord>, ApiError> {
        self.read_encrypted_json(tenant_id, BUCKET_REGISTRY_STORE, bucket)
    }

    fn require_bucket(&self, tenant_id: &TenantId, bucket: &str) -> Result<BucketRecord, ApiError> {
        let bucket = self.canonical_bucket(bucket.to_string())?;
        self.bucket_record(tenant_id, &bucket)?.ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::NotFound,
                "bucket_not_found",
                "bucket not found",
            )
        })
    }

    fn has_multipart_sessions(&self, tenant_id: &TenantId, bucket: &str) -> Result<bool, ApiError> {
        Ok(self
            .list_encrypted_json::<MultipartSessionRecord>(tenant_id, MULTIPART_SESSIONS_STORE)?
            .into_iter()
            .any(|session| session.bucket == bucket && !session.completed))
    }

    fn multipart_session(
        &self,
        tenant_id: &TenantId,
        upload_id: &str,
    ) -> Result<MultipartSessionRecord, ApiError> {
        self.read_encrypted_json(tenant_id, MULTIPART_SESSIONS_STORE, upload_id)?
            .ok_or_else(|| {
                ApiError::new(
                    ApiErrorCategory::NotFound,
                    "multipart_not_found",
                    "multipart upload session not found",
                )
            })
    }

    fn multipart_parts(
        &self,
        tenant_id: &TenantId,
        upload_id: &str,
    ) -> Result<Vec<MultipartPartRecord>, ApiError> {
        Ok(self
            .list_encrypted_json::<MultipartPartRecord>(tenant_id, MULTIPART_SESSIONS_STORE)?
            .into_iter()
            .filter(|part| part.upload_id == upload_id)
            .collect())
    }

    fn cleanup_multipart(
        &self,
        tenant_id: &TenantId,
        upload_id: &str,
        part_numbers: &BTreeSet<u32>,
    ) -> Result<(), ApiError> {
        for part_number in part_numbers {
            let part_key = multipart_part_store_key(upload_id, *part_number);
            self.delete_store_key(tenant_id, MULTIPART_PARTS_STORE, &part_key)?;
            self.delete_store_key(
                tenant_id,
                MULTIPART_SESSIONS_STORE,
                &format!("part-meta-{part_key}"),
            )?;
        }
        self.delete_store_key(tenant_id, MULTIPART_SESSIONS_STORE, upload_id)
    }

    fn sign_namespace_record(&self, record: &NamespaceMutationRecord) -> Result<String, ApiError> {
        let mut payload = Vec::new();
        into_writer(record, &mut payload).map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "signed_record_encode_failed",
                error.to_string(),
            )
        })?;
        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::EdDSA)
            .key_id(self.namespace_signing_key_id.as_bytes().to_vec())
            .build();
        let token = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(b"", |message| {
                self.namespace_signing_key.sign(message).to_bytes().to_vec()
            })
            .build();
        Ok(URL_SAFE_NO_PAD.encode(token.to_vec().map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "signed_record_encode_failed",
                error.to_string(),
            )
        })?))
    }

    fn validate_ciphertext_manifest_input(
        &self,
        request: &PutObjectRequest,
        ciphertext: &[u8],
    ) -> Result<(), ApiError> {
        if ciphertext.is_empty() {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "unsupported_plaintext_mode",
                "ciphertext object body must be non-empty",
            ));
        }
        if !request.payload_plaintext && request.wrapped_object_keys.is_empty() {
            return Err(ApiError::new(
                ApiErrorCategory::Unsupported,
                "unsupported_plaintext_mode",
                "ciphertext object uploads require wrapped object keys",
            ));
        }
        Ok(())
    }

    fn validate_access_profile(
        &self,
        access_profile: AccessProfile,
        plaintext_requested: bool,
    ) -> Result<(), ApiError> {
        match access_profile {
            AccessProfile::PublicCiphertext => {
                if plaintext_requested {
                    return Err(ApiError::new(
                        ApiErrorCategory::Unsupported,
                        "trusted_edge_required",
                        "plaintext serving requires trusted-edge-v1 profile",
                    ));
                }
                Ok(())
            }
            AccessProfile::TrustedEdgeV1 => {
                if plaintext_requested && !self.config.plaintext_profile_enabled {
                    return Err(ApiError::new(
                        ApiErrorCategory::Policy,
                        "trusted_edge_required",
                        "trusted-edge-v1 profile is disabled for this deployment",
                    ));
                }
                Ok(())
            }
        }
    }

    fn ensure_object_mutation_unlocked(
        &self,
        tenant_id: &TenantId,
        bucket: &str,
        key: &str,
        delete_op: bool,
        auth: &AuthContext,
    ) -> Result<(), ApiError> {
        let lock = self.read_encrypted_json::<ObjectLockRecord>(
            tenant_id,
            OBJECT_LOCK_STORE,
            &object_lock_store_key(bucket, key),
        )?;
        let Some(lock) = lock else {
            return Ok(());
        };
        if lock.legal_hold {
            return Err(ApiError::new(
                ApiErrorCategory::Conflict,
                "legal_hold_active",
                "object is under legal hold",
            ));
        }
        if let Some(until) = lock.immutable_until_ms {
            let now = now_ms();
            if now < until
                && !auth
                    .claims
                    .ops
                    .iter()
                    .any(|scope| matches!(scope, CapabilityScope::AdminRepair))
            {
                return Err(ApiError::new(
                    ApiErrorCategory::Conflict,
                    "lock_conflict",
                    if delete_op {
                        "object retention lock blocks delete before immutable-until"
                    } else {
                        "object retention lock blocks overwrite before immutable-until"
                    },
                ));
            }
        }
        Ok(())
    }

    fn edge_signature(&self, payload_b64: &str) -> Result<String, ApiError> {
        let mut mac = HmacSha256::new_from_slice(&self.edge_signing_secret).map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "edge_token_signing_failed",
                error.to_string(),
            )
        })?;
        mac.update(payload_b64.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }

    fn ensure_bucket_mutation_scope(
        &self,
        auth: &AuthContext,
        tenant_id: &TenantId,
    ) -> Result<(), ApiError> {
        if auth.claims.tenant_id != *tenant_id {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "tenant_mismatch",
                "tenant does not match the authenticated principal",
            ));
        }
        if !auth.claims.ops.iter().any(|scope| {
            matches!(
                scope,
                CapabilityScope::Write | CapabilityScope::Bind | CapabilityScope::Unbind
            )
        }) {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "operation_not_allowed",
                "bucket mutation requires write-capable credentials",
            ));
        }
        Ok(())
    }

    fn ensure_bucket_read_scope(
        &self,
        auth: &AuthContext,
        tenant_id: &TenantId,
    ) -> Result<(), ApiError> {
        if auth.claims.tenant_id != *tenant_id {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "tenant_mismatch",
                "tenant does not match the authenticated principal",
            ));
        }
        if !auth.claims.ops.iter().any(|scope| {
            matches!(
                scope,
                CapabilityScope::Read | CapabilityScope::List | CapabilityScope::Write
            )
        }) {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "operation_not_allowed",
                "bucket read requires read-capable credentials",
            ));
        }
        Ok(())
    }

    fn ensure_bucket_read_scope_for(
        &self,
        auth: &AuthContext,
        tenant_id: &TenantId,
        bucket: &str,
        key: Option<&str>,
    ) -> Result<(), ApiError> {
        if auth.claims.tenant_id != *tenant_id {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "tenant_mismatch",
                "tenant does not match the authenticated principal",
            ));
        }
        if has_read_capability(auth) {
            return Ok(());
        }
        let bucket_acl = self.read_encrypted_json::<BucketAclRecord>(
            tenant_id,
            ACL_STORE,
            &bucket_acl_store_key(bucket),
        )?;
        if bucket_acl
            .as_ref()
            .map(|record| acl_allows_read(record.acl))
            .unwrap_or(false)
        {
            return Ok(());
        }
        if let Some(key) = key {
            let object_acl = self.read_encrypted_json::<ObjectAclRecord>(
                tenant_id,
                ACL_STORE,
                &object_acl_store_key(bucket, key),
            )?;
            if object_acl
                .as_ref()
                .map(|record| acl_allows_read(record.acl))
                .unwrap_or(false)
            {
                return Ok(());
            }
        }
        Err(ApiError::new(
            ApiErrorCategory::Auth,
            "acl_denied",
            "read request is blocked by ACL policy",
        ))
    }

    fn canonical_bucket(&self, bucket: String) -> Result<String, ApiError> {
        if bucket.trim().is_empty() || bucket.contains('/') {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "invalid_bucket",
                "bucket name must be non-empty and must not contain '/'",
            ));
        }
        let canonical = canonical_path(&bucket).map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Validation,
                "invalid_bucket",
                error.to_string(),
            )
        })?;
        if canonical.trim().is_empty() || canonical.contains('/') {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "invalid_bucket",
                "bucket name must remain a single canonical segment after percent-decoding",
            ));
        }
        Ok(canonical)
    }

    fn canonical_object_key(&self, key: String) -> Result<String, ApiError> {
        canonical_path(&key).map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Validation,
                "invalid_object_key",
                error.to_string(),
            )
        })
    }

    fn ensure_store_roots(&self) -> Result<(), ApiError> {
        for store_kind in [
            BUCKET_REGISTRY_STORE,
            DISTRIBUTION_METADATA_STORE,
            MULTIPART_SESSIONS_STORE,
            MULTIPART_PARTS_STORE,
            PRESIGN_AUDIT_STORE,
            ACL_STORE,
            LIFECYCLE_STORE,
            OBJECT_LOCK_STORE,
            WEBSITE_STORE,
            REPLICATION_STORE,
            WORKER_CURSOR_STORE,
        ] {
            fs::create_dir_all(self.config.alpha.root_dir.join(store_kind)).map_err(|error| {
                ApiError::new(ApiErrorCategory::Storage, "mkdir_failed", error.to_string())
            })?;
        }
        Ok(())
    }

    fn write_encrypted_bytes(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        key: &str,
        bytes: &[u8],
    ) -> Result<(), ApiError> {
        let envelope = self
            .store_kms
            .encrypt_store_payload(tenant_id, store_kind, bytes)
            .map_err(|error| {
                crypto_error_to_api(error, "failed to encrypt distribution payload")
            })?;
        self.write_envelope(tenant_id, store_kind, key, &envelope)
    }

    fn write_encrypted_json<T: Serialize>(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        key: &str,
        value: &T,
    ) -> Result<(), ApiError> {
        let bytes = serde_json::to_vec_pretty(value).map_err(storage_serialize_error)?;
        self.write_encrypted_bytes(tenant_id, store_kind, key, &bytes)
    }

    fn read_encrypted_json<T: DeserializeOwned>(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        key: &str,
    ) -> Result<Option<T>, ApiError> {
        let Some(bytes) = self.read_encrypted_bytes(tenant_id, store_kind, key)? else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(storage_deserialize_error)
    }

    fn list_encrypted_json<T: DeserializeOwned>(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
    ) -> Result<Vec<T>, ApiError> {
        let tenant_root = self
            .config
            .alpha
            .root_dir
            .join(store_kind)
            .join(tenant_store_dir(tenant_id));
        if !tenant_root.exists() {
            return Ok(Vec::new());
        }
        let mut items = Vec::new();
        for entry in fs::read_dir(tenant_root).map_err(storage_read_error)? {
            let entry = entry.map_err(storage_read_error)?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let bytes = fs::read(&path).map_err(storage_read_error)?;
            let envelope: StoredEnvelope =
                serde_json::from_slice(&bytes).map_err(storage_deserialize_error)?;
            let plaintext = self
                .store_kms
                .decrypt_store_payload(tenant_id, store_kind, &envelope)
                .map_err(|error| {
                    crypto_error_to_api(error, "failed to decrypt distribution payload")
                })?;
            if let Ok(value) = serde_json::from_slice::<T>(&plaintext) {
                items.push(value);
            }
        }
        Ok(items)
    }

    fn read_encrypted_bytes(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>, ApiError> {
        let path = self.store_path(tenant_id, store_kind, key);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path).map_err(storage_read_error)?;
        let envelope: StoredEnvelope =
            serde_json::from_slice(&bytes).map_err(storage_deserialize_error)?;
        self.store_kms
            .decrypt_store_payload(tenant_id, store_kind, &envelope)
            .map(Some)
            .map_err(|error| crypto_error_to_api(error, "failed to decrypt distribution payload"))
    }

    fn write_envelope(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        key: &str,
        envelope: &StoredEnvelope,
    ) -> Result<(), ApiError> {
        let path = self.store_path(tenant_id, store_kind, key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                ApiError::new(ApiErrorCategory::Storage, "mkdir_failed", error.to_string())
            })?;
        }
        let bytes = serde_json::to_vec_pretty(envelope).map_err(storage_serialize_error)?;
        fs::write(path, bytes).map_err(storage_write_error)
    }

    fn delete_store_key(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        key: &str,
    ) -> Result<(), ApiError> {
        let path = self.store_path(tenant_id, store_kind, key);
        if path.exists() {
            fs::remove_file(path).map_err(storage_write_error)?;
        }
        Ok(())
    }

    fn store_path(&self, tenant_id: &TenantId, store_kind: &str, key: &str) -> PathBuf {
        self.config
            .alpha
            .root_dir
            .join(store_kind)
            .join(tenant_store_dir(tenant_id))
            .join(store_file_name(key))
    }
}

fn build_manifest(input: ManifestBuildInput) -> Result<Manifest, ApiError> {
    let chunks = chunk_ciphertext(&input.ciphertext);
    let chunk_refs = chunks
        .iter()
        .map(|chunk| ChunkRef {
            chunk_index: chunk.chunk_index,
            cid: chunk.cid.clone(),
            offset: chunk.offset,
            logical_len: chunk.stored_len,
            stored_len: chunk.stored_len,
            content_encoding: chunk.content_encoding.clone(),
        })
        .collect::<Vec<_>>();
    let manifest = Manifest {
        version: 1,
        tenant_id: input.tenant_id,
        logical_size: input.ciphertext.len() as u64,
        stored_size: input.ciphertext.len() as u64,
        chunker: "fixed-1m".to_string(),
        chunk_refs,
        content_type: input.content_type,
        created_at_ms: now_ms(),
        encryption_descriptor: EncryptionDescriptor {
            encryption_profile_id: input.encryption_profile_id,
            key_policy_id: input.key_policy_id,
            content_encryption_suite: input.content_encryption_suite,
            key_wrapping_suite: input.key_wrapping_suite,
            metadata_visibility: input.metadata_visibility,
            wrapped_object_keys: input.wrapped_object_keys,
            server_visible_metadata: input.server_visible_metadata,
            encrypted_client_metadata: input.encrypted_client_metadata,
        },
    };
    manifest.validate()?;
    Ok(manifest)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StagedChunk {
    chunk_index: u32,
    cid: String,
    offset: u64,
    stored_len: u64,
    content_encoding: String,
    bytes: Vec<u8>,
}

fn chunk_ciphertext(ciphertext: &[u8]) -> Vec<StagedChunk> {
    ciphertext
        .chunks(FIXED_CHUNK_SIZE)
        .enumerate()
        .map(|(index, chunk)| StagedChunk {
            chunk_index: index as u32,
            cid: cid_from_bytes(chunk),
            offset: (index * FIXED_CHUNK_SIZE) as u64,
            stored_len: chunk.len() as u64,
            content_encoding: "identity".to_string(),
            bytes: chunk.to_vec(),
        })
        .collect()
}

fn map_object_error(error: ApiError) -> ApiError {
    match error.code.as_str() {
        "path_not_bound" | "path_tombstoned" | "manifest_not_found" => ApiError::new(
            ApiErrorCategory::NotFound,
            "object_not_found",
            "object not found",
        ),
        _ => error,
    }
}

fn required_header(headers: &HeaderMap, name: &str) -> Result<String, ApiError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
        .ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "missing_required_header",
                format!("required header `{name}` is missing"),
            )
        })
}

fn parse_sigv4_authorization(value: &str) -> Result<ParsedSigV4Authorization, ApiError> {
    let prefix = "AWS4-HMAC-SHA256 ";
    let raw = value.strip_prefix(prefix).ok_or_else(|| {
        ApiError::new(
            ApiErrorCategory::Auth,
            "invalid_sigv4",
            "authorization header is not AWS4-HMAC-SHA256",
        )
    })?;
    let parts = raw.split(", ").collect::<Vec<_>>();
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for part in parts {
        if let Some(value) = part.strip_prefix("Credential=") {
            credential = Some(value.to_string());
        } else if let Some(value) = part.strip_prefix("SignedHeaders=") {
            signed_headers = Some(split_signed_headers(value));
        } else if let Some(value) = part.strip_prefix("Signature=") {
            signature = Some(value.to_string());
        }
    }
    let credential = credential.ok_or_else(|| {
        ApiError::new(
            ApiErrorCategory::Auth,
            "invalid_sigv4",
            "authorization header is missing Credential",
        )
    })?;
    let (access_key_id, date, region, service) = parse_sigv4_credential(&credential)?;
    Ok(ParsedSigV4Authorization {
        access_key_id,
        date: date.clone(),
        region: region.clone(),
        service: service.clone(),
        credential_scope: format!("{date}/{region}/{service}/aws4_request"),
        signed_headers: signed_headers.ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_sigv4",
                "authorization header is missing SignedHeaders",
            )
        })?,
        signature: signature.ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_sigv4",
                "authorization header is missing Signature",
            )
        })?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedSigV4Authorization {
    access_key_id: String,
    date: String,
    region: String,
    service: String,
    credential_scope: String,
    signed_headers: Vec<String>,
    signature: String,
}

fn parse_sigv4_credential(credential: &str) -> Result<(String, String, String, String), ApiError> {
    let parts = credential.split('/').collect::<Vec<_>>();
    if parts.len() != 5 || parts[4] != "aws4_request" {
        return Err(ApiError::new(
            ApiErrorCategory::Auth,
            "invalid_sigv4",
            "credential scope is malformed",
        ));
    }
    Ok((
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].to_string(),
        parts[3].to_string(),
    ))
}

fn canonical_sigv4_request(
    method: &str,
    raw_path: &str,
    raw_query: &str,
    headers: &HeaderMap,
    signed_headers: &[String],
    payload_hash: &str,
) -> Result<String, ApiError> {
    validate_signed_headers(signed_headers)?;
    let mut canonical_headers = String::new();
    for header in signed_headers {
        let value = required_single_signed_header(headers, header)?;
        canonical_headers.push_str(&format!(
            "{}:{}\n",
            header.to_ascii_lowercase(),
            normalize_header_value(value)
        ));
    }
    Ok(format!(
        "{method}\n{raw_path}\n{raw_query}\n{canonical_headers}\n{}\n{payload_hash}",
        signed_headers.join(";"),
    ))
}

fn sigv4_string_to_sign(date: &str, credential_scope: &str, canonical_request: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256\n{date}\n{credential_scope}\n{}",
        hex_sha256(canonical_request.as_bytes())
    )
}

fn sigv4_signature(
    secret_access_key: &str,
    date: &str,
    region: &str,
    service: &str,
    string_to_sign: &str,
) -> Result<String, ApiError> {
    let k_date = hmac_sha256(
        format!("AWS4{secret_access_key}").as_bytes(),
        date.as_bytes(),
    )?;
    let k_region = hmac_sha256(&k_date, region.as_bytes())?;
    let k_service = hmac_sha256(&k_region, service.as_bytes())?;
    let k_signing = hmac_sha256(&k_service, b"aws4_request")?;
    Ok(hex_lower(&hmac_sha256(
        &k_signing,
        string_to_sign.as_bytes(),
    )?))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, ApiError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|error| {
        ApiError::new(ApiErrorCategory::Auth, "invalid_sigv4", error.to_string())
    })?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn split_signed_headers(input: &str) -> Vec<String> {
    input
        .split(';')
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn parse_unique_query_pairs(
    input: &str,
    error_code: &'static str,
) -> Result<BTreeMap<String, String>, ApiError> {
    let mut pairs = BTreeMap::new();
    for pair in input.split('&').filter(|segment| !segment.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if pairs.contains_key(key) {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                error_code,
                format!("duplicate query parameter `{key}` is not allowed"),
            ));
        }
        pairs.insert(key.to_string(), value.to_string());
    }
    Ok(pairs)
}

fn canonical_presign_query(params: &BTreeMap<String, String>) -> String {
    let mut pairs = params
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .filter(|(key, _)| key != "X-Amz-Signature")
        .collect::<Vec<_>>();
    pairs.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn parse_amz_date_with_code(value: &str, error_code: &'static str) -> Result<u64, ApiError> {
    if value.len() != 16 || !value.ends_with('Z') {
        return Err(invalid_amz_date(error_code));
    }
    let year = value[0..4]
        .parse::<u64>()
        .map_err(|_| invalid_amz_date(error_code))?;
    let month = value[4..6]
        .parse::<u64>()
        .map_err(|_| invalid_amz_date(error_code))?;
    let day = value[6..8]
        .parse::<u64>()
        .map_err(|_| invalid_amz_date(error_code))?;
    let hour = value[9..11]
        .parse::<u64>()
        .map_err(|_| invalid_amz_date(error_code))?;
    let minute = value[11..13]
        .parse::<u64>()
        .map_err(|_| invalid_amz_date(error_code))?;
    let second = value[13..15]
        .parse::<u64>()
        .map_err(|_| invalid_amz_date(error_code))?;
    Ok(datetime_to_epoch_ms(year, month, day, hour, minute, second))
}

fn invalid_amz_date(error_code: &'static str) -> ApiError {
    ApiError::new(
        ApiErrorCategory::Auth,
        error_code,
        "invalid X-Amz-Date format",
    )
}

fn ensure_sigv4_time_window(
    issued_at_ms: u64,
    error_code: &'static str,
    request_kind: &str,
) -> Result<(), ApiError> {
    let now = now_ms();
    if issued_at_ms > now.saturating_add(MAX_SIGV4_CLOCK_SKEW_MS) {
        return Err(ApiError::new(
            ApiErrorCategory::Auth,
            error_code,
            format!("{request_kind} has a future X-Amz-Date outside the allowed clock skew"),
        ));
    }
    if now.saturating_sub(issued_at_ms) > MAX_SIGV4_CLOCK_SKEW_MS {
        return Err(ApiError::new(
            ApiErrorCategory::Auth,
            error_code,
            format!("{request_kind} is older than the allowed clock skew window"),
        ));
    }
    Ok(())
}

fn validate_signed_headers(signed_headers: &[String]) -> Result<(), ApiError> {
    if signed_headers.is_empty() {
        return Err(ApiError::new(
            ApiErrorCategory::Auth,
            "invalid_sigv4",
            "signed headers list must not be empty",
        ));
    }
    if !signed_headers.iter().any(|header| header == "host") {
        return Err(ApiError::new(
            ApiErrorCategory::Auth,
            "invalid_sigv4",
            "signed headers must include host",
        ));
    }
    for window in signed_headers.windows(2) {
        if window[0] >= window[1] {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_sigv4",
                "signed headers must be lowercase, unique, and sorted",
            ));
        }
    }
    if signed_headers.iter().any(|header| {
        header.is_empty()
            || header
                .chars()
                .any(|character| character.is_ascii_uppercase())
    }) {
        return Err(ApiError::new(
            ApiErrorCategory::Auth,
            "invalid_sigv4",
            "signed headers must be lowercase and non-empty",
        ));
    }
    Ok(())
}

fn required_single_signed_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<&'a str, ApiError> {
    let mut values = headers.get_all(name).iter();
    let first = values.next().ok_or_else(|| {
        ApiError::new(
            ApiErrorCategory::Auth,
            "invalid_sigv4",
            format!("missing signed header `{name}`"),
        )
    })?;
    if values.next().is_some() {
        return Err(ApiError::new(
            ApiErrorCategory::Auth,
            "invalid_sigv4",
            format!("duplicate signed header `{name}` is not allowed"),
        ));
    }
    first.to_str().map_err(|_| {
        ApiError::new(
            ApiErrorCategory::Auth,
            "invalid_sigv4",
            format!("signed header `{name}` is not valid ASCII"),
        )
    })
}

fn datetime_to_epoch_ms(
    year: u64,
    month: u64,
    day: u64,
    hour: u64,
    minute: u64,
    second: u64,
) -> u64 {
    let days = days_from_civil(year as i64, month as i64, day as i64);
    (days as u64 * 86_400 + hour * 3_600 + minute * 60 + second) * 1_000
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - (month <= 2) as i64;
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[cfg(test)]
fn civil_from_days(days: i64) -> (i64, u64, u64) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + (month <= 2) as i64;
    (year, month as u64, day as u64)
}

#[cfg(test)]
fn amz_date_from_epoch_ms(epoch_ms: u64) -> String {
    let total_seconds = epoch_ms / 1_000;
    let days = (total_seconds / 86_400) as i64;
    let seconds_of_day = total_seconds % 86_400;
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

fn scopes_for_http_method(method: &str) -> Vec<CapabilityScope> {
    match method {
        "GET" | "HEAD" => vec![CapabilityScope::Read, CapabilityScope::List],
        "PUT" | "POST" | "DELETE" => vec![
            CapabilityScope::Read,
            CapabilityScope::Write,
            CapabilityScope::Bind,
            CapabilityScope::Unbind,
            CapabilityScope::List,
        ],
        _ => vec![CapabilityScope::Read],
    }
}

fn has_read_capability(auth: &AuthContext) -> bool {
    auth.claims.ops.iter().any(|scope| {
        matches!(
            scope,
            CapabilityScope::Read | CapabilityScope::List | CapabilityScope::Write
        )
    })
}

fn acl_allows_read(acl: CannedAcl) -> bool {
    matches!(acl, CannedAcl::PublicRead | CannedAcl::AuthenticatedRead)
}

fn normalize_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn multipart_part_store_key(upload_id: &str, part_number: u32) -> String {
    format!("{upload_id}-part-{part_number:05}")
}

fn bucket_acl_store_key(bucket: &str) -> String {
    format!("bucket-{bucket}")
}

fn object_acl_store_key(bucket: &str, key: &str) -> String {
    format!("object-{bucket}-{key}")
}

fn lifecycle_store_key(bucket: &str) -> String {
    format!("bucket-{bucket}")
}

fn object_lock_store_key(bucket: &str, key: &str) -> String {
    format!("object-{bucket}-{key}")
}

fn website_store_key(bucket: &str) -> String {
    format!("bucket-{bucket}")
}

fn replication_config_store_key(source_bucket: &str) -> String {
    format!("config-{source_bucket}")
}

fn replication_status_store_key(source_bucket: &str) -> String {
    format!("status-{source_bucket}")
}

fn tenant_store_dir(tenant_id: &TenantId) -> String {
    URL_SAFE_NO_PAD.encode(tenant_id.0.as_bytes())
}

fn decode_tenant_store_dir(input: &str) -> Option<String> {
    let decoded = URL_SAFE_NO_PAD.decode(input.as_bytes()).ok()?;
    String::from_utf8(decoded).ok()
}

fn store_file_name(key: &str) -> String {
    format!("{}.json.enc", hex_sha256(key.as_bytes()))
}

fn tenant_dirs(root: PathBuf) -> Result<Vec<(String, PathBuf)>, ApiError> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut tenants = Vec::new();
    for entry in fs::read_dir(root).map_err(storage_read_error)? {
        let entry = entry.map_err(storage_read_error)?;
        if entry.path().is_dir() {
            tenants.push((
                decode_tenant_store_dir(&entry.file_name().to_string_lossy())
                    .unwrap_or_else(|| entry.file_name().to_string_lossy().to_string()),
                entry.path(),
            ));
        }
    }
    Ok(tenants)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn storage_serialize_error(error: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        ApiErrorCategory::Storage,
        "json_serialize_failed",
        error.to_string(),
    )
}

fn storage_deserialize_error(error: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        ApiErrorCategory::Storage,
        "json_deserialize_failed",
        error.to_string(),
    )
}

fn storage_read_error(error: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        ApiErrorCategory::Storage,
        "store_read_failed",
        error.to_string(),
    )
}

fn storage_write_error(error: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        ApiErrorCategory::Storage,
        "store_write_failed",
        error.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    use hsp_auth::IssuerRecord;
    use http::HeaderValue;

    static NEXT_TEMP_ROOT_ID: AtomicU64 = AtomicU64::new(1);

    fn temp_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "hsp-distribution-{}-{}",
            std::process::id(),
            NEXT_TEMP_ROOT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        root
    }

    fn service() -> DistributionService {
        let signing_key = SigningKey::from_bytes(&[17u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let registry = IssuerRegistry {
            issuers: vec![IssuerRecord {
                issuer: "dist".to_string(),
                key_id: "dist-key".to_string(),
                algorithm: "Ed25519".to_string(),
                public_key_b64: URL_SAFE_NO_PAD.encode(verifying_key.as_bytes()),
                audiences: vec!["hsp-s3".to_string(), "hsp-cdn".to_string()],
            }],
        };
        let root = temp_root();
        DistributionService::new(
            DistributionConfig {
                alpha: AlphaConfig {
                    authority: "localhost".to_string(),
                    gateway_base_url: "https://localhost/v1".to_string(),
                    root_dir: root,
                    native_port: 443,
                    server_instance_id: "test".to_string(),
                },
                capability_audience: "hsp-s3".to_string(),
                immutable_cid_ttl_sec: 3600,
                namespace_ttl_sec: 5,
                plaintext_profile_enabled: true,
                aws_kms: None,
            },
            LocalDevKms::from_seed(b"hsp-distribution-test-seed").unwrap(),
            registry,
            signing_key,
            "dist-key",
            b"edge-secret".to_vec(),
        )
        .unwrap()
    }

    fn auth() -> AuthContext {
        AuthContext {
            claims: CapabilityClaims {
                iss: "dist".to_string(),
                sub: "tester".to_string(),
                aud: "hsp-s3".to_string(),
                exp: now_ms() + 60_000,
                nbf: Some(now_ms() - 1_000),
                jti: Some(format!("jti-{}", now_ms())),
                ops: vec![
                    CapabilityScope::Read,
                    CapabilityScope::Write,
                    CapabilityScope::Bind,
                    CapabilityScope::Unbind,
                    CapabilityScope::List,
                ],
                tenant_id: TenantId("tenant-alpha".to_string()),
                namespace_prefix: None,
                path_prefix: None,
                max_object_size: Some(32 * 1024 * 1024),
                storage_classes: vec![DEFAULT_STORAGE_CLASS.to_string()],
                key_policy_id: Some(KeyPolicyId("policy-default".to_string())),
                metadata_visibility: Some(VisibilityMode::Split),
            },
            channel_binding: Some(ChannelBindingProof {
                binding_kind: "request-signature".to_string(),
                proof_b64: "test".to_string(),
                nonce: "nonce".to_string(),
            }),
        }
    }

    fn write_only_auth() -> AuthContext {
        AuthContext {
            claims: CapabilityClaims {
                iss: "dist".to_string(),
                sub: "writer".to_string(),
                aud: "hsp-s3".to_string(),
                exp: now_ms() + 60_000,
                nbf: Some(now_ms() - 1_000),
                jti: Some(format!("jti-write-{}", now_ms())),
                ops: vec![
                    CapabilityScope::Write,
                    CapabilityScope::Bind,
                    CapabilityScope::Unbind,
                ],
                tenant_id: TenantId("tenant-alpha".to_string()),
                namespace_prefix: None,
                path_prefix: None,
                max_object_size: Some(32 * 1024 * 1024),
                storage_classes: vec![DEFAULT_STORAGE_CLASS.to_string()],
                key_policy_id: Some(KeyPolicyId("policy-default".to_string())),
                metadata_visibility: Some(VisibilityMode::Split),
            },
            channel_binding: Some(ChannelBindingProof {
                binding_kind: "request-signature".to_string(),
                proof_b64: "write-only".to_string(),
                nonce: "nonce".to_string(),
            }),
        }
    }

    fn wrapped_key() -> WrappedObjectKeyRecord {
        WrappedObjectKeyRecord {
            recipient_key_id: "reader-1".to_string(),
            wrapping_suite: "HPKE/X25519".to_string(),
            wrapped_key_b64: URL_SAFE_NO_PAD.encode(b"wrapped"),
            key_version: 1,
            encapsulated_key_b64: Some(URL_SAFE_NO_PAD.encode(b"nonce")),
        }
    }

    fn register_sigv4_key(service: &DistributionService) {
        service
            .register_sigv4_access_key(SigV4AccessKeyRecord {
                access_key_id: "AKIA_TEST".to_string(),
                secret_access_key: "secret".to_string(),
                tenant_id: TenantId("tenant-alpha".to_string()),
                namespace_prefix: None,
                path_prefix: None,
                max_object_size: Some(32 * 1024 * 1024),
                storage_classes: vec![DEFAULT_STORAGE_CLASS.to_string()],
                key_policy_id: KeyPolicyId("policy-default".to_string()),
                metadata_visibility: VisibilityMode::Split,
                enabled: true,
            })
            .unwrap();
    }

    #[test]
    fn bucket_lifecycle_roundtrip() {
        let service = service();
        let auth = auth();
        let bucket = service
            .create_bucket(&auth, TenantId("tenant-alpha".to_string()), "media")
            .unwrap();
        assert_eq!(bucket.bucket, "media");

        let listed = service
            .list_buckets(&auth, TenantId("tenant-alpha".to_string()))
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].bucket, "media");

        service
            .delete_bucket(&auth, TenantId("tenant-alpha".to_string()), "media")
            .unwrap();
    }

    #[test]
    fn put_get_list_and_delete_object_roundtrip() {
        let service = service();
        let auth = auth();
        service
            .create_bucket(&auth, TenantId("tenant-alpha".to_string()), "media")
            .unwrap();

        let response = service
            .put_object(
                &auth,
                PutObjectRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    bucket: "media".to_string(),
                    key: "folder/object.bin".to_string(),
                    access_profile: AccessProfile::PublicCiphertext,
                    payload_plaintext: false,
                    content_type: "application/octet-stream".to_string(),
                    encryption_profile_id: EncryptionProfileId("profile-e2ee".to_string()),
                    key_policy_id: KeyPolicyId("policy-default".to_string()),
                    metadata_visibility: VisibilityMode::Split,
                    content_encryption_suite: "XChaCha20-Poly1305".to_string(),
                    key_wrapping_suite: "HPKE/X25519".to_string(),
                    wrapped_object_keys: vec![wrapped_key()],
                    server_visible_metadata: BTreeMap::from([(
                        "cache-control".to_string(),
                        "max-age=60".to_string(),
                    )]),
                    encrypted_client_metadata: BTreeMap::new(),
                    storage_class: DEFAULT_STORAGE_CLASS.to_string(),
                    idempotency_key: "put-1".to_string(),
                },
                b"ciphertext-object-data",
            )
            .unwrap();
        assert!(!response.object_cid.is_empty());

        let head = service
            .head_object(
                &auth,
                HeadObjectRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    bucket: "media".to_string(),
                    key: "folder/object.bin".to_string(),
                },
            )
            .unwrap();
        assert_eq!(head.content_length, 22);

        let get = service
            .get_object(
                &auth,
                GetObjectRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    bucket: Some("media".to_string()),
                    key: Some("folder/object.bin".to_string()),
                    cid: None,
                    access_profile: AccessProfile::PublicCiphertext,
                    prefer_plaintext: false,
                    range: None,
                    if_match: None,
                    if_none_match: None,
                },
            )
            .unwrap();
        assert_eq!(get.body, b"ciphertext-object-data");

        let listed = service
            .list_objects(
                &auth,
                ListObjectsRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    bucket: "media".to_string(),
                    prefix: Some("folder".to_string()),
                    continuation_token: None,
                    limit: Some(100),
                },
            )
            .unwrap();
        assert_eq!(listed.items.len(), 1);
        assert_eq!(listed.items[0].key, "folder/object.bin");

        let deleted = service
            .delete_object(
                &auth,
                DeleteObjectRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    bucket: "media".to_string(),
                    key: "folder/object.bin".to_string(),
                    idempotency_key: "delete-1".to_string(),
                },
            )
            .unwrap();
        assert!(deleted.tombstone);
    }

    #[test]
    fn multipart_upload_roundtrip() {
        let service = service();
        let auth = auth();
        service
            .create_bucket(&auth, TenantId("tenant-alpha".to_string()), "media")
            .unwrap();

        let created = service
            .create_multipart_upload(
                &auth,
                CreateMultipartUploadRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    bucket: "media".to_string(),
                    key: "multipart.bin".to_string(),
                    access_profile: AccessProfile::PublicCiphertext,
                    payload_plaintext: false,
                    content_type: "application/octet-stream".to_string(),
                    encryption_profile_id: EncryptionProfileId("profile-e2ee".to_string()),
                    key_policy_id: KeyPolicyId("policy-default".to_string()),
                    metadata_visibility: VisibilityMode::Split,
                    content_encryption_suite: "XChaCha20-Poly1305".to_string(),
                    key_wrapping_suite: "HPKE/X25519".to_string(),
                    wrapped_object_keys: vec![wrapped_key()],
                    server_visible_metadata: BTreeMap::new(),
                    encrypted_client_metadata: BTreeMap::new(),
                    storage_class: DEFAULT_STORAGE_CLASS.to_string(),
                    idempotency_key: "multipart-1".to_string(),
                },
            )
            .unwrap();

        let part1 = service
            .upload_part(
                &auth,
                UploadPartRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    upload_id: created.upload_id.clone(),
                    part_number: 1,
                },
                b"cipher",
            )
            .unwrap();
        let part2 = service
            .upload_part(
                &auth,
                UploadPartRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    upload_id: created.upload_id.clone(),
                    part_number: 2,
                },
                b"text",
            )
            .unwrap();

        let complete = service
            .complete_multipart_upload(
                &auth,
                CompleteMultipartUploadRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    upload_id: created.upload_id,
                    parts: vec![
                        CompletedMultipartPart {
                            part_number: 1,
                            etag: part1.etag,
                        },
                        CompletedMultipartPart {
                            part_number: 2,
                            etag: part2.etag,
                        },
                    ],
                },
            )
            .unwrap();
        assert_eq!(complete.key, "multipart.bin");

        let get = service
            .get_object(
                &auth,
                GetObjectRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    bucket: Some("media".to_string()),
                    key: Some("multipart.bin".to_string()),
                    cid: None,
                    access_profile: AccessProfile::PublicCiphertext,
                    prefer_plaintext: false,
                    range: None,
                    if_match: None,
                    if_none_match: None,
                },
            )
            .unwrap();
        assert_eq!(get.body, b"ciphertext");
    }

    #[test]
    fn edge_token_auth_roundtrip() {
        let service = service();
        let token = service
            .mint_edge_token(&EdgeTokenClaims {
                tenant_id: TenantId("tenant-alpha".to_string()),
                bucket: Some("media".to_string()),
                key: Some("object.bin".to_string()),
                cid: None,
                access_profile: AccessProfile::PublicCiphertext,
                method: "GET".to_string(),
                exp: now_ms() + 60_000,
            })
            .unwrap();
        let auth = service.authenticate_edge_token(&token).unwrap();
        assert_eq!(auth.claims.tenant_id.0, "tenant-alpha");
        assert_eq!(auth.claims.ops, vec![CapabilityScope::Read]);
    }

    #[test]
    fn sigv4_signature_derivation_is_stable() {
        let signature = sigv4_signature(
            "secret",
            "20260420",
            "auto",
            "s3",
            "AWS4-HMAC-SHA256\n20260420T101112Z\n20260420/auto/s3/aws4_request\nabc",
        )
        .unwrap();
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn trusted_edge_plaintext_roundtrip_works_when_profile_enabled() {
        let service = service();
        let auth = auth();
        service
            .create_bucket(&auth, TenantId("tenant-alpha".to_string()), "media")
            .unwrap();

        let put = service
            .put_object(
                &auth,
                PutObjectRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    bucket: "media".to_string(),
                    key: "trusted/plain.txt".to_string(),
                    access_profile: AccessProfile::TrustedEdgeV1,
                    payload_plaintext: true,
                    content_type: "text/plain".to_string(),
                    encryption_profile_id: EncryptionProfileId("profile-e2ee".to_string()),
                    key_policy_id: KeyPolicyId("policy-default".to_string()),
                    metadata_visibility: VisibilityMode::Split,
                    content_encryption_suite: "XChaCha20-Poly1305".to_string(),
                    key_wrapping_suite: "HPKE/X25519".to_string(),
                    wrapped_object_keys: Vec::new(),
                    server_visible_metadata: BTreeMap::new(),
                    encrypted_client_metadata: BTreeMap::new(),
                    storage_class: DEFAULT_STORAGE_CLASS.to_string(),
                    idempotency_key: "trusted-put".to_string(),
                },
                b"hello-trusted-edge",
            )
            .unwrap();
        assert!(!put.object_cid.is_empty());

        let get_plain = service
            .get_object(
                &auth,
                GetObjectRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    bucket: Some("media".to_string()),
                    key: Some("trusted/plain.txt".to_string()),
                    cid: None,
                    access_profile: AccessProfile::TrustedEdgeV1,
                    prefer_plaintext: true,
                    range: None,
                    if_match: None,
                    if_none_match: None,
                },
            )
            .unwrap();
        assert_eq!(get_plain.body, b"hello-trusted-edge");
    }

    #[test]
    fn public_read_acl_allows_read_without_explicit_read_scope() {
        let service = service();
        let admin = auth();
        service
            .create_bucket(&admin, TenantId("tenant-alpha".to_string()), "media")
            .unwrap();
        service
            .put_object(
                &admin,
                PutObjectRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    bucket: "media".to_string(),
                    key: "acl/object.bin".to_string(),
                    access_profile: AccessProfile::PublicCiphertext,
                    payload_plaintext: false,
                    content_type: "application/octet-stream".to_string(),
                    encryption_profile_id: EncryptionProfileId("profile-e2ee".to_string()),
                    key_policy_id: KeyPolicyId("policy-default".to_string()),
                    metadata_visibility: VisibilityMode::Split,
                    content_encryption_suite: "XChaCha20-Poly1305".to_string(),
                    key_wrapping_suite: "HPKE/X25519".to_string(),
                    wrapped_object_keys: vec![wrapped_key()],
                    server_visible_metadata: BTreeMap::new(),
                    encrypted_client_metadata: BTreeMap::new(),
                    storage_class: DEFAULT_STORAGE_CLASS.to_string(),
                    idempotency_key: "acl-put".to_string(),
                },
                b"ciphertext-object",
            )
            .unwrap();
        service
            .put_bucket_acl(
                &admin,
                TenantId("tenant-alpha".to_string()),
                "media",
                CannedAcl::PublicRead,
            )
            .unwrap();

        let reader = write_only_auth();
        let head = service
            .head_bucket(&reader, TenantId("tenant-alpha".to_string()), "media")
            .unwrap();
        assert_eq!(head.bucket, "media");
    }

    #[test]
    fn legal_hold_blocks_delete() {
        let service = service();
        let auth = auth();
        service
            .create_bucket(&auth, TenantId("tenant-alpha".to_string()), "media")
            .unwrap();
        service
            .put_object(
                &auth,
                PutObjectRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    bucket: "media".to_string(),
                    key: "lock/object.bin".to_string(),
                    access_profile: AccessProfile::PublicCiphertext,
                    payload_plaintext: false,
                    content_type: "application/octet-stream".to_string(),
                    encryption_profile_id: EncryptionProfileId("profile-e2ee".to_string()),
                    key_policy_id: KeyPolicyId("policy-default".to_string()),
                    metadata_visibility: VisibilityMode::Split,
                    content_encryption_suite: "XChaCha20-Poly1305".to_string(),
                    key_wrapping_suite: "HPKE/X25519".to_string(),
                    wrapped_object_keys: vec![wrapped_key()],
                    server_visible_metadata: BTreeMap::new(),
                    encrypted_client_metadata: BTreeMap::new(),
                    storage_class: DEFAULT_STORAGE_CLASS.to_string(),
                    idempotency_key: "lock-put".to_string(),
                },
                b"ciphertext",
            )
            .unwrap();
        service
            .put_object_legal_hold(
                &auth,
                TenantId("tenant-alpha".to_string()),
                "media",
                "lock/object.bin",
                true,
            )
            .unwrap();

        let error = service
            .delete_object(
                &auth,
                DeleteObjectRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    bucket: "media".to_string(),
                    key: "lock/object.bin".to_string(),
                    idempotency_key: "lock-del".to_string(),
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "legal_hold_active");
    }

    #[test]
    fn bucket_name_rejects_percent_decoded_slash() {
        let service = service();
        let auth = auth();
        let error = service
            .create_bucket(
                &auth,
                TenantId("tenant-alpha".to_string()),
                "media%2Fpublic",
            )
            .unwrap_err();
        assert_eq!(error.code, "invalid_bucket");
    }

    #[test]
    fn store_paths_do_not_collapse_distinct_keys() {
        let service = service();
        let tenant = TenantId("tenant-alpha".to_string());
        let slash = service.store_path(&tenant, ACL_STORE, "object-media-a/b");
        let underscore = service.store_path(&tenant, ACL_STORE, "object-media-a_b");
        assert_ne!(slash, underscore);
    }

    #[test]
    fn stale_header_sigv4_request_is_rejected() {
        let service = service();
        register_sigv4_key(&service);
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("s3.example.test"));
        headers.insert("x-amz-date", HeaderValue::from_static("20000101T000000Z"));
        headers.insert(
            "authorization",
            HeaderValue::from_static(
                "AWS4-HMAC-SHA256 Credential=AKIA_TEST/20000101/auto/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=deadbeef",
            ),
        );
        let error = service
            .authenticate_sigv4(&HttpRequestBinding {
                method: "GET",
                raw_path: "/media/object.bin",
                raw_query: "",
                headers: &headers,
                body: b"",
            })
            .unwrap_err();
        assert_eq!(error.code, "invalid_sigv4");
        assert!(error.message.contains("allowed clock skew"));
    }

    #[test]
    fn duplicate_presign_parameter_is_rejected() {
        let service = service();
        register_sigv4_key(&service);
        let headers = HeaderMap::new();
        let error = service
            .authenticate_sigv4(&HttpRequestBinding {
                method: "GET",
                raw_path: "/media/object.bin",
                raw_query: "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA_TEST/20260423/auto/s3/aws4_request&X-Amz-SignedHeaders=host&X-Amz-Signature=abc&X-Amz-Date=20260423T101112Z&X-Amz-Date=20260423T101113Z&X-Amz-Expires=30",
                headers: &headers,
                body: b"",
            })
            .unwrap_err();
        assert_eq!(error.code, "invalid_presign");
        assert!(error.message.contains("duplicate query parameter"));
    }

    #[test]
    fn duplicate_signed_header_is_rejected() {
        let service = service();
        register_sigv4_key(&service);
        let request_date = amz_date_from_epoch_ms(now_ms());
        let scope_date = &request_date[..8];
        let mut headers = HeaderMap::new();
        headers.append("host", HeaderValue::from_static("s3.example.test"));
        headers.append("host", HeaderValue::from_static("shadow.example.test"));
        headers.insert("x-amz-date", HeaderValue::from_str(&request_date).unwrap());
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!(
                "AWS4-HMAC-SHA256 Credential=AKIA_TEST/{scope_date}/auto/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=deadbeef"
            ))
            .unwrap(),
        );
        let error = service
            .authenticate_sigv4(&HttpRequestBinding {
                method: "GET",
                raw_path: "/media/object.bin",
                raw_query: "",
                headers: &headers,
                body: b"",
            })
            .unwrap_err();
        assert_eq!(error.code, "invalid_sigv4");
        assert!(error.message.contains("duplicate signed header"));
    }
}
