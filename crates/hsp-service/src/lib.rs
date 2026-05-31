use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hsp_auth::{
    denial_to_api_error, verify_signed_namespace_record, AuthContext, AuthRequestMeta,
    AuthorizationDecision, DenialReason, IssuerRegistry, PolicyEngine, ReplayStatus,
};
use hsp_core::{
    cid_from_bytes, public_multitenant_bootstrap_document, public_multitenant_info_response,
    public_multitenant_settings_frame, ApiError, ApiErrorCategory, BindRequest, BindResponse,
    BootstrapDocument, EventCursor, EventRecord, EventType, GetChunk, GetChunkDescriptor,
    GetPreference, GetRequest, GetResponse, GetResponseMeta, HeadRequest, HeadResponse,
    InfoResponse, ListCursor, ListItem, ListRequest, ListResponse, Manifest, NamespaceMutationKind,
    NamespaceMutationRecord, NoticeFrame, ObjectSelectorKind, OperationName, PutChunkRequest,
    PutChunkResponse, PutCommitRequest, PutCommitResponse, PutInitRequest, PutInitResponse,
    ReadinessReport, ResolveRequest, ResolveResponse, SettingsFrame, SubscribeEnvelope,
    SubscribeEnvelopeKind, SubscribeFilter, SubscribeRequest, TenantId, UnbindRequest,
    UnbindResponse,
};
use hsp_crypto::{
    crypto_error_to_api, required_runtime_secret_from_env, LocalDevKms, StoredEnvelope,
    DEFAULT_KMS_SEED_LITERALS,
};
use hsp_path::canonical_path;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlphaConfig {
    pub authority: String,
    pub gateway_base_url: String,
    pub root_dir: PathBuf,
    pub native_port: u16,
    pub server_instance_id: String,
}

#[derive(Debug)]
pub struct AlphaService {
    config: AlphaConfig,
    kms: LocalDevKms,
    policy_engine: PolicyEngine,
    issuer_registry: Option<IssuerRegistry>,
    observability: ObservabilityState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceMetricEntry {
    pub operation: String,
    pub tenant_id: String,
    pub namespace: Option<String>,
    pub status_code: u16,
    pub outcome: String,
    pub count: u64,
    pub latency_ms_sum: u64,
    pub object_size_bytes_sum: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceMetricSnapshot {
    pub entries: Vec<ServiceMetricEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredLogRecord {
    pub at_ms: u64,
    pub operation: String,
    pub tenant_id: String,
    pub namespace: Option<String>,
    pub status_code: u16,
    pub outcome: String,
    pub latency_ms: u64,
    pub object_size_bytes: Option<u64>,
    pub error_code: Option<String>,
}

#[derive(Debug, Default)]
struct ObservabilityState {
    metrics: Mutex<BTreeMap<MetricKey, MetricValue>>,
    logs: Mutex<Vec<StructuredLogRecord>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MetricKey {
    operation: String,
    tenant_id: String,
    namespace: Option<String>,
    status_code: u16,
    outcome: String,
}

#[derive(Debug, Clone, Default)]
struct MetricValue {
    count: u64,
    latency_ms_sum: u64,
    object_size_bytes_sum: u64,
}

struct Observation<'a> {
    operation: &'a str,
    tenant_id: &'a TenantId,
    namespace: Option<&'a str>,
    status_code: u16,
    outcome: &'a str,
    latency_ms: u64,
    object_size_bytes: Option<u64>,
    error_code: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UploadSessionRecord {
    session_id: String,
    tenant_id: TenantId,
    manifest: Manifest,
    manifest_cid: String,
    idempotency_key: String,
    storage_class: String,
    atomic_bind: Option<hsp_core::AtomicBindRequest>,
    uploaded_chunks: Vec<u32>,
    committed: bool,
    created_at_ms: u64,
    upload_deadline_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManifestRecord {
    tenant_id: TenantId,
    manifest: Manifest,
    manifest_cid: String,
    object_cid: String,
    storage_class: String,
    committed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IdempotencyRecord<T> {
    response: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReplayRecord {
    tenant_id: TenantId,
    jti: String,
    operation: String,
    subject: String,
    idempotency_key: String,
    observed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AuditRecord {
    seq: u64,
    tenant_id: TenantId,
    operation: String,
    subject: String,
    at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SequenceState {
    next_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NamespaceBindingState {
    path: String,
    target_cid: Option<String>,
    manifest_cid: Option<String>,
    revision: u64,
    record_cid: String,
    metadata: BTreeMap<String, String>,
    tombstone: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NamespaceCurrentState {
    namespace: String,
    revision: u64,
    bindings: BTreeMap<String, NamespaceBindingState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NamespaceRevisionState {
    next_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NamespaceJournalEntry {
    revision: u64,
    record: NamespaceMutationRecord,
    record_cid: String,
    target_cid: Option<String>,
    manifest_cid: Option<String>,
    metadata: BTreeMap<String, String>,
    tombstone: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectorResolution {
    manifest_cid: String,
    namespace: Option<String>,
    path: Option<String>,
    revision: Option<u64>,
    record_cid: Option<String>,
}

impl AlphaService {
    pub fn new(config: AlphaConfig, kms: LocalDevKms) -> Result<Self, ApiError> {
        let service = Self {
            config,
            kms,
            policy_engine: PolicyEngine::new(),
            issuer_registry: None,
            observability: ObservabilityState::default(),
        };

        service.ensure_store_roots()?;
        Ok(service)
    }

    pub fn with_issuer_registry(mut self, issuer_registry: IssuerRegistry) -> Self {
        self.issuer_registry = Some(issuer_registry);
        self
    }

    pub fn bootstrap_document(&self) -> BootstrapDocument {
        let mut document = public_multitenant_bootstrap_document(
            &self.config.authority,
            &self.config.gateway_base_url,
        );
        document.native.port = self.config.native_port;
        document
    }

    pub fn info(&self) -> InfoResponse {
        public_multitenant_info_response()
    }

    pub fn settings(&self) -> SettingsFrame {
        public_multitenant_settings_frame(self.config.server_instance_id.clone())
    }

    pub fn readiness(&self) -> ReadinessReport {
        ReadinessReport {
            ready: self.config.root_dir.exists(),
            kms_provider: "local-dev-kms".to_string(),
            encrypted_store_roots: vec![
                "chunks".to_string(),
                "manifests".to_string(),
                "namespace-current".to_string(),
                "namespace-journal".to_string(),
                "namespace-revisions".to_string(),
                "sessions".to_string(),
                "audit".to_string(),
                "idempotency".to_string(),
                "replay".to_string(),
                "events".to_string(),
            ],
        }
    }

    pub fn metrics_snapshot(&self) -> ServiceMetricSnapshot {
        let entries = self
            .observability
            .metrics
            .lock()
            .expect("metrics lock poisoned")
            .iter()
            .map(|(key, value)| ServiceMetricEntry {
                operation: key.operation.clone(),
                tenant_id: key.tenant_id.clone(),
                namespace: key.namespace.clone(),
                status_code: key.status_code,
                outcome: key.outcome.clone(),
                count: value.count,
                latency_ms_sum: value.latency_ms_sum,
                object_size_bytes_sum: value.object_size_bytes_sum,
            })
            .collect();
        ServiceMetricSnapshot { entries }
    }

    pub fn structured_logs(&self) -> Vec<StructuredLogRecord> {
        self.observability
            .logs
            .lock()
            .expect("structured logs lock poisoned")
            .clone()
    }

    pub fn prometheus_metrics(&self) -> String {
        let snapshot = self.metrics_snapshot();
        let mut output = String::from(
            "# HELP hsp_requests_total HSP requests by operation, tenant, namespace, status, and outcome.\n\
             # TYPE hsp_requests_total counter\n",
        );
        for entry in &snapshot.entries {
            let labels = prometheus_labels(entry);
            output.push_str(&format!("hsp_requests_total{{{labels}}} {}\n", entry.count));
        }
        output.push_str(
            "# HELP hsp_request_latency_ms_sum Total observed HSP request latency in milliseconds.\n\
             # TYPE hsp_request_latency_ms_sum counter\n",
        );
        for entry in &snapshot.entries {
            let labels = prometheus_labels(entry);
            output.push_str(&format!(
                "hsp_request_latency_ms_sum{{{labels}}} {}\n",
                entry.latency_ms_sum
            ));
        }
        output.push_str(
            "# HELP hsp_object_size_bytes_sum Total observed HSP object or chunk size in bytes.\n\
             # TYPE hsp_object_size_bytes_sum counter\n",
        );
        for entry in &snapshot.entries {
            let labels = prometheus_labels(entry);
            output.push_str(&format!(
                "hsp_object_size_bytes_sum{{{labels}}} {}\n",
                entry.object_size_bytes_sum
            ));
        }
        output
    }

    pub fn put_init(
        &self,
        auth: &AuthContext,
        request: PutInitRequest,
    ) -> Result<PutInitResponse, ApiError> {
        let started_at_ms = now_ms();
        request.manifest.validate()?;

        if request.manifest.tenant_id != request.tenant_id {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "manifest_tenant_mismatch",
                "manifest tenant_id must match request tenant_id",
            ));
        }

        if request.manifest.encryption_descriptor.key_policy_id != request.key_policy_id {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "manifest_key_policy_mismatch",
                "manifest encryption descriptor key_policy_id must match PUT_INIT key_policy_id",
            ));
        }

        if request.manifest.encryption_descriptor.encryption_profile_id
            != request.encryption_profile_id
        {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "manifest_encryption_profile_mismatch",
                "manifest encryption descriptor encryption_profile_id must match PUT_INIT encryption_profile_id",
            ));
        }

        if request.manifest.encryption_descriptor.metadata_visibility != request.metadata_visibility
        {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "manifest_visibility_mismatch",
                "manifest metadata_visibility must match PUT_INIT metadata_visibility",
            ));
        }

        let manifest_cid = request.manifest.manifest_cid();
        let meta = AuthRequestMeta {
            operation: OperationName::PutInit,
            tenant_id: &request.tenant_id,
            subject: &manifest_cid,
            namespace: request
                .atomic_bind
                .as_ref()
                .map(|bind| bind.namespace.as_str()),
            path: request.atomic_bind.as_ref().map(|bind| bind.path.as_str()),
            content_size: Some(request.manifest.stored_size),
            key_policy_id: Some(&request.key_policy_id),
            encryption_profile_id: Some(&request.encryption_profile_id),
            metadata_visibility: Some(request.metadata_visibility),
            idempotency_key: Some(&request.idempotency_key),
        };
        let decision = self.authorize(auth, &meta)?;

        let idempotency_key =
            self.idempotency_key(&request.tenant_id, "put_init", &request.idempotency_key);
        if decision.replay_status == ReplayStatus::IdempotentRetry {
            if let Some(record) = self.read_encrypted_json::<IdempotencyRecord<PutInitResponse>>(
                &request.tenant_id,
                "idempotency",
                &idempotency_key,
            )? {
                self.record_observation(Observation {
                    operation: "put_init",
                    tenant_id: &request.tenant_id,
                    namespace: request
                        .atomic_bind
                        .as_ref()
                        .map(|bind| bind.namespace.as_str()),
                    status_code: 200,
                    outcome: "idempotent_retry",
                    latency_ms: elapsed_ms(started_at_ms),
                    object_size_bytes: Some(request.manifest.stored_size),
                    error_code: None,
                });
                return Ok(record.response);
            }
        }

        let missing_chunks = request
            .manifest
            .chunk_refs
            .iter()
            .filter(|chunk| !self.chunk_exists(&request.tenant_id, &chunk.cid))
            .map(|chunk| chunk.chunk_index)
            .collect::<Vec<_>>();

        let session_record = UploadSessionRecord {
            session_id: format!("session-{}", manifest_cid),
            tenant_id: request.tenant_id.clone(),
            manifest: request.manifest.clone(),
            manifest_cid: manifest_cid.clone(),
            idempotency_key: request.idempotency_key.clone(),
            storage_class: request.storage_class.clone(),
            atomic_bind: request.atomic_bind.clone(),
            uploaded_chunks: Vec::new(),
            committed: false,
            created_at_ms: now_ms(),
            upload_deadline_ms: now_ms() + 15 * 60 * 1000,
        };
        self.write_encrypted_json(
            &request.tenant_id,
            "sessions",
            &session_record.session_id,
            &session_record,
        )?;

        let response = PutInitResponse {
            session_id: session_record.session_id.clone(),
            missing_chunks,
            accepted_manifest_cid: manifest_cid,
            upload_deadline_ms: session_record.upload_deadline_ms,
            max_parallel_chunk_streams: self.info().limits.max_parallel_chunk_streams,
        };

        self.write_encrypted_json(
            &request.tenant_id,
            "idempotency",
            &idempotency_key,
            &IdempotencyRecord {
                response: response.clone(),
            },
        )?;

        self.record_observation(Observation {
            operation: "put_init",
            tenant_id: &request.tenant_id,
            namespace: request
                .atomic_bind
                .as_ref()
                .map(|bind| bind.namespace.as_str()),
            status_code: 200,
            outcome: "ok",
            latency_ms: elapsed_ms(started_at_ms),
            object_size_bytes: Some(request.manifest.stored_size),
            error_code: None,
        });
        Ok(response)
    }

    pub fn put_chunk(
        &self,
        auth: &AuthContext,
        request: PutChunkRequest,
        ciphertext_chunk: &[u8],
    ) -> Result<PutChunkResponse, ApiError> {
        let started_at_ms = now_ms();
        let chunk_cid = hsp_core::cid_from_bytes(ciphertext_chunk);
        if chunk_cid != request.chunk_cid {
            self.record_observation(Observation {
                operation: "integrity_error",
                tenant_id: &request.tenant_id,
                namespace: None,
                status_code: 400,
                outcome: "integrity_error",
                latency_ms: elapsed_ms(started_at_ms),
                object_size_bytes: Some(ciphertext_chunk.len() as u64),
                error_code: Some("chunk_cid_mismatch"),
            });
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "chunk_cid_mismatch",
                "chunk ciphertext CID does not match request.chunk_cid",
            ));
        }

        let session = self
            .read_encrypted_json::<UploadSessionRecord>(
                &request.tenant_id,
                "sessions",
                &request.session_id,
            )?
            .ok_or_else(|| {
                ApiError::new(
                    ApiErrorCategory::NotFound,
                    "upload_session_not_found",
                    "upload session not found",
                )
            })?;

        if session.committed {
            return Err(ApiError::new(
                ApiErrorCategory::Conflict,
                "upload_session_already_committed",
                "upload session is already committed",
            ));
        }

        let manifest_chunk = session
            .manifest
            .chunk_refs
            .iter()
            .find(|chunk| chunk.chunk_index == request.chunk_index)
            .ok_or_else(|| {
                ApiError::new(
                    ApiErrorCategory::Validation,
                    "unknown_chunk_index",
                    "chunk_index is not present in the upload session manifest",
                )
            })?;

        if manifest_chunk.cid != request.chunk_cid
            || manifest_chunk.offset != request.chunk_offset
            || manifest_chunk.stored_len != request.chunk_length
        {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "chunk_descriptor_mismatch",
                "chunk descriptor does not match manifest chunk reference",
            ));
        }

        let chunk_subject = format!("{}:{}", request.session_id, request.chunk_index);
        let meta = AuthRequestMeta {
            operation: OperationName::PutChunk,
            tenant_id: &request.tenant_id,
            subject: &chunk_subject,
            namespace: None,
            path: None,
            content_size: Some(request.chunk_length),
            key_policy_id: Some(&session.manifest.encryption_descriptor.key_policy_id),
            encryption_profile_id: Some(
                &session.manifest.encryption_descriptor.encryption_profile_id,
            ),
            metadata_visibility: None,
            idempotency_key: None,
        };
        self.authorize(auth, &meta)?;

        let duplicate = self.chunk_exists(&request.tenant_id, &request.chunk_cid);
        if !duplicate {
            self.write_encrypted_bytes(
                &request.tenant_id,
                "chunks",
                &request.chunk_cid,
                ciphertext_chunk,
            )?;
        }

        let mut updated = session.clone();
        if !updated.uploaded_chunks.contains(&request.chunk_index) {
            updated.uploaded_chunks.push(request.chunk_index);
            updated.uploaded_chunks.sort_unstable();
        }
        self.write_encrypted_json(
            &request.tenant_id,
            "sessions",
            &request.session_id,
            &updated,
        )?;

        let response = PutChunkResponse {
            stored: !duplicate,
            duplicate,
            verified_cid: true,
        };
        self.record_observation(Observation {
            operation: "put_chunk",
            tenant_id: &request.tenant_id,
            namespace: None,
            status_code: 200,
            outcome: if duplicate { "duplicate" } else { "ok" },
            latency_ms: elapsed_ms(started_at_ms),
            object_size_bytes: Some(ciphertext_chunk.len() as u64),
            error_code: None,
        });
        Ok(response)
    }

    pub fn put_commit(
        &self,
        auth: &AuthContext,
        request: PutCommitRequest,
    ) -> Result<PutCommitResponse, ApiError> {
        let started_at_ms = now_ms();
        let session = self
            .read_encrypted_json::<UploadSessionRecord>(
                &request.tenant_id,
                "sessions",
                &request.session_id,
            )?
            .ok_or_else(|| {
                ApiError::new(
                    ApiErrorCategory::NotFound,
                    "upload_session_not_found",
                    "upload session not found",
                )
            })?;

        if session.manifest_cid != request.manifest_cid {
            return Err(ApiError::new(
                ApiErrorCategory::Conflict,
                "manifest_cid_mismatch",
                "request manifest_cid does not match upload session manifest",
            ));
        }

        let meta = AuthRequestMeta {
            operation: OperationName::PutCommit,
            tenant_id: &request.tenant_id,
            subject: &request.session_id,
            namespace: session
                .atomic_bind
                .as_ref()
                .map(|bind| bind.namespace.as_str()),
            path: session.atomic_bind.as_ref().map(|bind| bind.path.as_str()),
            content_size: Some(session.manifest.stored_size),
            key_policy_id: Some(&session.manifest.encryption_descriptor.key_policy_id),
            encryption_profile_id: Some(
                &session.manifest.encryption_descriptor.encryption_profile_id,
            ),
            metadata_visibility: None,
            idempotency_key: Some(&request.idempotency_key),
        };
        let decision = self.authorize(auth, &meta)?;

        let idempotency_key =
            self.idempotency_key(&request.tenant_id, "put_commit", &request.idempotency_key);
        if decision.replay_status == ReplayStatus::IdempotentRetry {
            if let Some(record) = self.read_encrypted_json::<IdempotencyRecord<PutCommitResponse>>(
                &request.tenant_id,
                "idempotency",
                &idempotency_key,
            )? {
                self.record_observation(Observation {
                    operation: "put",
                    tenant_id: &request.tenant_id,
                    namespace: session
                        .atomic_bind
                        .as_ref()
                        .map(|bind| bind.namespace.as_str()),
                    status_code: 200,
                    outcome: "idempotent_retry",
                    latency_ms: elapsed_ms(started_at_ms),
                    object_size_bytes: Some(session.manifest.stored_size),
                    error_code: None,
                });
                return Ok(record.response);
            }
        }

        for chunk_ref in &session.manifest.chunk_refs {
            if !self.chunk_exists(&request.tenant_id, &chunk_ref.cid) {
                return Err(ApiError::new(
                    ApiErrorCategory::Conflict,
                    "missing_chunk",
                    format!("missing ciphertext chunk {}", chunk_ref.cid),
                ));
            }
        }

        let manifest_record = ManifestRecord {
            tenant_id: request.tenant_id.clone(),
            manifest: session.manifest.clone(),
            manifest_cid: session.manifest_cid.clone(),
            object_cid: session.manifest_cid.clone(),
            storage_class: session.storage_class.clone(),
            committed_at_ms: now_ms(),
        };
        self.write_encrypted_json(
            &request.tenant_id,
            "manifests",
            &manifest_record.manifest_cid,
            &manifest_record,
        )?;

        if let Some(atomic_bind) = &session.atomic_bind {
            let bind_request = BindRequest {
                tenant_id: request.tenant_id.clone(),
                namespace: atomic_bind.namespace.clone(),
                path: atomic_bind.path.clone(),
                target_cid: manifest_record.object_cid.clone(),
                if_revision: atomic_bind.if_revision,
                if_absent: atomic_bind.if_revision.is_none(),
                metadata: atomic_bind.metadata.clone(),
                ttl_ms: atomic_bind.ttl_ms,
                idempotency_key: request.idempotency_key.clone(),
                signed_record_b64: atomic_bind.signed_record_b64.clone(),
            };
            if let Err(error) = self.bind_internal(auth, bind_request, false) {
                let _ = self.delete_store_key(
                    &request.tenant_id,
                    "manifests",
                    &manifest_record.manifest_cid,
                );
                return Err(error);
            }
        }

        let seq = self.append_event(
            &request.tenant_id,
            EventRecord {
                version: 1,
                seq: 0,
                at_ms: now_ms(),
                event_type: EventType::ObjectCommitted,
                subject_kind: "object".to_string(),
                namespace: session
                    .atomic_bind
                    .as_ref()
                    .map(|bind| bind.namespace.clone()),
                path: session.atomic_bind.as_ref().map(|bind| bind.path.clone()),
                cid: Some(manifest_record.object_cid.clone()),
                revision: None,
                trace_id: None,
                payload: BTreeMap::from([
                    ("session_id".to_string(), request.session_id.clone()),
                    (
                        "manifest_cid".to_string(),
                        manifest_record.manifest_cid.clone(),
                    ),
                ]),
            },
        )?;
        self.write_audit(
            &request.tenant_id,
            seq,
            OperationName::PutCommit.as_str(),
            &request.session_id,
        )?;

        let mut updated_session = session.clone();
        updated_session.committed = true;
        self.write_encrypted_json(
            &request.tenant_id,
            "sessions",
            &request.session_id,
            &updated_session,
        )?;

        let response = PutCommitResponse {
            object_cid: manifest_record.object_cid.clone(),
            committed: true,
            event_seq: seq,
        };
        self.write_encrypted_json(
            &request.tenant_id,
            "idempotency",
            &idempotency_key,
            &IdempotencyRecord {
                response: response.clone(),
            },
        )?;

        self.record_observation(Observation {
            operation: "put",
            tenant_id: &request.tenant_id,
            namespace: session
                .atomic_bind
                .as_ref()
                .map(|bind| bind.namespace.as_str()),
            status_code: 200,
            outcome: "ok",
            latency_ms: elapsed_ms(started_at_ms),
            object_size_bytes: Some(session.manifest.stored_size),
            error_code: None,
        });
        Ok(response)
    }

    pub fn head(&self, auth: &AuthContext, request: HeadRequest) -> Result<HeadResponse, ApiError> {
        let started_at_ms = now_ms();
        request.selector.validate()?;
        let resolution = self.selector_resolution(&request.tenant_id, &request.selector)?;
        let manifest_cid = resolution.manifest_cid.clone();
        let meta = AuthRequestMeta {
            operation: OperationName::Head,
            tenant_id: &request.tenant_id,
            subject: &manifest_cid,
            namespace: resolution.namespace.as_deref(),
            path: resolution.path.as_deref(),
            content_size: None,
            key_policy_id: None,
            encryption_profile_id: None,
            metadata_visibility: None,
            idempotency_key: None,
        };
        self.authorize(auth, &meta)?;

        let record = self.manifest_record(&request.tenant_id, &manifest_cid)?;
        let response = HeadResponse {
            exists: true,
            deleted: false,
            cid: record.object_cid.clone(),
            object_cid: record.object_cid.clone(),
            manifest_cid: record.manifest_cid.clone(),
            integrity_hash: record.object_cid.clone(),
            storage_class: record.storage_class.clone(),
            resolved_namespace: resolution.namespace,
            resolved_path: resolution.path,
            resolved_revision: resolution.revision,
            resolved_record_cid: resolution.record_cid,
            size_bytes: record.manifest.logical_size,
            ciphertext_size_bytes: record.manifest.stored_size,
            logical_size: record.manifest.logical_size,
            stored_size: record.manifest.stored_size,
            content_type: record.manifest.content_type.clone(),
            created_at_ms: record.manifest.created_at_ms,
            encryption_profile_id: record
                .manifest
                .encryption_descriptor
                .encryption_profile_id
                .clone(),
            key_policy_id: record.manifest.encryption_descriptor.key_policy_id.clone(),
            metadata_visibility: record.manifest.encryption_descriptor.metadata_visibility,
            server_visible_metadata: record
                .manifest
                .encryption_descriptor
                .server_visible_metadata
                .clone(),
            encrypted_client_metadata_redacted: !record
                .manifest
                .encryption_descriptor
                .encrypted_client_metadata
                .is_empty(),
        };
        self.record_observation(Observation {
            operation: "head",
            tenant_id: &request.tenant_id,
            namespace: response.resolved_namespace.as_deref(),
            status_code: 200,
            outcome: "ok",
            latency_ms: elapsed_ms(started_at_ms),
            object_size_bytes: Some(response.ciphertext_size_bytes),
            error_code: None,
        });

        Ok(response)
    }

    pub fn get(&self, auth: &AuthContext, request: GetRequest) -> Result<GetResponse, ApiError> {
        let started_at_ms = now_ms();
        request.selector.validate()?;
        if let Some(range) = &request.range {
            range.validate()?;
        }
        let resolution = self.selector_resolution(&request.tenant_id, &request.selector)?;
        let manifest_cid = resolution.manifest_cid.clone();
        let meta = AuthRequestMeta {
            operation: OperationName::Get,
            tenant_id: &request.tenant_id,
            subject: &manifest_cid,
            namespace: resolution.namespace.as_deref(),
            path: resolution.path.as_deref(),
            content_size: None,
            key_policy_id: None,
            encryption_profile_id: None,
            metadata_visibility: None,
            idempotency_key: None,
        };
        self.authorize(auth, &meta)?;

        let record = self.manifest_record(&request.tenant_id, &manifest_cid)?;
        let preference = request.preference.unwrap_or(GetPreference::ChunkStream);
        if preference == GetPreference::Raw {
            return Err(ApiError::new(
                ApiErrorCategory::Unsupported,
                "unsupported_preference",
                "raw GET is not supported in public E2EE beta",
            ));
        }

        let mut response = GetResponse {
            meta: GetResponseMeta {
                exists: true,
                deleted: false,
                cid: record.object_cid.clone(),
                object_cid: record.object_cid.clone(),
                manifest_cid: record.manifest_cid.clone(),
                integrity_hash: record.object_cid.clone(),
                storage_class: record.storage_class.clone(),
                resolved_namespace: resolution.namespace.clone(),
                resolved_path: resolution.path.clone(),
                resolved_revision: resolution.revision,
                resolved_record_cid: resolution.record_cid.clone(),
                size_bytes: record.manifest.logical_size,
                ciphertext_size_bytes: record.manifest.stored_size,
                logical_size: record.manifest.logical_size,
                stored_size: record.manifest.stored_size,
                content_type: record.manifest.content_type.clone(),
                created_at_ms: record.manifest.created_at_ms,
                encryption_profile_id: record
                    .manifest
                    .encryption_descriptor
                    .encryption_profile_id
                    .clone(),
                key_policy_id: record.manifest.encryption_descriptor.key_policy_id.clone(),
                metadata_visibility: record.manifest.encryption_descriptor.metadata_visibility,
                server_visible_metadata: record
                    .manifest
                    .encryption_descriptor
                    .server_visible_metadata
                    .clone(),
                encrypted_client_metadata_redacted: !record
                    .manifest
                    .encryption_descriptor
                    .encrypted_client_metadata
                    .is_empty(),
                preference,
                manifest: None,
                chunk_descriptors: Vec::new(),
            },
            chunks: Vec::new(),
        };

        if preference == GetPreference::ManifestOnly {
            response.meta.manifest = Some(record.manifest.clone());
            self.record_observation(Observation {
                operation: "get",
                tenant_id: &request.tenant_id,
                namespace: response.meta.resolved_namespace.as_deref(),
                status_code: 200,
                outcome: "manifest_only",
                latency_ms: elapsed_ms(started_at_ms),
                object_size_bytes: Some(response.meta.ciphertext_size_bytes),
                error_code: None,
            });
            return Ok(response);
        }

        let (range_start, range_end) = if let Some(range) = &request.range {
            if range.end >= record.manifest.logical_size {
                return Err(ApiError::new(
                    ApiErrorCategory::Validation,
                    "invalid_range",
                    "range end is outside object logical size",
                ));
            }
            (range.start, range.end)
        } else {
            (0, record.manifest.logical_size.saturating_sub(1))
        };

        for chunk_ref in &record.manifest.chunk_refs {
            let chunk_start = chunk_ref.offset;
            let chunk_end = chunk_ref
                .offset
                .saturating_add(chunk_ref.logical_len.saturating_sub(1));
            if chunk_end < range_start || chunk_start > range_end {
                continue;
            }

            let fragment_start = range_start.max(chunk_start);
            let fragment_end = range_end.min(chunk_end);
            let fragment_offset = fragment_start.saturating_sub(chunk_start);
            let fragment_length = fragment_end
                .saturating_sub(fragment_start)
                .saturating_add(1);
            let bytes = self
                .read_encrypted_bytes(&request.tenant_id, "chunks", &chunk_ref.cid)?
                .ok_or_else(|| {
                    ApiError::new(
                        ApiErrorCategory::NotFound,
                        "missing_chunk",
                        format!("missing ciphertext chunk {}", chunk_ref.cid),
                    )
                })?;

            let end_offset = (fragment_offset + fragment_length) as usize;
            let fragment = bytes
                .get(fragment_offset as usize..end_offset)
                .ok_or_else(|| {
                    ApiError::new(
                        ApiErrorCategory::Validation,
                        "invalid_range",
                        "requested chunk fragment does not match stored ciphertext length",
                    )
                })?;

            let descriptor = GetChunkDescriptor {
                chunk_index: chunk_ref.chunk_index,
                chunk_cid: chunk_ref.cid.clone(),
                chunk_offset: chunk_ref.offset,
                logical_range_start: fragment_start,
                logical_range_end: fragment_end,
                fragment_offset,
                fragment_length,
                content_encoding: chunk_ref.content_encoding.clone(),
            };
            response.meta.chunk_descriptors.push(descriptor.clone());
            response.chunks.push(GetChunk {
                descriptor,
                bytes: fragment.to_vec(),
            });
        }

        self.record_observation(Observation {
            operation: "get",
            tenant_id: &request.tenant_id,
            namespace: response.meta.resolved_namespace.as_deref(),
            status_code: 200,
            outcome: "chunk_stream",
            latency_ms: elapsed_ms(started_at_ms),
            object_size_bytes: Some(response.meta.ciphertext_size_bytes),
            error_code: None,
        });
        Ok(response)
    }

    pub fn resolve(
        &self,
        auth: &AuthContext,
        request: ResolveRequest,
    ) -> Result<ResolveResponse, ApiError> {
        let (namespace, path) =
            self.canonical_namespace_and_path(&request.namespace, &request.path)?;
        let subject = format!("{namespace}:{path}");
        let meta = AuthRequestMeta {
            operation: OperationName::Resolve,
            tenant_id: &request.tenant_id,
            subject: &subject,
            namespace: Some(&namespace),
            path: Some(&path),
            content_size: None,
            key_policy_id: None,
            encryption_profile_id: None,
            metadata_visibility: None,
            idempotency_key: None,
        };
        self.authorize(auth, &meta)?;

        let snapshot =
            self.namespace_snapshot_at(&request.tenant_id, &namespace, request.at_revision)?;
        let binding = snapshot.bindings.get(&path).ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::NotFound,
                "path_not_bound",
                "namespace path is not bound",
            )
        })?;
        if let Some(expected_revision) = request.if_revision {
            if binding.revision != expected_revision {
                return Err(ApiError::new(
                    ApiErrorCategory::Conflict,
                    "revision_conflict",
                    "namespace revision precondition failed",
                ));
            }
        }

        Ok(ResolveResponse {
            revision: binding.revision,
            target_cid: binding.target_cid.clone(),
            manifest_cid: binding.manifest_cid.clone(),
            record_cid: binding.record_cid.clone(),
            metadata: binding.metadata.clone(),
            tombstone: binding.tombstone,
        })
    }

    pub fn bind(&self, auth: &AuthContext, request: BindRequest) -> Result<BindResponse, ApiError> {
        self.bind_internal(auth, request, true)
    }

    pub fn unbind(
        &self,
        auth: &AuthContext,
        request: UnbindRequest,
    ) -> Result<UnbindResponse, ApiError> {
        self.unbind_internal(auth, request, true)
    }

    pub fn list(&self, auth: &AuthContext, request: ListRequest) -> Result<ListResponse, ApiError> {
        let namespace = canonical_path(&request.namespace).map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Validation,
                "invalid_namespace",
                error.to_string(),
            )
        })?;
        let prefix = request
            .prefix
            .as_deref()
            .map(|value| {
                canonical_path(value).map_err(|error| {
                    ApiError::new(
                        ApiErrorCategory::Validation,
                        "invalid_prefix",
                        error.to_string(),
                    )
                })
            })
            .transpose()?;

        let subject = format!("list:{namespace}");
        let meta = AuthRequestMeta {
            operation: OperationName::List,
            tenant_id: &request.tenant_id,
            subject: &subject,
            namespace: Some(&namespace),
            path: prefix.as_deref(),
            content_size: None,
            key_policy_id: None,
            encryption_profile_id: None,
            metadata_visibility: None,
            idempotency_key: None,
        };
        self.authorize(auth, &meta)?;

        let (snapshot_revision, last_path) = if let Some(cursor) = &request.cursor {
            let cursor = ListCursor::decode(cursor)?;
            if cursor.tenant_id != request.tenant_id
                || cursor.namespace != namespace
                || cursor.prefix != prefix
            {
                return Err(ApiError::new(
                    ApiErrorCategory::Validation,
                    "invalid_cursor",
                    "cursor does not match current list request",
                ));
            }
            (cursor.snapshot_revision, Some(cursor.last_path))
        } else {
            (
                self.namespace_current_state(&request.tenant_id, &namespace)?
                    .revision,
                None,
            )
        };

        let snapshot =
            self.namespace_snapshot_at(&request.tenant_id, &namespace, Some(snapshot_revision))?;
        let limit = request.limit.unwrap_or(100) as usize;
        let mut all_items = snapshot
            .bindings
            .values()
            .filter(|binding| {
                prefix.as_ref().is_none_or(|prefix| {
                    binding.path == *prefix || binding.path.starts_with(&format!("{prefix}/"))
                })
            })
            .filter(|binding| request.include_tombstones || !binding.tombstone)
            .cloned()
            .collect::<Vec<_>>();
        all_items.sort_by(|left, right| left.path.cmp(&right.path));

        let start_index = last_path
            .as_ref()
            .and_then(|path| all_items.iter().position(|binding| binding.path == *path))
            .map(|index| index + 1)
            .unwrap_or(0);
        let page = all_items
            .iter()
            .skip(start_index)
            .take(limit)
            .map(|binding| ListItem {
                namespace: namespace.clone(),
                path: binding.path.clone(),
                target_cid: binding.target_cid.clone(),
                manifest_cid: binding.manifest_cid.clone(),
                revision: binding.revision,
                record_cid: binding.record_cid.clone(),
                metadata: binding.metadata.clone(),
                tombstone: binding.tombstone,
            })
            .collect::<Vec<_>>();
        let truncated = start_index + page.len() < all_items.len();
        let next_cursor = truncated.then(|| {
            ListCursor {
                tenant_id: request.tenant_id.clone(),
                namespace: namespace.clone(),
                prefix: prefix.clone(),
                snapshot_revision,
                last_path: page
                    .last()
                    .map(|item| item.path.clone())
                    .unwrap_or_default(),
            }
            .encode()
        });

        Ok(ListResponse {
            items: page,
            next_cursor,
            truncated,
            namespace_revision_snapshot: snapshot_revision,
        })
    }

    pub fn subscribe_start(
        &self,
        auth: &AuthContext,
        request: &SubscribeRequest,
    ) -> Result<EventCursor, ApiError> {
        if request
            .filters
            .iter()
            .filter_map(|filter| filter.tenant_scope.as_ref())
            .any(|tenant_scope| tenant_scope != &request.tenant_id)
        {
            return Err(ApiError::new(
                ApiErrorCategory::Policy,
                "tenant_scope_mismatch",
                "subscribe filter tenant_scope must match request tenant_id",
            ));
        }

        let meta = AuthRequestMeta {
            operation: OperationName::Subscribe,
            tenant_id: &request.tenant_id,
            subject: "events",
            namespace: request
                .filters
                .first()
                .and_then(|filter| filter.namespace_prefix.as_deref()),
            path: request
                .filters
                .first()
                .and_then(|filter| filter.path_exact.as_deref()),
            content_size: None,
            key_policy_id: None,
            encryption_profile_id: None,
            metadata_visibility: None,
            idempotency_key: None,
        };
        self.authorize(auth, &meta)?;

        let latest_next_seq = self.next_read_event_seq(&request.tenant_id)?;
        let next_seq = if let Some(cursor) = &request.cursor {
            let decoded = EventCursor::decode(cursor)?;
            if decoded.tenant_id != request.tenant_id {
                return Err(ApiError::new(
                    ApiErrorCategory::Validation,
                    "invalid_cursor",
                    "event cursor tenant does not match request tenant",
                ));
            }
            decoded.next_seq
        } else if let Some(from_seq) = request.from_seq {
            from_seq
        } else {
            latest_next_seq
        };
        self.ensure_event_cursor_within_window(&request.tenant_id, next_seq)?;

        Ok(EventCursor {
            tenant_id: request.tenant_id.clone(),
            next_seq,
        })
    }

    pub fn subscribe_poll(
        &self,
        auth: &AuthContext,
        request: &SubscribeRequest,
        cursor: &EventCursor,
    ) -> Result<(Vec<SubscribeEnvelope>, EventCursor), ApiError> {
        let _ = self.subscribe_start(auth, request)?;
        let batch_max = request.batch_max.unwrap_or(64) as usize;
        let events =
            self.read_event_records_after(&request.tenant_id, cursor.next_seq, batch_max)?;
        let filtered = events
            .into_iter()
            .filter(|event| {
                request.filters.is_empty()
                    || request
                        .filters
                        .iter()
                        .any(|filter| self.event_matches_filter(event, filter))
            })
            .collect::<Vec<_>>();
        let next_seq = filtered
            .last()
            .map(|event| event.seq + 1)
            .unwrap_or(cursor.next_seq);
        let next_cursor = EventCursor {
            tenant_id: request.tenant_id.clone(),
            next_seq,
        };
        let envelopes = if filtered.is_empty() {
            vec![SubscribeEnvelope {
                kind: SubscribeEnvelopeKind::Notice,
                event: None,
                notice: Some(NoticeFrame {
                    kind: "heartbeat".to_string(),
                    message: None,
                    cursor: Some(next_cursor.encode()),
                }),
            }]
        } else {
            filtered
                .into_iter()
                .map(|event| SubscribeEnvelope {
                    kind: SubscribeEnvelopeKind::Event,
                    event: Some(event),
                    notice: None,
                })
                .collect()
        };
        Ok((envelopes, next_cursor))
    }

    fn authorize(
        &self,
        auth: &AuthContext,
        meta: &AuthRequestMeta<'_>,
    ) -> Result<AuthorizationDecision, ApiError> {
        let decision = self
            .policy_engine
            .authorize(auth, meta)
            .map_err(|reason| self.authorization_denied_api_error(meta, reason))?;
        self.observe_durable_replay(auth, meta, decision)
    }

    fn observe_durable_replay(
        &self,
        auth: &AuthContext,
        meta: &AuthRequestMeta<'_>,
        mut decision: AuthorizationDecision,
    ) -> Result<AuthorizationDecision, ApiError> {
        if !meta.operation.is_mutation() {
            return Ok(decision);
        }

        let Some(jti) = auth.claims.jti.as_deref() else {
            return Ok(decision);
        };

        let replay_key = self.replay_key(meta.tenant_id, jti, meta.operation, meta.subject);
        let replay_record = ReplayRecord {
            tenant_id: meta.tenant_id.clone(),
            jti: jti.to_string(),
            operation: meta.operation.as_str().to_string(),
            subject: meta.subject.to_string(),
            idempotency_key: meta.idempotency_key.unwrap_or_default().to_string(),
            observed_at_ms: now_ms(),
        };

        if self.create_encrypted_json(meta.tenant_id, "replay", &replay_key, &replay_record)? {
            return Ok(decision);
        }

        let existing = self
            .read_encrypted_json::<ReplayRecord>(meta.tenant_id, "replay", &replay_key)?
            .ok_or_else(|| {
                ApiError::new(
                    ApiErrorCategory::Storage,
                    "replay_record_missing",
                    "replay record disappeared after create conflict",
                )
            })?;

        if meta.idempotency_key == Some(existing.idempotency_key.as_str()) {
            decision.replay_status = ReplayStatus::IdempotentRetry;
            return Ok(decision);
        }

        Err(self.authorization_denied_api_error(meta, DenialReason::ReplayDetected))
    }

    fn authorization_denied_api_error(
        &self,
        meta: &AuthRequestMeta<'_>,
        reason: DenialReason,
    ) -> ApiError {
        let error = denial_to_api_error(reason);
        self.record_observation(Observation {
            operation: "auth_denied",
            tenant_id: meta.tenant_id,
            namespace: meta.namespace,
            status_code: 403,
            outcome: "auth_denied",
            latency_ms: 0,
            object_size_bytes: meta.content_size,
            error_code: Some(&error.code),
        });
        let _ = self.append_event(
            meta.tenant_id,
            EventRecord {
                version: 1,
                seq: 0,
                at_ms: now_ms(),
                event_type: EventType::AuthDenied,
                subject_kind: "auth".to_string(),
                namespace: meta.namespace.map(ToString::to_string),
                path: meta.path.map(ToString::to_string),
                cid: None,
                revision: None,
                trace_id: None,
                payload: BTreeMap::from([
                    ("code".to_string(), error.code.clone()),
                    ("operation".to_string(), meta.operation.as_str().to_string()),
                ]),
            },
        );
        error
    }

    fn selector_resolution(
        &self,
        tenant_id: &TenantId,
        selector: &hsp_core::ObjectSelector,
    ) -> Result<SelectorResolution, ApiError> {
        match selector.kind {
            ObjectSelectorKind::Cid => Ok(SelectorResolution {
                manifest_cid: selector.cid.clone().expect("validated cid selector"),
                namespace: None,
                path: None,
                revision: None,
                record_cid: None,
            }),
            ObjectSelectorKind::Namespace => {
                let namespace = selector
                    .namespace
                    .clone()
                    .expect("validated namespace selector");
                let path = selector.path.clone().expect("validated namespace selector");
                let resolved = self.resolve_snapshot(tenant_id, &namespace, &path, None, None)?;
                if resolved.tombstone {
                    return Err(ApiError::new(
                        ApiErrorCategory::NotFound,
                        "path_tombstoned",
                        "namespace path is tombstoned",
                    ));
                }
                let manifest_cid = resolved.manifest_cid.clone().ok_or_else(|| {
                    ApiError::new(
                        ApiErrorCategory::NotFound,
                        "path_not_bound",
                        "namespace path does not resolve to a committed object",
                    )
                })?;
                Ok(SelectorResolution {
                    manifest_cid,
                    namespace: Some(namespace),
                    path: Some(path),
                    revision: Some(resolved.revision),
                    record_cid: Some(resolved.record_cid),
                })
            }
        }
    }

    fn canonical_namespace_and_path(
        &self,
        namespace: &str,
        path: &str,
    ) -> Result<(String, String), ApiError> {
        let namespace = canonical_path(namespace).map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Validation,
                "invalid_namespace",
                error.to_string(),
            )
        })?;
        let path = canonical_path(path).map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Validation,
                "invalid_path",
                error.to_string(),
            )
        })?;
        Ok((namespace, path))
    }

    fn bind_internal(
        &self,
        auth: &AuthContext,
        request: BindRequest,
        persist_idempotency: bool,
    ) -> Result<BindResponse, ApiError> {
        let (namespace, path) =
            self.canonical_namespace_and_path(&request.namespace, &request.path)?;
        let signed_record = self.verify_signed_bind_record(&request, &namespace, &path)?;
        let subject = format!("{namespace}:{path}");
        let meta = AuthRequestMeta {
            operation: OperationName::Bind,
            tenant_id: &request.tenant_id,
            subject: &subject,
            namespace: Some(&namespace),
            path: Some(&path),
            content_size: None,
            key_policy_id: None,
            encryption_profile_id: None,
            metadata_visibility: None,
            idempotency_key: Some(&request.idempotency_key),
        };
        let decision = self.authorize(auth, &meta)?;

        let idempotency_key =
            self.idempotency_key(&request.tenant_id, "bind", &request.idempotency_key);
        if persist_idempotency && decision.replay_status == ReplayStatus::IdempotentRetry {
            if let Some(record) = self.read_encrypted_json::<IdempotencyRecord<BindResponse>>(
                &request.tenant_id,
                "idempotency",
                &idempotency_key,
            )? {
                return Ok(record.response);
            }
        }

        if request.if_revision.is_none() && !request.if_absent {
            return Err(ApiError::new(
                ApiErrorCategory::Conflict,
                "precondition_required",
                "BIND requires if_revision or if_absent=true",
            ));
        }

        let _ = self.manifest_record(&request.tenant_id, &request.target_cid)?;
        let mut current = self.namespace_current_state(&request.tenant_id, &namespace)?;
        let existing = current.bindings.get(&path).cloned();
        if request.if_absent && existing.as_ref().is_some_and(|binding| !binding.tombstone) {
            return Err(ApiError::new(
                ApiErrorCategory::Conflict,
                "revision_conflict",
                "path is already bound",
            ));
        }
        if let Some(expected_revision) = request.if_revision {
            let actual = existing
                .as_ref()
                .map(|binding| binding.revision)
                .unwrap_or(0);
            if actual != expected_revision {
                return Err(ApiError::new(
                    ApiErrorCategory::Conflict,
                    "revision_conflict",
                    "namespace revision precondition failed",
                ));
            }
        }

        let revision = self.next_namespace_revision(&request.tenant_id, &namespace)?;
        let binding = NamespaceBindingState {
            path: path.clone(),
            target_cid: Some(request.target_cid.clone()),
            manifest_cid: Some(request.target_cid.clone()),
            revision,
            record_cid: signed_record.record_cid(),
            metadata: request.metadata.clone(),
            tombstone: false,
        };
        current.revision = revision;
        current.bindings.insert(path.clone(), binding.clone());
        self.write_namespace_current_state(&request.tenant_id, &namespace, &current)?;
        self.append_namespace_journal(
            &request.tenant_id,
            &namespace,
            NamespaceJournalEntry {
                revision,
                record: signed_record.clone(),
                record_cid: binding.record_cid.clone(),
                target_cid: binding.target_cid.clone(),
                manifest_cid: binding.manifest_cid.clone(),
                metadata: binding.metadata.clone(),
                tombstone: false,
            },
        )?;
        let event_seq = self.append_event(
            &request.tenant_id,
            EventRecord {
                version: 1,
                seq: 0,
                at_ms: now_ms(),
                event_type: EventType::NamespaceBound,
                subject_kind: "namespace".to_string(),
                namespace: Some(namespace.clone()),
                path: Some(path.clone()),
                cid: Some(request.target_cid.clone()),
                revision: Some(revision),
                trace_id: None,
                payload: request.metadata.clone(),
            },
        )?;
        self.write_audit(
            &request.tenant_id,
            event_seq,
            OperationName::Bind.as_str(),
            &subject,
        )?;

        let response = BindResponse {
            revision,
            record_cid: binding.record_cid.clone(),
            event_seq,
        };
        if persist_idempotency {
            self.write_encrypted_json(
                &request.tenant_id,
                "idempotency",
                &idempotency_key,
                &IdempotencyRecord {
                    response: response.clone(),
                },
            )?;
        }
        Ok(response)
    }

    fn unbind_internal(
        &self,
        auth: &AuthContext,
        request: UnbindRequest,
        persist_idempotency: bool,
    ) -> Result<UnbindResponse, ApiError> {
        let started_at_ms = now_ms();
        let (namespace, path) =
            self.canonical_namespace_and_path(&request.namespace, &request.path)?;
        let signed_record = self.verify_signed_unbind_record(&request, &namespace, &path)?;
        if request.hard_delete
            && !auth
                .claims
                .ops
                .contains(&hsp_core::CapabilityScope::AdminRepair)
        {
            return Err(ApiError::new(
                ApiErrorCategory::Policy,
                "hard_delete_requires_admin",
                "hard delete requires admin.repair scope",
            ));
        }

        let subject = format!("{namespace}:{path}");
        let meta = AuthRequestMeta {
            operation: OperationName::Unbind,
            tenant_id: &request.tenant_id,
            subject: &subject,
            namespace: Some(&namespace),
            path: Some(&path),
            content_size: None,
            key_policy_id: None,
            encryption_profile_id: None,
            metadata_visibility: None,
            idempotency_key: Some(&request.idempotency_key),
        };
        let decision = self.authorize(auth, &meta)?;
        let idempotency_key =
            self.idempotency_key(&request.tenant_id, "unbind", &request.idempotency_key);
        if persist_idempotency && decision.replay_status == ReplayStatus::IdempotentRetry {
            if let Some(record) = self.read_encrypted_json::<IdempotencyRecord<UnbindResponse>>(
                &request.tenant_id,
                "idempotency",
                &idempotency_key,
            )? {
                self.record_observation(Observation {
                    operation: "delete",
                    tenant_id: &request.tenant_id,
                    namespace: Some(&namespace),
                    status_code: 200,
                    outcome: "idempotent_retry",
                    latency_ms: elapsed_ms(started_at_ms),
                    object_size_bytes: None,
                    error_code: None,
                });
                return Ok(record.response);
            }
        }

        let mut current = self.namespace_current_state(&request.tenant_id, &namespace)?;
        let existing = current.bindings.get(&path).cloned().ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::NotFound,
                "path_not_bound",
                "namespace path is not bound",
            )
        })?;
        if existing.revision != request.if_revision {
            return Err(ApiError::new(
                ApiErrorCategory::Conflict,
                "revision_conflict",
                "namespace revision precondition failed",
            ));
        }

        let revision = self.next_namespace_revision(&request.tenant_id, &namespace)?;
        let tombstone = !request.hard_delete;
        if tombstone {
            current.bindings.insert(
                path.clone(),
                NamespaceBindingState {
                    path: path.clone(),
                    target_cid: None,
                    manifest_cid: None,
                    revision,
                    record_cid: signed_record.record_cid(),
                    metadata: BTreeMap::new(),
                    tombstone: true,
                },
            );
        } else {
            current.bindings.remove(&path);
        }
        current.revision = revision;
        self.write_namespace_current_state(&request.tenant_id, &namespace, &current)?;
        self.append_namespace_journal(
            &request.tenant_id,
            &namespace,
            NamespaceJournalEntry {
                revision,
                record: signed_record.clone(),
                record_cid: signed_record.record_cid(),
                target_cid: None,
                manifest_cid: None,
                metadata: BTreeMap::new(),
                tombstone,
            },
        )?;
        let event_type = if tombstone {
            EventType::NamespaceTombstoned
        } else {
            EventType::NamespaceUnbound
        };
        let event_seq = self.append_event(
            &request.tenant_id,
            EventRecord {
                version: 1,
                seq: 0,
                at_ms: now_ms(),
                event_type,
                subject_kind: "namespace".to_string(),
                namespace: Some(namespace.clone()),
                path: Some(path.clone()),
                cid: None,
                revision: Some(revision),
                trace_id: None,
                payload: BTreeMap::new(),
            },
        )?;
        self.write_audit(
            &request.tenant_id,
            event_seq,
            OperationName::Unbind.as_str(),
            &subject,
        )?;
        let response = UnbindResponse {
            revision,
            record_cid: signed_record.record_cid(),
            event_seq,
            tombstone,
        };
        if persist_idempotency {
            self.write_encrypted_json(
                &request.tenant_id,
                "idempotency",
                &idempotency_key,
                &IdempotencyRecord {
                    response: response.clone(),
                },
            )?;
        }
        self.record_observation(Observation {
            operation: "delete",
            tenant_id: &request.tenant_id,
            namespace: Some(&namespace),
            status_code: 200,
            outcome: if tombstone {
                "tombstoned"
            } else {
                "hard_deleted"
            },
            latency_ms: elapsed_ms(started_at_ms),
            object_size_bytes: None,
            error_code: None,
        });
        Ok(response)
    }

    fn verify_signed_bind_record(
        &self,
        request: &BindRequest,
        namespace: &str,
        path: &str,
    ) -> Result<NamespaceMutationRecord, ApiError> {
        let registry = self.issuer_registry.as_ref().ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::Policy,
                "issuer_registry_missing",
                "signed namespace mutations require an issuer registry",
            )
        })?;
        let record = verify_signed_namespace_record(&request.signed_record_b64, registry)?;
        if record.tenant_id != request.tenant_id
            || record.namespace != namespace
            || record.path != path
            || record.kind != NamespaceMutationKind::Bind
            || record.target_cid.as_deref() != Some(request.target_cid.as_str())
            || record.if_revision != request.if_revision
            || record.ttl_ms != request.ttl_ms
            || record.metadata != request.metadata
        {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "signed_record_mismatch",
                "signed namespace mutation does not match bind request",
            ));
        }
        record.validate()?;
        Ok(record)
    }

    fn verify_signed_unbind_record(
        &self,
        request: &UnbindRequest,
        namespace: &str,
        path: &str,
    ) -> Result<NamespaceMutationRecord, ApiError> {
        let registry = self.issuer_registry.as_ref().ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::Policy,
                "issuer_registry_missing",
                "signed namespace mutations require an issuer registry",
            )
        })?;
        let record = verify_signed_namespace_record(&request.signed_record_b64, registry)?;
        let expected_kind = if request.hard_delete {
            NamespaceMutationKind::HardDelete
        } else {
            NamespaceMutationKind::Unbind
        };
        if record.tenant_id != request.tenant_id
            || record.namespace != namespace
            || record.path != path
            || record.kind != expected_kind
            || record.if_revision != Some(request.if_revision)
        {
            return Err(ApiError::new(
                ApiErrorCategory::Auth,
                "signed_record_mismatch",
                "signed namespace mutation does not match unbind request",
            ));
        }
        record.validate()?;
        Ok(record)
    }

    fn resolve_snapshot(
        &self,
        tenant_id: &TenantId,
        namespace: &str,
        path: &str,
        at_revision: Option<u64>,
        if_revision: Option<u64>,
    ) -> Result<ResolveResponse, ApiError> {
        let (namespace, path) = self.canonical_namespace_and_path(namespace, path)?;
        let snapshot = self.namespace_snapshot_at(tenant_id, &namespace, at_revision)?;
        let binding = snapshot.bindings.get(&path).ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::NotFound,
                "path_not_bound",
                "namespace path is not bound",
            )
        })?;
        if let Some(expected_revision) = if_revision {
            if binding.revision != expected_revision {
                return Err(ApiError::new(
                    ApiErrorCategory::Conflict,
                    "revision_conflict",
                    "namespace revision precondition failed",
                ));
            }
        }
        Ok(ResolveResponse {
            revision: binding.revision,
            target_cid: binding.target_cid.clone(),
            manifest_cid: binding.manifest_cid.clone(),
            record_cid: binding.record_cid.clone(),
            metadata: binding.metadata.clone(),
            tombstone: binding.tombstone,
        })
    }

    fn namespace_current_state(
        &self,
        tenant_id: &TenantId,
        namespace: &str,
    ) -> Result<NamespaceCurrentState, ApiError> {
        Ok(self
            .read_encrypted_json::<NamespaceCurrentState>(
                tenant_id,
                "namespace-current",
                namespace,
            )?
            .unwrap_or(NamespaceCurrentState {
                namespace: namespace.to_string(),
                revision: 0,
                bindings: BTreeMap::new(),
            }))
    }

    fn write_namespace_current_state(
        &self,
        tenant_id: &TenantId,
        namespace: &str,
        state: &NamespaceCurrentState,
    ) -> Result<(), ApiError> {
        self.write_encrypted_json(tenant_id, "namespace-current", namespace, state)
    }

    fn namespace_journal(
        &self,
        tenant_id: &TenantId,
        namespace: &str,
    ) -> Result<Vec<NamespaceJournalEntry>, ApiError> {
        Ok(self
            .read_encrypted_json::<Vec<NamespaceJournalEntry>>(
                tenant_id,
                "namespace-journal",
                namespace,
            )?
            .unwrap_or_default())
    }

    fn append_namespace_journal(
        &self,
        tenant_id: &TenantId,
        namespace: &str,
        entry: NamespaceJournalEntry,
    ) -> Result<(), ApiError> {
        let mut journal = self.namespace_journal(tenant_id, namespace)?;
        journal.push(entry);
        self.write_encrypted_json(tenant_id, "namespace-journal", namespace, &journal)
    }

    fn next_namespace_revision(
        &self,
        tenant_id: &TenantId,
        namespace: &str,
    ) -> Result<u64, ApiError> {
        let mut state = self
            .read_encrypted_json::<NamespaceRevisionState>(
                tenant_id,
                "namespace-revisions",
                namespace,
            )?
            .unwrap_or(NamespaceRevisionState { next_revision: 1 });
        let revision = state.next_revision;
        state.next_revision += 1;
        self.write_encrypted_json(tenant_id, "namespace-revisions", namespace, &state)?;
        Ok(revision)
    }

    fn namespace_snapshot_at(
        &self,
        tenant_id: &TenantId,
        namespace: &str,
        at_revision: Option<u64>,
    ) -> Result<NamespaceCurrentState, ApiError> {
        if at_revision.is_none() {
            return self.namespace_current_state(tenant_id, namespace);
        }

        let revision_limit = at_revision.unwrap_or_default();
        let mut snapshot = NamespaceCurrentState {
            namespace: namespace.to_string(),
            revision: revision_limit,
            bindings: BTreeMap::new(),
        };
        for entry in self.namespace_journal(tenant_id, namespace)? {
            if entry.revision > revision_limit {
                break;
            }
            if entry.tombstone {
                snapshot.bindings.insert(
                    entry.record.path.clone(),
                    NamespaceBindingState {
                        path: entry.record.path.clone(),
                        target_cid: None,
                        manifest_cid: None,
                        revision: entry.revision,
                        record_cid: entry.record_cid.clone(),
                        metadata: entry.metadata.clone(),
                        tombstone: true,
                    },
                );
            } else if entry.record.kind == NamespaceMutationKind::HardDelete {
                snapshot.bindings.remove(&entry.record.path);
            } else {
                snapshot.bindings.insert(
                    entry.record.path.clone(),
                    NamespaceBindingState {
                        path: entry.record.path.clone(),
                        target_cid: entry.target_cid.clone(),
                        manifest_cid: entry.manifest_cid.clone(),
                        revision: entry.revision,
                        record_cid: entry.record_cid.clone(),
                        metadata: entry.metadata.clone(),
                        tombstone: false,
                    },
                );
            }
        }
        Ok(snapshot)
    }

    fn append_event(&self, tenant_id: &TenantId, mut event: EventRecord) -> Result<u64, ApiError> {
        let seq = self.next_event_seq(tenant_id)?;
        event.seq = seq;
        self.write_encrypted_json(tenant_id, "events", &format!("event-{seq:020}"), &event)?;
        Ok(seq)
    }

    fn read_event_records_after(
        &self,
        tenant_id: &TenantId,
        next_seq: u64,
        batch_max: usize,
    ) -> Result<Vec<EventRecord>, ApiError> {
        let mut items = Vec::new();
        let latest_next_seq = self.next_read_event_seq(tenant_id)?;
        for seq in next_seq..latest_next_seq {
            if items.len() >= batch_max {
                break;
            }
            if let Some(event) = self.read_encrypted_json::<EventRecord>(
                tenant_id,
                "events",
                &format!("event-{seq:020}"),
            )? {
                items.push(event);
            }
        }
        Ok(items)
    }

    fn next_read_event_seq(&self, tenant_id: &TenantId) -> Result<u64, ApiError> {
        Ok(self
            .read_encrypted_json::<SequenceState>(tenant_id, "events", "sequence")?
            .unwrap_or(SequenceState { next_seq: 1 })
            .next_seq)
    }

    fn ensure_event_cursor_within_window(
        &self,
        tenant_id: &TenantId,
        next_seq: u64,
    ) -> Result<(), ApiError> {
        let latest_next_seq = self.next_read_event_seq(tenant_id)?;
        let oldest_allowed =
            latest_next_seq.saturating_sub(self.settings().event_replay_window_sec);
        if next_seq < oldest_allowed {
            return Err(ApiError::new(
                ApiErrorCategory::Validation,
                "cursor_expired",
                "event cursor is outside the replay window",
            ));
        }
        Ok(())
    }

    fn event_matches_filter(&self, event: &EventRecord, filter: &SubscribeFilter) -> bool {
        if let Some(namespace_prefix) = &filter.namespace_prefix {
            let Some(event_namespace) = &event.namespace else {
                return false;
            };
            if event_namespace != namespace_prefix
                && !event_namespace.starts_with(&format!("{namespace_prefix}/"))
            {
                return false;
            }
        }
        if let Some(path_exact) = &filter.path_exact {
            if event.path.as_deref() != Some(path_exact.as_str()) {
                return false;
            }
        }
        if let Some(object_cid) = &filter.object_cid {
            if event.cid.as_deref() != Some(object_cid.as_str()) {
                return false;
            }
        }
        if let Some(event_type) = filter.event_type {
            if event.event_type != event_type {
                return false;
            }
        }
        true
    }

    fn write_audit(
        &self,
        tenant_id: &TenantId,
        seq: u64,
        operation: &str,
        subject: &str,
    ) -> Result<(), ApiError> {
        self.write_encrypted_json(
            tenant_id,
            "audit",
            &format!("{seq}-{}", cid_from_bytes(subject.as_bytes())),
            &AuditRecord {
                seq,
                tenant_id: tenant_id.clone(),
                operation: operation.to_string(),
                subject: subject.to_string(),
                at_ms: now_ms(),
            },
        )
    }

    fn delete_store_key(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        key: &str,
    ) -> Result<(), ApiError> {
        let path = self.store_path(tenant_id, store_kind, key);
        if path.exists() {
            fs::remove_file(path).map_err(|error| {
                ApiError::new(
                    ApiErrorCategory::Storage,
                    "store_delete_failed",
                    error.to_string(),
                )
            })?;
        }
        Ok(())
    }

    fn manifest_record(
        &self,
        tenant_id: &TenantId,
        manifest_cid: &str,
    ) -> Result<ManifestRecord, ApiError> {
        self.read_encrypted_json::<ManifestRecord>(tenant_id, "manifests", manifest_cid)?
            .ok_or_else(|| {
                ApiError::new(
                    ApiErrorCategory::NotFound,
                    "manifest_not_found",
                    "manifest not found",
                )
            })
    }

    fn next_event_seq(&self, tenant_id: &TenantId) -> Result<u64, ApiError> {
        let state = self
            .read_encrypted_json::<SequenceState>(tenant_id, "events", "sequence")?
            .unwrap_or(SequenceState { next_seq: 1 });
        let current = state.next_seq;
        self.write_encrypted_json(
            tenant_id,
            "events",
            "sequence",
            &SequenceState {
                next_seq: current + 1,
            },
        )?;
        Ok(current)
    }

    fn chunk_exists(&self, tenant_id: &TenantId, cid: &str) -> bool {
        self.store_path(tenant_id, "chunks", cid).exists()
    }

    fn write_encrypted_bytes(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        key: &str,
        bytes: &[u8],
    ) -> Result<(), ApiError> {
        let envelope = self
            .kms
            .encrypt_store_payload(tenant_id, store_kind, bytes)
            .map_err(|error| {
                let api_error = crypto_error_to_api(error, "failed to encrypt store payload");
                self.record_observation(Observation {
                    operation: "kms_error",
                    tenant_id,
                    namespace: None,
                    status_code: 500,
                    outcome: "kms_error",
                    latency_ms: 0,
                    object_size_bytes: Some(bytes.len() as u64),
                    error_code: Some(&api_error.code),
                });
                api_error
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
        let bytes = serde_json::to_vec_pretty(value).map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Storage,
                "json_serialize_failed",
                error.to_string(),
            )
        })?;
        self.write_encrypted_bytes(tenant_id, store_kind, key, &bytes)
    }

    fn create_encrypted_json<T: Serialize>(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        key: &str,
        value: &T,
    ) -> Result<bool, ApiError> {
        let bytes = serde_json::to_vec_pretty(value).map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Storage,
                "json_serialize_failed",
                error.to_string(),
            )
        })?;
        let envelope = self
            .kms
            .encrypt_store_payload(tenant_id, store_kind, &bytes)
            .map_err(|error| crypto_error_to_api(error, "failed to encrypt store payload"))?;
        self.create_envelope(tenant_id, store_kind, key, &envelope)
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

        serde_json::from_slice(&bytes).map(Some).map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Storage,
                "json_deserialize_failed",
                error.to_string(),
            )
        })
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

        let bytes = fs::read(path).map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Storage,
                "store_read_failed",
                error.to_string(),
            )
        })?;
        let envelope: StoredEnvelope = serde_json::from_slice(&bytes).map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Storage,
                "envelope_deserialize_failed",
                error.to_string(),
            )
        })?;
        self.kms
            .decrypt_store_payload(tenant_id, store_kind, &envelope)
            .map(Some)
            .map_err(|error| {
                let api_error = crypto_error_to_api(error, "failed to decrypt store payload");
                self.record_observation(Observation {
                    operation: "kms_error",
                    tenant_id,
                    namespace: None,
                    status_code: 500,
                    outcome: "kms_error",
                    latency_ms: 0,
                    object_size_bytes: None,
                    error_code: Some(&api_error.code),
                });
                api_error
            })
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

        let bytes = serde_json::to_vec_pretty(envelope).map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Storage,
                "envelope_serialize_failed",
                error.to_string(),
            )
        })?;
        fs::write(path, bytes).map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Storage,
                "store_write_failed",
                error.to_string(),
            )
        })
    }

    fn create_envelope(
        &self,
        tenant_id: &TenantId,
        store_kind: &str,
        key: &str,
        envelope: &StoredEnvelope,
    ) -> Result<bool, ApiError> {
        let path = self.store_path(tenant_id, store_kind, key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                ApiError::new(ApiErrorCategory::Storage, "mkdir_failed", error.to_string())
            })?;
        }

        let bytes = serde_json::to_vec_pretty(envelope).map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Storage,
                "envelope_serialize_failed",
                error.to_string(),
            )
        })?;
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
            Err(error) => {
                return Err(ApiError::new(
                    ApiErrorCategory::Storage,
                    "store_create_failed",
                    error.to_string(),
                ))
            }
        };
        file.write_all(&bytes).map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Storage,
                "store_write_failed",
                error.to_string(),
            )
        })?;
        file.sync_all().map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Storage,
                "store_sync_failed",
                error.to_string(),
            )
        })?;
        Ok(true)
    }

    fn ensure_store_roots(&self) -> Result<(), ApiError> {
        for store_kind in [
            "chunks",
            "manifests",
            "namespace-current",
            "namespace-journal",
            "namespace-revisions",
            "sessions",
            "audit",
            "idempotency",
            "replay",
            "events",
        ] {
            fs::create_dir_all(self.config.root_dir.join(store_kind)).map_err(|error| {
                ApiError::new(ApiErrorCategory::Storage, "mkdir_failed", error.to_string())
            })?;
        }

        Ok(())
    }

    fn store_path(&self, tenant_id: &TenantId, store_kind: &str, key: &str) -> PathBuf {
        self.config
            .root_dir
            .join(store_kind)
            .join(tenant_store_dir(tenant_id))
            .join(store_file_name(key))
    }

    fn idempotency_key(&self, tenant_id: &TenantId, op: &str, value: &str) -> String {
        format!(
            "{op}-{}-{}",
            cid_from_bytes(tenant_id.0.as_bytes()),
            cid_from_bytes(value.as_bytes())
        )
    }

    fn replay_key(
        &self,
        tenant_id: &TenantId,
        jti: &str,
        operation: OperationName,
        subject: &str,
    ) -> String {
        let replay_key = format!("{tenant_id}|{jti}|{}|{subject}", operation.as_str());
        format!(
            "{}-{}",
            operation.as_str().to_ascii_lowercase(),
            cid_from_bytes(replay_key.as_bytes())
        )
    }

    fn record_observation(&self, observation: Observation<'_>) {
        let operation = observation.operation.to_string();
        let outcome = observation.outcome.to_string();
        let namespace = observation.namespace.map(ToString::to_string);
        let key = MetricKey {
            operation: operation.clone(),
            tenant_id: observation.tenant_id.0.clone(),
            namespace: namespace.clone(),
            status_code: observation.status_code,
            outcome: outcome.clone(),
        };
        let mut metrics = self
            .observability
            .metrics
            .lock()
            .expect("metrics lock poisoned");
        let value = metrics.entry(key).or_default();
        value.count = value.count.saturating_add(1);
        value.latency_ms_sum = value.latency_ms_sum.saturating_add(observation.latency_ms);
        value.object_size_bytes_sum = value
            .object_size_bytes_sum
            .saturating_add(observation.object_size_bytes.unwrap_or_default());
        drop(metrics);

        let mut logs = self
            .observability
            .logs
            .lock()
            .expect("structured logs lock poisoned");
        logs.push(StructuredLogRecord {
            at_ms: now_ms(),
            operation,
            tenant_id: observation.tenant_id.0.clone(),
            namespace,
            status_code: observation.status_code,
            outcome,
            latency_ms: observation.latency_ms,
            object_size_bytes: observation.object_size_bytes,
            error_code: observation.error_code.map(ToString::to_string),
        });
        const MAX_LOG_RECORDS: usize = 1024;
        if logs.len() > MAX_LOG_RECORDS {
            let overflow = logs.len() - MAX_LOG_RECORDS;
            logs.drain(0..overflow);
        }
    }
}

pub fn default_alpha_service(root_dir: impl AsRef<Path>) -> Result<AlphaService, ApiError> {
    let seed = required_runtime_secret_from_env("HSP_KMS_SEED", DEFAULT_KMS_SEED_LITERALS)
        .map_err(|error| {
            crypto_error_to_api(
                error,
                "HSP_KMS_SEED must be configured for alpha service KMS",
            )
        })?;
    alpha_service_with_kms_seed(root_dir, &seed)
}

pub fn alpha_service_with_kms_seed(
    root_dir: impl AsRef<Path>,
    kms_seed: &[u8],
) -> Result<AlphaService, ApiError> {
    let kms = LocalDevKms::from_seed(kms_seed)
        .map_err(|error| crypto_error_to_api(error, "failed to initialize configured KMS"))?;
    AlphaService::new(
        AlphaConfig {
            authority: "localhost".to_string(),
            gateway_base_url: "https://localhost/v1/".to_string(),
            root_dir: root_dir.as_ref().to_path_buf(),
            native_port: 443,
            server_instance_id: "hsp-alpha-dev".to_string(),
        },
        kms,
    )
}

fn tenant_store_dir(tenant_id: &TenantId) -> String {
    URL_SAFE_NO_PAD.encode(tenant_id.0.as_bytes())
}

fn store_file_name(key: &str) -> String {
    format!("{}.json.enc", cid_from_bytes(key.as_bytes()))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

fn elapsed_ms(start_ms: u64) -> u64 {
    now_ms().saturating_sub(start_ms)
}

fn prometheus_labels(entry: &ServiceMetricEntry) -> String {
    format!(
        "operation=\"{}\",tenant=\"{}\",namespace=\"{}\",status_code=\"{}\",outcome=\"{}\"",
        prometheus_escape(&entry.operation),
        prometheus_escape(&entry.tenant_id),
        prometheus_escape(entry.namespace.as_deref().unwrap_or("")),
        entry.status_code,
        prometheus_escape(&entry.outcome)
    )
}

fn prometheus_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use hsp_core::{
        ApiErrorCategory, CapabilityClaims, CapabilityScope, ChannelBindingProof, ChunkRef,
        EncryptionDescriptor, EncryptionProfileId, GetPreference, GetRequest, KeyPolicyId,
        Manifest, ObjectSelector, PutChunkRequest, PutCommitRequest, PutInitRequest,
        VisibilityMode, WrappedObjectKeyRecord,
    };

    static NEXT_TEMP_ROOT_ID: AtomicU64 = AtomicU64::new(1);

    fn temp_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "hsp-alpha-{}-{}",
            std::process::id(),
            NEXT_TEMP_ROOT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn store_paths_do_not_collapse_distinct_keys() {
        let service = alpha_service_with_kms_seed(temp_root(), test_kms_seed()).unwrap();
        let tenant = TenantId("tenant/a".to_string());
        let slash = service.store_path(&tenant, "manifests", "folder/object");
        let underscore = service.store_path(&tenant, "manifests", "folder_object");
        assert_ne!(slash, underscore);
    }

    fn service() -> AlphaService {
        alpha_service_with_kms_seed(temp_root(), test_kms_seed()).unwrap()
    }

    fn test_kms_seed() -> &'static [u8] {
        b"hsp-alpha-service-test-kms-seed-01"
    }

    fn auth_context() -> AuthContext {
        AuthContext {
            claims: CapabilityClaims {
                iss: "issuer".to_string(),
                sub: "subject".to_string(),
                aud: "hsp".to_string(),
                exp: now_ms() + 60_000,
                nbf: Some(now_ms() - 1_000),
                jti: Some("jti-put-init".to_string()),
                ops: vec![CapabilityScope::Read, CapabilityScope::Write],
                tenant_id: TenantId("tenant-alpha".to_string()),
                namespace_prefix: None,
                path_prefix: None,
                max_object_size: Some(10 * 1024 * 1024),
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

    fn manifest_with_chunk(chunk_cid: String) -> Manifest {
        let mut server_visible_metadata = BTreeMap::new();
        server_visible_metadata.insert("content-language".to_string(), "ru".to_string());

        Manifest {
            version: 1,
            tenant_id: TenantId("tenant-alpha".to_string()),
            logical_size: 11,
            stored_size: 11,
            chunker: "fixed-1m".to_string(),
            chunk_refs: vec![ChunkRef {
                chunk_index: 0,
                cid: chunk_cid,
                offset: 0,
                logical_len: 11,
                stored_len: 11,
                content_encoding: "identity".to_string(),
            }],
            content_type: "application/octet-stream".to_string(),
            created_at_ms: now_ms(),
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
                    encapsulated_key_b64: Some("bm9uY2U".to_string()),
                }],
                server_visible_metadata,
                encrypted_client_metadata: BTreeMap::from([(
                    "owner".to_string(),
                    "alice".to_string(),
                )]),
            },
        }
    }

    #[test]
    fn secure_alpha_upload_head_roundtrip() {
        let service = service();
        let chunk_bytes = b"ciphertext!";
        let chunk_cid = hsp_core::cid_from_bytes(chunk_bytes);
        let manifest = manifest_with_chunk(chunk_cid.clone());
        let auth = auth_context();

        let init = service
            .put_init(
                &auth,
                PutInitRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    manifest: manifest.clone(),
                    idempotency_key: "idem-1".to_string(),
                    encryption_profile_id: EncryptionProfileId("public-e2ee-v1".to_string()),
                    key_policy_id: KeyPolicyId("policy-default".to_string()),
                    metadata_visibility: VisibilityMode::Split,
                    storage_class: "hot".to_string(),
                    atomic_bind: None,
                },
            )
            .unwrap();

        let chunk_auth = AuthContext {
            claims: CapabilityClaims {
                jti: Some("jti-put-chunk".to_string()),
                ..auth.claims.clone()
            },
            channel_binding: auth.channel_binding.clone(),
        };

        service
            .put_chunk(
                &chunk_auth,
                PutChunkRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    session_id: init.session_id.clone(),
                    chunk_index: 0,
                    chunk_cid: chunk_cid.clone(),
                    chunk_offset: 0,
                    chunk_length: chunk_bytes.len() as u64,
                    content_encoding: "identity".to_string(),
                },
                chunk_bytes,
            )
            .unwrap();

        let commit_auth = AuthContext {
            claims: CapabilityClaims {
                jti: Some("jti-put-commit".to_string()),
                ..auth.claims.clone()
            },
            channel_binding: auth.channel_binding.clone(),
        };

        let commit = service
            .put_commit(
                &commit_auth,
                PutCommitRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    session_id: init.session_id.clone(),
                    manifest_cid: init.accepted_manifest_cid.clone(),
                    idempotency_key: "idem-commit".to_string(),
                },
            )
            .unwrap();

        let head = service
            .head(
                &auth,
                HeadRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    selector: ObjectSelector::cid(commit.object_cid),
                },
            )
            .unwrap();

        assert_eq!(
            head.server_visible_metadata.get("content-language"),
            Some(&"ru".to_string())
        );
        assert!(head.exists);
        assert!(!head.deleted);
        assert_eq!(head.cid, head.object_cid);
        assert_eq!(head.integrity_hash, head.object_cid);
        assert_eq!(head.size_bytes, 11);
        assert_eq!(head.ciphertext_size_bytes, 11);
        assert_eq!(head.encryption_profile_id.0, "public-e2ee-v1");
        assert_eq!(head.key_policy_id.0, "policy-default");
        assert!(head.encrypted_client_metadata_redacted);

        let metrics = service.prometheus_metrics();
        assert!(metrics.contains("hsp_requests_total"));
        assert!(metrics.contains("operation=\"head\""));
    }

    #[test]
    fn get_manifest_only_and_chunk_stream_work() {
        let service = service();
        let chunk_bytes = b"ciphertext!";
        let chunk_cid = hsp_core::cid_from_bytes(chunk_bytes);
        let manifest = manifest_with_chunk(chunk_cid.clone());
        let auth = auth_context();

        let init = service
            .put_init(
                &auth,
                PutInitRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    manifest: manifest.clone(),
                    idempotency_key: "idem-get".to_string(),
                    encryption_profile_id: EncryptionProfileId("public-e2ee-v1".to_string()),
                    key_policy_id: KeyPolicyId("policy-default".to_string()),
                    metadata_visibility: VisibilityMode::Split,
                    storage_class: "hot".to_string(),
                    atomic_bind: None,
                },
            )
            .unwrap();

        let chunk_auth = AuthContext {
            claims: CapabilityClaims {
                jti: Some("jti-get-put-chunk".to_string()),
                ..auth.claims.clone()
            },
            channel_binding: auth.channel_binding.clone(),
        };
        service
            .put_chunk(
                &chunk_auth,
                PutChunkRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    session_id: init.session_id.clone(),
                    chunk_index: 0,
                    chunk_cid: chunk_cid.clone(),
                    chunk_offset: 0,
                    chunk_length: chunk_bytes.len() as u64,
                    content_encoding: "identity".to_string(),
                },
                chunk_bytes,
            )
            .unwrap();

        let commit_auth = AuthContext {
            claims: CapabilityClaims {
                jti: Some("jti-get-put-commit".to_string()),
                ..auth.claims.clone()
            },
            channel_binding: auth.channel_binding.clone(),
        };
        let commit = service
            .put_commit(
                &commit_auth,
                PutCommitRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    session_id: init.session_id.clone(),
                    manifest_cid: init.accepted_manifest_cid.clone(),
                    idempotency_key: "idem-get-commit".to_string(),
                },
            )
            .unwrap();

        let manifest_only = service
            .get(
                &auth,
                GetRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    selector: ObjectSelector::cid(commit.object_cid.clone()),
                    preference: Some(GetPreference::ManifestOnly),
                    range: None,
                },
            )
            .unwrap();
        assert!(manifest_only.chunks.is_empty());
        assert!(manifest_only.meta.manifest.is_some());

        let chunk_stream = service
            .get(
                &auth,
                GetRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    selector: ObjectSelector::cid(commit.object_cid),
                    preference: Some(GetPreference::ChunkStream),
                    range: None,
                },
            )
            .unwrap();
        assert_eq!(chunk_stream.chunks.len(), 1);
        assert_eq!(chunk_stream.chunks[0].bytes, chunk_bytes);
        assert_eq!(
            chunk_stream.meta.integrity_hash,
            chunk_stream.meta.object_cid
        );
        assert_eq!(chunk_stream.meta.ciphertext_size_bytes, 11);
        assert_eq!(chunk_stream.meta.encryption_profile_id.0, "public-e2ee-v1");
    }

    #[test]
    fn put_chunk_rejects_cid_mismatch_and_records_integrity_metric() {
        let service = service();
        let auth = auth_context();
        let error = service
            .put_chunk(
                &auth,
                PutChunkRequest {
                    tenant_id: TenantId("tenant-alpha".to_string()),
                    session_id: "session-missing".to_string(),
                    chunk_index: 0,
                    chunk_cid: hsp_core::cid_from_bytes(b"expected"),
                    chunk_offset: 0,
                    chunk_length: 8,
                    content_encoding: "identity".to_string(),
                },
                b"tampered",
            )
            .expect_err("tampered chunk must be rejected before storage");

        assert_eq!(error.code, "chunk_cid_mismatch");
        let metrics = service.prometheus_metrics();
        assert!(metrics.contains("operation=\"integrity_error\""));
        assert!(service
            .structured_logs()
            .iter()
            .any(|record| record.error_code.as_deref() == Some("chunk_cid_mismatch")));
    }

    #[test]
    fn idempotent_put_init_returns_same_response() {
        let service = service();
        let chunk_cid = hsp_core::cid_from_bytes(b"ciphertext!");
        let manifest = manifest_with_chunk(chunk_cid);
        let auth = auth_context();

        let request = PutInitRequest {
            tenant_id: TenantId("tenant-alpha".to_string()),
            manifest,
            idempotency_key: "idem-1".to_string(),
            encryption_profile_id: EncryptionProfileId("public-e2ee-v1".to_string()),
            key_policy_id: KeyPolicyId("policy-default".to_string()),
            metadata_visibility: VisibilityMode::Split,
            storage_class: "hot".to_string(),
            atomic_bind: None,
        };

        let first = service.put_init(&auth, request.clone()).unwrap();
        let second = service.put_init(&auth, request).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn persisted_replay_survives_alpha_service_restart() {
        let root = temp_root();
        let service = alpha_service_with_kms_seed(root.clone(), test_kms_seed()).unwrap();
        let chunk_cid = hsp_core::cid_from_bytes(b"ciphertext!");
        let manifest = manifest_with_chunk(chunk_cid);
        let auth = auth_context();
        let request = PutInitRequest {
            tenant_id: TenantId("tenant-alpha".to_string()),
            manifest,
            idempotency_key: "idem-durable".to_string(),
            encryption_profile_id: EncryptionProfileId("public-e2ee-v1".to_string()),
            key_policy_id: KeyPolicyId("policy-default".to_string()),
            metadata_visibility: VisibilityMode::Split,
            storage_class: "hot".to_string(),
            atomic_bind: None,
        };

        let first = service.put_init(&auth, request.clone()).unwrap();

        let retry_service = alpha_service_with_kms_seed(root.clone(), test_kms_seed()).unwrap();
        let retry = retry_service.put_init(&auth, request.clone()).unwrap();
        assert_eq!(first, retry);

        let replay_service = alpha_service_with_kms_seed(root, test_kms_seed()).unwrap();
        let replay = PutInitRequest {
            idempotency_key: "idem-different".to_string(),
            ..request
        };
        let error = replay_service
            .put_init(&auth, replay)
            .expect_err("same mutation jti with different idempotency key must be rejected");
        assert_eq!(error.category, ApiErrorCategory::Replay);
        assert_eq!(error.code, "replay_detected");
    }

    #[test]
    fn readiness_reports_encrypted_store_roots() {
        let service = service();
        let readiness = service.readiness();
        assert!(readiness.ready);
        assert!(readiness
            .encrypted_store_roots
            .contains(&"chunks".to_string()));
        assert!(readiness
            .encrypted_store_roots
            .contains(&"namespace-current".to_string()));
        assert!(readiness
            .encrypted_store_roots
            .contains(&"namespace-journal".to_string()));
        assert!(readiness
            .encrypted_store_roots
            .contains(&"replay".to_string()));
    }
}
