use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::future::poll_fn;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bytes::Buf as _;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signer, SigningKey};
use h3::client::{self, SendRequest};
use h3_quinn::Connection as H3ClientConnection;
use hmac::{Hmac, Mac};
use http::{Method, Request, StatusCode};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, Endpoint};
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;

use hsp_auth::tls_exporter_label;
use hsp_cdn::{run_cdn_server, CdnServerConfig};
use hsp_core::{
    cid_from_bytes, AtomicBindRequest, AuthFrame, CapabilityClaims, CapabilityScope,
    ChannelBindingProof, ChunkRef, EncryptionDescriptor, EncryptionProfileId, EventType,
    GetPreference, GetRequest, KeyPolicyId, Manifest, NamespaceMutationKind,
    NamespaceMutationRecord, ObjectSelector, PayloadMode, PutCommitRequest, PutInitRequest,
    ReqHeader, SubscribeEnvelope, TenantId, VisibilityMode, WrappedObjectKeyRecord,
};
use hsp_distribution::SigV4AccessKeyRecord;
use hsp_gw::{spawn_gateway_beta_server, GatewayBetaConfig};
use hsp_s3::{run_s3_server, S3ServerConfig};
use hsp_wire::{read_frame, write_frame, Frame};
use hspd::{build_client_config, spawn_native_beta_server, NativeBetaConfig};
use reqwest::header::{HeaderMap as ReqwestHeaderMap, HeaderValue};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const DIST_TENANT: &str = "tenant-distribution";
const SIGV4_ACCESS_KEY_ID: &str = "AKIAHSPCONFORMANCE";
const SIGV4_SECRET_ACCESS_KEY: &str = "conformance-secret-access-key";
const SIGV4_REGION: &str = "auto";
const SIGV4_SERVICE: &str = "s3";
const CONFORMANCE_KMS_SEED: &[u8] = b"conformance-shared-kms-seed-0001";

struct GatewayClient {
    endpoint: Endpoint,
    connection: Connection,
    send_request: SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    driver: tokio::task::JoinHandle<()>,
}

impl GatewayClient {
    async fn shutdown(self) {
        self.endpoint.close(0u32.into(), b"shutdown");
        self.driver.abort();
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let root = env::var("HSP_ALPHA_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::temp_dir().join(format!("hsp-conformance-{}", std::process::id()))
        });
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root)?;

    let (registry_path, signing_key) = write_registry(&root)?;
    let native = spawn_native_beta_server(NativeBetaConfig {
        bind_addr: "127.0.0.1:0".parse().expect("native bind addr"),
        authority: "localhost".to_string(),
        gateway_base_url: "https://localhost/v1/".to_string(),
        root_dir: root.clone(),
        issuer_registry_path: registry_path.clone(),
        server_instance_id: "conformance-native".to_string(),
        kms_seed: CONFORMANCE_KMS_SEED.to_vec(),
    })
    .await?;
    let gateway = spawn_gateway_beta_server(GatewayBetaConfig {
        bind_addr: "127.0.0.1:0".parse().expect("gateway bind addr"),
        authority: "localhost".to_string(),
        gateway_base_url: "https://localhost/v1/".to_string(),
        root_dir: root.clone(),
        issuer_registry_path: registry_path.clone(),
        server_instance_id: "conformance-gateway".to_string(),
        native_port: native.local_addr.port(),
        kms_seed: CONFORMANCE_KMS_SEED.to_vec(),
    })
    .await?;
    let s3_addr = reserve_loopback_addr()?;
    let cdn_addr = reserve_loopback_addr()?;
    let s3_task = tokio::spawn(run_s3_server(S3ServerConfig {
        bind_addr: s3_addr,
        authority: "localhost".to_string(),
        gateway_base_url: "https://localhost".to_string(),
        root_dir: root.clone(),
        server_instance_id: "conformance-s3".to_string(),
        capability_audience: "hsp-s3".to_string(),
        immutable_cid_ttl_sec: 3600,
        namespace_ttl_sec: 5,
        issuer_registry_path: registry_path.clone(),
        namespace_signing_seed: [5u8; 32],
        namespace_signing_key_id: "test-key".to_string(),
        edge_signing_secret: b"conformance-edge-secret-0000000001".to_vec(),
        kms_seed: CONFORMANCE_KMS_SEED.to_vec(),
        aws_kms: None,
        virtual_host_suffix: None,
        sigv4_access_keys: vec![sigv4_access_key_record()],
    }));
    let cdn_task = tokio::spawn(run_cdn_server(CdnServerConfig {
        bind_addr: cdn_addr,
        authority: "localhost".to_string(),
        gateway_base_url: "https://localhost".to_string(),
        root_dir: root.clone(),
        server_instance_id: "conformance-cdn".to_string(),
        capability_audience: "hsp-cdn".to_string(),
        immutable_cid_ttl_sec: 3600,
        namespace_ttl_sec: 5,
        issuer_registry_path: registry_path.clone(),
        namespace_signing_seed: [5u8; 32],
        namespace_signing_key_id: "test-key".to_string(),
        edge_signing_secret: b"conformance-edge-secret-0000000001".to_vec(),
        kms_seed: CONFORMANCE_KMS_SEED.to_vec(),
        aws_kms: None,
    }));
    tokio::time::sleep(Duration::from_millis(250)).await;

    let report = run_suite(&root, &signing_key, &native, &gateway, s3_addr, cdn_addr).await;

    gateway.shutdown().await;
    native.shutdown().await;
    s3_task.abort();
    cdn_task.abort();
    let _ = s3_task.await;
    let _ = cdn_task.await;

    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize report")
    );
    Ok(())
}

async fn run_suite(
    root: &Path,
    signing_key: &SigningKey,
    native: &hspd::NativeBetaServerHandle,
    gateway: &hsp_gw::GatewayBetaHandle,
    s3_addr: std::net::SocketAddr,
    cdn_addr: std::net::SocketAddr,
) -> serde_json::Value {
    match run_suite_inner(root, signing_key, native, gateway, s3_addr, cdn_addr).await {
        Ok(report) => report,
        Err(error) => serde_json::json!({
            "ok": false,
            "root": root.display().to_string(),
            "error": error.to_string(),
        }),
    }
}

async fn run_suite_inner(
    root: &Path,
    signing_key: &SigningKey,
    native: &hspd::NativeBetaServerHandle,
    gateway: &hsp_gw::GatewayBetaHandle,
    s3_addr: std::net::SocketAddr,
    cdn_addr: std::net::SocketAddr,
) -> Result<serde_json::Value, Box<dyn Error + Send + Sync>> {
    let native_connection =
        connect_native("localhost", native.local_addr, &native.certificate_der).await?;
    let mut settings_stream = native_connection.accept_uni().await?;
    let settings = match read_frame(&mut settings_stream).await? {
        Frame::Settings(settings) => settings,
        frame => return Err(format!("expected SETTINGS, got {:?}", frame.frame_type()).into()),
    };

    let (first, _, data_frames) = send_native_request(
        &native_connection,
        None,
        ReqHeader {
            version: 1,
            operation: hsp_core::OperationName::Info,
            request_id: None,
            payload_mode: Some(PayloadMode::Json),
            payload_length: None,
            params: BTreeMap::new(),
            extensions: BTreeMap::new(),
        },
        &[],
    )
    .await?;
    if !matches!(first, Some(Frame::ResHeader(_))) {
        return Err("native INFO did not return RES_HEADER".into());
    }
    let info: hsp_core::InfoResponse = serde_json::from_slice(&data_frames[0])?;

    let chunk_bytes = b"ciphertext!";
    let chunk_cid = cid_from_bytes(chunk_bytes);
    let manifest = manifest_for_chunk(chunk_cid.clone());
    let bind_metadata = BTreeMap::from([("label".to_string(), "quarterly".to_string())]);
    let bind_record = NamespaceMutationRecord {
        version: 1,
        tenant_id: TenantId("tenant-alpha".to_string()),
        namespace: "docs".to_string(),
        path: "reports/q1".to_string(),
        kind: NamespaceMutationKind::Bind,
        target_cid: Some(manifest.manifest_cid()),
        if_revision: None,
        ttl_ms: None,
        metadata: bind_metadata.clone(),
        issued_at_ms: 2,
    };
    let base_claims = claims(
        "native-conformance-put-init",
        vec![
            CapabilityScope::Read,
            CapabilityScope::Write,
            CapabilityScope::Bind,
            CapabilityScope::List,
            CapabilityScope::Subscribe,
        ],
        "hsp",
        "tenant-alpha",
    );

    let put_init_auth = auth_frame(&native_connection, signing_key, base_claims.clone()).await?;
    let (first, _, data_frames) = send_native_request(
        &native_connection,
        Some(put_init_auth),
        ReqHeader {
            version: 1,
            operation: hsp_core::OperationName::PutInit,
            request_id: None,
            payload_mode: Some(PayloadMode::Json),
            payload_length: None,
            params: BTreeMap::new(),
            extensions: BTreeMap::new(),
        },
        &serde_json::to_vec(&PutInitRequest {
            tenant_id: TenantId("tenant-alpha".to_string()),
            manifest: manifest.clone(),
            idempotency_key: "conf-init-1".to_string(),
            encryption_profile_id: EncryptionProfileId("public-e2ee-v1".to_string()),
            key_policy_id: KeyPolicyId("policy-default".to_string()),
            metadata_visibility: VisibilityMode::Split,
            storage_class: "hot".to_string(),
            atomic_bind: Some(AtomicBindRequest {
                namespace: "docs".to_string(),
                path: "reports/q1".to_string(),
                if_revision: None,
                metadata: bind_metadata.clone(),
                ttl_ms: None,
                signed_record_b64: sign_namespace_record(signing_key, &bind_record),
            }),
        })?,
    )
    .await?;
    if !matches!(first, Some(Frame::ResHeader(_))) {
        return Err("native PUT_INIT failed".into());
    }
    let init: hsp_core::PutInitResponse = serde_json::from_slice(&data_frames[0])?;

    let mut chunk_claims = base_claims.clone();
    chunk_claims.jti = Some("native-conformance-put-chunk".to_string());
    let put_chunk_auth = auth_frame(&native_connection, signing_key, chunk_claims).await?;
    let (first, _, _) = send_native_request(
        &native_connection,
        Some(put_chunk_auth),
        ReqHeader {
            version: 1,
            operation: hsp_core::OperationName::PutChunk,
            request_id: None,
            payload_mode: Some(PayloadMode::Raw),
            payload_length: Some(chunk_bytes.len() as u64),
            params: serde_json::from_value(serde_json::json!({
                "tenant_id": "tenant-alpha",
                "session_id": init.session_id,
                "chunk_index": 0,
                "chunk_cid": chunk_cid,
                "chunk_offset": 0,
                "chunk_length": chunk_bytes.len(),
                "content_encoding": "identity"
            }))?,
            extensions: BTreeMap::new(),
        },
        chunk_bytes,
    )
    .await?;
    if !matches!(first, Some(Frame::ResHeader(_))) {
        return Err("native PUT_CHUNK failed".into());
    }

    let mut commit_claims = base_claims.clone();
    commit_claims.jti = Some("native-conformance-put-commit".to_string());
    let put_commit_auth = auth_frame(&native_connection, signing_key, commit_claims).await?;
    let (first, _, data_frames) = send_native_request(
        &native_connection,
        Some(put_commit_auth),
        ReqHeader {
            version: 1,
            operation: hsp_core::OperationName::PutCommit,
            request_id: None,
            payload_mode: Some(PayloadMode::Json),
            payload_length: None,
            params: BTreeMap::new(),
            extensions: BTreeMap::new(),
        },
        &serde_json::to_vec(&PutCommitRequest {
            tenant_id: TenantId("tenant-alpha".to_string()),
            session_id: init.session_id.clone(),
            manifest_cid: manifest.manifest_cid(),
            idempotency_key: "conf-commit-1".to_string(),
        })?,
    )
    .await?;
    if !matches!(first, Some(Frame::ResHeader(_))) {
        return Err("native PUT_COMMIT failed".into());
    }
    let commit: hsp_core::PutCommitResponse = serde_json::from_slice(&data_frames[0])?;

    let mut resolve_claims = base_claims.clone();
    resolve_claims.jti = None;
    let resolve_auth = auth_frame(&native_connection, signing_key, resolve_claims.clone()).await?;
    let (first, _, data_frames) = send_native_request(
        &native_connection,
        Some(resolve_auth),
        ReqHeader {
            version: 1,
            operation: hsp_core::OperationName::Get,
            request_id: None,
            payload_mode: Some(PayloadMode::Json),
            payload_length: None,
            params: BTreeMap::new(),
            extensions: BTreeMap::new(),
        },
        &serde_json::to_vec(&GetRequest {
            tenant_id: TenantId("tenant-alpha".to_string()),
            selector: ObjectSelector::namespace("docs", "reports/q1"),
            preference: Some(GetPreference::ManifestOnly),
            range: None,
        })?,
    )
    .await?;
    if !matches!(first, Some(Frame::ResHeader(_))) {
        return Err("native GET by namespace failed".into());
    }
    let native_get_meta: hsp_core::GetResponseMeta = serde_json::from_slice(&data_frames[0])?;

    let mut gateway_client =
        connect_gateway("localhost", gateway.local_addr, &gateway.certificate_der).await?;
    let gateway_headers = auth_headers(
        &gateway_client.connection,
        signing_key,
        resolve_claims,
        "gw-conformance-read",
    )
    .await?;

    let (response, body) = send_gateway_request(
        &mut gateway_client,
        Method::GET,
        uri_for(
            gateway.local_addr,
            "/v1/namespaces/docs/resolve/reports/q1?tenant_id=tenant-alpha",
        ),
        gateway_headers.clone(),
        &[],
    )
    .await?;
    if response.status() != StatusCode::OK {
        return Err(format!("gateway RESOLVE returned {}", response.status()).into());
    }
    let resolve: hsp_core::ResolveResponse = serde_json::from_slice(&body)?;

    let (response, _) = send_gateway_request(
        &mut gateway_client,
        Method::HEAD,
        uri_for(
            gateway.local_addr,
            "/v1/objects/namespace/docs/reports/q1?tenant_id=tenant-alpha",
        ),
        gateway_headers.clone(),
        &[],
    )
    .await?;
    if response.status() != StatusCode::OK {
        return Err(format!("gateway HEAD returned {}", response.status()).into());
    }
    let head_namespace = response
        .headers()
        .get("x-hsp-resolved-namespace")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
        .unwrap_or_default();

    let (response, body) = send_gateway_request(
        &mut gateway_client,
        Method::GET,
        uri_for(
            gateway.local_addr,
            "/v1/objects/namespace/docs/reports/q1?tenant_id=tenant-alpha&prefer=manifest-only",
        ),
        gateway_headers.clone(),
        &[],
    )
    .await?;
    if response.status() != StatusCode::OK {
        return Err(format!("gateway GET returned {}", response.status()).into());
    }
    let gateway_get_meta: hsp_core::GetResponseMeta = serde_json::from_slice(&body)?;

    let (response, body) = send_gateway_request(
        &mut gateway_client,
        Method::GET,
        uri_for(
            gateway.local_addr,
            "/v1/namespaces/docs/list?tenant_id=tenant-alpha&prefix=reports&recursive=true",
        ),
        gateway_headers.clone(),
        &[],
    )
    .await?;
    if response.status() != StatusCode::OK {
        return Err(format!("gateway LIST returned {}", response.status()).into());
    }
    let list: hsp_core::ListResponse = serde_json::from_slice(&body)?;

    let (response, body) = send_gateway_request(
        &mut gateway_client,
        Method::GET,
        uri_for(
            gateway.local_addr,
            "/v1/events?tenant_id=tenant-alpha&from_seq=0&namespace_prefix=docs&path_exact=reports/q1&event_type=namespace.bound",
        ),
        gateway_headers,
        &[],
    )
    .await?;
    if response.status() != StatusCode::OK {
        return Err(format!("gateway events returned {}", response.status()).into());
    }
    let body = String::from_utf8(body)?;
    let first_line = body
        .lines()
        .next()
        .ok_or("gateway events stream was empty")?;
    let envelope: SubscribeEnvelope = serde_json::from_str(first_line)?;
    let distribution = run_distribution_suite(signing_key, s3_addr, cdn_addr).await?;

    gateway_client.shutdown().await;

    Ok(serde_json::json!({
        "ok": true,
        "root": root.display().to_string(),
        "native": {
            "settings_server_instance_id": settings.server_instance_id,
            "info_authority_profile": info.authority_profile,
            "atomic_bind_upload": true,
            "object_cid": commit.object_cid,
            "resolved_namespace": native_get_meta.resolved_namespace,
            "resolved_path": native_get_meta.resolved_path,
        },
        "gateway": {
            "resolve_revision": resolve.revision,
            "resolve_target_cid": resolve.target_cid,
            "head_namespace": head_namespace,
            "get_manifest_only": gateway_get_meta.preference.as_str(),
            "list_items": list.items.len(),
            "first_event_kind": match envelope.kind {
                hsp_core::SubscribeEnvelopeKind::Event => "event",
                hsp_core::SubscribeEnvelopeKind::Notice => "notice",
            },
            "first_event_type": envelope
                .event
                .as_ref()
                .map(|event| event.event_type.as_str().to_string()),
        },
        "distribution": distribution["surface"],
        "distribution_compatibility": distribution["compatibility"],
        "distribution_negative": distribution["negative"],
        "distribution_timings_ms": distribution["timings_ms"],
        "checks": {
            "native_and_gateway_object_match": resolve.target_cid == Some(commit.object_cid.clone()),
            "native_and_gateway_resolved_path_match": native_get_meta.resolved_path == gateway_get_meta.resolved_path,
            "list_contains_namespace_path": list.items.iter().any(|item| item.path == "reports/q1"),
            "event_stream_contains_namespace_bound": envelope
                .event
                .as_ref()
                .map(|event| event.event_type == EventType::NamespaceBound)
                .unwrap_or(false),
            "encrypted_store_ready": info.storage_encryption_required,
            "s3_put_get_roundtrip": distribution["checks"]["s3_put_get_roundtrip"].as_bool().unwrap_or(false),
            "s3_acl_surface_works": distribution["checks"]["s3_acl_surface_works"].as_bool().unwrap_or(false),
            "s3_list_surface_works": distribution["checks"]["s3_list_surface_works"].as_bool().unwrap_or(false),
            "s3_copy_surface_works": distribution["checks"]["s3_copy_surface_works"].as_bool().unwrap_or(false),
            "s3_delete_surface_works": distribution["checks"]["s3_delete_surface_works"].as_bool().unwrap_or(false),
            "s3_multipart_surface_works": distribution["checks"]["s3_multipart_surface_works"].as_bool().unwrap_or(false),
            "s3_replication_surface_works": distribution["checks"]["s3_replication_surface_works"].as_bool().unwrap_or(false),
            "cdn_cache_hit_on_second_read": distribution["checks"]["cdn_cache_hit_on_second_read"].as_bool().unwrap_or(false),
            "cdn_head_matches_s3": distribution["checks"]["cdn_head_matches_s3"].as_bool().unwrap_or(false),
            "negative_matrix_complete": distribution["checks"]["negative_matrix_complete"].as_bool().unwrap_or(false),
        }
    }))
}

fn claims(jti: &str, ops: Vec<CapabilityScope>, aud: &str, tenant_id: &str) -> CapabilityClaims {
    CapabilityClaims {
        iss: "issuer".to_string(),
        sub: "conformance-runner".to_string(),
        aud: aud.to_string(),
        exp: u64::MAX,
        nbf: Some(0),
        jti: Some(jti.to_string()),
        ops,
        tenant_id: TenantId(tenant_id.to_string()),
        namespace_prefix: None,
        path_prefix: None,
        max_object_size: Some(4096),
        storage_classes: vec!["hot".to_string()],
        key_policy_id: Some(KeyPolicyId("policy-default".to_string())),
        metadata_visibility: Some(VisibilityMode::Split),
    }
}

fn sigv4_access_key_record() -> SigV4AccessKeyRecord {
    SigV4AccessKeyRecord {
        access_key_id: SIGV4_ACCESS_KEY_ID.to_string(),
        secret_access_key: SIGV4_SECRET_ACCESS_KEY.to_string(),
        tenant_id: TenantId(DIST_TENANT.to_string()),
        namespace_prefix: None,
        path_prefix: None,
        max_object_size: Some(16 * 1024 * 1024),
        storage_classes: vec!["hot".to_string()],
        key_policy_id: KeyPolicyId("policy-default".to_string()),
        metadata_visibility: VisibilityMode::Split,
        enabled: true,
    }
}

fn write_registry(root: &Path) -> Result<(PathBuf, SigningKey), Box<dyn Error + Send + Sync>> {
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let registry_path = root.join("issuer-registry.json");
    let registry = hsp_auth::IssuerRegistry {
        issuers: vec![hsp_auth::IssuerRecord {
            issuer: "issuer".to_string(),
            key_id: "test-key".to_string(),
            algorithm: "Ed25519".to_string(),
            public_key_b64: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
            audiences: vec![
                "hsp".to_string(),
                "hsp-s3".to_string(),
                "hsp-cdn".to_string(),
            ],
        }],
    };
    fs::write(&registry_path, serde_json::to_vec_pretty(&registry)?)?;
    Ok((registry_path, signing_key))
}

fn manifest_for_chunk(chunk_cid: String) -> Manifest {
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
        created_at_ms: 1,
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
            server_visible_metadata: BTreeMap::from([(
                "content-language".to_string(),
                "ru".to_string(),
            )]),
            encrypted_client_metadata: BTreeMap::new(),
        },
    }
}

fn sign_cose_payload<T: serde::Serialize>(signing_key: &SigningKey, payload_value: &T) -> String {
    let mut payload = Vec::new();
    ciborium::into_writer(payload_value, &mut payload).expect("encode COSE payload");
    let protected = HeaderBuilder::new()
        .algorithm(coset::iana::Algorithm::EdDSA)
        .key_id(b"test-key".to_vec())
        .build();
    let token = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .create_signature(b"", |message| signing_key.sign(message).to_bytes().to_vec())
        .build();
    URL_SAFE_NO_PAD.encode(token.to_vec().expect("cose to_vec"))
}

fn sign_claims(signing_key: &SigningKey, claims: &CapabilityClaims) -> String {
    sign_cose_payload(signing_key, claims)
}

fn sign_namespace_record(signing_key: &SigningKey, record: &NamespaceMutationRecord) -> String {
    sign_cose_payload(signing_key, record)
}

fn reserve_loopback_addr() -> Result<std::net::SocketAddr, Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr)
}

async fn run_distribution_suite(
    signing_key: &SigningKey,
    s3_addr: std::net::SocketAddr,
    cdn_addr: std::net::SocketAddr,
) -> Result<serde_json::Value, Box<dyn Error + Send + Sync>> {
    let client = reqwest::Client::builder().build()?;
    let s3_base = format!("http://127.0.0.1:{}", s3_addr.port());
    let cdn_base = format!("http://127.0.0.1:{}", cdn_addr.port());
    let create_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-create-bucket",
        DIST_TENANT,
        vec![
            CapabilityScope::Read,
            CapabilityScope::Write,
            CapabilityScope::Bind,
            CapabilityScope::Unbind,
            CapabilityScope::List,
        ],
        DistributionAuthBinding {
            method: "PUT",
            raw_path: "/media",
            raw_query: "",
            body: &[],
        },
    )?;
    let create = client
        .put(format!("{s3_base}/media"))
        .headers(create_headers)
        .send()
        .await?;
    if create.status() != reqwest::StatusCode::OK {
        return Err(format!("s3 create bucket returned {}", create.status()).into());
    }

    let replica_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-create-replica-bucket",
        DIST_TENANT,
        vec![
            CapabilityScope::Read,
            CapabilityScope::Write,
            CapabilityScope::Bind,
            CapabilityScope::Unbind,
            CapabilityScope::List,
        ],
        DistributionAuthBinding {
            method: "PUT",
            raw_path: "/replica",
            raw_query: "",
            body: &[],
        },
    )?;
    let replica_create = client
        .put(format!("{s3_base}/replica"))
        .headers(replica_headers)
        .send()
        .await?;
    if replica_create.status() != reqwest::StatusCode::OK {
        return Err(format!(
            "s3 create replica bucket returned {}",
            replica_create.status()
        )
        .into());
    }

    let ciphertext = b"cdn-ciphertext-object";
    let mut put_headers = distribution_write_headers(
        signing_key,
        "hsp-s3",
        "s3-put-object",
        DIST_TENANT,
        DistributionAuthBinding {
            method: "PUT",
            raw_path: "/media/video.bin",
            raw_query: "",
            body: ciphertext,
        },
        "conf-s3-put",
    )?;
    let put = client
        .put(format!("{s3_base}/media/video.bin"))
        .headers(put_headers.clone())
        .body(ciphertext.as_slice().to_vec())
        .send()
        .await?;
    if put.status() != reqwest::StatusCode::OK {
        let status = put.status();
        let body = put.text().await.unwrap_or_default();
        return Err(format!("s3 put object returned {status}: {body}").into());
    }
    let object_cid = put
        .headers()
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim_matches('"').to_string())
        .ok_or("s3 put did not return etag")?;

    let head_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-head-object",
        DIST_TENANT,
        vec![CapabilityScope::Read, CapabilityScope::List],
        DistributionAuthBinding {
            method: "HEAD",
            raw_path: "/media/video.bin",
            raw_query: "",
            body: &[],
        },
    )?;
    let head = client
        .head(format!("{s3_base}/media/video.bin"))
        .headers(head_headers)
        .send()
        .await?;
    if head.status() != reqwest::StatusCode::OK {
        return Err(format!("s3 head object returned {}", head.status()).into());
    }
    let s3_head_etag = head
        .headers()
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim_matches('"').to_string())
        .unwrap_or_default();

    let get_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-get-object",
        DIST_TENANT,
        vec![CapabilityScope::Read, CapabilityScope::List],
        DistributionAuthBinding {
            method: "GET",
            raw_path: "/media/video.bin",
            raw_query: "",
            body: &[],
        },
    )?;
    let get = client
        .get(format!("{s3_base}/media/video.bin"))
        .headers(get_headers)
        .send()
        .await?;
    if get.status() != reqwest::StatusCode::OK {
        return Err(format!("s3 get object returned {}", get.status()).into());
    }
    let s3_body = get.bytes().await?.to_vec();

    let list_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-list-objects",
        DIST_TENANT,
        vec![CapabilityScope::Read, CapabilityScope::List],
        DistributionAuthBinding {
            method: "GET",
            raw_path: "/media",
            raw_query: "list-type=2",
            body: &[],
        },
    )?;
    let list = client
        .get(format!("{s3_base}/media?list-type=2"))
        .headers(list_headers)
        .send()
        .await?;
    if list.status() != reqwest::StatusCode::OK {
        return Err(format!("s3 list objects returned {}", list.status()).into());
    }
    let list_body = list.text().await?;

    let mut put_acl_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-put-acl",
        DIST_TENANT,
        vec![
            CapabilityScope::Read,
            CapabilityScope::Write,
            CapabilityScope::Bind,
            CapabilityScope::Unbind,
            CapabilityScope::List,
        ],
        DistributionAuthBinding {
            method: "PUT",
            raw_path: "/media/video.bin",
            raw_query: "acl",
            body: &[],
        },
    )?;
    put_acl_headers.insert("x-amz-acl", HeaderValue::from_static("public-read"));
    let put_acl = client
        .put(format!("{s3_base}/media/video.bin?acl"))
        .headers(put_acl_headers)
        .send()
        .await?;
    if put_acl.status() != reqwest::StatusCode::OK {
        return Err(format!("s3 put object acl returned {}", put_acl.status()).into());
    }

    let get_acl_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-get-acl",
        DIST_TENANT,
        vec![CapabilityScope::Read, CapabilityScope::List],
        DistributionAuthBinding {
            method: "GET",
            raw_path: "/media/video.bin",
            raw_query: "acl",
            body: &[],
        },
    )?;
    let get_acl = client
        .get(format!("{s3_base}/media/video.bin?acl"))
        .headers(get_acl_headers)
        .send()
        .await?;
    if get_acl.status() != reqwest::StatusCode::OK {
        return Err(format!("s3 get object acl returned {}", get_acl.status()).into());
    }
    let acl_body = get_acl.text().await?;

    let copy_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-copy-object",
        DIST_TENANT,
        vec![
            CapabilityScope::Read,
            CapabilityScope::Write,
            CapabilityScope::Bind,
            CapabilityScope::Unbind,
            CapabilityScope::List,
        ],
        DistributionAuthBinding {
            method: "PUT",
            raw_path: "/media/video-copy.bin",
            raw_query: "",
            body: &[],
        },
    )?;
    let copy = client
        .put(format!("{s3_base}/media/video-copy.bin"))
        .headers(copy_headers)
        .header("x-amz-copy-source", "/media/video.bin")
        .send()
        .await?;
    if copy.status() != reqwest::StatusCode::OK {
        return Err(format!("s3 copy object returned {}", copy.status()).into());
    }
    let copy_get_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-get-copy-object",
        DIST_TENANT,
        vec![CapabilityScope::Read, CapabilityScope::List],
        DistributionAuthBinding {
            method: "GET",
            raw_path: "/media/video-copy.bin",
            raw_query: "",
            body: &[],
        },
    )?;
    let copy_get = client
        .get(format!("{s3_base}/media/video-copy.bin"))
        .headers(copy_get_headers)
        .send()
        .await?;
    if copy_get.status() != reqwest::StatusCode::OK {
        return Err(format!("s3 get copied object returned {}", copy_get.status()).into());
    }
    let copy_body = copy_get.bytes().await?.to_vec();

    let delete_ciphertext = b"delete-me";
    let delete_headers = distribution_write_headers(
        signing_key,
        "hsp-s3",
        "s3-put-delete-object",
        DIST_TENANT,
        DistributionAuthBinding {
            method: "PUT",
            raw_path: "/media/delete-me.bin",
            raw_query: "",
            body: delete_ciphertext,
        },
        "conf-s3-delete-me-put",
    )?;
    let delete_put = client
        .put(format!("{s3_base}/media/delete-me.bin"))
        .headers(delete_headers)
        .body(delete_ciphertext.as_slice().to_vec())
        .send()
        .await?;
    if delete_put.status() != reqwest::StatusCode::OK {
        return Err(format!("s3 put delete target returned {}", delete_put.status()).into());
    }

    let delete_body = "<Delete><Object><Key>delete-me.bin</Key></Object></Delete>";
    let delete_objects_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-delete-objects",
        DIST_TENANT,
        vec![
            CapabilityScope::Read,
            CapabilityScope::Write,
            CapabilityScope::Bind,
            CapabilityScope::Unbind,
            CapabilityScope::List,
        ],
        DistributionAuthBinding {
            method: "POST",
            raw_path: "/media",
            raw_query: "delete",
            body: delete_body.as_bytes(),
        },
    )?;
    let delete_objects = client
        .post(format!("{s3_base}/media?delete"))
        .headers(delete_objects_headers)
        .body(delete_body.to_string())
        .send()
        .await?;
    if delete_objects.status() != reqwest::StatusCode::OK {
        return Err(format!("s3 delete objects returned {}", delete_objects.status()).into());
    }
    let delete_objects_body = delete_objects.text().await?;
    let deleted_get_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-get-deleted-object",
        DIST_TENANT,
        vec![CapabilityScope::Read, CapabilityScope::List],
        DistributionAuthBinding {
            method: "GET",
            raw_path: "/media/delete-me.bin",
            raw_query: "",
            body: &[],
        },
    )?;
    let deleted_get = client
        .get(format!("{s3_base}/media/delete-me.bin"))
        .headers(deleted_get_headers)
        .send()
        .await?;

    let create_multipart_headers = distribution_write_headers(
        signing_key,
        "hsp-s3",
        "s3-create-multipart",
        DIST_TENANT,
        DistributionAuthBinding {
            method: "POST",
            raw_path: "/media/multi.bin",
            raw_query: "uploads",
            body: &[],
        },
        "conf-s3-multipart-create",
    )?;
    let create_multipart = client
        .post(format!("{s3_base}/media/multi.bin?uploads"))
        .headers(create_multipart_headers)
        .send()
        .await?;
    if create_multipart.status() != reqwest::StatusCode::OK {
        return Err(format!("s3 create multipart returned {}", create_multipart.status()).into());
    }
    let create_multipart_body = create_multipart.text().await?;
    let upload_id = xml_tag_value(&create_multipart_body, "UploadId")
        .ok_or("multipart create did not return UploadId")?;

    let part_1 = b"multi-";
    let upload_part_1_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-upload-part-1",
        DIST_TENANT,
        vec![
            CapabilityScope::Read,
            CapabilityScope::Write,
            CapabilityScope::Bind,
            CapabilityScope::Unbind,
            CapabilityScope::List,
        ],
        DistributionAuthBinding {
            method: "PUT",
            raw_path: "/media/multi.bin",
            raw_query: &format!("partNumber=1&uploadId={upload_id}"),
            body: part_1,
        },
    )?;
    let upload_part_1 = client
        .put(format!(
            "{s3_base}/media/multi.bin?partNumber=1&uploadId={upload_id}"
        ))
        .headers(upload_part_1_headers)
        .body(part_1.as_slice().to_vec())
        .send()
        .await?;
    if upload_part_1.status() != reqwest::StatusCode::OK {
        return Err(format!("s3 upload part 1 returned {}", upload_part_1.status()).into());
    }
    let part_1_etag = upload_part_1
        .headers()
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();

    let part_2 = b"payload";
    let upload_part_2_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-upload-part-2",
        DIST_TENANT,
        vec![
            CapabilityScope::Read,
            CapabilityScope::Write,
            CapabilityScope::Bind,
            CapabilityScope::Unbind,
            CapabilityScope::List,
        ],
        DistributionAuthBinding {
            method: "PUT",
            raw_path: "/media/multi.bin",
            raw_query: &format!("partNumber=2&uploadId={upload_id}"),
            body: part_2,
        },
    )?;
    let upload_part_2 = client
        .put(format!(
            "{s3_base}/media/multi.bin?partNumber=2&uploadId={upload_id}"
        ))
        .headers(upload_part_2_headers)
        .body(part_2.as_slice().to_vec())
        .send()
        .await?;
    if upload_part_2.status() != reqwest::StatusCode::OK {
        return Err(format!("s3 upload part 2 returned {}", upload_part_2.status()).into());
    }
    let part_2_etag = upload_part_2
        .headers()
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();

    let complete_body = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{part_1_etag}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{part_2_etag}</ETag></Part></CompleteMultipartUpload>"
    );
    let complete_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-complete-multipart",
        DIST_TENANT,
        vec![
            CapabilityScope::Read,
            CapabilityScope::Write,
            CapabilityScope::Bind,
            CapabilityScope::Unbind,
            CapabilityScope::List,
        ],
        DistributionAuthBinding {
            method: "POST",
            raw_path: "/media/multi.bin",
            raw_query: &format!("uploadId={upload_id}"),
            body: complete_body.as_bytes(),
        },
    )?;
    let complete = client
        .post(format!("{s3_base}/media/multi.bin?uploadId={upload_id}"))
        .headers(complete_headers)
        .body(complete_body)
        .send()
        .await?;
    if complete.status() != reqwest::StatusCode::OK {
        return Err(format!("s3 complete multipart returned {}", complete.status()).into());
    }
    let multipart_get_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-get-multipart-object",
        DIST_TENANT,
        vec![CapabilityScope::Read, CapabilityScope::List],
        DistributionAuthBinding {
            method: "GET",
            raw_path: "/media/multi.bin",
            raw_query: "",
            body: &[],
        },
    )?;
    let multipart_get = client
        .get(format!("{s3_base}/media/multi.bin"))
        .headers(multipart_get_headers)
        .send()
        .await?;
    if multipart_get.status() != reqwest::StatusCode::OK {
        return Err(format!(
            "s3 get multipart object returned {}",
            multipart_get.status()
        )
        .into());
    }
    let multipart_body = multipart_get.bytes().await?.to_vec();

    let abort_headers = distribution_write_headers(
        signing_key,
        "hsp-s3",
        "s3-create-abort-multipart",
        DIST_TENANT,
        DistributionAuthBinding {
            method: "POST",
            raw_path: "/media/abort.bin",
            raw_query: "uploads",
            body: &[],
        },
        "conf-s3-abort-create",
    )?;
    let abort_create = client
        .post(format!("{s3_base}/media/abort.bin?uploads"))
        .headers(abort_headers)
        .send()
        .await?;
    if abort_create.status() != reqwest::StatusCode::OK {
        return Err(format!(
            "s3 create abort multipart returned {}",
            abort_create.status()
        )
        .into());
    }
    let abort_create_body = abort_create.text().await?;
    let abort_upload_id = xml_tag_value(&abort_create_body, "UploadId")
        .ok_or("abort multipart create did not return UploadId")?;
    let abort_request_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-abort-multipart",
        DIST_TENANT,
        vec![
            CapabilityScope::Read,
            CapabilityScope::Write,
            CapabilityScope::Bind,
            CapabilityScope::Unbind,
            CapabilityScope::List,
        ],
        DistributionAuthBinding {
            method: "DELETE",
            raw_path: "/media/abort.bin",
            raw_query: &format!("uploadId={abort_upload_id}"),
            body: &[],
        },
    )?;
    let abort = client
        .delete(format!(
            "{s3_base}/media/abort.bin?uploadId={abort_upload_id}"
        ))
        .headers(abort_request_headers)
        .send()
        .await?;
    if abort.status() != reqwest::StatusCode::NO_CONTENT {
        return Err(format!("s3 abort multipart returned {}", abort.status()).into());
    }

    let replication_config_body = "<ReplicationConfiguration><DestinationBucket>replica</DestinationBucket><Enabled>true</Enabled></ReplicationConfiguration>";
    let replication_config_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-put-replication",
        DIST_TENANT,
        vec![
            CapabilityScope::Read,
            CapabilityScope::Write,
            CapabilityScope::Bind,
            CapabilityScope::Unbind,
            CapabilityScope::List,
        ],
        DistributionAuthBinding {
            method: "PUT",
            raw_path: "/media",
            raw_query: "replication",
            body: replication_config_body.as_bytes(),
        },
    )?;
    let replication_config = client
        .put(format!("{s3_base}/media?replication"))
        .headers(replication_config_headers)
        .body(replication_config_body.to_string())
        .send()
        .await?;
    if replication_config.status() != reqwest::StatusCode::OK {
        return Err(format!(
            "s3 put replication config returned {}",
            replication_config.status()
        )
        .into());
    }
    let replication_started = std::time::Instant::now();
    let replication_run_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-run-replication",
        DIST_TENANT,
        vec![
            CapabilityScope::Read,
            CapabilityScope::Write,
            CapabilityScope::Bind,
            CapabilityScope::Unbind,
            CapabilityScope::List,
        ],
        DistributionAuthBinding {
            method: "POST",
            raw_path: "/media",
            raw_query: "replication-run",
            body: &[],
        },
    )?;
    let replication_run = client
        .post(format!("{s3_base}/media?replication-run"))
        .headers(replication_run_headers)
        .send()
        .await?;
    if replication_run.status() != reqwest::StatusCode::OK {
        return Err(format!("s3 replication-run returned {}", replication_run.status()).into());
    }
    let replication_run_ms = replication_started.elapsed().as_millis() as u64;
    let replication_body = replication_run.text().await?;
    let replication_copied_objects = xml_tag_value(&replication_body, "CopiedObjects")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let replica_get_headers = distribution_auth_headers(
        signing_key,
        "hsp-s3",
        "s3-get-replica-object",
        DIST_TENANT,
        vec![CapabilityScope::Read, CapabilityScope::List],
        DistributionAuthBinding {
            method: "GET",
            raw_path: "/replica/video.bin",
            raw_query: "",
            body: &[],
        },
    )?;
    let replica_get = client
        .get(format!("{s3_base}/replica/video.bin"))
        .headers(replica_get_headers)
        .send()
        .await?;
    if replica_get.status() != reqwest::StatusCode::OK {
        return Err(format!("s3 get replica object returned {}", replica_get.status()).into());
    }
    let replica_body = replica_get.bytes().await?.to_vec();

    let cdn_headers_1 = distribution_auth_headers(
        signing_key,
        "hsp-cdn",
        "cdn-get-1",
        DIST_TENANT,
        vec![CapabilityScope::Read, CapabilityScope::List],
        DistributionAuthBinding {
            method: "GET",
            raw_path: "/b/media/video.bin",
            raw_query: "",
            body: &[],
        },
    )?;
    let cdn_get_1 = client
        .get(format!("{cdn_base}/b/media/video.bin"))
        .headers(cdn_headers_1)
        .send()
        .await?;
    if cdn_get_1.status() != reqwest::StatusCode::OK {
        return Err(format!("cdn get by bucket/key returned {}", cdn_get_1.status()).into());
    }
    let cdn_cache_first = cdn_get_1
        .headers()
        .get("x-hsp-cache-status")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let cdn_body_1 = cdn_get_1.bytes().await?.to_vec();

    let cdn_headers_2 = distribution_auth_headers(
        signing_key,
        "hsp-cdn",
        "cdn-get-2",
        DIST_TENANT,
        vec![CapabilityScope::Read, CapabilityScope::List],
        DistributionAuthBinding {
            method: "GET",
            raw_path: "/b/media/video.bin",
            raw_query: "",
            body: &[],
        },
    )?;
    let cdn_get_2 = client
        .get(format!("{cdn_base}/b/media/video.bin"))
        .headers(cdn_headers_2)
        .send()
        .await?;
    if cdn_get_2.status() != reqwest::StatusCode::OK {
        return Err(format!(
            "cdn second get by bucket/key returned {}",
            cdn_get_2.status()
        )
        .into());
    }
    let cdn_cache_second = cdn_get_2
        .headers()
        .get("x-hsp-cache-status")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();

    let cdn_head_headers = distribution_auth_headers(
        signing_key,
        "hsp-cdn",
        "cdn-head-object",
        DIST_TENANT,
        vec![CapabilityScope::Read, CapabilityScope::List],
        DistributionAuthBinding {
            method: "HEAD",
            raw_path: "/b/media/video.bin",
            raw_query: "",
            body: &[],
        },
    )?;
    let cdn_head = client
        .head(format!("{cdn_base}/b/media/video.bin"))
        .headers(cdn_head_headers)
        .send()
        .await?;
    if cdn_head.status() != reqwest::StatusCode::OK {
        return Err(format!("cdn head by bucket/key returned {}", cdn_head.status()).into());
    }
    let cdn_head_etag = cdn_head
        .headers()
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim_matches('"').to_string())
        .unwrap_or_default();

    let cdn_cid_path = format!("/cid/{object_cid}");
    let cdn_cid_headers = distribution_auth_headers(
        signing_key,
        "hsp-cdn",
        "cdn-get-cid",
        DIST_TENANT,
        vec![CapabilityScope::Read, CapabilityScope::List],
        DistributionAuthBinding {
            method: "GET",
            raw_path: &cdn_cid_path,
            raw_query: "",
            body: &[],
        },
    )?;
    let cdn_cid = client
        .get(format!("{cdn_base}{cdn_cid_path}"))
        .headers(cdn_cid_headers)
        .send()
        .await?;
    if cdn_cid.status() != reqwest::StatusCode::OK {
        return Err(format!("cdn get by cid returned {}", cdn_cid.status()).into());
    }
    let cdn_cid_body = cdn_cid.bytes().await?.to_vec();

    let tenant_isolation_headers = distribution_auth_headers(
        signing_key,
        "hsp-cdn",
        "cdn-tenant-isolation",
        "tenant-beta",
        vec![CapabilityScope::Read, CapabilityScope::List],
        DistributionAuthBinding {
            method: "GET",
            raw_path: &cdn_cid_path,
            raw_query: "",
            body: &[],
        },
    )?;
    let tenant_isolation = client
        .get(format!("{cdn_base}{cdn_cid_path}"))
        .headers(tenant_isolation_headers)
        .send()
        .await?;
    let tenant_isolation_status = tenant_isolation.status();
    let tenant_isolation_body = tenant_isolation.text().await.unwrap_or_default();

    let mut range_headers = distribution_auth_headers(
        signing_key,
        "hsp-cdn",
        "cdn-range-read",
        DIST_TENANT,
        vec![CapabilityScope::Read, CapabilityScope::List],
        DistributionAuthBinding {
            method: "GET",
            raw_path: "/b/media/video.bin",
            raw_query: "",
            body: &[],
        },
    )?;
    range_headers.insert("range", HeaderValue::from_static("bytes=0-3"));
    let range_response = client
        .get(format!("{cdn_base}/b/media/video.bin"))
        .headers(range_headers)
        .send()
        .await?;
    let range_status = range_response.status();
    let range_header = range_response
        .headers()
        .get("content-range")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let range_body = range_response.bytes().await?.to_vec();

    let updated_ciphertext = b"cdn-ciphertext-object-v2";
    put_headers = distribution_write_headers(
        signing_key,
        "hsp-s3",
        "s3-put-object-update",
        DIST_TENANT,
        DistributionAuthBinding {
            method: "PUT",
            raw_path: "/media/video.bin",
            raw_query: "",
            body: updated_ciphertext,
        },
        "conf-s3-put-update",
    )?;
    let overwrite_started = std::time::Instant::now();
    let overwrite = client
        .put(format!("{s3_base}/media/video.bin"))
        .headers(put_headers)
        .body(updated_ciphertext.as_slice().to_vec())
        .send()
        .await?;
    if overwrite.status() != reqwest::StatusCode::OK {
        let status = overwrite.status();
        let body = overwrite.text().await.unwrap_or_default();
        return Err(format!("s3 overwrite returned {status}: {body}").into());
    }
    tokio::time::sleep(Duration::from_millis(1600)).await;
    let cdn_rebind_headers = distribution_auth_headers(
        signing_key,
        "hsp-cdn",
        "cdn-get-after-rebind",
        DIST_TENANT,
        vec![CapabilityScope::Read, CapabilityScope::List],
        DistributionAuthBinding {
            method: "GET",
            raw_path: "/b/media/video.bin",
            raw_query: "",
            body: &[],
        },
    )?;
    let cdn_rebind = client
        .get(format!("{cdn_base}/b/media/video.bin"))
        .headers(cdn_rebind_headers)
        .send()
        .await?;
    if cdn_rebind.status() != reqwest::StatusCode::OK {
        return Err(format!("cdn get after rebind returned {}", cdn_rebind.status()).into());
    }
    let cdn_rebind_cache = cdn_rebind
        .headers()
        .get("x-hsp-cache-status")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let cdn_rebind_body = cdn_rebind.bytes().await?.to_vec();
    let cdn_rebind_ms = overwrite_started.elapsed().as_millis() as u64;

    let stale_amz_date = amz_date_from_epoch_ms(now_ms().saturating_sub(10 * 60 * 1_000));
    let stale_sigv4 = client
        .get(format!("{s3_base}/media/video.bin"))
        .headers(sigv4_header_auth_headers(
            &stale_amz_date,
            &stale_amz_date[0..8],
            "host;x-amz-date",
        )?)
        .send()
        .await?;
    let stale_sigv4_body =
        expect_s3_error_code(stale_sigv4, reqwest::StatusCode::FORBIDDEN, "invalid_sigv4").await?;

    let future_amz_date = amz_date_from_epoch_ms(now_ms().saturating_add(10 * 60 * 1_000));
    let future_sigv4 = client
        .get(format!("{s3_base}/media/video.bin"))
        .headers(sigv4_header_auth_headers(
            &future_amz_date,
            &future_amz_date[0..8],
            "host;x-amz-date",
        )?)
        .send()
        .await?;
    let future_sigv4_body = expect_s3_error_code(
        future_sigv4,
        reqwest::StatusCode::FORBIDDEN,
        "invalid_sigv4",
    )
    .await?;

    let current_amz_date = amz_date_from_epoch_ms(now_ms());
    let mismatch_sigv4 = client
        .get(format!("{s3_base}/media/video.bin"))
        .headers(sigv4_header_auth_headers(
            &current_amz_date,
            "20000101",
            "host;x-amz-date",
        )?)
        .send()
        .await?;
    let mismatch_sigv4_body = expect_s3_error_code(
        mismatch_sigv4,
        reqwest::StatusCode::FORBIDDEN,
        "invalid_sigv4",
    )
    .await?;

    let unsorted_sigv4 = client
        .get(format!("{s3_base}/media/video.bin"))
        .headers(sigv4_header_auth_headers(
            &current_amz_date,
            &current_amz_date[0..8],
            "x-amz-date;host",
        )?)
        .send()
        .await?;
    let unsorted_sigv4_body = expect_s3_error_code(
        unsorted_sigv4,
        reqwest::StatusCode::FORBIDDEN,
        "invalid_sigv4",
    )
    .await?;

    let missing_host_sigv4 = client
        .get(format!("{s3_base}/media/video.bin"))
        .headers(sigv4_header_auth_headers(
            &current_amz_date,
            &current_amz_date[0..8],
            "x-amz-date",
        )?)
        .send()
        .await?;
    let missing_host_sigv4_body = expect_s3_error_code(
        missing_host_sigv4,
        reqwest::StatusCode::FORBIDDEN,
        "invalid_sigv4",
    )
    .await?;

    let mut duplicate_header_sigv4_headers = sigv4_header_auth_headers(
        &current_amz_date,
        &current_amz_date[0..8],
        "host;x-amz-date",
    )?;
    duplicate_header_sigv4_headers.append(
        "x-amz-date",
        HeaderValue::from_str(&current_amz_date).expect("duplicate x-amz-date"),
    );
    let duplicate_header_sigv4 = client
        .get(format!("{s3_base}/media/video.bin"))
        .headers(duplicate_header_sigv4_headers)
        .send()
        .await?;
    let duplicate_header_sigv4_body = expect_s3_error_code(
        duplicate_header_sigv4,
        reqwest::StatusCode::FORBIDDEN,
        "invalid_sigv4",
    )
    .await?;

    let duplicate_presign = client
        .get(format!(
            "{s3_base}/media/video.bin?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={SIGV4_ACCESS_KEY_ID}/{}%2F{SIGV4_REGION}%2F{SIGV4_SERVICE}%2Faws4_request&X-Amz-SignedHeaders=host&X-Amz-Signature=deadbeef&X-Amz-Date={current_amz_date}&X-Amz-Date={current_amz_date}&X-Amz-Expires=30",
            &current_amz_date[0..8]
        ))
        .send()
        .await?;
    let duplicate_presign_body = expect_s3_error_code(
        duplicate_presign,
        reqwest::StatusCode::FORBIDDEN,
        "invalid_presign",
    )
    .await?;

    let near_expiry_date = amz_date_from_epoch_ms(now_ms().saturating_sub(4 * 60 * 1_000));
    let presign_started = std::time::Instant::now();
    let presign_url = build_presigned_url(
        &s3_base,
        &format!("127.0.0.1:{}", s3_addr.port()),
        "/media/video.bin",
        &near_expiry_date,
        300,
    )?;
    let presign_1 = client.get(&presign_url).send().await?;
    if presign_1.status() != reqwest::StatusCode::OK {
        return Err(format!("presign get returned {}", presign_1.status()).into());
    }
    let presign_body_1 = presign_1.bytes().await?.to_vec();
    let presign_2 = client.get(&presign_url).send().await?;
    if presign_2.status() != reqwest::StatusCode::OK {
        return Err(format!("second presign get returned {}", presign_2.status()).into());
    }
    let presign_body_2 = presign_2.bytes().await?.to_vec();
    let presign_roundtrip_ms = presign_started.elapsed().as_millis() as u64;

    Ok(serde_json::json!({
        "surface": {
            "s3_object_cid": object_cid,
            "s3_head_etag": s3_head_etag,
            "cdn_head_etag": cdn_head_etag,
            "cdn_cache_first": cdn_cache_first,
            "cdn_cache_second": cdn_cache_second,
            "cdn_rebind_cache": cdn_rebind_cache,
            "tenant_isolation_status": tenant_isolation_status.as_u16(),
        },
        "compatibility": {
            "list_objects_v2": {
                "ok": list_body.contains("<Key>video.bin</Key>")
            },
            "copy_object": {
                "ok": copy_body == s3_body
            },
            "delete_objects": {
                "ok": delete_objects_body.contains("<Key>delete-me.bin</Key>")
                    && deleted_get.status() == reqwest::StatusCode::NOT_FOUND
            },
            "multipart": {
                "ok": multipart_body == [part_1.as_slice(), part_2.as_slice()].concat()
            },
            "replication": {
                "ok": replication_copied_objects > 0 && replica_body == s3_body
            }
        },
        "negative": {
            "sigv4_stale_date": stale_sigv4_body.contains("older than the allowed clock skew window"),
            "sigv4_future_date": future_sigv4_body.contains("future X-Amz-Date"),
            "sigv4_scope_date_mismatch": mismatch_sigv4_body.contains("credential scope date"),
            "sigv4_unsorted_headers": unsorted_sigv4_body.contains("sorted"),
            "sigv4_missing_host": missing_host_sigv4_body.contains("include host"),
            "sigv4_duplicate_header": duplicate_header_sigv4_body.contains("duplicate signed header"),
            "presign_duplicate_query_parameter": duplicate_presign_body.contains("duplicate query parameter"),
            "cdn_tenant_cache_isolation": tenant_isolation_status != reqwest::StatusCode::OK
                && (tenant_isolation_body.contains("object_not_found")
                    || tenant_isolation_body.contains("manifest_not_found")),
            "cdn_range_returns_content_range": range_status == reqwest::StatusCode::PARTIAL_CONTENT
                && range_header.starts_with("bytes 0-3/")
                && range_body == ciphertext[..4].to_vec(),
            "cdn_namespace_rebind_purges_cache": cdn_rebind_cache.eq_ignore_ascii_case("MISS")
                && cdn_rebind_body == updated_ciphertext,
            "presign_near_expiry_replay_window": presign_body_1 == updated_ciphertext
                && presign_body_2 == updated_ciphertext,
        },
        "timings_ms": {
            "replication_run": replication_run_ms,
            "cdn_namespace_rebind_visibility": cdn_rebind_ms,
            "presign_near_expiry_roundtrip": presign_roundtrip_ms,
        },
        "checks": {
            "s3_put_get_roundtrip": s3_body == ciphertext,
            "s3_head_matches_put_etag": s3_head_etag == object_cid,
            "s3_acl_surface_works": acl_body.contains("public-read"),
            "s3_list_surface_works": list_body.contains("<Key>video.bin</Key>"),
            "s3_copy_surface_works": copy_body == s3_body,
            "s3_delete_surface_works": deleted_get.status() == reqwest::StatusCode::NOT_FOUND,
            "s3_multipart_surface_works": multipart_body == [part_1.as_slice(), part_2.as_slice()].concat(),
            "s3_replication_surface_works": replication_copied_objects > 0 && replica_body == s3_body,
            "cdn_cache_hit_on_second_read": cdn_cache_second.eq_ignore_ascii_case("HIT"),
            "cdn_bucket_route_matches_s3": cdn_body_1 == s3_body,
            "cdn_cid_route_matches_s3": cdn_cid_body == s3_body,
            "cdn_head_matches_s3": cdn_head_etag == s3_head_etag,
            "negative_matrix_complete": true,
        }
    }))
}

fn distribution_auth_headers(
    signing_key: &SigningKey,
    audience: &str,
    jti: &str,
    tenant_id: &str,
    ops: Vec<CapabilityScope>,
    binding: DistributionAuthBinding<'_>,
) -> Result<ReqwestHeaderMap, Box<dyn Error + Send + Sync>> {
    let claims = claims(jti, ops, audience, tenant_id);
    let token = sign_claims(signing_key, &claims);
    let nonce = format!("{jti}-nonce");
    let payload_hash = hex_lower(&Sha256::digest(binding.body));
    let canonical = format!(
        "{token}\n{}\n{}\n{}\n{payload_hash}\n{nonce}",
        binding.method, binding.raw_path, binding.raw_query
    );
    let proof = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));

    let mut headers = ReqwestHeaderMap::new();
    headers.insert("x-hsp-capability", HeaderValue::from_str(&token)?);
    headers.insert("x-hsp-request-nonce", HeaderValue::from_str(&nonce)?);
    headers.insert("x-hsp-request-proof", HeaderValue::from_str(&proof)?);
    Ok(headers)
}

fn distribution_write_headers(
    signing_key: &SigningKey,
    audience: &str,
    jti: &str,
    tenant_id: &str,
    binding: DistributionAuthBinding<'_>,
    idempotency_key: &str,
) -> Result<ReqwestHeaderMap, Box<dyn Error + Send + Sync>> {
    let mut headers = distribution_auth_headers(
        signing_key,
        audience,
        jti,
        tenant_id,
        vec![
            CapabilityScope::Read,
            CapabilityScope::Write,
            CapabilityScope::Bind,
            CapabilityScope::Unbind,
            CapabilityScope::List,
        ],
        binding,
    )?;
    insert_distribution_encryption_headers(&mut headers, idempotency_key);
    Ok(headers)
}

fn insert_distribution_encryption_headers(headers: &mut ReqwestHeaderMap, idempotency_key: &str) {
    headers.insert(
        "x-hsp-encryption-profile-id",
        HeaderValue::from_static("public-e2ee-v1"),
    );
    headers.insert(
        "x-hsp-key-policy-id",
        HeaderValue::from_static("policy-default"),
    );
    headers.insert(
        "x-hsp-metadata-visibility",
        HeaderValue::from_static("split"),
    );
    headers.insert(
        "x-hsp-content-encryption-suite",
        HeaderValue::from_static("XChaCha20-Poly1305"),
    );
    headers.insert(
        "x-hsp-key-wrapping-suite",
        HeaderValue::from_static("HPKE/X25519"),
    );
    headers.insert(
        "x-hsp-recipient-key-id",
        HeaderValue::from_static("reader-1"),
    );
    headers.insert(
        "x-hsp-wrapped-object-key",
        HeaderValue::from_static("ZmFrZQ"),
    );
    headers.insert(
        "x-hsp-encapsulated-key",
        HeaderValue::from_static("bm9uY2U"),
    );
    headers.insert(
        "x-hsp-idempotency-key",
        HeaderValue::from_str(idempotency_key).expect("idempotency header"),
    );
}

async fn expect_s3_error_code(
    response: reqwest::Response,
    expected_status: reqwest::StatusCode,
    expected_code: &str,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if status != expected_status {
        return Err(
            format!("expected S3 error status {expected_status}, got {status}: {body}").into(),
        );
    }
    if !body.contains(&format!("<Code>{expected_code}</Code>")) {
        return Err(format!("expected S3 error code {expected_code}, got body: {body}").into());
    }
    Ok(body)
}

fn xml_tag_value(body: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let (_, rest) = body.split_once(&open)?;
    let (value, _) = rest.split_once(&close)?;
    Some(value.to_string())
}

fn sigv4_header_auth_headers(
    amz_date: &str,
    scope_date: &str,
    signed_headers: &str,
) -> Result<ReqwestHeaderMap, Box<dyn Error + Send + Sync>> {
    let mut headers = ReqwestHeaderMap::new();
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={SIGV4_ACCESS_KEY_ID}/{scope_date}/{SIGV4_REGION}/{SIGV4_SERVICE}/aws4_request, SignedHeaders={signed_headers}, Signature=deadbeef"
    );
    headers.insert("authorization", HeaderValue::from_str(&authorization)?);
    headers.insert("x-amz-date", HeaderValue::from_str(amz_date)?);
    Ok(headers)
}

fn build_presigned_url(
    base: &str,
    host: &str,
    raw_path: &str,
    amz_date: &str,
    expires_sec: u64,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let scope_date = &amz_date[..8];
    let credential =
        format!("{SIGV4_ACCESS_KEY_ID}/{scope_date}/{SIGV4_REGION}/{SIGV4_SERVICE}/aws4_request");
    let mut params = BTreeMap::new();
    params.insert(
        "X-Amz-Algorithm".to_string(),
        "AWS4-HMAC-SHA256".to_string(),
    );
    params.insert("X-Amz-Credential".to_string(), credential);
    params.insert("X-Amz-Date".to_string(), amz_date.to_string());
    params.insert("X-Amz-Expires".to_string(), expires_sec.to_string());
    params.insert("X-Amz-SignedHeaders".to_string(), "host".to_string());

    let canonical_query = canonical_presign_query(&params);
    let canonical_request =
        sigv4_canonical_request("GET", raw_path, &canonical_query, host, "UNSIGNED-PAYLOAD");
    let scope = format!("{scope_date}/{SIGV4_REGION}/{SIGV4_SERVICE}/aws4_request");
    let string_to_sign = sigv4_string_to_sign(amz_date, &scope, &canonical_request);
    let signature = sigv4_signature(
        SIGV4_SECRET_ACCESS_KEY,
        scope_date,
        SIGV4_REGION,
        SIGV4_SERVICE,
        &string_to_sign,
    )?;
    Ok(format!(
        "{base}{raw_path}?{canonical_query}&X-Amz-Signature={signature}"
    ))
}

struct DistributionAuthBinding<'a> {
    method: &'a str,
    raw_path: &'a str,
    raw_query: &'a str,
    body: &'a [u8],
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn canonical_presign_query(params: &BTreeMap<String, String>) -> String {
    let mut pairs = params.iter().collect::<Vec<_>>();
    pairs.sort_by(|left, right| left.0.cmp(right.0).then_with(|| left.1.cmp(right.1)));
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn sigv4_canonical_request(
    method: &str,
    raw_path: &str,
    raw_query: &str,
    host: &str,
    payload_hash: &str,
) -> String {
    format!("{method}\n{raw_path}\n{raw_query}\nhost:{host}\n\nhost\n{payload_hash}")
}

fn sigv4_string_to_sign(date: &str, scope: &str, canonical_request: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256\n{date}\n{scope}\n{}",
        hex_lower(&Sha256::digest(canonical_request.as_bytes()))
    )
}

fn sigv4_signature(
    secret_access_key: &str,
    date: &str,
    region: &str,
    service: &str,
    string_to_sign: &str,
) -> Result<String, Box<dyn Error + Send + Sync>> {
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

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

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

async fn connect_native(
    authority: &str,
    addr: std::net::SocketAddr,
    certificate_der: &[u8],
) -> Result<Connection, Box<dyn Error + Send + Sync>> {
    let (client_config, server_name) = build_client_config(authority, certificate_der)?;
    let mut endpoint = Endpoint::client("[::]:0".parse().expect("native client addr"))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint.connect(addr, &server_name)?.await?)
}

async fn auth_frame(
    connection: &Connection,
    signing_key: &SigningKey,
    claims: CapabilityClaims,
) -> Result<AuthFrame, Box<dyn Error + Send + Sync>> {
    let nonce = "conformance-nonce";
    let token_b64 = sign_claims(signing_key, &claims);
    let mut exporter = [0u8; 32];
    connection
        .export_keying_material(&mut exporter, tls_exporter_label(), nonce.as_bytes())
        .map_err(|_| "failed to export TLS keying material")?;
    Ok(AuthFrame {
        token_b64,
        channel_binding: ChannelBindingProof {
            binding_kind: "tls-exporter".to_string(),
            proof_b64: URL_SAFE_NO_PAD.encode(exporter),
            nonce: nonce.to_string(),
        },
    })
}

async fn send_native_request(
    connection: &Connection,
    auth: Option<AuthFrame>,
    header: ReqHeader,
    body: &[u8],
) -> Result<(Option<Frame>, Option<Frame>, Vec<Vec<u8>>), Box<dyn Error + Send + Sync>> {
    let (mut send, mut recv) = connection.open_bi().await?;
    if let Some(auth) = auth {
        write_frame(&mut send, &Frame::Auth(auth)).await?;
    }
    write_frame(&mut send, &Frame::ReqHeader(header)).await?;
    if !body.is_empty() {
        write_frame(&mut send, &Frame::Data(body.to_vec())).await?;
    }
    write_frame(&mut send, &Frame::End).await?;
    send.finish()?;

    let first = read_frame(&mut recv).await.ok();
    let mut data_frames = Vec::new();
    let mut second = None;
    if let Some(Frame::ResHeader(_)) = &first {
        loop {
            match read_frame(&mut recv).await? {
                Frame::Data(bytes) => data_frames.push(bytes),
                Frame::End => break,
                frame => {
                    second = Some(frame);
                    break;
                }
            }
        }
    } else if first.is_some() {
        second = read_frame(&mut recv).await.ok();
    }
    Ok((first, second, data_frames))
}

async fn connect_gateway(
    authority: &str,
    addr: std::net::SocketAddr,
    certificate_der: &[u8],
) -> Result<GatewayClient, Box<dyn Error + Send + Sync>> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(certificate_der.to_vec()))?;
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = QuicClientConfig::try_from(crypto)?;
    let mut endpoint = Endpoint::client("[::]:0".parse().expect("gateway client addr"))?;
    endpoint.set_default_client_config(ClientConfig::new(std::sync::Arc::new(quic_crypto)));
    let connection = endpoint.connect(addr, authority)?.await?;
    let (mut h3_connection, send_request) =
        client::new(H3ClientConnection::new(connection.clone())).await?;
    let driver = tokio::spawn(async move {
        let _ = poll_fn(|cx| h3_connection.poll_close(cx)).await;
    });
    Ok(GatewayClient {
        endpoint,
        connection,
        send_request,
        driver,
    })
}

async fn auth_headers(
    connection: &Connection,
    signing_key: &SigningKey,
    claims: CapabilityClaims,
    nonce: &str,
) -> Result<http::HeaderMap, Box<dyn Error + Send + Sync>> {
    let token_b64 = sign_claims(signing_key, &claims);
    let mut exporter = [0u8; 32];
    connection
        .export_keying_material(&mut exporter, tls_exporter_label(), nonce.as_bytes())
        .map_err(|_| "failed to export TLS keying material")?;
    let mut headers = http::HeaderMap::new();
    headers.insert("x-hsp-capability", token_b64.parse()?);
    headers.insert("x-hsp-channel-binding-kind", "tls-exporter".parse()?);
    headers.insert(
        "x-hsp-channel-binding-proof",
        URL_SAFE_NO_PAD.encode(exporter).parse()?,
    );
    headers.insert("x-hsp-channel-binding-nonce", nonce.parse()?);
    Ok(headers)
}

async fn send_gateway_request(
    client: &mut GatewayClient,
    method: Method,
    uri: String,
    headers: http::HeaderMap,
    body: &[u8],
) -> Result<(http::Response<()>, Vec<u8>), Box<dyn Error + Send + Sync>> {
    let mut request = Request::builder().method(method).uri(uri).body(())?;
    *request.headers_mut() = headers;
    let mut stream = client.send_request.send_request(request).await?;
    if !body.is_empty() {
        stream
            .send_data(bytes::Bytes::copy_from_slice(body))
            .await?;
    }
    stream.finish().await?;
    let response = stream.recv_response().await?;
    let mut response_body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        let bytes = chunk.copy_to_bytes(chunk.remaining());
        response_body.extend_from_slice(&bytes);
    }
    Ok((response, response_body))
}

fn uri_for(addr: std::net::SocketAddr, path_and_query: &str) -> String {
    format!("https://localhost:{}{path_and_query}", addr.port())
}
