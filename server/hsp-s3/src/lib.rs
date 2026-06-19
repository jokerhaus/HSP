use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use ed25519_dalek::SigningKey;
use hsp_auth::{AuthContext, IssuerRegistry};
use hsp_core::{
    ApiError, ApiErrorCategory, CapabilityScope, KeyPolicyId, RangeSpec, VisibilityMode,
    WrappedObjectKeyRecord,
};
use hsp_crypto::{AwsKmsProviderConfig, LocalDevKms};
use hsp_distribution::{
    AbortMultipartUploadRequest, AccessProfile, CannedAcl, CompleteMultipartUploadRequest,
    CompletedMultipartPart, CreateMultipartUploadRequest, DeleteObjectRequest, DistributionConfig,
    DistributionService, GetObjectRequest, HeadObjectRequest, HttpRequestBinding, LifecycleConfig,
    LifecycleRule, ListObjectsRequest, PutObjectRequest, ReplicationConfig, SigV4AccessKeyRecord,
    UploadPartRequest, WebsiteConfig,
};
use hsp_service::{AlphaConfig, StorageBackendConfig};
use quick_xml::{de::from_str as from_xml_str, se::to_string as to_xml_string};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

const MAX_S3_REQUEST_BODY_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3ServerConfig {
    pub bind_addr: SocketAddr,
    pub authority: String,
    pub gateway_base_url: String,
    pub root_dir: PathBuf,
    pub storage_backend: StorageBackendConfig,
    pub server_instance_id: String,
    pub capability_audience: String,
    pub immutable_cid_ttl_sec: u64,
    pub namespace_ttl_sec: u64,
    pub issuer_registry_path: PathBuf,
    pub namespace_signing_seed: [u8; 32],
    pub namespace_signing_key_id: String,
    pub edge_signing_secret: Vec<u8>,
    pub kms_seed: Vec<u8>,
    pub aws_kms: Option<AwsKmsProviderConfig>,
    pub virtual_host_suffix: Option<String>,
    pub sigv4_access_keys: Vec<SigV4AccessKeyRecord>,
}

#[derive(Clone)]
struct S3State {
    service: Arc<DistributionService>,
    virtual_host_suffix: Option<String>,
}

pub async fn run_s3_server(
    config: S3ServerConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = Arc::new(S3State {
        service: Arc::new(build_distribution_service(&config)?),
        virtual_host_suffix: config.virtual_host_suffix.clone(),
    });
    let listener = TcpListener::bind(config.bind_addr).await?;
    axum::serve(listener, router(state)).await?;
    Ok(())
}

fn router(state: Arc<S3State>) -> Router {
    Router::new()
        .route("/", any(handle_request))
        .route("/{*path}", any(handle_request))
        .with_state(state)
}

fn build_distribution_service(config: &S3ServerConfig) -> Result<DistributionService, ApiError> {
    let issuer_registry = IssuerRegistry::load(&config.issuer_registry_path)?;
    let service = DistributionService::new(
        DistributionConfig {
            alpha: AlphaConfig {
                authority: config.authority.clone(),
                gateway_base_url: config.gateway_base_url.clone(),
                root_dir: config.root_dir.clone(),
                storage_backend: config.storage_backend.clone(),
                native_port: 443,
                server_instance_id: config.server_instance_id.clone(),
            },
            capability_audience: config.capability_audience.clone(),
            immutable_cid_ttl_sec: config.immutable_cid_ttl_sec,
            namespace_ttl_sec: config.namespace_ttl_sec,
            plaintext_profile_enabled: false,
            aws_kms: config.aws_kms.clone(),
        },
        LocalDevKms::from_seed(&config.kms_seed)
            .map_err(|error| hsp_crypto::crypto_error_to_api(error, "failed to initialize KMS"))?,
        issuer_registry,
        SigningKey::from_bytes(&config.namespace_signing_seed),
        config.namespace_signing_key_id.clone(),
        config.edge_signing_secret.clone(),
    )?;
    for record in &config.sigv4_access_keys {
        service.register_sigv4_access_key(record.clone())?;
    }
    Ok(service)
}

async fn handle_request(
    State(state): State<Arc<S3State>>,
    method: Method,
    headers: HeaderMap,
    uri: OriginalUri,
    request: Request<Body>,
) -> impl IntoResponse {
    let uri = uri.0;
    let path = uri.path().to_string();
    let query = uri.query().unwrap_or_default().to_string();
    let body = match to_bytes(request.into_body(), MAX_S3_REQUEST_BODY_BYTES).await {
        Ok(body) => body,
        Err(error) => {
            return api_error_response(ApiError::new(
                ApiErrorCategory::Validation,
                "invalid_body",
                error.to_string(),
            ))
        }
    };

    if method == Method::GET && path == "/metrics" {
        let auth =
            match authenticate_request(&state.service, &method, &path, &query, &headers, &body) {
                Ok(auth) => auth,
                Err(error) => return api_error_response(error),
            };
        if let Err(error) = require_scope(&auth, CapabilityScope::AdminMetricsRead) {
            return api_error_response(error);
        }
        return text_response(
            StatusCode::OK,
            "text/plain; version=0.0.4",
            state.service.prometheus_metrics(),
        )
        .unwrap_or_else(api_error_response);
    }
    if method == Method::GET && path == "/v1/observability/logs" {
        let auth =
            match authenticate_request(&state.service, &method, &path, &query, &headers, &body) {
                Ok(auth) => auth,
                Err(error) => return api_error_response(error),
            };
        if let Err(error) = require_scope(&auth, CapabilityScope::AdminAuditRead) {
            return api_error_response(error);
        }
        return json_response(StatusCode::OK, &state.service.structured_logs())
            .unwrap_or_else(api_error_response);
    }

    let resolved =
        match resolve_bucket_and_key(&headers, &uri, state.virtual_host_suffix.as_deref()) {
            Ok(route) => route,
            Err(error) => return api_error_response(error),
        };
    let auth = match authenticate_request(&state.service, &method, &path, &query, &headers, &body) {
        Ok(auth) => auth,
        Err(error) => return api_error_response(error),
    };

    let response = match dispatch_request(
        &state.service,
        &auth,
        &method,
        &headers,
        &query,
        resolved,
        body,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => api_error_response(error),
    };
    response
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedRoute {
    bucket: Option<String>,
    key: Option<String>,
}

fn resolve_bucket_and_key(
    headers: &HeaderMap,
    uri: &Uri,
    virtual_host_suffix: Option<&str>,
) -> Result<ResolvedRoute, ApiError> {
    if let Some(suffix) = virtual_host_suffix {
        if let Some(host) = headers.get("host").and_then(|value| value.to_str().ok()) {
            if host.ends_with(suffix) {
                let bucket = host
                    .trim_end_matches(suffix)
                    .trim_end_matches('.')
                    .to_string();
                let key = uri.path().trim_start_matches('/').to_string();
                return Ok(ResolvedRoute {
                    bucket: Some(bucket),
                    key: (!key.is_empty()).then_some(key),
                });
            }
        }
    }

    let path = uri.path().trim_start_matches('/');
    if path.is_empty() {
        return Ok(ResolvedRoute {
            bucket: None,
            key: None,
        });
    }
    let (bucket, key) = path
        .split_once('/')
        .map(|(bucket, key)| {
            (
                bucket.to_string(),
                (!key.is_empty()).then(|| key.to_string()),
            )
        })
        .unwrap_or_else(|| (path.to_string(), None));
    Ok(ResolvedRoute {
        bucket: Some(bucket),
        key,
    })
}

fn authenticate_request(
    service: &DistributionService,
    method: &Method,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<AuthContext, ApiError> {
    let binding = HttpRequestBinding {
        method: method.as_str(),
        raw_path: path,
        raw_query: query,
        headers,
        body,
    };
    if headers.contains_key("x-hsp-capability") {
        service.authenticate_hsp_capability(&binding)
    } else if headers.contains_key("authorization") || query.contains("X-Amz-Signature=") {
        service.authenticate_sigv4(&binding)
    } else {
        Err(ApiError::new(
            ApiErrorCategory::Auth,
            "missing_auth",
            "request must use HSP capability auth, SigV4, or presigned URL auth",
        ))
    }
}

async fn dispatch_request(
    service: &DistributionService,
    auth: &AuthContext,
    method: &Method,
    headers: &HeaderMap,
    query: &str,
    route: ResolvedRoute,
    body: Bytes,
) -> Result<Response<Body>, ApiError> {
    let params = query_pairs(query);
    match (method, route.bucket.as_deref(), route.key.as_deref()) {
        (&Method::GET, None, None) => {
            let buckets = service.list_buckets(auth, auth.claims.tenant_id.clone())?;
            xml_response(StatusCode::OK, &ListAllMyBucketsResult::from(buckets))
        }
        (&Method::GET, Some(bucket), None) if params.contains_key("acl") => {
            let acl =
                service.get_bucket_acl(auth, auth.claims.tenant_id.clone(), bucket.to_string())?;
            xml_response(StatusCode::OK, &AccessControlPolicyXml::from(acl.acl))
        }
        (&Method::PUT, Some(bucket), None) if params.contains_key("acl") => {
            let acl = parse_canned_acl(headers, &body)?;
            service.put_bucket_acl(auth, auth.claims.tenant_id.clone(), bucket.to_string(), acl)?;
            empty_response(StatusCode::OK)
        }
        (&Method::GET, Some(bucket), None) if params.contains_key("lifecycle") => {
            let lifecycle = service.get_lifecycle_config(
                auth,
                auth.claims.tenant_id.clone(),
                bucket.to_string(),
            )?;
            xml_response(StatusCode::OK, &LifecycleConfigurationXml::from(lifecycle))
        }
        (&Method::PUT, Some(bucket), None) if params.contains_key("lifecycle") => {
            let parsed: LifecycleConfigurationXml =
                from_xml_str(std::str::from_utf8(&body).unwrap_or_default()).map_err(xml_error)?;
            service.put_lifecycle_config(
                auth,
                lifecycle_config_from_xml(auth.claims.tenant_id.clone(), bucket, parsed),
            )?;
            empty_response(StatusCode::OK)
        }
        (&Method::DELETE, Some(bucket), None) if params.contains_key("lifecycle") => {
            service.delete_lifecycle_config(
                auth,
                auth.claims.tenant_id.clone(),
                bucket.to_string(),
            )?;
            empty_response(StatusCode::NO_CONTENT)
        }
        (&Method::GET, Some(bucket), None) if params.contains_key("website") => {
            let website = service.get_website_config(
                auth,
                auth.claims.tenant_id.clone(),
                bucket.to_string(),
            )?;
            xml_response(StatusCode::OK, &WebsiteConfigurationXml::from(website))
        }
        (&Method::PUT, Some(bucket), None) if params.contains_key("website") => {
            let parsed: WebsiteConfigurationXml =
                from_xml_str(std::str::from_utf8(&body).unwrap_or_default()).map_err(xml_error)?;
            service.put_website_config(
                auth,
                website_config_from_xml(auth.claims.tenant_id.clone(), bucket, parsed),
            )?;
            empty_response(StatusCode::OK)
        }
        (&Method::DELETE, Some(bucket), None) if params.contains_key("website") => {
            service.delete_website_config(
                auth,
                auth.claims.tenant_id.clone(),
                bucket.to_string(),
            )?;
            empty_response(StatusCode::NO_CONTENT)
        }
        (&Method::GET, Some(bucket), None) if params.contains_key("replication-status") => {
            let status = service.get_replication_status(
                auth,
                auth.claims.tenant_id.clone(),
                bucket.to_string(),
            )?;
            xml_response(StatusCode::OK, &ReplicationStatusXml::from(status))
        }
        (&Method::POST, Some(bucket), None) if params.contains_key("replication-run") => {
            let status = service.run_replication_once(
                auth,
                auth.claims.tenant_id.clone(),
                bucket.to_string(),
            )?;
            xml_response(StatusCode::OK, &ReplicationStatusXml::from(status))
        }
        (&Method::GET, Some(bucket), None) if params.contains_key("replication") => {
            let config = service.get_replication_config(
                auth,
                auth.claims.tenant_id.clone(),
                bucket.to_string(),
            )?;
            xml_response(StatusCode::OK, &ReplicationConfigurationXml::from(config))
        }
        (&Method::PUT, Some(bucket), None) if params.contains_key("replication") => {
            let parsed: ReplicationConfigurationXml =
                from_xml_str(std::str::from_utf8(&body).unwrap_or_default()).map_err(xml_error)?;
            service.put_replication_config(
                auth,
                replication_config_from_xml(auth.claims.tenant_id.clone(), bucket, parsed),
            )?;
            empty_response(StatusCode::OK)
        }
        (&Method::DELETE, Some(bucket), None) if params.contains_key("replication") => {
            service.delete_replication_config(
                auth,
                auth.claims.tenant_id.clone(),
                bucket.to_string(),
            )?;
            empty_response(StatusCode::NO_CONTENT)
        }
        (&Method::PUT, Some(bucket), None) => {
            service.create_bucket(auth, auth.claims.tenant_id.clone(), bucket.to_string())?;
            empty_response(StatusCode::OK)
        }
        (&Method::HEAD, Some(bucket), None) => {
            service.head_bucket(auth, auth.claims.tenant_id.clone(), bucket.to_string())?;
            empty_response(StatusCode::OK)
        }
        (&Method::DELETE, Some(bucket), None) => {
            service.delete_bucket(auth, auth.claims.tenant_id.clone(), bucket.to_string())?;
            empty_response(StatusCode::NO_CONTENT)
        }
        (&Method::GET, Some(bucket), None) if params.get("list-type") == Some(&"2".to_string()) => {
            let listed = service.list_objects(
                auth,
                ListObjectsRequest {
                    tenant_id: auth.claims.tenant_id.clone(),
                    bucket: bucket.to_string(),
                    prefix: params.get("prefix").cloned(),
                    continuation_token: params.get("continuation-token").cloned(),
                    limit: params
                        .get("max-keys")
                        .and_then(|value| value.parse::<u32>().ok()),
                },
            )?;
            xml_response(StatusCode::OK, &ListBucketResult::from(listed))
        }
        (&Method::POST, Some(bucket), None) if params.contains_key("delete") => {
            let delete: DeleteObjectsXml =
                from_xml_str(std::str::from_utf8(&body).unwrap_or_default()).map_err(xml_error)?;
            let deleted = delete.objects.clone();
            for object in &deleted {
                let _ = service.delete_object(
                    auth,
                    DeleteObjectRequest {
                        tenant_id: auth.claims.tenant_id.clone(),
                        bucket: bucket.to_string(),
                        key: object.key.clone(),
                        idempotency_key: format!("delete-{}", cid(object.key.as_bytes())),
                    },
                );
            }
            xml_response(StatusCode::OK, &DeleteResultXml { deleted })
        }
        (&Method::GET, Some(bucket), Some(key)) if params.contains_key("acl") => {
            let acl = service.get_object_acl(
                auth,
                auth.claims.tenant_id.clone(),
                bucket.to_string(),
                key.to_string(),
            )?;
            xml_response(StatusCode::OK, &AccessControlPolicyXml::from(acl.acl))
        }
        (&Method::PUT, Some(bucket), Some(key)) if params.contains_key("acl") => {
            let acl = parse_canned_acl(headers, &body)?;
            service.put_object_acl(
                auth,
                auth.claims.tenant_id.clone(),
                bucket.to_string(),
                key.to_string(),
                acl,
            )?;
            empty_response(StatusCode::OK)
        }
        (&Method::GET, Some(bucket), Some(key)) if params.contains_key("retention") => {
            let lock = service.get_object_lock(
                auth,
                auth.claims.tenant_id.clone(),
                bucket.to_string(),
                key.to_string(),
            )?;
            xml_response(StatusCode::OK, &ObjectRetentionXml::from(lock))
        }
        (&Method::PUT, Some(bucket), Some(key)) if params.contains_key("retention") => {
            let retention: ObjectRetentionXml =
                from_xml_str(std::str::from_utf8(&body).unwrap_or_default()).map_err(xml_error)?;
            service.put_object_retention(
                auth,
                auth.claims.tenant_id.clone(),
                bucket.to_string(),
                key.to_string(),
                retention.retain_until_ms,
                retention.mode.clone(),
            )?;
            empty_response(StatusCode::OK)
        }
        (&Method::GET, Some(bucket), Some(key)) if params.contains_key("legal-hold") => {
            let lock = service.get_object_lock(
                auth,
                auth.claims.tenant_id.clone(),
                bucket.to_string(),
                key.to_string(),
            )?;
            xml_response(StatusCode::OK, &LegalHoldXml::from(lock.legal_hold))
        }
        (&Method::PUT, Some(bucket), Some(key)) if params.contains_key("legal-hold") => {
            let legal_hold: LegalHoldXml =
                from_xml_str(std::str::from_utf8(&body).unwrap_or_default()).map_err(xml_error)?;
            service.put_object_legal_hold(
                auth,
                auth.claims.tenant_id.clone(),
                bucket.to_string(),
                key.to_string(),
                legal_hold.status.eq_ignore_ascii_case("on"),
            )?;
            empty_response(StatusCode::OK)
        }
        (&Method::PUT, Some(bucket), Some(key)) if headers.contains_key("x-amz-copy-source") => {
            let source = headers
                .get("x-amz-copy-source")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .trim_start_matches('/');
            let (source_bucket, source_key) = source.split_once('/').ok_or_else(|| {
                ApiError::new(
                    ApiErrorCategory::Validation,
                    "invalid_copy_source",
                    "x-amz-copy-source must use /bucket/key syntax",
                )
            })?;
            let copied = service.copy_object(
                auth,
                hsp_distribution::CopyObjectRequest {
                    tenant_id: auth.claims.tenant_id.clone(),
                    source_bucket: source_bucket.to_string(),
                    source_key: source_key.to_string(),
                    destination_bucket: bucket.to_string(),
                    destination_key: key.to_string(),
                    idempotency_key: format!("copy-{}", cid(source.as_bytes())),
                },
            )?;
            xml_response(StatusCode::OK, &CopyObjectResultXml::from(copied))
        }
        (&Method::POST, Some(bucket), Some(key)) if params.contains_key("uploads") => {
            let created = service.create_multipart_upload(
                auth,
                parse_create_multipart_request(auth, bucket, key, headers)?,
            )?;
            xml_response(
                StatusCode::OK,
                &InitiateMultipartUploadResultXml::from(created),
            )
        }
        (&Method::PUT, Some(_bucket), Some(_key))
            if params.contains_key("uploadId") && params.contains_key("partNumber") =>
        {
            let upload_id = params.get("uploadId").cloned().unwrap_or_default();
            let part_number = params
                .get("partNumber")
                .and_then(|value| value.parse::<u32>().ok())
                .ok_or_else(|| {
                    ApiError::new(
                        ApiErrorCategory::Validation,
                        "invalid_part_number",
                        "partNumber must be present for UploadPart",
                    )
                })?;
            let uploaded = service.upload_part(
                auth,
                UploadPartRequest {
                    tenant_id: auth.claims.tenant_id.clone(),
                    upload_id,
                    part_number,
                },
                &body,
            )?;
            let mut response = empty_response(StatusCode::OK)?;
            response.headers_mut().insert(
                "etag",
                format!("\"{}\"", uploaded.etag)
                    .parse()
                    .expect("etag header"),
            );
            Ok(response)
        }
        (&Method::POST, Some(_bucket), Some(_key)) if params.contains_key("uploadId") => {
            let upload_id = params.get("uploadId").cloned().unwrap_or_default();
            let completed: CompleteMultipartUploadXml =
                from_xml_str(std::str::from_utf8(&body).unwrap_or_default()).map_err(xml_error)?;
            let response = service.complete_multipart_upload(
                auth,
                CompleteMultipartUploadRequest {
                    tenant_id: auth.claims.tenant_id.clone(),
                    upload_id,
                    parts: completed
                        .parts
                        .into_iter()
                        .map(CompletedMultipartPart::from)
                        .collect(),
                },
            )?;
            xml_response(
                StatusCode::OK,
                &CompleteMultipartUploadResultXml::from(response),
            )
        }
        (&Method::DELETE, Some(_bucket), Some(_key)) if params.contains_key("uploadId") => {
            let upload_id = params.get("uploadId").cloned().unwrap_or_default();
            service.abort_multipart_upload(
                auth,
                AbortMultipartUploadRequest {
                    tenant_id: auth.claims.tenant_id.clone(),
                    upload_id,
                },
            )?;
            empty_response(StatusCode::NO_CONTENT)
        }
        (&Method::PUT, Some(bucket), Some(key)) => {
            let response = service.put_object(
                auth,
                parse_put_object_request(auth, bucket, key, headers)?,
                &body,
            )?;
            let mut http = empty_response(StatusCode::OK)?;
            http.headers_mut().insert(
                "etag",
                format!("\"{}\"", response.etag)
                    .parse()
                    .expect("etag header"),
            );
            Ok(http)
        }
        (&Method::HEAD, Some(bucket), Some(key)) => {
            let head = service.head_object(
                auth,
                HeadObjectRequest {
                    tenant_id: auth.claims.tenant_id.clone(),
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                },
            )?;
            head_response(head)
        }
        (&Method::GET, Some(bucket), Some(key)) => {
            let get = service.get_object(
                auth,
                GetObjectRequest {
                    tenant_id: auth.claims.tenant_id.clone(),
                    bucket: Some(bucket.to_string()),
                    key: Some(key.to_string()),
                    cid: None,
                    access_profile: parse_access_profile(headers)?,
                    prefer_plaintext: headers
                        .get("x-hsp-prefer-plaintext")
                        .and_then(|value| value.to_str().ok())
                        .map(|value| value.eq_ignore_ascii_case("true"))
                        .unwrap_or(false)
                        || params
                            .get("mode")
                            .map(|value| value == "plaintext")
                            .unwrap_or(false),
                    range: parse_range(headers)?,
                    if_match: headers
                        .get("if-match")
                        .and_then(|value| value.to_str().ok())
                        .map(trim_etag),
                    if_none_match: headers
                        .get("if-none-match")
                        .and_then(|value| value.to_str().ok())
                        .map(trim_etag),
                },
            )?;
            get_response(get)
        }
        (&Method::DELETE, Some(bucket), Some(key)) => {
            service.delete_object(
                auth,
                DeleteObjectRequest {
                    tenant_id: auth.claims.tenant_id.clone(),
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    idempotency_key: format!("delete-{}", cid(key.as_bytes())),
                },
            )?;
            empty_response(StatusCode::NO_CONTENT)
        }
        _ => Err(ApiError::new(
            ApiErrorCategory::NotFound,
            "route_not_found",
            "S3 route not found",
        )),
    }
}

fn parse_put_object_request(
    auth: &AuthContext,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
) -> Result<PutObjectRequest, ApiError> {
    let payload_plaintext = parse_payload_plaintext(headers);
    Ok(PutObjectRequest {
        tenant_id: auth.claims.tenant_id.clone(),
        bucket: bucket.to_string(),
        key: key.to_string(),
        access_profile: parse_access_profile(headers)?,
        payload_plaintext,
        content_type: headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string(),
        encryption_profile_id: hsp_core::EncryptionProfileId(required_header(
            headers,
            "x-hsp-encryption-profile-id",
        )?),
        key_policy_id: KeyPolicyId(required_header(headers, "x-hsp-key-policy-id")?),
        metadata_visibility: parse_visibility_mode(&required_header(
            headers,
            "x-hsp-metadata-visibility",
        )?)?,
        content_encryption_suite: headers
            .get("x-hsp-content-encryption-suite")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("XChaCha20-Poly1305")
            .to_string(),
        key_wrapping_suite: headers
            .get("x-hsp-key-wrapping-suite")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("HPKE/X25519")
            .to_string(),
        wrapped_object_keys: parse_wrapped_object_keys(headers, payload_plaintext)?,
        server_visible_metadata: server_visible_metadata(headers),
        encrypted_client_metadata: BTreeMap::new(),
        storage_class: headers
            .get("x-hsp-storage-class")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("hot")
            .to_string(),
        idempotency_key: headers
            .get("x-hsp-idempotency-key")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("put-object")
            .to_string(),
    })
}

fn parse_create_multipart_request(
    auth: &AuthContext,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
) -> Result<CreateMultipartUploadRequest, ApiError> {
    let payload_plaintext = parse_payload_plaintext(headers);
    Ok(CreateMultipartUploadRequest {
        tenant_id: auth.claims.tenant_id.clone(),
        bucket: bucket.to_string(),
        key: key.to_string(),
        access_profile: parse_access_profile(headers)?,
        payload_plaintext,
        content_type: headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string(),
        encryption_profile_id: hsp_core::EncryptionProfileId(required_header(
            headers,
            "x-hsp-encryption-profile-id",
        )?),
        key_policy_id: KeyPolicyId(required_header(headers, "x-hsp-key-policy-id")?),
        metadata_visibility: parse_visibility_mode(&required_header(
            headers,
            "x-hsp-metadata-visibility",
        )?)?,
        content_encryption_suite: headers
            .get("x-hsp-content-encryption-suite")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("XChaCha20-Poly1305")
            .to_string(),
        key_wrapping_suite: headers
            .get("x-hsp-key-wrapping-suite")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("HPKE/X25519")
            .to_string(),
        wrapped_object_keys: parse_wrapped_object_keys(headers, payload_plaintext)?,
        server_visible_metadata: server_visible_metadata(headers),
        encrypted_client_metadata: BTreeMap::new(),
        storage_class: headers
            .get("x-hsp-storage-class")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("hot")
            .to_string(),
        idempotency_key: headers
            .get("x-hsp-idempotency-key")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("multipart")
            .to_string(),
    })
}

fn parse_wrapped_object_key(headers: &HeaderMap) -> Result<WrappedObjectKeyRecord, ApiError> {
    Ok(WrappedObjectKeyRecord {
        recipient_key_id: required_header(headers, "x-hsp-recipient-key-id")?,
        wrapping_suite: required_header(headers, "x-hsp-key-wrapping-suite")?,
        wrapped_key_b64: required_header(headers, "x-hsp-wrapped-object-key")?,
        key_version: headers
            .get("x-hsp-wrapped-object-key-version")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(1),
        encapsulated_key_b64: headers
            .get("x-hsp-encapsulated-key")
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string),
    })
}

fn parse_wrapped_object_keys(
    headers: &HeaderMap,
    payload_plaintext: bool,
) -> Result<Vec<WrappedObjectKeyRecord>, ApiError> {
    let has_required_headers = headers.contains_key("x-hsp-recipient-key-id")
        && headers.contains_key("x-hsp-wrapped-object-key");
    if has_required_headers {
        return Ok(vec![parse_wrapped_object_key(headers)?]);
    }
    if payload_plaintext {
        return Ok(Vec::new());
    }
    Err(ApiError::new(
        ApiErrorCategory::Validation,
        "missing_required_header",
        "ciphertext mode requires wrapped object key headers",
    ))
}

fn server_visible_metadata(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            let key = name.as_str();
            key.strip_prefix("x-amz-meta-").map(|suffix| {
                (
                    suffix.to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
        })
        .collect()
}

fn parse_visibility_mode(value: &str) -> Result<VisibilityMode, ApiError> {
    match value {
        "server_visible" => Ok(VisibilityMode::ServerVisible),
        "encrypted_only" => Ok(VisibilityMode::EncryptedOnly),
        "split" => Ok(VisibilityMode::Split),
        _ => Err(ApiError::new(
            ApiErrorCategory::Validation,
            "invalid_metadata_visibility",
            "x-hsp-metadata-visibility must be server_visible, encrypted_only, or split",
        )),
    }
}

fn parse_range(headers: &HeaderMap) -> Result<Option<RangeSpec>, ApiError> {
    let Some(header) = headers.get("range").and_then(|value| value.to_str().ok()) else {
        return Ok(None);
    };
    let raw = header.strip_prefix("bytes=").ok_or_else(|| {
        ApiError::new(
            ApiErrorCategory::Validation,
            "invalid_range",
            "Range header must use bytes=start-end syntax",
        )
    })?;
    let (start, end) = raw.split_once('-').ok_or_else(|| {
        ApiError::new(
            ApiErrorCategory::Validation,
            "invalid_range",
            "Range header must include start and end",
        )
    })?;
    Ok(Some(RangeSpec {
        start: start.parse().map_err(|_| invalid_range())?,
        end: end.parse().map_err(|_| invalid_range())?,
    }))
}

fn parse_access_profile(headers: &HeaderMap) -> Result<AccessProfile, ApiError> {
    let value = headers
        .get("x-hsp-access-profile")
        .and_then(|header| header.to_str().ok())
        .unwrap_or("public-ciphertext");
    match value {
        "public-ciphertext" => Ok(AccessProfile::PublicCiphertext),
        "trusted-edge-v1" => Ok(AccessProfile::TrustedEdgeV1),
        _ => Err(ApiError::new(
            ApiErrorCategory::Validation,
            "invalid_access_profile",
            "x-hsp-access-profile must be public-ciphertext or trusted-edge-v1",
        )),
    }
}

fn parse_payload_plaintext(headers: &HeaderMap) -> bool {
    headers
        .get("x-hsp-payload-mode")
        .and_then(|header| header.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("plaintext"))
        .unwrap_or(false)
}

fn parse_canned_acl(headers: &HeaderMap, body: &[u8]) -> Result<CannedAcl, ApiError> {
    if let Some(value) = headers
        .get("x-amz-acl")
        .and_then(|value| value.to_str().ok())
    {
        return canned_acl_from_str(value);
    }
    if !body.is_empty() {
        let parsed: AccessControlPolicyXml =
            from_xml_str(std::str::from_utf8(body).unwrap_or_default()).map_err(xml_error)?;
        return canned_acl_from_str(&parsed.canned_acl);
    }
    Ok(CannedAcl::Private)
}

fn canned_acl_from_str(value: &str) -> Result<CannedAcl, ApiError> {
    match value {
        "private" => Ok(CannedAcl::Private),
        "public-read" => Ok(CannedAcl::PublicRead),
        "authenticated-read" => Ok(CannedAcl::AuthenticatedRead),
        _ => Err(ApiError::new(
            ApiErrorCategory::Validation,
            "acl_denied",
            "supported canned ACL values are private, public-read, authenticated-read",
        )),
    }
}

fn invalid_range() -> ApiError {
    ApiError::new(
        ApiErrorCategory::Validation,
        "invalid_range",
        "Range header is invalid",
    )
}

fn required_header(headers: &HeaderMap, name: &str) -> Result<String, ApiError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
        .ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::Validation,
                "missing_required_header",
                format!("required header `{name}` is missing"),
            )
        })
}

fn query_pairs(query: &str) -> BTreeMap<String, String> {
    query
        .split('&')
        .filter(|segment| !segment.is_empty())
        .map(|segment| segment.split_once('=').unwrap_or((segment, "")))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn head_response(head: hsp_distribution::HeadObjectResponse) -> Result<Response<Body>, ApiError> {
    let mut response = empty_response(StatusCode::OK)?;
    response
        .headers_mut()
        .insert("etag", format!("\"{}\"", head.etag).parse().expect("etag"));
    response.headers_mut().insert(
        "x-hsp-exists",
        head.exists.to_string().parse().expect("bool"),
    );
    response.headers_mut().insert(
        "x-hsp-deleted",
        head.deleted.to_string().parse().expect("bool"),
    );
    response
        .headers_mut()
        .insert("x-hsp-cid", head.cid.parse().expect("cid"));
    response.headers_mut().insert(
        "x-hsp-object-cid",
        head.object_cid.parse().expect("object cid"),
    );
    response.headers_mut().insert(
        "x-hsp-manifest-cid",
        head.manifest_cid.parse().expect("manifest cid"),
    );
    response.headers_mut().insert(
        "x-hsp-integrity-hash",
        head.integrity_hash.parse().expect("integrity hash"),
    );
    response.headers_mut().insert(
        "x-hsp-size-bytes",
        head.size_bytes.to_string().parse().expect("size bytes"),
    );
    response.headers_mut().insert(
        "x-hsp-ciphertext-size-bytes",
        head.ciphertext_size_bytes
            .to_string()
            .parse()
            .expect("ciphertext size bytes"),
    );
    response.headers_mut().insert(
        "content-length",
        head.content_length
            .to_string()
            .parse()
            .expect("content-length"),
    );
    response.headers_mut().insert(
        "content-type",
        head.content_type.parse().expect("content-type"),
    );
    response.headers_mut().insert(
        "last-modified",
        head.last_modified_ms
            .to_string()
            .parse()
            .expect("last-modified"),
    );
    response.headers_mut().insert(
        "x-hsp-created-at-ms",
        head.last_modified_ms
            .to_string()
            .parse()
            .expect("created-at-ms"),
    );
    response.headers_mut().insert(
        "x-hsp-encryption-profile-id",
        head.encryption_profile_id
            .0
            .parse()
            .expect("encryption profile"),
    );
    response.headers_mut().insert(
        "x-hsp-key-policy-id",
        head.key_policy_id.0.parse().expect("key policy"),
    );
    response.headers_mut().insert(
        "x-hsp-metadata-visibility",
        head.metadata_visibility
            .as_str()
            .parse()
            .expect("visibility"),
    );
    response.headers_mut().insert(
        "x-hsp-encrypted-client-metadata-redacted",
        head.encrypted_client_metadata_redacted
            .to_string()
            .parse()
            .expect("metadata redacted"),
    );
    Ok(response)
}

fn get_response(get: hsp_distribution::GetObjectResponse) -> Result<Response<Body>, ApiError> {
    let mut response = Response::builder()
        .status(if get.content_range.is_some() {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        })
        .body(Body::from(get.body))
        .map_err(http_error)?;
    response.headers_mut().insert(
        "etag",
        format!("\"{}\"", get.head.etag).parse().expect("etag"),
    );
    response.headers_mut().insert(
        "content-length",
        get.head
            .content_length
            .to_string()
            .parse()
            .expect("content-length"),
    );
    response.headers_mut().insert(
        "content-type",
        get.head.content_type.parse().expect("content-type"),
    );
    response.headers_mut().insert(
        "cache-control",
        get.cache_control.parse().expect("cache-control"),
    );
    if let Some(content_range) = get.content_range {
        response.headers_mut().insert(
            "content-range",
            content_range.parse().expect("content-range"),
        );
    }
    Ok(response)
}

fn empty_response(status: StatusCode) -> Result<Response<Body>, ApiError> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .map_err(http_error)
}

fn text_response(
    status: StatusCode,
    content_type: &'static str,
    body: String,
) -> Result<Response<Body>, ApiError> {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Body::from(body))
        .map_err(http_error)
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Result<Response<Body>, ApiError> {
    let body = serde_json::to_vec(value).map_err(|error| {
        ApiError::new(
            ApiErrorCategory::Storage,
            "json_serialize_failed",
            error.to_string(),
        )
    })?;
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .map_err(http_error)
}

fn xml_response<T: Serialize>(status: StatusCode, value: &T) -> Result<Response<Body>, ApiError> {
    let xml = to_xml_string(value).map_err(xml_error)?;
    Response::builder()
        .status(status)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .map_err(http_error)
}

fn api_error_response(error: ApiError) -> Response<Body> {
    let status = match error.category {
        hsp_core::ApiErrorCategory::Auth => StatusCode::FORBIDDEN,
        hsp_core::ApiErrorCategory::Replay => StatusCode::CONFLICT,
        hsp_core::ApiErrorCategory::Policy => StatusCode::FORBIDDEN,
        hsp_core::ApiErrorCategory::Validation => StatusCode::BAD_REQUEST,
        hsp_core::ApiErrorCategory::Unsupported => StatusCode::BAD_REQUEST,
        hsp_core::ApiErrorCategory::NotFound => StatusCode::NOT_FOUND,
        hsp_core::ApiErrorCategory::Conflict => StatusCode::CONFLICT,
        hsp_core::ApiErrorCategory::Storage => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let body = to_xml_string(&ErrorXml::from(error)).unwrap_or_else(|_| {
        "<Error><Code>internal_error</Code><Message>failed to serialize error</Message></Error>"
            .to_string()
    });
    Response::builder()
        .status(status)
        .header("content-type", "application/xml")
        .body(Body::from(body))
        .expect("error response")
}

fn require_scope(auth: &AuthContext, scope: CapabilityScope) -> Result<(), ApiError> {
    if auth.claims.ops.contains(&scope) {
        return Ok(());
    }
    Err(ApiError::new(
        ApiErrorCategory::Policy,
        "missing_required_scope",
        format!("{} scope is required", scope.as_str()),
    ))
}

fn trim_etag(value: &str) -> String {
    value.trim().trim_matches('"').to_string()
}

fn cid(bytes: &[u8]) -> String {
    hsp_core::cid_from_bytes(bytes)
}

fn http_error(error: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        hsp_core::ApiErrorCategory::Storage,
        "http_build_failed",
        error.to_string(),
    )
}

fn xml_error(error: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        hsp_core::ApiErrorCategory::Validation,
        "invalid_xml",
        error.to_string(),
    )
}

#[derive(Debug, Serialize)]
#[serde(rename = "Error")]
struct ErrorXml {
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Message")]
    message: String,
}

impl From<ApiError> for ErrorXml {
    fn from(value: ApiError) -> Self {
        Self {
            code: value.code,
            message: value.message,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename = "ListAllMyBucketsResult")]
struct ListAllMyBucketsResult {
    #[serde(rename = "Buckets")]
    buckets: BucketsXml,
}

impl From<Vec<hsp_distribution::BucketSummary>> for ListAllMyBucketsResult {
    fn from(value: Vec<hsp_distribution::BucketSummary>) -> Self {
        Self {
            buckets: BucketsXml {
                bucket: value
                    .into_iter()
                    .map(|bucket| BucketXml {
                        name: bucket.bucket,
                    })
                    .collect(),
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct BucketsXml {
    #[serde(rename = "Bucket")]
    bucket: Vec<BucketXml>,
}

#[derive(Debug, Serialize)]
struct BucketXml {
    #[serde(rename = "Name")]
    name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename = "ListBucketResult")]
struct ListBucketResult {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "IsTruncated")]
    is_truncated: bool,
    #[serde(
        rename = "NextContinuationToken",
        skip_serializing_if = "Option::is_none"
    )]
    next_continuation_token: Option<String>,
    #[serde(rename = "Contents")]
    contents: Vec<ListBucketContentsXml>,
}

impl From<hsp_distribution::ListObjectsResponse> for ListBucketResult {
    fn from(value: hsp_distribution::ListObjectsResponse) -> Self {
        Self {
            name: value.bucket,
            is_truncated: value.is_truncated,
            next_continuation_token: value.next_continuation_token,
            contents: value
                .items
                .into_iter()
                .map(|item| ListBucketContentsXml {
                    key: item.key,
                    etag: format!("\"{}\"", item.etag),
                    size: item.content_length,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ListBucketContentsXml {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "ETag")]
    etag: String,
    #[serde(rename = "Size")]
    size: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename = "Delete")]
struct DeleteObjectsXml {
    #[serde(rename = "Object", default)]
    objects: Vec<DeleteObjectXml>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct DeleteObjectXml {
    #[serde(rename = "Key")]
    key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename = "DeleteResult")]
struct DeleteResultXml {
    #[serde(rename = "Deleted", default)]
    deleted: Vec<DeleteObjectXml>,
}

#[derive(Debug, Serialize)]
#[serde(rename = "CopyObjectResult")]
struct CopyObjectResultXml {
    #[serde(rename = "ETag")]
    etag: String,
}

impl From<hsp_distribution::CopyObjectResponse> for CopyObjectResultXml {
    fn from(value: hsp_distribution::CopyObjectResponse) -> Self {
        Self {
            etag: format!("\"{}\"", value.object_cid),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename = "InitiateMultipartUploadResult")]
struct InitiateMultipartUploadResultXml {
    #[serde(rename = "Bucket")]
    bucket: String,
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "UploadId")]
    upload_id: String,
}

impl From<hsp_distribution::CreateMultipartUploadResponse> for InitiateMultipartUploadResultXml {
    fn from(value: hsp_distribution::CreateMultipartUploadResponse) -> Self {
        Self {
            bucket: value.bucket,
            key: value.key,
            upload_id: value.upload_id,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename = "CompleteMultipartUpload")]
struct CompleteMultipartUploadXml {
    #[serde(rename = "Part", default)]
    parts: Vec<CompletedMultipartPartXml>,
}

#[derive(Debug, Deserialize)]
struct CompletedMultipartPartXml {
    #[serde(rename = "PartNumber")]
    part_number: u32,
    #[serde(rename = "ETag")]
    etag: String,
}

impl From<CompletedMultipartPartXml> for CompletedMultipartPart {
    fn from(value: CompletedMultipartPartXml) -> Self {
        Self {
            part_number: value.part_number,
            etag: trim_etag(&value.etag),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename = "CompleteMultipartUploadResult")]
struct CompleteMultipartUploadResultXml {
    #[serde(rename = "Bucket")]
    bucket: String,
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "ETag")]
    etag: String,
}

impl From<hsp_distribution::PutObjectResponse> for CompleteMultipartUploadResultXml {
    fn from(value: hsp_distribution::PutObjectResponse) -> Self {
        Self {
            bucket: value.bucket,
            key: value.key,
            etag: format!("\"{}\"", value.etag),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "AccessControlPolicy")]
struct AccessControlPolicyXml {
    #[serde(rename = "CannedACL")]
    canned_acl: String,
}

impl From<CannedAcl> for AccessControlPolicyXml {
    fn from(value: CannedAcl) -> Self {
        Self {
            canned_acl: value.as_str().to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "LifecycleConfiguration")]
struct LifecycleConfigurationXml {
    #[serde(rename = "Rule", default)]
    rules: Vec<LifecycleRuleXml>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LifecycleRuleXml {
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(rename = "Prefix", skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "ExpirationDays", skip_serializing_if = "Option::is_none")]
    expiration_days: Option<u32>,
    #[serde(rename = "TransitionDays", skip_serializing_if = "Option::is_none")]
    transition_days: Option<u32>,
    #[serde(
        rename = "TransitionStorageClass",
        skip_serializing_if = "Option::is_none"
    )]
    transition_storage_class: Option<String>,
}

fn lifecycle_config_from_xml(
    tenant_id: hsp_core::TenantId,
    bucket: &str,
    value: LifecycleConfigurationXml,
) -> LifecycleConfig {
    LifecycleConfig {
        tenant_id,
        bucket: bucket.to_string(),
        rules: value
            .rules
            .into_iter()
            .map(|rule| LifecycleRule {
                id: rule.id.unwrap_or_else(|| cid(bucket.as_bytes())),
                prefix: rule.prefix,
                expire_after_days: rule.expiration_days,
                transition_after_days: rule.transition_days,
                transition_storage_class: rule.transition_storage_class,
                enabled: rule.status.eq_ignore_ascii_case("enabled"),
            })
            .collect(),
        updated_at_ms: 0,
    }
}

impl From<LifecycleConfig> for LifecycleConfigurationXml {
    fn from(value: LifecycleConfig) -> Self {
        Self {
            rules: value
                .rules
                .into_iter()
                .map(|rule| LifecycleRuleXml {
                    id: Some(rule.id),
                    prefix: rule.prefix,
                    status: if rule.enabled {
                        "Enabled".to_string()
                    } else {
                        "Disabled".to_string()
                    },
                    expiration_days: rule.expire_after_days,
                    transition_days: rule.transition_after_days,
                    transition_storage_class: rule.transition_storage_class,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "ObjectRetention")]
struct ObjectRetentionXml {
    #[serde(rename = "Mode", skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    #[serde(rename = "RetainUntilMs", skip_serializing_if = "Option::is_none")]
    retain_until_ms: Option<u64>,
}

impl From<hsp_distribution::ObjectLockRecord> for ObjectRetentionXml {
    fn from(value: hsp_distribution::ObjectLockRecord) -> Self {
        Self {
            mode: value.mode,
            retain_until_ms: value.immutable_until_ms,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "LegalHold")]
struct LegalHoldXml {
    #[serde(rename = "Status")]
    status: String,
}

impl From<bool> for LegalHoldXml {
    fn from(value: bool) -> Self {
        Self {
            status: if value { "ON" } else { "OFF" }.to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "WebsiteConfiguration")]
struct WebsiteConfigurationXml {
    #[serde(rename = "Enabled")]
    enabled: bool,
    #[serde(rename = "IndexDocument")]
    index_document: String,
    #[serde(rename = "ErrorDocument")]
    error_document: String,
    #[serde(rename = "AccessProfile")]
    access_profile: String,
}

fn website_config_from_xml(
    tenant_id: hsp_core::TenantId,
    bucket: &str,
    value: WebsiteConfigurationXml,
) -> WebsiteConfig {
    WebsiteConfig {
        tenant_id,
        bucket: bucket.to_string(),
        enabled: value.enabled,
        index_document: value.index_document,
        error_document: value.error_document,
        access_profile: match value.access_profile.as_str() {
            "trusted-edge-v1" => AccessProfile::TrustedEdgeV1,
            _ => AccessProfile::PublicCiphertext,
        },
        updated_at_ms: 0,
    }
}

impl From<WebsiteConfig> for WebsiteConfigurationXml {
    fn from(value: WebsiteConfig) -> Self {
        Self {
            enabled: value.enabled,
            index_document: value.index_document,
            error_document: value.error_document,
            access_profile: value.access_profile.as_str().to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "ReplicationConfiguration")]
struct ReplicationConfigurationXml {
    #[serde(rename = "DestinationBucket")]
    destination_bucket: String,
    #[serde(rename = "Prefix", skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(rename = "Enabled")]
    enabled: bool,
}

fn replication_config_from_xml(
    tenant_id: hsp_core::TenantId,
    source_bucket: &str,
    value: ReplicationConfigurationXml,
) -> ReplicationConfig {
    ReplicationConfig {
        tenant_id,
        source_bucket: source_bucket.to_string(),
        destination_bucket: value.destination_bucket,
        prefix: value.prefix,
        enabled: value.enabled,
        updated_at_ms: 0,
    }
}

impl From<ReplicationConfig> for ReplicationConfigurationXml {
    fn from(value: ReplicationConfig) -> Self {
        Self {
            destination_bucket: value.destination_bucket,
            prefix: value.prefix,
            enabled: value.enabled,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "ReplicationStatus")]
struct ReplicationStatusXml {
    #[serde(rename = "SourceBucket")]
    source_bucket: String,
    #[serde(rename = "DestinationBucket")]
    destination_bucket: String,
    #[serde(rename = "CopiedObjects")]
    copied_objects: u64,
    #[serde(rename = "FailedObjects")]
    failed_objects: u64,
    #[serde(rename = "LastRunMs")]
    last_run_ms: u64,
    #[serde(rename = "LastError", skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
}

impl From<hsp_distribution::ReplicationStatus> for ReplicationStatusXml {
    fn from(value: hsp_distribution::ReplicationStatus) -> Self {
        Self {
            source_bucket: value.source_bucket,
            destination_bucket: value.destination_bucket,
            copied_objects: value.copied_objects,
            failed_objects: value.failed_objects,
            last_run_ms: value.last_run_ms,
            last_error: value.last_error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    use axum::body::Body;
    use base64::Engine as _;
    use tower::ServiceExt;

    static NEXT_TEMP_ROOT_ID: AtomicU64 = AtomicU64::new(1);

    #[tokio::test]
    async fn root_without_auth_is_rejected() {
        let app = router(Arc::new(S3State {
            service: Arc::new(build_test_service()),
            virtual_host_suffix: None,
        }));
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn path_style_routing_preserves_empty_key_segments() {
        let route = resolve_bucket_and_key(
            &HeaderMap::new(),
            &"/media/a//b".parse::<Uri>().unwrap(),
            None,
        )
        .unwrap();

        assert_eq!(route.bucket.as_deref(), Some("media"));
        assert_eq!(route.key.as_deref(), Some("a//b"));
    }

    fn build_test_service() -> DistributionService {
        let root = std::env::temp_dir().join(format!(
            "hsp-s3-test-{}-{}",
            std::process::id(),
            NEXT_TEMP_ROOT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        let signing_key = SigningKey::from_bytes(&[21u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let registry_path = root.join("issuer-registry.json");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            &registry_path,
            serde_json::to_vec_pretty(&IssuerRegistry {
                issuers: vec![hsp_auth::IssuerRecord {
                    issuer: "dist".to_string(),
                    key_id: "dist-key".to_string(),
                    algorithm: "Ed25519".to_string(),
                    public_key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(verifying_key.as_bytes()),
                    audiences: vec!["hsp-s3".to_string()],
                }],
            })
            .unwrap(),
        )
        .unwrap();
        build_distribution_service(&S3ServerConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            authority: "localhost".to_string(),
            gateway_base_url: "https://localhost".to_string(),
            root_dir: root,
            storage_backend: StorageBackendConfig::Filesystem,
            server_instance_id: "test".to_string(),
            capability_audience: "hsp-s3".to_string(),
            immutable_cid_ttl_sec: 3600,
            namespace_ttl_sec: 5,
            issuer_registry_path: registry_path,
            namespace_signing_seed: [21u8; 32],
            namespace_signing_key_id: "dist-key".to_string(),
            edge_signing_secret: b"s3-test-edge-secret-000000000001".to_vec(),
            kms_seed: b"hsp-s3-runtime-seed".to_vec(),
            aws_kms: None,
            virtual_host_suffix: None,
            sigv4_access_keys: Vec::new(),
        })
        .unwrap()
    }
}
