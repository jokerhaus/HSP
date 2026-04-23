use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use ed25519_dalek::SigningKey;
use hsp_auth::IssuerRegistry;
use hsp_core::{
    ApiError, ApiErrorCategory, CapabilityClaims, CapabilityScope, EventRecord, EventType,
    RangeSpec, SubscribeEnvelopeKind, SubscribeFilter, SubscribeRequest, TenantId,
};
use hsp_crypto::{AwsKmsProviderConfig, LocalDevKms};
use hsp_distribution::{
    AccessProfile, DistributionConfig, DistributionService, GetObjectRequest, HttpRequestBinding,
};
use hsp_service::AlphaConfig;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdnServerConfig {
    pub bind_addr: SocketAddr,
    pub authority: String,
    pub gateway_base_url: String,
    pub root_dir: PathBuf,
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
}

#[derive(Clone)]
struct CdnState {
    service: Arc<DistributionService>,
    cache: Arc<Mutex<BTreeMap<String, CachedObject>>>,
    immutable_cid_ttl_sec: u64,
    namespace_ttl_sec: u64,
}

#[derive(Debug, Clone)]
struct CachedObject {
    body: Bytes,
    content_type: String,
    etag: String,
    cache_control: String,
    content_length: u64,
    expires_at_ms: u64,
}

pub async fn run_cdn_server(
    config: CdnServerConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = Arc::new(CdnState {
        service: Arc::new(build_distribution_service(&config)?),
        cache: Arc::new(Mutex::new(BTreeMap::new())),
        immutable_cid_ttl_sec: config.immutable_cid_ttl_sec,
        namespace_ttl_sec: config.namespace_ttl_sec,
    });
    spawn_cache_invalidation_worker(state.clone());
    let listener = TcpListener::bind(config.bind_addr).await?;
    axum::serve(listener, router(state)).await?;
    Ok(())
}

fn router(state: Arc<CdnState>) -> Router {
    Router::new()
        .route("/cid/{cid}", any(handle_request))
        .route("/b/{bucket}/{*key}", any(handle_request))
        .with_state(state)
}

fn build_distribution_service(config: &CdnServerConfig) -> Result<DistributionService, ApiError> {
    let issuer_registry = IssuerRegistry::load(&config.issuer_registry_path)?;
    DistributionService::new(
        DistributionConfig {
            alpha: AlphaConfig {
                authority: config.authority.clone(),
                gateway_base_url: config.gateway_base_url.clone(),
                root_dir: config.root_dir.clone(),
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
    )
}

async fn handle_request(
    State(state): State<Arc<CdnState>>,
    method: Method,
    headers: HeaderMap,
    uri: OriginalUri,
    request: Request<Body>,
) -> impl IntoResponse {
    if method != Method::GET && method != Method::HEAD {
        return api_error_response(ApiError::new(
            ApiErrorCategory::Unsupported,
            "method_not_allowed",
            "CDN only supports GET and HEAD",
        ));
    }

    let uri = uri.0;
    let path = uri.path().to_string();
    let query = uri.query().unwrap_or_default().to_string();
    let body = match to_bytes(request.into_body(), usize::MAX).await {
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

    let auth = match authenticate_request(&state.service, &method, &path, &query, &headers, &body) {
        Ok(auth) => auth,
        Err(error) => return api_error_response(error),
    };
    let edge_claims = edge_claims(&state.service, &headers, &query).ok();

    match dispatch_request(&state, &auth, edge_claims, &method, &headers, &path, &query).await {
        Ok(response) => response,
        Err(error) => api_error_response(error),
    }
}

fn authenticate_request(
    service: &DistributionService,
    method: &Method,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<hsp_auth::AuthContext, ApiError> {
    let query_params = query_pairs(query);
    if let Some(token) = headers
        .get("x-hsp-edge-token")
        .and_then(|value| value.to_str().ok())
        .or_else(|| query_params.get("token").map(String::as_str))
    {
        service.authenticate_edge_token(token)
    } else if headers.contains_key("x-hsp-capability") {
        service.authenticate_hsp_capability(&HttpRequestBinding {
            method: method.as_str(),
            raw_path: path,
            raw_query: query,
            headers,
            body,
        })
    } else if headers.contains_key("authorization") || query.contains("X-Amz-Signature=") {
        service.authenticate_sigv4(&HttpRequestBinding {
            method: method.as_str(),
            raw_path: path,
            raw_query: query,
            headers,
            body,
        })
    } else {
        Err(ApiError::new(
            ApiErrorCategory::Auth,
            "missing_auth",
            "CDN requests require edge token, HSP capability auth, or SigV4 auth",
        ))
    }
}

fn edge_claims(
    service: &DistributionService,
    headers: &HeaderMap,
    query: &str,
) -> Result<hsp_distribution::EdgeTokenClaims, ApiError> {
    let query_params = query_pairs(query);
    let token = headers
        .get("x-hsp-edge-token")
        .and_then(|value| value.to_str().ok())
        .or_else(|| query_params.get("token").map(String::as_str))
        .ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "missing_edge_token",
                "edge token is missing",
            )
        })?;
    service.decode_edge_token(token)
}

async fn dispatch_request(
    state: &CdnState,
    auth: &hsp_auth::AuthContext,
    edge_claims: Option<hsp_distribution::EdgeTokenClaims>,
    method: &Method,
    headers: &HeaderMap,
    path: &str,
    query: &str,
) -> Result<Response<Body>, ApiError> {
    if let Some(cid) = path.strip_prefix("/cid/") {
        if let Some(claims) = &edge_claims {
            if claims.cid.as_deref() != Some(cid) {
                return Err(ApiError::new(
                    ApiErrorCategory::Auth,
                    "invalid_edge_token_scope",
                    "edge token is not scoped to the requested CID",
                ));
            }
        }
        let prefer_plaintext = edge_claims
            .as_ref()
            .map(|claims| claims.access_profile == AccessProfile::TrustedEdgeV1)
            .unwrap_or(false)
            && query_pairs(query)
                .get("mode")
                .map(|mode| mode == "plaintext")
                .unwrap_or(false);
        let range = parse_range(headers)?;
        return serve_cached_object(
            state,
            method,
            cid_cache_key(&auth.claims.tenant_id, cid, prefer_plaintext),
            true,
            range.is_none(),
            || async {
                state.service.get_object(
                    auth,
                    GetObjectRequest {
                        tenant_id: auth.claims.tenant_id.clone(),
                        bucket: None,
                        key: None,
                        cid: Some(cid.to_string()),
                        access_profile: edge_claims
                            .as_ref()
                            .map(|claims| claims.access_profile)
                            .unwrap_or(AccessProfile::PublicCiphertext),
                        prefer_plaintext,
                        range,
                        if_match: None,
                        if_none_match: None,
                    },
                )
            },
        )
        .await;
    }

    if let Some(raw) = path.strip_prefix("/b/") {
        let (bucket, key) = raw.split_once('/').ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::Validation,
                "invalid_bucket_path",
                "bucket route must use /b/{bucket}/{key}",
            )
        })?;
        if let Some(claims) = &edge_claims {
            if claims.bucket.as_deref() != Some(bucket) || claims.key.as_deref() != Some(key) {
                return Err(ApiError::new(
                    ApiErrorCategory::Auth,
                    "invalid_edge_token_scope",
                    "edge token is not scoped to the requested bucket/key",
                ));
            }
        }
        let prefer_plaintext = edge_claims
            .as_ref()
            .map(|claims| claims.access_profile == AccessProfile::TrustedEdgeV1)
            .unwrap_or(false)
            && query_pairs(query)
                .get("mode")
                .map(|mode| mode == "plaintext")
                .unwrap_or(false);
        let range = parse_range(headers)?;
        return serve_cached_object(
            state,
            method,
            namespace_cache_key(&auth.claims.tenant_id, bucket, key, prefer_plaintext),
            false,
            range.is_none(),
            || async {
                state.service.get_object(
                    auth,
                    GetObjectRequest {
                        tenant_id: auth.claims.tenant_id.clone(),
                        bucket: Some(bucket.to_string()),
                        key: Some(key.to_string()),
                        cid: None,
                        access_profile: edge_claims
                            .as_ref()
                            .map(|claims| claims.access_profile)
                            .unwrap_or(AccessProfile::PublicCiphertext),
                        prefer_plaintext,
                        range,
                        if_match: None,
                        if_none_match: None,
                    },
                )
            },
        )
        .await;
    }

    Err(ApiError::new(
        ApiErrorCategory::NotFound,
        "route_not_found",
        "CDN route not found",
    ))
}

async fn serve_cached_object<F, Fut>(
    state: &CdnState,
    method: &Method,
    cache_key: String,
    immutable: bool,
    allow_cache_hit: bool,
    fetch: F,
) -> Result<Response<Body>, ApiError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<hsp_distribution::GetObjectResponse, ApiError>>,
{
    let now = now_ms();
    if allow_cache_hit {
        if let Some(entry) = state.cache.lock().await.get(&cache_key).cloned() {
            if entry.expires_at_ms >= now {
                return cached_response(method, entry, "HIT");
            }
        }
    }

    let fresh = fetch().await?;
    let response = origin_response(method, &fresh, "MISS")?;
    let ttl = if immutable {
        state.immutable_cid_ttl_sec
    } else {
        state.namespace_ttl_sec
    };
    if fresh.content_range.is_none() && is_cacheable(&fresh) {
        let entry = CachedObject {
            body: Bytes::from(fresh.body.clone()),
            content_type: fresh.head.content_type.clone(),
            etag: fresh.head.etag.clone(),
            cache_control: fresh.cache_control.clone(),
            content_length: fresh.head.content_length,
            expires_at_ms: now.saturating_add(ttl * 1_000),
        };
        state.cache.lock().await.insert(cache_key, entry);
    }
    Ok(response)
}

fn cached_response(
    method: &Method,
    entry: CachedObject,
    cache_status: &str,
) -> Result<Response<Body>, ApiError> {
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("etag", format!("\"{}\"", entry.etag))
        .header("content-type", entry.content_type)
        .header("content-length", entry.content_length.to_string())
        .header("cache-control", entry.cache_control)
        .header("x-hsp-cache-status", cache_status)
        .body(if *method == Method::HEAD {
            Body::empty()
        } else {
            Body::from(entry.body)
        })
        .map_err(http_error)?;
    Ok(response)
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

fn origin_response(
    method: &Method,
    response: &hsp_distribution::GetObjectResponse,
    cache_status: &str,
) -> Result<Response<Body>, ApiError> {
    let mut builder = Response::builder()
        .status(if response.content_range.is_some() {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        })
        .header("etag", format!("\"{}\"", response.head.etag))
        .header("content-type", response.head.content_type.as_str())
        .header("content-length", response.body.len().to_string())
        .header("cache-control", response.cache_control.as_str())
        .header("x-hsp-cache-status", cache_status)
        .header("x-hsp-exists", response.head.exists.to_string())
        .header("x-hsp-deleted", response.head.deleted.to_string())
        .header("x-hsp-cid", response.head.cid.as_str())
        .header("x-hsp-object-cid", response.head.object_cid.as_str())
        .header("x-hsp-manifest-cid", response.head.manifest_cid.as_str())
        .header(
            "x-hsp-integrity-hash",
            response.head.integrity_hash.as_str(),
        )
        .header("x-hsp-size-bytes", response.head.size_bytes.to_string())
        .header(
            "x-hsp-ciphertext-size-bytes",
            response.head.ciphertext_size_bytes.to_string(),
        )
        .header(
            "x-hsp-created-at-ms",
            response.head.last_modified_ms.to_string(),
        )
        .header(
            "x-hsp-encryption-profile-id",
            response.head.encryption_profile_id.0.as_str(),
        )
        .header(
            "x-hsp-key-policy-id",
            response.head.key_policy_id.0.as_str(),
        )
        .header(
            "x-hsp-metadata-visibility",
            response.head.metadata_visibility.as_str(),
        )
        .header(
            "x-hsp-encrypted-client-metadata-redacted",
            response.head.encrypted_client_metadata_redacted.to_string(),
        );
    if let Some(content_range) = &response.content_range {
        builder = builder.header("content-range", content_range.as_str());
    }
    builder
        .body(if *method == Method::HEAD {
            Body::empty()
        } else {
            Body::from(response.body.clone())
        })
        .map_err(http_error)
}

fn require_scope(auth: &hsp_auth::AuthContext, scope: CapabilityScope) -> Result<(), ApiError> {
    if auth.claims.ops.contains(&scope) {
        return Ok(());
    }
    Err(ApiError::new(
        ApiErrorCategory::Policy,
        "missing_required_scope",
        format!("{} scope is required", scope.as_str()),
    ))
}

fn is_cacheable(response: &hsp_distribution::GetObjectResponse) -> bool {
    !response
        .cache_control
        .split(',')
        .any(|directive| directive.trim().eq_ignore_ascii_case("no-store"))
}

fn parse_range(headers: &HeaderMap) -> Result<Option<RangeSpec>, ApiError> {
    let Some(header) = headers.get("range").and_then(|value| value.to_str().ok()) else {
        return Ok(None);
    };
    let raw = header.strip_prefix("bytes=").ok_or_else(invalid_range)?;
    let (start, end) = raw.split_once('-').ok_or_else(invalid_range)?;
    Ok(Some(RangeSpec {
        start: start.parse().map_err(|_| invalid_range())?,
        end: end.parse().map_err(|_| invalid_range())?,
    }))
}

fn query_pairs(query: &str) -> BTreeMap<String, String> {
    query
        .split('&')
        .filter(|segment| !segment.is_empty())
        .map(|segment| segment.split_once('=').unwrap_or((segment, "")))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn invalid_range() -> ApiError {
    ApiError::new(
        ApiErrorCategory::Validation,
        "invalid_range",
        "Range header is invalid",
    )
}

fn api_error_response(error: ApiError) -> Response<Body> {
    let status = match error.category {
        ApiErrorCategory::Auth | ApiErrorCategory::Policy => StatusCode::FORBIDDEN,
        ApiErrorCategory::Replay | ApiErrorCategory::Conflict => StatusCode::CONFLICT,
        ApiErrorCategory::Validation | ApiErrorCategory::Unsupported => StatusCode::BAD_REQUEST,
        ApiErrorCategory::NotFound => StatusCode::NOT_FOUND,
        ApiErrorCategory::Storage => StatusCode::INTERNAL_SERVER_ERROR,
    };
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&ErrorBody::from(error)).unwrap_or_else(|_| b"{}".to_vec()),
        ))
        .expect("cdn error response")
}

fn http_error(error: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        ApiErrorCategory::Storage,
        "http_build_failed",
        error.to_string(),
    )
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

fn spawn_cache_invalidation_worker(state: Arc<CdnState>) {
    tokio::spawn(async move {
        let mut cursors: BTreeMap<String, String> = BTreeMap::new();
        loop {
            let tenants = tenant_ids_from_cache(&state.cache).await;
            for tenant in tenants {
                let result = poll_cache_invalidation_events(&state, &tenant, &mut cursors).await;
                if let Err(error) = result {
                    // Cursor can age out; retry from latest position on next loop.
                    if error.code == "cursor_expired" || error.code == "invalid_cursor" {
                        cursors.remove(&tenant.0);
                        continue;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(750)).await;
        }
    });
}

async fn tenant_ids_from_cache(cache: &Mutex<BTreeMap<String, CachedObject>>) -> Vec<TenantId> {
    let guard = cache.lock().await;
    let mut tenants = BTreeMap::<String, ()>::new();
    for key in guard.keys() {
        if let Some(raw) = key.strip_prefix("ns:") {
            if let Some((tenant, _)) = raw.split_once(':') {
                tenants.insert(tenant.to_string(), ());
            }
        }
    }
    tenants.into_keys().map(TenantId).collect()
}

async fn poll_cache_invalidation_events(
    state: &CdnState,
    tenant_id: &TenantId,
    cursors: &mut BTreeMap<String, String>,
) -> Result<(), ApiError> {
    let auth = internal_subscribe_auth(tenant_id.clone());
    let subscribe = SubscribeRequest {
        tenant_id: tenant_id.clone(),
        filters: vec![SubscribeFilter {
            namespace_prefix: None,
            path_exact: None,
            object_cid: None,
            event_type: None,
            tenant_scope: None,
        }],
        cursor: cursors.get(&tenant_id.0).cloned(),
        from_seq: (!cursors.contains_key(&tenant_id.0)).then_some(0),
        heartbeat_ms: Some(50),
        batch_max: Some(128),
    };
    let cursor = state.service.alpha().subscribe_start(&auth, &subscribe)?;
    let (envelopes, next_cursor) = state
        .service
        .alpha()
        .subscribe_poll(&auth, &subscribe, &cursor)?;
    cursors.insert(tenant_id.0.clone(), next_cursor.encode());

    let mut cache = state.cache.lock().await;
    for envelope in envelopes {
        if envelope.kind != SubscribeEnvelopeKind::Event {
            continue;
        }
        if let Some(event) = envelope.event {
            apply_event_invalidation(&mut cache, tenant_id, &event);
        }
    }
    Ok(())
}

fn internal_subscribe_auth(tenant_id: TenantId) -> hsp_auth::AuthContext {
    hsp_auth::AuthContext {
        claims: CapabilityClaims {
            iss: "hsp-cdn".to_string(),
            sub: "cache-invalidator".to_string(),
            aud: "hsp-cdn".to_string(),
            exp: now_ms().saturating_add(30_000),
            nbf: Some(now_ms().saturating_sub(1_000)),
            jti: None,
            ops: vec![CapabilityScope::Read, CapabilityScope::Subscribe],
            tenant_id,
            namespace_prefix: None,
            path_prefix: None,
            max_object_size: None,
            storage_classes: vec!["hot".to_string()],
            key_policy_id: None,
            metadata_visibility: None,
        },
        channel_binding: None,
    }
}

fn apply_event_invalidation(
    cache: &mut BTreeMap<String, CachedObject>,
    tenant_id: &TenantId,
    event: &EventRecord,
) {
    match event.event_type {
        EventType::NamespaceBound
        | EventType::NamespaceUnbound
        | EventType::NamespaceTombstoned
        | EventType::ObjectCommitted => {
            if let (Some(namespace), Some(path)) =
                (event.namespace.as_deref(), event.path.as_deref())
            {
                cache.remove(&namespace_cache_key(tenant_id, namespace, path, false));
                cache.remove(&namespace_cache_key(tenant_id, namespace, path, true));
            }
        }
        _ => {}
    }
}

fn cid_cache_key(tenant_id: &TenantId, cid: &str, plaintext: bool) -> String {
    format!("cid:{}:{}:{cid}", tenant_id.0, cache_mode_suffix(plaintext))
}

fn namespace_cache_key(tenant_id: &TenantId, bucket: &str, key: &str, plaintext: bool) -> String {
    format!(
        "ns:{}:{}:{}/{}",
        tenant_id.0,
        cache_mode_suffix(plaintext),
        bucket,
        key
    )
}

fn cache_mode_suffix(plaintext: bool) -> &'static str {
    if plaintext {
        "plaintext"
    } else {
        "ciphertext"
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorBody {
    code: String,
    message: String,
}

impl From<ApiError> for ErrorBody {
    fn from(value: ApiError) -> Self {
        Self {
            code: value.code,
            message: value.message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::Engine as _;
    use hsp_auth::IssuerRecord;
    use tower::ServiceExt;

    #[tokio::test]
    async fn route_without_auth_is_rejected() {
        let app = router(Arc::new(CdnState {
            service: Arc::new(build_test_service()),
            cache: Arc::new(Mutex::new(BTreeMap::new())),
            immutable_cid_ttl_sec: 3600,
            namespace_ttl_sec: 5,
        }));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/cid/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn namespace_events_purge_namespace_cache_entry() {
        let mut cache = BTreeMap::new();
        cache.insert(
            namespace_cache_key(
                &TenantId("tenant-alpha".to_string()),
                "media",
                "folder/object.bin",
                false,
            ),
            CachedObject {
                body: Bytes::from_static(b"ciphertext"),
                content_type: "application/octet-stream".to_string(),
                etag: "etag".to_string(),
                cache_control: "private,max-age=5".to_string(),
                content_length: 10,
                expires_at_ms: now_ms() + 5_000,
            },
        );
        apply_event_invalidation(
            &mut cache,
            &TenantId("tenant-alpha".to_string()),
            &EventRecord {
                version: 1,
                seq: 1,
                at_ms: now_ms(),
                event_type: EventType::NamespaceUnbound,
                subject_kind: "namespace".to_string(),
                namespace: Some("media".to_string()),
                path: Some("folder/object.bin".to_string()),
                cid: None,
                revision: Some(2),
                trace_id: None,
                payload: BTreeMap::new(),
            },
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn cid_cache_keys_are_tenant_scoped() {
        assert_ne!(
            cid_cache_key(&TenantId("tenant-alpha".to_string()), "cid-1", false),
            cid_cache_key(&TenantId("tenant-beta".to_string()), "cid-1", false)
        );
    }

    #[test]
    fn plaintext_responses_are_not_cacheable() {
        let response = hsp_distribution::GetObjectResponse {
            head: hsp_distribution::HeadObjectResponse {
                exists: true,
                deleted: false,
                cid: "cid-1".to_string(),
                bucket: "media".to_string(),
                key: "plain.txt".to_string(),
                object_cid: "cid-1".to_string(),
                manifest_cid: "cid-1".to_string(),
                integrity_hash: "cid-1".to_string(),
                etag: "cid-1".to_string(),
                size_bytes: 5,
                ciphertext_size_bytes: 5,
                content_length: 5,
                content_type: "text/plain".to_string(),
                last_modified_ms: now_ms(),
                encryption_profile_id: hsp_core::EncryptionProfileId("trusted-edge-v1".to_string()),
                key_policy_id: hsp_core::KeyPolicyId("policy-default".to_string()),
                server_visible_metadata: BTreeMap::new(),
                encrypted_client_metadata_redacted: true,
                metadata_visibility: hsp_core::VisibilityMode::Split,
            },
            body: b"hello".to_vec(),
            immutable: false,
            cache_control: "private, no-store".to_string(),
            content_range: None,
        };
        assert!(!is_cacheable(&response));
    }

    fn build_test_service() -> DistributionService {
        let root = std::env::temp_dir().join(format!("hsp-cdn-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let signing_key = SigningKey::from_bytes(&[33u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let registry_path = root.join("issuer-registry.json");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            &registry_path,
            serde_json::to_vec_pretty(&IssuerRegistry {
                issuers: vec![IssuerRecord {
                    issuer: "dist".to_string(),
                    key_id: "dist-key".to_string(),
                    algorithm: "Ed25519".to_string(),
                    public_key_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(verifying_key.as_bytes()),
                    audiences: vec!["hsp-cdn".to_string()],
                }],
            })
            .unwrap(),
        )
        .unwrap();
        build_distribution_service(&CdnServerConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            authority: "localhost".to_string(),
            gateway_base_url: "https://localhost".to_string(),
            root_dir: root,
            server_instance_id: "test".to_string(),
            capability_audience: "hsp-cdn".to_string(),
            immutable_cid_ttl_sec: 3600,
            namespace_ttl_sec: 5,
            issuer_registry_path: registry_path,
            namespace_signing_seed: [33u8; 32],
            namespace_signing_key_id: "dist-key".to_string(),
            edge_signing_secret: b"edge-secret".to_vec(),
            kms_seed: b"hsp-cdn-runtime-seed".to_vec(),
            aws_kms: None,
        })
        .unwrap()
    }
}
