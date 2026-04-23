use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bytes::{Buf, Bytes};
use h3::server::Connection as H3Connection;
use h3_quinn::Connection as H3QuinnConnection;
use http::header::{HeaderName, CONTENT_TYPE};
use http::{Method, Request, Response, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Connection, Endpoint, ServerConfig};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::task::JoinHandle;
use tokio::time::sleep;

use hsp_auth::{
    tls_exporter_label, verify_cose_sign1_token, verify_tls_exporter_binding, AuthContext,
    IssuerRegistry,
};
use hsp_core::{
    ApiError, ApiErrorCategory, BindRequest, GetPreference, GetRequest, HeadRequest, ListRequest,
    ObjectSelector, PutChunkRequest, PutCommitRequest, PutInitRequest, ResolveRequest,
    SubscribeEnvelopeKind, SubscribeFilter, SubscribeRequest, UnbindRequest,
};
use hsp_service::{AlphaConfig, AlphaService};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayBetaConfig {
    pub bind_addr: SocketAddr,
    pub authority: String,
    pub gateway_base_url: String,
    pub root_dir: PathBuf,
    pub issuer_registry_path: PathBuf,
    pub server_instance_id: String,
    pub native_port: u16,
}

pub struct GatewayBetaHandle {
    endpoint: Endpoint,
    task: JoinHandle<()>,
    pub local_addr: SocketAddr,
    pub certificate_der: Vec<u8>,
}

struct GatewayState {
    service: Arc<AlphaService>,
    issuer_registry: Arc<IssuerRegistry>,
}

type GatewayBodyResponse = Result<(Response<()>, Option<Vec<Bytes>>), Box<dyn Error + Send + Sync>>;

impl GatewayBetaHandle {
    pub async fn shutdown(self) {
        self.endpoint.close(0u32.into(), b"shutdown");
        self.task.abort();
    }
}

pub async fn spawn_gateway_beta_server(
    config: GatewayBetaConfig,
) -> Result<GatewayBetaHandle, Box<dyn Error + Send + Sync>> {
    install_crypto_provider();
    let issuer_registry = Arc::new(IssuerRegistry::load(&config.issuer_registry_path)?);
    let (server_config, certificate_der) = build_server_config(&config.authority)?;
    let endpoint = Endpoint::server(server_config, config.bind_addr)?;
    let local_addr = endpoint.local_addr()?;
    let gateway_base_url = if config.bind_addr.port() == 0 {
        resolved_gateway_base_url(&config.gateway_base_url, local_addr.port())
    } else {
        config.gateway_base_url.clone()
    };
    let service = Arc::new(
        AlphaService::new(
            AlphaConfig {
                authority: config.authority.clone(),
                gateway_base_url,
                root_dir: config.root_dir.clone(),
                native_port: config.native_port,
                server_instance_id: config.server_instance_id.clone(),
            },
            hsp_crypto::LocalDevKms::from_seed(b"hsp-secure-alpha-local-seed").map_err(
                |error| {
                    hsp_crypto::crypto_error_to_api(error, "failed to initialize local dev KMS")
                },
            )?,
        )?
        .with_issuer_registry((*issuer_registry).clone()),
    );
    let state = Arc::new(GatewayState {
        service,
        issuer_registry,
    });
    let accept_endpoint = endpoint.clone();
    let task = tokio::spawn(async move {
        while let Some(connecting) = accept_endpoint.accept().await {
            let state = state.clone();
            tokio::spawn(async move {
                if let Ok(connection) = connecting.await {
                    let _ = handle_gateway_connection(connection, state).await;
                }
            });
        }
    });

    Ok(GatewayBetaHandle {
        endpoint,
        task,
        local_addr,
        certificate_der,
    })
}

async fn handle_gateway_connection(
    connection: Connection,
    state: Arc<GatewayState>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let h3_conn = H3QuinnConnection::new(connection.clone());
    let mut h3 = H3Connection::new(h3_conn).await?;

    loop {
        match h3.accept().await {
            Ok(Some(resolver)) => {
                let (request, mut stream) = match resolver.resolve_request().await {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                if request.method() == Method::GET && request.uri().path() == "/v1/events" {
                    if let Err(error) =
                        handle_gateway_subscribe(&connection, &state, &request, &mut stream).await
                    {
                        let (response, body) = error_response(&error)?;
                        stream.send_response(response).await?;
                        if let Some(body) = body {
                            for chunk in body {
                                stream.send_data(chunk).await?;
                            }
                        }
                        stream.finish().await?;
                    }
                    continue;
                }
                let response = route_request(&connection, &state, &request, &mut stream).await;
                match response {
                    Ok((response, maybe_body)) => {
                        stream.send_response(response).await?;
                        if let Some(body) = maybe_body {
                            for chunk in body {
                                stream.send_data(chunk).await?;
                            }
                        }
                        stream.finish().await?;
                    }
                    Err(error) => {
                        let (response, body) = error_response(&error)?;
                        stream.send_response(response).await?;
                        if let Some(body) = body {
                            for chunk in body {
                                stream.send_data(chunk).await?;
                            }
                        }
                        stream.finish().await?;
                    }
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }

    Ok(())
}

async fn route_request<T>(
    connection: &Connection,
    state: &GatewayState,
    request: &Request<()>,
    stream: &mut h3::server::RequestStream<T, Bytes>,
) -> Result<(Response<()>, Option<Vec<Bytes>>), ApiError>
where
    T: h3::quic::BidiStream<Bytes>,
{
    let path = request.uri().path();
    let query = request.uri().query().unwrap_or_default();

    match (request.method(), path) {
        (&Method::GET, "/.well-known/hsp") => Ok(json_response(
            StatusCode::OK,
            &state.service.bootstrap_document(),
        )?),
        (&Method::GET, "/v1/info") => Ok(json_response(StatusCode::OK, &state.service.info())?),
        (&Method::POST, "/v1/uploads") => {
            let auth = verify_gateway_auth(connection, request.headers(), &state.issuer_registry)?;
            let body = read_http_body(stream).await.map_err(http_body_error)?;
            let request: PutInitRequest = serde_json::from_slice(&body).map_err(bad_json)?;
            let response = state.service.put_init(&auth, request)?;
            Ok(json_response(StatusCode::OK, &response)?)
        }
        (&Method::GET, object_path) if object_path.starts_with("/v1/objects/namespace/") => {
            let (namespace, path) =
                split_namespace_object_route(object_path, "/v1/objects/namespace/")?;
            let auth = verify_gateway_auth(connection, request.headers(), &state.issuer_registry)?;
            let prefer = query_value(query, "prefer").and_then(parse_preference);
            let range = match (
                query_value(query, "range_start"),
                query_value(query, "range_end"),
            ) {
                (Some(start), Some(end)) => Some(hsp_core::RangeSpec {
                    start: start.parse().map_err(|_| invalid_range())?,
                    end: end.parse().map_err(|_| invalid_range())?,
                }),
                _ => None,
            };
            let response = state.service.get(
                &auth,
                GetRequest {
                    tenant_id: tenant_from_query(query)?,
                    selector: ObjectSelector::namespace(namespace, path),
                    preference: prefer,
                    range,
                },
            )?;
            if response.meta.preference == GetPreference::ManifestOnly {
                Ok(json_response(StatusCode::OK, &response.meta)?)
            } else {
                Ok(chunk_stream_response(&response.meta, &response.chunks)?)
            }
        }
        (&Method::HEAD, object_path) if object_path.starts_with("/v1/objects/namespace/") => {
            let (namespace, path) =
                split_namespace_object_route(object_path, "/v1/objects/namespace/")?;
            let auth = verify_gateway_auth(connection, request.headers(), &state.issuer_registry)?;
            let response = state.service.head(
                &auth,
                HeadRequest {
                    tenant_id: tenant_from_query(query)?,
                    selector: ObjectSelector::namespace(namespace, path),
                },
            )?;
            Ok(head_response(&response)?)
        }
        (&Method::GET, object_path) if object_path.starts_with("/v1/objects/cid/") => {
            let cid = object_path
                .trim_start_matches("/v1/objects/cid/")
                .to_string();
            if request.method() == Method::HEAD {
                unreachable!()
            }
            let auth = verify_gateway_auth(connection, request.headers(), &state.issuer_registry)?;
            let prefer = query_value(query, "prefer").and_then(parse_preference);
            let range = match (
                query_value(query, "range_start"),
                query_value(query, "range_end"),
            ) {
                (Some(start), Some(end)) => Some(hsp_core::RangeSpec {
                    start: start.parse().map_err(|_| invalid_range())?,
                    end: end.parse().map_err(|_| invalid_range())?,
                }),
                _ => None,
            };
            let response = state.service.get(
                &auth,
                GetRequest {
                    tenant_id: tenant_from_query(query)?,
                    selector: ObjectSelector::cid(cid),
                    preference: prefer,
                    range,
                },
            )?;
            if response.meta.preference == GetPreference::ManifestOnly {
                Ok(json_response(StatusCode::OK, &response.meta)?)
            } else {
                Ok(chunk_stream_response(&response.meta, &response.chunks)?)
            }
        }
        (&Method::HEAD, object_path) if object_path.starts_with("/v1/objects/cid/") => {
            let cid = object_path
                .trim_start_matches("/v1/objects/cid/")
                .to_string();
            let auth = verify_gateway_auth(connection, request.headers(), &state.issuer_registry)?;
            let response = state.service.head(
                &auth,
                HeadRequest {
                    tenant_id: tenant_from_query(query)?,
                    selector: ObjectSelector::cid(cid),
                },
            )?;
            Ok(head_response(&response)?)
        }
        (&Method::PUT, chunk_path)
            if chunk_path.starts_with("/v1/uploads/") && chunk_path.contains("/chunks/") =>
        {
            let auth = verify_gateway_auth(connection, request.headers(), &state.issuer_registry)?;
            let body = read_http_body(stream).await.map_err(http_body_error)?;
            let parts = chunk_path
                .trim_start_matches("/v1/uploads/")
                .split("/chunks/")
                .collect::<Vec<_>>();
            if parts.len() != 2 {
                return Err(ApiError::new(
                    ApiErrorCategory::Validation,
                    "invalid_chunk_path",
                    "invalid upload chunk path",
                ));
            }
            let request = PutChunkRequest {
                tenant_id: tenant_from_query(query)?,
                session_id: parts[0].to_string(),
                chunk_index: parts[1].parse().map_err(|_| {
                    ApiError::new(
                        ApiErrorCategory::Validation,
                        "invalid_chunk_index",
                        "invalid chunk index",
                    )
                })?,
                chunk_cid: required_query(query, "chunk_cid")?,
                chunk_offset: required_query(query, "chunk_offset")?
                    .parse()
                    .map_err(|_| {
                        ApiError::new(
                            ApiErrorCategory::Validation,
                            "invalid_chunk_offset",
                            "invalid chunk offset",
                        )
                    })?,
                chunk_length: required_query(query, "chunk_length")?
                    .parse()
                    .map_err(|_| {
                        ApiError::new(
                            ApiErrorCategory::Validation,
                            "invalid_chunk_length",
                            "invalid chunk length",
                        )
                    })?,
                content_encoding: required_query(query, "content_encoding")?,
            };
            let response = state.service.put_chunk(&auth, request, &body)?;
            Ok(json_response(StatusCode::OK, &response)?)
        }
        (&Method::POST, commit_path)
            if commit_path.starts_with("/v1/uploads/") && commit_path.ends_with(":commit") =>
        {
            let auth = verify_gateway_auth(connection, request.headers(), &state.issuer_registry)?;
            let body = read_http_body(stream).await.map_err(http_body_error)?;
            let mut commit: PutCommitRequest = serde_json::from_slice(&body).map_err(bad_json)?;
            commit.session_id = commit_path
                .trim_start_matches("/v1/uploads/")
                .trim_end_matches(":commit")
                .to_string();
            let response = state.service.put_commit(&auth, commit)?;
            Ok(json_response(StatusCode::OK, &response)?)
        }
        (&Method::GET, path)
            if path.starts_with("/v1/namespaces/") && path.contains("/resolve/") =>
        {
            let (namespace, item_path) = split_namespace_operation(path, "/resolve/")?;
            let auth = verify_gateway_auth(connection, request.headers(), &state.issuer_registry)?;
            let response = state.service.resolve(
                &auth,
                ResolveRequest {
                    tenant_id: tenant_from_query(query)?,
                    namespace,
                    path: item_path,
                    at_revision: query_value(query, "at_revision")
                        .map(|value| value.parse().map_err(|_| invalid_revision()))
                        .transpose()?,
                    if_revision: query_value(query, "if_revision")
                        .map(|value| value.parse().map_err(|_| invalid_revision()))
                        .transpose()?,
                },
            )?;
            Ok(json_response(StatusCode::OK, &response)?)
        }
        (&Method::PUT, path) if path.starts_with("/v1/namespaces/") && path.contains("/bind/") => {
            let (namespace, item_path) = split_namespace_operation(path, "/bind/")?;
            let auth = verify_gateway_auth(connection, request.headers(), &state.issuer_registry)?;
            let body = read_http_body(stream).await.map_err(http_body_error)?;
            let mut bind: BindRequest = serde_json::from_slice(&body).map_err(bad_json)?;
            bind.namespace = namespace;
            bind.path = item_path;
            let response = state.service.bind(&auth, bind)?;
            Ok(json_response(StatusCode::OK, &response)?)
        }
        (&Method::DELETE, path)
            if path.starts_with("/v1/namespaces/") && path.contains("/bind/") =>
        {
            let (namespace, item_path) = split_namespace_operation(path, "/bind/")?;
            let auth = verify_gateway_auth(connection, request.headers(), &state.issuer_registry)?;
            let body = read_http_body(stream).await.map_err(http_body_error)?;
            let mut unbind: UnbindRequest = serde_json::from_slice(&body).map_err(bad_json)?;
            unbind.namespace = namespace;
            unbind.path = item_path;
            let response = state.service.unbind(&auth, unbind)?;
            Ok(json_response(StatusCode::OK, &response)?)
        }
        (&Method::GET, path) if path.starts_with("/v1/namespaces/") && path.ends_with("/list") => {
            let namespace = path
                .trim_start_matches("/v1/namespaces/")
                .trim_end_matches("/list")
                .trim_end_matches('/')
                .to_string();
            let auth = verify_gateway_auth(connection, request.headers(), &state.issuer_registry)?;
            let response = state.service.list(
                &auth,
                ListRequest {
                    tenant_id: tenant_from_query(query)?,
                    namespace,
                    prefix: query_value(query, "prefix"),
                    cursor: query_value(query, "cursor"),
                    limit: query_value(query, "limit")
                        .map(|value| value.parse().map_err(|_| invalid_limit()))
                        .transpose()?,
                    recursive: query_value(query, "recursive")
                        .map(|value| value == "true")
                        .unwrap_or(false),
                    include_tombstones: query_value(query, "include_tombstones")
                        .map(|value| value == "true")
                        .unwrap_or(false),
                },
            )?;
            Ok(json_response(StatusCode::OK, &response)?)
        }
        _ => Err(ApiError::new(
            ApiErrorCategory::NotFound,
            "route_not_found",
            "gateway route not found",
        )),
    }
}

async fn handle_gateway_subscribe<T>(
    connection: &Connection,
    state: &GatewayState,
    request: &Request<()>,
    stream: &mut h3::server::RequestStream<T, Bytes>,
) -> Result<(), ApiError>
where
    T: h3::quic::BidiStream<Bytes>,
{
    let auth = verify_gateway_auth(connection, request.headers(), &state.issuer_registry)?;
    let query = request.uri().query().unwrap_or_default();
    let subscribe = SubscribeRequest {
        tenant_id: tenant_from_query(query)?,
        filters: vec![SubscribeFilter {
            namespace_prefix: query_value(query, "namespace_prefix"),
            path_exact: query_value(query, "path_exact"),
            object_cid: query_value(query, "object_cid"),
            event_type: query_value(query, "event_type").and_then(parse_event_type),
            tenant_scope: None,
        }],
        cursor: query_value(query, "cursor"),
        from_seq: query_value(query, "from_seq")
            .map(|value| value.parse().map_err(|_| invalid_revision()))
            .transpose()?,
        heartbeat_ms: query_value(query, "heartbeat_ms")
            .map(|value| value.parse().map_err(|_| invalid_heartbeat()))
            .transpose()?,
        batch_max: query_value(query, "batch_max")
            .map(|value| value.parse().map_err(|_| invalid_limit()))
            .transpose()?,
    };
    let mut cursor = state.service.subscribe_start(&auth, &subscribe)?;
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-hsp-events+jsonl")
        .body(())
        .map_err(http_build_error)?;
    stream.send_response(response).await.map_err(http3_error)?;
    let heartbeat_ms = subscribe.heartbeat_ms.unwrap_or(250).min(5_000);
    let mut idle_rounds = 0u32;
    loop {
        let (envelopes, next_cursor) = state.service.subscribe_poll(&auth, &subscribe, &cursor)?;
        cursor = next_cursor;
        let mut emitted_event = false;
        for envelope in envelopes {
            if envelope.kind == SubscribeEnvelopeKind::Event {
                emitted_event = true;
            }
            let line = serde_json::to_vec(&envelope).map_err(bad_json)?;
            stream
                .send_data(Bytes::from([line, b"\n".to_vec()].concat()))
                .await
                .map_err(http3_error)?;
        }
        if emitted_event {
            idle_rounds = 0;
        } else {
            idle_rounds += 1;
        }
        if idle_rounds >= 20 {
            stream.finish().await.map_err(http3_error)?;
            return Ok(());
        }
        sleep(Duration::from_millis(heartbeat_ms)).await;
    }
}

fn verify_gateway_auth(
    connection: &Connection,
    headers: &http::HeaderMap,
    issuer_registry: &IssuerRegistry,
) -> Result<AuthContext, ApiError> {
    let token_b64 = required_header(headers, "x-hsp-capability")?;
    let binding_kind = required_header(headers, "x-hsp-channel-binding-kind")?;
    let proof_b64 = required_header(headers, "x-hsp-channel-binding-proof")?;
    let nonce = required_header(headers, "x-hsp-channel-binding-nonce")?;
    let claims = verify_cose_sign1_token(&token_b64, issuer_registry)?;
    let binding = hsp_core::ChannelBindingProof {
        binding_kind,
        proof_b64,
        nonce,
    };
    let mut exported_key_material = [0u8; 32];
    connection
        .export_keying_material(
            &mut exported_key_material,
            tls_exporter_label(),
            binding.nonce.as_bytes(),
        )
        .map_err(|_| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_channel_binding",
                "failed to export TLS keying material",
            )
        })?;
    verify_tls_exporter_binding(&exported_key_material, &binding)?;
    Ok(AuthContext {
        claims,
        channel_binding: Some(binding),
    })
}

async fn read_http_body<T>(
    stream: &mut h3::server::RequestStream<T, Bytes>,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>>
where
    T: h3::quic::BidiStream<Bytes>,
{
    let mut body = Vec::new();
    while let Some(chunk) = stream.recv_data().await? {
        let mut chunk = chunk;
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    Ok(body)
}

fn json_response<T: serde::Serialize>(
    status: StatusCode,
    value: &T,
) -> Result<(Response<()>, Option<Vec<Bytes>>), ApiError> {
    let body = serde_json::to_vec(value).map_err(|error| {
        ApiError::new(
            ApiErrorCategory::Validation,
            "json_encode_failed",
            error.to_string(),
        )
    })?;
    let response = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(())
        .map_err(http_build_error)?;
    Ok((response, Some(vec![Bytes::from(body)])))
}

fn chunk_stream_response(
    meta: &hsp_core::GetResponseMeta,
    chunks: &[hsp_core::GetChunk],
) -> Result<(Response<()>, Option<Vec<Bytes>>), ApiError> {
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-hsp-chunk-stream+jsonl")
        .body(())
        .map_err(http_build_error)?;

    let mut body = Vec::new();
    body.push(Bytes::from(format!(
        "{}\n",
        serde_json::json!({
            "type": "meta",
            "meta": meta,
        })
    )));
    for chunk in chunks {
        body.push(Bytes::from(format!(
            "{}\n",
            serde_json::json!({
                "type": "chunk",
                "descriptor": chunk.descriptor,
                "data_b64": URL_SAFE_NO_PAD.encode(&chunk.bytes),
            })
        )));
    }
    Ok((response, Some(body)))
}

fn head_response(
    head: &hsp_core::HeadResponse,
) -> Result<(Response<()>, Option<Vec<Bytes>>), ApiError> {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(
            HeaderName::from_static("x-hsp-object-cid"),
            head.object_cid.as_str(),
        )
        .header(
            HeaderName::from_static("x-hsp-manifest-cid"),
            head.manifest_cid.as_str(),
        )
        .header(
            HeaderName::from_static("x-hsp-storage-class"),
            head.storage_class.as_str(),
        )
        .header(
            HeaderName::from_static("x-hsp-logical-size"),
            head.logical_size.to_string(),
        )
        .header(
            HeaderName::from_static("x-hsp-stored-size"),
            head.stored_size.to_string(),
        )
        .header(
            HeaderName::from_static("x-hsp-content-type"),
            head.content_type.as_str(),
        )
        .header(
            HeaderName::from_static("x-hsp-metadata-visibility"),
            head.metadata_visibility.as_str(),
        )
        .header(
            HeaderName::from_static("x-hsp-encrypted-client-metadata-redacted"),
            if head.encrypted_client_metadata_redacted {
                "true"
            } else {
                "false"
            },
        );
    if let Some(namespace) = &head.resolved_namespace {
        builder = builder.header(
            HeaderName::from_static("x-hsp-resolved-namespace"),
            namespace.as_str(),
        );
    }
    if let Some(path) = &head.resolved_path {
        builder = builder.header(
            HeaderName::from_static("x-hsp-resolved-path"),
            path.as_str(),
        );
    }
    if let Some(revision) = head.resolved_revision {
        builder = builder.header(
            HeaderName::from_static("x-hsp-resolved-revision"),
            revision.to_string(),
        );
    }
    if let Some(record_cid) = &head.resolved_record_cid {
        builder = builder.header(
            HeaderName::from_static("x-hsp-resolved-record-cid"),
            record_cid.as_str(),
        );
    }
    let response = builder.body(()).map_err(http_build_error)?;
    Ok((response, None))
}

fn error_response(error: &ApiError) -> GatewayBodyResponse {
    let body = serde_json::to_vec(error)?;
    let response = Response::builder()
        .status(status_for_error(error))
        .header(CONTENT_TYPE, "application/json")
        .header(
            HeaderName::from_static("x-hsp-error-code"),
            error.code.as_str(),
        )
        .header(
            HeaderName::from_static("x-hsp-error-category"),
            error.category.category_as_str(),
        )
        .body(())?;
    Ok((response, Some(vec![Bytes::from(body)])))
}

fn tenant_from_query(query: &str) -> Result<hsp_core::TenantId, ApiError> {
    Ok(hsp_core::TenantId(required_query(query, "tenant_id")?))
}

fn required_query(query: &str, key: &str) -> Result<String, ApiError> {
    query_value(query, key).ok_or_else(|| {
        ApiError::new(
            ApiErrorCategory::Validation,
            format!("missing_{key}"),
            format!("{key} query parameter is required"),
        )
    })
}

fn query_value(query: &str, key: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, value)| value.to_string())
}

fn required_header(headers: &http::HeaderMap, name: &str) -> Result<String, ApiError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
        .ok_or_else(|| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "missing_auth_header",
                format!("{name} header is required"),
            )
        })
}

fn split_namespace_operation(path: &str, marker: &str) -> Result<(String, String), ApiError> {
    let tail = path.trim_start_matches("/v1/namespaces/");
    let (namespace, item_path) = tail.split_once(marker).ok_or_else(|| {
        ApiError::new(
            ApiErrorCategory::Validation,
            "invalid_namespace_route",
            "invalid namespace route",
        )
    })?;
    Ok((namespace.to_string(), item_path.to_string()))
}

fn split_namespace_object_route(path: &str, prefix: &str) -> Result<(String, String), ApiError> {
    let tail = path.trim_start_matches(prefix);
    let (namespace, item_path) = tail.split_once('/').ok_or_else(|| {
        ApiError::new(
            ApiErrorCategory::Validation,
            "invalid_namespace_route",
            "invalid namespace object route",
        )
    })?;
    Ok((namespace.to_string(), item_path.to_string()))
}

fn parse_preference(value: String) -> Option<GetPreference> {
    match value.as_str() {
        "chunk-stream" => Some(GetPreference::ChunkStream),
        "manifest-only" => Some(GetPreference::ManifestOnly),
        "raw" => Some(GetPreference::Raw),
        _ => None,
    }
}

fn parse_event_type(value: String) -> Option<hsp_core::EventType> {
    match value.as_str() {
        "object.committed" => Some(hsp_core::EventType::ObjectCommitted),
        "namespace.bound" => Some(hsp_core::EventType::NamespaceBound),
        "namespace.unbound" => Some(hsp_core::EventType::NamespaceUnbound),
        "namespace.tombstoned" => Some(hsp_core::EventType::NamespaceTombstoned),
        "auth.denied" => Some(hsp_core::EventType::AuthDenied),
        "pin.accepted" => Some(hsp_core::EventType::PinAccepted),
        _ => None,
    }
}

fn invalid_range() -> ApiError {
    ApiError::new(
        ApiErrorCategory::Validation,
        "invalid_range",
        "invalid range",
    )
}

fn invalid_revision() -> ApiError {
    ApiError::new(
        ApiErrorCategory::Validation,
        "invalid_revision",
        "invalid revision",
    )
}

fn invalid_limit() -> ApiError {
    ApiError::new(
        ApiErrorCategory::Validation,
        "invalid_limit",
        "invalid limit",
    )
}

fn invalid_heartbeat() -> ApiError {
    ApiError::new(
        ApiErrorCategory::Validation,
        "invalid_heartbeat_ms",
        "invalid heartbeat",
    )
}

fn bad_json(error: serde_json::Error) -> ApiError {
    ApiError::new(
        ApiErrorCategory::Validation,
        "invalid_json",
        error.to_string(),
    )
}

fn http_body_error(error: Box<dyn Error + Send + Sync>) -> ApiError {
    ApiError::new(
        ApiErrorCategory::Validation,
        "gateway_body_read_failed",
        error.to_string(),
    )
}

fn http_build_error(error: http::Error) -> ApiError {
    ApiError::new(
        ApiErrorCategory::Validation,
        "gateway_response_build_failed",
        error.to_string(),
    )
}

fn http3_error(error: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        ApiErrorCategory::Validation,
        "gateway_stream_failed",
        error.to_string(),
    )
}

fn status_for_error(error: &ApiError) -> StatusCode {
    match error.category {
        ApiErrorCategory::Auth => StatusCode::UNAUTHORIZED,
        ApiErrorCategory::Replay
        | ApiErrorCategory::Policy
        | ApiErrorCategory::Validation
        | ApiErrorCategory::Unsupported
        | ApiErrorCategory::Conflict => StatusCode::BAD_REQUEST,
        ApiErrorCategory::NotFound => StatusCode::NOT_FOUND,
        ApiErrorCategory::Storage => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn build_server_config(
    authority: &str,
) -> Result<(ServerConfig, Vec<u8>), Box<dyn Error + Send + Sync>> {
    install_crypto_provider();
    let certified = generate_simple_self_signed(vec![authority.to_string()])?;
    let cert_der = certified.cert.der().to_vec();
    let key_der = certified.signing_key.serialize_der();
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
        )?;
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let server_config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    Ok((server_config, cert_der))
}

fn resolved_gateway_base_url(base_url: &str, local_port: u16) -> String {
    let Ok(uri) = base_url.parse::<http::Uri>() else {
        return base_url.to_string();
    };
    let mut parts = uri.into_parts();
    let Some(authority) = parts.authority.take() else {
        return base_url.to_string();
    };
    let host = authority.host();
    let authority_value = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{local_port}")
    } else {
        format!("{host}:{local_port}")
    };
    let Ok(authority) = http::uri::Authority::from_str(&authority_value) else {
        return base_url.to_string();
    };
    parts.authority = Some(authority);
    http::Uri::from_parts(parts)
        .map(|uri| uri.to_string())
        .unwrap_or_else(|_| base_url.to_string())
}

fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

trait ApiErrorCategoryExt {
    fn category_as_str(&self) -> &'static str;
}

impl ApiErrorCategoryExt for ApiErrorCategory {
    fn category_as_str(&self) -> &'static str {
        match self {
            ApiErrorCategory::Auth => "auth",
            ApiErrorCategory::Replay => "replay",
            ApiErrorCategory::Policy => "policy",
            ApiErrorCategory::Validation => "validation",
            ApiErrorCategory::Unsupported => "unsupported",
            ApiErrorCategory::NotFound => "not_found",
            ApiErrorCategory::Conflict => "conflict",
            ApiErrorCategory::Storage => "storage",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::future::poll_fn;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use bytes::Buf as _;
    use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
    use ed25519_dalek::{Signer, SigningKey};
    use h3::client::{self, SendRequest};
    use h3_quinn::Connection as H3ClientConnection;
    use quinn::crypto::rustls::QuicClientConfig;
    use quinn::ClientConfig;
    use rustls::RootCertStore;

    use hsp_core::{
        cid_from_bytes, BindRequest, CapabilityClaims, CapabilityScope, ChunkRef,
        EncryptionDescriptor, EncryptionProfileId, EventType, GetPreference, KeyPolicyId, Manifest,
        NamespaceMutationKind, NamespaceMutationRecord, PutChunkResponse, PutCommitRequest,
        PutCommitResponse, PutInitRequest, PutInitResponse, SubscribeEnvelope,
        SubscribeEnvelopeKind, TenantId, UnbindRequest, VisibilityMode, WrappedObjectKeyRecord,
    };

    use super::*;

    struct GatewayClient {
        endpoint: Endpoint,
        connection: Connection,
        send_request: SendRequest<h3_quinn::OpenStreams, Bytes>,
        driver: JoinHandle<()>,
    }

    impl GatewayClient {
        async fn shutdown(self) {
            self.endpoint.close(0u32.into(), b"shutdown");
            self.driver.abort();
        }
    }

    fn temp_root(label: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("hsp-gateway-beta-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn write_registry(root: &Path) -> (PathBuf, SigningKey) {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let registry_path = root.join("issuer-registry.json");
        let registry = hsp_auth::IssuerRegistry {
            issuers: vec![hsp_auth::IssuerRecord {
                issuer: "issuer".to_string(),
                key_id: "test-key".to_string(),
                algorithm: "Ed25519".to_string(),
                public_key_b64: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
                audiences: vec!["hsp".to_string()],
            }],
        };
        fs::write(
            &registry_path,
            serde_json::to_vec_pretty(&registry).unwrap(),
        )
        .unwrap();
        (registry_path, signing_key)
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
                encrypted_client_metadata: BTreeMap::from([(
                    "owner".to_string(),
                    "alice".to_string(),
                )]),
            },
        }
    }

    fn claims(jti: Option<&str>, ops: Vec<CapabilityScope>) -> CapabilityClaims {
        CapabilityClaims {
            iss: "issuer".to_string(),
            sub: "subject".to_string(),
            aud: "hsp".to_string(),
            exp: u64::MAX,
            nbf: Some(0),
            jti: jti.map(ToString::to_string),
            ops,
            tenant_id: TenantId("tenant-alpha".to_string()),
            namespace_prefix: None,
            path_prefix: None,
            max_object_size: Some(4096),
            storage_classes: vec!["hot".to_string()],
            key_policy_id: Some(KeyPolicyId("policy-default".to_string())),
            metadata_visibility: Some(VisibilityMode::Split),
        }
    }

    fn sign_cose_payload<T: serde::Serialize>(
        signing_key: &SigningKey,
        payload_value: &T,
    ) -> String {
        let mut payload = Vec::new();
        ciborium::into_writer(payload_value, &mut payload).unwrap();
        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::EdDSA)
            .key_id(b"test-key".to_vec())
            .build();
        let token = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(b"", |message| signing_key.sign(message).to_bytes().to_vec())
            .build();
        URL_SAFE_NO_PAD.encode(token.to_vec().unwrap())
    }

    fn sign_claims(signing_key: &SigningKey, claims: &CapabilityClaims) -> String {
        sign_cose_payload(signing_key, claims)
    }

    fn sign_namespace_record(signing_key: &SigningKey, record: &NamespaceMutationRecord) -> String {
        sign_cose_payload(signing_key, record)
    }

    async fn connect(authority: &str, addr: SocketAddr, certificate_der: &[u8]) -> GatewayClient {
        install_crypto_provider();
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(certificate_der.to_vec()))
            .unwrap();
        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let quic_crypto = QuicClientConfig::try_from(crypto).unwrap();
        let mut endpoint = Endpoint::client("[::]:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(ClientConfig::new(Arc::new(quic_crypto)));
        let connection = endpoint.connect(addr, authority).unwrap().await.unwrap();
        let (mut h3_connection, send_request) =
            client::new(H3ClientConnection::new(connection.clone()))
                .await
                .unwrap();
        let driver = tokio::spawn(async move {
            let _ = poll_fn(|cx| h3_connection.poll_close(cx)).await;
        });

        GatewayClient {
            endpoint,
            connection,
            send_request,
            driver,
        }
    }

    async fn auth_headers(
        connection: &Connection,
        signing_key: &SigningKey,
        claims: CapabilityClaims,
        nonce: &str,
    ) -> http::HeaderMap {
        let token_b64 = sign_claims(signing_key, &claims);
        let mut exporter = [0u8; 32];
        connection
            .export_keying_material(&mut exporter, tls_exporter_label(), nonce.as_bytes())
            .unwrap();

        let mut headers = http::HeaderMap::new();
        headers.insert("x-hsp-capability", token_b64.parse().unwrap());
        headers.insert(
            "x-hsp-channel-binding-kind",
            "tls-exporter".parse().unwrap(),
        );
        headers.insert(
            "x-hsp-channel-binding-proof",
            URL_SAFE_NO_PAD.encode(exporter).parse().unwrap(),
        );
        headers.insert("x-hsp-channel-binding-nonce", nonce.parse().unwrap());
        headers
    }

    async fn send_request(
        client: &mut GatewayClient,
        method: Method,
        uri: String,
        headers: http::HeaderMap,
        body: &[u8],
    ) -> (http::Response<()>, Vec<u8>) {
        let mut request = Request::builder().method(method).uri(uri).body(()).unwrap();
        *request.headers_mut() = headers;

        let mut stream = client.send_request.send_request(request).await.unwrap();
        if !body.is_empty() {
            stream
                .send_data(Bytes::copy_from_slice(body))
                .await
                .unwrap();
        }
        stream.finish().await.unwrap();

        let response = stream.recv_response().await.unwrap();
        let mut response_body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            let bytes = chunk.copy_to_bytes(chunk.remaining());
            response_body.extend_from_slice(&bytes);
        }

        (response, response_body)
    }

    fn uri_for(addr: SocketAddr, path_and_query: &str) -> String {
        format!("https://localhost:{}{path_and_query}", addr.port())
    }

    #[tokio::test]
    async fn gateway_serves_bootstrap_and_info_on_http3() {
        let root = temp_root("info");
        let (registry_path, _signing_key) = write_registry(&root);
        let handle = spawn_gateway_beta_server(GatewayBetaConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            authority: "localhost".to_string(),
            gateway_base_url: "https://localhost/v1/".to_string(),
            root_dir: root,
            issuer_registry_path: registry_path,
            server_instance_id: "gateway-info".to_string(),
            native_port: 9443,
        })
        .await
        .unwrap();

        let mut client = connect("localhost", handle.local_addr, &handle.certificate_der).await;

        let (response, body) = send_request(
            &mut client,
            Method::GET,
            uri_for(handle.local_addr, "/.well-known/hsp"),
            http::HeaderMap::new(),
            &[],
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let bootstrap: hsp_core::BootstrapDocument = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            bootstrap.gateway.base_url,
            format!("https://localhost:{}/v1/", handle.local_addr.port())
        );

        let (response, body) = send_request(
            &mut client,
            Method::GET,
            uri_for(handle.local_addr, "/v1/info"),
            http::HeaderMap::new(),
            &[],
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let info: hsp_core::InfoResponse = serde_json::from_slice(&body).unwrap();
        assert!(info
            .supported_extensions
            .contains(&"gateway-http3-beta".to_string()));

        client.shutdown().await;
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn gateway_upload_head_and_get_roundtrip() {
        let root = temp_root("roundtrip");
        let (registry_path, signing_key) = write_registry(&root);
        let handle = spawn_gateway_beta_server(GatewayBetaConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            authority: "localhost".to_string(),
            gateway_base_url: "https://localhost/v1/".to_string(),
            root_dir: root,
            issuer_registry_path: registry_path,
            server_instance_id: "gateway-roundtrip".to_string(),
            native_port: 9443,
        })
        .await
        .unwrap();

        let mut client = connect("localhost", handle.local_addr, &handle.certificate_der).await;
        let chunk_bytes = b"ciphertext!";
        let chunk_cid = cid_from_bytes(chunk_bytes);
        let manifest = manifest_for_chunk(chunk_cid.clone());

        let put_init_headers = auth_headers(
            &client.connection,
            &signing_key,
            claims(
                Some("gateway-put-init"),
                vec![CapabilityScope::Read, CapabilityScope::Write],
            ),
            "gw-put-init",
        )
        .await;
        let (response, body) = send_request(
            &mut client,
            Method::POST,
            uri_for(handle.local_addr, "/v1/uploads"),
            put_init_headers,
            &serde_json::to_vec(&PutInitRequest {
                tenant_id: TenantId("tenant-alpha".to_string()),
                manifest: manifest.clone(),
                idempotency_key: "idem-1".to_string(),
                encryption_profile_id: EncryptionProfileId("public-e2ee-v1".to_string()),
                key_policy_id: KeyPolicyId("policy-default".to_string()),
                metadata_visibility: VisibilityMode::Split,
                storage_class: "hot".to_string(),
                atomic_bind: None,
            })
            .unwrap(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let init: PutInitResponse = serde_json::from_slice(&body).unwrap();

        let put_chunk_headers = auth_headers(
            &client.connection,
            &signing_key,
            claims(
                Some("gateway-put-chunk"),
                vec![CapabilityScope::Read, CapabilityScope::Write],
            ),
            "gw-put-chunk",
        )
        .await;
        let (response, body) = send_request(
            &mut client,
            Method::PUT,
            uri_for(
                handle.local_addr,
                &format!(
                    "/v1/uploads/{}/chunks/0?tenant_id=tenant-alpha&chunk_cid={}&chunk_offset=0&chunk_length={}&content_encoding=identity",
                    init.session_id,
                    chunk_cid,
                    chunk_bytes.len()
                ),
            ),
            put_chunk_headers,
            chunk_bytes,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let put_chunk: PutChunkResponse = serde_json::from_slice(&body).unwrap();
        assert!(put_chunk.verified_cid);

        let put_commit_headers = auth_headers(
            &client.connection,
            &signing_key,
            claims(
                Some("gateway-put-commit"),
                vec![CapabilityScope::Read, CapabilityScope::Write],
            ),
            "gw-put-commit",
        )
        .await;
        let (response, body) = send_request(
            &mut client,
            Method::POST,
            uri_for(
                handle.local_addr,
                &format!("/v1/uploads/{}:commit", init.session_id),
            ),
            put_commit_headers,
            &serde_json::to_vec(&PutCommitRequest {
                tenant_id: TenantId("tenant-alpha".to_string()),
                session_id: init.session_id.clone(),
                manifest_cid: init.accepted_manifest_cid.clone(),
                idempotency_key: "idem-commit".to_string(),
            })
            .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let commit: PutCommitResponse = serde_json::from_slice(&body).unwrap();

        let read_headers = auth_headers(
            &client.connection,
            &signing_key,
            claims(Some("gateway-read"), vec![CapabilityScope::Read]),
            "gw-read",
        )
        .await;
        let (response, _) = send_request(
            &mut client,
            Method::HEAD,
            uri_for(
                handle.local_addr,
                &format!(
                    "/v1/objects/cid/{}?tenant_id=tenant-alpha",
                    commit.object_cid
                ),
            ),
            read_headers.clone(),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-hsp-encrypted-client-metadata-redacted")
                .unwrap(),
            "true"
        );

        let (response, body) = send_request(
            &mut client,
            Method::GET,
            uri_for(
                handle.local_addr,
                &format!(
                    "/v1/objects/cid/{}?tenant_id=tenant-alpha&prefer=manifest-only",
                    commit.object_cid
                ),
            ),
            read_headers.clone(),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let meta: hsp_core::GetResponseMeta = serde_json::from_slice(&body).unwrap();
        assert_eq!(meta.preference, GetPreference::ManifestOnly);
        assert!(meta.manifest.is_some());

        let (response, body) = send_request(
            &mut client,
            Method::GET,
            uri_for(
                handle.local_addr,
                &format!(
                    "/v1/objects/cid/{}?tenant_id=tenant-alpha",
                    commit.object_cid
                ),
            ),
            read_headers,
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/x-hsp-chunk-stream+jsonl"
        );
        let lines = String::from_utf8(body).unwrap();
        assert!(lines.contains("\"type\":\"meta\""));
        assert!(lines.contains("\"type\":\"chunk\""));
        assert!(lines.contains("Y2lwaGVydGV4dCE"));

        client.shutdown().await;
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn gateway_rejects_missing_auth_headers() {
        let root = temp_root("missing-auth");
        let (registry_path, _signing_key) = write_registry(&root);
        let handle = spawn_gateway_beta_server(GatewayBetaConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            authority: "localhost".to_string(),
            gateway_base_url: "https://localhost/v1/".to_string(),
            root_dir: root,
            issuer_registry_path: registry_path,
            server_instance_id: "gateway-missing-auth".to_string(),
            native_port: 9443,
        })
        .await
        .unwrap();

        let mut client = connect("localhost", handle.local_addr, &handle.certificate_der).await;
        let (response, body) = send_request(
            &mut client,
            Method::HEAD,
            uri_for(
                handle.local_addr,
                "/v1/objects/cid/sha256-missing?tenant_id=tenant-alpha",
            ),
            http::HeaderMap::new(),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get("x-hsp-error-code").unwrap(),
            "missing_auth_header"
        );
        let error: ApiError = serde_json::from_slice(&body).unwrap();
        assert_eq!(error.code, "missing_auth_header");

        client.shutdown().await;
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn gateway_rejects_invalid_token_signature() {
        let root = temp_root("invalid-token");
        let (registry_path, _trusted_signing_key) = write_registry(&root);
        let untrusted_signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let handle = spawn_gateway_beta_server(GatewayBetaConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            authority: "localhost".to_string(),
            gateway_base_url: "https://localhost/v1/".to_string(),
            root_dir: root,
            issuer_registry_path: registry_path,
            server_instance_id: "gateway-invalid-token".to_string(),
            native_port: 9443,
        })
        .await
        .unwrap();

        let mut client = connect("localhost", handle.local_addr, &handle.certificate_der).await;
        let bad_headers = auth_headers(
            &client.connection,
            &untrusted_signing_key,
            claims(Some("gateway-invalid"), vec![CapabilityScope::Read]),
            "gw-invalid",
        )
        .await;
        let (response, body) = send_request(
            &mut client,
            Method::HEAD,
            uri_for(
                handle.local_addr,
                "/v1/objects/cid/sha256-missing?tenant_id=tenant-alpha",
            ),
            bad_headers,
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get("x-hsp-error-code").unwrap(),
            "invalid_token_signature"
        );
        let error: ApiError = serde_json::from_slice(&body).unwrap();
        assert_eq!(error.code, "invalid_token_signature");

        client.shutdown().await;
        handle.shutdown().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn gateway_supports_namespace_routes_and_event_stream() {
        let root = temp_root("namespace");
        let (registry_path, signing_key) = write_registry(&root);
        let handle = spawn_gateway_beta_server(GatewayBetaConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            authority: "localhost".to_string(),
            gateway_base_url: "https://localhost/v1/".to_string(),
            root_dir: root,
            issuer_registry_path: registry_path,
            server_instance_id: "gateway-namespace".to_string(),
            native_port: 9443,
        })
        .await
        .unwrap();

        let mut client = connect("localhost", handle.local_addr, &handle.certificate_der).await;
        let chunk_bytes = b"ciphertext!";
        let chunk_cid = cid_from_bytes(chunk_bytes);
        let manifest = manifest_for_chunk(chunk_cid.clone());

        let put_init_headers = auth_headers(
            &client.connection,
            &signing_key,
            claims(
                Some("gateway-ns-put-init"),
                vec![CapabilityScope::Read, CapabilityScope::Write],
            ),
            "gw-ns-put-init",
        )
        .await;
        let (response, body) = send_request(
            &mut client,
            Method::POST,
            uri_for(handle.local_addr, "/v1/uploads"),
            put_init_headers,
            &serde_json::to_vec(&PutInitRequest {
                tenant_id: TenantId("tenant-alpha".to_string()),
                manifest: manifest.clone(),
                idempotency_key: "idem-gw-ns-1".to_string(),
                encryption_profile_id: EncryptionProfileId("public-e2ee-v1".to_string()),
                key_policy_id: KeyPolicyId("policy-default".to_string()),
                metadata_visibility: VisibilityMode::Split,
                storage_class: "hot".to_string(),
                atomic_bind: None,
            })
            .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let init: PutInitResponse = serde_json::from_slice(&body).unwrap();

        let put_chunk_headers = auth_headers(
            &client.connection,
            &signing_key,
            claims(
                Some("gateway-ns-put-chunk"),
                vec![CapabilityScope::Read, CapabilityScope::Write],
            ),
            "gw-ns-put-chunk",
        )
        .await;
        let (response, body) = send_request(
            &mut client,
            Method::PUT,
            uri_for(
                handle.local_addr,
                &format!(
                    "/v1/uploads/{}/chunks/0?tenant_id=tenant-alpha&chunk_cid={}&chunk_offset=0&chunk_length={}&content_encoding=identity",
                    init.session_id,
                    chunk_cid,
                    chunk_bytes.len()
                ),
            ),
            put_chunk_headers,
            chunk_bytes,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let put_chunk: PutChunkResponse = serde_json::from_slice(&body).unwrap();
        assert!(put_chunk.verified_cid);

        let put_commit_headers = auth_headers(
            &client.connection,
            &signing_key,
            claims(
                Some("gateway-ns-put-commit"),
                vec![CapabilityScope::Read, CapabilityScope::Write],
            ),
            "gw-ns-put-commit",
        )
        .await;
        let (response, body) = send_request(
            &mut client,
            Method::POST,
            uri_for(
                handle.local_addr,
                &format!("/v1/uploads/{}:commit", init.session_id),
            ),
            put_commit_headers,
            &serde_json::to_vec(&PutCommitRequest {
                tenant_id: TenantId("tenant-alpha".to_string()),
                session_id: init.session_id.clone(),
                manifest_cid: init.accepted_manifest_cid.clone(),
                idempotency_key: "idem-gw-ns-commit".to_string(),
            })
            .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let commit: PutCommitResponse = serde_json::from_slice(&body).unwrap();

        let bind_metadata = BTreeMap::from([("label".to_string(), "quarterly".to_string())]);
        let bind_record = NamespaceMutationRecord {
            version: 1,
            tenant_id: TenantId("tenant-alpha".to_string()),
            namespace: "docs".to_string(),
            path: "reports/q1".to_string(),
            kind: NamespaceMutationKind::Bind,
            target_cid: Some(commit.object_cid.clone()),
            if_revision: None,
            ttl_ms: None,
            metadata: bind_metadata.clone(),
            issued_at_ms: 2,
        };
        let bind_headers = auth_headers(
            &client.connection,
            &signing_key,
            claims(
                Some("gateway-ns-bind"),
                vec![
                    CapabilityScope::Read,
                    CapabilityScope::Bind,
                    CapabilityScope::Unbind,
                    CapabilityScope::List,
                    CapabilityScope::Subscribe,
                ],
            ),
            "gw-ns-bind",
        )
        .await;
        let (response, body) = send_request(
            &mut client,
            Method::PUT,
            uri_for(handle.local_addr, "/v1/namespaces/docs/bind/reports/q1"),
            bind_headers,
            &serde_json::to_vec(&BindRequest {
                tenant_id: TenantId("tenant-alpha".to_string()),
                namespace: "docs".to_string(),
                path: "reports/q1".to_string(),
                target_cid: commit.object_cid.clone(),
                if_revision: None,
                if_absent: true,
                metadata: bind_metadata.clone(),
                ttl_ms: None,
                idempotency_key: "idem-gw-bind-1".to_string(),
                signed_record_b64: sign_namespace_record(&signing_key, &bind_record),
            })
            .unwrap(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let bind_response: hsp_core::BindResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(bind_response.revision, 1);

        let read_headers = auth_headers(
            &client.connection,
            &signing_key,
            claims(
                Some("gateway-ns-read"),
                vec![
                    CapabilityScope::Read,
                    CapabilityScope::List,
                    CapabilityScope::Subscribe,
                ],
            ),
            "gw-ns-read",
        )
        .await;

        let (response, body) = send_request(
            &mut client,
            Method::GET,
            uri_for(
                handle.local_addr,
                "/v1/namespaces/docs/resolve/reports/q1?tenant_id=tenant-alpha",
            ),
            read_headers.clone(),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let resolve: hsp_core::ResolveResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resolve.target_cid, Some(commit.object_cid.clone()));
        assert_eq!(resolve.revision, bind_response.revision);

        let (response, _) = send_request(
            &mut client,
            Method::HEAD,
            uri_for(
                handle.local_addr,
                "/v1/objects/namespace/docs/reports/q1?tenant_id=tenant-alpha",
            ),
            read_headers.clone(),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-hsp-resolved-namespace").unwrap(),
            "docs"
        );
        assert_eq!(
            response.headers().get("x-hsp-resolved-path").unwrap(),
            "reports/q1"
        );

        let (response, body) = send_request(
            &mut client,
            Method::GET,
            uri_for(
                handle.local_addr,
                "/v1/objects/namespace/docs/reports/q1?tenant_id=tenant-alpha&prefer=manifest-only",
            ),
            read_headers.clone(),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let meta: hsp_core::GetResponseMeta = serde_json::from_slice(&body).unwrap();
        assert_eq!(meta.resolved_namespace.as_deref(), Some("docs"));
        assert_eq!(meta.resolved_path.as_deref(), Some("reports/q1"));
        assert_eq!(meta.resolved_revision, Some(bind_response.revision));

        let (response, body) = send_request(
            &mut client,
            Method::GET,
            uri_for(
                handle.local_addr,
                "/v1/namespaces/docs/list?tenant_id=tenant-alpha&prefix=reports&recursive=true",
            ),
            read_headers.clone(),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let list: hsp_core::ListResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(list.items.len(), 1);
        assert_eq!(list.items[0].path, "reports/q1");

        let (response, body) = send_request(
            &mut client,
            Method::GET,
            uri_for(
                handle.local_addr,
                "/v1/events?tenant_id=tenant-alpha&from_seq=0&namespace_prefix=docs&path_exact=reports/q1&event_type=namespace.bound",
            ),
            read_headers.clone(),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/x-hsp-events+jsonl"
        );
        let first_line = String::from_utf8(body)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_string();
        let envelope: SubscribeEnvelope = serde_json::from_str(&first_line).unwrap();
        assert_eq!(envelope.kind, SubscribeEnvelopeKind::Event);
        assert_eq!(
            envelope.event.unwrap().event_type,
            EventType::NamespaceBound
        );

        let unbind_record = NamespaceMutationRecord {
            version: 1,
            tenant_id: TenantId("tenant-alpha".to_string()),
            namespace: "docs".to_string(),
            path: "reports/q1".to_string(),
            kind: NamespaceMutationKind::Unbind,
            target_cid: None,
            if_revision: Some(bind_response.revision),
            ttl_ms: None,
            metadata: BTreeMap::new(),
            issued_at_ms: 3,
        };
        let unbind_headers = auth_headers(
            &client.connection,
            &signing_key,
            claims(
                Some("gateway-ns-unbind"),
                vec![CapabilityScope::Unbind, CapabilityScope::Read],
            ),
            "gw-ns-unbind",
        )
        .await;
        let (response, body) = send_request(
            &mut client,
            Method::DELETE,
            uri_for(handle.local_addr, "/v1/namespaces/docs/bind/reports/q1"),
            unbind_headers,
            &serde_json::to_vec(&UnbindRequest {
                tenant_id: TenantId("tenant-alpha".to_string()),
                namespace: "docs".to_string(),
                path: "reports/q1".to_string(),
                if_revision: bind_response.revision,
                hard_delete: false,
                idempotency_key: "idem-gw-unbind-1".to_string(),
                signed_record_b64: sign_namespace_record(&signing_key, &unbind_record),
            })
            .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let unbind_response: hsp_core::UnbindResponse = serde_json::from_slice(&body).unwrap();
        assert!(unbind_response.tombstone);

        let (response, body) = send_request(
            &mut client,
            Method::HEAD,
            uri_for(
                handle.local_addr,
                "/v1/objects/namespace/docs/reports/q1?tenant_id=tenant-alpha",
            ),
            read_headers,
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let error: ApiError = serde_json::from_slice(&body).unwrap();
        assert_eq!(error.code, "path_tombstoned");

        client.shutdown().await;
        handle.shutdown().await;
    }
}
