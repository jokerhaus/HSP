use std::collections::BTreeMap;
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use hsp_auth::{
    tls_exporter_label, verify_cose_sign1_token, verify_tls_exporter_binding, AuthContext,
    IssuerRegistry,
};
use hsp_core::{
    ApiError, ApiErrorCategory, BindRequest, GetChunk, GetRequest, GetResponseMeta, HeadRequest,
    ListRequest, PayloadMode, PutChunkRequest, PutCommitRequest, PutInitRequest, ReqHeader,
    ResHeader, ResolveRequest, SubscribeEnvelopeKind, SubscribeRequest, UnbindRequest,
};
use hsp_service::{AlphaConfig, AlphaService};
use hsp_wire::{read_frame, write_frame, Frame, WireCodecError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeBetaConfig {
    pub bind_addr: SocketAddr,
    pub authority: String,
    pub gateway_base_url: String,
    pub root_dir: PathBuf,
    pub issuer_registry_path: PathBuf,
    pub server_instance_id: String,
    pub kms_seed: Vec<u8>,
}

pub struct NativeBetaServerHandle {
    endpoint: Endpoint,
    task: JoinHandle<()>,
    pub local_addr: SocketAddr,
    pub certificate_der: Vec<u8>,
}

struct NativeState {
    service: Arc<AlphaService>,
    issuer_registry: Arc<IssuerRegistry>,
}

fn native_runtime_kms(seed: &[u8]) -> Result<hsp_crypto::LocalDevKms, ApiError> {
    let seed = hsp_crypto::validate_runtime_secret_bytes(
        "HSP_KMS_SEED",
        seed,
        hsp_crypto::DEFAULT_KMS_SEED_LITERALS,
    )
    .map_err(|error| {
        hsp_crypto::crypto_error_to_api(
            error,
            "HSP_KMS_SEED must be configured for native beta runtime KMS",
        )
    })?;
    hsp_crypto::LocalDevKms::from_seed(&seed)
        .map_err(|error| hsp_crypto::crypto_error_to_api(error, "failed to initialize native KMS"))
}

impl NativeBetaServerHandle {
    pub async fn shutdown(self) {
        self.endpoint.close(0u32.into(), b"shutdown");
        self.task.abort();
    }
}

pub async fn spawn_native_beta_server(
    config: NativeBetaConfig,
) -> Result<NativeBetaServerHandle, Box<dyn Error + Send + Sync>> {
    install_crypto_provider();
    let issuer_registry = Arc::new(IssuerRegistry::load(&config.issuer_registry_path)?);
    let (server_config, certificate_der) = build_server_config(&config.authority)?;
    let endpoint = Endpoint::server(server_config, config.bind_addr)?;
    let local_addr = endpoint.local_addr()?;
    let service = Arc::new(
        AlphaService::new(
            AlphaConfig {
                authority: config.authority.clone(),
                gateway_base_url: config.gateway_base_url.clone(),
                root_dir: config.root_dir.clone(),
                native_port: local_addr.port(),
                server_instance_id: config.server_instance_id.clone(),
            },
            native_runtime_kms(&config.kms_seed)?,
        )?
        .with_issuer_registry((*issuer_registry).clone()),
    );
    let state = Arc::new(NativeState {
        service,
        issuer_registry,
    });
    let accept_endpoint = endpoint.clone();
    let task = tokio::spawn(async move {
        while let Some(connecting) = accept_endpoint.accept().await {
            let state = state.clone();
            tokio::spawn(async move {
                if let Ok(connection) = connecting.await {
                    connection.set_max_concurrent_bi_streams(128u32.into());
                    connection.set_max_concurrent_uni_streams(8u32.into());
                    if send_settings(&connection, &state.service).await.is_ok() {
                        let _ = handle_connection(connection, state).await;
                    }
                }
            });
        }
    });

    Ok(NativeBetaServerHandle {
        endpoint,
        task,
        local_addr,
        certificate_der,
    })
}

pub fn build_client_config(
    authority: &str,
    certificate_der: &[u8],
) -> Result<(quinn::ClientConfig, String), Box<dyn Error + Send + Sync>> {
    install_crypto_provider();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(certificate_der.to_vec()))?;
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"hsp/1".to_vec()];
    let quic_crypto = QuicClientConfig::try_from(crypto)?;
    Ok((
        quinn::ClientConfig::new(Arc::new(quic_crypto)),
        authority.to_string(),
    ))
}

async fn send_settings(
    connection: &Connection,
    service: &AlphaService,
) -> Result<(), WireCodecError> {
    let mut stream = connection.open_uni().await.map_err(io_to_wire)?;
    write_frame(&mut stream, &Frame::Settings(service.settings())).await?;
    stream
        .finish()
        .map_err(|error| WireCodecError::InvalidFrame(error.to_string()))?;
    Ok(())
}

async fn handle_connection(
    connection: Connection,
    state: Arc<NativeState>,
) -> Result<(), WireCodecError> {
    loop {
        let (send, recv) = connection.accept_bi().await.map_err(io_to_wire)?;
        let state = state.clone();
        let connection = connection.clone();
        tokio::spawn(async move {
            let _ = handle_request_stream(connection, state, send, recv).await;
        });
    }
}

async fn handle_request_stream(
    connection: Connection,
    state: Arc<NativeState>,
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<(), WireCodecError> {
    let first_frame = read_frame(&mut recv).await?;
    let (auth, header) = match first_frame {
        Frame::ReqHeader(header) if header.operation == hsp_core::OperationName::Info => {
            (None, header)
        }
        Frame::Auth(auth_frame) => {
            let auth = verify_auth_frame(&connection, &state.issuer_registry, auth_frame)
                .map_err(api_to_wire)?;
            match read_frame(&mut recv).await? {
                Frame::ReqHeader(header) => (Some(auth), header),
                _ => {
                    return write_error(
                        &mut send,
                        ApiError::new(
                            ApiErrorCategory::Validation,
                            "missing_req_header",
                            "REQ_HEADER must follow AUTH",
                        ),
                    )
                    .await;
                }
            }
        }
        Frame::ReqHeader(_) => {
            return write_error(
                &mut send,
                ApiError::new(
                    ApiErrorCategory::Auth,
                    "missing_auth_frame",
                    "AUTH frame is required before request header",
                ),
            )
            .await;
        }
        Frame::Data(_) => {
            return write_error(
                &mut send,
                ApiError::new(
                    ApiErrorCategory::Validation,
                    "unexpected_data_frame",
                    "DATA frame arrived before request header",
                ),
            )
            .await;
        }
        _ => {
            return write_error(
                &mut send,
                ApiError::new(
                    ApiErrorCategory::Validation,
                    "invalid_request_sequence",
                    "unexpected frame order",
                ),
            )
            .await;
        }
    };

    let body = read_body(&mut recv).await?;
    match header.operation {
        hsp_core::OperationName::Info => {
            let info = state.service.info();
            write_json_response(&mut send, 200, &info).await
        }
        hsp_core::OperationName::Head => {
            let auth = required_auth(auth.as_ref(), "HEAD")?;
            let request: HeadRequest = decode_json(&body)?;
            match state.service.head(auth, request) {
                Ok(response) => write_json_response(&mut send, 200, &response).await,
                Err(error) => write_error(&mut send, error).await,
            }
        }
        hsp_core::OperationName::Get => {
            let auth = required_auth(auth.as_ref(), "GET")?;
            let request: GetRequest = decode_json(&body)?;
            match state.service.get(auth, request) {
                Ok(response) => {
                    if response.meta.preference == hsp_core::GetPreference::ManifestOnly {
                        write_json_response(&mut send, 200, &response.meta).await
                    } else {
                        write_chunk_stream_response(
                            &mut send,
                            200,
                            &response.meta,
                            &response.chunks,
                        )
                        .await
                    }
                }
                Err(error) => write_error(&mut send, error).await,
            }
        }
        hsp_core::OperationName::Resolve => {
            let auth = required_auth(auth.as_ref(), "RESOLVE")?;
            let request: ResolveRequest = decode_json(&body)?;
            match state.service.resolve(auth, request) {
                Ok(response) => write_json_response(&mut send, 200, &response).await,
                Err(error) => write_error(&mut send, error).await,
            }
        }
        hsp_core::OperationName::Bind => {
            let auth = required_auth(auth.as_ref(), "BIND")?;
            let request: BindRequest = decode_json(&body)?;
            match state.service.bind(auth, request) {
                Ok(response) => write_json_response(&mut send, 200, &response).await,
                Err(error) => write_error(&mut send, error).await,
            }
        }
        hsp_core::OperationName::Unbind => {
            let auth = required_auth(auth.as_ref(), "UNBIND")?;
            let request: UnbindRequest = decode_json(&body)?;
            match state.service.unbind(auth, request) {
                Ok(response) => write_json_response(&mut send, 200, &response).await,
                Err(error) => write_error(&mut send, error).await,
            }
        }
        hsp_core::OperationName::List => {
            let auth = required_auth(auth.as_ref(), "LIST")?;
            let request: ListRequest = decode_json(&body)?;
            match state.service.list(auth, request) {
                Ok(response) => write_json_response(&mut send, 200, &response).await,
                Err(error) => write_error(&mut send, error).await,
            }
        }
        hsp_core::OperationName::Subscribe => {
            let auth = required_auth(auth.as_ref(), "SUBSCRIBE")?;
            let request: SubscribeRequest = decode_json(&body)?;
            match state.service.subscribe_start(auth, &request) {
                Ok(mut cursor) => {
                    write_subscription_header(&mut send, &cursor).await?;
                    let heartbeat_ms = request.heartbeat_ms.unwrap_or(250).min(5_000);
                    let mut idle_rounds = 0u32;
                    loop {
                        let (envelopes, next_cursor) =
                            match state.service.subscribe_poll(auth, &request, &cursor) {
                                Ok(result) => result,
                                Err(error) => return write_error(&mut send, error).await,
                            };
                        cursor = next_cursor;
                        let mut emitted_event = false;
                        for envelope in envelopes {
                            match envelope.kind {
                                SubscribeEnvelopeKind::Event => {
                                    if let Some(event) = envelope.event {
                                        write_frame(&mut send, &Frame::Event(event)).await?;
                                        emitted_event = true;
                                    }
                                }
                                SubscribeEnvelopeKind::Notice => {
                                    if let Some(notice) = envelope.notice {
                                        write_frame(&mut send, &Frame::Notice(notice)).await?;
                                    }
                                }
                            }
                        }
                        if emitted_event {
                            idle_rounds = 0;
                        } else {
                            idle_rounds += 1;
                        }
                        if idle_rounds >= 20 {
                            write_frame(
                                &mut send,
                                &Frame::GoAway(hsp_core::GoAwayFrame {
                                    reason: "subscribe_idle_timeout".to_string(),
                                }),
                            )
                            .await?;
                            return write_frame(&mut send, &Frame::End).await;
                        }
                        sleep(Duration::from_millis(heartbeat_ms)).await;
                    }
                }
                Err(error) => write_error(&mut send, error).await,
            }
        }
        hsp_core::OperationName::PutInit => {
            let auth = required_auth(auth.as_ref(), "PUT_INIT")?;
            let request: PutInitRequest = decode_json(&body)?;
            match state.service.put_init(auth, request) {
                Ok(response) => write_json_response(&mut send, 200, &response).await,
                Err(error) => write_error(&mut send, error).await,
            }
        }
        hsp_core::OperationName::PutChunk => {
            let auth = required_auth(auth.as_ref(), "PUT_CHUNK")?;
            let request: PutChunkRequest = decode_json_params(&header)?;
            match state.service.put_chunk(auth, request, &body) {
                Ok(response) => write_json_response(&mut send, 200, &response).await,
                Err(error) => write_error(&mut send, error).await,
            }
        }
        hsp_core::OperationName::PutCommit => {
            let auth = required_auth(auth.as_ref(), "PUT_COMMIT")?;
            let request: PutCommitRequest = decode_json(&body)?;
            match state.service.put_commit(auth, request) {
                Ok(response) => write_json_response(&mut send, 200, &response).await,
                Err(error) => write_error(&mut send, error).await,
            }
        }
    }
}

fn verify_auth_frame(
    connection: &Connection,
    issuer_registry: &IssuerRegistry,
    auth_frame: hsp_core::AuthFrame,
) -> Result<AuthContext, ApiError> {
    let claims = verify_cose_sign1_token(&auth_frame.token_b64, issuer_registry)?;
    let mut exported_key_material = [0u8; 32];
    connection
        .export_keying_material(
            &mut exported_key_material,
            tls_exporter_label(),
            auth_frame.channel_binding.nonce.as_bytes(),
        )
        .map_err(|_error| {
            ApiError::new(
                ApiErrorCategory::Auth,
                "invalid_channel_binding",
                "failed to export TLS keying material",
            )
        })?;
    verify_tls_exporter_binding(&exported_key_material, &auth_frame.channel_binding)?;
    Ok(AuthContext {
        claims,
        channel_binding: Some(auth_frame.channel_binding),
    })
}

async fn read_body(recv: &mut RecvStream) -> Result<Vec<u8>, WireCodecError> {
    let mut body = Vec::new();
    loop {
        match read_frame(recv).await? {
            Frame::Data(bytes) => body.extend_from_slice(&bytes),
            Frame::End => break,
            frame => {
                return Err(WireCodecError::InvalidFrame(format!(
                    "unexpected frame {:?} while reading body",
                    frame.frame_type()
                )))
            }
        }
    }
    Ok(body)
}

async fn write_json_response<T: serde::Serialize>(
    send: &mut SendStream,
    status_code: u16,
    value: &T,
) -> Result<(), WireCodecError> {
    let body = serde_json::to_vec(value)
        .map_err(|error| WireCodecError::InvalidFrame(error.to_string()))?;
    let header = ResHeader {
        version: 1,
        status_code,
        request_id: None,
        payload_mode: Some(PayloadMode::Json),
        payload_length: Some(body.len() as u64),
        meta: BTreeMap::new(),
        extensions: BTreeMap::new(),
    };
    write_frame(send, &Frame::ResHeader(header)).await?;
    write_frame(send, &Frame::Data(body)).await?;
    write_frame(send, &Frame::End).await
}

async fn write_chunk_stream_response(
    send: &mut SendStream,
    status_code: u16,
    meta: &GetResponseMeta,
    chunks: &[GetChunk],
) -> Result<(), WireCodecError> {
    let mut header_meta = BTreeMap::new();
    header_meta.insert(
        "get_meta".to_string(),
        serde_json::to_value(meta)
            .map_err(|error| WireCodecError::InvalidFrame(error.to_string()))?,
    );
    let header = ResHeader {
        version: 1,
        status_code,
        request_id: None,
        payload_mode: Some(PayloadMode::ChunkStream),
        payload_length: None,
        meta: header_meta,
        extensions: BTreeMap::new(),
    };
    write_frame(send, &Frame::ResHeader(header)).await?;
    for chunk in chunks {
        write_frame(send, &Frame::Data(chunk.bytes.clone())).await?;
    }
    write_frame(send, &Frame::End).await
}

async fn write_subscription_header(
    send: &mut SendStream,
    cursor: &hsp_core::EventCursor,
) -> Result<(), WireCodecError> {
    let mut meta = BTreeMap::new();
    meta.insert(
        "cursor".to_string(),
        serde_json::Value::String(cursor.encode()),
    );
    let header = ResHeader {
        version: 1,
        status_code: 200,
        request_id: None,
        payload_mode: Some(PayloadMode::None),
        payload_length: None,
        meta,
        extensions: BTreeMap::new(),
    };
    write_frame(send, &Frame::ResHeader(header)).await
}

async fn write_error(send: &mut SendStream, error: ApiError) -> Result<(), WireCodecError> {
    write_frame(
        send,
        &Frame::Error(hsp_core::WireErrorFrame {
            category: error.category,
            code: error.code,
            message: error.message,
        }),
    )
    .await
}

fn decode_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, WireCodecError> {
    serde_json::from_slice(bytes).map_err(|error| WireCodecError::InvalidFrame(error.to_string()))
}

fn decode_json_params<T: serde::de::DeserializeOwned>(
    header: &ReqHeader,
) -> Result<T, WireCodecError> {
    let value = serde_json::Value::Object(header.params.clone().into_iter().collect());
    serde_json::from_value(value).map_err(|error| WireCodecError::InvalidFrame(error.to_string()))
}

fn required_auth<'a>(
    auth: Option<&'a AuthContext>,
    operation: &str,
) -> Result<&'a AuthContext, WireCodecError> {
    auth.ok_or_else(|| {
        api_to_wire(ApiError::new(
            ApiErrorCategory::Auth,
            "missing_auth_frame",
            format!("{operation} requires AUTH frame"),
        ))
    })
}

fn build_server_config(
    authority: &str,
) -> Result<(ServerConfig, Vec<u8>), Box<dyn Error + Send + Sync>> {
    let certified = generate_simple_self_signed(vec![authority.to_string()])?;
    let cert_der = certified.cert.der().to_vec();
    let key_der = certified.signing_key.serialize_der();
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
        )?;
    crypto.alpn_protocols = vec![b"hsp/1".to_vec()];
    let server_config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    Ok((server_config, cert_der))
}

fn api_to_wire(error: ApiError) -> WireCodecError {
    WireCodecError::InvalidFrame(format!("{}: {}", error.code, error.message))
}

fn io_to_wire(error: quinn::ConnectionError) -> WireCodecError {
    WireCodecError::InvalidFrame(error.to_string())
}

fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::time::Duration;

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use hsp_core::{
        cid_from_bytes, AuthFrame, BindRequest, CapabilityClaims, CapabilityScope,
        ChannelBindingProof, ChunkRef, EncryptionDescriptor, EncryptionProfileId, EventType,
        GetPreference, GetRequest, HeadRequest, KeyPolicyId, ListRequest, Manifest,
        NamespaceMutationKind, NamespaceMutationRecord, ObjectSelector, PutCommitRequest,
        PutInitRequest, ReqHeader, ResolveRequest, SubscribeFilter, SubscribeRequest,
        UnbindRequest, VisibilityMode, WrappedObjectKeyRecord,
    };

    use super::*;

    fn temp_root(label: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("hsp-native-beta-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn native_runtime_kms_rejects_legacy_default_seed() {
        let error = native_runtime_kms(b"hsp-secure-alpha-local-seed").unwrap_err();
        assert_eq!(error.category, hsp_core::ApiErrorCategory::Policy);
        assert_eq!(error.code, "crypto_error");
    }

    fn write_registry(root: &Path) -> (PathBuf, SigningKey) {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
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
            tenant_id: hsp_core::TenantId("tenant-alpha".to_string()),
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
                server_visible_metadata: BTreeMap::new(),
                encrypted_client_metadata: BTreeMap::new(),
            },
        }
    }

    fn sign_cose_payload<T: serde::Serialize>(
        signing_key: &SigningKey,
        payload_value: &T,
    ) -> String {
        use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
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

    async fn connect(
        authority: &str,
        addr: SocketAddr,
        certificate_der: &[u8],
    ) -> quinn::Connection {
        let (client_config, server_name) = build_client_config(authority, certificate_der).unwrap();
        let mut endpoint = Endpoint::client("[::]:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        endpoint.connect(addr, &server_name).unwrap().await.unwrap()
    }

    async fn auth_frame(
        connection: &quinn::Connection,
        signing_key: &SigningKey,
        claims: CapabilityClaims,
    ) -> AuthFrame {
        let nonce = "native-test-nonce";
        let token_b64 = sign_claims(signing_key, &claims);
        let mut exporter = [0u8; 32];
        connection
            .export_keying_material(&mut exporter, tls_exporter_label(), nonce.as_bytes())
            .unwrap();
        AuthFrame {
            token_b64,
            channel_binding: ChannelBindingProof {
                binding_kind: "tls-exporter".to_string(),
                proof_b64: URL_SAFE_NO_PAD.encode(exporter),
                nonce: nonce.to_string(),
            },
        }
    }

    async fn send_request(
        connection: &quinn::Connection,
        auth: Option<AuthFrame>,
        header: ReqHeader,
        body: &[u8],
    ) -> (Option<Frame>, Option<Frame>, Vec<Vec<u8>>) {
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        if let Some(auth) = auth {
            write_frame(&mut send, &Frame::Auth(auth)).await.unwrap();
        }
        write_frame(&mut send, &Frame::ReqHeader(header))
            .await
            .unwrap();
        if !body.is_empty() {
            write_frame(&mut send, &Frame::Data(body.to_vec()))
                .await
                .unwrap();
        }
        write_frame(&mut send, &Frame::End).await.unwrap();
        send.finish().unwrap();

        let first = read_frame(&mut recv).await.ok();
        let mut data_frames = Vec::new();
        let mut second = None;
        if let Some(Frame::ResHeader(_)) = &first {
            loop {
                match read_frame(&mut recv).await.unwrap() {
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
        (first, second, data_frames)
    }

    #[tokio::test]
    async fn native_server_serves_settings_and_info() {
        let root = temp_root("info");
        let (registry_path, _signing_key) = write_registry(&root);
        let handle = spawn_native_beta_server(NativeBetaConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            authority: "localhost".to_string(),
            gateway_base_url: "https://localhost/v1/".to_string(),
            root_dir: root.clone(),
            issuer_registry_path: registry_path,
            server_instance_id: "native-info".to_string(),
            kms_seed: b"native-info-test-kms-seed-00000001".to_vec(),
        })
        .await
        .unwrap();

        let connection = connect("localhost", handle.local_addr, &handle.certificate_der).await;
        let mut settings_stream = connection.accept_uni().await.unwrap();
        let settings = read_frame(&mut settings_stream).await.unwrap();
        assert!(matches!(settings, Frame::Settings(_)));

        let (first, _, data_frames) = send_request(
            &connection,
            None,
            ReqHeader {
                version: 1,
                operation: hsp_core::OperationName::Info,
                request_id: None,
                payload_mode: None,
                payload_length: None,
                params: BTreeMap::new(),
                extensions: BTreeMap::new(),
            },
            &[],
        )
        .await;
        assert!(matches!(first, Some(Frame::ResHeader(_))));
        assert_eq!(data_frames.len(), 1);
        let info: hsp_core::InfoResponse = serde_json::from_slice(&data_frames[0]).unwrap();
        assert!(info.storage_encryption_required);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn native_server_handles_encrypted_upload_and_get() {
        let root = temp_root("upload");
        let (registry_path, signing_key) = write_registry(&root);
        let handle = spawn_native_beta_server(NativeBetaConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            authority: "localhost".to_string(),
            gateway_base_url: "https://localhost/v1/".to_string(),
            root_dir: root.clone(),
            issuer_registry_path: registry_path,
            server_instance_id: "native-upload".to_string(),
            kms_seed: b"native-upload-test-kms-seed-000001".to_vec(),
        })
        .await
        .unwrap();

        let connection = connect("localhost", handle.local_addr, &handle.certificate_der).await;
        let mut settings_stream = connection.accept_uni().await.unwrap();
        let _ = read_frame(&mut settings_stream).await.unwrap();

        let chunk_bytes = b"ciphertext!";
        let chunk_cid = cid_from_bytes(chunk_bytes);
        let manifest = manifest_for_chunk(chunk_cid.clone());
        let claims = CapabilityClaims {
            iss: "issuer".to_string(),
            sub: "subject".to_string(),
            aud: "hsp".to_string(),
            exp: u64::MAX,
            nbf: Some(0),
            jti: Some("native-put-init".to_string()),
            ops: vec![CapabilityScope::Read, CapabilityScope::Write],
            tenant_id: hsp_core::TenantId("tenant-alpha".to_string()),
            namespace_prefix: None,
            path_prefix: None,
            max_object_size: Some(4096),
            storage_classes: vec!["hot".to_string()],
            key_policy_id: Some(KeyPolicyId("policy-default".to_string())),
            metadata_visibility: Some(VisibilityMode::Split),
        };
        let put_init_auth = auth_frame(&connection, &signing_key, claims.clone()).await;
        let (first, _, data_frames) = send_request(
            &connection,
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
                tenant_id: hsp_core::TenantId("tenant-alpha".to_string()),
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
        assert!(matches!(first, Some(Frame::ResHeader(_))));
        let init: hsp_core::PutInitResponse = serde_json::from_slice(&data_frames[0]).unwrap();

        let mut chunk_claims = claims.clone();
        chunk_claims.jti = Some("native-put-chunk".to_string());
        let put_chunk_auth = auth_frame(&connection, &signing_key, chunk_claims).await;
        let (first, _, _) = send_request(
            &connection,
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
                }))
                .unwrap_or_default(),
                extensions: BTreeMap::new(),
            },
            chunk_bytes,
        )
        .await;
        assert!(matches!(first, Some(Frame::ResHeader(_))));

        let mut commit_claims = claims.clone();
        commit_claims.jti = Some("native-put-commit".to_string());
        let put_commit_auth = auth_frame(&connection, &signing_key, commit_claims).await;
        let (first, _, data_frames) = send_request(
            &connection,
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
                tenant_id: hsp_core::TenantId("tenant-alpha".to_string()),
                session_id: format!("session-{}", manifest.manifest_cid()),
                manifest_cid: manifest.manifest_cid(),
                idempotency_key: "idem-commit".to_string(),
            })
            .unwrap(),
        )
        .await;
        assert!(matches!(first, Some(Frame::ResHeader(_))));
        let commit: hsp_core::PutCommitResponse = serde_json::from_slice(&data_frames[0]).unwrap();

        let get_auth = auth_frame(&connection, &signing_key, claims).await;
        let (first, _, data_frames) = send_request(
            &connection,
            Some(get_auth),
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
                tenant_id: hsp_core::TenantId("tenant-alpha".to_string()),
                selector: ObjectSelector::cid(commit.object_cid),
                preference: Some(GetPreference::ManifestOnly),
                range: None,
            })
            .unwrap(),
        )
        .await;
        assert!(matches!(first, Some(Frame::ResHeader(_))));
        let meta: GetResponseMeta = serde_json::from_slice(&data_frames[0]).unwrap();
        assert_eq!(meta.preference, GetPreference::ManifestOnly);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn native_server_supports_namespace_bind_list_and_subscribe() {
        let root = temp_root("namespace");
        let (registry_path, signing_key) = write_registry(&root);
        let handle = spawn_native_beta_server(NativeBetaConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            authority: "localhost".to_string(),
            gateway_base_url: "https://localhost/v1/".to_string(),
            root_dir: root.clone(),
            issuer_registry_path: registry_path,
            server_instance_id: "native-namespace".to_string(),
            kms_seed: b"native-namespace-test-kms-seed-01".to_vec(),
        })
        .await
        .unwrap();

        let connection = connect("localhost", handle.local_addr, &handle.certificate_der).await;
        let mut settings_stream = connection.accept_uni().await.unwrap();
        let _ = read_frame(&mut settings_stream).await.unwrap();

        let chunk_bytes = b"ciphertext!";
        let chunk_cid = cid_from_bytes(chunk_bytes);
        let manifest = manifest_for_chunk(chunk_cid.clone());
        let base_claims = CapabilityClaims {
            iss: "issuer".to_string(),
            sub: "subject".to_string(),
            aud: "hsp".to_string(),
            exp: u64::MAX,
            nbf: Some(0),
            jti: Some("native-v1-put-init".to_string()),
            ops: vec![
                CapabilityScope::Read,
                CapabilityScope::Write,
                CapabilityScope::Bind,
                CapabilityScope::Unbind,
                CapabilityScope::List,
                CapabilityScope::Subscribe,
            ],
            tenant_id: hsp_core::TenantId("tenant-alpha".to_string()),
            namespace_prefix: None,
            path_prefix: None,
            max_object_size: Some(4096),
            storage_classes: vec!["hot".to_string()],
            key_policy_id: Some(KeyPolicyId("policy-default".to_string())),
            metadata_visibility: Some(VisibilityMode::Split),
        };

        let put_init_auth = auth_frame(&connection, &signing_key, base_claims.clone()).await;
        let (first, _, data_frames) = send_request(
            &connection,
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
                tenant_id: hsp_core::TenantId("tenant-alpha".to_string()),
                manifest: manifest.clone(),
                idempotency_key: "idem-v1-1".to_string(),
                encryption_profile_id: EncryptionProfileId("public-e2ee-v1".to_string()),
                key_policy_id: KeyPolicyId("policy-default".to_string()),
                metadata_visibility: VisibilityMode::Split,
                storage_class: "hot".to_string(),
                atomic_bind: None,
            })
            .unwrap(),
        )
        .await;
        assert!(matches!(first, Some(Frame::ResHeader(_))));
        let init: hsp_core::PutInitResponse = serde_json::from_slice(&data_frames[0]).unwrap();

        let mut chunk_claims = base_claims.clone();
        chunk_claims.jti = Some("native-v1-put-chunk".to_string());
        let put_chunk_auth = auth_frame(&connection, &signing_key, chunk_claims).await;
        let (first, _, _) = send_request(
            &connection,
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
                }))
                .unwrap_or_default(),
                extensions: BTreeMap::new(),
            },
            chunk_bytes,
        )
        .await;
        assert!(matches!(first, Some(Frame::ResHeader(_))));

        let mut commit_claims = base_claims.clone();
        commit_claims.jti = Some("native-v1-put-commit".to_string());
        let put_commit_auth = auth_frame(&connection, &signing_key, commit_claims).await;
        let (first, _, data_frames) = send_request(
            &connection,
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
                tenant_id: hsp_core::TenantId("tenant-alpha".to_string()),
                session_id: init.session_id.clone(),
                manifest_cid: manifest.manifest_cid(),
                idempotency_key: "idem-v1-commit".to_string(),
            })
            .unwrap(),
        )
        .await;
        assert!(matches!(first, Some(Frame::ResHeader(_))));
        let commit: hsp_core::PutCommitResponse = serde_json::from_slice(&data_frames[0]).unwrap();

        let bind_metadata = BTreeMap::from([("label".to_string(), "quarterly".to_string())]);
        let bind_record = NamespaceMutationRecord {
            version: 1,
            tenant_id: hsp_core::TenantId("tenant-alpha".to_string()),
            namespace: "docs".to_string(),
            path: "reports/q1".to_string(),
            kind: NamespaceMutationKind::Bind,
            target_cid: Some(commit.object_cid.clone()),
            if_revision: None,
            ttl_ms: None,
            metadata: bind_metadata.clone(),
            issued_at_ms: 2,
        };
        let bind_request = BindRequest {
            tenant_id: hsp_core::TenantId("tenant-alpha".to_string()),
            namespace: "docs".to_string(),
            path: "reports/q1".to_string(),
            target_cid: commit.object_cid.clone(),
            if_revision: None,
            if_absent: true,
            metadata: bind_metadata.clone(),
            ttl_ms: None,
            idempotency_key: "idem-bind-1".to_string(),
            signed_record_b64: sign_namespace_record(&signing_key, &bind_record),
        };
        let mut bind_claims = base_claims.clone();
        bind_claims.jti = Some("native-v1-bind".to_string());
        let bind_auth = auth_frame(&connection, &signing_key, bind_claims).await;
        let (first, _, data_frames) = send_request(
            &connection,
            Some(bind_auth),
            ReqHeader {
                version: 1,
                operation: hsp_core::OperationName::Bind,
                request_id: None,
                payload_mode: Some(PayloadMode::Json),
                payload_length: None,
                params: BTreeMap::new(),
                extensions: BTreeMap::new(),
            },
            &serde_json::to_vec(&bind_request).unwrap(),
        )
        .await;
        assert!(matches!(first, Some(Frame::ResHeader(_))));
        let bind_response: hsp_core::BindResponse =
            serde_json::from_slice(&data_frames[0]).unwrap();
        assert_eq!(bind_response.revision, 1);

        let read_auth = auth_frame(&connection, &signing_key, base_claims.clone()).await;
        let (first, _, data_frames) = send_request(
            &connection,
            Some(read_auth),
            ReqHeader {
                version: 1,
                operation: hsp_core::OperationName::Resolve,
                request_id: None,
                payload_mode: Some(PayloadMode::Json),
                payload_length: None,
                params: BTreeMap::new(),
                extensions: BTreeMap::new(),
            },
            &serde_json::to_vec(&ResolveRequest {
                tenant_id: hsp_core::TenantId("tenant-alpha".to_string()),
                namespace: "docs".to_string(),
                path: "reports/q1".to_string(),
                at_revision: None,
                if_revision: None,
            })
            .unwrap(),
        )
        .await;
        assert!(matches!(first, Some(Frame::ResHeader(_))));
        let resolved: hsp_core::ResolveResponse = serde_json::from_slice(&data_frames[0]).unwrap();
        assert_eq!(resolved.target_cid, Some(commit.object_cid.clone()));
        assert_eq!(resolved.revision, bind_response.revision);

        let head_auth = auth_frame(&connection, &signing_key, base_claims.clone()).await;
        let (first, _, data_frames) = send_request(
            &connection,
            Some(head_auth),
            ReqHeader {
                version: 1,
                operation: hsp_core::OperationName::Head,
                request_id: None,
                payload_mode: Some(PayloadMode::Json),
                payload_length: None,
                params: BTreeMap::new(),
                extensions: BTreeMap::new(),
            },
            &serde_json::to_vec(&HeadRequest {
                tenant_id: hsp_core::TenantId("tenant-alpha".to_string()),
                selector: ObjectSelector::namespace("docs", "reports/q1"),
            })
            .unwrap(),
        )
        .await;
        assert!(matches!(first, Some(Frame::ResHeader(_))));
        let head: hsp_core::HeadResponse = serde_json::from_slice(&data_frames[0]).unwrap();
        assert_eq!(head.resolved_namespace.as_deref(), Some("docs"));
        assert_eq!(head.resolved_path.as_deref(), Some("reports/q1"));
        assert_eq!(head.resolved_revision, Some(bind_response.revision));

        let get_auth = auth_frame(&connection, &signing_key, base_claims.clone()).await;
        let (first, _, data_frames) = send_request(
            &connection,
            Some(get_auth),
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
                tenant_id: hsp_core::TenantId("tenant-alpha".to_string()),
                selector: ObjectSelector::namespace("docs", "reports/q1"),
                preference: Some(GetPreference::ManifestOnly),
                range: None,
            })
            .unwrap(),
        )
        .await;
        assert!(matches!(first, Some(Frame::ResHeader(_))));
        let get_meta: GetResponseMeta = serde_json::from_slice(&data_frames[0]).unwrap();
        assert_eq!(get_meta.resolved_namespace.as_deref(), Some("docs"));
        assert_eq!(get_meta.resolved_path.as_deref(), Some("reports/q1"));
        assert_eq!(get_meta.resolved_revision, Some(bind_response.revision));

        let list_auth = auth_frame(&connection, &signing_key, base_claims.clone()).await;
        let (first, _, data_frames) = send_request(
            &connection,
            Some(list_auth),
            ReqHeader {
                version: 1,
                operation: hsp_core::OperationName::List,
                request_id: None,
                payload_mode: Some(PayloadMode::Json),
                payload_length: None,
                params: BTreeMap::new(),
                extensions: BTreeMap::new(),
            },
            &serde_json::to_vec(&ListRequest {
                tenant_id: hsp_core::TenantId("tenant-alpha".to_string()),
                namespace: "docs".to_string(),
                prefix: Some("reports".to_string()),
                cursor: None,
                limit: Some(10),
                recursive: true,
                include_tombstones: false,
            })
            .unwrap(),
        )
        .await;
        assert!(matches!(first, Some(Frame::ResHeader(_))));
        let list: hsp_core::ListResponse = serde_json::from_slice(&data_frames[0]).unwrap();
        assert_eq!(list.items.len(), 1);
        assert_eq!(list.items[0].path, "reports/q1");
        assert_eq!(
            list.items[0].target_cid.as_deref(),
            Some(commit.object_cid.as_str())
        );

        let subscribe_auth = auth_frame(&connection, &signing_key, base_claims.clone()).await;
        let (first, second, _) = send_request(
            &connection,
            Some(subscribe_auth),
            ReqHeader {
                version: 1,
                operation: hsp_core::OperationName::Subscribe,
                request_id: None,
                payload_mode: Some(PayloadMode::Json),
                payload_length: None,
                params: BTreeMap::new(),
                extensions: BTreeMap::new(),
            },
            &serde_json::to_vec(&SubscribeRequest {
                tenant_id: hsp_core::TenantId("tenant-alpha".to_string()),
                filters: vec![SubscribeFilter {
                    event_type: Some(EventType::NamespaceBound),
                    namespace_prefix: Some("docs".to_string()),
                    path_exact: Some("reports/q1".to_string()),
                    object_cid: None,
                    tenant_scope: None,
                }],
                cursor: None,
                from_seq: Some(0),
                heartbeat_ms: Some(100),
                batch_max: Some(8),
            })
            .unwrap(),
        )
        .await;
        assert!(matches!(first, Some(Frame::ResHeader(_))));
        match second {
            Some(Frame::Event(event)) => {
                assert_eq!(event.event_type, EventType::NamespaceBound);
                assert_eq!(event.seq, bind_response.event_seq);
            }
            other => panic!("expected namespace-bound event, got {other:?}"),
        }

        let unbind_record = NamespaceMutationRecord {
            version: 1,
            tenant_id: hsp_core::TenantId("tenant-alpha".to_string()),
            namespace: "docs".to_string(),
            path: "reports/q1".to_string(),
            kind: NamespaceMutationKind::Unbind,
            target_cid: None,
            if_revision: Some(bind_response.revision),
            ttl_ms: None,
            metadata: BTreeMap::new(),
            issued_at_ms: 3,
        };
        let mut unbind_claims = base_claims.clone();
        unbind_claims.jti = Some("native-v1-unbind".to_string());
        let unbind_auth = auth_frame(&connection, &signing_key, unbind_claims).await;
        let (first, _, data_frames) = send_request(
            &connection,
            Some(unbind_auth),
            ReqHeader {
                version: 1,
                operation: hsp_core::OperationName::Unbind,
                request_id: None,
                payload_mode: Some(PayloadMode::Json),
                payload_length: None,
                params: BTreeMap::new(),
                extensions: BTreeMap::new(),
            },
            &serde_json::to_vec(&UnbindRequest {
                tenant_id: hsp_core::TenantId("tenant-alpha".to_string()),
                namespace: "docs".to_string(),
                path: "reports/q1".to_string(),
                if_revision: bind_response.revision,
                hard_delete: false,
                idempotency_key: "idem-unbind-1".to_string(),
                signed_record_b64: sign_namespace_record(&signing_key, &unbind_record),
            })
            .unwrap(),
        )
        .await;
        assert!(matches!(first, Some(Frame::ResHeader(_))));
        let unbind_response: hsp_core::UnbindResponse =
            serde_json::from_slice(&data_frames[0]).unwrap();
        assert!(unbind_response.tombstone);

        let read_auth = auth_frame(&connection, &signing_key, base_claims).await;
        let (first, _, _) = send_request(
            &connection,
            Some(read_auth),
            ReqHeader {
                version: 1,
                operation: hsp_core::OperationName::Head,
                request_id: None,
                payload_mode: Some(PayloadMode::Json),
                payload_length: None,
                params: BTreeMap::new(),
                extensions: BTreeMap::new(),
            },
            &serde_json::to_vec(&HeadRequest {
                tenant_id: hsp_core::TenantId("tenant-alpha".to_string()),
                selector: ObjectSelector::namespace("docs", "reports/q1"),
            })
            .unwrap(),
        )
        .await;
        match first {
            Some(Frame::Error(error)) => assert_eq!(error.code, "path_tombstoned"),
            other => panic!("expected path_tombstoned error, got {other:?}"),
        }

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn authority_mismatch_is_rejected() {
        let root = temp_root("authority");
        let (registry_path, _) = write_registry(&root);
        let handle = spawn_native_beta_server(NativeBetaConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            authority: "localhost".to_string(),
            gateway_base_url: "https://localhost/v1/".to_string(),
            root_dir: root.clone(),
            issuer_registry_path: registry_path,
            server_instance_id: "native-authority".to_string(),
            kms_seed: b"native-authority-test-kms-seed-01".to_vec(),
        })
        .await
        .unwrap();

        let (client_config, server_name) =
            build_client_config("wrong-host", &handle.certificate_der).unwrap();
        let mut endpoint = Endpoint::client("[::]:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let error = endpoint
            .connect(handle.local_addr, &server_name)
            .unwrap()
            .await
            .unwrap_err();
        assert!(error.to_string().contains("certificate"));
        handle.shutdown().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
