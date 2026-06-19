use std::collections::BTreeSet;
use std::env;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Once};
use std::time::SystemTime;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use hmac::{Hmac, Mac};
use hsp_core::{ApiError, ApiErrorCategory};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

type HmacSha256 = Hmac<Sha256>;
static RUSTLS_CRYPTO_PROVIDER: Once = Once::new();

#[derive(Clone, PartialEq, Eq)]
pub enum StorageBackendConfig {
    Filesystem,
    S3(S3StorageBackendConfig),
}

impl fmt::Debug for StorageBackendConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Filesystem => formatter.write_str("Filesystem"),
            Self::S3(config) => formatter.debug_tuple("S3").field(config).finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct S3StorageBackendConfig {
    pub endpoint_url: String,
    pub bucket: String,
    pub region: String,
    pub prefix: String,
    pub access_key: String,
    pub secret_key: String,
    pub ca_cert_path: Option<PathBuf>,
}

impl fmt::Debug for S3StorageBackendConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S3StorageBackendConfig")
            .field("endpoint_url", &self.endpoint_url)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("prefix", &self.prefix)
            .field("access_key", &redact_nonempty(&self.access_key))
            .field("secret_key", &redact_nonempty(&self.secret_key))
            .field("ca_cert_path", &self.ca_cert_path)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct StoreBackend {
    kind: StoreBackendKind,
}

#[derive(Clone, Debug)]
enum StoreBackendKind {
    Filesystem { root_dir: PathBuf },
    S3(Box<S3ObjectStore>),
}

impl StoreBackend {
    pub fn from_config(root_dir: PathBuf, config: &StorageBackendConfig) -> Result<Self, ApiError> {
        let kind = match config {
            StorageBackendConfig::Filesystem => StoreBackendKind::Filesystem { root_dir },
            StorageBackendConfig::S3(config) => {
                StoreBackendKind::S3(Box::new(S3ObjectStore::new(config)?))
            }
        };
        Ok(Self { kind })
    }

    pub fn ready(&self) -> bool {
        match &self.kind {
            StoreBackendKind::Filesystem { root_dir } => root_dir.exists(),
            StoreBackendKind::S3(store) => store.head_bucket().is_ok(),
        }
    }

    pub fn ensure_store_roots(&self, store_kinds: &[&str]) -> Result<(), ApiError> {
        match &self.kind {
            StoreBackendKind::Filesystem { root_dir } => {
                for store_kind in store_kinds {
                    fs::create_dir_all(root_dir.join(store_kind)).map_err(|error| {
                        ApiError::new(ApiErrorCategory::Storage, "mkdir_failed", error.to_string())
                    })?;
                }
                Ok(())
            }
            StoreBackendKind::S3(store) => store.head_bucket().map(|_| ()),
        }
    }

    pub fn exists(&self, key: &str) -> bool {
        match &self.kind {
            StoreBackendKind::Filesystem { root_dir } => root_dir.join(key).exists(),
            StoreBackendKind::S3(store) => store.head_object(key).unwrap_or(false),
        }
    }

    pub fn read(&self, key: &str) -> Result<Option<Vec<u8>>, ApiError> {
        match &self.kind {
            StoreBackendKind::Filesystem { root_dir } => {
                let path = root_dir.join(key);
                if !path.exists() {
                    return Ok(None);
                }
                fs::read(path).map(Some).map_err(storage_read_error)
            }
            StoreBackendKind::S3(store) => store.get_object(key),
        }
    }

    pub fn write(&self, key: &str, bytes: &[u8]) -> Result<(), ApiError> {
        match &self.kind {
            StoreBackendKind::Filesystem { root_dir } => {
                let path = root_dir.join(key);
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(|error| {
                        ApiError::new(ApiErrorCategory::Storage, "mkdir_failed", error.to_string())
                    })?;
                }
                fs::write(path, bytes).map_err(storage_write_error)
            }
            StoreBackendKind::S3(store) => store.put_object(key, bytes, false).map(|_| ()),
        }
    }

    pub fn create(&self, key: &str, bytes: &[u8]) -> Result<bool, ApiError> {
        match &self.kind {
            StoreBackendKind::Filesystem { root_dir } => {
                let path = root_dir.join(key);
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(|error| {
                        ApiError::new(ApiErrorCategory::Storage, "mkdir_failed", error.to_string())
                    })?;
                }
                let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
                    Ok(file) => file,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        return Ok(false)
                    }
                    Err(error) => return Err(storage_create_error(error)),
                };
                file.write_all(bytes).map_err(storage_write_error)?;
                file.sync_all().map_err(storage_sync_error)?;
                Ok(true)
            }
            StoreBackendKind::S3(store) => store.put_object(key, bytes, true),
        }
    }

    pub fn delete(&self, key: &str) -> Result<(), ApiError> {
        match &self.kind {
            StoreBackendKind::Filesystem { root_dir } => {
                let path = root_dir.join(key);
                if path.exists() {
                    fs::remove_file(path).map_err(storage_delete_error)?;
                }
                Ok(())
            }
            StoreBackendKind::S3(store) => store.delete_object(key),
        }
    }

    pub fn list_values(&self, prefix: &str) -> Result<Vec<Vec<u8>>, ApiError> {
        match &self.kind {
            StoreBackendKind::Filesystem { root_dir } => {
                let root = root_dir.join(prefix);
                if !root.exists() {
                    return Ok(Vec::new());
                }
                let mut items = Vec::new();
                for entry in fs::read_dir(root).map_err(storage_read_error)? {
                    let entry = entry.map_err(storage_read_error)?;
                    let path = entry.path();
                    if path.is_file() {
                        items.push(fs::read(path).map_err(storage_read_error)?);
                    }
                }
                Ok(items)
            }
            StoreBackendKind::S3(store) => {
                let mut values = Vec::new();
                for key in store.list_keys(prefix)? {
                    if let Some(bytes) = store.get_object(&key)? {
                        values.push(bytes);
                    }
                }
                Ok(values)
            }
        }
    }

    pub fn list_child_dirs(&self, prefix: &str) -> Result<Vec<String>, ApiError> {
        match &self.kind {
            StoreBackendKind::Filesystem { root_dir } => {
                let root = root_dir.join(prefix);
                if !root.exists() {
                    return Ok(Vec::new());
                }
                let mut children = Vec::new();
                for entry in fs::read_dir(root).map_err(storage_read_error)? {
                    let entry = entry.map_err(storage_read_error)?;
                    if entry.path().is_dir() {
                        children.push(entry.file_name().to_string_lossy().to_string());
                    }
                }
                Ok(children)
            }
            StoreBackendKind::S3(store) => {
                let normalized_prefix = normalize_store_prefix(prefix);
                let mut children = BTreeSet::new();
                for key in store.list_keys(&normalized_prefix)? {
                    if let Some(rest) = key.strip_prefix(&normalized_prefix) {
                        if let Some(child) =
                            rest.split('/').next().filter(|value| !value.is_empty())
                        {
                            children.insert(child.to_string());
                        }
                    }
                }
                Ok(children.into_iter().collect())
            }
        }
    }
}

#[derive(Clone)]
struct S3ObjectStore {
    config: S3StorageBackendConfig,
    endpoint_url: String,
    endpoint_host: String,
    agent: ureq::Agent,
}

impl fmt::Debug for S3ObjectStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S3ObjectStore")
            .field("config", &self.config)
            .field("endpoint_url", &self.endpoint_url)
            .field("endpoint_host", &self.endpoint_host)
            .finish_non_exhaustive()
    }
}

impl S3ObjectStore {
    fn new(config: &S3StorageBackendConfig) -> Result<Self, ApiError> {
        let endpoint_url = config.endpoint_url.trim().trim_end_matches('/').to_string();
        if endpoint_url.is_empty() {
            return Err(config_error("HSP_BACKING_S3_ENDPOINT is required"));
        }
        if config.bucket.trim().is_empty() {
            return Err(config_error("HSP_BACKING_S3_BUCKET is required"));
        }
        if config.access_key.trim().is_empty() {
            return Err(config_error(
                "HSP_BACKING_S3_ACCESS_KEY or AWS_ACCESS_KEY_ID is required",
            ));
        }
        if config.secret_key.trim().is_empty() {
            return Err(config_error(
                "HSP_BACKING_S3_SECRET_KEY or AWS_SECRET_ACCESS_KEY is required",
            ));
        }
        let endpoint_host = endpoint_host(&endpoint_url)?;
        let ca_cert_path = config.ca_cert_path.clone();
        let agent = build_s3_agent(ca_cert_path.as_ref())?;
        Ok(Self {
            config: S3StorageBackendConfig {
                endpoint_url: endpoint_url.clone(),
                bucket: config.bucket.trim().to_string(),
                region: first_non_empty(&config.region, "us-east-1"),
                prefix: normalize_store_prefix(&config.prefix),
                access_key: config.access_key.trim().to_string(),
                secret_key: config.secret_key.trim().to_string(),
                ca_cert_path,
            },
            endpoint_url,
            endpoint_host,
            agent,
        })
    }

    fn head_bucket(&self) -> Result<(), ApiError> {
        let status = self.request_status("HEAD", "", &[], None, &[])?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(storage_status_error("s3_head_bucket_failed", status, ""))
        }
    }

    fn head_object(&self, key: &str) -> Result<bool, ApiError> {
        let status = self.request_status("HEAD", &self.backend_key(key), &[], None, &[])?;
        match status {
            200..=299 => Ok(true),
            404 => Ok(false),
            _ => Err(storage_status_error("s3_head_object_failed", status, key)),
        }
    }

    fn get_object(&self, key: &str) -> Result<Option<Vec<u8>>, ApiError> {
        let response = self.request("GET", &self.backend_key(key), &[], None, &[])?;
        match response {
            S3Response::Ok(bytes) => Ok(Some(bytes)),
            S3Response::Status(404, _) => Ok(None),
            S3Response::Status(status, body) => Err(storage_status_error(
                "s3_get_object_failed",
                status,
                &first_non_empty(&body, key),
            )),
        }
    }

    fn put_object(&self, key: &str, bytes: &[u8], only_if_absent: bool) -> Result<bool, ApiError> {
        let extra_headers = if only_if_absent {
            vec![("if-none-match".to_string(), "*".to_string())]
        } else {
            Vec::new()
        };
        let response = self.request(
            "PUT",
            &self.backend_key(key),
            &[],
            Some(bytes),
            &extra_headers,
        )?;
        match response {
            S3Response::Ok(_) => Ok(true),
            S3Response::Status(409 | 412, _) if only_if_absent => Ok(false),
            S3Response::Status(status, body) => Err(storage_status_error(
                "s3_put_object_failed",
                status,
                &first_non_empty(&body, key),
            )),
        }
    }

    fn delete_object(&self, key: &str) -> Result<(), ApiError> {
        let response = self.request("DELETE", &self.backend_key(key), &[], None, &[])?;
        match response {
            S3Response::Ok(_) | S3Response::Status(404, _) => Ok(()),
            S3Response::Status(status, body) => Err(storage_status_error(
                "s3_delete_object_failed",
                status,
                &first_non_empty(&body, key),
            )),
        }
    }

    fn list_keys(&self, prefix: &str) -> Result<Vec<String>, ApiError> {
        let prefix = self.backend_key(prefix);
        let mut keys = Vec::new();
        let mut continuation_token: Option<String> = None;
        loop {
            let mut query = vec![
                ("list-type".to_string(), "2".to_string()),
                ("prefix".to_string(), prefix.clone()),
                ("max-keys".to_string(), "1000".to_string()),
            ];
            if let Some(token) = &continuation_token {
                query.push(("continuation-token".to_string(), token.clone()));
            }
            let response = self.request("GET", "", &query, None, &[])?;
            let body = match response {
                S3Response::Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                S3Response::Status(status, body) => {
                    return Err(storage_status_error(
                        "s3_list_objects_failed",
                        status,
                        &first_non_empty(&body, &prefix),
                    ))
                }
            };
            keys.extend(
                xml_values(&body, "Key")
                    .into_iter()
                    .map(|key| self.strip_backend_prefix(&key)),
            );
            let truncated = xml_values(&body, "IsTruncated")
                .into_iter()
                .next()
                .map(|value| value.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !truncated {
                break;
            }
            continuation_token = xml_values(&body, "NextContinuationToken")
                .into_iter()
                .next();
            if continuation_token.is_none() {
                break;
            }
        }
        Ok(keys)
    }

    fn request_status(
        &self,
        method: &str,
        key: &str,
        query: &[(String, String)],
        body: Option<&[u8]>,
        extra_headers: &[(String, String)],
    ) -> Result<u16, ApiError> {
        match self.request(method, key, query, body, extra_headers)? {
            S3Response::Ok(_) => Ok(200),
            S3Response::Status(status, _) => Ok(status),
        }
    }

    fn request(
        &self,
        method: &str,
        key: &str,
        query: &[(String, String)],
        body: Option<&[u8]>,
        extra_headers: &[(String, String)],
    ) -> Result<S3Response, ApiError> {
        let payload = body.unwrap_or_default();
        let payload_hash = hex::encode(Sha256::digest(payload));
        let timestamp = amz_timestamp()?;
        let date = timestamp[..8].to_string();
        let encoded_key = encode_s3_key_path(key);
        let canonical_uri = if encoded_key.is_empty() {
            format!("/{}/", percent_encode_path_segment(&self.config.bucket))
        } else {
            format!(
                "/{}/{}",
                percent_encode_path_segment(&self.config.bucket),
                encoded_key
            )
        };
        let canonical_query = canonical_query_string(query);
        let url = if canonical_query.is_empty() {
            format!("{}{}", self.endpoint_url, canonical_uri)
        } else {
            format!("{}{}?{}", self.endpoint_url, canonical_uri, canonical_query)
        };

        let mut headers = vec![
            ("host".to_string(), self.endpoint_host.clone()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-date".to_string(), timestamp.clone()),
        ];
        headers.extend(extra_headers.iter().cloned());
        headers.sort_by(|left, right| left.0.cmp(&right.0));
        let signed_headers = headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let canonical_headers = headers
            .iter()
            .map(|(name, value)| format!("{}:{}\n", name.to_ascii_lowercase(), value.trim()))
            .collect::<String>();
        let canonical_request = format!(
            "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );
        let credential_scope = format!("{date}/{}/s3/aws4_request", self.config.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{timestamp}\n{credential_scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );
        let signing_key = signing_key(&self.config.secret_key, &date, &self.config.region);
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.config.access_key
        );

        let mut request = self
            .agent
            .request(method, &url)
            .set("Authorization", &authorization)
            .set("Host", &self.endpoint_host)
            .set("x-amz-content-sha256", &payload_hash)
            .set("x-amz-date", &timestamp);
        for (name, value) in extra_headers {
            request = request.set(name, value);
        }
        let result = if let Some(body) = body {
            request.send_bytes(body)
        } else {
            request.call()
        };
        match result {
            Ok(response) => read_success_response(response),
            Err(ureq::Error::Status(status, response)) => {
                Ok(S3Response::Status(status, read_response_body(response)))
            }
            Err(ureq::Error::Transport(error)) => Err(ApiError::new(
                ApiErrorCategory::Storage,
                "s3_transport_failed",
                error.to_string(),
            )),
        }
    }

    fn backend_key(&self, key: &str) -> String {
        let trimmed = key.trim_matches('/');
        match self.config.prefix.trim_matches('/') {
            "" => trimmed.to_string(),
            prefix if trimmed.is_empty() => prefix.to_string(),
            prefix => format!("{prefix}/{trimmed}"),
        }
    }

    fn strip_backend_prefix(&self, key: &str) -> String {
        let prefix = self.config.prefix.trim_matches('/');
        if prefix.is_empty() {
            key.trim_start_matches('/').to_string()
        } else {
            key.trim_start_matches('/')
                .strip_prefix(prefix)
                .unwrap_or(key)
                .trim_start_matches('/')
                .to_string()
        }
    }
}

enum S3Response {
    Ok(Vec<u8>),
    Status(u16, String),
}

pub fn storage_backend_config_from_env() -> Result<StorageBackendConfig, ApiError> {
    match env::var("HSP_STORAGE_BACKEND")
        .unwrap_or_else(|_| "filesystem".to_string())
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "filesystem" | "fs" => Ok(StorageBackendConfig::Filesystem),
        "s3" => Ok(StorageBackendConfig::S3(S3StorageBackendConfig {
            endpoint_url: env_required("HSP_BACKING_S3_ENDPOINT")?,
            bucket: env_required("HSP_BACKING_S3_BUCKET")?,
            region: env::var("HSP_BACKING_S3_REGION").unwrap_or_else(|_| "us-east-1".to_string()),
            prefix: env::var("HSP_BACKING_S3_PREFIX").unwrap_or_default(),
            access_key: env::var("HSP_BACKING_S3_ACCESS_KEY")
                .or_else(|_| env::var("AWS_ACCESS_KEY_ID"))
                .map_err(|_| {
                    config_error("HSP_BACKING_S3_ACCESS_KEY or AWS_ACCESS_KEY_ID is required")
                })?,
            secret_key: env::var("HSP_BACKING_S3_SECRET_KEY")
                .or_else(|_| env::var("AWS_SECRET_ACCESS_KEY"))
                .map_err(|_| {
                    config_error("HSP_BACKING_S3_SECRET_KEY or AWS_SECRET_ACCESS_KEY is required")
                })?,
            ca_cert_path: env_optional_path("HSP_BACKING_S3_CA_CERT_PATH"),
        })),
        value => Err(config_error(&format!(
            "unsupported HSP_STORAGE_BACKEND {value:?}; use filesystem or s3"
        ))),
    }
}

fn env_optional_path(name: &str) -> Option<PathBuf> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn env_required(name: &str) -> Result<String, ApiError> {
    env::var(name)
        .map(|value| value.trim().to_string())
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| config_error(&format!("{name} is required")))
}

fn endpoint_host(endpoint_url: &str) -> Result<String, ApiError> {
    let without_scheme = endpoint_url
        .strip_prefix("https://")
        .or_else(|| endpoint_url.strip_prefix("http://"))
        .ok_or_else(|| {
            config_error("HSP_BACKING_S3_ENDPOINT must start with http:// or https://")
        })?;
    let host = without_scheme
        .split('/')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    if host.is_empty() {
        Err(config_error("HSP_BACKING_S3_ENDPOINT host is empty"))
    } else {
        Ok(host)
    }
}

fn build_s3_agent(ca_cert_path: Option<&PathBuf>) -> Result<ureq::Agent, ApiError> {
    RUSTLS_CRYPTO_PROVIDER.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });

    let Some(ca_cert_path) = ca_cert_path else {
        return Ok(ureq::builder().build());
    };
    let pem = fs::read(ca_cert_path).map_err(|error| {
        ApiError::new(
            ApiErrorCategory::Storage,
            "s3_ca_read_failed",
            format!("failed to read {}: {error}", ca_cert_path.display()),
        )
    })?;
    let certs = parse_pem_certificates(&pem).map_err(|error| {
        ApiError::new(
            ApiErrorCategory::Storage,
            "s3_ca_parse_failed",
            format!("failed to parse {}: {error}", ca_cert_path.display()),
        )
    })?;
    if certs.is_empty() {
        return Err(ApiError::new(
            ApiErrorCategory::Storage,
            "s3_ca_parse_failed",
            format!(
                "{} does not contain PEM certificates",
                ca_cert_path.display()
            ),
        ));
    }
    let mut root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let (valid, _invalid) = root_store.add_parsable_certificates(certs);
    if valid == 0 {
        return Err(ApiError::new(
            ApiErrorCategory::Storage,
            "s3_ca_parse_failed",
            format!(
                "{} does not contain usable CA certificates",
                ca_cert_path.display()
            ),
        ));
    }
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(ureq::builder().tls_config(Arc::new(tls_config)).build())
}

fn parse_pem_certificates(
    pem: &[u8],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let text =
        std::str::from_utf8(pem).map_err(|_| "CA bundle is not valid UTF-8 PEM".to_string())?;
    let mut certs = Vec::new();
    let mut rest = text;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    while let Some(begin) = rest.find(BEGIN) {
        let after_begin = &rest[begin + BEGIN.len()..];
        let Some(end) = after_begin.find(END) else {
            return Err("certificate block is missing END marker".to_string());
        };
        let body = &after_begin[..end];
        let base64_body = body
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<String>();
        let der = STANDARD
            .decode(base64_body.as_bytes())
            .map_err(|error| format!("certificate base64 decode failed: {error}"))?;
        certs.push(rustls::pki_types::CertificateDer::from(der));
        rest = &after_begin[end + END.len()..];
    }

    Ok(certs)
}

fn amz_timestamp() -> Result<String, ApiError> {
    let now = OffsetDateTime::from(SystemTime::now());
    Ok(format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    ))
}

fn signing_key(secret_key: &str, date: &str, region: &str) -> Vec<u8> {
    let date_key = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, b"s3");
    hmac_sha256(&service_key, b"aws4_request")
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn canonical_query_string(query: &[(String, String)]) -> String {
    let mut pairs = query
        .iter()
        .map(|(key, value)| (percent_encode_query(key), percent_encode_query(value)))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode_s3_key_path(key: &str) -> String {
    key.trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(percent_encode_path_segment)
        .collect::<Vec<_>>()
        .join("/")
}

fn percent_encode_path_segment(value: &str) -> String {
    percent_encode(value, false)
}

fn percent_encode_query(value: &str) -> String {
    percent_encode(value, true)
}

fn percent_encode(value: &str, encode_slash: bool) -> String {
    let mut encoded = String::new();
    for byte in value.as_bytes() {
        let allowed = byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (!encode_slash && *byte == b'/');
        if allowed {
            encoded.push(*byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn normalize_store_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim().trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}/")
    }
}

fn xml_values(body: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut values = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find(&open) {
        let value_start = start + open.len();
        let Some(end) = rest[value_start..].find(&close) else {
            break;
        };
        values.push(xml_unescape(&rest[value_start..value_start + end]));
        rest = &rest[value_start + end + close.len()..];
    }
    values
}

fn xml_unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn read_success_response(response: ureq::Response) -> Result<S3Response, ApiError> {
    read_response_bytes(response).map(S3Response::Ok)
}

fn read_response_body(response: ureq::Response) -> String {
    read_response_bytes(response)
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .unwrap_or_default()
}

fn read_response_bytes(response: ureq::Response) -> Result<Vec<u8>, ApiError> {
    const MAX_S3_BACKEND_RESPONSE_BYTES: u64 = 128 * 1024 * 1024;
    let reader = response.into_reader();
    let mut bytes = Vec::new();
    reader
        .take(MAX_S3_BACKEND_RESPONSE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ApiError::new(
                ApiErrorCategory::Storage,
                "s3_read_failed",
                error.to_string(),
            )
        })?;
    if bytes.len() as u64 > MAX_S3_BACKEND_RESPONSE_BYTES {
        return Err(ApiError::new(
            ApiErrorCategory::Storage,
            "s3_response_too_large",
            "S3 backend response exceeds the configured read limit",
        ));
    }
    Ok(bytes)
}

fn first_non_empty(value: &str, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_string()
    } else {
        value.trim().to_string()
    }
}

fn redact_nonempty(value: &str) -> &str {
    if value.trim().is_empty() {
        ""
    } else {
        "<redacted>"
    }
}

fn config_error(message: &str) -> ApiError {
    ApiError::new(ApiErrorCategory::Storage, "storage_config_invalid", message)
}

fn storage_read_error(error: std::io::Error) -> ApiError {
    ApiError::new(
        ApiErrorCategory::Storage,
        "store_read_failed",
        error.to_string(),
    )
}

fn storage_write_error(error: std::io::Error) -> ApiError {
    ApiError::new(
        ApiErrorCategory::Storage,
        "store_write_failed",
        error.to_string(),
    )
}

fn storage_create_error(error: std::io::Error) -> ApiError {
    ApiError::new(
        ApiErrorCategory::Storage,
        "store_create_failed",
        error.to_string(),
    )
}

fn storage_sync_error(error: std::io::Error) -> ApiError {
    ApiError::new(
        ApiErrorCategory::Storage,
        "store_sync_failed",
        error.to_string(),
    )
}

fn storage_delete_error(error: std::io::Error) -> ApiError {
    ApiError::new(
        ApiErrorCategory::Storage,
        "store_delete_failed",
        error.to_string(),
    )
}

fn storage_status_error(code: &str, status: u16, detail: &str) -> ApiError {
    let detail = if detail.trim().is_empty() {
        format!("S3 returned status {status}")
    } else {
        format!("S3 returned status {status}: {}", detail.trim())
    };
    ApiError::new(ApiErrorCategory::Storage, code, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ROOT_ID: AtomicU64 = AtomicU64::new(1);

    fn temp_root() -> PathBuf {
        let root = env::temp_dir().join(format!(
            "hsp-store-{}-{}",
            std::process::id(),
            NEXT_TEMP_ROOT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        root
    }

    fn s3_config() -> S3StorageBackendConfig {
        S3StorageBackendConfig {
            endpoint_url: "https://s3.eu-storage.internal".to_string(),
            bucket: "ping-hsp-media-prod".to_string(),
            region: "eu".to_string(),
            prefix: "media/".to_string(),
            access_key: "access-key-for-test".to_string(),
            secret_key: "secret-key-for-test".to_string(),
            ca_cert_path: None,
        }
    }

    #[test]
    fn filesystem_store_roundtrips_and_lists_values() {
        let root = temp_root();
        let store = StoreBackend::from_config(root.clone(), &StorageBackendConfig::Filesystem)
            .expect("filesystem store");

        assert!(!store.ready());
        store
            .ensure_store_roots(&["objects", "metadata"])
            .expect("create store roots");
        assert!(store.ready());

        assert_eq!(store.read("objects/tenant-a/missing").unwrap(), None);
        assert!(store.create("objects/tenant-a/one.bin", b"alpha").unwrap());
        assert!(!store
            .create("objects/tenant-a/one.bin", b"replacement")
            .unwrap());
        assert_eq!(
            store.read("objects/tenant-a/one.bin").unwrap(),
            Some(b"alpha".to_vec())
        );

        store.write("objects/tenant-a/two.bin", b"beta").unwrap();

        let mut values = store.list_values("objects/tenant-a/").unwrap();
        values.sort();
        assert_eq!(values, vec![b"alpha".to_vec(), b"beta".to_vec()]);

        let mut children = store.list_child_dirs("objects").unwrap();
        children.sort();
        assert_eq!(children, vec!["tenant-a".to_string()]);

        store.delete("objects/tenant-a/one.bin").unwrap();
        assert_eq!(store.read("objects/tenant-a/one.bin").unwrap(), None);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn s3_config_debug_redacts_credentials() {
        let debug = format!("{:?}", StorageBackendConfig::S3(s3_config()));

        assert!(debug.contains("s3.eu-storage.internal"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("access-key-for-test"));
        assert!(!debug.contains("secret-key-for-test"));
    }

    #[test]
    fn s3_store_normalizes_prefix_and_keys() {
        let store = S3ObjectStore::new(&s3_config()).expect("s3 store");

        assert_eq!(
            store.backend_key("objects/tenant/key"),
            "media/objects/tenant/key"
        );
        assert_eq!(
            store.backend_key("/objects/tenant/key/"),
            "media/objects/tenant/key"
        );
        assert_eq!(
            store.strip_backend_prefix("media/objects/tenant/key"),
            "objects/tenant/key"
        );
        assert_eq!(
            store.strip_backend_prefix("/media/objects/tenant/key"),
            "objects/tenant/key"
        );
    }

    #[test]
    fn s3_encoding_matches_sigv4_path_and_query_rules() {
        assert_eq!(
            encode_s3_key_path("a b/plus+slash%"),
            "a%20b/plus%2Bslash%25"
        );
        assert_eq!(
            percent_encode_query("a b/plus+slash%"),
            "a%20b%2Fplus%2Bslash%25"
        );
        assert_eq!(
            canonical_query_string(&[
                ("prefix".to_string(), "media/a b".to_string()),
                ("list-type".to_string(), "2".to_string()),
            ]),
            "list-type=2&prefix=media%2Fa%20b"
        );
    }

    #[test]
    fn s3_list_xml_values_are_unescaped() {
        let body = "<ListBucketResult><Contents><Key>media/a&amp;b.json</Key></Contents><IsTruncated>false</IsTruncated></ListBucketResult>";

        assert_eq!(xml_values(body, "Key"), vec!["media/a&b.json".to_string()]);
        assert_eq!(xml_values(body, "IsTruncated"), vec!["false".to_string()]);
    }
}
