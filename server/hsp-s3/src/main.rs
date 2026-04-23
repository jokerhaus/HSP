use std::env;
use std::path::PathBuf;

use hsp_crypto::AwsKmsProviderConfig;
use hsp_distribution::SigV4AccessKeyRecord;
use hsp_s3::{run_s3_server, S3ServerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bind_addr = env::var("HSP_S3_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8081".to_string())
        .parse()?;
    let root_dir =
        PathBuf::from(env::var("HSP_ROOT_DIR").unwrap_or_else(|_| "./.hsp-data".to_string()));
    let issuer_registry_path = PathBuf::from(
        env::var("HSP_ISSUER_REGISTRY")
            .unwrap_or_else(|_| "./deploy/issuer-registry.dev.json".to_string()),
    );
    let namespace_signing_seed = env::var("HSP_DISTRIBUTION_SIGNING_SEED")
        .ok()
        .and_then(|value| parse_hex_32(&value))
        .unwrap_or([21u8; 32]);
    let sigv4_access_keys = env::var("HSP_SIGV4_ACCESS_KEYS")
        .ok()
        .map(std::fs::read)
        .transpose()?
        .map(|bytes| serde_json::from_slice::<Vec<SigV4AccessKeyRecord>>(&bytes))
        .transpose()?
        .unwrap_or_default();

    run_s3_server(S3ServerConfig {
        bind_addr,
        authority: env::var("HSP_AUTHORITY").unwrap_or_else(|_| "localhost".to_string()),
        gateway_base_url: env::var("HSP_GATEWAY_BASE_URL")
            .unwrap_or_else(|_| "https://localhost".to_string()),
        root_dir,
        server_instance_id: env::var("HSP_SERVER_INSTANCE_ID")
            .unwrap_or_else(|_| "hsp-s3-dev".to_string()),
        capability_audience: env::var("HSP_CAPABILITY_AUDIENCE")
            .unwrap_or_else(|_| "hsp-s3".to_string()),
        immutable_cid_ttl_sec: env::var("HSP_IMMUTABLE_CID_TTL_SEC")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(3600),
        namespace_ttl_sec: env::var("HSP_NAMESPACE_TTL_SEC")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(5),
        issuer_registry_path,
        namespace_signing_seed,
        namespace_signing_key_id: env::var("HSP_DISTRIBUTION_SIGNING_KEY_ID")
            .unwrap_or_else(|_| "dist-key".to_string()),
        edge_signing_secret: env::var("HSP_EDGE_SIGNING_SECRET")
            .unwrap_or_else(|_| "edge-secret".to_string())
            .into_bytes(),
        kms_seed: env::var("HSP_KMS_SEED")
            .unwrap_or_else(|_| "hsp-s3-runtime-seed".to_string())
            .into_bytes(),
        aws_kms: aws_kms_config_from_env(),
        virtual_host_suffix: env::var("HSP_S3_VHOST_SUFFIX").ok(),
        sigv4_access_keys,
    })
    .await
}

fn parse_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

fn aws_kms_config_from_env() -> Option<AwsKmsProviderConfig> {
    let key_alias = env::var("HSP_AWS_KMS_KEY_ALIAS").ok()?;
    let region = env::var("HSP_AWS_KMS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
    let workload_identity_required = env::var("HSP_AWS_WORKLOAD_IDENTITY_REQUIRED")
        .ok()
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(true);
    Some(AwsKmsProviderConfig {
        key_alias,
        region,
        workload_identity_required,
    })
}
