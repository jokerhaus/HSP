use std::env;
use std::path::PathBuf;

use hsp_cdn::{run_cdn_server, CdnServerConfig};
use hsp_crypto::AwsKmsProviderConfig;
use hsp_crypto::{
    required_runtime_secret_from_env, DEFAULT_EDGE_SIGNING_SECRET_LITERALS,
    DEFAULT_KMS_SEED_LITERALS,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bind_addr = env::var("HSP_CDN_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8082".to_string())
        .parse()?;
    let root_dir =
        PathBuf::from(env::var("HSP_ROOT_DIR").unwrap_or_else(|_| "./.hsp-data".to_string()));
    let issuer_registry_path = PathBuf::from(
        env::var("HSP_ISSUER_REGISTRY")
            .unwrap_or_else(|_| "./deploy/issuer-registry.dev.json".to_string()),
    );
    let namespace_signing_seed = parse_hex_32(
        &env::var("HSP_DISTRIBUTION_SIGNING_SEED")
            .map_err(|_| "HSP_DISTRIBUTION_SIGNING_SEED must be configured explicitly")?,
    )
    .ok_or("HSP_DISTRIBUTION_SIGNING_SEED must be a 64-character hex string")?;

    run_cdn_server(CdnServerConfig {
        bind_addr,
        authority: env::var("HSP_AUTHORITY").unwrap_or_else(|_| "localhost".to_string()),
        gateway_base_url: env::var("HSP_GATEWAY_BASE_URL")
            .unwrap_or_else(|_| "https://localhost".to_string()),
        root_dir,
        server_instance_id: env::var("HSP_SERVER_INSTANCE_ID")
            .unwrap_or_else(|_| "hsp-cdn-dev".to_string()),
        capability_audience: env::var("HSP_CAPABILITY_AUDIENCE")
            .unwrap_or_else(|_| "hsp-cdn".to_string()),
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
        edge_signing_secret: required_runtime_secret_from_env(
            "HSP_EDGE_SIGNING_SECRET",
            DEFAULT_EDGE_SIGNING_SECRET_LITERALS,
        )?,
        kms_seed: required_runtime_secret_from_env("HSP_KMS_SEED", DEFAULT_KMS_SEED_LITERALS)?,
        aws_kms: aws_kms_config_from_env(),
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

#[cfg(test)]
mod tests {
    use hsp_crypto::CryptoError;

    #[test]
    fn cdn_runtime_secrets_reject_legacy_defaults() {
        assert_eq!(
            hsp_crypto::validate_runtime_secret(
                "HSP_EDGE_SIGNING_SECRET",
                "edge-secret",
                hsp_crypto::DEFAULT_EDGE_SIGNING_SECRET_LITERALS,
            )
            .unwrap_err(),
            CryptoError::WeakRuntimeSecret("HSP_EDGE_SIGNING_SECRET")
        );
        assert_eq!(
            hsp_crypto::validate_runtime_secret(
                "HSP_KMS_SEED",
                "hsp-cdn-runtime-seed",
                hsp_crypto::DEFAULT_KMS_SEED_LITERALS,
            )
            .unwrap_err(),
            CryptoError::WeakRuntimeSecret("HSP_KMS_SEED")
        );
    }
}
