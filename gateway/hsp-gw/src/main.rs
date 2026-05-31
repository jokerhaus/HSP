use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;

use hsp_crypto::{required_runtime_secret_from_env, DEFAULT_KMS_SEED_LITERALS};
use hsp_gw::spawn_gateway_beta_server;
use hsp_service::default_alpha_service;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let root = env::var("HSP_ALPHA_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(".hsp-alpha"));
    let command = env::args()
        .nth(1)
        .unwrap_or_else(|| "bootstrap".to_string());

    let service = default_alpha_service(root)?;

    match command.as_str() {
        "serve" => {
            let bind_addr = env::var("HSP_GW_BIND_ADDR")
                .ok()
                .and_then(|value| value.parse::<SocketAddr>().ok())
                .unwrap_or_else(|| {
                    "127.0.0.1:9444"
                        .parse()
                        .expect("invalid default gateway bind")
                });
            let authority = env::var("HSP_AUTHORITY").unwrap_or_else(|_| "localhost".to_string());
            let gateway_base_url = env::var("HSP_GATEWAY_BASE_URL")
                .unwrap_or_else(|_| "https://localhost/v1/".to_string());
            let issuer_registry_path = env::var("HSP_ISSUER_REGISTRY")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(".hsp-alpha/issuer-registry.json"));
            let server_instance_id = env::var("HSP_SERVER_INSTANCE_ID")
                .unwrap_or_else(|_| "hsp-gateway-beta".to_string());
            let native_port = env::var("HSP_NATIVE_PORT")
                .ok()
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(9443);
            let kms_seed =
                required_runtime_secret_from_env("HSP_KMS_SEED", DEFAULT_KMS_SEED_LITERALS)?;

            let handle = spawn_gateway_beta_server(hsp_gw::GatewayBetaConfig {
                bind_addr,
                authority,
                gateway_base_url,
                root_dir: env::var("HSP_ALPHA_ROOT")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from(".hsp-alpha")),
                issuer_registry_path,
                server_instance_id,
                native_port,
                kms_seed,
            })
            .await?;
            println!("{{\"bind_addr\":\"{}\"}}", handle.local_addr);
            std::future::pending::<()>().await;
        }
        "info" => println!(
            "{}",
            serde_json::to_string_pretty(&service.info())
                .expect("failed to serialize info response")
        ),
        "readiness" => println!(
            "{}",
            serde_json::to_string_pretty(&service.readiness())
                .expect("failed to serialize readiness report")
        ),
        _ => println!(
            "{}",
            serde_json::to_string_pretty(&service.bootstrap_document())
                .expect("failed to serialize bootstrap document")
        ),
    }
    Ok(())
}
