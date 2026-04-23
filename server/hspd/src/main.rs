use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use hsp_service::default_alpha_service;
use hspd::spawn_native_beta_server;

#[tokio::main]
async fn main() {
    let root = env::var("HSP_ALPHA_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(".hsp-alpha"));
    let command = env::args().nth(1).unwrap_or_else(|| "info".to_string());

    let service = default_alpha_service(root).expect("failed to initialize secure alpha service");

    match command.as_str() {
        "serve" => {
            let bind_addr = env::var("HSP_BIND_ADDR")
                .ok()
                .and_then(|value| value.parse::<SocketAddr>().ok())
                .unwrap_or_else(|| {
                    "127.0.0.1:9443"
                        .parse()
                        .expect("invalid default bind address")
                });
            let authority = env::var("HSP_AUTHORITY").unwrap_or_else(|_| "localhost".to_string());
            let gateway_base_url = env::var("HSP_GATEWAY_BASE_URL")
                .unwrap_or_else(|_| "https://localhost/v1/".to_string());
            let issuer_registry_path = env::var("HSP_ISSUER_REGISTRY")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(".hsp-alpha/issuer-registry.json"));
            let server_instance_id = env::var("HSP_SERVER_INSTANCE_ID")
                .unwrap_or_else(|_| "hsp-native-beta".to_string());

            let handle = spawn_native_beta_server(hspd::NativeBetaConfig {
                bind_addr,
                authority,
                gateway_base_url,
                root_dir: env::var("HSP_ALPHA_ROOT")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from(".hsp-alpha")),
                issuer_registry_path,
                server_instance_id,
            })
            .await
            .expect("failed to start native beta server");
            println!("{{\"bind_addr\":\"{}\"}}", handle.local_addr);
            std::future::pending::<()>().await;
        }
        "bootstrap" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&service.bootstrap_document())
                    .expect("failed to serialize bootstrap document")
            );
        }
        "readiness" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&service.readiness())
                    .expect("failed to serialize readiness report")
            );
        }
        _ => {
            println!(
                "{}",
                serde_json::to_string_pretty(&service.info())
                    .expect("failed to serialize info response")
            );
        }
    }
}
