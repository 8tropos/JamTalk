use jam_messenger::{web_api, ServiceState};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let addr: SocketAddr = std::env::var("JAMTALK_API_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:8080".parse().expect("default addr"));

    let state = web_api::AppState::new(ServiceState::default());

    println!("JamTalk API listening on http://{}", addr);
    web_api::run_http_server(addr, state).await;
}
