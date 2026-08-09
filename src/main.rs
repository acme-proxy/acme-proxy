//! ACME Proxy Binary Entrypoint

#[tokio::main]
async fn main() {
    acme_proxy::cli::run().await;
}
