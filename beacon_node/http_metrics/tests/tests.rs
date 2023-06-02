use beacon_chain::test_utils::EphemeralHarnessType;
use environment::null_logger;
use http_metrics::Config;
use reqwest::header::HeaderValue;
use reqwest::StatusCode;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::oneshot;
use types::MainnetEthSpec;

type Context = http_metrics::Context<EphemeralHarnessType<MainnetEthSpec>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn returns_200_ok() {
    async {
        let log = null_logger().unwrap();

        let context = Arc::new(Context {
            config: Config {
                enabled: true,
                listen_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                listen_port: 0,
                allow_origin: None,
                allocator_metrics_enabled: true,
            },
            chain: None,
            db_path: None,
            freezer_db_path: None,
            gossipsub_registry: None,
            log,
        });

        let ctx = context.clone();
        let (_shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let server_shutdown = async {
            // It's not really interesting why this triggered, just that it happened.
            let _ = shutdown_rx.await;
        };
        let (listening_socket, server) = http_metrics::serve(ctx, server_shutdown).unwrap();

        tokio::spawn(server);

        let url = format!(
            "http://{}:{}/metrics",
            listening_socket.ip(),
            listening_socket.port()
        );

        let response = reqwest::get(&url).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            &HeaderValue::from_str("text/plain").unwrap()
        );
    }
    .await
}
