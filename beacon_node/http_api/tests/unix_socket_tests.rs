//! Tests for serving the beacon HTTP API over a Unix domain socket (`--http-unix-socket`).

use beacon_chain::test_utils::BeaconChainHarness;
use http_api::{
    Config,
    test_utils::{ApiServer, create_api_server_with_config},
};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use types::MainnetEthSpec;

type E = MainnetEthSpec;

const VALIDATOR_COUNT: usize = 8;

/// A unique socket path under the temp dir, so parallel test binaries don't collide and we stay
/// well under the platform's socket path length limit.
fn unique_socket_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("lh-http-api-{}-{nanos}.sock", std::process::id()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_the_api_over_a_unix_socket() {
    let harness = BeaconChainHarness::builder(E::default())
        .spec_or_default(None)
        .mock_execution_layer()
        .deterministic_keypairs(VALIDATOR_COUNT)
        .fresh_ephemeral_store()
        .build();

    let socket_path = unique_socket_path();
    let config = Config {
        unix_socket: Some(socket_path.clone()),
        ..Config::default()
    };

    let ApiServer {
        server,
        listening_socket,
        ..
    } = create_api_server_with_config(harness.chain.clone(), config, &harness.runtime).await;

    // No TCP socket is allocated when serving over a Unix domain socket.
    assert!(
        listening_socket.is_none(),
        "a Unix-socket server must not report a TCP `SocketAddr`"
    );

    harness
        .runtime
        .task_executor
        .spawn(server, "api_server_unix_socket");

    // The socket file should exist once the listener is bound.
    assert!(
        socket_path.exists(),
        "socket file should be created at {}",
        socket_path.display()
    );

    // Send a minimal HTTP/1.1 request over the socket and assert a successful response from a
    // real route.
    let mut stream = UnixStream::connect(&socket_path)
        .await
        .expect("should connect to the API unix socket");
    stream
        .write_all(
            b"GET /eth/v1/node/version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("should write request to the socket");

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("should read response from the socket");
    let response = String::from_utf8_lossy(&response);

    assert!(
        response.starts_with("HTTP/1.1 200 "),
        "expected a 200 response, got: {response}"
    );
    // The `Server` header and the `/version` body both carry the Lighthouse identifier.
    assert!(
        response.contains("Lighthouse"),
        "response should identify Lighthouse: {response}"
    );

    // Clean up the socket file (the server also removes it on graceful shutdown).
    let _ = std::fs::remove_file(&socket_path);
}
