#![cfg(test)]

use crate::{
    http_api::{Config, Context},
    InitializedValidators, ValidatorDefinitions,
};
use environment::null_logger;
use eth2::{
    lighthouse_vc::{http_client::ValidatorClientHttpClient, types::*},
    Url,
};
use parking_lot::RwLock;
use std::marker::PhantomData;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};
use tokio::sync::oneshot;

type E = MainnetEthSpec;

struct ApiTester {
    datadir: TempDir,
    client: ValidatorClientHttpClient,
    _server_shutdown: oneshot::Sender<()>,
}

impl ApiTester {
    pub async fn new() -> Self {
        let log = null_logger().unwrap();

        let datadir = tempdir().unwrap();

        let validator_defs = ValidatorDefinitions::open_or_create(datadir.path()).unwrap();

        let initialized_validators = InitializedValidators::from_definitions(
            validator_defs,
            datadir.path().into(),
            false,
            log.clone(),
        )
        .await
        .unwrap();

        let context: Arc<Context<E>> = Arc::new(Context {
            initialized_validators: Some(Arc::new(RwLock::new(initialized_validators))),
            config: Config {
                enabled: true,
                listen_addr: Ipv4Addr::new(127, 0, 0, 1),
                listen_port: 0,
                allow_origin: None,
            },
            log,
            _phantom: PhantomData,
        });
        let ctx = context.clone();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_shutdown = async {
            // It's not really interesting why this triggered, just that it happened.
            let _ = shutdown_rx.await;
        };
        let (listening_socket, server) = super::serve(ctx, server_shutdown).unwrap();

        tokio::spawn(async { server.await });

        let client = ValidatorClientHttpClient::new(
            Url::parse(&format!(
                "http://{}:{}",
                listening_socket.ip(),
                listening_socket.port()
            ))
            .unwrap(),
        );

        Self {
            datadir,
            client,
            _server_shutdown: shutdown_tx,
        }
    }

    pub async fn test_get_lighthouse_version(self) -> Self {
        let result = self.client.get_lighthouse_version().await.unwrap().data;

        let expected = VersionData {
            version: lighthouse_version::version_with_platform(),
        };

        assert_eq!(result, expected);

        self
    }

    #[cfg(target_os = "linux")]
    pub async fn test_get_lighthouse_health(self) -> Self {
        self.client.get_lighthouse_health().await.unwrap();

        self
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn test_get_lighthouse_health(self) -> Self {
        self.client.get_lighthouse_health().await.unwrap_err();

        self
    }
}

#[tokio::test(core_threads = 2)]
async fn simple_getters() {
    ApiTester::new()
        .await
        .test_get_lighthouse_version()
        .await
        .test_get_lighthouse_health()
        .await;
}
