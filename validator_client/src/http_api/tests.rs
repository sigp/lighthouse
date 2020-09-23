#![cfg(test)]

use crate::{
    http_api::{Config, Context},
    InitializedValidators, ValidatorDefinitions,
};
use environment::null_logger;
use eth2::{types::*, BeaconNodeHttpClient, Url};
use parking_lot::RwLock;
use std::convert::TryInto;
use std::marker::PhantomData;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tree_hash::TreeHash;
use types::{
    test_utils::generate_deterministic_keypairs, AggregateSignature, BeaconState, BitList, Domain,
    EthSpec, Hash256, Keypair, MainnetEthSpec, RelativeEpoch, SelectionProof, SignedRoot, Slot,
};

type E = MainnetEthSpec;

struct ApiTester {
    datadir: TempDir,
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

        let client = BeaconNodeHttpClient::new(
            Url::parse(&format!(
                "http://{}:{}",
                listening_socket.ip(),
                listening_socket.port()
            ))
            .unwrap(),
        );

        Self {
            datadir,
            _server_shutdown: shutdown_tx,
        }
    }
}
