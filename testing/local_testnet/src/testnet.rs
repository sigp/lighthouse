use crate::config::ConfigError::TomlDeserialize;
use crate::config::*;
use crate::process::TestnetProcess;
use clap_utils::TomlValue;
use eth2::lighthouse_vc::http_client::ValidatorClientHttpClient;
use eth2::types::{Epoch, EthSpec, EthSpecId, GnosisEthSpec, MainnetEthSpec, MinimalEthSpec};
use eth2::BeaconNodeHttpClient;
use slot_clock::{SlotClock, SystemTimeSlotClock};
use std::future::Future;
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;

#[derive(thiserror::Error, Debug)]
pub enum TestnetError {
    #[error("eth spec config required")]
    MissingSpec,
    #[error("unable to parse eth spec: {0}")]
    InvalidSpec(String),
    #[error("missing config for delayed start validator")]
    NoDelayedStartValidators,
    #[error("config error")]
    Config(#[from] ConfigError),
}

pub struct Testnet {
    pub ganache: TestnetProcess,
    pub bootnode: TestnetProcess,
    pub beacon_nodes: Vec<TestnetBeaconNode>,
    pub validator_clients: Vec<TestnetValidatorClient>,
    pub delayed_start_configs: Vec<Config>,
    pub slot_clock: SystemTimeSlotClock,
    pub global_config: GlobalTomlConfig,
    pub lighthouse_bin_location: PathBuf,
}

pub struct TestnetValidatorClient {
    pub process: TestnetProcess,
    pub config: Config,
    pub http_client: ValidatorClientHttpClient,
}

pub struct TestnetBeaconNode {
    pub process: TestnetProcess,
    pub config: Config,
    pub http_client: BeaconNodeHttpClient,
}

impl Testnet {
    pub fn wait_epochs(self, epochs: Epoch) -> Result<Self, TestnetError> {
        let spec = EthSpecId::from_str(
            self.global_config
                .spec
                .as_ref()
                .map(TomlValue::as_str)
                .flatten()
                .ok_or(TestnetError::MissingSpec)?,
        )
        .map_err(TestnetError::InvalidSpec)?;
        let slots_per_epoch = match spec {
            EthSpecId::Mainnet => MainnetEthSpec::slots_per_epoch(),
            EthSpecId::Gnosis => GnosisEthSpec::slots_per_epoch(),
            EthSpecId::Minimal => MinimalEthSpec::slots_per_epoch(),
        };

        thread::sleep(
            self.slot_clock.slot_duration() * slots_per_epoch as u32 * epochs.as_u64() as u32,
        );
        Ok(self)
    }

    pub fn add_validator(self) -> Result<Self, TestnetError> {
        self.add_validator_with_config(|_| {})
    }

    pub fn add_validator_with_config<F: Fn(&mut Config)>(
        mut self,
        f: F,
    ) -> Result<Self, TestnetError> {
        let mut config = self
            .delayed_start_configs
            .pop()
            .ok_or(TestnetError::NoDelayedStartValidators)?;
        f(&mut config);
        self.validator_clients.push(crate::config::spawn_validator(
            &self.lighthouse_bin_location,
            config,
        )?);
        Ok(self)
    }

    pub async fn check_all_active(self) -> Self {
        self.check_beacon_nodes(|node| async move {
            assert!(node.get_lighthouse_health().await.is_ok());
        })
        .await
        .check_validator_clients(|i, node| async move {
            dbg!(node.get_lighthouse_health().await.unwrap().data);
            assert!(node.get_lighthouse_health().await.is_ok());
        })
        .await
    }

    pub async fn check_beacon_nodes<F, T>(self, f: F) -> Self
    where
        F: Fn(BeaconNodeHttpClient) -> T,
        T: Future<Output = ()>,
    {
        for node in self.beacon_nodes.iter() {
            f(node.http_client.clone()).await;
        }
        self
    }

    pub async fn check_validator_clients<F, T>(self, f: F) -> Self
    where
        F: Fn(usize, ValidatorClientHttpClient) -> T,
        T: Future<Output = ()>,
    {
        for (i, node) in self.validator_clients.iter().enumerate() {
            f(i, node.http_client.clone()).await;
        }
        self
    }
}
