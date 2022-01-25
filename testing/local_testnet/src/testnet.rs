use crate::config::*;
use crate::process::TestnetProcess;
use eth2::lighthouse_vc::http_client::ValidatorClientHttpClient;
use eth2::types::{Epoch, EthSpec, EthSpecId, MainnetEthSpec, MinimalEthSpec};
use slot_clock::{SlotClock, SystemTimeSlotClock};
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
    pub beacon_nodes: Vec<TestnetProcess>,
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

impl Testnet {
    pub fn wait_epochs(self, epochs: Epoch) -> Result<Self, TestnetError> {
        let spec = EthSpecId::from_str(
            self.global_config
                .spec
                .as_str()
                .ok_or(TestnetError::MissingSpec)?,
        )
        .map_err(TestnetError::InvalidSpec)?;
        let slots_per_epoch = match spec {
            EthSpecId::Mainnet => MainnetEthSpec::slots_per_epoch(),
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
}
