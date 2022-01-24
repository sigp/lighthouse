use crate::config::*;
use crate::process::SimProcess;
use eth2::lighthouse_vc::http_client::ValidatorClientHttpClient;
use eth2::types::{Epoch, EthSpec, EthSpecId, MainnetEthSpec, MinimalEthSpec};
use slot_clock::{SlotClock, SystemTimeSlotClock};
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;

pub struct Testnet {
    pub ganache: SimProcess,
    pub bootnode: SimProcess,
    pub beacon_nodes: Vec<SimProcess>,
    pub validator_clients: Vec<TestnetValidatorClient>,
    pub delayed_start_configs: Vec<Config>,
    pub slot_clock: SystemTimeSlotClock,
    pub global_config: GlobalTomlConfig,
    pub lighthouse_bin_location: PathBuf,
}

pub struct TestnetValidatorClient {
    pub process: SimProcess,
    pub config: Config,
    pub http_client: ValidatorClientHttpClient,
}

impl Testnet {
    pub fn wait_epochs(self, epochs: Epoch) -> Self {
        let spec = EthSpecId::from_str(self.global_config.spec.as_str().unwrap()).unwrap();
        let slots_per_epoch = match spec {
            EthSpecId::Mainnet => MainnetEthSpec::slots_per_epoch(),
            EthSpecId::Minimal => MinimalEthSpec::slots_per_epoch(),
        };

        thread::sleep(
            self.slot_clock.slot_duration() * slots_per_epoch as u32 * epochs.as_u64() as u32,
        );
        self
    }

    pub fn add_validator(mut self) -> Self {
        self.add_validator_with_config(|_| {})
    }

    pub fn add_validator_with_config<F: Fn(&mut Config)>(mut self, f: F) -> Self {
        let mut config = self.delayed_start_configs.pop().unwrap();
        f(&mut config);
        self.validator_clients.push(
            crate::config::spawn_validator(&self.lighthouse_bin_location, config)
                .expect("unable to spawn validator"),
        );
        self
    }
}
