use std::env;
use types::{init_fork_schedule, EthSpec, ForkSchedule, Slot};

pub use case_result::CaseResult;
pub use cases::Case;
pub use cases::{
    EffectiveBalanceUpdates, Eth1DataReset, HistoricalRootsUpdate, JustificationAndFinalization,
    ParticipationRecordUpdates, RandaoMixesReset, RegistryUpdates, RewardsAndPenalties, Slashings,
    SlashingsReset, SyncCommitteeUpdates,
};
pub use error::Error;
pub use handler::*;
pub use type_name::TypeName;

mod bls_setting;
mod case_result;
mod cases;
mod decode;
mod error;
mod handler;
mod results;
mod type_name;

pub fn init_testing_fork_schedule(fork_name: &str) {
    let fork_schedule = if fork_name == "phase0" {
        ForkSchedule {
            altair_fork_slot: None,
        }
    } else if fork_name == "altair" {
        ForkSchedule {
            altair_fork_slot: Some(Slot::new(0)),
        }
    } else {
        panic!("unknown fork: {}", fork_name);
    };
    init_fork_schedule(fork_schedule);
}

pub fn get_fork_name() -> String {
    env::var("FORK_NAME").expect("FORK_NAME must be set")
}
