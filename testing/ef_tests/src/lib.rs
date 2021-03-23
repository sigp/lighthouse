use types::{init_fork_schedule, ChainSpec, EthSpec, ForkSchedule};

pub use case_result::CaseResult;
pub use cases::Case;
pub use cases::{
    FinalUpdates, JustificationAndFinalization, RegistryUpdates, RewardsAndPenalties, Slashings,
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

pub fn init_testing_fork_schedule(spec: &ChainSpec) {
    init_fork_schedule(ForkSchedule {
        altair_fork_slot: spec.altair_fork_slot,
        altair_fork_version: spec.altair_fork_version,
    });
}
