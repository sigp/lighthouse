pub use case_result::CaseResult;
pub use cases::{
    Case, EffectiveBalanceUpdates, Eth1DataReset, HistoricalRootsUpdate, InactivityUpdates,
    JustificationAndFinalization, ParticipationFlagUpdates, ParticipationRecordUpdates,
    RandaoMixesReset, RegistryUpdates, RewardsAndPenalties, Slashings, SlashingsReset,
    SyncCommitteeUpdates, WithdrawalsPayload,
};
pub use decode::log_file_access;
pub use error::Error;
pub use handler::*;
pub use type_name::TypeName;
use types::{ChainSpec, EthSpec, ForkName};

mod bls_setting;
mod case_result;
mod cases;
mod decode;
mod error;
mod handler;
mod results;
mod type_name;

pub fn testing_spec<E: EthSpec>(fork_name: ForkName) -> ChainSpec {
    fork_name.make_genesis_spec(E::default_spec())
}
