pub use case_result::CaseResult;
pub use cases::{
    BuilderPendingPayments, Case, EffectiveBalanceUpdates, Eth1DataReset, ExecutionPayloadBidBlock,
    FeatureName, HistoricalRootsUpdate, HistoricalSummariesUpdate, InactivityUpdates,
    JustificationAndFinalization, ParentExecutionPayloadBlock, ParticipationFlagUpdates,
    ParticipationRecordUpdates, PendingBalanceDeposits, PendingConsolidations,
    PendingDepositsChurn, ProposerLookahead, PtcWindow, RandaoMixesReset, RegistryUpdates,
    RewardsAndPenalties, Slashings, SlashingsReset, SyncCommitteeUpdates, VoluntaryExitChurn,
    WithdrawalsPayload,
};
pub use decode::log_file_access;
pub use error::Error;
pub use handler::*;
pub use type_name::TypeName;
use types::{ChainSpec, ForkName, Spec};

mod bls_setting;
mod case_result;
mod cases;
mod decode;
mod error;
mod handler;
mod results;
mod type_name;

pub fn testing_spec(fork_name: ForkName) -> ChainSpec {
    fork_name.make_genesis_spec(Spec::default_spec())
}
