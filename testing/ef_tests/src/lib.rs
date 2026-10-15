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
    without_eip8198(fork_name.make_genesis_spec(E::default_spec()))
}

/// Keeps the slot duration at Heze. Lighthouse activates EIP-8198 at Heze, but the upstream Heze
/// tests do not include it.
pub fn without_eip8198(mut spec: ChainSpec) -> ChainSpec {
    spec.slot_duration_ms_eip8198 = spec.genesis_slot_duration().as_millis() as u64;
    spec
}
