#![cfg(all(feature = "ef_tests", feature = "spec-minimal"))]
mod pq_support;
use ef_tests::*;
use types::*;
type Spec = MinimalEthSpec;
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn operations_attestation() {
    pq_support::run_handler(OperationsHandler::<Spec, Attestation<Spec>>::default());
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn operations_attester_slashing() {
    pq_support::run_handler(OperationsHandler::<Spec, AttesterSlashing<Spec>>::default());
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn operations_block_header() {
    pq_support::run_handler(OperationsHandler::<Spec, BeaconBlock<Spec>>::default());
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn operations_builder_deposit_request() {
    pq_support::run_handler(OperationsHandler::<Spec, BuilderDepositRequest>::default());
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn operations_builder_exit_request() {
    pq_support::run_handler(OperationsHandler::<Spec, BuilderExitRequest>::default());
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn operations_consolidation_request() {
    pq_support::run_handler(OperationsHandler::<Spec, ConsolidationRequest>::default());
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn operations_deposit_request() {
    pq_support::run_handler(OperationsHandler::<Spec, DepositRequest>::default());
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn operations_execution_payload_bid() {
    pq_support::run_handler(OperationsHandler::<Spec, ExecutionPayloadBidBlock<Spec>>::default());
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn operations_parent_execution_payload() {
    pq_support::run_handler(
        OperationsHandler::<Spec, ParentExecutionPayloadBlock<Spec>>::default(),
    );
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn operations_proposer_slashing() {
    pq_support::run_handler(OperationsHandler::<Spec, ProposerSlashingPq>::default());
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn operations_withdrawal_request() {
    pq_support::run_handler(OperationsHandler::<Spec, WithdrawalRequest>::default());
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn operations_withdrawals() {
    pq_support::run_handler(OperationsHandler::<Spec, WithdrawalsPayload<Spec>>::default());
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn epoch_builder_pending_payments() {
    pq_support::run_handler_as(
        EpochProcessingHandler::<Spec, BuilderPendingPayments>::default(),
        "epoch_processing",
        "builder_pending_payments",
    );
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn epoch_effective_balance_updates() {
    pq_support::run_handler_as(
        EpochProcessingHandler::<Spec, EffectiveBalanceUpdates>::default(),
        "epoch_processing",
        "effective_balance_updates",
    );
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn epoch_historical_summaries_update() {
    pq_support::run_handler_as(
        EpochProcessingHandler::<Spec, HistoricalSummariesUpdate>::default(),
        "epoch_processing",
        "historical_summaries_update",
    );
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn epoch_inactivity_updates() {
    pq_support::run_handler_as(
        EpochProcessingHandler::<Spec, InactivityUpdates>::default(),
        "epoch_processing",
        "inactivity_updates",
    );
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn epoch_justification_and_finalization() {
    pq_support::run_handler_as(
        EpochProcessingHandler::<Spec, JustificationAndFinalization>::default(),
        "epoch_processing",
        "justification_and_finalization",
    );
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn epoch_participation_flag_updates() {
    pq_support::run_handler_as(
        EpochProcessingHandler::<Spec, ParticipationFlagUpdates>::default(),
        "epoch_processing",
        "participation_flag_updates",
    );
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn epoch_pending_consolidations() {
    pq_support::run_handler_as(
        EpochProcessingHandler::<Spec, PendingConsolidations>::default(),
        "epoch_processing",
        "pending_consolidations",
    );
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn epoch_pending_deposits() {
    pq_support::run_handler_as(
        EpochProcessingHandler::<Spec, PendingBalanceDeposits>::default(),
        "epoch_processing",
        "pending_deposits",
    );
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn epoch_pending_deposits_churn() {
    pq_support::run_handler_as(
        EpochProcessingHandler::<Spec, PendingDepositsChurn>::default(),
        "epoch_processing",
        "pending_deposits_churn",
    );
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn epoch_proposer_lookahead() {
    pq_support::run_handler_as(
        EpochProcessingHandler::<Spec, ProposerLookahead>::default(),
        "epoch_processing",
        "proposer_lookahead",
    );
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn epoch_ptc_window() {
    pq_support::run_handler_as(
        EpochProcessingHandler::<Spec, PtcWindow>::default(),
        "epoch_processing",
        "ptc_window",
    );
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn epoch_randao_mixes_reset() {
    pq_support::run_handler_as(
        EpochProcessingHandler::<Spec, RandaoMixesReset>::default(),
        "epoch_processing",
        "randao_mixes_reset",
    );
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn epoch_registry_updates() {
    pq_support::run_handler_as(
        EpochProcessingHandler::<Spec, RegistryUpdates>::default(),
        "epoch_processing",
        "registry_updates",
    );
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn epoch_rewards_and_penalties() {
    pq_support::run_handler_as(
        EpochProcessingHandler::<Spec, RewardsAndPenalties>::default(),
        "epoch_processing",
        "rewards_and_penalties",
    );
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn epoch_slashings() {
    pq_support::run_handler_as(
        EpochProcessingHandler::<Spec, Slashings>::default(),
        "epoch_processing",
        "slashings",
    );
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn epoch_slashings_reset() {
    pq_support::run_handler_as(
        EpochProcessingHandler::<Spec, SlashingsReset>::default(),
        "epoch_processing",
        "slashings_reset",
    );
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn sanity_blocks() {
    pq_support::run_handler(SanityBlocksHandler::<Spec>::default());
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn sanity_slots() {
    pq_support::run_handler(SanitySlotsHandler::<Spec>::default());
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn random() {
    pq_support::run_handler(RandomHandler::<Spec>::default());
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn finality() {
    pq_support::run_handler(FinalityHandler::<Spec>::default());
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn fork() {
    pq_support::run_handler(ForkHandler::<Spec>::default());
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn rewards_basic() {
    pq_support::run_handler(RewardsHandler::<Spec>::new("basic"));
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn rewards_inactivity_scores() {
    pq_support::run_handler(RewardsHandler::<Spec>::new("inactivity_scores"));
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn rewards_leak() {
    pq_support::run_handler(RewardsHandler::<Spec>::new("leak"));
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn rewards_random() {
    pq_support::run_handler(RewardsHandler::<Spec>::new("random"));
}

#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn epoch_aggregation_committee_window() {
    pq_support::run_handler(EpochProcessingHandler::<
        Spec,
        ef_tests::AggregationCommitteeWindow,
    >::default());
}
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn epoch_preregistration_expiry() {
    pq_support::run_handler(EpochProcessingHandler::<Spec, PreregistrationExpiry>::default());
}

#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn operations_randao() {
    pq_support::run_handler(OperationsHandler::<Spec, RandaoBody<Spec>>::default());
}

#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn unsupported_execution_requests() {
    for name in [
        "validator_preregistration_request",
        "builder_preregistration_request",
        "voluntary_exit_request",
    ] {
        pq_support::unsupported_handler(
            "operations",
            name,
            "The devnet client explicitly rejects this request type in apply_parent_execution_payload_pq; no standalone transition is implemented.",
        );
    }
}
