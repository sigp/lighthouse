#![cfg(feature = "ef_tests")]

use ef_tests::*;
use types::*;

// Check that the hand-computed multiplications on Spec are correctly computed.
// This test lives here because one is most likely to muck these up during a spec update.
fn check_typenum_values() {
    assert_eq!(
        Spec::MAX_PENDING_ATTESTATIONS,
        Spec::MAX_ATTESTATIONS * Spec::SLOTS_PER_EPOCH
    );
    assert_eq!(
        Spec::SLOTS_PER_ETH1_VOTING_PERIOD,
        Spec::EPOCHS_PER_ETH1_VOTING_PERIOD * Spec::SLOTS_PER_EPOCH
    );
    assert_eq!(
        Spec::MAX_VALIDATORS_PER_SLOT,
        Spec::MAX_COMMITTEES_PER_SLOT * Spec::MAX_VALIDATORS_PER_COMMITTEE
    );
}

#[test]
fn derived_typenum_values() {
    check_typenum_values();
}

#[test]
fn shuffling() {
    ShufflingHandler::default().run();
}

#[test]
fn operations_deposit() {
    OperationsHandler::<Deposit>::default().run();
}

#[test]
fn operations_exit() {
    OperationsHandler::<SignedVoluntaryExit>::default().run();
}

#[test]
fn operations_proposer_slashing() {
    OperationsHandler::<ProposerSlashing>::default().run();
}

#[test]
fn operations_attester_slashing() {
    OperationsHandler::<AttesterSlashing>::default().run();
}

#[test]
fn operations_attestation() {
    OperationsHandler::<Attestation>::default().run();
}

#[test]
fn operations_block_header() {
    OperationsHandler::<BeaconBlock>::default().run();
}

#[test]
fn operations_sync_aggregate() {
    OperationsHandler::<SyncAggregate>::default().run();
}

#[test]
fn operations_execution_payload_full() {
    OperationsHandler::<BeaconBlockBody<FullPayload>>::default().run();
}

#[test]
fn operations_execution_payload_blinded() {
    OperationsHandler::<BeaconBlockBody<BlindedPayload>>::default().run();
}

#[test]
fn operations_execution_payload_envelope() {
    OperationsHandler::<SignedExecutionPayloadEnvelope>::default().run();
}

#[test]
fn operations_execution_payload_bid() {
    OperationsHandler::<ExecutionPayloadBidBlock>::default().run();
}

#[test]
fn operations_parent_execution_payload() {
    OperationsHandler::<ParentExecutionPayloadBlock>::default().run();
}

#[test]
fn operations_payload_attestation() {
    OperationsHandler::<PayloadAttestation>::default().run();
}

#[test]
fn operations_withdrawals() {
    OperationsHandler::<WithdrawalsPayload>::default().run();
}

#[test]
fn operations_withdrawal_requests() {
    OperationsHandler::<WithdrawalRequest>::default().run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn operations_deposit_requests() {
    OperationsHandler::<DepositRequest>::default().run();
}

#[test]
fn operations_consolidations() {
    OperationsHandler::<ConsolidationRequest>::default().run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn operations_builder_deposit_requests() {
    OperationsHandler::<BuilderDepositRequest>::default().run();
}

#[test]
fn operations_builder_exit_requests() {
    OperationsHandler::<BuilderExitRequest>::default().run();
}

#[test]
fn operations_bls_to_execution_change() {
    OperationsHandler::<SignedBlsToExecutionChange>::default().run();
}

#[test]
fn operations_voluntary_exit_churn() {
    OperationsHandler::<VoluntaryExitChurn>::default().run();
}

#[test]
fn sanity_blocks() {
    SanityBlocksHandler::default().run();
}

#[test]
fn sanity_slots() {
    SanitySlotsHandler::default().run();
}

#[test]
fn random() {
    RandomHandler::default().run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn bls_aggregate() {
    BlsAggregateSigsHandler::default().run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn bls_sign() {
    BlsSignMsgHandler::default().run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn bls_verify() {
    BlsVerifyMsgHandler::default().run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn bls_batch_verify() {
    BlsBatchVerifyHandler::default().run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn bls_aggregate_verify() {
    BlsAggregateVerifyHandler::default().run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn bls_fast_aggregate_verify() {
    BlsFastAggregateVerifyHandler::default().run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn bls_eth_aggregate_pubkeys() {
    BlsEthAggregatePubkeysHandler::default().run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn bls_eth_fast_aggregate_verify() {
    BlsEthFastAggregateVerifyHandler::default().run();
}

/// As for `ssz_static_test_no_run` (below), but also executes the function as a test.
#[cfg(feature = "fake_crypto")]
macro_rules! ssz_static_test {
    ($($args:tt)*) => {
        ssz_static_test_no_run!(#[test] $($args)*);
    };
}

/// Generates a test function for SSZ static tests.
#[cfg(feature = "fake_crypto")]
macro_rules! ssz_static_test_no_run {
    // Top-level (uses SszStaticHandler by default)
    ($(#[$test:meta])? $test_name:ident, $typ:ident$(<$generics:tt>)?) => {
        ssz_static_test_no_run!($(#[$test])? $test_name, SszStaticHandler, $typ);
    };
    // Base case.
    ($(#[$test:meta])? $test_name:ident, $handler:ident, $typ:ident) => {
        $(#[$test])?
        fn $test_name() {
            $handler::<$typ>::default().run();
        }
    };
}

#[cfg(feature = "fake_crypto")]
mod ssz_static {
    use ef_tests::{Handler, SszStaticHandler, SszStaticTHCHandler, SszStaticWithSpecHandler};
    use types::state::HistoricalSummary;
    use types::{
        AttesterSlashingBase, AttesterSlashingElectra, Builder, BuilderPendingPayment,
        BuilderPendingWithdrawal, ConsolidationRequest, DepositRequest, ExecutionPayloadBid,
        ExecutionPayloadEnvelope, IndexedPayloadAttestation, LightClientBootstrapAltair,
        PayloadAttestation, PayloadAttestationData, PayloadAttestationMessage, PendingDeposit,
        PendingPartialWithdrawal, SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope,
        WithdrawalRequest, *,
    };

    ssz_static_test!(attestation_data, AttestationData);
    ssz_static_test!(beacon_block, SszStaticWithSpecHandler, BeaconBlock);
    ssz_static_test!(beacon_block_header, BeaconBlockHeader);
    ssz_static_test!(beacon_state, SszStaticTHCHandler, BeaconState);
    ssz_static_test!(checkpoint, Checkpoint);
    ssz_static_test!(deposit, Deposit);
    ssz_static_test!(deposit_data, DepositData);
    ssz_static_test!(deposit_message, DepositMessage);
    // NOTE: Eth1Block intentionally omitted, see: https://github.com/sigp/lighthouse/issues/1835
    ssz_static_test!(eth1_data, Eth1Data);
    ssz_static_test!(fork, Fork);
    ssz_static_test!(fork_data, ForkData);
    // `HistoricalBatch` was removed in Capella, so test vectors only exist for Base,
    // Altair and Bellatrix.
    #[test]
    fn historical_batch() {
        SszStaticHandler::<HistoricalBatch>::pre_capella().run();
    }
    // `PendingAttestation` was removed in Altair, so test vectors only exist for Base.
    #[test]
    fn pending_attestation() {
        SszStaticHandler::<PendingAttestation>::base_only().run();
    }
    ssz_static_test!(proposer_slashing, ProposerSlashing);
    ssz_static_test!(
        signed_beacon_block,
        SszStaticWithSpecHandler,
        SignedBeaconBlock
    );
    ssz_static_test!(signed_beacon_block_header, SignedBeaconBlockHeader);
    ssz_static_test!(signed_voluntary_exit, SignedVoluntaryExit);
    ssz_static_test!(signing_data, SigningData);
    ssz_static_test!(validator, Validator);
    ssz_static_test!(voluntary_exit, VoluntaryExit);

    #[test]
    fn attestation() {
        SszStaticHandler::<AttestationBase>::pre_electra().run();
        SszStaticHandler::<AttestationElectra>::electra_through_fulu().run();
        SszStaticHandler::<AttestationGloas>::gloas_and_later().run();
    }

    #[test]
    fn single_attestation() {
        SszStaticHandler::<SingleAttestation>::electra_and_later().run();
    }

    #[test]
    fn attester_slashing() {
        SszStaticHandler::<AttesterSlashingBase>::pre_electra().run();
        SszStaticHandler::<AttesterSlashingElectra>::electra_through_fulu().run();
        SszStaticHandler::<AttesterSlashingGloas>::gloas_and_later().run();
    }

    #[test]
    fn indexed_attestation() {
        SszStaticHandler::<IndexedAttestationBase>::pre_electra().run();
        SszStaticHandler::<IndexedAttestationElectra>::electra_through_fulu().run();
        SszStaticHandler::<IndexedAttestationGloas>::gloas_and_later().run();
    }

    #[test]
    fn signed_aggregate_and_proof() {
        SszStaticHandler::<SignedAggregateAndProofBase>::pre_electra().run();
        SszStaticHandler::<SignedAggregateAndProofElectra>::electra_through_fulu().run();
        SszStaticHandler::<SignedAggregateAndProofGloas>::gloas_and_later().run();
    }

    #[test]
    fn aggregate_and_proof() {
        SszStaticHandler::<AggregateAndProofBase>::pre_electra().run();
        SszStaticHandler::<AggregateAndProofElectra>::electra_through_fulu().run();
        SszStaticHandler::<AggregateAndProofGloas>::gloas_and_later().run();
    }

    // BeaconBlockBody has no internal indicator of which fork it is for, so we test it separately.
    #[test]
    fn beacon_block_body() {
        SszStaticHandler::<BeaconBlockBodyBase>::base_only().run();
        SszStaticHandler::<BeaconBlockBodyAltair>::altair_only().run();
        SszStaticHandler::<BeaconBlockBodyBellatrix>::bellatrix_only().run();
        SszStaticHandler::<BeaconBlockBodyCapella>::capella_only().run();
        SszStaticHandler::<BeaconBlockBodyDeneb>::deneb_only().run();
        SszStaticHandler::<BeaconBlockBodyElectra>::electra_only().run();
        SszStaticHandler::<BeaconBlockBodyFulu>::fulu_only().run();
        SszStaticHandler::<BeaconBlockBodyGloas>::gloas_only().run();
        SszStaticHandler::<BeaconBlockBodyHeze>::heze_only().run();
    }

    // Altair and later
    #[test]
    fn contribution_and_proof() {
        SszStaticHandler::<ContributionAndProof>::altair_and_later().run();
    }

    // LightClientBootstrap has no internal indicator of which fork it is for, so we test it separately.
    #[test]
    fn light_client_bootstrap() {
        SszStaticHandler::<LightClientBootstrapAltair>::altair_only().run();
        SszStaticHandler::<LightClientBootstrapAltair>::bellatrix_only().run();
        SszStaticHandler::<LightClientBootstrapCapella>::capella_only().run();
        SszStaticHandler::<LightClientBootstrapDeneb>::deneb_only().run();
        SszStaticHandler::<LightClientBootstrapElectra>::electra_only().run();
        SszStaticHandler::<LightClientBootstrapFulu>::fulu_only().run();
    }

    // LightClientHeader has no internal indicator of which fork it is for, so we test it separately.
    #[test]
    fn light_client_header() {
        SszStaticHandler::<LightClientHeaderAltair>::altair_only().run();
        SszStaticHandler::<LightClientHeaderAltair>::bellatrix_only().run();
        SszStaticHandler::<LightClientHeaderCapella>::capella_only().run();
        SszStaticHandler::<LightClientHeaderDeneb>::deneb_only().run();
        SszStaticHandler::<LightClientHeaderElectra>::electra_only().run();
        SszStaticHandler::<LightClientHeaderFulu>::fulu_only().run();
    }

    // LightClientOptimisticUpdate has no internal indicator of which fork it is for, so we test it separately.
    #[test]
    fn light_client_optimistic_update() {
        SszStaticHandler::<LightClientOptimisticUpdateAltair>::altair_only().run();
        SszStaticHandler::<LightClientOptimisticUpdateAltair>::bellatrix_only().run();
        SszStaticHandler::<LightClientOptimisticUpdateCapella>::capella_only().run();
        SszStaticHandler::<LightClientOptimisticUpdateDeneb>::deneb_only().run();
        SszStaticHandler::<LightClientOptimisticUpdateElectra>::electra_only().run();
        SszStaticHandler::<LightClientOptimisticUpdateFulu>::fulu_only().run();
    }

    // LightClientFinalityUpdate has no internal indicator of which fork it is for, so we test it separately.
    #[test]
    fn light_client_finality_update() {
        SszStaticHandler::<LightClientFinalityUpdateAltair>::altair_only().run();
        SszStaticHandler::<LightClientFinalityUpdateAltair>::bellatrix_only().run();
        SszStaticHandler::<LightClientFinalityUpdateCapella>::capella_only().run();
        SszStaticHandler::<LightClientFinalityUpdateDeneb>::deneb_only().run();
        SszStaticHandler::<LightClientFinalityUpdateElectra>::electra_only().run();
        SszStaticHandler::<LightClientFinalityUpdateFulu>::fulu_only().run();
    }

    // LightClientUpdate has no internal indicator of which fork it is for, so we test it separately.
    #[test]
    fn light_client_update() {
        SszStaticHandler::<LightClientUpdateAltair>::altair_only().run();
        SszStaticHandler::<LightClientUpdateAltair>::bellatrix_only().run();
        SszStaticHandler::<LightClientUpdateCapella>::capella_only().run();
        SszStaticHandler::<LightClientUpdateDeneb>::deneb_only().run();
        SszStaticHandler::<LightClientUpdateElectra>::electra_only().run();
        SszStaticHandler::<LightClientUpdateFulu>::fulu_only().run();
    }

    #[test]
    fn signed_contribution_and_proof() {
        SszStaticHandler::<SignedContributionAndProof>::altair_and_later().run();
    }

    #[test]
    fn sync_aggregate() {
        SszStaticHandler::<SyncAggregate>::altair_and_later().run();
    }

    #[test]
    fn sync_committee() {
        SszStaticHandler::<SyncCommittee>::altair_and_later().run();
    }

    #[test]
    fn sync_committee_contribution() {
        SszStaticHandler::<SyncCommitteeContribution>::altair_and_later().run();
    }

    #[test]
    fn sync_committee_message() {
        SszStaticHandler::<SyncCommitteeMessage>::altair_and_later().run();
    }

    #[test]
    fn sync_aggregator_selection_data() {
        SszStaticHandler::<SyncAggregatorSelectionData>::altair_and_later().run();
    }

    // Bellatrix and later
    #[test]
    fn execution_payload() {
        SszStaticHandler::<ExecutionPayloadBellatrix>::bellatrix_only().run();
        SszStaticHandler::<ExecutionPayloadCapella>::capella_only().run();
        SszStaticHandler::<ExecutionPayloadDeneb>::deneb_only().run();
        SszStaticHandler::<ExecutionPayloadElectra>::electra_only().run();
        SszStaticHandler::<ExecutionPayloadFulu>::fulu_only().run();
        SszStaticHandler::<ExecutionPayloadGloas>::gloas_only().run();
        SszStaticHandler::<ExecutionPayloadHeze>::heze_only().run();
    }

    #[test]
    fn execution_payload_header() {
        SszStaticHandler::<ExecutionPayloadHeaderBellatrix>::bellatrix_only().run();
        SszStaticHandler::<ExecutionPayloadHeaderCapella>::capella_only().run();
        SszStaticHandler::<ExecutionPayloadHeaderDeneb>::deneb_only().run();
        SszStaticHandler::<ExecutionPayloadHeaderElectra>::electra_only().run();
        SszStaticHandler::<ExecutionPayloadHeaderFulu>::fulu_only().run();
    }

    #[test]
    fn execution_payload_bid() {
        SszStaticHandler::<ExecutionPayloadBid>::gloas_and_later().run();
    }

    #[test]
    fn signed_execution_payload_bid() {
        SszStaticHandler::<SignedExecutionPayloadBid>::gloas_and_later().run();
    }

    #[test]
    fn withdrawal() {
        SszStaticHandler::<Withdrawal>::capella_and_later().run();
    }

    #[test]
    fn bls_to_execution_change() {
        SszStaticHandler::<BlsToExecutionChange>::capella_and_later().run();
    }

    #[test]
    fn signed_bls_to_execution_change() {
        SszStaticHandler::<SignedBlsToExecutionChange>::capella_and_later().run();
    }

    #[test]
    fn blob_sidecar() {
        SszStaticHandler::<BlobSidecar>::deneb_only().run();
        SszStaticHandler::<BlobSidecar>::electra_only().run();
    }

    #[test]
    fn blob_identifier() {
        SszStaticHandler::<BlobIdentifier>::deneb_only().run();
        SszStaticHandler::<BlobIdentifier>::electra_only().run();
    }

    #[test]
    fn historical_summary() {
        SszStaticHandler::<HistoricalSummary>::capella_and_later().run();
    }

    #[test]
    fn data_column_sidecar() {
        SszStaticHandler::<DataColumnSidecarFulu>::fulu_only().run();
        SszStaticHandler::<DataColumnSidecarGloas>::gloas_only().run();
        SszStaticHandler::<DataColumnSidecarGloas>::heze_only().run();
    }

    #[test]
    fn data_column_by_root_identifier() {
        SszStaticWithSpecHandler::<DataColumnsByRootIdentifier>::fulu_and_later().run();
    }

    #[test]
    fn consolidation() {
        SszStaticHandler::<ConsolidationRequest>::electra_and_later().run();
    }

    #[test]
    fn deposit_request() {
        SszStaticHandler::<DepositRequest>::electra_and_later().run();
    }

    #[test]
    fn withdrawal_request() {
        SszStaticHandler::<WithdrawalRequest>::electra_and_later().run();
    }

    #[test]
    fn pending_balance_deposit() {
        SszStaticHandler::<PendingDeposit>::electra_and_later().run();
    }

    #[test]
    fn pending_consolidation() {
        SszStaticHandler::<PendingConsolidation>::electra_and_later().run();
    }

    #[test]
    fn pending_partial_withdrawal() {
        SszStaticHandler::<PendingPartialWithdrawal>::electra_and_later().run();
    }

    #[test]
    fn execution_requests() {
        SszStaticHandler::<ExecutionRequestsElectra>::electra_only().run();
        SszStaticHandler::<ExecutionRequestsElectra>::fulu_only().run();
        SszStaticHandler::<ExecutionRequestsGloas>::gloas_only().run();
    }

    // Gloas and later
    #[test]
    fn builder() {
        SszStaticHandler::<Builder>::gloas_and_later().run();
    }

    #[test]
    fn builder_deposit_request() {
        SszStaticHandler::<BuilderDepositRequest>::gloas_and_later().run();
    }

    #[test]
    fn builder_exit_request() {
        SszStaticHandler::<BuilderExitRequest>::gloas_and_later().run();
    }

    #[test]
    fn builder_pending_payment() {
        SszStaticHandler::<BuilderPendingPayment>::gloas_and_later().run();
    }

    #[test]
    fn builder_pending_withdrawal() {
        SszStaticHandler::<BuilderPendingWithdrawal>::gloas_and_later().run();
    }

    #[test]
    fn payload_attestation_data() {
        SszStaticHandler::<PayloadAttestationData>::gloas_and_later().run();
    }

    #[test]
    fn payload_attestation() {
        SszStaticHandler::<PayloadAttestation>::gloas_and_later().run();
    }

    #[test]
    fn payload_attestation_message() {
        SszStaticHandler::<PayloadAttestationMessage>::gloas_and_later().run();
    }

    #[test]
    fn indexed_payload_attestation() {
        SszStaticHandler::<IndexedPayloadAttestation>::gloas_and_later().run();
    }

    #[test]
    fn execution_payload_envelope() {
        SszStaticHandler::<ExecutionPayloadEnvelope>::gloas_and_later().run();
    }

    #[test]
    fn signed_execution_payload_envelope() {
        SszStaticHandler::<SignedExecutionPayloadEnvelope>::gloas_and_later().run();
    }

    #[test]
    fn proposer_preferences() {
        SszStaticHandler::<ProposerPreferences>::gloas_and_later().run();
    }

    #[test]
    fn signed_proposer_preferences() {
        SszStaticHandler::<SignedProposerPreferences>::gloas_and_later().run();
    }
}

#[test]
fn ssz_generic() {
    SszGenericHandler::<BasicVector>::default().run();
    SszGenericHandler::<Bitlist>::default().run();
    SszGenericHandler::<Bitvector>::default().run();
    SszGenericHandler::<Boolean>::default().run();
    SszGenericHandler::<Uints>::default().run();
    SszGenericHandler::<Containers>::default().run();
    SszGenericHandler::<BasicProgressiveList>::default().run();
    SszGenericHandler::<ProgressiveBitlist>::default().run();
    SszGenericHandler::<ProgressiveContainers>::default().run();
    SszGenericHandler::<CompatibleUnions>::default().run();
}

#[test]
fn epoch_processing_justification_and_finalization() {
    EpochProcessingHandler::<JustificationAndFinalization>::default().run();
}

#[test]
fn epoch_processing_rewards_and_penalties() {
    EpochProcessingHandler::<RewardsAndPenalties>::default().run();
}

#[test]
fn epoch_processing_registry_updates() {
    EpochProcessingHandler::<RegistryUpdates>::default().run();
}

#[test]
fn epoch_processing_slashings() {
    EpochProcessingHandler::<Slashings>::default().run();
}

#[test]
fn epoch_processing_eth1_data_reset() {
    EpochProcessingHandler::<Eth1DataReset>::default().run();
}

#[test]
fn epoch_processing_pending_balance_deposits() {
    EpochProcessingHandler::<PendingBalanceDeposits>::default().run();
}

#[test]
fn epoch_processing_pending_deposits_churn() {
    EpochProcessingHandler::<PendingDepositsChurn>::default().run();
}

#[test]
fn epoch_processing_pending_consolidations() {
    EpochProcessingHandler::<PendingConsolidations>::default().run();
}

#[test]
fn epoch_processing_effective_balance_updates() {
    EpochProcessingHandler::<EffectiveBalanceUpdates>::default().run();
}

#[test]
fn epoch_processing_slashings_reset() {
    EpochProcessingHandler::<SlashingsReset>::default().run();
}

#[test]
fn epoch_processing_randao_mixes_reset() {
    EpochProcessingHandler::<RandaoMixesReset>::default().run();
}

#[test]
fn epoch_processing_historical_roots_update() {
    EpochProcessingHandler::<HistoricalRootsUpdate>::default().run();
}

#[test]
fn epoch_processing_historical_summaries_update() {
    EpochProcessingHandler::<HistoricalSummariesUpdate>::default().run();
}

#[test]
fn epoch_processing_participation_record_updates() {
    EpochProcessingHandler::<ParticipationRecordUpdates>::default().run();
}

#[test]
fn epoch_processing_sync_committee_updates() {
    // There are presently no mainnet tests, see:
    // https://github.com/ethereum/consensus-spec-tests/issues/29
    EpochProcessingHandler::<SyncCommitteeUpdates>::default().run();
}

#[test]
fn epoch_processing_inactivity_updates() {
    EpochProcessingHandler::<InactivityUpdates>::default().run();
}

#[test]
fn epoch_processing_participation_flag_updates() {
    EpochProcessingHandler::<ParticipationFlagUpdates>::default().run();
}

#[test]
fn epoch_processing_proposer_lookahead() {
    EpochProcessingHandler::<ProposerLookahead>::default().run();
}

#[test]
fn epoch_processing_ptc_window() {
    EpochProcessingHandler::<PtcWindow>::default().run();
}

#[test]
fn epoch_processing_builder_pending_payments() {
    EpochProcessingHandler::<BuilderPendingPayments>::default().run();
}

#[test]
fn fork_upgrade() {
    ForkHandler::default().run();
}

#[test]
fn transition() {
    TransitionHandler::default().run();
}

#[test]
fn finality() {
    FinalityHandler::default().run();
}

#[test]
fn fork_choice_get_head() {
    ForkChoiceHandler::new("get_head").run();
}

#[test]
fn fork_choice_on_attestation() {
    ForkChoiceHandler::new("on_attestation").run();
}

#[test]
fn fork_choice_on_block() {
    ForkChoiceHandler::new("on_block").run();
}

#[test]
fn fork_choice_ex_ante() {
    ForkChoiceHandler::new("ex_ante").run();
}

#[test]
fn fork_choice_reorg() {
    ForkChoiceHandler::new("reorg").run();
}

#[test]
fn fork_choice_withholding() {
    ForkChoiceHandler::new("withholding").run();
}

#[test]
fn fork_choice_get_proposer_head() {
    ForkChoiceHandler::new("get_proposer_head").run();
}

#[test]
fn fork_choice_deposit_with_reorg() {
    ForkChoiceHandler::new("deposit_with_reorg").run();
}

macro_rules! fast_confirmation_tests {
    ($($name:ident: $handler:literal),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                FastConfirmationHandler::new($handler).run();
            }
        )*
    };
}

fast_confirmation_tests! {
    fast_confirmation_basic: "basic",
    fast_confirmation_current_epoch: "current_epoch",
    fast_confirmation_empty_slots: "empty_slots",
    fast_confirmation_ffg: "ffg",
    fast_confirmation_is_one_confirmed: "is_one_confirmed",
    fast_confirmation_previous_epoch: "previous_epoch",
    fast_confirmation_reconfirmation: "reconfirmation",
    fast_confirmation_restart_gu: "restart_gu",
    fast_confirmation_revert_finality: "revert_finality",
    fast_confirmation_variables: "variables",
}

#[test]
fn fork_choice_on_execution_payload_envelope() {
    ForkChoiceHandler::new("on_execution_payload_envelope").run();
}

#[test]
fn fork_choice_get_parent_payload_status() {
    ForkChoiceHandler::new("get_parent_payload_status").run();
}

#[test]
fn fork_choice_on_payload_attestation_message() {
    ForkChoiceHandler::new("on_payload_attestation_message").run();
}

#[test]
fn fork_choice_payload_timeliness() {
    ForkChoiceHandler::new("payload_timeliness").run();
}

#[test]
fn fork_choice_payload_data_availability() {
    ForkChoiceHandler::new("payload_data_availability").run();
}

#[test]
fn optimistic_sync() {
    OptimisticSyncHandler::default().run();
}

#[test]
fn genesis_initialization() {
    GenesisInitializationHandler::default().run();
}

#[test]
fn genesis_validity() {
    GenesisValidityHandler::default().run();
}

#[test]
fn kzg_blob_to_kzg_commitment() {
    KZGBlobToKZGCommitmentHandler::default().run();
}

#[test]
fn kzg_compute_blob_kzg_proof() {
    KZGComputeBlobKZGProofHandler::default().run();
}

#[test]
fn kzg_compute_kzg_proof() {
    KZGComputeKZGProofHandler::default().run();
}

#[test]
fn kzg_verify_blob_kzg_proof() {
    KZGVerifyBlobKZGProofHandler::default().run();
}

#[test]
fn kzg_verify_blob_kzg_proof_batch() {
    KZGVerifyBlobKZGProofBatchHandler::default().run();
}

#[test]
fn kzg_verify_kzg_proof() {
    KZGVerifyKZGProofHandler::default().run();
}

#[test]
fn kzg_compute_cells() {
    KZGComputeCellsHandler::default().run();
}

#[test]
fn kzg_compute_cells_and_proofs() {
    KZGComputeCellsAndKZGProofHandler::default().run();
}

#[test]
fn kzg_verify_cell_proof_batch() {
    KZGVerifyCellKZGProofBatchHandler::default().run();
}

#[test]
fn kzg_recover_cells_and_proofs() {
    KZGRecoverCellsAndKZGProofHandler::default().run();
}

#[test]
fn light_client_merkle_proof_validity() {
    MerkleProofValidityHandler::default().run();
}

#[test]
fn light_client_update() {
    LightClientUpdateHandler::default().run();
}

#[test]
#[cfg(feature = "fake_crypto")]
fn kzg_inclusion_merkle_proof_validity() {
    KzgInclusionMerkleProofValidityHandler::default().run();
}

#[test]
fn rewards() {
    for handler in &["basic", "leak", "random", "inactivity_scores"] {
        RewardsHandler::new(handler).run();
    }
}

#[test]
fn get_custody_groups() {
    GetCustodyGroupsHandler::default().run();
}

#[test]
fn compute_columns_for_custody_group() {
    ComputeColumnsForCustodyGroupHandler::default().run();
}

#[test]
fn gossip_beacon_block() {
    GossipValidationHandler::new("gossip_beacon_block").run();
}

#[test]
fn gossip_proposer_slashing() {
    GossipValidationHandler::new("gossip_proposer_slashing").run();
}

#[test]
fn gossip_attester_slashing() {
    GossipValidationHandler::new("gossip_attester_slashing").run();
}

#[test]
fn gossip_voluntary_exit() {
    GossipValidationHandler::latest_stable("gossip_voluntary_exit").run();
}

#[test]
fn gossip_beacon_attestation() {
    GossipValidationHandler::latest_stable("gossip_beacon_attestation").run();
}

#[test]
fn gossip_beacon_aggregate_and_proof() {
    GossipValidationHandler::latest_stable("gossip_beacon_aggregate_and_proof").run();
}

#[test]
fn gossip_bls_to_execution_change() {
    GossipValidationHandler::latest_stable("gossip_bls_to_execution_change").run();
}

#[test]
fn gossip_sync_committee_message() {
    GossipValidationHandler::latest_stable("gossip_sync_committee_message").run();
}

#[test]
fn gossip_sync_committee_contribution_and_proof() {
    GossipValidationHandler::latest_stable("gossip_sync_committee_contribution_and_proof").run();
}
