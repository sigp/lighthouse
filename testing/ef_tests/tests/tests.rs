#![cfg(feature = "ef_tests")]

use ef_tests::*;
use typenum::Unsigned;
use types::*;

// Check that the hand-computed multiplications on EthSpec are correctly computed.
// This test lives here because one is most likely to muck these up during a spec update.
fn check_typenum_values<E: EthSpec>() {
    assert_eq!(
        E::MaxPendingAttestations::to_u64(),
        E::MaxAttestations::to_u64() * E::SlotsPerEpoch::to_u64()
    );
    assert_eq!(
        E::SlotsPerEth1VotingPeriod::to_u64(),
        E::EpochsPerEth1VotingPeriod::to_u64() * E::SlotsPerEpoch::to_u64()
    );
    assert_eq!(
        E::MaxValidatorsPerSlot::to_u64(),
        E::MaxCommitteesPerSlot::to_u64() * E::MaxValidatorsPerCommittee::to_u64()
    );
}

#[test]
fn derived_typenum_values() {
    check_typenum_values::<Spec>();
}

#[test]
fn shuffling() {
    ShufflingHandler::<Spec>::default().run();
}

#[test]
fn operations_deposit() {
    OperationsHandler::<Spec, Deposit>::default().run();
}

#[test]
fn operations_exit() {
    OperationsHandler::<Spec, SignedVoluntaryExit>::default().run();
}

#[test]
fn operations_proposer_slashing() {
    OperationsHandler::<Spec, ProposerSlashing>::default().run();
}

#[test]
fn operations_attester_slashing() {
    OperationsHandler::<Spec, AttesterSlashing<_>>::default().run();
}

#[test]
fn operations_attestation() {
    OperationsHandler::<Spec, Attestation<_>>::default().run();
}

#[test]
fn operations_block_header() {
    OperationsHandler::<Spec, BeaconBlock<_>>::default().run();
}

#[test]
fn operations_sync_aggregate() {
    OperationsHandler::<Spec, SyncAggregate<_>>::default().run();
}

#[test]
fn operations_execution_payload_full() {
    OperationsHandler::<Spec, BeaconBlockBody<_, FullPayload<_>>>::default().run();
}

#[test]
fn operations_execution_payload_blinded() {
    OperationsHandler::<Spec, BeaconBlockBody<_, BlindedPayload<_>>>::default().run();
}

#[test]
fn operations_execution_payload_envelope() {
    OperationsHandler::<Spec, SignedExecutionPayloadEnvelope<_>>::default().run();
}

#[test]
fn operations_execution_payload_bid() {
    OperationsHandler::<Spec, ExecutionPayloadBidBlock<_>>::default().run();
}

#[test]
fn operations_parent_execution_payload() {
    OperationsHandler::<Spec, ParentExecutionPayloadBlock<_>>::default().run();
}

#[test]
fn operations_payload_attestation() {
    OperationsHandler::<Spec, PayloadAttestation<_>>::default().run();
}

#[test]
fn operations_withdrawals() {
    OperationsHandler::<Spec, WithdrawalsPayload<_>>::default().run();
}

#[test]
fn operations_withdrawal_requests() {
    OperationsHandler::<Spec, WithdrawalRequest>::default().run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn operations_deposit_requests() {
    OperationsHandler::<Spec, DepositRequest>::default().run();
}

#[test]
fn operations_consolidations() {
    OperationsHandler::<Spec, ConsolidationRequest>::default().run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn operations_builder_deposit_requests() {
    OperationsHandler::<Spec, BuilderDepositRequest>::default().run();
}

#[test]
fn operations_builder_exit_requests() {
    OperationsHandler::<Spec, BuilderExitRequest>::default().run();
}

#[test]
fn operations_bls_to_execution_change() {
    OperationsHandler::<Spec, SignedBlsToExecutionChange>::default().run();
}

#[test]
fn operations_voluntary_exit_churn() {
    OperationsHandler::<Spec, VoluntaryExitChurn>::default().run();
}

#[test]
fn sanity_blocks() {
    SanityBlocksHandler::<Spec>::default().run();
}

#[test]
fn sanity_slots() {
    SanitySlotsHandler::<Spec>::default().run();
}

#[test]
fn random() {
    RandomHandler::<Spec>::default().run();
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

/// Generate a function to run the SSZ static tests for a type.
///
/// Quite complex in order to support an optional #[test] attrib and generics.
#[cfg(feature = "fake_crypto")]
macro_rules! ssz_static_test_no_run {
    // Top-level
    ($(#[$test:meta])? $test_name:ident, $typ:ident$(<$generics:tt>)?) => {
        ssz_static_test_no_run!($(#[$test])? $test_name, SszStaticHandler, $typ$(<$generics>)?);
    };
    // Generic
    ($(#[$test:meta])? $test_name:ident, $handler:ident, $typ:ident<_>) => {
        ssz_static_test_no_run!(
            $(#[$test])?
            $test_name,
            $handler,
            {
                ($typ<Spec>, Spec)
            }
        );
    };
    // Non-generic
    ($(#[$test:meta])? $test_name:ident, $handler:ident, $typ:ident) => {
        ssz_static_test_no_run!(
            $(#[$test])?
            $test_name,
            $handler,
            {
                ($typ, Spec)
            }
        );
    };
    // Base case
    ($(#[$test:meta])? $test_name:ident, $handler:ident, { $(($($typ:ty),+)),+ }) => {
        $(#[$test])?
        fn $test_name() {
            $(
                $handler::<$($typ),+>::default().run();
            )+
        }
    };
}

#[cfg(feature = "fake_crypto")]
mod ssz_static {
    use ef_tests::{Handler, SszStaticHandler, SszStaticTHCHandler, SszStaticWithSpecHandler};
    use types::state::HistoricalSummary;
    use types::{
        AttesterSlashingBase, AttesterSlashingElectra, Builder, BuilderPendingPayment,
        BuilderPendingWithdrawal, ConsolidationRequest, DepositRequest, ExecutionPayloadEnvelope,
        IndexedPayloadAttestation, LightClientBootstrapAltair, PayloadAttestation,
        PayloadAttestationData, PayloadAttestationMessage, PendingDeposit,
        PendingPartialWithdrawal, SignedExecutionPayloadEnvelope, WithdrawalRequest, *,
    };

    ssz_static_test!(attestation_data, AttestationData);
    ssz_static_test!(beacon_block, SszStaticWithSpecHandler, BeaconBlock<_>);
    ssz_static_test!(beacon_block_header, BeaconBlockHeader);
    ssz_static_test!(beacon_state, SszStaticTHCHandler, BeaconState<_>);
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
        SszStaticHandler::<HistoricalBatch<Spec>, Spec>::pre_capella().run();
    }
    // `PendingAttestation` was removed in Altair, so test vectors only exist for Base.
    #[test]
    fn pending_attestation() {
        SszStaticHandler::<PendingAttestation<Spec>, Spec>::base_only().run();
    }
    ssz_static_test!(proposer_slashing, ProposerSlashing);
    ssz_static_test!(
        signed_beacon_block,
        SszStaticWithSpecHandler,
        SignedBeaconBlock<_>
    );
    ssz_static_test!(signed_beacon_block_header, SignedBeaconBlockHeader);
    ssz_static_test!(signed_voluntary_exit, SignedVoluntaryExit);
    ssz_static_test!(signing_data, SigningData);
    ssz_static_test!(validator, Validator);
    ssz_static_test!(voluntary_exit, VoluntaryExit);

    #[test]
    fn attestation() {
        SszStaticHandler::<AttestationBase<Spec>, Spec>::pre_electra().run();
        SszStaticHandler::<AttestationElectra<Spec>, Spec>::electra_through_fulu().run();
        SszStaticHandler::<AttestationGloas<Spec>, Spec>::gloas_and_later().run();
    }

    #[test]
    fn single_attestation() {
        SszStaticHandler::<SingleAttestation, Spec>::electra_and_later().run();
    }

    #[test]
    fn attester_slashing() {
        SszStaticHandler::<AttesterSlashingBase<Spec>, Spec>::pre_electra().run();
        SszStaticHandler::<AttesterSlashingElectra<Spec>, Spec>::electra_through_fulu().run();
        SszStaticHandler::<AttesterSlashingGloas<Spec>, Spec>::gloas_and_later().run();
    }

    #[test]
    fn indexed_attestation() {
        SszStaticHandler::<IndexedAttestationBase<Spec>, Spec>::pre_electra().run();
        SszStaticHandler::<IndexedAttestationElectra<Spec>, Spec>::electra_through_fulu().run();
        SszStaticHandler::<IndexedAttestationGloas<Spec>, Spec>::gloas_and_later().run();
    }

    #[test]
    fn signed_aggregate_and_proof() {
        SszStaticHandler::<SignedAggregateAndProofBase<Spec>, Spec>::pre_electra().run();
        SszStaticHandler::<SignedAggregateAndProofElectra<Spec>, Spec>::electra_through_fulu()
            .run();
        SszStaticHandler::<SignedAggregateAndProofGloas<Spec>, Spec>::gloas_and_later().run();
    }

    #[test]
    fn aggregate_and_proof() {
        SszStaticHandler::<AggregateAndProofBase<Spec>, Spec>::pre_electra().run();
        SszStaticHandler::<AggregateAndProofElectra<Spec>, Spec>::electra_through_fulu().run();
        SszStaticHandler::<AggregateAndProofGloas<Spec>, Spec>::gloas_and_later().run();
    }

    // BeaconBlockBody has no internal indicator of which fork it is for, so we test it separately.
    #[test]
    fn beacon_block_body() {
        SszStaticHandler::<BeaconBlockBodyBase<Spec>, Spec>::base_only().run();
        SszStaticHandler::<BeaconBlockBodyAltair<Spec>, Spec>::altair_only().run();
        SszStaticHandler::<BeaconBlockBodyBellatrix<Spec>, Spec>::bellatrix_only().run();
        SszStaticHandler::<BeaconBlockBodyCapella<Spec>, Spec>::capella_only().run();
        SszStaticHandler::<BeaconBlockBodyDeneb<Spec>, Spec>::deneb_only().run();
        SszStaticHandler::<BeaconBlockBodyElectra<Spec>, Spec>::electra_only().run();
        SszStaticHandler::<BeaconBlockBodyFulu<Spec>, Spec>::fulu_only().run();
        SszStaticHandler::<BeaconBlockBodyGloas<Spec>, Spec>::gloas_only().run();
        SszStaticHandler::<BeaconBlockBodyHeze<Spec>, Spec>::heze_only().run();
    }

    // Altair and later
    #[test]
    fn contribution_and_proof() {
        SszStaticHandler::<ContributionAndProof<Spec>, Spec>::altair_and_later().run();
    }

    // LightClientBootstrap has no internal indicator of which fork it is for, so we test it separately.
    #[test]
    fn light_client_bootstrap() {
        SszStaticHandler::<LightClientBootstrapAltair<Spec>, Spec>::altair_only().run();
        SszStaticHandler::<LightClientBootstrapAltair<Spec>, Spec>::bellatrix_only().run();
        SszStaticHandler::<LightClientBootstrapCapella<Spec>, Spec>::capella_only().run();
        SszStaticHandler::<LightClientBootstrapDeneb<Spec>, Spec>::deneb_only().run();
        SszStaticHandler::<LightClientBootstrapElectra<Spec>, Spec>::electra_only().run();
        SszStaticHandler::<LightClientBootstrapFulu<Spec>, Spec>::fulu_only().run();
        SszStaticHandler::<LightClientBootstrapGloas<Spec>, Spec>::gloas_only().run();
    }

    // LightClientHeader has no internal indicator of which fork it is for, so we test it separately.
    #[test]
    fn light_client_header() {
        SszStaticHandler::<LightClientHeaderAltair<Spec>, Spec>::altair_only().run();
        SszStaticHandler::<LightClientHeaderAltair<Spec>, Spec>::bellatrix_only().run();

        SszStaticHandler::<LightClientHeaderCapella<Spec>, Spec>::capella_only().run();

        SszStaticHandler::<LightClientHeaderDeneb<Spec>, Spec>::deneb_only().run();
        SszStaticHandler::<LightClientHeaderElectra<Spec>, Spec>::electra_only().run();
        SszStaticHandler::<LightClientHeaderFulu<Spec>, Spec>::fulu_only().run();
        SszStaticHandler::<LightClientHeaderGloas<Spec>, Spec>::gloas_only().run();
    }

    // LightClientOptimisticUpdate has no internal indicator of which fork it is for, so we test it separately.
    #[test]
    fn light_client_optimistic_update() {
        SszStaticHandler::<LightClientOptimisticUpdateAltair<Spec>, Spec>::altair_only().run();
        SszStaticHandler::<LightClientOptimisticUpdateAltair<Spec>, Spec>::bellatrix_only().run();
        SszStaticHandler::<LightClientOptimisticUpdateCapella<Spec>, Spec>::capella_only().run();
        SszStaticHandler::<LightClientOptimisticUpdateDeneb<Spec>, Spec>::deneb_only().run();
        SszStaticHandler::<LightClientOptimisticUpdateElectra<Spec>, Spec>::electra_only().run();
        SszStaticHandler::<LightClientOptimisticUpdateFulu<Spec>, Spec>::fulu_only().run();
        SszStaticHandler::<LightClientOptimisticUpdateGloas<Spec>, Spec>::gloas_only().run();
    }

    // LightClientFinalityUpdate has no internal indicator of which fork it is for, so we test it separately.
    #[test]
    fn light_client_finality_update() {
        SszStaticHandler::<LightClientFinalityUpdateAltair<Spec>, Spec>::altair_only().run();
        SszStaticHandler::<LightClientFinalityUpdateAltair<Spec>, Spec>::bellatrix_only().run();
        SszStaticHandler::<LightClientFinalityUpdateCapella<Spec>, Spec>::capella_only().run();
        SszStaticHandler::<LightClientFinalityUpdateDeneb<Spec>, Spec>::deneb_only().run();
        SszStaticHandler::<LightClientFinalityUpdateElectra<Spec>, Spec>::electra_only().run();
        SszStaticHandler::<LightClientFinalityUpdateFulu<Spec>, Spec>::fulu_only().run();
        SszStaticHandler::<LightClientFinalityUpdateGloas<Spec>, Spec>::gloas_only().run();
    }

    // LightClientUpdate has no internal indicator of which fork it is for, so we test it separately.
    #[test]
    fn light_client_update() {
        SszStaticHandler::<LightClientUpdateAltair<Spec>, Spec>::altair_only().run();
        SszStaticHandler::<LightClientUpdateAltair<Spec>, Spec>::bellatrix_only().run();
        SszStaticHandler::<LightClientUpdateCapella<Spec>, Spec>::capella_only().run();
        SszStaticHandler::<LightClientUpdateDeneb<Spec>, Spec>::deneb_only().run();
        SszStaticHandler::<LightClientUpdateElectra<Spec>, Spec>::electra_only().run();
        SszStaticHandler::<LightClientUpdateFulu<Spec>, Spec>::fulu_only().run();
        SszStaticHandler::<LightClientUpdateGloas<Spec>, Spec>::gloas_only().run();
    }

    #[test]
    fn signed_contribution_and_proof() {
        SszStaticHandler::<SignedContributionAndProof<Spec>, Spec>::altair_and_later().run();
    }

    #[test]
    fn sync_aggregate() {
        SszStaticHandler::<SyncAggregate<Spec>, Spec>::altair_and_later().run();
    }

    #[test]
    fn sync_committee() {
        SszStaticHandler::<SyncCommittee<Spec>, Spec>::altair_and_later().run();
    }

    #[test]
    fn sync_committee_contribution() {
        SszStaticHandler::<SyncCommitteeContribution<Spec>, Spec>::altair_and_later().run();
    }

    #[test]
    fn sync_committee_message() {
        SszStaticHandler::<SyncCommitteeMessage, Spec>::altair_and_later().run();
    }

    #[test]
    fn sync_aggregator_selection_data() {
        SszStaticHandler::<SyncAggregatorSelectionData, Spec>::altair_and_later().run();
    }

    // Bellatrix and later
    #[test]
    fn execution_payload() {
        SszStaticHandler::<ExecutionPayloadBellatrix<Spec>, Spec>::bellatrix_only().run();
        SszStaticHandler::<ExecutionPayloadCapella<Spec>, Spec>::capella_only().run();
        SszStaticHandler::<ExecutionPayloadDeneb<Spec>, Spec>::deneb_only().run();
        SszStaticHandler::<ExecutionPayloadElectra<Spec>, Spec>::electra_only().run();
        SszStaticHandler::<ExecutionPayloadFulu<Spec>, Spec>::fulu_only().run();
        SszStaticHandler::<ExecutionPayloadGloas<Spec>, Spec>::gloas_only().run();
        SszStaticHandler::<ExecutionPayloadHeze<Spec>, Spec>::heze_only().run();
    }

    #[test]
    fn execution_payload_header() {
        SszStaticHandler::<ExecutionPayloadHeaderBellatrix<Spec>, Spec>::bellatrix_only().run();
        SszStaticHandler::<ExecutionPayloadHeaderCapella<Spec>, Spec>::capella_only().run();
        SszStaticHandler::<ExecutionPayloadHeaderDeneb<Spec>, Spec>::deneb_only().run();
        SszStaticHandler::<ExecutionPayloadHeaderElectra<Spec>, Spec>::electra_only().run();
        SszStaticHandler::<ExecutionPayloadHeaderFulu<Spec>, Spec>::fulu_only().run();
    }

    #[test]
    fn execution_payload_bid() {
        SszStaticHandler::<ExecutionPayloadBidGloas<Spec>, Spec>::gloas_only().run();
        SszStaticHandler::<ExecutionPayloadBidHeze<Spec>, Spec>::heze_only().run();
    }

    #[test]
    fn signed_execution_payload_bid() {
        SszStaticHandler::<SignedExecutionPayloadBidGloas<Spec>, Spec>::gloas_only().run();
        SszStaticHandler::<SignedExecutionPayloadBidHeze<Spec>, Spec>::heze_only().run();
    }

    #[test]
    fn withdrawal() {
        SszStaticHandler::<Withdrawal, Spec>::capella_and_later().run();
    }

    #[test]
    fn bls_to_execution_change() {
        SszStaticHandler::<BlsToExecutionChange, Spec>::capella_and_later().run();
    }

    #[test]
    fn signed_bls_to_execution_change() {
        SszStaticHandler::<SignedBlsToExecutionChange, Spec>::capella_and_later().run();
    }

    #[test]
    fn blob_sidecar() {
        SszStaticHandler::<BlobSidecar<Spec>, Spec>::deneb_only().run();
        SszStaticHandler::<BlobSidecar<Spec>, Spec>::electra_only().run();
    }

    #[test]
    fn blob_identifier() {
        SszStaticHandler::<BlobIdentifier, Spec>::deneb_only().run();
        SszStaticHandler::<BlobIdentifier, Spec>::electra_only().run();
    }

    #[test]
    fn historical_summary() {
        SszStaticHandler::<HistoricalSummary, Spec>::capella_and_later().run();
    }

    #[test]
    fn data_column_sidecar() {
        SszStaticHandler::<DataColumnSidecarFulu<Spec>, Spec>::fulu_only().run();
        SszStaticHandler::<DataColumnSidecarGloas<Spec>, Spec>::gloas_only().run();
        SszStaticHandler::<DataColumnSidecarGloas<Spec>, Spec>::heze_only().run();
    }

    #[test]
    fn data_column_by_root_identifier() {
        SszStaticWithSpecHandler::<DataColumnsByRootIdentifier<Spec>, Spec>::fulu_and_later().run();
    }

    #[test]
    fn consolidation() {
        SszStaticHandler::<ConsolidationRequest, Spec>::electra_and_later().run();
    }

    #[test]
    fn deposit_request() {
        SszStaticHandler::<DepositRequest, Spec>::electra_and_later().run();
    }

    #[test]
    fn withdrawal_request() {
        SszStaticHandler::<WithdrawalRequest, Spec>::electra_and_later().run();
    }

    #[test]
    fn pending_balance_deposit() {
        SszStaticHandler::<PendingDeposit, Spec>::electra_and_later().run();
    }

    #[test]
    fn pending_consolidation() {
        SszStaticHandler::<PendingConsolidation, Spec>::electra_and_later().run();
    }

    #[test]
    fn pending_partial_withdrawal() {
        SszStaticHandler::<PendingPartialWithdrawal, Spec>::electra_and_later().run();
    }

    #[test]
    fn execution_requests() {
        SszStaticHandler::<ExecutionRequestsElectra<Spec>, Spec>::electra_only().run();
        SszStaticHandler::<ExecutionRequestsElectra<Spec>, Spec>::fulu_only().run();
        SszStaticHandler::<ExecutionRequestsGloas<Spec>, Spec>::gloas_only().run();
    }

    // Gloas and later
    #[test]
    fn builder() {
        SszStaticHandler::<Builder, Spec>::gloas_and_later().run();
    }

    #[test]
    fn builder_deposit_request() {
        SszStaticHandler::<BuilderDepositRequest, Spec>::gloas_and_later().run();
    }

    #[test]
    fn builder_exit_request() {
        SszStaticHandler::<BuilderExitRequest, Spec>::gloas_and_later().run();
    }

    #[test]
    fn builder_pending_payment() {
        SszStaticHandler::<BuilderPendingPayment, Spec>::gloas_and_later().run();
    }

    #[test]
    fn builder_pending_withdrawal() {
        SszStaticHandler::<BuilderPendingWithdrawal, Spec>::gloas_and_later().run();
    }

    #[test]
    fn payload_attestation_data() {
        SszStaticHandler::<PayloadAttestationData, Spec>::gloas_and_later().run();
    }

    #[test]
    fn payload_attestation() {
        SszStaticHandler::<PayloadAttestation<Spec>, Spec>::gloas_and_later().run();
    }

    #[test]
    fn payload_attestation_message() {
        SszStaticHandler::<PayloadAttestationMessage, Spec>::gloas_and_later().run();
    }

    #[test]
    fn indexed_payload_attestation() {
        SszStaticHandler::<IndexedPayloadAttestation<Spec>, Spec>::gloas_and_later().run();
    }

    #[test]
    fn execution_payload_envelope() {
        SszStaticHandler::<ExecutionPayloadEnvelope<Spec>, Spec>::gloas_and_later().run();
    }

    #[test]
    fn signed_execution_payload_envelope() {
        SszStaticHandler::<SignedExecutionPayloadEnvelope<Spec>, Spec>::gloas_and_later().run();
    }

    #[test]
    fn proposer_preferences() {
        SszStaticHandler::<ProposerPreferences, Spec>::gloas_and_later().run();
    }

    #[test]
    fn signed_proposer_preferences() {
        SszStaticHandler::<SignedProposerPreferences, Spec>::gloas_and_later().run();
    }
}

#[test]
fn epoch_processing_justification_and_finalization() {
    EpochProcessingHandler::<Spec, JustificationAndFinalization>::default().run();
}

#[test]
fn epoch_processing_rewards_and_penalties() {
    EpochProcessingHandler::<Spec, RewardsAndPenalties>::default().run();
}

#[test]
fn epoch_processing_registry_updates() {
    EpochProcessingHandler::<Spec, RegistryUpdates>::default().run();
}

#[test]
fn epoch_processing_slashings() {
    EpochProcessingHandler::<Spec, Slashings>::default().run();
}

#[test]
fn epoch_processing_eth1_data_reset() {
    EpochProcessingHandler::<Spec, Eth1DataReset>::default().run();
}

#[test]
fn epoch_processing_pending_balance_deposits() {
    EpochProcessingHandler::<Spec, PendingBalanceDeposits>::default().run();
}

#[test]
fn epoch_processing_pending_deposits_churn() {
    EpochProcessingHandler::<Spec, PendingDepositsChurn>::default().run();
}

#[test]
fn epoch_processing_pending_consolidations() {
    EpochProcessingHandler::<Spec, PendingConsolidations>::default().run();
}

#[test]
fn epoch_processing_effective_balance_updates() {
    EpochProcessingHandler::<Spec, EffectiveBalanceUpdates>::default().run();
}

#[test]
fn epoch_processing_slashings_reset() {
    EpochProcessingHandler::<Spec, SlashingsReset>::default().run();
}

#[test]
fn epoch_processing_randao_mixes_reset() {
    EpochProcessingHandler::<Spec, RandaoMixesReset>::default().run();
}

#[test]
fn epoch_processing_historical_roots_update() {
    EpochProcessingHandler::<Spec, HistoricalRootsUpdate>::default().run();
}

#[test]
fn epoch_processing_historical_summaries_update() {
    EpochProcessingHandler::<Spec, HistoricalSummariesUpdate>::default().run();
}

#[test]
fn epoch_processing_participation_record_updates() {
    EpochProcessingHandler::<Spec, ParticipationRecordUpdates>::default().run();
}

#[test]
#[cfg(feature = "spec-minimal")]
fn epoch_processing_sync_committee_updates() {
    // There are presently no mainnet tests, see:
    // https://github.com/ethereum/consensus-spec-tests/issues/29
    EpochProcessingHandler::<Spec, SyncCommitteeUpdates>::default().run();
}

#[test]
fn epoch_processing_inactivity_updates() {
    EpochProcessingHandler::<Spec, InactivityUpdates>::default().run();
}

#[test]
fn epoch_processing_participation_flag_updates() {
    EpochProcessingHandler::<Spec, ParticipationFlagUpdates>::default().run();
}

#[test]
fn epoch_processing_proposer_lookahead() {
    EpochProcessingHandler::<Spec, ProposerLookahead>::default().run();
}

#[test]
fn epoch_processing_ptc_window() {
    EpochProcessingHandler::<Spec, PtcWindow>::default().run();
}

#[test]
fn epoch_processing_builder_pending_payments() {
    EpochProcessingHandler::<Spec, BuilderPendingPayments>::default().run();
}

#[test]
fn fork_upgrade() {
    ForkHandler::<Spec>::default().run();
}

#[test]
fn transition() {
    TransitionHandler::<Spec>::default().run();
}

#[test]
fn finality() {
    FinalityHandler::<Spec>::default().run();
}

#[test]
fn fork_choice_get_head() {
    ForkChoiceHandler::<Spec>::new("get_head").run();
}

#[test]
fn fork_choice_on_attestation() {
    ForkChoiceHandler::<Spec>::new("on_attestation").run();
}

#[test]
fn fork_choice_on_block() {
    ForkChoiceHandler::<Spec>::new("on_block").run();
}

#[test]
fn fork_choice_ex_ante() {
    ForkChoiceHandler::<Spec>::new("ex_ante").run();
}

#[test]
#[cfg(feature = "spec-minimal")]
fn fork_choice_reorg() {
    ForkChoiceHandler::<Spec>::new("reorg").run();
    // There is no mainnet variant for this test.
}

#[test]
#[cfg(feature = "spec-minimal")]
fn fork_choice_withholding() {
    ForkChoiceHandler::<Spec>::new("withholding").run();
    // There is no mainnet variant for this test.
}

#[test]
fn fork_choice_get_proposer_head() {
    ForkChoiceHandler::<Spec>::new("get_proposer_head").run();
}

#[test]
#[cfg(feature = "spec-minimal")]
fn fork_choice_deposit_with_reorg() {
    ForkChoiceHandler::<Spec>::new("deposit_with_reorg").run();
    // There is no mainnet variant for this test.
}

macro_rules! fast_confirmation_tests {
    ($($name:ident: $handler:literal),* $(,)?) => {
        $(
            #[test]
            #[cfg(feature = "spec-minimal")]
            fn $name() {
                FastConfirmationHandler::<Spec>::new($handler).run();
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
    ForkChoiceHandler::<Spec>::new("on_execution_payload_envelope").run();
}

#[test]
fn fork_choice_get_parent_payload_status() {
    ForkChoiceHandler::<Spec>::new("get_parent_payload_status").run();
}

#[test]
fn fork_choice_on_payload_attestation_message() {
    ForkChoiceHandler::<Spec>::new("on_payload_attestation_message").run();
}

#[test]
fn fork_choice_payload_timeliness() {
    ForkChoiceHandler::<Spec>::new("payload_timeliness").run();
}

#[test]
fn fork_choice_payload_data_availability() {
    ForkChoiceHandler::<Spec>::new("payload_data_availability").run();
}

#[test]
#[cfg(feature = "spec-minimal")]
fn fork_choice_should_apply_proposer_boost() {
    ForkChoiceHandler::<Spec>::new("should_apply_proposer_boost").run();
    // There is no mainnet variant for this test.
}

#[test]
#[cfg(feature = "spec-minimal")]
fn fork_choice_compliance_attester_slashing_test() {
    ForkChoiceComplianceHandler::<Spec>::new("attester_slashing_test").run();
}

#[test]
#[cfg(feature = "spec-minimal")]
fn fork_choice_compliance_block_cover_test() {
    ForkChoiceComplianceHandler::<Spec>::new("block_cover_test").run();
}

#[test]
#[cfg(feature = "spec-minimal")]
fn fork_choice_compliance_block_tree_test() {
    ForkChoiceComplianceHandler::<Spec>::new("block_tree_test").run();
}

#[test]
#[cfg(feature = "spec-minimal")]
fn fork_choice_compliance_block_weight_test() {
    ForkChoiceComplianceHandler::<Spec>::new("block_weight_test").run();
}

#[test]
#[cfg(feature = "spec-minimal")]
fn fork_choice_compliance_invalid_message_test() {
    ForkChoiceComplianceHandler::<Spec>::new("invalid_message_test").run();
}

#[test]
#[cfg(feature = "spec-minimal")]
fn fork_choice_compliance_shuffling_test() {
    ForkChoiceComplianceHandler::<Spec>::new("shuffling_test").run();
}

#[test]
fn optimistic_sync() {
    OptimisticSyncHandler::<Spec>::default().run();
}

#[test]
#[cfg(feature = "spec-minimal")]
fn genesis_initialization() {
    GenesisInitializationHandler::<Spec>::default().run();
}

#[test]
#[cfg(feature = "spec-minimal")]
fn genesis_validity() {
    GenesisValidityHandler::<Spec>::default().run();
    // Note: there are no genesis validity tests for mainnet
}

#[test]
fn light_client_merkle_proof_validity() {
    MerkleProofValidityHandler::<Spec>::default().run();
}

#[test]
#[cfg(feature = "spec-minimal")]
fn light_client_update() {
    LightClientUpdateHandler::<Spec>::default().run();
}

#[test]
#[cfg(feature = "fake_crypto")]
fn kzg_inclusion_merkle_proof_validity() {
    KzgInclusionMerkleProofValidityHandler::<Spec>::default().run();
}

#[test]
fn rewards() {
    for handler in &["basic", "leak", "random", "inactivity_scores"] {
        RewardsHandler::<Spec>::new(handler).run();
    }
}

#[test]
fn get_custody_groups() {
    GetCustodyGroupsHandler::<Spec>::default().run();
}

#[test]
fn compute_columns_for_custody_group() {
    ComputeColumnsForCustodyGroupHandler::<Spec>::default().run();
}

#[test]
fn gossip_beacon_block() {
    GossipValidationHandler::<Spec>::new("gossip_beacon_block").run();
}

#[test]
fn gossip_proposer_slashing() {
    GossipValidationHandler::<Spec>::new("gossip_proposer_slashing").run();
}

#[test]
fn gossip_attester_slashing() {
    GossipValidationHandler::<Spec>::new("gossip_attester_slashing").run();
}

#[test]
fn gossip_voluntary_exit() {
    GossipValidationHandler::<Spec>::latest_stable("gossip_voluntary_exit").run();
}

#[test]
fn gossip_beacon_attestation() {
    GossipValidationHandler::<Spec>::latest_stable("gossip_beacon_attestation").run();
}

#[test]
fn gossip_beacon_aggregate_and_proof() {
    GossipValidationHandler::<Spec>::latest_stable("gossip_beacon_aggregate_and_proof").run();
}

#[test]
fn gossip_bls_to_execution_change() {
    GossipValidationHandler::<Spec>::latest_stable("gossip_bls_to_execution_change").run();
}

#[test]
fn gossip_sync_committee_message() {
    GossipValidationHandler::<Spec>::latest_stable("gossip_sync_committee_message").run();
}

#[test]
fn gossip_sync_committee_contribution_and_proof() {
    GossipValidationHandler::<Spec>::latest_stable("gossip_sync_committee_contribution_and_proof")
        .run();
}
