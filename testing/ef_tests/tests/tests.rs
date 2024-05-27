#![cfg(feature = "ef_tests")]

use ef_tests::*;
use types::{MainnetEthSpec, MinimalEthSpec, *};

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
}

#[test]
fn derived_typenum_values() {
    check_typenum_values::<MinimalEthSpec>();
    check_typenum_values::<MainnetEthSpec>();
}

#[test]
fn shuffling() {
    ShufflingHandler::<MinimalEthSpec>::default().run();
    ShufflingHandler::<MainnetEthSpec>::default().run();
}

#[test]
fn operations_deposit() {
    OperationsHandler::<MinimalEthSpec, Deposit>::default().run();
    OperationsHandler::<MainnetEthSpec, Deposit>::default().run();
}

#[test]
fn operations_exit() {
    OperationsHandler::<MinimalEthSpec, SignedVoluntaryExit>::default().run();
    OperationsHandler::<MainnetEthSpec, SignedVoluntaryExit>::default().run();
}

#[test]
fn operations_proposer_slashing() {
    OperationsHandler::<MinimalEthSpec, ProposerSlashing>::default().run();
    OperationsHandler::<MainnetEthSpec, ProposerSlashing>::default().run();
}

#[test]
fn operations_attester_slashing() {
    OperationsHandler::<MinimalEthSpec, AttesterSlashing<_>>::default().run();
    OperationsHandler::<MainnetEthSpec, AttesterSlashing<_>>::default().run();
}

#[test]
fn operations_attestation() {
    OperationsHandler::<MinimalEthSpec, Attestation<_>>::default().run();
    OperationsHandler::<MainnetEthSpec, Attestation<_>>::default().run();
}

#[test]
fn operations_block_header() {
    OperationsHandler::<MinimalEthSpec, BeaconBlock<_>>::default().run();
    OperationsHandler::<MainnetEthSpec, BeaconBlock<_>>::default().run();
}

#[test]
fn operations_sync_aggregate() {
    OperationsHandler::<MinimalEthSpec, SyncAggregate<_>>::default().run();
    OperationsHandler::<MainnetEthSpec, SyncAggregate<_>>::default().run();
}

#[test]
fn operations_execution_payload_full() {
    OperationsHandler::<MinimalEthSpec, BeaconBlockBody<_, FullPayload<_>>>::default().run();
    OperationsHandler::<MainnetEthSpec, BeaconBlockBody<_, FullPayload<_>>>::default().run();
}

#[test]
fn operations_execution_payload_blinded() {
    OperationsHandler::<MinimalEthSpec, BeaconBlockBody<_, BlindedPayload<_>>>::default().run();
    OperationsHandler::<MainnetEthSpec, BeaconBlockBody<_, BlindedPayload<_>>>::default().run();
}

#[test]
fn operations_withdrawals() {
    OperationsHandler::<MinimalEthSpec, WithdrawalsPayload<_>>::default().run();
    OperationsHandler::<MainnetEthSpec, WithdrawalsPayload<_>>::default().run();
}

#[test]
fn operations_bls_to_execution_change() {
    OperationsHandler::<MinimalEthSpec, SignedBlsToExecutionChange>::default().run();
    OperationsHandler::<MainnetEthSpec, SignedBlsToExecutionChange>::default().run();
}

#[test]
fn sanity_blocks() {
    SanityBlocksHandler::<MinimalEthSpec>::default().run();
    SanityBlocksHandler::<MainnetEthSpec>::default().run();
}

#[test]
fn sanity_slots() {
    SanitySlotsHandler::<MinimalEthSpec>::default().run();
    SanitySlotsHandler::<MainnetEthSpec>::default().run();
}

#[test]
fn random() {
    RandomHandler::<MinimalEthSpec>::default().run();
    RandomHandler::<MainnetEthSpec>::default().run();
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
/// Quite complex in order to support an optional #[test] attrib, generics, and the two EthSpecs.
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
                ($typ<MinimalEthSpec>, MinimalEthSpec),
                ($typ<MainnetEthSpec>, MainnetEthSpec)
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
                ($typ, MinimalEthSpec),
                ($typ, MainnetEthSpec)
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
    use types::blob_sidecar::BlobIdentifier;
    use types::historical_summary::HistoricalSummary;
    use types::{LightClientBootstrapAltair, *};

    ssz_static_test!(aggregate_and_proof, AggregateAndProof<_>);
    ssz_static_test!(attestation, Attestation<_>);
    ssz_static_test!(attestation_data, AttestationData);
    ssz_static_test!(attester_slashing, AttesterSlashing<_>);
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
    ssz_static_test!(historical_batch, HistoricalBatch<_>);
    ssz_static_test!(indexed_attestation, IndexedAttestation<_>);
    ssz_static_test!(pending_attestation, PendingAttestation<_>);
    ssz_static_test!(proposer_slashing, ProposerSlashing);
    ssz_static_test!(signed_aggregate_and_proof, SignedAggregateAndProof<_>);
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
    // BeaconBlockBody has no internal indicator of which fork it is for, so we test it separately.
    #[test]
    fn beacon_block_body() {
        SszStaticHandler::<BeaconBlockBodyBase<MinimalEthSpec>, MinimalEthSpec>::base_only().run();
        SszStaticHandler::<BeaconBlockBodyBase<MainnetEthSpec>, MainnetEthSpec>::base_only().run();
        SszStaticHandler::<BeaconBlockBodyAltair<MinimalEthSpec>, MinimalEthSpec>::altair_only()
            .run();
        SszStaticHandler::<BeaconBlockBodyAltair<MainnetEthSpec>, MainnetEthSpec>::altair_only()
            .run();
        SszStaticHandler::<BeaconBlockBodyBellatrix<MinimalEthSpec>, MinimalEthSpec>::bellatrix_only()
            .run();
        SszStaticHandler::<BeaconBlockBodyBellatrix<MainnetEthSpec>, MainnetEthSpec>::bellatrix_only()
            .run();
        SszStaticHandler::<BeaconBlockBodyCapella<MinimalEthSpec>, MinimalEthSpec>::capella_only()
            .run();
        SszStaticHandler::<BeaconBlockBodyCapella<MainnetEthSpec>, MainnetEthSpec>::capella_only()
            .run();
        SszStaticHandler::<BeaconBlockBodyDeneb<MinimalEthSpec>, MinimalEthSpec>::deneb_only()
            .run();
        SszStaticHandler::<BeaconBlockBodyDeneb<MainnetEthSpec>, MainnetEthSpec>::deneb_only()
            .run();
    }

    // Altair and later
    #[test]
    fn contribution_and_proof() {
        SszStaticHandler::<ContributionAndProof<MinimalEthSpec>, MinimalEthSpec>::altair_and_later(
        )
        .run();
        SszStaticHandler::<ContributionAndProof<MainnetEthSpec>, MainnetEthSpec>::altair_and_later(
        )
        .run();
    }

    // LightClientBootstrap has no internal indicator of which fork it is for, so we test it separately.
    #[test]
    fn light_client_bootstrap() {
        SszStaticHandler::<LightClientBootstrapAltair<MinimalEthSpec>, MinimalEthSpec>::altair_only()
            .run();
        SszStaticHandler::<LightClientBootstrapAltair<MainnetEthSpec>, MainnetEthSpec>::altair_only()
            .run();
        SszStaticHandler::<LightClientBootstrapAltair<MinimalEthSpec>, MinimalEthSpec>::bellatrix_only(
        )
        .run();
        SszStaticHandler::<LightClientBootstrapAltair<MainnetEthSpec>, MainnetEthSpec>::bellatrix_only(
        )
        .run();
        SszStaticHandler::<LightClientBootstrapCapella<MinimalEthSpec>, MinimalEthSpec>::capella_only()
            .run();
        SszStaticHandler::<LightClientBootstrapCapella<MainnetEthSpec>, MainnetEthSpec>::capella_only()
            .run();
        SszStaticHandler::<LightClientBootstrapDeneb<MinimalEthSpec>, MinimalEthSpec>::deneb_only()
            .run();
        SszStaticHandler::<LightClientBootstrapDeneb<MainnetEthSpec>, MainnetEthSpec>::deneb_only()
            .run();
    }

    // LightClientHeader has no internal indicator of which fork it is for, so we test it separately.
    #[test]
    fn light_client_header() {
        SszStaticHandler::<LightClientHeaderAltair<MinimalEthSpec>, MinimalEthSpec>::altair_only()
            .run();
        SszStaticHandler::<LightClientHeaderAltair<MainnetEthSpec>, MainnetEthSpec>::altair_only()
            .run();
        SszStaticHandler::<LightClientHeaderAltair<MinimalEthSpec>, MinimalEthSpec>::bellatrix_only()
            .run();
        SszStaticHandler::<LightClientHeaderAltair<MainnetEthSpec>, MainnetEthSpec>::bellatrix_only()
            .run();

        SszStaticHandler::<LightClientHeaderCapella<MinimalEthSpec>, MinimalEthSpec>::capella_only(
        )
        .run();
        SszStaticHandler::<LightClientHeaderCapella<MainnetEthSpec>, MainnetEthSpec>::capella_only(
        )
        .run();

        SszStaticHandler::<LightClientHeaderDeneb<MinimalEthSpec>, MinimalEthSpec>::deneb_only()
            .run();
        SszStaticHandler::<LightClientHeaderDeneb<MainnetEthSpec>, MainnetEthSpec>::deneb_only()
            .run();
    }

    // LightClientOptimisticUpdate has no internal indicator of which fork it is for, so we test it separately.
    #[test]
    fn light_client_optimistic_update() {
        SszStaticHandler::<LightClientOptimisticUpdateAltair<MinimalEthSpec>, MinimalEthSpec>::altair_only(
        )
            .run();
        SszStaticHandler::<LightClientOptimisticUpdateAltair<MainnetEthSpec>, MainnetEthSpec>::altair_only(
        )
            .run();
        SszStaticHandler::<LightClientOptimisticUpdateAltair<MinimalEthSpec>, MinimalEthSpec>::bellatrix_only(
        )
            .run();
        SszStaticHandler::<LightClientOptimisticUpdateAltair<MainnetEthSpec>, MainnetEthSpec>::bellatrix_only(
        )
            .run();
        SszStaticHandler::<LightClientOptimisticUpdateCapella<MinimalEthSpec>, MinimalEthSpec>::capella_only(
        )
            .run();
        SszStaticHandler::<LightClientOptimisticUpdateCapella<MainnetEthSpec>, MainnetEthSpec>::capella_only(
        )
            .run();
        SszStaticHandler::<LightClientOptimisticUpdateDeneb<MinimalEthSpec>, MinimalEthSpec>::deneb_only(
        )
            .run();
        SszStaticHandler::<LightClientOptimisticUpdateDeneb<MainnetEthSpec>, MainnetEthSpec>::deneb_only(
        )
            .run();
    }

    // LightClientFinalityUpdate has no internal indicator of which fork it is for, so we test it separately.
    #[test]
    fn light_client_finality_update() {
        SszStaticHandler::<LightClientFinalityUpdateAltair<MinimalEthSpec>, MinimalEthSpec>::altair_only(
        )
            .run();
        SszStaticHandler::<LightClientFinalityUpdateAltair<MainnetEthSpec>, MainnetEthSpec>::altair_only(
        )
            .run();
        SszStaticHandler::<LightClientFinalityUpdateAltair<MinimalEthSpec>, MinimalEthSpec>::bellatrix_only(
        )
            .run();
        SszStaticHandler::<LightClientFinalityUpdateAltair<MainnetEthSpec>, MainnetEthSpec>::bellatrix_only(
        )
            .run();
        SszStaticHandler::<LightClientFinalityUpdateCapella<MinimalEthSpec>, MinimalEthSpec>::capella_only(
        )
            .run();
        SszStaticHandler::<LightClientFinalityUpdateCapella<MainnetEthSpec>, MainnetEthSpec>::capella_only(
        )
            .run();
        SszStaticHandler::<LightClientFinalityUpdateDeneb<MinimalEthSpec>, MinimalEthSpec>::deneb_only(
        )
            .run();
        SszStaticHandler::<LightClientFinalityUpdateDeneb<MainnetEthSpec>, MainnetEthSpec>::deneb_only(
        )
            .run();
    }

    // LightClientUpdate has no internal indicator of which fork it is for, so we test it separately.
    #[test]
    fn light_client_update() {
        SszStaticHandler::<LightClientUpdateAltair<MinimalEthSpec>, MinimalEthSpec>::altair_only()
            .run();
        SszStaticHandler::<LightClientUpdateAltair<MainnetEthSpec>, MainnetEthSpec>::altair_only()
            .run();
        SszStaticHandler::<LightClientUpdateAltair<MinimalEthSpec>, MinimalEthSpec>::bellatrix_only()
            .run();
        SszStaticHandler::<LightClientUpdateAltair<MainnetEthSpec>, MainnetEthSpec>::bellatrix_only()
            .run();
        SszStaticHandler::<LightClientUpdateCapella<MinimalEthSpec>, MinimalEthSpec>::capella_only(
        )
        .run();
        SszStaticHandler::<LightClientUpdateCapella<MainnetEthSpec>, MainnetEthSpec>::capella_only(
        )
        .run();
        SszStaticHandler::<LightClientUpdateDeneb<MinimalEthSpec>, MinimalEthSpec>::deneb_only()
            .run();
        SszStaticHandler::<LightClientUpdateDeneb<MainnetEthSpec>, MainnetEthSpec>::deneb_only()
            .run();
    }

    #[test]
    fn signed_contribution_and_proof() {
        SszStaticHandler::<SignedContributionAndProof<MinimalEthSpec>, MinimalEthSpec>::altair_and_later().run();
        SszStaticHandler::<SignedContributionAndProof<MainnetEthSpec>, MainnetEthSpec>::altair_and_later().run();
    }

    #[test]
    fn sync_aggregate() {
        SszStaticHandler::<SyncAggregate<MinimalEthSpec>, MinimalEthSpec>::altair_and_later().run();
        SszStaticHandler::<SyncAggregate<MainnetEthSpec>, MainnetEthSpec>::altair_and_later().run();
    }

    #[test]
    fn sync_committee() {
        SszStaticHandler::<SyncCommittee<MinimalEthSpec>, MinimalEthSpec>::altair_and_later().run();
        SszStaticHandler::<SyncCommittee<MainnetEthSpec>, MainnetEthSpec>::altair_and_later().run();
    }

    #[test]
    fn sync_committee_contribution() {
        SszStaticHandler::<SyncCommitteeContribution<MinimalEthSpec>, MinimalEthSpec>::altair_and_later().run();
        SszStaticHandler::<SyncCommitteeContribution<MainnetEthSpec>, MainnetEthSpec>::altair_and_later().run();
    }

    #[test]
    fn sync_committee_message() {
        SszStaticHandler::<SyncCommitteeMessage, MinimalEthSpec>::altair_and_later().run();
        SszStaticHandler::<SyncCommitteeMessage, MainnetEthSpec>::altair_and_later().run();
    }

    #[test]
    fn sync_aggregator_selection_data() {
        SszStaticHandler::<SyncAggregatorSelectionData, MinimalEthSpec>::altair_and_later().run();
        SszStaticHandler::<SyncAggregatorSelectionData, MainnetEthSpec>::altair_and_later().run();
    }

    // Bellatrix and later
    #[test]
    fn execution_payload() {
        SszStaticHandler::<ExecutionPayloadBellatrix<MinimalEthSpec>, MinimalEthSpec>::bellatrix_only()
            .run();
        SszStaticHandler::<ExecutionPayloadBellatrix<MainnetEthSpec>, MainnetEthSpec>::bellatrix_only()
            .run();
        SszStaticHandler::<ExecutionPayloadCapella<MinimalEthSpec>, MinimalEthSpec>::capella_only()
            .run();
        SszStaticHandler::<ExecutionPayloadCapella<MainnetEthSpec>, MainnetEthSpec>::capella_only()
            .run();
        SszStaticHandler::<ExecutionPayloadDeneb<MinimalEthSpec>, MinimalEthSpec>::deneb_only()
            .run();
        SszStaticHandler::<ExecutionPayloadDeneb<MainnetEthSpec>, MainnetEthSpec>::deneb_only()
            .run();
    }

    #[test]
    fn execution_payload_header() {
        SszStaticHandler::<ExecutionPayloadHeaderBellatrix<MinimalEthSpec>, MinimalEthSpec>::bellatrix_only()
            .run();
        SszStaticHandler::<ExecutionPayloadHeaderBellatrix<MainnetEthSpec>, MainnetEthSpec>::bellatrix_only()
            .run();
        SszStaticHandler::<ExecutionPayloadHeaderCapella<MinimalEthSpec>, MinimalEthSpec>
            ::capella_only().run();
        SszStaticHandler::<ExecutionPayloadHeaderCapella<MainnetEthSpec>, MainnetEthSpec>
            ::capella_only().run();
        SszStaticHandler::<ExecutionPayloadHeaderDeneb<MinimalEthSpec>, MinimalEthSpec>
            ::deneb_only().run();
        SszStaticHandler::<ExecutionPayloadHeaderDeneb<MainnetEthSpec>, MainnetEthSpec>
            ::deneb_only().run();
    }

    #[test]
    fn withdrawal() {
        SszStaticHandler::<Withdrawal, MinimalEthSpec>::capella_and_later().run();
        SszStaticHandler::<Withdrawal, MainnetEthSpec>::capella_and_later().run();
    }

    #[test]
    fn bls_to_execution_change() {
        SszStaticHandler::<BlsToExecutionChange, MinimalEthSpec>::capella_and_later().run();
        SszStaticHandler::<BlsToExecutionChange, MainnetEthSpec>::capella_and_later().run();
    }

    #[test]
    fn signed_bls_to_execution_change() {
        SszStaticHandler::<SignedBlsToExecutionChange, MinimalEthSpec>::capella_and_later().run();
        SszStaticHandler::<SignedBlsToExecutionChange, MainnetEthSpec>::capella_and_later().run();
    }

    #[test]
    fn blob_sidecar() {
        SszStaticHandler::<BlobSidecar<MinimalEthSpec>, MinimalEthSpec>::deneb_only().run();
        SszStaticHandler::<BlobSidecar<MainnetEthSpec>, MainnetEthSpec>::deneb_only().run();
    }

    #[test]
    fn blob_identifier() {
        SszStaticHandler::<BlobIdentifier, MinimalEthSpec>::deneb_only().run();
        SszStaticHandler::<BlobIdentifier, MainnetEthSpec>::deneb_only().run();
    }

    #[test]
    fn historical_summary() {
        SszStaticHandler::<HistoricalSummary, MinimalEthSpec>::capella_and_later().run();
        SszStaticHandler::<HistoricalSummary, MainnetEthSpec>::capella_and_later().run();
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
}

#[test]
fn epoch_processing_justification_and_finalization() {
    EpochProcessingHandler::<MinimalEthSpec, JustificationAndFinalization>::default().run();
    EpochProcessingHandler::<MainnetEthSpec, JustificationAndFinalization>::default().run();
}

#[test]
fn epoch_processing_rewards_and_penalties() {
    EpochProcessingHandler::<MinimalEthSpec, RewardsAndPenalties>::default().run();
    EpochProcessingHandler::<MainnetEthSpec, RewardsAndPenalties>::default().run();
}

#[test]
fn epoch_processing_registry_updates() {
    EpochProcessingHandler::<MinimalEthSpec, RegistryUpdates>::default().run();
    EpochProcessingHandler::<MainnetEthSpec, RegistryUpdates>::default().run();
}

#[test]
fn epoch_processing_slashings() {
    EpochProcessingHandler::<MinimalEthSpec, Slashings>::default().run();
    EpochProcessingHandler::<MainnetEthSpec, Slashings>::default().run();
}

#[test]
fn epoch_processing_eth1_data_reset() {
    EpochProcessingHandler::<MinimalEthSpec, Eth1DataReset>::default().run();
    EpochProcessingHandler::<MainnetEthSpec, Eth1DataReset>::default().run();
}

#[test]
fn epoch_processing_effective_balance_updates() {
    EpochProcessingHandler::<MinimalEthSpec, EffectiveBalanceUpdates>::default().run();
    EpochProcessingHandler::<MainnetEthSpec, EffectiveBalanceUpdates>::default().run();
}

#[test]
fn epoch_processing_slashings_reset() {
    EpochProcessingHandler::<MinimalEthSpec, SlashingsReset>::default().run();
    EpochProcessingHandler::<MainnetEthSpec, SlashingsReset>::default().run();
}

#[test]
fn epoch_processing_randao_mixes_reset() {
    EpochProcessingHandler::<MinimalEthSpec, RandaoMixesReset>::default().run();
    EpochProcessingHandler::<MainnetEthSpec, RandaoMixesReset>::default().run();
}

#[test]
fn epoch_processing_historical_roots_update() {
    EpochProcessingHandler::<MinimalEthSpec, HistoricalRootsUpdate>::default().run();
    EpochProcessingHandler::<MainnetEthSpec, HistoricalRootsUpdate>::default().run();
}

#[test]
fn epoch_processing_historical_summaries_update() {
    EpochProcessingHandler::<MinimalEthSpec, HistoricalSummariesUpdate>::default().run();
    EpochProcessingHandler::<MainnetEthSpec, HistoricalSummariesUpdate>::default().run();
}

#[test]
fn epoch_processing_participation_record_updates() {
    EpochProcessingHandler::<MinimalEthSpec, ParticipationRecordUpdates>::default().run();
    EpochProcessingHandler::<MainnetEthSpec, ParticipationRecordUpdates>::default().run();
}

#[test]
fn epoch_processing_sync_committee_updates() {
    // There are presently no mainnet tests, see:
    // https://github.com/ethereum/consensus-spec-tests/issues/29
    EpochProcessingHandler::<MinimalEthSpec, SyncCommitteeUpdates>::default().run();
}

#[test]
fn epoch_processing_inactivity_updates() {
    EpochProcessingHandler::<MinimalEthSpec, InactivityUpdates>::default().run();
    EpochProcessingHandler::<MainnetEthSpec, InactivityUpdates>::default().run();
}

#[test]
fn epoch_processing_participation_flag_updates() {
    EpochProcessingHandler::<MinimalEthSpec, ParticipationFlagUpdates>::default().run();
    EpochProcessingHandler::<MainnetEthSpec, ParticipationFlagUpdates>::default().run();
}

#[test]
fn fork_upgrade() {
    ForkHandler::<MinimalEthSpec>::default().run();
    ForkHandler::<MainnetEthSpec>::default().run();
}

#[test]
fn transition() {
    TransitionHandler::<MinimalEthSpec>::default().run();
    TransitionHandler::<MainnetEthSpec>::default().run();
}

#[test]
fn finality() {
    FinalityHandler::<MinimalEthSpec>::default().run();
    FinalityHandler::<MainnetEthSpec>::default().run();
}

#[test]
fn fork_choice_get_head() {
    ForkChoiceHandler::<MinimalEthSpec>::new("get_head").run();
    ForkChoiceHandler::<MainnetEthSpec>::new("get_head").run();
}

#[test]
fn fork_choice_on_block() {
    ForkChoiceHandler::<MinimalEthSpec>::new("on_block").run();
    ForkChoiceHandler::<MainnetEthSpec>::new("on_block").run();
}

#[test]
fn fork_choice_on_merge_block() {
    ForkChoiceHandler::<MinimalEthSpec>::new("on_merge_block").run();
    ForkChoiceHandler::<MainnetEthSpec>::new("on_merge_block").run();
}

#[test]
fn fork_choice_ex_ante() {
    ForkChoiceHandler::<MinimalEthSpec>::new("ex_ante").run();
    ForkChoiceHandler::<MainnetEthSpec>::new("ex_ante").run();
}

#[test]
fn fork_choice_reorg() {
    ForkChoiceHandler::<MinimalEthSpec>::new("reorg").run();
    // There is no mainnet variant for this test.
}

#[test]
fn fork_choice_withholding() {
    ForkChoiceHandler::<MinimalEthSpec>::new("withholding").run();
    // There is no mainnet variant for this test.
}

#[test]
fn fork_choice_should_override_forkchoice_update() {
    ForkChoiceHandler::<MinimalEthSpec>::new("should_override_forkchoice_update").run();
    ForkChoiceHandler::<MainnetEthSpec>::new("should_override_forkchoice_update").run();
}

#[test]
fn fork_choice_get_proposer_head() {
    ForkChoiceHandler::<MinimalEthSpec>::new("get_proposer_head").run();
    ForkChoiceHandler::<MainnetEthSpec>::new("get_proposer_head").run();
}

#[test]
fn optimistic_sync() {
    OptimisticSyncHandler::<MinimalEthSpec>::default().run();
    OptimisticSyncHandler::<MainnetEthSpec>::default().run();
}

#[test]
fn genesis_initialization() {
    GenesisInitializationHandler::<MinimalEthSpec>::default().run();
}

#[test]
fn genesis_validity() {
    GenesisValidityHandler::<MinimalEthSpec>::default().run();
    // Note: there are no genesis validity tests for mainnet
}

#[test]
fn kzg_blob_to_kzg_commitment() {
    KZGBlobToKZGCommitmentHandler::<MainnetEthSpec>::default().run();
}

#[test]
fn kzg_compute_blob_kzg_proof() {
    KZGComputeBlobKZGProofHandler::<MainnetEthSpec>::default().run();
}

#[test]
fn kzg_compute_kzg_proof() {
    KZGComputeKZGProofHandler::<MainnetEthSpec>::default().run();
}

#[test]
fn kzg_verify_blob_kzg_proof() {
    KZGVerifyBlobKZGProofHandler::<MainnetEthSpec>::default().run();
}

#[test]
fn kzg_verify_blob_kzg_proof_batch() {
    KZGVerifyBlobKZGProofBatchHandler::<MainnetEthSpec>::default().run();
}

#[test]
fn kzg_verify_kzg_proof() {
    KZGVerifyKZGProofHandler::<MainnetEthSpec>::default().run();
}

#[test]
fn merkle_proof_validity() {
    MerkleProofValidityHandler::<MainnetEthSpec>::default().run();
}

#[test]
#[cfg(feature = "fake_crypto")]
fn kzg_inclusion_merkle_proof_validity() {
    KzgInclusionMerkleProofValidityHandler::<MainnetEthSpec>::default().run();
    KzgInclusionMerkleProofValidityHandler::<MinimalEthSpec>::default().run();
}

#[test]
fn rewards() {
    for handler in &["basic", "leak", "random"] {
        RewardsHandler::<MinimalEthSpec>::new(handler).run();
        RewardsHandler::<MainnetEthSpec>::new(handler).run();
    }
}
