#![cfg(feature = "ef_tests")]

use ef_tests::*;
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
    OperationsHandler::<MinimalEthSpec, FullPayload<_>>::default().run();
    OperationsHandler::<MainnetEthSpec, FullPayload<_>>::default().run();
}

#[test]
fn operations_execution_payload_blinded() {
    OperationsHandler::<MinimalEthSpec, BlindedPayload<_>>::default().run();
    OperationsHandler::<MainnetEthSpec, BlindedPayload<_>>::default().run();
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
    use types::*;

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
    // NOTE: LightClient* intentionally omitted
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
        SszStaticHandler::<BeaconBlockBodyMerge<MinimalEthSpec>, MinimalEthSpec>::merge_only()
            .run();
        SszStaticHandler::<BeaconBlockBodyMerge<MainnetEthSpec>, MainnetEthSpec>::merge_only()
            .run();
        SszStaticHandler::<BeaconBlockBodyCapella<MinimalEthSpec>, MinimalEthSpec>::capella_only()
            .run();
        SszStaticHandler::<BeaconBlockBodyCapella<MainnetEthSpec>, MainnetEthSpec>::capella_only()
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

    // Merge and later
    #[test]
    fn execution_payload() {
        SszStaticHandler::<ExecutionPayloadMerge<MinimalEthSpec>, MinimalEthSpec>::merge_only()
            .run();
        SszStaticHandler::<ExecutionPayloadMerge<MainnetEthSpec>, MainnetEthSpec>::merge_only()
            .run();
        SszStaticHandler::<ExecutionPayloadCapella<MinimalEthSpec>, MinimalEthSpec>::capella_only()
            .run();
        SszStaticHandler::<ExecutionPayloadCapella<MainnetEthSpec>, MainnetEthSpec>::capella_only()
            .run();
    }

    #[test]
    fn execution_payload_header() {
        SszStaticHandler::<ExecutionPayloadHeaderMerge<MinimalEthSpec>, MinimalEthSpec>::merge_only()
            .run();
        SszStaticHandler::<ExecutionPayloadHeaderMerge<MainnetEthSpec>, MainnetEthSpec>::merge_only()
            .run();
        SszStaticHandler::<ExecutionPayloadHeaderCapella<MinimalEthSpec>, MinimalEthSpec>
            ::capella_only().run();
        SszStaticHandler::<ExecutionPayloadHeaderCapella<MainnetEthSpec>, MainnetEthSpec>
            ::capella_only().run();
    }

    #[test]
    fn withdrawal() {
        SszStaticHandler::<Withdrawal, MinimalEthSpec>::capella_only().run();
        SszStaticHandler::<Withdrawal, MainnetEthSpec>::capella_only().run();
    }

    #[test]
    fn bls_to_execution_change() {
        SszStaticHandler::<BlsToExecutionChange, MinimalEthSpec>::capella_only().run();
        SszStaticHandler::<BlsToExecutionChange, MainnetEthSpec>::capella_only().run();
    }

    #[test]
    fn signed_bls_to_execution_change() {
        SszStaticHandler::<SignedBlsToExecutionChange, MinimalEthSpec>::capella_only().run();
        SszStaticHandler::<SignedBlsToExecutionChange, MainnetEthSpec>::capella_only().run();
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
fn rewards() {
    for handler in &["basic", "leak", "random"] {
        RewardsHandler::<MinimalEthSpec>::new(handler).run();
        RewardsHandler::<MainnetEthSpec>::new(handler).run();
    }
}
