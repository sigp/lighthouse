#![cfg(feature = "ef_tests")]

use ef_tests::*;
use std::collections::HashMap;
use std::path::PathBuf;
use types::*;

// Check that the config from the Eth2.0 spec tests matches our minimal/mainnet config.
fn config_test<E: EthSpec + TypeName>() {
    let config_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("eth2.0-spec-tests")
        .join("tests")
        .join(E::name())
        .join("config");
    let phase0_config_path = config_dir.join("phase0.yaml");
    let altair_config_path = config_dir.join("altair.yaml");
    let phase0_config = YamlConfig::from_file(&phase0_config_path).expect("config file loads OK");
    let altair_config = AltairConfig::from_file(&altair_config_path).expect("altair config loads");
    let spec = E::default_spec();

    let unified_spec = altair_config
        .apply_to_chain_spec::<E>(
            &phase0_config
                .apply_to_chain_spec::<E>(&spec)
                .expect("phase0 config matches"),
        )
        .expect("altair config matches");

    assert_eq!(unified_spec, spec);

    let phase0_from_spec = YamlConfig::from_spec::<E>(&spec);
    assert_eq!(phase0_from_spec, phase0_config);

    assert_eq!(
        phase0_config.extra_fields,
        HashMap::new(),
        "not all config fields read"
    );
}

#[test]
fn mainnet_config_ok() {
    config_test::<MainnetEthSpec>();
}

#[test]
fn minimal_config_ok() {
    config_test::<MinimalEthSpec>();
}

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
    ShufflingHandler::<MinimalEthSpec>::run();
    ShufflingHandler::<MainnetEthSpec>::run();
}

#[test]
fn operations_deposit() {
    OperationsHandler::<MinimalEthSpec, Deposit>::run();
    OperationsHandler::<MainnetEthSpec, Deposit>::run();
}

#[test]
fn operations_exit() {
    OperationsHandler::<MinimalEthSpec, SignedVoluntaryExit>::run();
    OperationsHandler::<MainnetEthSpec, SignedVoluntaryExit>::run();
}

#[test]
fn operations_proposer_slashing() {
    OperationsHandler::<MinimalEthSpec, ProposerSlashing>::run();
    OperationsHandler::<MainnetEthSpec, ProposerSlashing>::run();
}

#[test]
fn operations_attester_slashing() {
    OperationsHandler::<MinimalEthSpec, AttesterSlashing<_>>::run();
    OperationsHandler::<MainnetEthSpec, AttesterSlashing<_>>::run();
}

#[test]
fn operations_attestation() {
    OperationsHandler::<MinimalEthSpec, Attestation<_>>::run();
    OperationsHandler::<MainnetEthSpec, Attestation<_>>::run();
}

#[test]
fn operations_block_header() {
    OperationsHandler::<MinimalEthSpec, BeaconBlock<_>>::run();
    OperationsHandler::<MainnetEthSpec, BeaconBlock<_>>::run();
}

#[test]
fn sanity_blocks() {
    SanityBlocksHandler::<MinimalEthSpec>::run();
    SanityBlocksHandler::<MainnetEthSpec>::run();
}

#[test]
fn sanity_slots() {
    SanitySlotsHandler::<MinimalEthSpec>::run();
    SanitySlotsHandler::<MainnetEthSpec>::run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn bls_aggregate() {
    BlsAggregateSigsHandler::run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn bls_sign() {
    BlsSignMsgHandler::run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn bls_verify() {
    BlsVerifyMsgHandler::run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn bls_aggregate_verify() {
    BlsAggregateVerifyHandler::run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn bls_fast_aggregate_verify() {
    BlsFastAggregateVerifyHandler::run();
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
                $handler::<$($typ),+>::run();
            )+
        }
    };
}

#[cfg(feature = "fake_crypto")]
mod ssz_static {
    use ef_tests::{get_fork_name, Handler, SszStaticHandler, SszStaticTHCHandler};
    use types::*;

    ssz_static_test!(aggregate_and_proof, AggregateAndProof<_>);
    ssz_static_test!(attestation, Attestation<_>);
    ssz_static_test!(attestation_data, AttestationData);
    ssz_static_test!(attester_slashing, AttesterSlashing<_>);
    ssz_static_test!(beacon_block, BeaconBlock<_>);
    ssz_static_test!(beacon_block_header, BeaconBlockHeader);
    ssz_static_test!(
        beacon_state,
        SszStaticTHCHandler, {
            (BeaconState<MinimalEthSpec>, BeaconTreeHashCache<_>, MinimalEthSpec),
            (BeaconState<MainnetEthSpec>, BeaconTreeHashCache<_>, MainnetEthSpec)
        }
    );
    ssz_static_test!(checkpoint, Checkpoint);
    // FIXME(altair): add ContributionAndProof
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
    ssz_static_test!(signed_beacon_block, SignedBeaconBlock<_>);
    ssz_static_test!(signed_beacon_block_header, SignedBeaconBlockHeader);
    // FIXME(altair): add SignedContributionAndProof
    ssz_static_test!(signed_voluntary_exit, SignedVoluntaryExit);
    ssz_static_test!(signing_data, SigningData);
    // FIXME(altair): add SyncCommitteeContribution/Signature/SigningData
    ssz_static_test!(validator, Validator);
    ssz_static_test!(voluntary_exit, VoluntaryExit);

    // BeaconBlockBody has no internal indicator of which fork it is for, so we test it
    // separately.
    ssz_static_test_no_run!(beacon_block_body_phase0, BeaconBlockBodyBase<_>);
    ssz_static_test_no_run!(beacon_block_body_altair, BeaconBlockBodyAltair<_>);
    #[test]
    fn beacon_block_body() {
        fork_variant_test(beacon_block_body_phase0, beacon_block_body_altair);
    }

    ssz_static_test_no_run!(sync_aggregate_altair, SyncAggregate<_>);
    #[test]
    fn sync_aggregate() {
        fork_variant_test(|| (), sync_aggregate_altair);
    }

    ssz_static_test_no_run!(sync_committee_altair, SyncCommittee<_>);
    #[test]
    fn sync_committee() {
        fork_variant_test(|| (), sync_committee_altair);
    }

    fn fork_variant_test(phase0: impl FnOnce(), altair: impl FnOnce()) {
        match get_fork_name().as_str() {
            "phase0" => phase0(),
            "altair" => altair(),
            fork_name => panic!("unknown fork: {}", fork_name),
        }
    }
}

#[test]
fn ssz_generic() {
    SszGenericHandler::<BasicVector>::run();
    SszGenericHandler::<Bitlist>::run();
    SszGenericHandler::<Bitvector>::run();
    SszGenericHandler::<Boolean>::run();
    SszGenericHandler::<Uints>::run();
    SszGenericHandler::<Containers>::run();
}

#[test]
fn epoch_processing_justification_and_finalization() {
    EpochProcessingHandler::<MinimalEthSpec, JustificationAndFinalization>::run();
    EpochProcessingHandler::<MainnetEthSpec, JustificationAndFinalization>::run();
}

#[test]
fn epoch_processing_rewards_and_penalties() {
    EpochProcessingHandler::<MinimalEthSpec, RewardsAndPenalties>::run();
    EpochProcessingHandler::<MainnetEthSpec, RewardsAndPenalties>::run();
}

#[test]
fn epoch_processing_registry_updates() {
    EpochProcessingHandler::<MinimalEthSpec, RegistryUpdates>::run();
    EpochProcessingHandler::<MainnetEthSpec, RegistryUpdates>::run();
}

#[test]
fn epoch_processing_slashings() {
    EpochProcessingHandler::<MinimalEthSpec, Slashings>::run();
    EpochProcessingHandler::<MainnetEthSpec, Slashings>::run();
}

#[test]
fn epoch_processing_eth1_data_reset() {
    EpochProcessingHandler::<MinimalEthSpec, Eth1DataReset>::run();
    EpochProcessingHandler::<MainnetEthSpec, Eth1DataReset>::run();
}

#[test]
fn epoch_processing_effective_balance_updates() {
    EpochProcessingHandler::<MinimalEthSpec, EffectiveBalanceUpdates>::run();
    EpochProcessingHandler::<MainnetEthSpec, EffectiveBalanceUpdates>::run();
}

#[test]
fn epoch_processing_slashings_reset() {
    EpochProcessingHandler::<MinimalEthSpec, SlashingsReset>::run();
    EpochProcessingHandler::<MainnetEthSpec, SlashingsReset>::run();
}

#[test]
fn epoch_processing_randao_mixes_reset() {
    EpochProcessingHandler::<MinimalEthSpec, RandaoMixesReset>::run();
    EpochProcessingHandler::<MainnetEthSpec, RandaoMixesReset>::run();
}

#[test]
fn epoch_processing_historical_roots_update() {
    EpochProcessingHandler::<MinimalEthSpec, HistoricalRootsUpdate>::run();
    EpochProcessingHandler::<MainnetEthSpec, HistoricalRootsUpdate>::run();
}

#[test]
fn epoch_processing_participation_record_updates() {
    EpochProcessingHandler::<MinimalEthSpec, ParticipationRecordUpdates>::run();
    EpochProcessingHandler::<MainnetEthSpec, ParticipationRecordUpdates>::run();
}

#[test]
fn finality() {
    FinalityHandler::<MinimalEthSpec>::run();
    FinalityHandler::<MainnetEthSpec>::run();
}

#[test]
fn genesis_initialization() {
    GenesisInitializationHandler::<MinimalEthSpec>::run();
}

#[test]
fn genesis_validity() {
    GenesisValidityHandler::<MinimalEthSpec>::run();
    // Note: there are no genesis validity tests for mainnet
}
