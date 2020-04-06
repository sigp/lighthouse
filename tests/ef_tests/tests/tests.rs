#![cfg(feature = "ef_tests")]

use ef_tests::*;
use std::path::PathBuf;
use types::*;

// Check that the config from the Eth2.0 spec tests matches our minimal/mainnet config.
fn config_test<E: EthSpec + TypeName>() {
    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("eth2.0-spec-tests")
        .join("tests")
        .join(E::name())
        .join("config.yaml");
    let yaml_config = YamlConfig::from_file(&config_path).expect("config file loads OK");
    let spec = E::default_spec();
    assert_eq!(yaml_config.apply_to_chain_spec::<E>(&spec), Some(spec));
}

#[test]
fn mainnet_config_ok() {
    config_test::<MainnetEthSpec>();
}

#[test]
fn minimal_config_ok() {
    config_test::<MinimalEthSpec>();
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

#[cfg(feature = "fake_crypto")]
macro_rules! ssz_static_test {
    // Non-tree hash caching
    ($test_name:ident, $typ:ident$(<$generics:tt>)?) => {
        ssz_static_test!($test_name, SszStaticHandler, $typ$(<$generics>)?);
    };
    // Generic
    ($test_name:ident, $handler:ident, $typ:ident<_>) => {
        ssz_static_test!(
            $test_name, $handler, {
                ($typ<MinimalEthSpec>, MinimalEthSpec),
                ($typ<MainnetEthSpec>, MainnetEthSpec)
            }
        );
    };
    // Non-generic
    ($test_name:ident, $handler:ident, $typ:ident) => {
        ssz_static_test!(
            $test_name, $handler, {
                ($typ, MinimalEthSpec),
                ($typ, MainnetEthSpec)
            }
        );
    };
    // Base case
    ($test_name:ident, $handler:ident, { $(($($typ:ty),+)),+ }) => {
        #[test]
        fn $test_name() {
            $(
                $handler::<$($typ),+>::run();
            )+
        }
    };
}

#[cfg(feature = "fake_crypto")]
mod ssz_static {
    use ef_tests::{Handler, SszStaticHandler, SszStaticTHCHandler};
    use types::*;

    ssz_static_test!(attestation, Attestation<_>);
    ssz_static_test!(attestation_data, AttestationData);
    ssz_static_test!(attester_slashing, AttesterSlashing<_>);
    ssz_static_test!(beacon_block, BeaconBlock<_>);
    ssz_static_test!(beacon_block_body, BeaconBlockBody<_>);
    ssz_static_test!(beacon_block_header, BeaconBlockHeader);
    ssz_static_test!(
        beacon_state,
        SszStaticTHCHandler, {
            (BeaconState<MinimalEthSpec>, BeaconTreeHashCache, MinimalEthSpec),
            (BeaconState<MainnetEthSpec>, BeaconTreeHashCache, MainnetEthSpec)
        }
    );
    ssz_static_test!(checkpoint, Checkpoint);
    ssz_static_test!(deposit, Deposit);
    ssz_static_test!(deposit_data, DepositData);
    ssz_static_test!(eth1_data, Eth1Data);
    ssz_static_test!(fork, Fork);
    ssz_static_test!(historical_batch, HistoricalBatch<_>);
    ssz_static_test!(indexed_attestation, IndexedAttestation<_>);
    ssz_static_test!(pending_attestation, PendingAttestation<_>);
    ssz_static_test!(proposer_slashing, ProposerSlashing);
    ssz_static_test!(validator, Validator);
    ssz_static_test!(voluntary_exit, VoluntaryExit);
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
    // Note: there are no reward and penalty tests for mainnet yet
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
fn epoch_processing_final_updates() {
    EpochProcessingHandler::<MainnetEthSpec, FinalUpdates>::run();
    EpochProcessingHandler::<MainnetEthSpec, FinalUpdates>::run();
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
