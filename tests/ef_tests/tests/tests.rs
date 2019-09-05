use ef_tests::*;
use types::*;

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
fn operations_transfer() {
    OperationsHandler::<MinimalEthSpec, Transfer>::run();
    // Note: there are no transfer tests for mainnet
}

#[test]
fn operations_exit() {
    OperationsHandler::<MinimalEthSpec, VoluntaryExit>::run();
    OperationsHandler::<MainnetEthSpec, VoluntaryExit>::run();
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
fn bls_aggregate_pubkeys() {
    BlsAggregatePubkeysHandler::run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn bls_aggregate_sigs() {
    BlsAggregateSigsHandler::run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn bls_msg_hash_g2_compressed() {
    BlsG2CompressedHandler::run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn bls_priv_to_pub() {
    BlsPrivToPubHandler::run();
}

#[test]
#[cfg(not(feature = "fake_crypto"))]
fn bls_sign_msg() {
    BlsSignMsgHandler::run();
}

#[cfg(feature = "fake_crypto")]
macro_rules! ssz_static_test {
    // Signed-root
    ($test_name:ident, $typ:ident$(<$generics:tt>)?, SR) => {
        ssz_static_test!($test_name, SszStaticSRHandler, $typ$(<$generics>)?);
    };
    // Non-signed root
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
    ($test_name:ident, $handler:ident, { $(($typ:ty, $spec:ident)),+ }) => {
        #[test]
        fn $test_name() {
            $(
                $handler::<$typ, $spec>::run();
            )+
        }
    };
}

#[cfg(feature = "fake_crypto")]
mod ssz_static {
    use ef_tests::{Handler, SszStaticHandler, SszStaticSRHandler};
    use types::*;

    ssz_static_test!(attestation, Attestation<_>, SR);
    ssz_static_test!(attestation_data, AttestationData);
    ssz_static_test!(
        attestation_data_and_custody_bit,
        AttestationDataAndCustodyBit
    );
    ssz_static_test!(attester_slashing, AttesterSlashing<_>);
    ssz_static_test!(beacon_block, BeaconBlock<_>, SR);
    ssz_static_test!(beacon_block_body, BeaconBlockBody<_>);
    ssz_static_test!(beacon_block_header, BeaconBlockHeader, SR);
    ssz_static_test!(beacon_state, BeaconState<_>);
    ssz_static_test!(checkpoint, Checkpoint);
    ssz_static_test!(compact_committee, CompactCommittee<_>);
    ssz_static_test!(crosslink, Crosslink);
    ssz_static_test!(deposit, Deposit);
    ssz_static_test!(deposit_data, DepositData, SR);
    ssz_static_test!(eth1_data, Eth1Data);
    ssz_static_test!(fork, Fork);
    ssz_static_test!(historical_batch, HistoricalBatch<_>);
    ssz_static_test!(indexed_attestation, IndexedAttestation<_>, SR);
    ssz_static_test!(pending_attestation, PendingAttestation<_>);
    ssz_static_test!(proposer_slashing, ProposerSlashing);
    ssz_static_test!(transfer, Transfer, SR);
    ssz_static_test!(validator, Validator);
    ssz_static_test!(voluntary_exit, VoluntaryExit, SR);
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
fn epoch_processing_crosslinks() {
    EpochProcessingHandler::<MinimalEthSpec, Crosslinks>::run();
    EpochProcessingHandler::<MainnetEthSpec, Crosslinks>::run();
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
