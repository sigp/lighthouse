//! Mapping from types to canonical string identifiers used in testing.
use types::*;

pub trait TypeName {
    fn name() -> &'static str;
}

#[macro_export]
macro_rules! type_name {
    ($typ:ident) => {
        type_name!($typ, stringify!($typ));
    };
    ($typ:ident, $name:expr) => {
        impl TypeName for $typ {
            fn name() -> &'static str {
                $name
            }
        }
    };
}

#[macro_export]
macro_rules! type_name_generic {
    ($typ:ident) => {
        type_name_generic!($typ, stringify!($typ));
    };
    ($typ:ident, $name:expr) => {
        impl<E: EthSpec> TypeName for $typ<E> {
            fn name() -> &'static str {
                $name
            }
        }
    };
}

type_name!(MinimalEthSpec, "minimal");
type_name!(MainnetEthSpec, "mainnet");

type_name_generic!(Attestation);
type_name!(AttestationData);
type_name!(AttestationDataAndCustodyBit);
type_name_generic!(AttesterSlashing);
type_name_generic!(BeaconBlock);
type_name_generic!(BeaconBlockBody);
type_name!(BeaconBlockHeader);
type_name_generic!(BeaconState);
type_name!(Checkpoint);
type_name_generic!(CompactCommittee);
type_name!(Crosslink);
type_name!(Deposit);
type_name!(DepositData);
type_name!(Eth1Data);
type_name!(Fork);
type_name_generic!(HistoricalBatch);
type_name_generic!(IndexedAttestation);
type_name_generic!(PendingAttestation);
type_name!(ProposerSlashing);
type_name!(Transfer);
type_name!(Validator);
type_name!(VoluntaryExit);
