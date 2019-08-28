//! Mapping from types to canonical string identifiers used in testing.
use types::*;

pub trait TypeName {
    fn name() -> &'static str;
}

impl TypeName for MinimalEthSpec {
    fn name() -> &'static str {
        "minimal"
    }
}

impl TypeName for MainnetEthSpec {
    fn name() -> &'static str {
        "mainnet"
    }
}

macro_rules! impl_name {
    ($typ:ident) => {
        impl TypeName for $typ {
            fn name() -> &'static str {
                stringify!($typ)
            }
        }
    };
}

macro_rules! impl_name_generic {
    ($typ:ident) => {
        impl<E: EthSpec> TypeName for $typ<E> {
            fn name() -> &'static str {
                stringify!($typ)
            }
        }
    };
}

impl_name_generic!(Attestation);
impl_name!(AttestationData);
impl_name!(AttestationDataAndCustodyBit);
impl_name_generic!(AttesterSlashing);
impl_name_generic!(BeaconBlock);
impl_name_generic!(BeaconBlockBody);
impl_name!(BeaconBlockHeader);
impl_name_generic!(BeaconState);
impl_name!(Checkpoint);
impl_name_generic!(CompactCommittee);
impl_name!(Crosslink);
impl_name!(Deposit);
impl_name!(DepositData);
impl_name!(Eth1Data);
impl_name!(Fork);
impl_name_generic!(HistoricalBatch);
impl_name_generic!(IndexedAttestation);
impl_name_generic!(PendingAttestation);
impl_name!(ProposerSlashing);
impl_name!(Transfer);
impl_name!(Validator);
impl_name!(VoluntaryExit);
