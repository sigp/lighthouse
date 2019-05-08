use crate::*;
use fixed_len_vec::typenum::{Unsigned, U1024, U8, U8192};

pub trait BeaconStateTypes {
    type ShardCount: Unsigned + Clone + Sync + Send;
    type SlotsPerHistoricalRoot: Unsigned + Clone + Sync + Send;
    type LatestRandaoMixesLength: Unsigned + Clone + Sync + Send;
    type LatestActiveIndexRootsLength: Unsigned + Clone + Sync + Send;
    type LatestSlashedExitLength: Unsigned + Clone + Sync + Send;

    fn spec() -> ChainSpec;
}

#[derive(Clone, PartialEq, Debug)]
pub struct FoundationStateTypes;

impl BeaconStateTypes for FoundationStateTypes {
    type ShardCount = U1024;
    type SlotsPerHistoricalRoot = U8192;
    type LatestRandaoMixesLength = U8192;
    type LatestActiveIndexRootsLength = U8192;
    type LatestSlashedExitLength = U8192;

    fn spec() -> ChainSpec {
        ChainSpec::foundation()
    }
}

pub type FoundationBeaconState = BeaconState<FoundationStateTypes>;

#[derive(Clone, PartialEq, Debug)]
pub struct FewValidatorsStateTypes;

impl BeaconStateTypes for FewValidatorsStateTypes {
    type ShardCount = U8;
    type SlotsPerHistoricalRoot = U8192;
    type LatestRandaoMixesLength = U8192;
    type LatestActiveIndexRootsLength = U8192;
    type LatestSlashedExitLength = U8192;

    fn spec() -> ChainSpec {
        ChainSpec::few_validators()
    }
}

pub type FewValidatorsBeaconState = BeaconState<FewValidatorsStateTypes>;
