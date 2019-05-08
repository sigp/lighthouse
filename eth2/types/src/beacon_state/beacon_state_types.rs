use crate::*;
use fixed_len_vec::typenum::{Unsigned, U1024, U8, U8192};

pub trait BeaconStateTypes {
    type ShardCount: Unsigned + Clone + Sync + Send;
    type SlotsPerHistoricalRoot: Unsigned + Clone + Sync + Send;
    type LatestRandaoMixesLength: Unsigned + Clone + Sync + Send;
    type LatestActiveIndexRootsLength: Unsigned + Clone + Sync + Send;
    type LatestSlashedExitLength: Unsigned + Clone + Sync + Send;
}

#[derive(Clone, PartialEq, Debug)]
pub struct FoundationStateParams;

impl BeaconStateTypes for FoundationStateParams {
    type ShardCount = U1024;
    type SlotsPerHistoricalRoot = U8192;
    type LatestRandaoMixesLength = U8192;
    type LatestActiveIndexRootsLength = U8192;
    type LatestSlashedExitLength = U8192;
}

pub type FoundationBeaconState = BeaconState<FoundationStateParams>;

#[derive(Clone, PartialEq, Debug)]
pub struct FewValidatorsStateParams;

impl BeaconStateTypes for FewValidatorsStateParams {
    type ShardCount = U8;
    type SlotsPerHistoricalRoot = U8192;
    type LatestRandaoMixesLength = U8192;
    type LatestActiveIndexRootsLength = U8192;
    type LatestSlashedExitLength = U8192;
}

pub type FewValidatorsBeaconState = BeaconState<FewValidatorsStateParams>;
