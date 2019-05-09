use crate::*;
use fixed_len_vec::typenum::{Unsigned, U1024, U8, U8192};
use serde_derive::{Deserialize, Serialize};
use std::fmt::Debug;

pub trait BeaconStateTypes:
    'static + Default + Sync + Send + Clone + Debug + PartialEq + serde::de::DeserializeOwned
{
    type ShardCount: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type SlotsPerHistoricalRoot: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type LatestRandaoMixesLength: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type LatestActiveIndexRootsLength: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type LatestSlashedExitLength: Unsigned + Clone + Sync + Send + Debug + PartialEq;

    fn spec() -> ChainSpec;
}

/// Ethereum Foundation specifications.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
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

#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
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

#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct LighthouseTestnetStateTypes;

impl BeaconStateTypes for LighthouseTestnetStateTypes {
    type ShardCount = U8;
    type SlotsPerHistoricalRoot = U8192;
    type LatestRandaoMixesLength = U8192;
    type LatestActiveIndexRootsLength = U8192;
    type LatestSlashedExitLength = U8192;

    fn spec() -> ChainSpec {
        ChainSpec::lighthouse_testnet()
    }
}

pub type LighthouseTestnetBeaconState = BeaconState<LighthouseTestnetStateTypes>;
