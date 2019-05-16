use crate::*;
use fixed_len_vec::typenum::{Unsigned, U1024, U8, U8192};
use serde_derive::{Deserialize, Serialize};
use std::fmt::Debug;

pub trait EthSpec:
    'static + Default + Sync + Send + Clone + Debug + PartialEq + serde::de::DeserializeOwned
{
    type ShardCount: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type SlotsPerHistoricalRoot: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type LatestRandaoMixesLength: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type LatestActiveIndexRootsLength: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type LatestSlashedExitLength: Unsigned + Clone + Sync + Send + Debug + PartialEq;

    fn spec() -> ChainSpec;

    /// Returns the `SLOTS_PER_EPOCH` constant for this specification.
    ///
    /// Spec v0.6.1
    fn slots_per_epoch() -> u64 {
        Self::spec().slots_per_epoch
    }

    /// Returns the `SLOTS_PER_EPOCH` constant for this specification.
    ///
    /// Spec v0.6.1
    fn genesis_epoch() -> Epoch {
        Self::spec().genesis_epoch
    }

    /// Returns the `SHARD_COUNT` constant for this specification.
    ///
    /// Spec v0.5.1
    fn shard_count() -> usize {
        Self::ShardCount::to_usize()
    }

    /// Returns the `SLOTS_PER_HISTORICAL_ROOT` constant for this specification.
    ///
    /// Spec v0.5.1
    fn slots_per_historical_root() -> usize {
        Self::SlotsPerHistoricalRoot::to_usize()
    }

    /// Returns the `LATEST_RANDAO_MIXES_LENGTH` constant for this specification.
    ///
    /// Spec v0.5.1
    fn latest_randao_mixes_length() -> usize {
        Self::LatestRandaoMixesLength::to_usize()
    }

    /// Returns the `LATEST_ACTIVE_INDEX_ROOTS` constant for this specification.
    ///
    /// Spec v0.5.1
    fn latest_active_index_roots() -> usize {
        Self::LatestActiveIndexRootsLength::to_usize()
    }

    /// Returns the `LATEST_SLASHED_EXIT_LENGTH` constant for this specification.
    ///
    /// Spec v0.5.1
    fn latest_slashed_exit_length() -> usize {
        Self::LatestSlashedExitLength::to_usize()
    }
}

/// Ethereum Foundation specifications.
///
/// Spec v0.5.1
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct FoundationEthSpec;

impl EthSpec for FoundationEthSpec {
    type ShardCount = U1024;
    type SlotsPerHistoricalRoot = U8192;
    type LatestRandaoMixesLength = U8192;
    type LatestActiveIndexRootsLength = U8192;
    type LatestSlashedExitLength = U8192;

    fn spec() -> ChainSpec {
        ChainSpec::foundation()
    }
}

pub type FoundationBeaconState = BeaconState<FoundationEthSpec>;

/// Ethereum Foundation specifications, modified to be suitable for < 1000 validators.
///
/// Spec v0.5.1
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct FewValidatorsEthSpec;

impl EthSpec for FewValidatorsEthSpec {
    type ShardCount = U8;
    type SlotsPerHistoricalRoot = U8192;
    type LatestRandaoMixesLength = U8192;
    type LatestActiveIndexRootsLength = U8192;
    type LatestSlashedExitLength = U8192;

    fn spec() -> ChainSpec {
        ChainSpec::few_validators()
    }
}

pub type FewValidatorsBeaconState = BeaconState<FewValidatorsEthSpec>;

/// Specifications suitable for a small-scale (< 1000 validators) lighthouse testnet.
///
/// Spec v0.5.1
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct LighthouseTestnetEthSpec;

impl EthSpec for LighthouseTestnetEthSpec {
    type ShardCount = U8;
    type SlotsPerHistoricalRoot = U8192;
    type LatestRandaoMixesLength = U8192;
    type LatestActiveIndexRootsLength = U8192;
    type LatestSlashedExitLength = U8192;

    fn spec() -> ChainSpec {
        ChainSpec::lighthouse_testnet()
    }
}

pub type LighthouseTestnetBeaconState = BeaconState<LighthouseTestnetEthSpec>;
