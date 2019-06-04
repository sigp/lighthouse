use crate::*;
use fixed_len_vec::typenum::{Unsigned, U1024, U8, U8192};
use serde_derive::{Deserialize, Serialize};
use std::fmt::Debug;

pub trait EthSpec: 'static + Default + Sync + Send + Clone + Debug + PartialEq {
    type ShardCount: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type SlotsPerHistoricalRoot: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type LatestRandaoMixesLength: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type LatestActiveIndexRootsLength: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type LatestSlashedExitLength: Unsigned + Clone + Sync + Send + Debug + PartialEq;

    fn spec() -> ChainSpec;

    /// Return the number of committees in one epoch.
    ///
    /// Spec v0.6.1
    fn get_epoch_committee_count(active_validator_count: usize) -> usize {
        let target_committee_size = Self::spec().target_committee_size;
        let shard_count = Self::shard_count();
        let slots_per_epoch = Self::slots_per_epoch() as usize;

        std::cmp::max(
            1,
            std::cmp::min(
                shard_count / slots_per_epoch,
                active_validator_count / slots_per_epoch / target_committee_size,
            ),
        ) * slots_per_epoch
    }

    /// Return the number of shards to increment `state.latest_start_shard` by in a given epoch.
    ///
    /// Spec v0.6.3
    fn get_shard_delta(active_validator_count: usize) -> u64 {
        std::cmp::min(
            Self::get_epoch_committee_count(active_validator_count) as u64,
            Self::ShardCount::to_u64() - Self::ShardCount::to_u64() / Self::spec().slots_per_epoch,
        )
    }

    /// Returns the minimum number of validators required for this spec.
    ///
    /// This is the _absolute_ minimum, the number required to make the chain operate in the most
    /// basic sense. This count is not required to provide any security guarantees regarding
    /// decentralization, entropy, etc.
    fn minimum_validator_count() -> usize {
        Self::slots_per_epoch() as usize
    }

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
    /// Spec v0.6.1
    fn shard_count() -> usize {
        Self::ShardCount::to_usize()
    }

    /// Returns the `SLOTS_PER_HISTORICAL_ROOT` constant for this specification.
    ///
    /// Spec v0.6.1
    fn slots_per_historical_root() -> usize {
        Self::SlotsPerHistoricalRoot::to_usize()
    }

    /// Returns the `LATEST_RANDAO_MIXES_LENGTH` constant for this specification.
    ///
    /// Spec v0.6.1
    fn latest_randao_mixes_length() -> usize {
        Self::LatestRandaoMixesLength::to_usize()
    }

    /// Returns the `LATEST_ACTIVE_INDEX_ROOTS` constant for this specification.
    ///
    /// Spec v0.6.1
    fn latest_active_index_roots() -> usize {
        Self::LatestActiveIndexRootsLength::to_usize()
    }

    /// Returns the `LATEST_SLASHED_EXIT_LENGTH` constant for this specification.
    ///
    /// Spec v0.6.1
    fn latest_slashed_exit_length() -> usize {
        Self::LatestSlashedExitLength::to_usize()
    }
}

/// Ethereum Foundation specifications.
///
/// Spec v0.6.1
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
