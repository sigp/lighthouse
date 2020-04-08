use crate::*;
use serde_derive::{Deserialize, Serialize};
use ssz_types::typenum::{
    Unsigned, U0, U1, U1024, U1099511627776, U128, U16, U16777216, U2, U2048, U32, U4, U4096, U64,
    U65536, U8, U8192,
};
use std::fmt::Debug;

pub trait EthSpec: 'static + Default + Sync + Send + Clone + Debug + PartialEq {
    /*
     * Constants
     */
    type GenesisEpoch: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type JustificationBitsLength: Unsigned + Clone + Sync + Send + Debug + PartialEq + Default;
    type SubnetBitfieldLength: Unsigned + Clone + Sync + Send + Debug + PartialEq + Default;
    /*
     * Misc
     */
    type MaxValidatorsPerCommittee: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /*
     * Time parameters
     */
    type SlotsPerEpoch: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type EpochsPerEth1VotingPeriod: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type SlotsPerHistoricalRoot: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /*
     * State list lengths
     */
    type EpochsPerHistoricalVector: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type EpochsPerSlashingsVector: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type HistoricalRootsLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type ValidatorRegistryLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /*
     * Max operations per block
     */
    type MaxProposerSlashings: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxAttesterSlashings: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxAttestations: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxDeposits: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    type MaxVoluntaryExits: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /*
     * Derived values (set these CAREFULLY)
     */
    /// The length of the `{previous,current}_epoch_attestations` lists.
    ///
    /// Must be set to `MaxAttestations * SlotsPerEpoch`
    // NOTE: we could safely instantiate these by using type-level arithmetic, but doing
    // so adds ~25s to the time required to type-check this crate
    type MaxPendingAttestations: Unsigned + Clone + Sync + Send + Debug + PartialEq;
    /// The length of `eth1_data_votes`.
    ///
    /// Must be set to `EpochsPerEth1VotingPeriod * SlotsPerEpoch`
    type SlotsPerEth1VotingPeriod: Unsigned + Clone + Sync + Send + Debug + PartialEq;

    fn default_spec() -> ChainSpec;

    fn genesis_epoch() -> Epoch {
        Epoch::new(Self::GenesisEpoch::to_u64())
    }

    /// Return the number of committees per slot.
    ///
    /// Note: the number of committees per slot is constant in each epoch, and depends only on
    /// the `active_validator_count` during the slot's epoch.
    ///
    /// Spec v0.11.1
    fn get_committee_count_per_slot(active_validator_count: usize, spec: &ChainSpec) -> usize {
        let slots_per_epoch = Self::SlotsPerEpoch::to_usize();

        std::cmp::max(
            1,
            std::cmp::min(
                spec.max_committees_per_slot,
                active_validator_count / slots_per_epoch / spec.target_committee_size,
            ),
        )
    }

    /// Returns the minimum number of validators required for this spec.
    ///
    /// This is the _absolute_ minimum, the number required to make the chain operate in the most
    /// basic sense. This count is not required to provide any security guarantees regarding
    /// decentralization, entropy, etc.
    fn minimum_validator_count() -> usize {
        Self::SlotsPerEpoch::to_usize()
    }

    /// Returns the `SLOTS_PER_EPOCH` constant for this specification.
    ///
    /// Spec v0.11.1
    fn slots_per_epoch() -> u64 {
        Self::SlotsPerEpoch::to_u64()
    }

    /// Returns the `SLOTS_PER_HISTORICAL_ROOT` constant for this specification.
    ///
    /// Spec v0.11.1
    fn slots_per_historical_root() -> usize {
        Self::SlotsPerHistoricalRoot::to_usize()
    }

    /// Returns the `EPOCHS_PER_HISTORICAL_VECTOR` constant for this specification.
    ///
    /// Spec v0.11.1
    fn epochs_per_historical_vector() -> usize {
        Self::EpochsPerHistoricalVector::to_usize()
    }

    /// Returns the `SLOTS_PER_ETH1_VOTING_PERIOD` constant for this specification.
    ///
    /// Spec v0.11.1
    fn slots_per_eth1_voting_period() -> usize {
        Self::SlotsPerEth1VotingPeriod::to_usize()
    }
}

/// Macro to inherit some type values from another EthSpec.
#[macro_export]
macro_rules! params_from_eth_spec {
    ($spec_ty:ty { $($ty_name:ident),+ }) => {
        $(type $ty_name = <$spec_ty as EthSpec>::$ty_name;)+
    }
}

/// Ethereum Foundation specifications.
///
/// Spec v0.11.1
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct MainnetEthSpec;

impl EthSpec for MainnetEthSpec {
    type JustificationBitsLength = U4;
    type SubnetBitfieldLength = U64;
    type MaxValidatorsPerCommittee = U2048;
    type GenesisEpoch = U0;
    type SlotsPerEpoch = U32;
    type EpochsPerEth1VotingPeriod = U32;
    type SlotsPerHistoricalRoot = U8192;
    type EpochsPerHistoricalVector = U65536;
    type EpochsPerSlashingsVector = U8192;
    type HistoricalRootsLimit = U16777216;
    type ValidatorRegistryLimit = U1099511627776;
    type MaxProposerSlashings = U16;
    type MaxAttesterSlashings = U1;
    type MaxAttestations = U128;
    type MaxDeposits = U16;
    type MaxVoluntaryExits = U16;
    type MaxPendingAttestations = U4096; // 128 max attestations * 32 slots per epoch
    type SlotsPerEth1VotingPeriod = U1024; // 32 epochs * 32 slots per epoch

    fn default_spec() -> ChainSpec {
        ChainSpec::mainnet()
    }
}

pub type FoundationBeaconState = BeaconState<MainnetEthSpec>;

/// Ethereum Foundation minimal spec, as defined in the eth2.0-specs repo.
///
/// Spec v0.11.1
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct MinimalEthSpec;

impl EthSpec for MinimalEthSpec {
    type SlotsPerEpoch = U8;
    type EpochsPerEth1VotingPeriod = U2;
    type SlotsPerHistoricalRoot = U64;
    type EpochsPerHistoricalVector = U64;
    type EpochsPerSlashingsVector = U64;
    type MaxPendingAttestations = U1024; // 128 max attestations * 8 slots per epoch
    type SlotsPerEth1VotingPeriod = U16; // 2 epochs * 8 slots per epoch

    params_from_eth_spec!(MainnetEthSpec {
        JustificationBitsLength,
        SubnetBitfieldLength,
        MaxValidatorsPerCommittee,
        GenesisEpoch,
        HistoricalRootsLimit,
        ValidatorRegistryLimit,
        MaxProposerSlashings,
        MaxAttesterSlashings,
        MaxAttestations,
        MaxDeposits,
        MaxVoluntaryExits
    });

    fn default_spec() -> ChainSpec {
        ChainSpec::minimal()
    }
}

pub type MinimalBeaconState = BeaconState<MinimalEthSpec>;

/// Interop testnet spec
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct InteropEthSpec;

impl EthSpec for InteropEthSpec {
    type SlotsPerEpoch = U8;
    type EpochsPerEth1VotingPeriod = U2;
    type SlotsPerHistoricalRoot = U64;
    type EpochsPerHistoricalVector = U64;
    type EpochsPerSlashingsVector = U64;
    type MaxPendingAttestations = U1024; // 128 max attestations * 8 slots per epoch
    type SlotsPerEth1VotingPeriod = U16; // 2 epochs * 8 slots per epoch

    params_from_eth_spec!(MainnetEthSpec {
        JustificationBitsLength,
        SubnetBitfieldLength,
        MaxValidatorsPerCommittee,
        GenesisEpoch,
        HistoricalRootsLimit,
        ValidatorRegistryLimit,
        MaxProposerSlashings,
        MaxAttesterSlashings,
        MaxAttestations,
        MaxDeposits,
        MaxVoluntaryExits
    });

    fn default_spec() -> ChainSpec {
        ChainSpec::interop()
    }
}

pub type InteropBeaconState = BeaconState<InteropEthSpec>;
