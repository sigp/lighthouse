pub mod consts;

mod application_domain;
mod chain_spec;
mod config_and_preset;
mod enr_fork_id;
mod eth_spec;
mod execution_block_hash;
mod graffiti;
mod non_zero_usize;
mod preset;
mod relative_epoch;
mod signing_data;
mod slot_data;
#[macro_use]
mod slot_epoch_macros;
mod slot_epoch;
#[cfg(feature = "sqlite")]
mod sqlite;

pub use application_domain::{APPLICATION_DOMAIN_BUILDER, ApplicationDomain};
pub use chain_spec::{BlobParameters, BlobSchedule, ChainSpec, Config, Domain};
pub use config_and_preset::{
    ConfigAndPreset, ConfigAndPresetDeneb, ConfigAndPresetElectra, ConfigAndPresetFulu,
    ConfigAndPresetGloas, get_extra_fields,
};
pub use enr_fork_id::EnrForkId;
pub use eth_spec::{EthSpec, EthSpecId, GNOSIS, GnosisEthSpec, MainnetEthSpec, MinimalEthSpec};
pub use execution_block_hash::ExecutionBlockHash;
pub use graffiti::{GRAFFITI_BYTES_LEN, Graffiti, GraffitiString};
pub use non_zero_usize::new_non_zero_usize;
pub use preset::{
    AltairPreset, BasePreset, BellatrixPreset, CapellaPreset, DenebPreset, ElectraPreset,
    FuluPreset, GloasPreset,
};
pub use relative_epoch::{Error as RelativeEpochError, RelativeEpoch};
pub use signing_data::{SignedRoot, SigningData};
pub use slot_data::SlotData;
pub use slot_epoch::{Epoch, Slot};

#[cfg(test)]
pub(crate) use chain_spec::{
    max_blobs_by_root_request_common, max_data_columns_by_root_request_common,
};

pub type Hash256 = alloy_primitives::B256;
pub type Uint256 = alloy_primitives::U256;
pub type Hash64 = alloy_primitives::B64;
pub type Address = alloy_primitives::Address;
pub type VersionedHash = Hash256;
pub type MerkleProof = Vec<Hash256>;
