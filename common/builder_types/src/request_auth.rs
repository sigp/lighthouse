use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash_derive::TreeHash;
use types::{ForkName, SignedRoot, Slot};

// I would like to avoid defining this on the EthSpec if we can get away with it.
// Since it's outside the consensus-spec and is generically named..
pub type MaxDataSize = typenum::U4096;

pub type RequestAuthData = VariableList<u8, MaxDataSize>;

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct RequestAuth {
    /// Opaque authentication data unique to the builder, agreed upon out of band. The meaning of
    /// the up to `MaxDataSize` (4096) bytes is left to the proposer and builder; the builder checks
    /// the exact bytes when it verifies. When no value has been agreed out of band, implementations
    /// SHOULD default to the UTF-8 bytes of the builder's own advertised URL, exactly as advertised,
    /// so proposers with no prior relationship can construct an identical `data` deterministically.
    /// A zero-length `data` is invalid.
    ///
    /// Serialized as a `0x`-prefixed hex string (builder-specs #165 `format: hex`).
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub data: RequestAuthData,
    /// The proposal slot this request is authorized for.
    pub slot: Slot,
}

impl SignedRoot for RequestAuth {}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(RequestAuth);
}
