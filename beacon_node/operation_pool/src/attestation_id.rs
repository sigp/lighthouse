use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

/// Serialized `AttestationData` augmented with a domain to encode the fork info.
///
/// [DEPRECATED] To be removed once all nodes have updated to schema v12.
#[derive(
    PartialEq, Eq, Clone, Hash, Debug, PartialOrd, Ord, Encode, Decode, Serialize, Deserialize,
)]
pub struct AttestationId {
    v: Vec<u8>,
}
