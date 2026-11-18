use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;
use xmss::XmssPublicKey;

use crate::fork::ForkName;

/// A voluntary exit, emitted as an execution layer request by the system contract.
///
/// The system contract verifies the exit's signature, so the request carries none.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct VoluntaryExitRequest {
    pub pubkey: XmssPublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(VoluntaryExitRequest);
}
