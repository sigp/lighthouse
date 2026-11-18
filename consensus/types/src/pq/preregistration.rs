use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;
use xmss::XmssPublicKey;

use crate::{
    core::{Hash256, Slot},
    fork::ForkName,
};

/// A request, emitted by the system contract, to bind an XMSS public key to withdrawal
/// credentials and a VRF root ahead of the validator's first deposit.
///
/// The system contract verifies the binding's signature, so the request carries none.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct ValidatorPreregistrationRequest {
    pub pubkey: XmssPublicKey,
    pub withdrawal_credentials: Hash256,
    pub vrf_root: Hash256,
}

/// A validator preregistration stored in the beacon state.
///
/// `expiry_slot` is the absolute deadline computed when the preregistration is stored.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct ValidatorPreregistration {
    pub pubkey: XmssPublicKey,
    pub withdrawal_credentials: Hash256,
    pub vrf_root: Hash256,
    pub expiry_slot: Slot,
}

/// A request, emitted by the system contract, to bind a builder's XMSS public key to withdrawal
/// credentials ahead of its first deposit. A builder has no VRF root.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct BuilderPreregistrationRequest {
    pub pubkey: XmssPublicKey,
    pub withdrawal_credentials: Hash256,
}

/// A builder preregistration stored in the beacon state.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct BuilderPreregistration {
    pub pubkey: XmssPublicKey,
    pub withdrawal_credentials: Hash256,
    pub expiry_slot: Slot,
}

#[cfg(test)]
mod tests {
    use super::*;

    mod validator_preregistration_request {
        use super::*;
        ssz_and_tree_hash_tests!(ValidatorPreregistrationRequest);
    }
    mod validator_preregistration {
        use super::*;
        ssz_and_tree_hash_tests!(ValidatorPreregistration);
    }
    mod builder_preregistration_request {
        use super::*;
        ssz_and_tree_hash_tests!(BuilderPreregistrationRequest);
    }
    mod builder_preregistration {
        use super::*;
        ssz_and_tree_hash_tests!(BuilderPreregistration);
    }
}
