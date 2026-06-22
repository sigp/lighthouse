use bls::{PublicKeyBytes, SignatureBytes};
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::{ChainSpec, DepositMessage, Domain, SignedRoot, core::Hash256, fork::ForkName};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct BuilderDepositRequest {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    pub signature: SignatureBytes,
}

impl BuilderDepositRequest {
    fn as_deposit_message(&self) -> DepositMessage {
        DepositMessage {
            pubkey: self.pubkey,
            withdrawal_credentials: self.withdrawal_credentials,
            amount: self.amount,
        }
    }

    pub fn version(&self) -> Option<u8> {
        self.withdrawal_credentials.as_slice().first().cloned()
    }

    pub fn is_valid_builder_deposit_signature(&self, spec: &ChainSpec) -> bool {
        let Ok(pubkey) = self.pubkey.decompress() else {
            return false;
        };
        let Ok(signature) = self.signature.decompress() else {
            return false;
        };

        let domain = spec.compute_domain(
            Domain::BuilderDeposit,
            spec.genesis_fork_version,
            Hash256::ZERO,
        );
        let signing_root = self.as_deposit_message().signing_root(domain);

        signature.verify(&pubkey, signing_root)
    }
}

impl BuilderDepositRequest {
    pub fn max_size() -> usize {
        Self {
            pubkey: PublicKeyBytes::empty(),
            withdrawal_credentials: Hash256::ZERO,
            amount: 0,
            signature: SignatureBytes::empty(),
        }
        .as_ssz_bytes()
        .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(BuilderDepositRequest);
}
