use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use types::{AttestationDataAndCustodyBit, Epoch, Hash256};

#[derive(Debug, Clone, Encode, Decode)]
pub struct ValidatorHistoricalAttestation {
    pub source_epoch: Epoch,
    pub target_epoch: Epoch,
    pub signing_root: Hash256,
}

impl ValidatorHistoricalAttestation {
    pub fn new(source_epoch: u64, target_epoch: u64, signing_root: Hash256) -> Self {
        Self {
            source_epoch: Epoch::from(source_epoch),
            target_epoch: Epoch::from(target_epoch),
            signing_root,
        }
    }

    pub fn from(attestation: &AttestationDataAndCustodyBit) -> Self {
        Self {
            source_epoch: attestation.data.source.epoch,
            target_epoch: attestation.data.target.epoch,
            signing_root: Hash256::from_slice(&attestation.tree_hash_root()),
        }
    }
}
