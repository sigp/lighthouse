use crate::attestation_id::DOMAIN_BYTES_LEN;
use serde_derive::{Deserialize, Serialize};
use ssz::ssz_encode;
use ssz_derive::{Decode, Encode};
use types::sync_committee_contribution::SyncAggregateData;
use types::{ChainSpec, Domain, Epoch, EthSpec, Fork, Hash256, Slot};

/// Serialized `SyncAggregateData` augmented with a domain to encode the fork info.
#[derive(
    PartialEq, Eq, Clone, Hash, Debug, PartialOrd, Ord, Encode, Decode, Serialize, Deserialize,
)]
pub struct SyncAggregateId {
    v: Vec<u8>,
}

impl SyncAggregateId {
    pub fn from_data<T: EthSpec>(
        slot: Slot,
        beacon_block_root: Hash256,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Self {
        let mut bytes = ssz_encode(&SyncAggregateData {
            slot,
            beacon_block_root,
        });
        let epoch = slot.epoch(T::slots_per_epoch());
        bytes.extend_from_slice(
            SyncAggregateId::compute_domain_bytes(epoch, fork, genesis_validators_root, spec)
                .as_bytes(),
        );
        SyncAggregateId { v: bytes }
    }

    pub fn compute_domain_bytes(
        epoch: Epoch,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Hash256 {
        spec.get_domain(epoch, Domain::SyncCommittee, fork, genesis_validators_root)
    }

    pub fn domain_bytes_match(&self, domain_bytes: &Hash256) -> bool {
        &self.v[self.v.len() - DOMAIN_BYTES_LEN..] == domain_bytes.as_bytes()
    }
}
