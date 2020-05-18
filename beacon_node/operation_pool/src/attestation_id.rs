use serde_derive::{Deserialize, Serialize};
use ssz::ssz_encode;
use ssz_derive::{Decode, Encode};
use types::{AttestationData, ChainSpec, Domain, Epoch, Fork, Hash256};

/// Serialized `AttestationData` augmented with a domain to encode the fork info.
#[derive(
    PartialEq, Eq, Clone, Hash, Debug, PartialOrd, Ord, Encode, Decode, Serialize, Deserialize,
)]
pub struct AttestationId {
    v: Vec<u8>,
}

/// Number of domain bytes that the end of an attestation ID is padded with.
const DOMAIN_BYTES_LEN: usize = std::mem::size_of::<Hash256>();

impl AttestationId {
    pub fn from_data(
        attestation: &AttestationData,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Self {
        let mut bytes = ssz_encode(attestation);
        let epoch = attestation.target.epoch;
        bytes.extend_from_slice(
            AttestationId::compute_domain_bytes(epoch, fork, genesis_validators_root, spec)
                .as_bytes(),
        );
        AttestationId { v: bytes }
    }

    pub fn compute_domain_bytes(
        epoch: Epoch,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Hash256 {
        spec.get_domain(epoch, Domain::BeaconAttester, fork, genesis_validators_root)
    }

    pub fn domain_bytes_match(&self, domain_bytes: &Hash256) -> bool {
        &self.v[self.v.len() - DOMAIN_BYTES_LEN..] == domain_bytes.as_bytes()
    }
}
