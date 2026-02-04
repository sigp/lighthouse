use crate::execution::{ExecutionPayloadGloas, ExecutionRequests};
use crate::test_utils::TestRandom;
use crate::{EthSpec, ForkName, Hash256, SignedRoot, Slot};
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(Debug, Clone, Serialize, Encode, Decode, Deserialize, TestRandom, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[context_deserialize(ForkName)]
#[serde(bound = "E: EthSpec")]
pub struct ExecutionPayloadEnvelope<E: EthSpec> {
    pub payload: ExecutionPayloadGloas<E>,
    pub execution_requests: ExecutionRequests<E>,
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_index: u64,
    pub beacon_block_root: Hash256,
    pub slot: Slot,
    pub state_root: Hash256,
}

impl<E: EthSpec> SignedRoot for ExecutionPayloadEnvelope<E> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;
    use crate::test_utils::TestRandom;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    ssz_and_tree_hash_tests!(ExecutionPayloadEnvelope<MainnetEthSpec>);

    #[test]
    fn signing_root_is_deterministic() {
        let mut rng = XorShiftRng::from_seed([0x42; 16]);
        let envelope = ExecutionPayloadEnvelope::<MainnetEthSpec>::random_for_test(&mut rng);
        let domain = Hash256::random_for_test(&mut rng);

        let signing_root_1 = envelope.signing_root(domain);
        let signing_root_2 = envelope.signing_root(domain);

        assert_eq!(signing_root_1, signing_root_2);
    }

    #[test]
    fn signing_root_changes_with_domain() {
        let mut rng = XorShiftRng::from_seed([0x42; 16]);
        let envelope = ExecutionPayloadEnvelope::<MainnetEthSpec>::random_for_test(&mut rng);
        let domain_1 = Hash256::random_for_test(&mut rng);
        let domain_2 = Hash256::random_for_test(&mut rng);

        let signing_root_1 = envelope.signing_root(domain_1);
        let signing_root_2 = envelope.signing_root(domain_2);

        assert_ne!(signing_root_1, signing_root_2);
    }

    #[test]
    fn signing_root_changes_with_envelope_data() {
        let mut rng = XorShiftRng::from_seed([0x42; 16]);
        let envelope_1 = ExecutionPayloadEnvelope::<MainnetEthSpec>::random_for_test(&mut rng);
        let mut envelope_2 = envelope_1.clone();
        envelope_2.beacon_block_root = Hash256::random_for_test(&mut rng);

        let domain = Hash256::random_for_test(&mut rng);

        let signing_root_1 = envelope_1.signing_root(domain);
        let signing_root_2 = envelope_2.signing_root(domain);

        assert_ne!(signing_root_1, signing_root_2);
    }
}
