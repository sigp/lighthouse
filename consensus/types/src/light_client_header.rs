use crate::{test_utils::TestRandom, EthSpec, ExecutionPayloadHeader, Hash256, SignedBeaconBlock};
use crate::{BeaconBlockHeader, ExecutionPayload};
use merkle_proof::{verify_merkle_proof, MerkleTree};
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;

const EXECUTION_PAYLOAD_INDEX: u32 = 25;
const FLOOR_LOG2_EXECUTION_PAYLOAD_INDEX: u32 = 4;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, arbitrary::Arbitrary)]
#[ssz(struct_behaviour = "transparent")]
pub struct ExecutionBranch(pub [u8; FLOOR_LOG2_EXECUTION_PAYLOAD_INDEX as usize]);

impl TestRandom for Option<ExecutionBranch> {
    fn random_for_test(rng: &mut impl rand::RngCore) -> Self {
        Some(ExecutionBranch(<[u8; FLOOR_LOG2_EXECUTION_PAYLOAD_INDEX
            as usize] as TestRandom>::random_for_test(
            rng
        )))
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TestRandom,
    arbitrary::Arbitrary,
)]
#[serde(bound = "E: EthSpec")]
#[arbitrary(bound = "E: EthSpec")]
#[ssz(struct_behaviour = "container")]
pub struct LightClientHeader<E: EthSpec> {
    pub beacon: BeaconBlockHeader,
    #[test_random(default)]
    #[ssz(skip_serializing, skip_deserializing)]
    pub execution: Option<ExecutionPayloadHeader<E>>,
    #[test_random(default)]
    pub execution_branch: Option<ExecutionBranch>,
}

impl<E: EthSpec> From<BeaconBlockHeader> for LightClientHeader<E> {
    fn from(beacon: BeaconBlockHeader) -> Self {
        LightClientHeader {
            beacon,
            execution: None,
            execution_branch: None,
        }
    }
}

impl<E: EthSpec> From<SignedBeaconBlock<E>> for LightClientHeader<E> {
    fn from(block: SignedBeaconBlock<E>) -> Self {
        let epoch = block.message().slot().epoch(E::slots_per_epoch());

        // TODO epoch greater than or equal to capella
        if epoch >= 0 {
            let payload: ExecutionPayload<E> = block
                .message()
                .execution_payload()
                .unwrap()
                .execution_payload_capella()
                .unwrap()
                .to_owned()
                .into();

            // TODO fix unwrap
            let header = ExecutionPayloadHeader::from(payload.to_ref());
            let leaves = block
                .message()
                .body_capella()
                .unwrap()
                .as_ssz_bytes()
                .iter()
                .map(|data| data.tree_hash_root())
                .collect::<Vec<_>>();

            let tree = MerkleTree::create(&leaves, FLOOR_LOG2_EXECUTION_PAYLOAD_INDEX as usize);

            let _ = tree
                .generate_proof(
                    EXECUTION_PAYLOAD_INDEX as usize,
                    FLOOR_LOG2_EXECUTION_PAYLOAD_INDEX as usize,
                )
                .unwrap();

            return LightClientHeader {
                beacon: block.message().block_header(),
                execution: Some(header),
                execution_branch: None, // Some(execution_branch),
            };
        };

        LightClientHeader {
            beacon: block.message().block_header(),
            execution: None,
            execution_branch: None,
        }
    }
}

impl<E: EthSpec> LightClientHeader<E> {
    fn get_lc_execution_root(&self) -> Option<Hash256> {
        let epoch = self.beacon.slot.epoch(E::slots_per_epoch());

        // TODO greater than or equal to CAPELLA
        if epoch >= 0 {
            if let Some(execution) = &self.execution {
                return Some(execution.tree_hash_root());
            }
        }

        return None;
    }

    fn is_valid_light_client_header(&self) -> bool {
        let epoch = self.beacon.slot.epoch(E::slots_per_epoch());

        // TODO LESS THAN CAPELLA
        if epoch < 0 {
            return self.execution == None && self.execution_branch == None;
        }

        let Some(execution_root) = self.get_lc_execution_root() else {
            return false;
        };

        let Some(execution_branch) = &self.execution_branch else {
            return false;
        };

        return verify_merkle_proof(
            execution_root,
            &[Hash256::from_slice(&execution_branch.0)],
            FLOOR_LOG2_EXECUTION_PAYLOAD_INDEX as usize,
            get_subtree_index(EXECUTION_PAYLOAD_INDEX) as usize,
            self.beacon.body_root,
        );
    }
}

// TODO move to the relevant place
fn get_subtree_index(generalized_index: u32) -> u32 {
    return generalized_index % 2 * (log2_int(generalized_index));
}

// TODO move to the relevant place
fn log2_int(x: u32) -> u32 {
    if x == 0 {
        return 0;
    }
    31 - x.leading_zeros()
}
