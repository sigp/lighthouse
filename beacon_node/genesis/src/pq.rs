//! Key derivation used by the ethPandaOps PQ genesis tooling.

use bls::SecretKey;
use ethereum_hashing::hash32_concat;
use state_processing::pq::{VRF_TREE_DEPTH, compute_vrf_leaf, hash_vrf_node};
use types::{Hash256, Slot, VrfProof};
use xmss::XmssSecretKey;

const POPULATED_DEPTH: usize = 20;
const POPULATED_LEAVES: u64 = 1 << POPULATED_DEPTH;
// Keep roots of small subtrees instead of the full 64 MiB tree of each key.
const SUBTREE_DEPTH: usize = 10;
const SUBTREE_LEAVES: u64 = 1 << SUBTREE_DEPTH;

pub fn xmss_key_from_bls(key: &SecretKey) -> XmssSecretKey {
    XmssSecretKey::from_seed(&hash32_concat(b"leanxmss-seed", key.serialize().as_bytes()))
}

/// The devnet seeds the first 2^20 leaves with Keccak-256 and pads the rest with zeros.
pub struct VrfTree {
    seed: [u8; 32],
    subtree_roots: Vec<Hash256>,
}

impl VrfTree {
    pub fn from_bls(key: &SecretKey) -> Self {
        let seed = hash32_concat(b"vrf-seed", key.serialize().as_bytes());
        let subtree_roots = (0..POPULATED_LEAVES)
            .step_by(SUBTREE_LEAVES as usize)
            .map(|start| {
                let mut nodes = populated_subtree(&seed, start);
                reduce_merkle_nodes(&mut nodes, 0, &mut Vec::new());
                nodes.first().copied().unwrap_or_default()
            })
            .collect();
        Self {
            seed,
            subtree_roots,
        }
    }

    pub fn root(&self) -> Hash256 {
        let mut branch = Vec::new();
        self.populated_root(0, &mut branch)
            .into_iter()
            .chain(
                zero_hashes()
                    .into_iter()
                    .skip(POPULATED_DEPTH)
                    .take(VRF_TREE_DEPTH - POPULATED_DEPTH),
            )
            .reduce(hash_vrf_node)
            .unwrap_or_default()
    }

    /// A proof opens the absolute slot, with the sibling of each node ordered bottom-up.
    pub fn proof(&self, slot: Slot) -> Result<VrfProof, types::BeaconStateError> {
        let index = slot.as_u64() & ((1 << VRF_TREE_DEPTH) - 1);
        let mut proof = Vec::with_capacity(VRF_TREE_DEPTH + 1);
        let zeros = zero_hashes();
        if index < POPULATED_LEAVES {
            let start = index & !(SUBTREE_LEAVES - 1);
            let mut nodes = populated_subtree(&self.seed, start);
            proof.push(compute_vrf_leaf(&self.seed, index));
            reduce_merkle_nodes(&mut nodes, (index % SUBTREE_LEAVES) as usize, &mut proof);
            self.populated_root((index / SUBTREE_LEAVES) as usize, &mut proof);
            proof.extend_from_slice(&zeros[POPULATED_DEPTH..VRF_TREE_DEPTH]);
        } else {
            let joined_depth = index.ilog2() as usize;
            let mut ignored_branch = Vec::new();
            let mut populated = self
                .populated_root(0, &mut ignored_branch)
                .unwrap_or_default();
            proof.push(Hash256::ZERO);
            for (level, zero) in zeros.into_iter().take(VRF_TREE_DEPTH).enumerate() {
                if level == joined_depth {
                    proof.push(populated);
                } else {
                    proof.push(zero);
                }
                if level >= POPULATED_DEPTH && level < joined_depth {
                    populated = hash_vrf_node(populated, zero);
                }
            }
        }
        Ok(VrfProof::new(proof)?)
    }

    fn populated_root(&self, subtree_index: usize, branch: &mut Vec<Hash256>) -> Option<Hash256> {
        let mut nodes = self.subtree_roots.clone();
        reduce_merkle_nodes(&mut nodes, subtree_index, branch);
        nodes.first().copied()
    }
}

fn populated_subtree(seed: &[u8; 32], start: u64) -> Vec<Hash256> {
    (0..SUBTREE_LEAVES)
        .map(|offset| compute_vrf_leaf(seed, start.saturating_add(offset)))
        .collect()
}

fn zero_hashes() -> [Hash256; VRF_TREE_DEPTH] {
    let mut previous = Hash256::ZERO;
    std::array::from_fn(|_| {
        let zero = previous;
        previous = hash_vrf_node(zero, zero);
        zero
    })
}

fn reduce_merkle_nodes(nodes: &mut Vec<Hash256>, mut index: usize, branch: &mut Vec<Hash256>) {
    while nodes.len() > 1 {
        if let Some(sibling) = nodes.get(index ^ 1) {
            branch.push(*sibling);
        }
        let next_len = nodes.len() / 2;
        for position in 0..next_len {
            if let Some([left, right]) = nodes.get(position * 2..).and_then(<[_]>::first_chunk) {
                let parent = hash_vrf_node(*left, *right);
                if let Some(node) = nodes.get_mut(position) {
                    *node = parent;
                }
            }
        }
        nodes.truncate(next_len);
        index /= 2;
    }
}

pub struct PqGenesisKeys {
    pub xmss: XmssSecretKey,
    pub vrf: VrfTree,
}

impl PqGenesisKeys {
    pub fn from_bls(key: &SecretKey) -> Self {
        Self {
            xmss: xmss_key_from_bls(key),
            vrf: VrfTree::from_bls(key),
        }
    }
}

#[cfg(all(test, not(debug_assertions)))]
mod tests {
    use super::*;

    #[test]
    fn pq_ethpandaops_keys_and_vrf_tree_boundaries() {
        let secret = "0x2892f3ba475c3640a67fe730798ad9c4eed3a6d934db85f91c41cfc837ce8834"
            .parse::<Hash256>()
            .unwrap();
        let key = SecretKey::deserialize(secret.as_slice()).unwrap();
        let keys = PqGenesisKeys::from_bls(&key);
        assert_eq!(
            keys.xmss.public_key(),
            "0x155a29b971da2b771fdf52c768af63fa03f78f25487e3e0ed03d012b7039d88b"
                .parse()
                .unwrap(),
        );
        let root = keys.vrf.root();
        assert_eq!(
            root,
            "0x46f6772a35c14c7f8467e9d8791450ed3c6853191129876fc50e769ec9bac18d"
                .parse::<Hash256>()
                .unwrap(),
        );
        // PyCryptodome Keccak-256 and the patched eth-beacon-genesis generator
        // independently agree on the padded tree. SHA-256 fingerprints the proof bytes.
        for (index, digest) in [
            (
                0,
                "0x4107fa0f9dad85074520eb0cdcf35264504f076c0c50b8cf8103a509c372d86c",
            ),
            (
                5,
                "0x4e0efa764e7c54ddbfba1f1266497f55b82a4d363d30f77dfb520904f59aa8d5",
            ),
            (
                POPULATED_LEAVES - 1,
                "0x4be4c0afca9d7139ed7a1e52a399bf4787478cd561bb32a0138a0550fd44d7d5",
            ),
            (
                POPULATED_LEAVES,
                "0x3b7f91d3371503c6268e3fa967ca51cbe43b6803f7c9662d95734e1b1d36d381",
            ),
            (
                (1 << VRF_TREE_DEPTH) - 1,
                "0xa6e044ad1b73627b876ce31ecd9ee2c2093279ee56af9c67004f7a26cb49c5a4",
            ),
        ] {
            let slot = Slot::new(index);
            let proof = keys.vrf.proof(slot).unwrap();
            let proof_bytes: Vec<_> = proof.iter().flat_map(|node| node.0).collect();
            assert_eq!(
                Hash256::from(ethereum_hashing::hash_fixed(&proof_bytes)),
                digest.parse::<Hash256>().unwrap()
            );
            assert_eq!(proof[0] == Hash256::ZERO, index >= POPULATED_LEAVES);
            assert!(state_processing::pq::is_valid_vrf_proof(&proof, slot, root));
            assert!(!state_processing::pq::is_valid_vrf_proof(
                &proof,
                slot,
                Hash256::ZERO
            ));
        }
    }
}
