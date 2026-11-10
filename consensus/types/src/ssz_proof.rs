//! SSZ proofs with a single branch, built from the node's existing state and cached list trees.

use crate::{
    BeaconBlockHeader, BeaconState, BeaconStateError, EthSpec, ForkName, Hash256, Validator,
};
use ethereum_hashing::{ZERO_HASHES, hash32_concat};
use milhouse::{AnyListRef, List, Tree, UpdateMap, Value, level_iter::LevelNode};
use serde::{Deserialize, Serialize};
use std::fmt;
use tree_hash::TreeHash;
use typenum::Unsigned;

const VALIDATORS_FIELD_INDEX: usize = 11;
const BALANCES_FIELD_INDEX: usize = 12;
const VALIDATOR_FIELD_DEPTH: usize = 3;
const BALANCE_PACKING_DEPTH: usize = 2;

/// A leaf (or subtree root) and witnesses ordered from the leaf to `root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SszProof {
    #[serde(with = "serde_utils::quoted_u64")]
    pub gindex: u64,
    pub leaf: Hash256,
    pub witnesses: Vec<Hash256>,
    pub root: Hash256,
}

impl SszProof {
    pub fn verify(&self) -> bool {
        if self.gindex.checked_ilog2().map(|depth| depth as usize) != Some(self.witnesses.len()) {
            return false;
        }
        let mut node = self.leaf;
        let mut index = self.gindex;
        for sibling in &self.witnesses {
            node = if index & 1 == 0 {
                hash_pair(node, *sibling)
            } else {
                hash_pair(*sibling, node)
            };
            index >>= 1;
        }
        index == 1 && node == self.root
    }
}

#[derive(Debug)]
pub enum SszProofError {
    InvalidGeneralizedIndex(u64),
    UnsupportedGeneralizedIndex(u64),
    UnsupportedFork(ForkName),
    OutOfBounds { index: usize, length: usize },
    State(BeaconStateError),
    List(milhouse::Error),
    InvalidTree,
}

impl fmt::Display for SszProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGeneralizedIndex(index) => write!(f, "invalid generalized index {index}"),
            Self::UnsupportedGeneralizedIndex(index) => {
                write!(
                    f,
                    "generalized index {index} is not supported by this proof endpoint"
                )
            }
            Self::UnsupportedFork(fork) => write!(f, "state proofs are not supported for {fork}"),
            Self::OutOfBounds { index, length } => {
                write!(f, "list index {index} is outside length {length}")
            }
            Self::State(error) => write!(f, "state proof error: {error:?}"),
            Self::List(error) => write!(f, "list proof error: {error:?}"),
            Self::InvalidTree => write!(f, "inconsistent Merkle tree while constructing proof"),
        }
    }
}

impl std::error::Error for SszProofError {}

impl From<BeaconStateError> for SszProofError {
    fn from(error: BeaconStateError) -> Self {
        Self::State(error)
    }
}

impl From<milhouse::Error> for SszProofError {
    fn from(error: milhouse::Error) -> Self {
        Self::List(error)
    }
}

impl BeaconBlockHeader {
    /// Prove a block field or an ancestor in the block's outer container.
    /// The header has the same SSZ root as the corresponding unsigned beacon block.
    pub fn get_ssz_proof(&self, gindex: u64) -> Result<SszProof, SszProofError> {
        let roots = [
            self.slot.tree_hash_root(),
            self.proposer_index.tree_hash_root(),
            self.parent_root,
            self.state_root,
            self.body_root,
        ];
        let (leaf, witnesses) = container_branch(&roots, gindex)?;
        checked_proof(gindex, leaf, witnesses, self.canonical_root())
    }
}

impl<E: EthSpec> BeaconState<E> {
    /// Prove container nodes, validator record fields, or packed balance chunks.
    /// Produce the response without serializing the complete state as SSZ.
    pub fn get_ssz_proof(&mut self, gindex: u64) -> Result<SszProof, SszProofError> {
        let depth = proof_depth(gindex)?;
        let root = self.canonical_root()?;
        if gindex == 1 {
            return checked_proof(gindex, root, vec![], root);
        }
        let fork = self.fork_name_unchecked();
        // Progressive containers and lists use different semantics for generalized indices.
        // Reject them until nested progressive proofs are implemented and verified together.
        if fork.gloas_enabled() {
            return Err(SszProofError::UnsupportedFork(fork));
        }
        let field_roots = self.get_beacon_state_leaves();
        let container_depth = self.num_fields_pow2().ilog2() as usize;
        if depth <= container_depth {
            let (leaf, witnesses) = container_branch(&field_roots, gindex)?;
            return checked_proof(gindex, leaf, witnesses, root);
        }
        let field_depth = depth
            .checked_sub(container_depth)
            .ok_or(SszProofError::InvalidTree)?;
        let field_gindex = gindex >> field_depth;
        let container_width =
            u64::try_from(self.num_fields_pow2()).map_err(|_| SszProofError::InvalidTree)?;
        let field_index = field_gindex
            .checked_sub(container_width)
            .and_then(|index| usize::try_from(index).ok())
            .ok_or(SszProofError::UnsupportedGeneralizedIndex(gindex))?;
        if field_index != VALIDATORS_FIELD_INDEX && field_index != BALANCES_FIELD_INDEX {
            return Err(SszProofError::UnsupportedGeneralizedIndex(gindex));
        }
        let data_gindex = field_gindex
            .checked_mul(2)
            .ok_or(SszProofError::InvalidTree)?;
        let (_, field_witnesses) = container_branch(&field_roots, field_gindex)?;
        let length = if field_index == VALIDATORS_FIELD_INDEX {
            self.validators().len()
        } else {
            self.balances().len()
        };
        let length_root = u64::try_from(length)
            .map_err(|_| SszProofError::InvalidTree)?
            .tree_hash_root();
        if gindex
            == data_gindex
                .checked_add(1)
                .ok_or(SszProofError::InvalidTree)?
        {
            let field_root = field_roots
                .get(field_index)
                .ok_or(SszProofError::InvalidTree)?;
            // The list root mixes the data tree with its length; obtain the data root directly.
            let data_root = if field_index == VALIDATORS_FIELD_INDEX {
                match self.validators() {
                    AnyListRef::Basic(list) => list_branch(list, 1, 0)?.0,
                    AnyListRef::Progressive(_) => return Err(SszProofError::UnsupportedFork(fork)),
                }
            } else {
                match self.balances() {
                    AnyListRef::Basic(list) => list_branch(list, 1, BALANCE_PACKING_DEPTH)?.0,
                    AnyListRef::Progressive(_) => return Err(SszProofError::UnsupportedFork(fork)),
                }
            };
            if hash_pair(data_root, length_root) != *field_root {
                return Err(SszProofError::InvalidTree);
            }
            let mut witnesses = vec![data_root];
            witnesses.extend(field_witnesses);
            return checked_proof(gindex, length_root, witnesses, root);
        }
        let relative = relative_gindex(gindex, data_gindex)?;
        let registry_depth = E::ValidatorRegistryLimit::to_usize().ilog2() as usize;
        let (leaf, mut witnesses) = if field_index == BALANCES_FIELD_INDEX {
            match self.balances() {
                AnyListRef::Basic(list) => list_branch(list, relative, BALANCE_PACKING_DEPTH)?,
                AnyListRef::Progressive(_) => return Err(SszProofError::UnsupportedFork(fork)),
            }
        } else {
            let relative_depth = proof_depth(relative)?;
            let list = match self.validators() {
                AnyListRef::Basic(list) => list,
                AnyListRef::Progressive(_) => return Err(SszProofError::UnsupportedFork(fork)),
            };
            if relative_depth <= registry_depth {
                list_branch(list, relative, 0)?
            } else {
                let record_depth = relative_depth
                    .checked_sub(registry_depth)
                    .ok_or(SszProofError::InvalidTree)?;
                if record_depth > VALIDATOR_FIELD_DEPTH {
                    return Err(SszProofError::UnsupportedGeneralizedIndex(gindex));
                }
                let record_gindex = relative >> record_depth;
                let base = 1u64
                    .checked_shl(registry_depth as u32)
                    .ok_or(SszProofError::InvalidTree)?;
                let index = record_gindex
                    .checked_sub(base)
                    .and_then(|index| usize::try_from(index).ok())
                    .ok_or(SszProofError::InvalidTree)?;
                let validator = list.get(index).ok_or(SszProofError::OutOfBounds {
                    index,
                    length: list.len(),
                })?;
                let record_relative = relative_gindex(relative, record_gindex)?;
                let (leaf, mut witnesses) =
                    container_branch(&validator_roots(validator), record_relative)?;
                witnesses.extend(list_branch(list, record_gindex, 0)?.1);
                (leaf, witnesses)
            }
        };
        witnesses.push(length_root);
        witnesses.extend(field_witnesses);
        checked_proof(gindex, leaf, witnesses, root)
    }
}

fn validator_roots(validator: &Validator) -> [Hash256; 8] {
    [
        validator.pubkey.tree_hash_root(),
        validator.withdrawal_credentials,
        validator.effective_balance.tree_hash_root(),
        validator.slashed.tree_hash_root(),
        validator.activation_eligibility_epoch.tree_hash_root(),
        validator.activation_epoch.tree_hash_root(),
        validator.exit_epoch.tree_hash_root(),
        validator.withdrawable_epoch.tree_hash_root(),
    ]
}

fn proof_depth(gindex: u64) -> Result<usize, SszProofError> {
    gindex
        .checked_ilog2()
        .map(|depth| depth as usize)
        .ok_or(SszProofError::InvalidGeneralizedIndex(gindex))
}

fn relative_gindex(gindex: u64, ancestor: u64) -> Result<u64, SszProofError> {
    let depth = proof_depth(gindex)?
        .checked_sub(proof_depth(ancestor)?)
        .ok_or(SszProofError::UnsupportedGeneralizedIndex(gindex))?;
    if gindex >> depth != ancestor {
        return Err(SszProofError::UnsupportedGeneralizedIndex(gindex));
    }
    let base = 1u64
        .checked_shl(depth as u32)
        .ok_or(SszProofError::InvalidTree)?;
    Ok(base | (gindex & base.saturating_sub(1)))
}

fn hash_pair(left: Hash256, right: Hash256) -> Hash256 {
    Hash256::from(hash32_concat(left.as_slice(), right.as_slice()))
}

fn checked_proof(
    gindex: u64,
    leaf: Hash256,
    witnesses: Vec<Hash256>,
    root: Hash256,
) -> Result<SszProof, SszProofError> {
    let proof = SszProof {
        gindex,
        leaf,
        witnesses,
        root,
    };
    if proof.verify() {
        Ok(proof)
    } else {
        Err(SszProofError::InvalidTree)
    }
}

fn container_branch(
    roots: &[Hash256],
    gindex: u64,
) -> Result<(Hash256, Vec<Hash256>), SszProofError> {
    let depth = proof_depth(gindex)?;
    let width = roots
        .len()
        .checked_next_power_of_two()
        .ok_or(SszProofError::InvalidTree)?;
    if roots.is_empty() || depth > width.ilog2() as usize {
        return Err(SszProofError::UnsupportedGeneralizedIndex(gindex));
    }
    let mut leaves = roots.to_vec();
    leaves.resize(width, Hash256::ZERO);
    let mut layers = vec![leaves];
    while let Some(layer) = layers.last().filter(|layer| layer.len() > 1) {
        let next = layer
            .chunks_exact(2)
            .map(|pair| {
                let left = pair.first().copied().ok_or(SszProofError::InvalidTree)?;
                let right = pair.get(1).copied().ok_or(SszProofError::InvalidTree)?;
                Ok(hash_pair(left, right))
            })
            .collect::<Result<Vec<_>, SszProofError>>()?;
        layers.push(next);
    }
    let start_layer = layers
        .len()
        .checked_sub(1)
        .and_then(|height| height.checked_sub(depth))
        .ok_or(SszProofError::InvalidTree)?;
    let base = 1u64
        .checked_shl(depth as u32)
        .ok_or(SszProofError::InvalidTree)?;
    let mut index = gindex
        .checked_sub(base)
        .and_then(|index| usize::try_from(index).ok())
        .ok_or(SszProofError::InvalidTree)?;
    let leaf = layers
        .get(start_layer)
        .and_then(|layer| layer.get(index))
        .copied()
        .ok_or(SszProofError::InvalidTree)?;
    let mut witnesses = Vec::with_capacity(depth);
    for layer in layers.iter().skip(start_layer).take(depth) {
        witnesses.push(
            layer
                .get(index ^ 1)
                .copied()
                .ok_or(SszProofError::InvalidTree)?,
        );
        index >>= 1;
    }
    Ok((leaf, witnesses))
}

fn list_branch<T, N, U>(
    list: &List<T, N, U>,
    gindex: u64,
    packing_depth: usize,
) -> Result<(Hash256, Vec<Hash256>), SszProofError>
where
    T: Value + Send + Sync,
    N: Unsigned,
    U: UpdateMap<T>,
{
    let full_depth = (N::to_usize().ilog2() as usize)
        .checked_sub(packing_depth)
        .ok_or(SszProofError::InvalidTree)?;
    let target_depth = proof_depth(gindex)?;
    if target_depth > full_depth {
        return Err(SszProofError::UnsupportedGeneralizedIndex(gindex));
    }
    let base = 1u64
        .checked_shl(target_depth as u32)
        .ok_or(SszProofError::InvalidTree)?;
    let first_element = gindex
        .checked_sub(base)
        .and_then(|index| {
            index.checked_shl(
                full_depth
                    .checked_sub(target_depth)?
                    .checked_add(packing_depth)? as u32,
            )
        })
        .and_then(|index| usize::try_from(index).ok())
        .ok_or(SszProofError::InvalidTree)?;
    if target_depth > 0 && first_element >= list.len() {
        return Err(SszProofError::OutOfBounds {
            index: first_element,
            length: list.len(),
        });
    }
    // Starting at zero yields the already cached root tree, not a walk over every record.
    let mut iter = list.level_iter_from(0)?;
    let root = match iter.next() {
        Some(LevelNode::Internal(root)) => Some(root.as_ref()),
        None if list.is_empty() => None,
        _ => return Err(SszProofError::InvalidTree),
    };
    let mut node = root;
    let mut node_depth = full_depth;
    let mut remaining = target_depth;
    let mut witnesses = Vec::with_capacity(target_depth);
    while remaining > 0 {
        remaining = remaining.checked_sub(1).ok_or(SszProofError::InvalidTree)?;
        node_depth = node_depth
            .checked_sub(1)
            .ok_or(SszProofError::InvalidTree)?;
        match node {
            Some(Tree::Node { left, right, .. }) => {
                let (child, sibling) = if (gindex >> remaining) & 1 == 0 {
                    (left, right)
                } else {
                    (right, left)
                };
                witnesses.push(sibling.tree_hash());
                node = Some(child.as_ref());
            }
            Some(Tree::Zero(_)) | None => {
                witnesses.push(zero_hash(node_depth)?);
                node = None;
            }
            _ => return Err(SszProofError::InvalidTree),
        }
    }
    let leaf = node
        .map(Tree::tree_hash)
        .map(Ok)
        .unwrap_or_else(|| zero_hash(node_depth))?;
    witnesses.reverse();
    Ok((leaf, witnesses))
}

fn zero_hash(depth: usize) -> Result<Hash256, SszProofError> {
    ZERO_HASHES
        .get(depth)
        .copied()
        .map(Hash256::from)
        .ok_or(SszProofError::InvalidTree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Epoch, Eth1Data, MinimalEthSpec, Slot};
    use bls::PublicKeyBytes;

    type E = MinimalEthSpec;

    fn validator(index: usize) -> Validator {
        Validator {
            pubkey: PublicKeyBytes::empty(),
            withdrawal_credentials: Hash256::repeat_byte(index as u8),
            effective_balance: 32_000_000_000 + index as u64,
            slashed: index.is_multiple_of(2),
            activation_eligibility_epoch: Epoch::new(index as u64),
            activation_epoch: Epoch::new(index as u64 + 1),
            exit_epoch: Epoch::new(index as u64 + 2),
            withdrawable_epoch: Epoch::new(index as u64 + 3),
        }
    }

    fn state(count: usize) -> BeaconState<E> {
        let spec = E::default_spec();
        let mut state = BeaconState::<E>::new(0, Eth1Data::default(), &spec);
        for index in 0..count {
            state.validators_mut().push(validator(index)).unwrap();
            state.balances_mut().push(42 + index as u64 * 100).unwrap();
        }
        state
    }

    fn field_index(state: &BeaconState<E>, field: usize) -> u64 {
        (state.num_fields_pow2() + field) as u64
    }

    fn balance_index(state: &BeaconState<E>, validator: usize) -> u64 {
        let depth = <E as EthSpec>::ValidatorRegistryLimit::to_usize().ilog2() as usize - 2;
        ((field_index(state, BALANCES_FIELD_INDEX) * 2) << depth) + (validator / 4) as u64
    }

    fn validator_index(state: &BeaconState<E>, validator: usize, field: usize) -> u64 {
        let depth = <E as EthSpec>::ValidatorRegistryLimit::to_usize().ilog2() as usize;
        (((field_index(state, VALIDATORS_FIELD_INDEX) * 2) << depth) + validator as u64) * 8
            + field as u64
    }

    fn check(proof: &SszProof, root: Hash256) {
        assert!(proof.verify());
        assert_eq!(proof.root, root);
        let depth = proof.gindex.ilog2() as usize;
        assert!(merkle_proof::verify_merkle_proof(
            proof.leaf,
            &proof.witnesses,
            depth,
            proof.gindex as usize - (1usize << depth),
            root,
        ));
    }

    #[test]
    fn block_header_fields_and_ancestors() {
        let header = BeaconBlockHeader {
            slot: Slot::new(123),
            proposer_index: 17,
            parent_root: Hash256::repeat_byte(1),
            state_root: Hash256::repeat_byte(2),
            body_root: Hash256::repeat_byte(3),
        };
        for gindex in 1..16 {
            check(
                &header.get_ssz_proof(gindex).unwrap(),
                header.canonical_root(),
            );
        }
        let proof = header.get_ssz_proof(11).unwrap();
        assert_eq!(proof.leaf, header.state_root);
        assert_eq!(proof.witnesses.len(), 3);
        assert!(matches!(
            header.get_ssz_proof(0),
            Err(SszProofError::InvalidGeneralizedIndex(0))
        ));
        assert!(matches!(
            header.get_ssz_proof(16),
            Err(SszProofError::UnsupportedGeneralizedIndex(16))
        ));
    }

    #[test]
    fn validator_fields_include_length_and_container_branches() {
        let mut state = state(9);
        let root = state.canonical_root().unwrap();
        for index in [0, 4, 8] {
            let roots = validator_roots(state.validators().get(index).unwrap());
            for (field, expected_leaf) in roots.iter().enumerate() {
                let gindex = validator_index(&state, index, field);
                let proof = state.get_ssz_proof(gindex).unwrap();
                assert_eq!(proof.leaf, *expected_leaf);
                check(&proof, root);
            }
            let record_gindex = validator_index(&state, index, 0) / 8;
            let proof = state.get_ssz_proof(record_gindex).unwrap();
            assert_eq!(
                proof.leaf,
                state.validators().get(index).unwrap().tree_hash_root()
            );
            check(&proof, root);
        }
    }

    #[test]
    fn balances_are_packed_in_groups_of_four_and_padded() {
        let mut state = state(9);
        let root = state.canonical_root().unwrap();
        for start in [0, 4, 8] {
            let mut expected = [0u8; 32];
            for offset in 0..4 {
                if let Some(value) = state.balances().get(start + offset) {
                    expected[offset * 8..offset * 8 + 8].copy_from_slice(&value.to_le_bytes());
                }
            }
            let proof = state.get_ssz_proof(balance_index(&state, start)).unwrap();
            assert_eq!(proof.leaf, Hash256::from(expected));
            check(&proof, root);
        }
        assert_eq!(balance_index(&state, 0), balance_index(&state, 3));
    }

    #[test]
    fn empty_list_roots_and_lengths_are_provable() {
        let mut state = state(0);
        let root = state.canonical_root().unwrap();
        for field in [VALIDATORS_FIELD_INDEX, BALANCES_FIELD_INDEX] {
            let field_gindex = field_index(&state, field);
            for gindex in [field_gindex, field_gindex * 2, field_gindex * 2 + 1] {
                check(&state.get_ssz_proof(gindex).unwrap(), root);
            }
            assert_eq!(
                state.get_ssz_proof(field_gindex * 2 + 1).unwrap().leaf,
                Hash256::ZERO
            );
        }
    }

    #[test]
    fn pending_mutations_change_proofs_without_mutating_a_clone() {
        let mut state = state(9);
        let mut original = state.clone();
        let balance_gindex = balance_index(&state, 4);
        let validator_gindex = validator_index(&state, 2, 2);
        let old_balance = original.get_ssz_proof(balance_gindex).unwrap();
        let old_validator = original.get_ssz_proof(validator_gindex).unwrap();
        *state.balances_mut().get_mut(4).unwrap() = 987_654;
        state.validators_mut().get_mut(2).unwrap().effective_balance = 123_456;
        let balance = state.get_ssz_proof(balance_gindex).unwrap();
        let validator = state.get_ssz_proof(validator_gindex).unwrap();
        assert_ne!(balance.leaf, old_balance.leaf);
        assert_ne!(validator.leaf, old_validator.leaf);
        check(&balance, state.canonical_root().unwrap());
        check(&validator, balance.root);
        assert_eq!(original.get_ssz_proof(balance_gindex).unwrap(), old_balance);
    }

    #[test]
    fn invalid_indices_and_nonexistent_records_are_rejected() {
        let mut state = state(9);
        assert!(matches!(
            state.get_ssz_proof(0),
            Err(SszProofError::InvalidGeneralizedIndex(0))
        ));
        assert!(state.get_ssz_proof(u64::MAX).is_err());
        let invalid_validator = validator_index(&state, 9, 0);
        assert!(matches!(
            state.get_ssz_proof(invalid_validator),
            Err(SszProofError::OutOfBounds { .. })
        ));
        let invalid_balance = balance_index(&state, 12);
        assert!(matches!(
            state.get_ssz_proof(invalid_balance),
            Err(SszProofError::OutOfBounds { .. })
        ));
        let unsupported_field_child = field_index(&state, 0) * 2;
        assert!(matches!(
            state.get_ssz_proof(unsupported_field_child),
            Err(SszProofError::UnsupportedGeneralizedIndex(_))
        ));
    }

    #[test]
    fn corrupted_proofs_and_incorrect_depth_are_rejected() {
        let mut state = state(9);
        let proof = state.get_ssz_proof(balance_index(&state, 4)).unwrap();
        let mut corrupted = proof.clone();
        corrupted.leaf = Hash256::repeat_byte(0xff);
        assert!(!corrupted.verify());
        let mut shortened = proof.clone();
        shortened.witnesses.pop();
        assert!(!shortened.verify());
        let mut wrong_index = proof;
        wrong_index.gindex = 0;
        assert!(!wrong_index.verify());
    }

    #[test]
    fn proofs_match_lodestar_reference_vectors() {
        #[derive(Deserialize)]
        struct Vector {
            fork: String,
            state_ssz: String,
            proofs: Vec<SszProof>,
        }
        let vectors: Vec<Vector> =
            serde_json::from_str(include_str!("../tests/fixtures/ssz_proofs/vectors.json"))
                .unwrap();
        for vector in vectors {
            let fork = match vector.fork.as_str() {
                "phase0" => ForkName::Base,
                "fulu" => ForkName::Fulu,
                other => panic!("unexpected fixture fork {other}"),
            };
            let spec = fork.make_genesis_spec(E::default_spec());
            let bytes = hex::decode(vector.state_ssz.strip_prefix("0x").unwrap()).unwrap();
            let mut state = BeaconState::<E>::from_ssz_bytes(&bytes, &spec).unwrap();
            for expected in vector.proofs {
                let actual = state.get_ssz_proof(expected.gindex).unwrap();
                assert_eq!(
                    actual, expected,
                    "{} gindex {}",
                    vector.fork, expected.gindex
                );
                check(&actual, expected.root);
            }
        }
    }
}
