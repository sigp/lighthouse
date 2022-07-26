use crate::error::Error;
use crate::proto_array::{InvalidationOperation, Iter, ProposerBoost, ProtoArray, ProtoNode};
use crate::ssz_container::SszContainer;
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::collections::{BTreeSet, HashMap};
use types::{
    AttestationShufflingId, ChainSpec, Checkpoint, Epoch, EthSpec, ExecutionBlockHash, Hash256,
    Slot,
};

pub const DEFAULT_PRUNE_THRESHOLD: usize = 256;

#[derive(Default, PartialEq, Clone, Encode, Decode)]
pub struct VoteTracker {
    current_root: Hash256,
    next_root: Hash256,
    next_epoch: Epoch,
}

/// Represents the verification status of an execution payload.
#[derive(Clone, Copy, Debug, PartialEq, Encode, Decode, Serialize, Deserialize)]
#[ssz(enum_behaviour = "union")]
pub enum ExecutionStatus {
    /// An EL has determined that the payload is valid.
    Valid(ExecutionBlockHash),
    /// An EL has determined that the payload is invalid.
    Invalid(ExecutionBlockHash),
    /// An EL has not yet verified the execution payload.
    Optimistic(ExecutionBlockHash),
    /// The block is either prior to the merge fork, or after the merge fork but before the terminal
    /// PoW block has been found.
    ///
    /// # Note:
    ///
    /// This `bool` only exists to satisfy our SSZ implementation which requires all variants
    /// to have a value. It can be set to anything.
    Irrelevant(bool), // TODO(merge): fix bool.
}

impl ExecutionStatus {
    pub fn is_execution_enabled(&self) -> bool {
        !matches!(self, ExecutionStatus::Irrelevant(_))
    }

    pub fn irrelevant() -> Self {
        ExecutionStatus::Irrelevant(false)
    }

    pub fn block_hash(&self) -> Option<ExecutionBlockHash> {
        match self {
            ExecutionStatus::Valid(hash)
            | ExecutionStatus::Invalid(hash)
            | ExecutionStatus::Optimistic(hash) => Some(*hash),
            ExecutionStatus::Irrelevant(_) => None,
        }
    }

    /// Returns `true` if the block:
    ///
    /// - Has a valid payload, OR
    /// - Does not have execution enabled.
    ///
    /// Whenever this function returns `true`, the block is *fully valid*.
    pub fn is_valid_or_irrelevant(&self) -> bool {
        matches!(
            self,
            ExecutionStatus::Valid(_) | ExecutionStatus::Irrelevant(_)
        )
    }

    /// Returns `true` if the block:
    ///
    /// - Has execution enabled, AND
    /// - Has a valid payload
    ///
    /// This function will return `false` for any block from a slot prior to the Bellatrix fork.
    /// This means that some blocks that are perfectly valid will still receive a `false` response.
    /// See `Self::is_valid_or_irrelevant` for a function that will always return `true` given any
    /// perfectly valid block.
    pub fn is_valid_and_post_bellatrix(&self) -> bool {
        matches!(self, ExecutionStatus::Valid(_))
    }

    /// Returns `true` if the block:
    ///
    /// - Has execution enabled, AND
    /// - Has a payload that has not yet been verified by an EL.
    pub fn is_optimistic(&self) -> bool {
        matches!(self, ExecutionStatus::Optimistic(_))
    }

    /// Returns `true` if the block:
    ///
    /// - Has execution enabled, AND
    /// - Has an invalid payload.
    pub fn is_invalid(&self) -> bool {
        matches!(self, ExecutionStatus::Invalid(_))
    }

    /// Returns `true` if the block:
    ///
    /// - Does not have execution enabled (before or after Bellatrix fork)
    pub fn is_irrelevant(&self) -> bool {
        matches!(self, ExecutionStatus::Irrelevant(_))
    }
}

/// A block that is to be applied to the fork choice.
///
/// A simplified version of `types::BeaconBlock`.
#[derive(Clone, Debug, PartialEq)]
pub struct Block {
    pub slot: Slot,
    pub root: Hash256,
    pub parent_root: Option<Hash256>,
    pub state_root: Hash256,
    pub target_root: Hash256,
    pub current_epoch_shuffling_id: AttestationShufflingId,
    pub next_epoch_shuffling_id: AttestationShufflingId,
    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    /// Indicates if an execution node has marked this block as valid. Also contains the execution
    /// block hash.
    pub execution_status: ExecutionStatus,
    pub unrealized_justified_checkpoint: Option<Checkpoint>,
    pub unrealized_finalized_checkpoint: Option<Checkpoint>,
}

/// A Vec-wrapper which will grow to match any request.
///
/// E.g., a `get` or `insert` to an out-of-bounds element will cause the Vec to grow (using
/// Default) to the smallest size required to fulfill the request.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct ElasticList<T>(pub Vec<T>);

impl<T> ElasticList<T>
where
    T: Default,
{
    fn ensure(&mut self, i: usize) {
        if self.0.len() <= i {
            self.0.resize_with(i + 1, Default::default);
        }
    }

    pub fn get_mut(&mut self, i: usize) -> &mut T {
        self.ensure(i);
        &mut self.0[i]
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.0.iter_mut()
    }
}

#[derive(PartialEq)]
pub struct ProtoArrayForkChoice {
    pub(crate) proto_array: ProtoArray,
    pub(crate) votes: ElasticList<VoteTracker>,
    pub(crate) balances: Vec<u64>,
}

impl ProtoArrayForkChoice {
    #[allow(clippy::too_many_arguments)]
    pub fn new<E: EthSpec>(
        finalized_block_slot: Slot,
        finalized_block_state_root: Hash256,
        justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
        current_epoch_shuffling_id: AttestationShufflingId,
        next_epoch_shuffling_id: AttestationShufflingId,
        execution_status: ExecutionStatus,
    ) -> Result<Self, String> {
        let mut proto_array = ProtoArray {
            prune_threshold: DEFAULT_PRUNE_THRESHOLD,
            justified_checkpoint,
            finalized_checkpoint,
            nodes: Vec::with_capacity(1),
            indices: HashMap::with_capacity(1),
            previous_proposer_boost: ProposerBoost::default(),
        };

        let block = Block {
            slot: finalized_block_slot,
            root: finalized_checkpoint.root,
            parent_root: None,
            state_root: finalized_block_state_root,
            // We are using the finalized_root as the target_root, since it always lies on an
            // epoch boundary.
            target_root: finalized_checkpoint.root,
            current_epoch_shuffling_id,
            next_epoch_shuffling_id,
            justified_checkpoint,
            finalized_checkpoint,
            execution_status,
            unrealized_justified_checkpoint: Some(justified_checkpoint),
            unrealized_finalized_checkpoint: Some(finalized_checkpoint),
        };

        proto_array
            .on_block::<E>(block, finalized_block_slot)
            .map_err(|e| format!("Failed to add finalized block to proto_array: {:?}", e))?;

        Ok(Self {
            proto_array,
            votes: ElasticList::default(),
            balances: vec![],
        })
    }

    /// See `ProtoArray::propagate_execution_payload_validation` for documentation.
    pub fn process_execution_payload_validation(
        &mut self,
        block_root: Hash256,
    ) -> Result<(), String> {
        self.proto_array
            .propagate_execution_payload_validation(block_root)
            .map_err(|e| format!("Failed to process valid payload: {:?}", e))
    }

    /// See `ProtoArray::propagate_execution_payload_invalidation` for documentation.
    pub fn process_execution_payload_invalidation(
        &mut self,
        op: &InvalidationOperation,
    ) -> Result<(), String> {
        self.proto_array
            .propagate_execution_payload_invalidation(op)
            .map_err(|e| format!("Failed to process invalid payload: {:?}", e))
    }

    pub fn process_attestation(
        &mut self,
        validator_index: usize,
        block_root: Hash256,
        target_epoch: Epoch,
    ) -> Result<(), String> {
        let vote = self.votes.get_mut(validator_index);

        if target_epoch > vote.next_epoch || *vote == VoteTracker::default() {
            vote.next_root = block_root;
            vote.next_epoch = target_epoch;
        }

        Ok(())
    }

    pub fn process_block<E: EthSpec>(
        &mut self,
        block: Block,
        current_slot: Slot,
    ) -> Result<(), String> {
        if block.parent_root.is_none() {
            return Err("Missing parent root".to_string());
        }

        self.proto_array
            .on_block::<E>(block, current_slot)
            .map_err(|e| format!("process_block_error: {:?}", e))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn find_head<E: EthSpec>(
        &mut self,
        justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
        justified_state_balances: &[u64],
        proposer_boost_root: Hash256,
        equivocating_indices: &BTreeSet<u64>,
        current_slot: Slot,
        spec: &ChainSpec,
    ) -> Result<Hash256, String> {
        let old_balances = &mut self.balances;

        let new_balances = justified_state_balances;

        let deltas = compute_deltas(
            &self.proto_array.indices,
            &mut self.votes,
            old_balances,
            new_balances,
            equivocating_indices,
        )
        .map_err(|e| format!("find_head compute_deltas failed: {:?}", e))?;

        self.proto_array
            .apply_score_changes::<E>(
                deltas,
                justified_checkpoint,
                finalized_checkpoint,
                new_balances,
                proposer_boost_root,
                current_slot,
                spec,
            )
            .map_err(|e| format!("find_head apply_score_changes failed: {:?}", e))?;

        *old_balances = new_balances.to_vec();

        self.proto_array
            .find_head::<E>(&justified_checkpoint.root, current_slot)
            .map_err(|e| format!("find_head failed: {:?}", e))
    }

    pub fn maybe_prune(&mut self, finalized_root: Hash256) -> Result<(), String> {
        self.proto_array
            .maybe_prune(finalized_root)
            .map_err(|e| format!("find_head maybe_prune failed: {:?}", e))
    }

    pub fn set_prune_threshold(&mut self, prune_threshold: usize) {
        self.proto_array.prune_threshold = prune_threshold;
    }

    pub fn len(&self) -> usize {
        self.proto_array.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.proto_array.nodes.is_empty()
    }

    pub fn contains_block(&self, block_root: &Hash256) -> bool {
        self.proto_array.indices.contains_key(block_root)
    }

    fn get_proto_node(&self, block_root: &Hash256) -> Option<&ProtoNode> {
        let block_index = self.proto_array.indices.get(block_root)?;
        self.proto_array.nodes.get(*block_index)
    }

    pub fn get_block(&self, block_root: &Hash256) -> Option<Block> {
        let block = self.get_proto_node(block_root)?;
        let parent_root = block
            .parent
            .and_then(|i| self.proto_array.nodes.get(i))
            .map(|parent| parent.root);

        // If a node does not have a `finalized_checkpoint` or `justified_checkpoint` populated,
        // it means it is not a descendant of the finalized checkpoint, so it is valid to return
        // `None` here.
        if let (Some(justified_checkpoint), Some(finalized_checkpoint)) =
            (block.justified_checkpoint, block.finalized_checkpoint)
        {
            Some(Block {
                slot: block.slot,
                root: block.root,
                parent_root,
                state_root: block.state_root,
                target_root: block.target_root,
                current_epoch_shuffling_id: block.current_epoch_shuffling_id.clone(),
                next_epoch_shuffling_id: block.next_epoch_shuffling_id.clone(),
                justified_checkpoint,
                finalized_checkpoint,
                execution_status: block.execution_status,
                unrealized_justified_checkpoint: block.unrealized_justified_checkpoint,
                unrealized_finalized_checkpoint: block.unrealized_finalized_checkpoint,
            })
        } else {
            None
        }
    }

    /// Returns the `block.execution_status` field, if the block is present.
    pub fn get_block_execution_status(&self, block_root: &Hash256) -> Option<ExecutionStatus> {
        let block = self.get_proto_node(block_root)?;
        Some(block.execution_status)
    }

    /// Returns the weight of a given block.
    pub fn get_weight(&self, block_root: &Hash256) -> Option<u64> {
        let block_index = self.proto_array.indices.get(block_root)?;
        self.proto_array
            .nodes
            .get(*block_index)
            .map(|node| node.weight)
    }

    /// See `ProtoArray` documentation.
    pub fn is_descendant(&self, ancestor_root: Hash256, descendant_root: Hash256) -> bool {
        self.proto_array
            .is_descendant(ancestor_root, descendant_root)
    }

    pub fn latest_message(&self, validator_index: usize) -> Option<(Hash256, Epoch)> {
        if validator_index < self.votes.0.len() {
            let vote = &self.votes.0[validator_index];

            if *vote == VoteTracker::default() {
                None
            } else {
                Some((vote.next_root, vote.next_epoch))
            }
        } else {
            None
        }
    }

    /// See `ProtoArray::iter_nodes`
    pub fn iter_nodes<'a>(&'a self, block_root: &Hash256) -> Iter<'a> {
        self.proto_array.iter_nodes(block_root)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        SszContainer::from(self).as_ssz_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        SszContainer::from_ssz_bytes(bytes)
            .map(Into::into)
            .map_err(|e| format!("Failed to decode ProtoArrayForkChoice: {:?}", e))
    }

    /// Returns a read-lock to core `ProtoArray` struct.
    ///
    /// Should only be used when encoding/decoding during troubleshooting.
    pub fn core_proto_array(&self) -> &ProtoArray {
        &self.proto_array
    }

    /// Returns a mutable reference to the core `ProtoArray` struct.
    ///
    /// Should only be used during database schema migrations.
    pub fn core_proto_array_mut(&mut self) -> &mut ProtoArray {
        &mut self.proto_array
    }
}

/// Returns a list of `deltas`, where there is one delta for each of the indices in
/// `0..indices.len()`.
///
/// The deltas are formed by a change between `old_balances` and `new_balances`, and/or a change of vote in `votes`.
///
/// ## Errors
///
/// - If a value in `indices` is greater to or equal to `indices.len()`.
/// - If some `Hash256` in `votes` is not a key in `indices` (except for `Hash256::zero()`, this is
/// always valid).
fn compute_deltas(
    indices: &HashMap<Hash256, usize>,
    votes: &mut ElasticList<VoteTracker>,
    old_balances: &[u64],
    new_balances: &[u64],
    equivocating_indices: &BTreeSet<u64>,
) -> Result<Vec<i64>, Error> {
    let mut deltas = vec![0_i64; indices.len()];

    for (val_index, vote) in votes.iter_mut().enumerate() {
        // There is no need to create a score change if the validator has never voted or both their
        // votes are for the zero hash (alias to the genesis block).
        if vote.current_root == Hash256::zero() && vote.next_root == Hash256::zero() {
            continue;
        }

        // Handle newly slashed validators by deducting their weight from their current vote. We
        // determine if they are newly slashed by checking whether their `vote.current_root` is
        // non-zero. After applying the deduction a single time we set their `current_root` to zero
        // and never update it again (thus preventing repeat deductions).
        //
        // Even if they make new attestations which are processed by `process_attestation` these
        // will only update their `vote.next_root`.
        if equivocating_indices.contains(&(val_index as u64)) {
            // First time we've processed this slashing in fork choice:
            //
            // 1. Add a negative delta for their `current_root`.
            // 2. Set their `current_root` (permanently) to zero.
            if !vote.current_root.is_zero() {
                let old_balance = old_balances.get(val_index).copied().unwrap_or(0);

                if let Some(current_delta_index) = indices.get(&vote.current_root).copied() {
                    let delta = deltas
                        .get(current_delta_index)
                        .ok_or(Error::InvalidNodeDelta(current_delta_index))?
                        .checked_sub(old_balance as i64)
                        .ok_or(Error::DeltaOverflow(current_delta_index))?;

                    // Array access safe due to check on previous line.
                    deltas[current_delta_index] = delta;
                }

                vote.current_root = Hash256::zero();
            }
            // We've handled this slashed validator, continue without applying an ordinary delta.
            continue;
        }

        // If the validator was not included in the _old_ balances (i.e., it did not exist yet)
        // then say its balance was zero.
        let old_balance = old_balances.get(val_index).copied().unwrap_or(0);

        // If the validators vote is not known in the _new_ balances, then use a balance of zero.
        //
        // It is possible that there is a vote for an unknown validator if we change our justified
        // state to a new state with a higher epoch that is on a different fork because that fork may have
        // on-boarded less validators than the prior fork.
        let new_balance = new_balances.get(val_index).copied().unwrap_or(0);

        if vote.current_root != vote.next_root || old_balance != new_balance {
            // We ignore the vote if it is not known in `indices`. We assume that it is outside
            // of our tree (i.e., pre-finalization) and therefore not interesting.
            if let Some(current_delta_index) = indices.get(&vote.current_root).copied() {
                let delta = deltas
                    .get(current_delta_index)
                    .ok_or(Error::InvalidNodeDelta(current_delta_index))?
                    .checked_sub(old_balance as i64)
                    .ok_or(Error::DeltaOverflow(current_delta_index))?;

                // Array access safe due to check on previous line.
                deltas[current_delta_index] = delta;
            }

            // We ignore the vote if it is not known in `indices`. We assume that it is outside
            // of our tree (i.e., pre-finalization) and therefore not interesting.
            if let Some(next_delta_index) = indices.get(&vote.next_root).copied() {
                let delta = deltas
                    .get(next_delta_index)
                    .ok_or(Error::InvalidNodeDelta(next_delta_index))?
                    .checked_add(new_balance as i64)
                    .ok_or(Error::DeltaOverflow(next_delta_index))?;

                // Array access safe due to check on previous line.
                deltas[next_delta_index] = delta;
            }

            vote.current_root = vote.next_root;
        }
    }

    Ok(deltas)
}

#[cfg(test)]
mod test_compute_deltas {
    use super::*;
    use types::MainnetEthSpec;

    /// Gives a hash that is not the zero hash (unless i is `usize::max_value)`.
    fn hash_from_index(i: usize) -> Hash256 {
        Hash256::from_low_u64_be(i as u64 + 1)
    }

    #[test]
    fn finalized_descendant() {
        let genesis_slot = Slot::new(0);
        let genesis_epoch = Epoch::new(0);

        let state_root = Hash256::from_low_u64_be(0);
        let finalized_root = Hash256::from_low_u64_be(1);
        let finalized_desc = Hash256::from_low_u64_be(2);
        let not_finalized_desc = Hash256::from_low_u64_be(3);
        let unknown = Hash256::from_low_u64_be(4);
        let junk_shuffling_id =
            AttestationShufflingId::from_components(Epoch::new(0), Hash256::zero());
        let execution_status = ExecutionStatus::irrelevant();

        let genesis_checkpoint = Checkpoint {
            epoch: genesis_epoch,
            root: finalized_root,
        };

        let mut fc = ProtoArrayForkChoice::new::<MainnetEthSpec>(
            genesis_slot,
            state_root,
            genesis_checkpoint,
            genesis_checkpoint,
            junk_shuffling_id.clone(),
            junk_shuffling_id.clone(),
            execution_status,
        )
        .unwrap();

        // Add block that is a finalized descendant.
        fc.proto_array
            .on_block::<MainnetEthSpec>(
                Block {
                    slot: genesis_slot + 1,
                    root: finalized_desc,
                    parent_root: Some(finalized_root),
                    state_root,
                    target_root: finalized_root,
                    current_epoch_shuffling_id: junk_shuffling_id.clone(),
                    next_epoch_shuffling_id: junk_shuffling_id.clone(),
                    justified_checkpoint: genesis_checkpoint,
                    finalized_checkpoint: genesis_checkpoint,
                    execution_status,
                    unrealized_justified_checkpoint: Some(genesis_checkpoint),
                    unrealized_finalized_checkpoint: Some(genesis_checkpoint),
                },
                genesis_slot + 1,
            )
            .unwrap();

        // Add block that is *not* a finalized descendant.
        fc.proto_array
            .on_block::<MainnetEthSpec>(
                Block {
                    slot: genesis_slot + 1,
                    root: not_finalized_desc,
                    parent_root: None,
                    state_root,
                    target_root: finalized_root,
                    current_epoch_shuffling_id: junk_shuffling_id.clone(),
                    next_epoch_shuffling_id: junk_shuffling_id,
                    justified_checkpoint: genesis_checkpoint,
                    finalized_checkpoint: genesis_checkpoint,
                    execution_status,
                    unrealized_justified_checkpoint: None,
                    unrealized_finalized_checkpoint: None,
                },
                genesis_slot + 1,
            )
            .unwrap();

        assert!(!fc.is_descendant(unknown, unknown));
        assert!(!fc.is_descendant(unknown, finalized_root));
        assert!(!fc.is_descendant(unknown, finalized_desc));
        assert!(!fc.is_descendant(unknown, not_finalized_desc));

        assert!(fc.is_descendant(finalized_root, finalized_root));
        assert!(fc.is_descendant(finalized_root, finalized_desc));
        assert!(!fc.is_descendant(finalized_root, not_finalized_desc));
        assert!(!fc.is_descendant(finalized_root, unknown));

        assert!(!fc.is_descendant(finalized_desc, not_finalized_desc));
        assert!(fc.is_descendant(finalized_desc, finalized_desc));
        assert!(!fc.is_descendant(finalized_desc, finalized_root));
        assert!(!fc.is_descendant(finalized_desc, unknown));

        assert!(fc.is_descendant(not_finalized_desc, not_finalized_desc));
        assert!(!fc.is_descendant(not_finalized_desc, finalized_desc));
        assert!(!fc.is_descendant(not_finalized_desc, finalized_root));
        assert!(!fc.is_descendant(not_finalized_desc, unknown));
    }

    #[test]
    fn zero_hash() {
        let validator_count: usize = 16;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();
        let mut old_balances = vec![];
        let mut new_balances = vec![];
        let equivocating_indices = BTreeSet::new();

        for i in 0..validator_count {
            indices.insert(hash_from_index(i), i);
            votes.0.push(VoteTracker {
                current_root: Hash256::zero(),
                next_root: Hash256::zero(),
                next_epoch: Epoch::new(0),
            });
            old_balances.push(0);
            new_balances.push(0);
        }

        let deltas = compute_deltas(
            &indices,
            &mut votes,
            &old_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");

        assert_eq!(
            deltas.len(),
            validator_count,
            "deltas should have expected length"
        );
        assert_eq!(
            deltas,
            vec![0; validator_count],
            "deltas should all be zero"
        );

        for vote in votes.0 {
            assert_eq!(
                vote.current_root, vote.next_root,
                "the vote shoulds should have been updated"
            );
        }
    }

    #[test]
    fn all_voted_the_same() {
        const BALANCE: u64 = 42;

        let validator_count: usize = 16;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();
        let mut old_balances = vec![];
        let mut new_balances = vec![];
        let equivocating_indices = BTreeSet::new();

        for i in 0..validator_count {
            indices.insert(hash_from_index(i), i);
            votes.0.push(VoteTracker {
                current_root: Hash256::zero(),
                next_root: hash_from_index(0),
                next_epoch: Epoch::new(0),
            });
            old_balances.push(BALANCE);
            new_balances.push(BALANCE);
        }

        let deltas = compute_deltas(
            &indices,
            &mut votes,
            &old_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");

        assert_eq!(
            deltas.len(),
            validator_count,
            "deltas should have expected length"
        );

        for (i, delta) in deltas.into_iter().enumerate() {
            if i == 0 {
                assert_eq!(
                    delta,
                    BALANCE as i64 * validator_count as i64,
                    "zero'th root should have a delta"
                );
            } else {
                assert_eq!(delta, 0, "all other deltas should be zero");
            }
        }

        for vote in votes.0 {
            assert_eq!(
                vote.current_root, vote.next_root,
                "the vote shoulds should have been updated"
            );
        }
    }

    #[test]
    fn different_votes() {
        const BALANCE: u64 = 42;

        let validator_count: usize = 16;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();
        let mut old_balances = vec![];
        let mut new_balances = vec![];
        let equivocating_indices = BTreeSet::new();

        for i in 0..validator_count {
            indices.insert(hash_from_index(i), i);
            votes.0.push(VoteTracker {
                current_root: Hash256::zero(),
                next_root: hash_from_index(i),
                next_epoch: Epoch::new(0),
            });
            old_balances.push(BALANCE);
            new_balances.push(BALANCE);
        }

        let deltas = compute_deltas(
            &indices,
            &mut votes,
            &old_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");

        assert_eq!(
            deltas.len(),
            validator_count,
            "deltas should have expected length"
        );

        for delta in deltas.into_iter() {
            assert_eq!(
                delta, BALANCE as i64,
                "each root should have the same delta"
            );
        }

        for vote in votes.0 {
            assert_eq!(
                vote.current_root, vote.next_root,
                "the vote shoulds should have been updated"
            );
        }
    }

    #[test]
    fn moving_votes() {
        const BALANCE: u64 = 42;

        let validator_count: usize = 16;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();
        let mut old_balances = vec![];
        let mut new_balances = vec![];
        let equivocating_indices = BTreeSet::new();

        for i in 0..validator_count {
            indices.insert(hash_from_index(i), i);
            votes.0.push(VoteTracker {
                current_root: hash_from_index(0),
                next_root: hash_from_index(1),
                next_epoch: Epoch::new(0),
            });
            old_balances.push(BALANCE);
            new_balances.push(BALANCE);
        }

        let deltas = compute_deltas(
            &indices,
            &mut votes,
            &old_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");

        assert_eq!(
            deltas.len(),
            validator_count,
            "deltas should have expected length"
        );

        let total_delta = BALANCE as i64 * validator_count as i64;

        for (i, delta) in deltas.into_iter().enumerate() {
            if i == 0 {
                assert_eq!(
                    delta,
                    0 - total_delta,
                    "zero'th root should have a negative delta"
                );
            } else if i == 1 {
                assert_eq!(delta, total_delta, "first root should have positive delta");
            } else {
                assert_eq!(delta, 0, "all other deltas should be zero");
            }
        }

        for vote in votes.0 {
            assert_eq!(
                vote.current_root, vote.next_root,
                "the vote shoulds should have been updated"
            );
        }
    }

    #[test]
    fn move_out_of_tree() {
        const BALANCE: u64 = 42;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();
        let equivocating_indices = BTreeSet::new();

        // There is only one block.
        indices.insert(hash_from_index(1), 0);

        // There are two validators.
        let old_balances = vec![BALANCE; 2];
        let new_balances = vec![BALANCE; 2];

        // One validator moves their vote from the block to the zero hash.
        votes.0.push(VoteTracker {
            current_root: hash_from_index(1),
            next_root: Hash256::zero(),
            next_epoch: Epoch::new(0),
        });

        // One validator moves their vote from the block to something outside the tree.
        votes.0.push(VoteTracker {
            current_root: hash_from_index(1),
            next_root: Hash256::from_low_u64_be(1337),
            next_epoch: Epoch::new(0),
        });

        let deltas = compute_deltas(
            &indices,
            &mut votes,
            &old_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");

        assert_eq!(deltas.len(), 1, "deltas should have expected length");

        assert_eq!(
            deltas[0],
            0 - BALANCE as i64 * 2,
            "the block should have lost both balances"
        );

        for vote in votes.0 {
            assert_eq!(
                vote.current_root, vote.next_root,
                "the vote shoulds should have been updated"
            );
        }
    }

    #[test]
    fn changing_balances() {
        const OLD_BALANCE: u64 = 42;
        const NEW_BALANCE: u64 = OLD_BALANCE * 2;

        let validator_count: usize = 16;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();
        let mut old_balances = vec![];
        let mut new_balances = vec![];
        let equivocating_indices = BTreeSet::new();

        for i in 0..validator_count {
            indices.insert(hash_from_index(i), i);
            votes.0.push(VoteTracker {
                current_root: hash_from_index(0),
                next_root: hash_from_index(1),
                next_epoch: Epoch::new(0),
            });
            old_balances.push(OLD_BALANCE);
            new_balances.push(NEW_BALANCE);
        }

        let deltas = compute_deltas(
            &indices,
            &mut votes,
            &old_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");

        assert_eq!(
            deltas.len(),
            validator_count,
            "deltas should have expected length"
        );

        for (i, delta) in deltas.into_iter().enumerate() {
            if i == 0 {
                assert_eq!(
                    delta,
                    0 - OLD_BALANCE as i64 * validator_count as i64,
                    "zero'th root should have a negative delta"
                );
            } else if i == 1 {
                assert_eq!(
                    delta,
                    NEW_BALANCE as i64 * validator_count as i64,
                    "first root should have positive delta"
                );
            } else {
                assert_eq!(delta, 0, "all other deltas should be zero");
            }
        }

        for vote in votes.0 {
            assert_eq!(
                vote.current_root, vote.next_root,
                "the vote shoulds should have been updated"
            );
        }
    }

    #[test]
    fn validator_appears() {
        const BALANCE: u64 = 42;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();
        let equivocating_indices = BTreeSet::new();

        // There are two blocks.
        indices.insert(hash_from_index(1), 0);
        indices.insert(hash_from_index(2), 1);

        // There is only one validator in the old balances.
        let old_balances = vec![BALANCE; 1];
        // There are two validators in the new balances.
        let new_balances = vec![BALANCE; 2];

        // Both validator move votes from block 1 to block 2.
        for _ in 0..2 {
            votes.0.push(VoteTracker {
                current_root: hash_from_index(1),
                next_root: hash_from_index(2),
                next_epoch: Epoch::new(0),
            });
        }

        let deltas = compute_deltas(
            &indices,
            &mut votes,
            &old_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");

        assert_eq!(deltas.len(), 2, "deltas should have expected length");

        assert_eq!(
            deltas[0],
            0 - BALANCE as i64,
            "block 1 should have only lost one balance"
        );
        assert_eq!(
            deltas[1],
            2 * BALANCE as i64,
            "block 2 should have gained two balances"
        );

        for vote in votes.0 {
            assert_eq!(
                vote.current_root, vote.next_root,
                "the vote shoulds should have been updated"
            );
        }
    }

    #[test]
    fn validator_disappears() {
        const BALANCE: u64 = 42;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();
        let equivocating_indices = BTreeSet::new();

        // There are two blocks.
        indices.insert(hash_from_index(1), 0);
        indices.insert(hash_from_index(2), 1);

        // There are two validators in the old balances.
        let old_balances = vec![BALANCE; 2];
        // There is only one validator in the new balances.
        let new_balances = vec![BALANCE; 1];

        // Both validator move votes from block 1 to block 2.
        for _ in 0..2 {
            votes.0.push(VoteTracker {
                current_root: hash_from_index(1),
                next_root: hash_from_index(2),
                next_epoch: Epoch::new(0),
            });
        }

        let deltas = compute_deltas(
            &indices,
            &mut votes,
            &old_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");

        assert_eq!(deltas.len(), 2, "deltas should have expected length");

        assert_eq!(
            deltas[0],
            0 - BALANCE as i64 * 2,
            "block 1 should have lost both balances"
        );
        assert_eq!(
            deltas[1], BALANCE as i64,
            "block 2 should have only gained one balance"
        );

        for vote in votes.0 {
            assert_eq!(
                vote.current_root, vote.next_root,
                "the vote should have been updated"
            );
        }
    }

    #[test]
    fn validator_equivocates() {
        const OLD_BALANCE: u64 = 42;
        const NEW_BALANCE: u64 = 43;

        let mut indices = HashMap::new();
        let mut votes = ElasticList::default();

        // There are two blocks.
        indices.insert(hash_from_index(1), 0);
        indices.insert(hash_from_index(2), 1);

        // There are two validators.
        let old_balances = vec![OLD_BALANCE; 2];
        let new_balances = vec![NEW_BALANCE; 2];

        // Both validator move votes from block 1 to block 2.
        for _ in 0..2 {
            votes.0.push(VoteTracker {
                current_root: hash_from_index(1),
                next_root: hash_from_index(2),
                next_epoch: Epoch::new(0),
            });
        }

        // Validator 0 is slashed.
        let equivocating_indices = BTreeSet::from_iter([0]);

        let deltas = compute_deltas(
            &indices,
            &mut votes,
            &old_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");

        assert_eq!(deltas.len(), 2, "deltas should have expected length");

        assert_eq!(
            deltas[0],
            -2 * OLD_BALANCE as i64,
            "block 1 should have lost two old balances"
        );
        assert_eq!(
            deltas[1], NEW_BALANCE as i64,
            "block 2 should have gained one balance"
        );

        // Validator 0's current root should have been reset.
        assert_eq!(votes.0[0].current_root, Hash256::zero());
        assert_eq!(votes.0[0].next_root, hash_from_index(2));

        // Validator 1's current root should have been updated.
        assert_eq!(votes.0[1].current_root, hash_from_index(2));

        // Re-computing the deltas should be a no-op (no repeat deduction for the slashed validator).
        let deltas = compute_deltas(
            &indices,
            &mut votes,
            &new_balances,
            &new_balances,
            &equivocating_indices,
        )
        .expect("should compute deltas");
        assert_eq!(deltas, vec![0, 0]);
    }
}
