//! Provides the `InclusionListStore`, an in-memory store of the `SignedInclusionList`s received
//! for recent slots ([New in Heze:EIP7805]).
//!
//! It backs the gossip first-or-second and equivocation checks, the fork-choice enforcement reads
//! (timely inclusion lists only), and the block-production reads (all inclusion lists). Entries are
//! keyed by `(slot, committee_root)`: by slot so they can be pruned as they age out, and by
//! committee root so a committee disagreement across a reorg does not collide. Only the current
//! slot and the two preceding it are retained.

use ssz_types::{BitVector, FixedVector};
use std::collections::{HashMap, HashSet};
use tree_hash::TreeHash;
use types::{EthSpec, Hash256, SignedInclusionList, Slot, Transaction};

/// Slots retained behind the current slot, i.e. `{N, N-1, N-2}`.
///
/// One more than `MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS` requires. A payload envelope for slot `S`
/// is checked against the slot `S-1` inclusion lists, and that check is not guaranteed to run
/// within slot `S`, so the read may happen once the clock has already reached `S+1`.
const SLOTS_RETAINED: u64 = 2;

/// The result of inserting a `SignedInclusionList`. Drives the gossip accept/ignore verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// Stored for the first time.
    New,
    /// An exact duplicate of an already-stored inclusion list.
    Seen,
    /// A second, differing inclusion list from this validator. The validator is now flagged as an
    /// equivocator and this message is not stored, but it is still forwarded per the spec.
    Equivocating,
    /// A further inclusion list from an already-flagged equivocator.
    SubsequentEquivocation,
    /// The inclusion list's slot is older than the retained window.
    Old,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    /// The committee length did not match `INCLUSION_LIST_COMMITTEE_SIZE`.
    InvalidCommittee(ssz_types::Error),
    /// A bit index was out of range for the committee bitvector.
    Bitfield(ssz::BitfieldError),
}

impl From<ssz_types::Error> for Error {
    fn from(e: ssz_types::Error) -> Self {
        Error::InvalidCommittee(e)
    }
}

impl From<ssz::BitfieldError> for Error {
    fn from(e: ssz::BitfieldError) -> Self {
        Error::Bitfield(e)
    }
}

struct SlotEntry<E: EthSpec> {
    /// `committee_root -> { il_root -> (signed_inclusion_list, is_timely) }`, where
    /// `il_root = hash_tree_root(message)`.
    by_committee: HashMap<Hash256, HashMap<Hash256, (SignedInclusionList<E>, bool)>>,
    /// Validators flagged as equivocators, grouped by `committee_root`.
    equivocators: HashMap<Hash256, HashSet<u64>>,
    /// Count of valid inclusion lists seen this slot per validator, for the first-or-second rule.
    validator_counts: HashMap<u64, usize>,
}

impl<E: EthSpec> Default for SlotEntry<E> {
    fn default() -> Self {
        Self {
            by_committee: HashMap::new(),
            equivocators: HashMap::new(),
            validator_counts: HashMap::new(),
        }
    }
}

pub struct InclusionListStore<E: EthSpec> {
    slots: HashMap<Slot, SlotEntry<E>>,
    lowest_permissible_slot: Slot,
}

impl<E: EthSpec> Default for InclusionListStore<E> {
    fn default() -> Self {
        Self {
            slots: HashMap::new(),
            lowest_permissible_slot: Slot::new(0),
        }
    }
}

impl<E: EthSpec> InclusionListStore<E> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate-and-insert a received `SignedInclusionList`, detecting equivocation.
    ///
    /// The caller is expected to have already run the gossip p2p checks; this is the final
    /// validation step and the source of truth for whether the message should be forwarded.
    pub fn process_inclusion_list(
        &mut self,
        signed_inclusion_list: SignedInclusionList<E>,
        is_timely: bool,
    ) -> InsertOutcome {
        let slot = signed_inclusion_list.message.slot;
        let committee_root = signed_inclusion_list.message.inclusion_list_committee_root;
        let validator_index = signed_inclusion_list.message.validator_index;

        if slot < self.lowest_permissible_slot {
            return InsertOutcome::Old;
        }

        let il_root = signed_inclusion_list.message.tree_hash_root();
        let entry = self.slots.entry(slot).or_default();

        *entry.validator_counts.entry(validator_index).or_insert(0) += 1;

        if entry
            .equivocators
            .get(&committee_root)
            .is_some_and(|set| set.contains(&validator_index))
        {
            return InsertOutcome::SubsequentEquivocation;
        }

        let stored = entry.by_committee.get(&committee_root);
        if stored.is_some_and(|map| map.contains_key(&il_root)) {
            return InsertOutcome::Seen;
        }
        let is_equivocation = stored.is_some_and(|map| {
            map.values()
                .any(|(il, _)| il.message.validator_index == validator_index)
        });

        if is_equivocation {
            entry
                .equivocators
                .entry(committee_root)
                .or_default()
                .insert(validator_index);
            return InsertOutcome::Equivocating;
        }

        entry
            .by_committee
            .entry(committee_root)
            .or_default()
            .insert(il_root, (signed_inclusion_list, is_timely));
        InsertOutcome::New
    }

    /// Answers the gossip "first or second valid message from this validator" check.
    pub fn seen_twice(&self, slot: Slot, validator_index: u64) -> bool {
        self.slots
            .get(&slot)
            .and_then(|entry| entry.validator_counts.get(&validator_index))
            .is_some_and(|count| *count >= 2)
    }

    /// Validator indices that submitted a valid, non-equivocating inclusion list for
    /// `(slot, committee_root)`, timely-filtered when `only_timely` is set.
    fn submitted_validators(
        &self,
        slot: Slot,
        committee_root: Hash256,
        only_timely: bool,
    ) -> HashSet<u64> {
        let Some(entry) = self.slots.get(&slot) else {
            return HashSet::new();
        };
        let Some(stored) = entry.by_committee.get(&committee_root) else {
            return HashSet::new();
        };
        let equivocators = entry.equivocators.get(&committee_root);

        stored
            .values()
            .filter(|(_, is_timely)| !only_timely || *is_timely)
            .map(|(il, _)| il.message.validator_index)
            .filter(|validator| !equivocators.is_some_and(|set| set.contains(validator)))
            .collect()
    }

    /// The union of transactions from all valid, non-equivocating inclusion lists for
    /// `(slot, committee_root)`, deduplicated. Timely-filtered when `only_timely` is set.
    pub fn get_inclusion_list_transactions(
        &self,
        slot: Slot,
        committee_root: Hash256,
        only_timely: bool,
    ) -> Vec<Transaction<E::MaxBytesPerTransaction>> {
        let Some(entry) = self.slots.get(&slot) else {
            return Vec::new();
        };
        let Some(stored) = entry.by_committee.get(&committee_root) else {
            return Vec::new();
        };
        let equivocators = entry.equivocators.get(&committee_root);

        let mut seen = HashSet::new();
        let mut transactions = Vec::new();
        for (il, is_timely) in stored.values() {
            if only_timely && !is_timely {
                continue;
            }
            if equivocators.is_some_and(|set| set.contains(&il.message.validator_index)) {
                continue;
            }
            for tx in il.message.transactions.iter() {
                if seen.insert(tx.tree_hash_root()) {
                    transactions.push(tx.clone());
                }
            }
        }
        transactions
    }

    /// The committee bits for `slot`: bit `i` is set iff `committee[i]` submitted a valid,
    /// non-equivocating inclusion list. Timely-filtered when `only_timely` is set.
    ///
    /// `committee` is the ordered inclusion list committee; the caller resolves it since the store
    /// retains only the `committee_root`, not the committee itself, and the bits are
    /// position-indexed.
    pub fn get_inclusion_list_bits(
        &self,
        slot: Slot,
        committee: &[u64],
        only_timely: bool,
    ) -> Result<BitVector<E::InclusionListCommitteeSize>, Error> {
        let committee_root = Self::committee_root(committee)?;
        let submitted = self.submitted_validators(slot, committee_root, only_timely);

        let mut bits = BitVector::new();
        for (i, validator) in committee.iter().enumerate() {
            if submitted.contains(validator) {
                bits.set(i, true)?;
            }
        }
        Ok(bits)
    }

    /// Whether `bits` is inclusive of the node's own view, i.e. every member we saw an inclusion
    /// list from is also set in `bits`. Used to validate an incoming bid's `inclusion_list_bits`.
    pub fn is_inclusion_list_bits_inclusive(
        &self,
        slot: Slot,
        committee: &[u64],
        bits: &BitVector<E::InclusionListCommitteeSize>,
        only_timely: bool,
    ) -> Result<bool, Error> {
        let local = self.get_inclusion_list_bits(slot, committee, only_timely)?;
        for i in 0..local.len() {
            if local.get(i)? && !bits.get(i)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The stored signed inclusion lists for the given `validators`, used to serve
    /// `InclusionListsByIndices`. Equivocators and missing entries are skipped.
    pub fn get_signed_inclusion_lists(
        &self,
        slot: Slot,
        committee_root: Hash256,
        validators: &[u64],
    ) -> Vec<SignedInclusionList<E>> {
        let Some(entry) = self.slots.get(&slot) else {
            return Vec::new();
        };
        let Some(stored) = entry.by_committee.get(&committee_root) else {
            return Vec::new();
        };
        let equivocators = entry.equivocators.get(&committee_root);
        let requested: HashSet<u64> = validators.iter().copied().collect();

        stored
            .values()
            .map(|(il, _)| il)
            .filter(|il| requested.contains(&il.message.validator_index))
            .filter(|il| !equivocators.is_some_and(|set| set.contains(&il.message.validator_index)))
            .cloned()
            .collect()
    }

    /// Drop every slot below `current_slot - SLOTS_RETAINED`. Hooked into the per-slot timer.
    pub fn prune(&mut self, current_slot: Slot) {
        let lowest_permissible_slot = current_slot.saturating_sub(SLOTS_RETAINED);
        self.lowest_permissible_slot = lowest_permissible_slot;
        self.slots
            .retain(|slot, _| *slot >= lowest_permissible_slot);
    }

    /// `hash_tree_root` of the ordered committee as `Vector[ValidatorIndex, INCLUSION_LIST_COMMITTEE_SIZE]`,
    /// matching the gossiped `inclusion_list_committee_root`.
    fn committee_root(committee: &[u64]) -> Result<Hash256, ssz_types::Error> {
        let committee: FixedVector<u64, E::InclusionListCommitteeSize> =
            FixedVector::new(committee.to_vec())?;
        Ok(committee.tree_hash_root())
    }
}

#[cfg(test)]
mod tests {
    use super::{InclusionListStore, InsertOutcome};
    use bls::Signature;
    use ssz_types::{BitVector, VariableList};
    use types::{
        EthSpec, Hash256, InclusionList, MinimalEthSpec, SignedInclusionList, Slot, Transaction,
    };

    type E = MinimalEthSpec;

    fn root(byte: u8) -> Hash256 {
        Hash256::from([byte; 32])
    }

    fn tx(byte: u8) -> Transaction<<E as EthSpec>::MaxBytesPerTransaction> {
        VariableList::new(vec![byte]).unwrap()
    }

    fn signed_il(
        slot: u64,
        validator_index: u64,
        committee_root: Hash256,
        tx_bytes: &[u8],
    ) -> SignedInclusionList<E> {
        let transactions = VariableList::new(tx_bytes.iter().map(|b| tx(*b)).collect()).unwrap();
        SignedInclusionList {
            message: InclusionList {
                slot: Slot::new(slot),
                validator_index,
                inclusion_list_committee_root: committee_root,
                transactions,
            },
            signature: Signature::empty(),
        }
    }

    #[test]
    fn new_then_duplicate_is_seen() {
        let mut store = InclusionListStore::<E>::new();
        let il = signed_il(10, 1, root(1), &[0xaa]);
        assert_eq!(
            store.process_inclusion_list(il.clone(), true),
            InsertOutcome::New
        );
        assert_eq!(store.process_inclusion_list(il, true), InsertOutcome::Seen);
    }

    #[test]
    fn differing_list_flags_equivocation() {
        let mut store = InclusionListStore::<E>::new();
        assert_eq!(
            store.process_inclusion_list(signed_il(10, 1, root(1), &[0xaa]), true),
            InsertOutcome::New
        );
        assert_eq!(
            store.process_inclusion_list(signed_il(10, 1, root(1), &[0xbb]), true),
            InsertOutcome::Equivocating
        );
        assert_eq!(
            store.process_inclusion_list(signed_il(10, 1, root(1), &[0xcc]), true),
            InsertOutcome::SubsequentEquivocation
        );
    }

    #[test]
    fn old_slot_rejected_after_prune() {
        let mut store = InclusionListStore::<E>::new();
        store.prune(Slot::new(20));
        assert_eq!(
            store.process_inclusion_list(signed_il(10, 1, root(1), &[0xaa]), true),
            InsertOutcome::Old
        );
    }

    #[test]
    fn seen_twice_counts_valid_arrivals() {
        let mut store = InclusionListStore::<E>::new();
        assert!(!store.seen_twice(Slot::new(10), 1));
        store.process_inclusion_list(signed_il(10, 1, root(1), &[0xaa]), true);
        assert!(!store.seen_twice(Slot::new(10), 1));
        // A differing (equivocating) message still counts as a valid arrival.
        store.process_inclusion_list(signed_il(10, 1, root(1), &[0xbb]), true);
        assert!(store.seen_twice(Slot::new(10), 1));
    }

    #[test]
    fn transactions_are_deduplicated_and_timely_filtered() {
        let mut store = InclusionListStore::<E>::new();
        let cr = root(1);
        store.process_inclusion_list(signed_il(10, 1, cr, &[0xaa, 0xbb]), true);
        store.process_inclusion_list(signed_il(10, 2, cr, &[0xbb, 0xcc]), false);

        let all = store.get_inclusion_list_transactions(Slot::new(10), cr, false);
        assert_eq!(all.len(), 3);

        let timely = store.get_inclusion_list_transactions(Slot::new(10), cr, true);
        assert_eq!(timely.len(), 2);
    }

    #[test]
    fn equivocators_excluded_from_reads() {
        let mut store = InclusionListStore::<E>::new();
        let cr = root(1);
        store.process_inclusion_list(signed_il(10, 1, cr, &[0xaa]), true);
        store.process_inclusion_list(signed_il(10, 1, cr, &[0xbb]), true);
        assert!(
            store
                .get_inclusion_list_transactions(Slot::new(10), cr, false)
                .is_empty()
        );
    }

    #[test]
    fn bits_reflect_submitters_and_inclusivity() {
        let mut store = InclusionListStore::<E>::new();
        let committee: Vec<u64> = (100..116).collect();
        let cr = InclusionListStore::<E>::committee_root(&committee).unwrap();

        store.process_inclusion_list(signed_il(10, committee[3], cr, &[0xaa]), true);
        store.process_inclusion_list(signed_il(10, committee[7], cr, &[0xbb]), true);

        let bits = store
            .get_inclusion_list_bits(Slot::new(10), &committee, false)
            .unwrap();
        assert!(bits.get(3).unwrap());
        assert!(bits.get(7).unwrap());
        assert!(!bits.get(0).unwrap());

        assert!(
            store
                .is_inclusion_list_bits_inclusive(Slot::new(10), &committee, &bits, false)
                .unwrap()
        );

        let mut missing = BitVector::<<E as EthSpec>::InclusionListCommitteeSize>::new();
        missing.set(7, true).unwrap();
        assert!(
            !store
                .is_inclusion_list_bits_inclusive(Slot::new(10), &committee, &missing, false)
                .unwrap()
        );
    }

    #[test]
    fn get_signed_inclusion_lists_skips_equivocators_and_missing() {
        let mut store = InclusionListStore::<E>::new();
        let cr = root(1);
        store.process_inclusion_list(signed_il(10, 1, cr, &[0xaa]), true);
        store.process_inclusion_list(signed_il(10, 2, cr, &[0xbb]), true);
        store.process_inclusion_list(signed_il(10, 2, cr, &[0xcc]), true);

        let result = store.get_signed_inclusion_lists(Slot::new(10), cr, &[1, 2, 3]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].message.validator_index, 1);
    }

    #[test]
    fn prune_drops_old_slots() {
        let mut store = InclusionListStore::<E>::new();
        let cr = root(1);
        store.process_inclusion_list(signed_il(10, 1, cr, &[0xaa]), true);
        store.process_inclusion_list(signed_il(12, 1, cr, &[0xbb]), true);

        store.prune(Slot::new(12));
        assert!(
            !store
                .get_inclusion_list_transactions(Slot::new(10), cr, false)
                .is_empty()
        );

        store.prune(Slot::new(13));
        assert!(
            store
                .get_inclusion_list_transactions(Slot::new(10), cr, false)
                .is_empty()
        );
    }
}
