//! Provides the `InclusionListStore`, an in-memory store of the `SignedInclusionList`s received
//! for recent slots ([New in Heze:EIP7805]).
//!
//! It backs the gossip first-or-second and equivocation checks, the fork-choice enforcement reads
//! (timely inclusion lists only), and the block-production reads (all inclusion lists). Entries are
//! keyed by `(slot, dependent_root)`, which pins an inclusion list to the committee it was produced
//! against.

use ssz_types::{BitVector, FixedVector, ProgressiveVariableList};
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use tree_hash::TreeHash;
use types::{ChainSpec, EthSpec, Hash256, SignedInclusionList, Slot};

/// The shuffling `dependent_root` an inclusion list was produced against.
pub type DependentRoot = Hash256;

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
    /// A bit index was out of range for the committee bitvector.
    Bitfield(ssz::BitfieldError),
}

impl From<ssz::BitfieldError> for Error {
    fn from(e: ssz::BitfieldError) -> Self {
        Error::Bitfield(e)
    }
}

#[derive(Default)]
struct SlotEntry {
    /// Keyed by validator index, so a validator holds at most one inclusion list per dependent
    /// root. The `bool` records whether it arrived timely.
    by_dependent_root: HashMap<DependentRoot, HashMap<u64, (SignedInclusionList, bool)>>,
    /// Validator indices flagged as equivocators.
    equivocators: HashMap<DependentRoot, HashSet<u64>>,
    /// Count of valid inclusion lists seen this slot per validator, for the first-or-second rule.
    validator_counts: HashMap<u64, usize>,
}

pub struct InclusionListStore<E: EthSpec> {
    slots: HashMap<Slot, SlotEntry>,
    lowest_permissible_slot: Slot,
    first_heze_slot: Slot,
    /// One more than `MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS` requires. A slot `S` payload
    /// envelope reads the slot `S-1` lists, and might not be processed until the clock is at `S+1`.
    slots_retained: u64,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> InclusionListStore<E> {
    pub fn new(spec: &ChainSpec) -> Self {
        // `heze_fork_epoch` holds the far future sentinel when Heze is unscheduled.
        let first_heze_slot = spec
            .heze_fork_epoch
            .filter(|_| spec.is_heze_scheduled())
            .map(|epoch| epoch.start_slot(E::slots_per_epoch()))
            .unwrap_or_else(|| Slot::new(0));
        Self {
            slots: HashMap::new(),
            lowest_permissible_slot: first_heze_slot,
            first_heze_slot,
            slots_retained: spec
                .min_slots_for_inclusion_lists_requests
                .saturating_add(1),
            _phantom: PhantomData,
        }
    }

    /// Validate-and-insert a received `SignedInclusionList`, detecting equivocation.
    ///
    /// TODO(heze): accept a `GossipVerifiedInclusionList` once gossip verification lands, so the
    /// caller cannot skip the p2p checks.
    pub fn process_inclusion_list(
        &mut self,
        signed_inclusion_list: SignedInclusionList,
        is_timely: bool,
    ) -> InsertOutcome {
        let inclusion_list = &signed_inclusion_list.message;
        let slot = inclusion_list.slot;
        let dependent_root = inclusion_list.dependent_root;
        let validator_index = inclusion_list.validator_index;

        if slot < self.lowest_permissible_slot {
            return InsertOutcome::Old;
        }

        let entry = self.slots.entry(slot).or_default();
        let stored_differs = entry
            .by_dependent_root
            .get(&dependent_root)
            .and_then(|by_validator| by_validator.get(&validator_index))
            .map(|(stored, _)| stored.message != *inclusion_list);

        match stored_differs {
            // An exact duplicate is not a second valid message, so it is not counted.
            Some(false) => InsertOutcome::Seen,
            Some(true) => {
                let newly_flagged = entry
                    .equivocators
                    .entry(dependent_root)
                    .or_default()
                    .insert(validator_index);
                if newly_flagged {
                    *entry.validator_counts.entry(validator_index).or_insert(0) += 1;
                    InsertOutcome::Equivocating
                } else {
                    InsertOutcome::SubsequentEquivocation
                }
            }
            None => {
                *entry.validator_counts.entry(validator_index).or_insert(0) += 1;
                entry
                    .by_dependent_root
                    .entry(dependent_root)
                    .or_default()
                    .insert(validator_index, (signed_inclusion_list, is_timely));
                InsertOutcome::New
            }
        }
    }

    /// Answers the gossip "first or second valid message from this validator" check.
    pub fn seen_twice(&self, slot: Slot, validator_index: u64) -> bool {
        self.slots
            .get(&slot)
            .and_then(|entry| entry.validator_counts.get(&validator_index))
            .is_some_and(|count| *count >= 2)
    }

    /// Validator indices that submitted a valid, non-equivocating inclusion list for
    /// `(slot, dependent_root)`, timely-filtered when `only_timely` is set.
    fn submitted_validators(
        &self,
        slot: Slot,
        dependent_root: DependentRoot,
        only_timely: bool,
    ) -> HashSet<u64> {
        let Some(entry) = self.slots.get(&slot) else {
            return HashSet::new();
        };
        let Some(stored) = entry.by_dependent_root.get(&dependent_root) else {
            return HashSet::new();
        };
        let equivocators = entry.equivocators.get(&dependent_root);

        stored
            .iter()
            .filter(|(_, (_, is_timely))| !only_timely || *is_timely)
            .map(|(validator, _)| *validator)
            .filter(|validator| !equivocators.is_some_and(|set| set.contains(validator)))
            .collect()
    }

    /// The union of transactions from all valid, non-equivocating inclusion lists for
    /// `(slot, dependent_root)`, deduplicated. Timely-filtered when `only_timely` is set.
    pub fn get_inclusion_list_transactions(
        &self,
        slot: Slot,
        dependent_root: DependentRoot,
        only_timely: bool,
    ) -> Vec<ProgressiveVariableList<u8>> {
        let Some(entry) = self.slots.get(&slot) else {
            return Vec::new();
        };
        let Some(stored) = entry.by_dependent_root.get(&dependent_root) else {
            return Vec::new();
        };
        let equivocators = entry.equivocators.get(&dependent_root);

        let mut seen = HashSet::new();
        let mut transactions = Vec::new();
        for (validator, (il, is_timely)) in stored.iter() {
            if only_timely && !is_timely {
                continue;
            }
            if equivocators.is_some_and(|set| set.contains(validator)) {
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

    /// The committee bits for `(slot, dependent_root)`: bit `i` is set iff `il_committee[i]`
    /// submitted a valid, non-equivocating inclusion list. Timely-filtered when `only_timely` is
    /// set.
    ///
    /// `il_committee` is the ordered inclusion list committee.
    pub fn get_inclusion_list_bits(
        &self,
        slot: Slot,
        dependent_root: DependentRoot,
        il_committee: &FixedVector<u64, E::InclusionListCommitteeSize>,
        only_timely: bool,
    ) -> Result<BitVector<E::InclusionListCommitteeSize>, Error> {
        let submitted = self.submitted_validators(slot, dependent_root, only_timely);

        let mut bits = BitVector::new();
        for (i, validator) in il_committee.iter().enumerate() {
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
        dependent_root: DependentRoot,
        il_committee: &FixedVector<u64, E::InclusionListCommitteeSize>,
        bits: &BitVector<E::InclusionListCommitteeSize>,
        only_timely: bool,
    ) -> Result<bool, Error> {
        let local =
            self.get_inclusion_list_bits(slot, dependent_root, il_committee, only_timely)?;
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
        dependent_root: DependentRoot,
        validators: &[u64],
    ) -> Vec<SignedInclusionList> {
        let Some(entry) = self.slots.get(&slot) else {
            return Vec::new();
        };
        let Some(stored) = entry.by_dependent_root.get(&dependent_root) else {
            return Vec::new();
        };
        let equivocators = entry.equivocators.get(&dependent_root);
        let requested: HashSet<u64> = validators.iter().copied().collect();

        stored
            .iter()
            .filter(|(validator, _)| requested.contains(validator))
            .filter(|(validator, _)| !equivocators.is_some_and(|set| set.contains(validator)))
            .map(|(_, (il, _))| il.clone())
            .collect()
    }

    /// Drop every slot below `current_slot - slots_retained`. Hooked into the per-slot timer.
    pub fn prune(&mut self, current_slot: Slot) {
        let lowest_permissible_slot = std::cmp::max(
            current_slot.saturating_sub(self.slots_retained),
            self.first_heze_slot,
        );
        self.lowest_permissible_slot = lowest_permissible_slot;
        self.slots
            .retain(|slot, _| *slot >= lowest_permissible_slot);
    }
}

#[cfg(test)]
mod tests {
    use super::{DependentRoot, InclusionListStore, InsertOutcome};
    use bls::Signature;
    use ssz_types::{BitVector, FixedVector, ProgressiveVariableList};
    use types::{
        Epoch, EthSpec, Hash256, InclusionList, MinimalEthSpec, SignedInclusionList, Slot,
    };

    type E = MinimalEthSpec;

    fn new_store() -> InclusionListStore<E> {
        InclusionListStore::new(&E::default_spec())
    }

    fn root(byte: u8) -> Hash256 {
        Hash256::from([byte; 32])
    }

    fn tx(byte: u8) -> ProgressiveVariableList<u8> {
        ProgressiveVariableList::new(vec![byte])
    }

    fn signed_il(
        slot: u64,
        validator_index: u64,
        dependent_root: DependentRoot,
        tx_bytes: &[u8],
    ) -> SignedInclusionList {
        SignedInclusionList {
            message: InclusionList {
                slot: Slot::new(slot),
                validator_index,
                dependent_root,
                transactions: ProgressiveVariableList::new(
                    tx_bytes.iter().map(|b| tx(*b)).collect(),
                ),
            },
            signature: Signature::empty(),
        }
    }

    #[test]
    fn new_then_duplicate_is_seen() {
        let mut store = new_store();
        let il = signed_il(10, 1, root(1), &[0xaa]);
        assert_eq!(
            store.process_inclusion_list(il.clone(), true),
            InsertOutcome::New
        );
        assert_eq!(store.process_inclusion_list(il, true), InsertOutcome::Seen);
        // A duplicate is not a second valid message.
        assert!(!store.seen_twice(Slot::new(10), 1));
    }

    #[test]
    fn differing_list_flags_equivocation() {
        let mut store = new_store();
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
        let mut store = new_store();
        store.prune(Slot::new(20));
        assert_eq!(
            store.process_inclusion_list(signed_il(10, 1, root(1), &[0xaa]), true),
            InsertOutcome::Old
        );
    }

    #[test]
    fn seen_twice_counts_valid_arrivals() {
        let mut store = new_store();
        assert!(!store.seen_twice(Slot::new(10), 1));
        store.process_inclusion_list(signed_il(10, 1, root(1), &[0xaa]), true);
        assert!(!store.seen_twice(Slot::new(10), 1));
        // A differing (equivocating) message still counts as a valid arrival.
        store.process_inclusion_list(signed_il(10, 1, root(1), &[0xbb]), true);
        assert!(store.seen_twice(Slot::new(10), 1));
    }

    #[test]
    fn transactions_are_deduplicated_and_timely_filtered() {
        let mut store = new_store();
        let dr = root(1);
        store.process_inclusion_list(signed_il(10, 1, dr, &[0xaa, 0xbb]), true);
        store.process_inclusion_list(signed_il(10, 2, dr, &[0xbb, 0xcc]), false);

        let all = store.get_inclusion_list_transactions(Slot::new(10), dr, false);
        assert_eq!(all.len(), 3);

        let timely = store.get_inclusion_list_transactions(Slot::new(10), dr, true);
        assert_eq!(timely.len(), 2);
    }

    #[test]
    fn equivocators_excluded_from_reads() {
        let mut store = new_store();
        let dr = root(1);
        store.process_inclusion_list(signed_il(10, 1, dr, &[0xaa]), true);
        store.process_inclusion_list(signed_il(10, 1, dr, &[0xbb]), true);
        assert!(
            store
                .get_inclusion_list_transactions(Slot::new(10), dr, false)
                .is_empty()
        );
    }

    #[test]
    fn bits_reflect_submitters_and_inclusivity() {
        let mut store = new_store();
        let il_committee: FixedVector<u64, <E as EthSpec>::InclusionListCommitteeSize> =
            FixedVector::new((100..116).collect()).unwrap();
        let dr = root(1);

        store.process_inclusion_list(signed_il(10, il_committee[3], dr, &[0xaa]), true);
        store.process_inclusion_list(signed_il(10, il_committee[7], dr, &[0xbb]), true);

        let bits = store
            .get_inclusion_list_bits(Slot::new(10), dr, &il_committee, false)
            .unwrap();
        assert!(bits.get(3).unwrap());
        assert!(bits.get(7).unwrap());
        assert!(!bits.get(0).unwrap());

        assert!(
            store
                .is_inclusion_list_bits_inclusive(Slot::new(10), dr, &il_committee, &bits, false)
                .unwrap()
        );

        let mut missing = BitVector::<<E as EthSpec>::InclusionListCommitteeSize>::new();
        missing.set(7, true).unwrap();
        assert!(
            !store
                .is_inclusion_list_bits_inclusive(Slot::new(10), dr, &il_committee, &missing, false)
                .unwrap()
        );
    }

    /// Two branches can have different dependent roots, so one list per branch is not equivocation.
    #[test]
    fn differing_dependent_roots_are_not_equivocation() {
        let mut store = new_store();
        assert_eq!(
            store.process_inclusion_list(signed_il(10, 1, root(1), &[0xaa]), true),
            InsertOutcome::New
        );
        assert_eq!(
            store.process_inclusion_list(signed_il(10, 1, root(2), &[0xbb]), true),
            InsertOutcome::New
        );

        for dr in [root(1), root(2)] {
            assert_eq!(
                store
                    .get_inclusion_list_transactions(Slot::new(10), dr, false)
                    .len(),
                1
            );
        }

        // Both still count against the first-or-second rule, which is per validator and slot.
        assert!(store.seen_twice(Slot::new(10), 1));
    }

    #[test]
    fn get_signed_inclusion_lists_skips_equivocators_and_missing() {
        let mut store = new_store();
        let dr = root(1);
        store.process_inclusion_list(signed_il(10, 1, dr, &[0xaa]), true);
        store.process_inclusion_list(signed_il(10, 2, dr, &[0xbb]), true);
        store.process_inclusion_list(signed_il(10, 2, dr, &[0xcc]), true);

        let result = store.get_signed_inclusion_lists(Slot::new(10), dr, &[1, 2, 3]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].message.validator_index, 1);
    }

    #[test]
    fn prune_drops_old_slots() {
        let mut store = new_store();
        let dr = root(1);
        store.process_inclusion_list(signed_il(10, 1, dr, &[0xaa]), true);
        store.process_inclusion_list(signed_il(12, 1, dr, &[0xbb]), true);

        store.prune(Slot::new(12));
        assert!(
            !store
                .get_inclusion_list_transactions(Slot::new(10), dr, false)
                .is_empty()
        );

        store.prune(Slot::new(13));
        assert!(
            store
                .get_inclusion_list_transactions(Slot::new(10), dr, false)
                .is_empty()
        );
    }

    /// A devnet may raise `MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS`, which must widen the window.
    #[test]
    fn retention_window_follows_the_spec_value() {
        let mut spec = E::default_spec();
        spec.min_slots_for_inclusion_lists_requests = 4;
        let mut store = InclusionListStore::<E>::new(&spec);
        let dr = root(1);
        store.process_inclusion_list(signed_il(10, 1, dr, &[0xaa]), true);

        store.prune(Slot::new(15));
        assert!(
            !store
                .get_inclusion_list_transactions(Slot::new(10), dr, false)
                .is_empty()
        );

        store.prune(Slot::new(16));
        assert!(
            store
                .get_inclusion_list_transactions(Slot::new(10), dr, false)
                .is_empty()
        );
    }

    #[test]
    fn floor_starts_at_the_first_heze_slot() {
        let mut spec = E::default_spec();
        spec.heze_fork_epoch = Some(Epoch::new(4));
        let mut store = InclusionListStore::<E>::new(&spec);
        let first_heze_slot = Epoch::new(4).start_slot(E::slots_per_epoch());
        let dr = root(1);

        assert_eq!(
            store.process_inclusion_list(
                signed_il(first_heze_slot.as_u64() - 1, 1, dr, &[0xaa]),
                true
            ),
            InsertOutcome::Old
        );
        assert_eq!(
            store.process_inclusion_list(signed_il(first_heze_slot.as_u64(), 1, dr, &[0xaa]), true),
            InsertOutcome::New
        );
    }

    /// The far future sentinel must not become the floor.
    #[test]
    fn unscheduled_heze_leaves_the_floor_at_zero() {
        let mut spec = E::default_spec();
        spec.heze_fork_epoch = Some(spec.far_future_epoch);
        let mut store = InclusionListStore::<E>::new(&spec);

        assert_eq!(
            store.process_inclusion_list(signed_il(10, 1, root(1), &[0xaa]), true),
            InsertOutcome::New
        );
    }
}
