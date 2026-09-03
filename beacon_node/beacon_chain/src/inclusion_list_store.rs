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
        self.lowest_permissible_slot = std::cmp::max(
            current_slot.saturating_sub(self.slots_retained),
            self.lowest_permissible_slot,
        );
        self.slots
            .retain(|slot, _| *slot >= self.lowest_permissible_slot);
    }
}

#[cfg(test)]
mod tests {
    use super::{DependentRoot, InclusionListStore, InsertOutcome};
    use bls::Signature;
    use proptest::prelude::*;
    use ssz_types::{BitVector, FixedVector, ProgressiveVariableList};
    use std::collections::{BTreeMap, BTreeSet, HashSet};
    use tree_hash::TreeHash;
    use typenum::Unsigned;
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

    // ------------------------------------------------------------------
    // Property-based checks.
    //
    // Four invariants:
    //
    // 1. The validators the inclusion list store reports for `(slot, dependent_root)` are
    //    those with a stored inclusion list that are not equivocating. An equivocator's
    //    committee bit is unset and their inclusion list is not served, and everyone else's is.
    //
    // 2. `get_inclusion_list_transactions` is the deduplicated union (by tree hash) of the
    //    transactions in the stored lists of non-equivocating validators.
    //
    // 3. The `InsertOutcome` returned by `process_inclusion_list` reports the change it
    //    made to the inclusion list store. `New` stores a list, `Old` changes nothing,
    //    and every other outcome leaves the store untouched.
    //
    // 4. After `prune(current_slot)`, every slot below `current_slot - slots_retained` is
    //    dropped, every slot at or above is retained, and `lowest_permissible_slot` is set
    //    to `max(current_slot - slots_retained, lowest_permissible_slot)`.
    //
    // Invariants 1 and 2 are asserted for `only_timely` in `{false, true}`.
    // ------------------------------------------------------------------

    const PROP_VALIDATORS: [u64; 3] = [1, 2, 3];
    const PROP_SLOTS: [u64; 2] = [10, 11];

    fn prop_roots() -> [DependentRoot; 2] {
        [root(1), root(2)]
    }

    /// The committee used by the property tests.
    fn prop_committee() -> FixedVector<u64, <E as EthSpec>::InclusionListCommitteeSize> {
        let mut members = PROP_VALIDATORS.to_vec();
        let padding = <E as EthSpec>::InclusionListCommitteeSize::to_usize() - members.len();
        members.extend((0..padding).map(|i| 1_000 + i as u64));
        FixedVector::new(members).expect("committee is the right length")
    }

    /// Validators flagged as equivocators for `(slot, dependent_root)`.
    fn flagged_validators(
        store: &InclusionListStore<E>,
        slot: Slot,
        dependent_root: DependentRoot,
    ) -> HashSet<u64> {
        store
            .slots
            .get(&slot)
            .and_then(|entry| entry.equivocators.get(&dependent_root))
            .cloned()
            .unwrap_or_default()
    }

    /// The validators expected to be reported for `(slot, dependent_root)`: those with a stored
    /// inclusion list, minus the equivocators, timely-filtered when `only_timely` is set.
    fn expected_submitters(
        store: &InclusionListStore<E>,
        slot: Slot,
        dependent_root: DependentRoot,
        only_timely: bool,
    ) -> HashSet<u64> {
        let flagged = flagged_validators(store, slot, dependent_root);

        store
            .slots
            .get(&slot)
            .and_then(|entry| entry.by_dependent_root.get(&dependent_root))
            .map(|stored| {
                stored
                    .iter()
                    .filter(|(validator, _)| !flagged.contains(validator))
                    .filter(|(_, (_, is_timely))| !only_timely || *is_timely)
                    .map(|(validator, _)| *validator)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Invariant 1.
    fn assert_reported_submitters_are_exact(
        store: &InclusionListStore<E>,
        slot: Slot,
        dependent_root: DependentRoot,
        only_timely: bool,
    ) {
        let expected = expected_submitters(store, slot, dependent_root, only_timely);
        let committee = prop_committee();

        assert_eq!(
            store.submitted_validators(slot, dependent_root, only_timely),
            expected,
            "submitted validators do not match the surviving lists (only_timely={only_timely})"
        );

        let bits = store
            .get_inclusion_list_bits(slot, dependent_root, &committee, only_timely)
            .expect("committee is in range");
        for (i, validator) in committee.iter().enumerate() {
            assert_eq!(
                bits.get(i).expect("bit is in range"),
                expected.contains(validator),
                "wrong bit for validator {validator} at position {i} \
                 (only_timely={only_timely})"
            );
        }

        // `get_signed_inclusion_lists` ignores timeliness, so it is compared against the
        // unfiltered expectation.
        let served: HashSet<u64> = store
            .get_signed_inclusion_lists(slot, dependent_root, &PROP_VALIDATORS)
            .iter()
            .map(|il| il.message.validator_index)
            .collect();
        assert_eq!(
            served,
            expected_submitters(store, slot, dependent_root, false),
            "served inclusion lists do not match the surviving lists"
        );
    }

    /// Invariant 2.
    fn assert_transactions_are_union(
        store: &InclusionListStore<E>,
        slot: Slot,
        dependent_root: DependentRoot,
        only_timely: bool,
    ) {
        let flagged = flagged_validators(store, slot, dependent_root);

        let expected: HashSet<Hash256> = store
            .slots
            .get(&slot)
            .and_then(|entry| entry.by_dependent_root.get(&dependent_root))
            .map(|stored| {
                stored
                    .iter()
                    .filter(|(validator, _)| !flagged.contains(validator))
                    .filter(|(_, (_, is_timely))| !only_timely || *is_timely)
                    .flat_map(|(_, (il, _))| {
                        il.message.transactions.iter().map(|tx| tx.tree_hash_root())
                    })
                    .collect()
            })
            .unwrap_or_default();

        let actual = store.get_inclusion_list_transactions(slot, dependent_root, only_timely);
        let actual_roots: Vec<Hash256> = actual.iter().map(|tx| tx.tree_hash_root()).collect();
        let actual_set: HashSet<Hash256> = actual_roots.iter().copied().collect();

        assert_eq!(
            actual_set.len(),
            actual_roots.len(),
            "duplicate transactions in the union"
        );
        assert_eq!(
            actual_set, expected,
            "union does not match the non-equivocating lists (only_timely={only_timely})"
        );
    }

    /// The store's contents, in a form that can be compared before and after an operation.
    #[derive(Debug, Default, Clone, PartialEq)]
    struct Snapshot {
        /// `(slot, dependent_root, validator)` -> (inclusion list tree hash, timeliness).
        stored: BTreeMap<(u64, Hash256, u64), (Hash256, bool)>,
        /// `(slot, dependent_root)` -> flagged validators.
        equivocators: BTreeMap<(u64, Hash256), BTreeSet<u64>>,
        /// `(slot, validator)` -> count of valid arrivals.
        counts: BTreeMap<(u64, u64), usize>,
    }

    fn snapshot(store: &InclusionListStore<E>) -> Snapshot {
        let mut snapshot = Snapshot::default();
        for (slot, entry) in store.slots.iter() {
            for (dependent_root, by_validator) in entry.by_dependent_root.iter() {
                for (validator, (il, is_timely)) in by_validator.iter() {
                    snapshot.stored.insert(
                        (slot.as_u64(), *dependent_root, *validator),
                        (il.tree_hash_root(), *is_timely),
                    );
                }
            }
            for (dependent_root, flagged) in entry.equivocators.iter() {
                snapshot.equivocators.insert(
                    (slot.as_u64(), *dependent_root),
                    flagged.iter().copied().collect(),
                );
            }
            for (validator, count) in entry.validator_counts.iter() {
                snapshot.counts.insert((slot.as_u64(), *validator), *count);
            }
        }
        snapshot
    }

    /// Invariant 3.
    fn assert_outcome_matches_transition(
        before: &Snapshot,
        after: &Snapshot,
        outcome: InsertOutcome,
        key: (u64, Hash256, u64),
    ) {
        // The stored lists, ignoring the one this insert was for.
        let others = |snapshot: &Snapshot| {
            snapshot
                .stored
                .iter()
                .filter(|(entry_key, _)| **entry_key != key)
                .map(|(entry_key, value)| (*entry_key, *value))
                .collect::<BTreeMap<_, _>>()
        };

        match outcome {
            InsertOutcome::New => {
                assert!(
                    !before.stored.contains_key(&key),
                    "`New` but a list was already stored for {key:?}"
                );
                assert!(
                    after.stored.contains_key(&key),
                    "`New` but no list was stored for {key:?}"
                );
                assert_eq!(
                    others(after),
                    others(before),
                    "`New` modified a list it should not have"
                );
            }
            InsertOutcome::Seen
            | InsertOutcome::Equivocating
            | InsertOutcome::SubsequentEquivocation => {
                assert_eq!(
                    after.stored, before.stored,
                    "`{outcome:?}` must not change any stored list"
                );
            }
            InsertOutcome::Old => {
                assert_eq!(after, before, "`Old` must not change any state");
            }
        }
    }

    /// Invariant 4.
    fn assert_prune_matches_store_change(
        before: &Snapshot,
        floor_before: Slot,
        after: &Snapshot,
        floor_after: Slot,
        current_slot: Slot,
        slots_retained: u64,
    ) {
        let expected_floor =
            std::cmp::max(current_slot.saturating_sub(slots_retained), floor_before);
        assert_eq!(
            floor_after, expected_floor,
            "prune({current_slot}) moved the floor to {floor_after}, expected {expected_floor}"
        );
        assert!(
            floor_after >= floor_before,
            "prune lowered the floor from {floor_before} to {floor_after}"
        );

        let retained = |snapshot: &Snapshot| Snapshot {
            stored: snapshot
                .stored
                .iter()
                .filter(|((slot, _, _), _)| *slot >= expected_floor.as_u64())
                .map(|(key, value)| (*key, *value))
                .collect(),
            equivocators: snapshot
                .equivocators
                .iter()
                .filter(|((slot, _), _)| *slot >= expected_floor.as_u64())
                .map(|(key, value)| (*key, value.clone()))
                .collect(),
            counts: snapshot
                .counts
                .iter()
                .filter(|((slot, _), _)| *slot >= expected_floor.as_u64())
                .map(|(key, value)| (*key, *value))
                .collect(),
        };

        assert_eq!(
            *after,
            retained(before),
            "prune({current_slot}) did not drop exactly the slots below {expected_floor}"
        );
    }

    /// Assert invariants 1 and 2 across every `(slot, dependent_root, only_timely)` combination.
    fn assert_invariants(store: &InclusionListStore<E>) {
        for slot in PROP_SLOTS {
            for dependent_root in prop_roots() {
                for only_timely in [false, true] {
                    let slot = Slot::new(slot);
                    assert_reported_submitters_are_exact(store, slot, dependent_root, only_timely);
                    assert_transactions_are_union(store, slot, dependent_root, only_timely);
                }
            }
        }
    }

    /// A single operation applied to the store by the property test.
    #[derive(Debug, Clone)]
    enum Op {
        Insert {
            slot: u64,
            validator: u64,
            dependent_root: DependentRoot,
            payload: u8,
            is_timely: bool,
        },
        Prune {
            current_slot: u64,
        },
    }

    /// Prunes are drawn from a range that straddles `PROP_SLOTS`, so some are no-ops, some drop
    /// one slot, and some drop both.
    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            4 => (
                0usize..PROP_SLOTS.len(),
                0usize..PROP_VALIDATORS.len(),
                0usize..2,
                0u8..4,
                any::<bool>(),
            )
                .prop_map(|(slot, validator, dependent_root, payload, is_timely)| Op::Insert {
                    slot: PROP_SLOTS[slot],
                    validator: PROP_VALIDATORS[validator],
                    dependent_root: prop_roots()[dependent_root],
                    payload,
                    is_timely,
                }),
            1 => (8u64..16).prop_map(|current_slot| Op::Prune { current_slot }),
        ]
    }

    proptest! {
        #[test]
        fn invariants_hold_under_arbitrary_operations(
            ops in proptest::collection::vec(op_strategy(), 0..24)
        ) {
            let mut store = new_store();
            assert_invariants(&store);

            for op in ops {
                match op {
                    Op::Insert {
                        slot,
                        validator,
                        dependent_root,
                        payload,
                        is_timely,
                    } => {
                        let il = signed_il(slot, validator, dependent_root, &[0xa0 + payload]);

                        let before = snapshot(&store);
                        let outcome = store.process_inclusion_list(il, is_timely);
                        let after = snapshot(&store);

                        assert_outcome_matches_transition(
                            &before,
                            &after,
                            outcome,
                            (slot, dependent_root, validator),
                        );
                    }
                    Op::Prune { current_slot } => {
                        let current_slot = Slot::new(current_slot);
                        let slots_retained = store.slots_retained;

                        let before = snapshot(&store);
                        let floor_before = store.lowest_permissible_slot;
                        store.prune(current_slot);
                        let after = snapshot(&store);

                        assert_prune_matches_store_change(
                            &before,
                            floor_before,
                            &after,
                            store.lowest_permissible_slot,
                            current_slot,
                            slots_retained,
                        );
                    }
                }
                assert_invariants(&store);
            }
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
