//! Provides the `InclusionListStore`, an in-memory store of the `SignedInclusionList`s received
//! for recent slots ([New in Heze:EIP7805]).
//!
//! It backs the gossip first-or-second and equivocation checks, the fork-choice enforcement reads
//! (timely inclusion lists only), and the block-production reads (all inclusion lists). Entries are
//! keyed by `(slot, dependent_root)`, which pins an inclusion list to the committee it was produced
//! against.

use crate::inclusion_list_verification::gossip_verified_inclusion_list::GossipVerifiedInclusionList;
use ssz_types::ProgressiveVariableList;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use tree_hash::TreeHash;
use types::{
    ChainSpec, EthSpec, Hash256, InclusionList, InclusionListBits, InclusionListCommittee,
    SignedInclusionList, Slot,
};

/// The shuffling `dependent_root` an inclusion list was produced against.
pub type DependentRoot = Hash256;

/// The spec's inclusion list store key, `(slot, dependent_root)`.
///
/// Derive it with `BeaconChain::inclusion_list_key` or `BeaconChain::inclusion_list_key_for_payload`
/// rather than computing the slot or the dependent root by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InclusionListKey {
    slot: Slot,
    dependent_root: DependentRoot,
}

impl InclusionListKey {
    /// A key from parts that have not been checked, such as a peer request.
    /// `BeaconChain::get_inclusion_list_committee` rejects a wrong `dependent_root`.
    pub fn new(slot: Slot, dependent_root: DependentRoot) -> Self {
        Self {
            slot,
            dependent_root,
        }
    }

    pub fn slot(&self) -> Slot {
        self.slot
    }

    pub fn dependent_root(&self) -> DependentRoot {
        self.dependent_root
    }
}

impl From<&InclusionList> for InclusionListKey {
    fn from(inclusion_list: &InclusionList) -> Self {
        Self::new(inclusion_list.slot, inclusion_list.dependent_root)
    }
}

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
}

pub struct InclusionListStore<E: EthSpec> {
    slots: HashMap<Slot, SlotEntry>,
    lowest_permissible_slot: Slot,
    /// One more than `MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS` requires. A slot `S` payload
    /// envelope reads the slot `S-1` lists, and might not be processed until the clock is at `S+1`.
    slots_retained: u64,
    _phantom: PhantomData<E>,
}

/// Returns whether `bits` is inclusive of `local`: every bit set in `local` is also set in `bits`.
pub fn inclusion_list_bits_are_inclusive<E: EthSpec>(
    local: &InclusionListBits<E>,
    bits: &InclusionListBits<E>,
) -> Result<bool, Error> {
    for i in 0..local.len() {
        if local.get(i)? && !bits.get(i)? {
            return Ok(false);
        }
    }
    Ok(true)
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

    /// Insert a `GossipVerifiedInclusionList`, detecting equivocation.
    pub fn process_inclusion_list(
        &mut self,
        verified_inclusion_list: GossipVerifiedInclusionList,
    ) -> InsertOutcome {
        let GossipVerifiedInclusionList {
            signed_inclusion_list,
            is_timely,
        } = verified_inclusion_list;
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
            // An exact duplicate is not a second valid message.
            Some(false) => InsertOutcome::Seen,
            Some(true) => {
                let newly_flagged = entry
                    .equivocators
                    .entry(dependent_root)
                    .or_default()
                    .insert(validator_index);
                if newly_flagged {
                    InsertOutcome::Equivocating
                } else {
                    InsertOutcome::SubsequentEquivocation
                }
            }
            None => {
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
    ///
    /// A validator's second valid message is always the one that flags it as an equivocator.
    pub fn seen_twice(&self, key: &InclusionListKey, validator_index: u64) -> bool {
        let InclusionListKey {
            slot,
            dependent_root,
        } = *key;
        self.slots
            .get(&slot)
            .and_then(|entry| entry.equivocators.get(&dependent_root))
            .is_some_and(|equivocators| equivocators.contains(&validator_index))
    }

    /// Validator indices that submitted a valid, non-equivocating inclusion list for
    /// `(slot, dependent_root)`, timely-filtered when `only_timely` is set.
    fn submitted_validators(&self, key: &InclusionListKey, only_timely: bool) -> HashSet<u64> {
        let InclusionListKey {
            slot,
            dependent_root,
        } = *key;
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
        key: &InclusionListKey,
        only_timely: bool,
    ) -> Vec<ProgressiveVariableList<u8>> {
        let InclusionListKey {
            slot,
            dependent_root,
        } = *key;
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
        il_committee: &InclusionListCommittee<E>,
        key: &InclusionListKey,
        only_timely: bool,
    ) -> Result<InclusionListBits<E>, Error> {
        let submitted = self.submitted_validators(key, only_timely);

        let mut bits = InclusionListBits::<E>::new();
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
        il_committee: &InclusionListCommittee<E>,
        key: &InclusionListKey,
        bits: &InclusionListBits<E>,
        only_timely: bool,
    ) -> Result<bool, Error> {
        let local = self.get_inclusion_list_bits(il_committee, key, only_timely)?;
        inclusion_list_bits_are_inclusive::<E>(&local, bits)
    }

    /// The stored signed inclusion lists for the given `validators`, used to serve
    /// `InclusionListsByIndices`. Equivocators and missing entries are skipped.
    pub fn get_signed_inclusion_lists(
        &self,
        key: &InclusionListKey,
        validators: &[u64],
    ) -> Vec<SignedInclusionList> {
        let InclusionListKey {
            slot,
            dependent_root,
        } = *key;
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
    use super::{DependentRoot, InclusionListKey, InclusionListStore, InsertOutcome};
    use crate::inclusion_list_verification::gossip_verified_inclusion_list::GossipVerifiedInclusionList;
    use bls::Signature;
    use proptest::prelude::*;
    use ssz_types::{BitVector, FixedVector, ProgressiveVariableList};
    use std::collections::{BTreeMap, BTreeSet, HashSet};
    use tree_hash::TreeHash;
    use typenum::Unsigned;
    use types::{
        Epoch, EthSpec, Hash256, InclusionList, InclusionListCommittee, SignedInclusionList, Slot,
        Spec,
    };

    type E = Spec;

    fn new_store() -> InclusionListStore<E> {
        InclusionListStore::new(&E::default_spec())
    }

    fn root(byte: u8) -> Hash256 {
        Hash256::from([byte; 32])
    }

    fn key(slot: u64, dependent_root: DependentRoot) -> InclusionListKey {
        InclusionListKey::new(Slot::new(slot), dependent_root)
    }

    fn tx(byte: u8) -> ProgressiveVariableList<u8> {
        ProgressiveVariableList::new(vec![byte]).unwrap()
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
                )
                .unwrap(),
            },
            signature: Signature::empty(),
        }
    }

    fn verified(
        signed_inclusion_list: SignedInclusionList,
        is_timely: bool,
    ) -> GossipVerifiedInclusionList {
        GossipVerifiedInclusionList {
            signed_inclusion_list,
            is_timely,
        }
    }

    // ------------------------------------------------------------------
    // Property-based checks.
    //
    // Four invariants:
    //
    // 1. The validators the inclusion list store returns for `(slot, dependent_root)` are
    //    those with a stored inclusion list that are not equivocating. An equivocator's
    //    committee bit is unset, their inclusion list is not served, and `seen_twice` is set.
    //
    // 2. `get_inclusion_list_transactions` is the deduplicated union (by tree hash) of the
    //    transactions in the stored lists of non-equivocating validators.
    //
    // 3. `process_inclusion_list` returns the outcome and makes the exact change that a
    //    reference model derives from the store contents before the insert.
    //
    // 4. After `prune(current_slot)`, every slot below `current_slot - slots_retained` is
    //    dropped, every slot at or above is retained, and `lowest_permissible_slot` is set
    //    to `max(current_slot - slots_retained, lowest_permissible_slot)`.
    //
    // Invariants 1 and 2 are asserted for `only_timely` in `{false, true}`.
    // ------------------------------------------------------------------

    const PROP_VALIDATORS: [u64; 3] = [1, 2, 3];
    const PROP_UNKNOWN_VALIDATOR: u64 = 99;
    const PROP_SLOTS: [u64; 2] = [10, 11];

    fn prop_roots() -> [DependentRoot; 2] {
        [root(1), root(2)]
    }

    /// The committee used by the property tests.
    fn prop_committee() -> InclusionListCommittee<E> {
        let members = (0..<E as EthSpec>::InclusionListCommitteeSize::to_usize())
            .map(|i| PROP_VALIDATORS[i % PROP_VALIDATORS.len()])
            .collect();
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

    /// The validators expected to be reported for `(slot, dependent_root)`, timely-filtered
    /// when `only_timely` is `True`.
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
        let key = InclusionListKey::new(slot, dependent_root);
        let expected = expected_submitters(store, slot, dependent_root, only_timely);
        let committee = prop_committee();

        let flagged = flagged_validators(store, slot, dependent_root);
        for validator in PROP_VALIDATORS {
            assert_eq!(
                store.seen_twice(&key, validator),
                flagged.contains(&validator),
                "seen_twice does not match the equivocator flag for validator {validator}"
            );
        }

        assert_eq!(
            store.submitted_validators(&key, only_timely),
            expected,
            "submitted validators do not match the surviving lists (only_timely={only_timely})"
        );

        let bits = store
            .get_inclusion_list_bits(&committee, &key, only_timely)
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
        // unfiltered expectation, for every subset of validators plus one never stored.
        let unfiltered = expected_submitters(store, slot, dependent_root, false);
        for mask in 0..(1usize << PROP_VALIDATORS.len()) {
            let requested: Vec<u64> = PROP_VALIDATORS
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, validator)| *validator)
                .chain([PROP_UNKNOWN_VALIDATOR])
                .collect();
            let served: HashSet<u64> = store
                .get_signed_inclusion_lists(&key, &requested)
                .iter()
                .map(|il| il.message.validator_index)
                .collect();
            let expected: HashSet<u64> = unfiltered
                .iter()
                .copied()
                .filter(|validator| requested.contains(validator))
                .collect();
            assert_eq!(
                served, expected,
                "served inclusion lists do not match the surviving lists for {requested:?}"
            );
        }
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

        let actual = store.get_inclusion_list_transactions(
            &InclusionListKey::new(slot, dependent_root),
            only_timely,
        );
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
    }

    fn snapshot(store: &InclusionListStore<E>) -> Snapshot {
        let mut snapshot = Snapshot::default();
        for (slot, entry) in store.slots.iter() {
            for (dependent_root, by_validator) in entry.by_dependent_root.iter() {
                for (validator, (il, is_timely)) in by_validator.iter() {
                    snapshot.stored.insert(
                        (slot.as_u64(), *dependent_root, *validator),
                        (il.message.tree_hash_root(), *is_timely),
                    );
                }
            }
            for (dependent_root, flagged) in entry.equivocators.iter() {
                snapshot.equivocators.insert(
                    (slot.as_u64(), *dependent_root),
                    flagged.iter().copied().collect(),
                );
            }
        }
        snapshot
    }

    /// Invariant 3.
    fn expected_insert(
        before: &Snapshot,
        floor: Slot,
        key: (u64, Hash256, u64),
        il_root: Hash256,
        is_timely: bool,
    ) -> (InsertOutcome, Snapshot) {
        let (slot, dependent_root, validator) = key;
        let mut expected = before.clone();
        if slot < floor.as_u64() {
            return (InsertOutcome::Old, expected);
        }

        let outcome = match before.stored.get(&key) {
            None => {
                expected.stored.insert(key, (il_root, is_timely));
                InsertOutcome::New
            }
            Some((stored_root, _)) if *stored_root == il_root => InsertOutcome::Seen,
            Some(_) => {
                let newly_flagged = expected
                    .equivocators
                    .entry((slot, dependent_root))
                    .or_default()
                    .insert(validator);
                if newly_flagged {
                    InsertOutcome::Equivocating
                } else {
                    InsertOutcome::SubsequentEquivocation
                }
            }
        };
        (outcome, expected)
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

    /// Prunes are generated for a range of `PROP_SLOTS`, some are no-ops, some drop
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

                        let expected = expected_insert(
                            &snapshot(&store),
                            store.lowest_permissible_slot,
                            (slot, dependent_root, validator),
                            il.message.tree_hash_root(),
                            is_timely,
                        );
                        let outcome = store.process_inclusion_list(verified(il, is_timely));

                        assert_eq!(
                            (outcome, snapshot(&store)),
                            expected,
                            "insert at {slot} by {validator} did not match the model"
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
            store.process_inclusion_list(verified(il.clone(), true)),
            InsertOutcome::New
        );
        assert_eq!(
            store.process_inclusion_list(verified(il, true)),
            InsertOutcome::Seen
        );
        // A duplicate is not a second valid message.
        assert!(!store.seen_twice(&key(10, root(1)), 1));
    }

    #[test]
    fn differing_list_flags_equivocation() {
        let mut store = new_store();
        assert_eq!(
            store.process_inclusion_list(verified(signed_il(10, 1, root(1), &[0xaa]), true)),
            InsertOutcome::New
        );
        assert_eq!(
            store.process_inclusion_list(verified(signed_il(10, 1, root(1), &[0xbb]), true)),
            InsertOutcome::Equivocating
        );
        assert_eq!(
            store.process_inclusion_list(verified(signed_il(10, 1, root(1), &[0xcc]), true)),
            InsertOutcome::SubsequentEquivocation
        );
    }

    #[test]
    fn old_slot_rejected_after_prune() {
        let mut store = new_store();
        store.prune(Slot::new(20));
        assert_eq!(
            store.process_inclusion_list(verified(signed_il(10, 1, root(1), &[0xaa]), true)),
            InsertOutcome::Old
        );
    }

    #[test]
    fn seen_twice_counts_valid_arrivals() {
        let mut store = new_store();
        assert!(!store.seen_twice(&key(10, root(1)), 1));
        store.process_inclusion_list(verified(signed_il(10, 1, root(1), &[0xaa]), true));
        assert!(!store.seen_twice(&key(10, root(1)), 1));
        // A differing (equivocating) message still counts as a valid arrival.
        store.process_inclusion_list(verified(signed_il(10, 1, root(1), &[0xbb]), true));
        assert!(store.seen_twice(&key(10, root(1)), 1));
    }

    #[test]
    fn transactions_are_deduplicated_and_timely_filtered() {
        let mut store = new_store();
        let dr = root(1);
        store.process_inclusion_list(verified(signed_il(10, 1, dr, &[0xaa, 0xbb]), true));
        store.process_inclusion_list(verified(signed_il(10, 2, dr, &[0xbb, 0xcc]), false));

        let all = store.get_inclusion_list_transactions(&key(10, dr), false);
        assert_eq!(all.len(), 3);

        let timely = store.get_inclusion_list_transactions(&key(10, dr), true);
        assert_eq!(timely.len(), 2);
    }

    #[test]
    fn equivocators_excluded_from_reads() {
        let mut store = new_store();
        let dr = root(1);
        store.process_inclusion_list(verified(signed_il(10, 1, dr, &[0xaa]), true));
        store.process_inclusion_list(verified(signed_il(10, 1, dr, &[0xbb]), true));
        assert!(
            store
                .get_inclusion_list_transactions(&key(10, dr), false)
                .is_empty()
        );
    }

    #[test]
    fn bits_reflect_submitters_and_inclusivity() {
        let mut store = new_store();
        let il_committee: InclusionListCommittee<E> =
            FixedVector::new((100..116).collect()).unwrap();
        let dr = root(1);

        store.process_inclusion_list(verified(signed_il(10, il_committee[3], dr, &[0xaa]), true));
        store.process_inclusion_list(verified(signed_il(10, il_committee[7], dr, &[0xbb]), true));

        let bits = store
            .get_inclusion_list_bits(&il_committee, &key(10, dr), false)
            .unwrap();
        assert!(bits.get(3).unwrap());
        assert!(bits.get(7).unwrap());
        assert!(!bits.get(0).unwrap());

        assert!(
            store
                .is_inclusion_list_bits_inclusive(&il_committee, &key(10, dr), &bits, false)
                .unwrap()
        );

        let mut missing = BitVector::<<E as EthSpec>::InclusionListCommitteeSize>::new();
        missing.set(7, true).unwrap();
        assert!(
            !store
                .is_inclusion_list_bits_inclusive(&il_committee, &key(10, dr), &missing, false)
                .unwrap()
        );
    }

    /// Two branches can have different dependent roots, so one list per branch is not equivocation.
    #[test]
    fn differing_dependent_roots_are_not_equivocation() {
        let mut store = new_store();
        assert_eq!(
            store.process_inclusion_list(verified(signed_il(10, 1, root(1), &[0xaa]), true)),
            InsertOutcome::New
        );
        assert_eq!(
            store.process_inclusion_list(verified(signed_il(10, 1, root(2), &[0xbb]), true)),
            InsertOutcome::New
        );

        for dr in [root(1), root(2)] {
            assert_eq!(
                store
                    .get_inclusion_list_transactions(&key(10, dr), false)
                    .len(),
                1
            );
        }

        // Each dependent root is counted separately.
        assert!(!store.seen_twice(&key(10, root(1)), 1));
        assert!(!store.seen_twice(&key(10, root(2)), 1));
    }

    #[test]
    fn get_signed_inclusion_lists_skips_equivocators_and_missing() {
        let mut store = new_store();
        let dr = root(1);
        store.process_inclusion_list(verified(signed_il(10, 1, dr, &[0xaa]), true));
        store.process_inclusion_list(verified(signed_il(10, 2, dr, &[0xbb]), true));
        store.process_inclusion_list(verified(signed_il(10, 2, dr, &[0xcc]), true));

        let result = store.get_signed_inclusion_lists(&key(10, dr), &[1, 2, 3]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].message.validator_index, 1);
    }

    #[test]
    fn prune_drops_old_slots() {
        let mut store = new_store();
        let dr = root(1);
        store.process_inclusion_list(verified(signed_il(10, 1, dr, &[0xaa]), true));
        store.process_inclusion_list(verified(signed_il(12, 1, dr, &[0xbb]), true));

        store.prune(Slot::new(12));
        assert!(
            !store
                .get_inclusion_list_transactions(&key(10, dr), false)
                .is_empty()
        );

        store.prune(Slot::new(13));
        assert!(
            store
                .get_inclusion_list_transactions(&key(10, dr), false)
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
        store.process_inclusion_list(verified(signed_il(10, 1, dr, &[0xaa]), true));

        store.prune(Slot::new(15));
        assert!(
            !store
                .get_inclusion_list_transactions(&key(10, dr), false)
                .is_empty()
        );

        store.prune(Slot::new(16));
        assert!(
            store
                .get_inclusion_list_transactions(&key(10, dr), false)
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
            store.process_inclusion_list(verified(
                signed_il(first_heze_slot.as_u64() - 1, 1, dr, &[0xaa]),
                true
            )),
            InsertOutcome::Old
        );
        assert_eq!(
            store.process_inclusion_list(verified(
                signed_il(first_heze_slot.as_u64(), 1, dr, &[0xaa]),
                true
            )),
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
            store.process_inclusion_list(verified(signed_il(10, 1, root(1), &[0xaa]), true)),
            InsertOutcome::New
        );
    }
}
