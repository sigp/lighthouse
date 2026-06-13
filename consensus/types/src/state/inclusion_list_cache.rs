use crate::{EthSpec, Hash256, InclusionListCommittee, SignedInclusionList, Slot, Transactions};
use ssz_types::BitVector;
use std::collections::{HashMap, HashSet};
use tracing::{debug, info};
use tree_hash::TreeHash;

/// Number of slots of inclusion lists to retain. ILs are only read for the
/// previous slot (payload building, bid bits, satisfaction checks), so a small
/// window is sufficient.
const RETAIN_SLOTS: u64 = 8;

type ValidatorIndex = u64;
type CommitteeRoot = Hash256;
type InclusionListRoot = Hash256;

/// Mirror of the spec's `InclusionListStore`, additionally grouped by slot so
/// old entries can be pruned.
///
/// See: https://github.com/ethereum/consensus-specs/blob/master/specs/heze/inclusion-list.md#inclusionliststore
#[derive(Debug, Default, Clone, PartialEq)]
pub struct InclusionListCache<E: EthSpec> {
    inner_map: HashMap<Slot, Inner<E>>,
}

#[derive(Debug, Default, Clone, PartialEq)]
struct Inner<E: EthSpec> {
    /// Inclusion lists keyed by committee root, then by the message's tree hash root.
    inclusion_lists: HashMap<CommitteeRoot, HashMap<InclusionListRoot, SignedInclusionList<E>>>,
    /// Timeliness per inclusion list root.
    inclusion_list_timeliness: HashMap<InclusionListRoot, bool>,
    /// Equivocating validators per committee root. Stored inclusion lists from
    /// equivocators are kept and filtered out at read time, per the spec.
    equivocators: HashMap<CommitteeRoot, HashSet<ValidatorIndex>>,
}

impl<E: EthSpec> InclusionListCache<E> {
    /// Drop inclusion lists older than `RETAIN_SLOTS` behind `current_slot`.
    pub fn prune(&mut self, current_slot: Slot) {
        self.inner_map
            .retain(|slot, _| *slot + RETAIN_SLOTS >= current_slot);
    }

    /// Returns `true` if this message should be IGNOREd per the p2p rule:
    /// "[IGNORE] The message is either the first or second valid message received from the
    /// validator with index message.validator_index".
    ///
    /// A second *distinct* message must be accepted (and forwarded) so that equivocation
    /// evidence propagates; only duplicates and third-or-later messages are ignored.
    pub fn inclusion_list_seen(&self, inclusion_list: &SignedInclusionList<E>) -> bool {
        let slot = inclusion_list.message.slot;
        let key = inclusion_list.message.inclusion_list_committee_root;
        let validator_index = inclusion_list.message.validator_index;
        let Some(inner) = self.inner_map.get(&slot) else {
            return false;
        };

        // Two distinct messages already seen from this validator.
        if inner
            .equivocators
            .get(&key)
            .is_some_and(|equivocators| equivocators.contains(&validator_index))
        {
            return true;
        }

        // Exact duplicate of an already-stored message.
        inner.inclusion_lists.get(&key).is_some_and(|ils| {
            ils.values().any(|stored| {
                stored.message.validator_index == validator_index
                    && stored.message == inclusion_list.message
            })
        })
    }

    /// Mirror of the spec's `process_inclusion_list`.
    pub fn on_inclusion_list(&mut self, inclusion_list: SignedInclusionList<E>, is_timely: bool) {
        let slot = inclusion_list.message.slot;
        let key = inclusion_list.message.inclusion_list_committee_root;
        let validator_index = inclusion_list.message.validator_index;
        let inner = self.inner_map.entry(slot).or_default();

        // Ignore inclusion lists from known equivocators.
        if inner
            .equivocators
            .get(&key)
            .is_some_and(|equivocators| equivocators.contains(&validator_index))
        {
            debug!(
                ?slot,
                validator_index, "Ignoring inclusion list from equivocating validator",
            );
            return;
        }

        if let Some(stored) = inner.inclusion_lists.get(&key).and_then(|ils| {
            ils.values()
                .find(|stored| stored.message.validator_index == validator_index)
        }) {
            if stored.message != inclusion_list.message {
                info!(?slot, validator_index, "Equivocating inclusion list");
                inner
                    .equivocators
                    .entry(key)
                    .or_default()
                    .insert(validator_index);
            }
            // Whether it was an equivocation or not, this message has been processed.
            return;
        }

        let il_root = inclusion_list.message.tree_hash_root();
        inner
            .inclusion_lists
            .entry(key)
            .or_default()
            .insert(il_root, inclusion_list);
        inner.inclusion_list_timeliness.insert(il_root, is_timely);

        info!(
            ?slot,
            validator_index, is_timely, "Added inclusion list to the cache",
        );
    }

    /// Mirror of the spec's `get_inclusion_list_transactions`, unioned over all committee
    /// roots observed for `slot`.
    ///
    /// Gossip verification only admits inclusion lists whose committee root matches the
    /// locally computed committee, so in practice a single committee root exists per slot;
    /// the union is a safe superset across re-orgs that change the committee mid-slot.
    pub fn get_inclusion_list_transactions(
        &self,
        slot: Slot,
        only_timely: bool,
    ) -> Option<Transactions<E>> {
        let inner = self.inner_map.get(&slot)?;
        let mut transactions = HashSet::new();
        for (key, ils) in &inner.inclusion_lists {
            let equivocators = inner.equivocators.get(key);
            for (il_root, il) in ils {
                if equivocators
                    .is_some_and(|equivocators| equivocators.contains(&il.message.validator_index))
                {
                    continue;
                }
                if only_timely
                    && !inner
                        .inclusion_list_timeliness
                        .get(il_root)
                        .copied()
                        .unwrap_or(false)
                {
                    continue;
                }
                for tx in il.message.transactions.iter() {
                    transactions.insert(tx.clone());
                }
            }
        }
        let transactions: Vec<_> = transactions.into_iter().collect();
        transactions.try_into().ok()
    }

    /// Mirror of the spec's `get_inclusion_list_bits`: a bitvector over committee indices
    /// with bits set for valid, non-equivocating inclusion list submissions.
    pub fn get_inclusion_list_bits(
        &self,
        slot: Slot,
        committee: &InclusionListCommittee<E>,
        only_timely: bool,
    ) -> BitVector<E::InclusionListCommitteeSize> {
        let mut bits = BitVector::new();
        let Some(inner) = self.inner_map.get(&slot) else {
            return bits;
        };
        let key = committee.tree_hash_root();
        let Some(ils) = inner.inclusion_lists.get(&key) else {
            return bits;
        };
        let equivocators = inner.equivocators.get(&key);

        let submitted: HashSet<ValidatorIndex> = ils
            .iter()
            .filter(|(il_root, il)| {
                if equivocators
                    .is_some_and(|equivocators| equivocators.contains(&il.message.validator_index))
                {
                    return false;
                }
                !only_timely
                    || inner
                        .inclusion_list_timeliness
                        .get(*il_root)
                        .copied()
                        .unwrap_or(false)
            })
            .map(|(_, il)| il.message.validator_index)
            .collect();

        for (i, validator_index) in committee.iter().enumerate() {
            if submitted.contains(validator_index) {
                bits.set(i, true).ok();
            }
        }

        bits
    }

    /// Returns the stored (non-equivocating) inclusion lists at `slot` whose
    /// `message.validator_index` is in `validator_indices`.
    pub fn get_inclusion_lists_for_validators(
        &self,
        slot: Slot,
        validator_indices: &[u64],
    ) -> Vec<SignedInclusionList<E>> {
        let Some(inner) = self.inner_map.get(&slot) else {
            return vec![];
        };
        let requested: HashSet<ValidatorIndex> = validator_indices.iter().copied().collect();

        let mut inclusion_lists = vec![];
        for (key, ils) in &inner.inclusion_lists {
            let equivocators = inner.equivocators.get(key);
            for il in ils.values() {
                let validator_index = il.message.validator_index;
                if !requested.contains(&validator_index) {
                    continue;
                }
                if equivocators.is_some_and(|equivocators| equivocators.contains(&validator_index))
                {
                    continue;
                }
                inclusion_lists.push(il.clone());
            }
        }
        inclusion_lists
    }

    /// Checks that `inclusion_list_bits` is a superset of the locally observed bits.
    pub fn is_inclusion_list_bits_inclusive(
        &self,
        slot: Slot,
        committee: &InclusionListCommittee<E>,
        inclusion_list_bits: &BitVector<E::InclusionListCommitteeSize>,
        only_timely: bool,
    ) -> bool {
        let local_bits = self.get_inclusion_list_bits(slot, committee, only_timely);
        // Every bit set in local_bits must also be set in inclusion_list_bits.
        for i in 0..local_bits.len() {
            if local_bits.get(i).unwrap_or(false) && !inclusion_list_bits.get(i).unwrap_or(false) {
                return false;
            }
        }
        true
    }
}
