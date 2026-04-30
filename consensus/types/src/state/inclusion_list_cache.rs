use crate::{
    EthSpec, InclusionListCommittee, SignedInclusionList, Slot, Transaction, Transactions,
};
use ssz_types::BitVector;
use std::collections::{HashMap, HashSet};
use tracing::info;

/// Map from slot to inclusion lists.
// TODO(focil): Spec keys InclusionListStore by (slot, committee_root), not just slot.
// A reorg that changes committee membership for the same slot would conflate ILs.
// See: https://github.com/ethereum/consensus-specs/blob/master/specs/heze/inclusion-list.md#inclusionliststore
#[derive(Debug, Default, Clone, PartialEq)]
pub struct InclusionListCache<E: EthSpec> {
    inner_map: HashMap<Slot, Inner<E>>,
}

type ValidatorIndex = u64;

#[derive(Debug, Default, Clone, PartialEq)]
struct Inner<E: EthSpec> {
    pub inclusion_lists: HashSet<SignedInclusionList<E>>,
    pub inclusion_lists_seen: HashSet<ValidatorIndex>,
    pub inclusion_list_equivocators: HashSet<ValidatorIndex>,
    // TODO(focil): Spec tracks timeliness per IL root, not per validator index.
    // Functionally equivalent for non-equivocating validators.
    // See: https://github.com/ethereum/consensus-specs/blob/master/specs/heze/inclusion-list.md#inclusionliststore
    pub inclusion_list_timeliness: HashMap<ValidatorIndex, bool>,
    pub inclusion_list_transactions: HashSet<Transaction<E::MaxBytesPerTransaction>>,
    pub timely_transactions: HashSet<Transaction<E::MaxBytesPerTransaction>>,
    /// Track which transactions belong to which validator so we can remove them on equivocation.
    pub validator_transactions:
        HashMap<ValidatorIndex, Vec<Transaction<E::MaxBytesPerTransaction>>>,
}

impl<E: EthSpec> InclusionListCache<E> {
    pub fn clear_cache(&mut self, slot: Slot) {
        self.inner_map.remove(&slot);
    }

    pub fn inclusion_list_seen(&self, inclusion_list: &SignedInclusionList<E>) -> bool {
        let slot = inclusion_list.message.slot;
        let Some(inner) = self.inner_map.get(&slot) else {
            return false;
        };

        inner
            .inclusion_lists_seen
            .contains(&inclusion_list.message.validator_index)
    }

    pub fn on_inclusion_list(&mut self, inclusion_list: SignedInclusionList<E>, is_timely: bool) {
        let slot = inclusion_list.message.slot;
        let validator_index = inclusion_list.message.validator_index;
        let inner = self.inner_map.entry(slot).or_default();

        if inner.inclusion_list_equivocators.contains(&validator_index) {
            info!(
                ?slot,
                validator_index, "This validator was flagged for an equivocating inclusion list",
            );
            return;
        }

        // Skip inserting into the cache if we've already seen an identical IL
        if inner.inclusion_lists_seen.contains(&validator_index)
            && inner.inclusion_lists.contains(&inclusion_list)
        {
            info!("Already seen identical inclusion list from this validator");
            return;
        }

        if inner.inclusion_lists_seen.contains(&validator_index)
            && !inner.inclusion_lists.contains(&inclusion_list)
        {
            info!(?slot, validator_index, "Equivocating inclusion list",);
            inner.inclusion_list_equivocators.insert(validator_index);

            // Remove equivocator's transactions per spec
            if let Some(txs) = inner.validator_transactions.remove(&validator_index) {
                for tx in &txs {
                    inner.inclusion_list_transactions.remove(tx);
                    inner.timely_transactions.remove(tx);
                }
            }
            inner.inclusion_list_timeliness.remove(&validator_index);
            return;
        }

        let txs: Vec<_> = inclusion_list
            .message
            .transactions
            .iter()
            .cloned()
            .collect();
        for tx in &txs {
            inner.inclusion_list_transactions.insert(tx.clone());
            if is_timely {
                inner.timely_transactions.insert(tx.clone());
            }
        }
        inner.validator_transactions.insert(validator_index, txs);
        inner
            .inclusion_list_timeliness
            .insert(validator_index, is_timely);
        inner.inclusion_lists_seen.insert(validator_index);
        inner.inclusion_lists.insert(inclusion_list);

        info!(
            ?slot,
            tx_count = inner.inclusion_list_transactions.len(),
            timely_tx_count = inner.timely_transactions.len(),
            "Successfully added inclusion list transactions to the cache",
        );
    }

    pub fn get_inclusion_list_transactions(
        &self,
        slot: Slot,
        only_timely: bool,
    ) -> Option<Transactions<E>> {
        let Some(inner) = self.inner_map.get(&slot) else {
            return None;
        };

        let txs = if only_timely {
            &inner.timely_transactions
        } else {
            &inner.inclusion_list_transactions
        };

        let il: Vec<_> = txs.iter().cloned().collect();
        il.try_into().ok()
    }

    /// Returns a bitvector with bits set for each committee member who submitted a valid,
    /// non-equivocating inclusion list.
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

        for (i, validator_index) in committee.iter().enumerate() {
            if inner.inclusion_list_equivocators.contains(validator_index) {
                continue;
            }
            if !inner.inclusion_lists_seen.contains(validator_index) {
                continue;
            }
            if only_timely {
                if inner.inclusion_list_timeliness.get(validator_index) == Some(&true) {
                    bits.set(i, true).ok();
                }
            } else {
                bits.set(i, true).ok();
            }
        }

        bits
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
        // Check that inclusion_list_bits is a superset of local_bits:
        // every bit set in local_bits must also be set in inclusion_list_bits.
        for i in 0..local_bits.len() {
            if local_bits.get(i).unwrap_or(false) && !inclusion_list_bits.get(i).unwrap_or(false) {
                return false;
            }
        }
        true
    }
}
