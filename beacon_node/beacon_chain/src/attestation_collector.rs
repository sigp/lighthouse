use parking_lot::RwLock;
use std::collections::{BTreeMap, HashMap};
use std::marker::PhantomData;
use types::{Attestation, EthSpec, IndexedAttestation, Slot};

const SLOT_HISTORY: u64 = 32;

/// Collect raw attestations as they arrive off the network, without any additional aggregation.
#[derive(Default)]
pub struct AttestationCollector<E: EthSpec> {
    inner: RwLock<Inner<E>>,
}

#[derive(Default)]
pub struct Inner<E: EthSpec> {
    unaggregated: HashMap<Slot, Vec<(Attestation<E>, IndexedAttestation<E>)>>,
    aggregated: HashMap<Slot, Vec<(Attestation<E>, IndexedAttestation<E>)>>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> AttestationCollector<E> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_unaggregated(&self, attestation: Attestation<E>, indexed: IndexedAttestation<E>) {
        let mut inner = self.inner.write();
        inner.prune_to(attestation.data.slot);
        inner
            .unaggregated
            .entry(attestation.data.slot)
            .or_insert_with(Vec::new)
            .push((attestation, indexed));
    }

    pub fn insert_aggregated(&self, attestation: Attestation<E>, indexed: IndexedAttestation<E>) {
        let mut inner = self.inner.write();
        inner.prune_to(attestation.data.slot);
        inner
            .aggregated
            .entry(attestation.data.slot)
            .or_insert_with(Vec::new)
            .push((attestation, indexed));
    }

    /// Return `(unaggregated, aggregated)`.
    pub fn dump_attestations(
        &self,
        current_slot: Slot,
    ) -> (
        BTreeMap<Slot, Vec<(Attestation<E>, Vec<u64>)>>,
        BTreeMap<Slot, Vec<(Attestation<E>, Vec<u64>)>>,
    ) {
        let inner = self.inner.read();

        let min_slot = current_slot - E::slots_per_epoch();

        let convert =
            |raw_attestations: &HashMap<Slot, Vec<(Attestation<E>, IndexedAttestation<E>)>>| {
                raw_attestations
                    .iter()
                    .filter(|(slot, _)| **slot >= min_slot)
                    .map(|(slot, attestations)| {
                        (
                            *slot,
                            attestations
                                .iter()
                                .map(|(attestation, indexed)| {
                                    (attestation.clone(), indexed.attesting_indices.to_vec())
                                })
                                .collect(),
                        )
                    })
                    .collect()
            };

        let unaggregated = convert(&inner.unaggregated);
        let aggregated = convert(&inner.aggregated);
        (unaggregated, aggregated)
    }
}

impl<E: EthSpec> Inner<E> {
    fn prune_to(&mut self, current_slot: Slot) {
        let retain_slot = current_slot - SLOT_HISTORY;
        self.unaggregated.retain(|slot, _| *slot >= retain_slot);
        self.aggregated.retain(|slot, _| *slot >= retain_slot);
    }
}
