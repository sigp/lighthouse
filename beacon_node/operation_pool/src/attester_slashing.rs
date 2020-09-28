use types::{BeaconState, IndexedAttestation, ChainSpec, EthSpec};
use std::convert::TryFrom;
use crate::max_cover::MaxCover;

pub struct AttesterSlashingMaxCover<'a, T: EthSpec> {
    indexed_attestation: &'a IndexedAttestation<T>,
    effective_balances: Vec<u64>,
}

impl <'a, T: EthSpec> AttesterSlashingMaxCover<'a, T> {
    pub fn new(
        indexed_attestation: &'a IndexedAttestation<T>,
        state: &BeaconState<T>,
        spec: &ChainSpec, 
    ) -> Option<Self> {
        let mut effective_balances: Vec<u64> = Vec::with_capacity(indexed_attestation.attesting_indices.len());

        for vd in &indexed_attestation.attesting_indices {
            let eff_balance = state.get_effective_balance(*vd as usize, spec).ok()?;
            effective_balances.push(eff_balance);
        }
        
        Some(Self {
            indexed_attestation,
            effective_balances,
        })
    }
}

impl <'a, T: EthSpec> MaxCover for AttesterSlashingMaxCover<'a, T> {
    /// The result type, of which we would eventually like a collection of maximal quality.
    type Object = IndexedAttestation<T>;
    /// The type used to represent sets.
    type Set = Vec<u64>;

    /// Extract an object for inclusion in a solution.
    fn object(&self) -> IndexedAttestation<T> {
        self.indexed_attestation.clone()
    }

    /// Get the set of elements covered.
    fn covering_set(&self) -> &Vec<u64> {
        &self.effective_balances
    }
    /// Update the set of items covered, for the inclusion of some object in the solution.
    fn update_covering_set(&mut self, best_att: &IndexedAttestation<T>, covered_validator_indices: &Vec<u64>) {
        if best_att == self.indexed_attestation {
            return;
        }

        let mut i = 0;
        self.effective_balances.retain(|_| (!covered_validator_indices.contains(&i), i += 1).0);
    }

    /// The quality of this item's covering set, usually its cardinality.
    fn score(&self) -> usize {
        self.effective_balances.iter().sum::<u64>() as usize + self.effective_balances.len()
    }
}