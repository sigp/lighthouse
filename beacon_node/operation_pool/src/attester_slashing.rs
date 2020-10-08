use crate::max_cover::MaxCover;
use std::collections::HashMap;
use types::{AttesterSlashing, BeaconState, ChainSpec, EthSpec};

pub struct AttesterSlashingMaxCover<'a, T: EthSpec> {
    slashing: &'a AttesterSlashing<T>,
    effective_balances: HashMap<u64, u64>,
}

impl<'a, T: EthSpec> AttesterSlashingMaxCover<'a, T> {
    pub fn new(
        slashing: &'a AttesterSlashing<T>,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Option<Self> {
        let length = slashing.attestation_1.attesting_indices.len()
            + slashing.attestation_2.attesting_indices.len();
        let mut effective_balances: HashMap<u64, u64> = HashMap::with_capacity(length);

        for vd in &slashing.attestation_1.attesting_indices {
            let eff_balance = state.get_effective_balance(*vd as usize, spec).ok()?;
            effective_balances.insert(*vd, eff_balance);
        }

        for vd in &slashing.attestation_2.attesting_indices {
            let eff_balance = state.get_effective_balance(*vd as usize, spec).ok()?;
            effective_balances.insert(*vd, eff_balance);
        }

        Some(Self {
            slashing,
            effective_balances,
        })
    }
}

impl<'a, T: EthSpec> MaxCover for AttesterSlashingMaxCover<'a, T> {
    /// The result type, of which we would eventually like a collection of maximal quality.
    type Object = AttesterSlashing<T>;
    /// The type used to represent sets.
    type Set = HashMap<u64, u64>;

    /// Extract an object for inclusion in a solution.
    fn object(&self) -> AttesterSlashing<T> {
        self.slashing.clone()
    }

    /// Get the set of elements covered.
    fn covering_set(&self) -> &HashMap<u64, u64> {
        &self.effective_balances
    }
    /// Update the set of items covered, for the inclusion of some object in the solution.
    fn update_covering_set(
        &mut self,
        best_slashing: &AttesterSlashing<T>,
        covered_validator_indices: &HashMap<u64, u64>,
    ) {
        if best_slashing == self.slashing {
            return;
        }

        self.effective_balances
            .retain(|k, _| !covered_validator_indices.contains_key(k));
    }

    /// The quality of this item's covering set, usually its cardinality.
    fn score(&self) -> usize {
        self.effective_balances.values().sum::<u64>() as usize
            + self.effective_balances.keys().len()
    }
}
