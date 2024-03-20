use crate::max_cover::MaxCover;
use state_processing::per_block_processing::get_slashable_indices_modular;
use std::collections::{HashMap, HashSet};
use types::{AttesterSlashing, BeaconState, EthSpec};

#[derive(Debug, Clone)]
pub struct AttesterSlashingMaxCover<'a, E: EthSpec> {
    slashing: &'a AttesterSlashing<E>,
    effective_balances: HashMap<u64, u64>,
}

impl<'a, E: EthSpec> AttesterSlashingMaxCover<'a, E> {
    pub fn new(
        slashing: &'a AttesterSlashing<E>,
        proposer_slashing_indices: &HashSet<u64>,
        state: &BeaconState<E>,
    ) -> Option<Self> {
        let mut effective_balances: HashMap<u64, u64> = HashMap::new();
        let epoch = state.current_epoch();

        let slashable_validators =
            get_slashable_indices_modular(state, slashing, |index, validator| {
                validator.is_slashable_at(epoch) && !proposer_slashing_indices.contains(&index)
            })
            .ok()?;

        for vd in slashable_validators {
            let eff_balance = state.get_effective_balance(vd as usize).ok()?;
            effective_balances.insert(vd, eff_balance);
        }

        Some(Self {
            slashing,
            effective_balances,
        })
    }
}

impl<'a, E: EthSpec> MaxCover for AttesterSlashingMaxCover<'a, E> {
    /// The result type, of which we would eventually like a collection of maximal quality.
    type Object = AttesterSlashing<E>;
    type Intermediate = AttesterSlashing<E>;
    /// The type used to represent sets.
    type Set = HashMap<u64, u64>;

    fn intermediate(&self) -> &AttesterSlashing<E> {
        self.slashing
    }

    fn convert_to_object(slashing: &AttesterSlashing<E>) -> AttesterSlashing<E> {
        slashing.clone()
    }

    /// Get the set of elements covered.
    fn covering_set(&self) -> &HashMap<u64, u64> {
        &self.effective_balances
    }
    /// Update the set of items covered, for the inclusion of some object in the solution.
    fn update_covering_set(
        &mut self,
        _best_slashing: &AttesterSlashing<E>,
        covered_validator_indices: &HashMap<u64, u64>,
    ) {
        self.effective_balances
            .retain(|k, _| !covered_validator_indices.contains_key(k));
    }

    /// The quality of this item's covering set, usually its cardinality.
    fn score(&self) -> usize {
        self.effective_balances.values().sum::<u64>() as usize
    }
}
