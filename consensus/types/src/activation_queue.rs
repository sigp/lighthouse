use crate::{ChainSpec, Epoch, Validator};
use std::collections::BTreeSet;

/// Activation queue computed during epoch processing for use in the *next* epoch.
#[derive(Debug, PartialEq, Eq, Default, Clone, arbitrary::Arbitrary)]
pub struct ActivationQueue {
    /// Validators represented by `(activation_eligibility_epoch, index)` in sorted order.
    queue: BTreeSet<(Epoch, usize)>,
}

impl ActivationQueue {
    pub fn add_if_could_be_eligible_for_activation(
        &mut self,
        index: usize,
        validator: &Validator,
        next_epoch: Epoch,
        spec: &ChainSpec,
    ) {
        if validator.could_be_eligible_for_activation_at(next_epoch, spec) {
            self.queue
                .insert((validator.activation_eligibility_epoch, index));
        }
    }

    pub fn get_validators_eligible_for_activation(
        &self,
        finalized_epoch: Epoch,
        churn_limit: usize,
    ) -> BTreeSet<usize> {
        self.queue
            .iter()
            .filter_map(|&(eligibility_epoch, index)| {
                (eligibility_epoch <= finalized_epoch).then_some(index)
            })
            .take(churn_limit)
            .collect()
    }
}
