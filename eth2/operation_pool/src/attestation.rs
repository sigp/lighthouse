use crate::max_cover::MaxCover;
use types::{Attestation, BeaconState, BitList, EthSpec};

pub struct AttMaxCover<'a, T: EthSpec> {
    /// Underlying attestation.
    att: &'a Attestation<T>,
    /// Bitfield of validators that are covered by this attestation.
    fresh_validators: BitList<T::MaxValidatorsPerCommittee>,
}

impl<'a, T: EthSpec> AttMaxCover<'a, T> {
    pub fn new(
        att: &'a Attestation<T>,
        fresh_validators: BitList<T::MaxValidatorsPerCommittee>,
    ) -> Self {
        Self {
            att,
            fresh_validators,
        }
    }
}

impl<'a, T: EthSpec> MaxCover for AttMaxCover<'a, T> {
    type Object = Attestation<T>;
    type Set = BitList<T::MaxValidatorsPerCommittee>;

    fn object(&self) -> Attestation<T> {
        self.att.clone()
    }

    fn covering_set(&self) -> &BitList<T::MaxValidatorsPerCommittee> {
        &self.fresh_validators
    }

    /// Sneaky: we keep all the attestations together in one bucket, even though
    /// their aggregation bitfields refer to different committees. In order to avoid
    /// confusing committees when updating covering sets, we update only those attestations
    /// whose shard and epoch match the attestation being included in the solution, by the logic
    /// that a shard and epoch uniquely identify a committee.
    fn update_covering_set(
        &mut self,
        best_att: &Attestation<T>,
        covered_validators: &BitList<T::MaxValidatorsPerCommittee>,
    ) {
        if self.att.data.crosslink.shard == best_att.data.crosslink.shard
            && self.att.data.target.epoch == best_att.data.target.epoch
        {
            self.fresh_validators.difference_inplace(covered_validators);
        }
    }

    fn score(&self) -> usize {
        self.fresh_validators.num_set_bits()
    }
}

/// Extract the validators for which `attestation` would be their earliest in the epoch.
///
/// The reward paid to a proposer for including an attestation is proportional to the number
/// of validators for which the included attestation is their first in the epoch. The attestation
/// is judged against the state's `current_epoch_attestations` or `previous_epoch_attestations`
/// depending on when it was created, and all those validators who have already attested are
/// removed from the `aggregation_bits` before returning it.
// TODO: This could be optimised with a map from validator index to whether that validator has
// attested in each of the current and previous epochs. Currently quadratic in number of validators.
pub fn earliest_attestation_validators<T: EthSpec>(
    attestation: &Attestation<T>,
    state: &BeaconState<T>,
) -> BitList<T::MaxValidatorsPerCommittee> {
    // Bitfield of validators whose attestations are new/fresh.
    let mut new_validators = attestation.aggregation_bits.clone();

    let state_attestations = if attestation.data.target.epoch == state.current_epoch() {
        &state.current_epoch_attestations
    } else if attestation.data.target.epoch == state.previous_epoch() {
        &state.previous_epoch_attestations
    } else {
        return BitList::with_capacity(0).unwrap();
    };

    state_attestations
        .iter()
        // In a single epoch, an attester should only be attesting for one shard.
        // TODO: we avoid including slashable attestations in the state here,
        // but maybe we should do something else with them (like construct slashings).
        .filter(|existing_attestation| {
            existing_attestation.data.crosslink.shard == attestation.data.crosslink.shard
        })
        .for_each(|existing_attestation| {
            // Remove the validators who have signed the existing attestation (they are not new)
            new_validators.difference_inplace(&existing_attestation.aggregation_bits);
        });

    new_validators
}
