use types::*;

pub mod attesting_indices_base {
    use crate::per_block_processing::errors::{AttestationInvalid as Invalid, BlockOperationError};
    use types::*;

    /// Convert `attestation` to (almost) indexed-verifiable form.
    ///
    /// Spec v0.12.1
    pub fn get_indexed_attestation<E: EthSpec>(
        committee: &[usize],
        attestation: &AttestationBase<E>,
    ) -> Result<IndexedAttestation<E>, BlockOperationError<Invalid>> {
        let attesting_indices =
            get_attesting_indices::<E>(committee, &attestation.aggregation_bits)?;
        Ok(IndexedAttestation::Base(IndexedAttestationBase {
            attesting_indices: VariableList::new(attesting_indices)?,
            data: attestation.data.clone(),
            signature: attestation.signature.clone(),
        }))
    }

    /// Returns validator indices which participated in the attestation, sorted by increasing index.
    pub fn get_attesting_indices<E: EthSpec>(
        committee: &[usize],
        bitlist: &BitList<E::MaxValidatorsPerCommittee>,
    ) -> Result<Vec<u64>, BeaconStateError> {
        if bitlist.len() != committee.len() {
            return Err(BeaconStateError::InvalidBitfield);
        }

        let mut indices = Vec::with_capacity(bitlist.num_set_bits());

        for (i, validator_index) in committee.iter().enumerate() {
            if let Ok(true) = bitlist.get(i) {
                indices.push(*validator_index as u64)
            }
        }

        indices.sort_unstable();

        Ok(indices)
    }
}

pub mod attesting_indices_electra {
    use std::collections::{HashMap, HashSet};

    use crate::per_block_processing::errors::{AttestationInvalid as Invalid, BlockOperationError};
    use itertools::Itertools;
    use safe_arith::SafeArith;
    use types::*;

    // TODO(electra) remove duplicate code
    // get_indexed_attestation is almost an exact duplicate
    // the only differences are the invalid selection proof 
    // and aggregator not in committee checks
    pub fn get_indexed_attestation_from_signed_aggregate<E: EthSpec>(
        committees: &[BeaconCommittee],
        signed_aggregate: &SignedAggregateAndProofElectra<E>,
        spec: &ChainSpec,
    ) -> Result<IndexedAttestation<E>, BeaconStateError> {
        let mut output: HashSet<u64> = HashSet::new();

        let committee_bits = &signed_aggregate.message.aggregate.committee_bits;
        let aggregation_bits = &signed_aggregate.message.aggregate.aggregation_bits;
        let aggregator_index = signed_aggregate.message.aggregator_index;
        let attestation = &signed_aggregate.message.aggregate;

        let committee_indices = get_committee_indices::<E>(committee_bits);

        let mut committee_offset = 0;

        let committees_map: HashMap<u64, &BeaconCommittee> = committees
            .iter()
            .map(|committee| (committee.index, committee))
            .collect();

        let committee_count_per_slot = committees.len() as u64;
        let mut participant_count = 0;

        // TODO(electra):
        // Note: this clones the signature which is known to be a relatively slow operation.
        //
        // Future optimizations should remove this clone.
        let selection_proof =
            SelectionProof::from(signed_aggregate.message.selection_proof.clone());

        for index in committee_indices {
            if let Some(&beacon_committee) = committees_map.get(&index) {
                if !selection_proof
                    .is_aggregator(beacon_committee.committee.len(), spec)
                    .map_err(BeaconStateError::ArithError)?
                {
                    return Err(BeaconStateError::InvalidSelectionProof { aggregator_index });
                }

                if !beacon_committee
                    .committee
                    .contains(&(aggregator_index as usize))
                {
                    return Err(BeaconStateError::AggregatorNotInCommittee { aggregator_index });
                }

                // This check is new to the spec's `process_attestation` in Electra.
                if index >= committee_count_per_slot {
                    return Err(BeaconStateError::InvalidCommitteeIndex(index));
                }

                participant_count.safe_add_assign(beacon_committee.committee.len() as u64)?;
                let committee_attesters = beacon_committee
                    .committee
                    .iter()
                    .enumerate()
                    .filter_map(|(i, &index)| {
                        if let Ok(aggregation_bit_index) = committee_offset.safe_add(i) {
                            if aggregation_bits.get(aggregation_bit_index).unwrap_or(false) {
                                return Some(index as u64);
                            }
                        }
                        None
                    })
                    .collect::<HashSet<u64>>();

                output.extend(committee_attesters);

                committee_offset.safe_add_assign(beacon_committee.committee.len())?;
            } else {
                return Err(Error::NoCommitteeFound(index));
            }
        }

        // This check is new to the spec's `process_attestation` in Electra.
        if participant_count as usize != aggregation_bits.len() {
            return Err(Error::InvalidBitfield);
        }

        let mut indices = output.into_iter().collect_vec();
        indices.sort_unstable();

        Ok(IndexedAttestation::Electra(IndexedAttestationElectra {
            attesting_indices: VariableList::new(indices)?,
            data: attestation.data.clone(),
            signature: attestation.signature.clone(),
        }))
    }

    pub fn get_indexed_attestation<E: EthSpec>(
        committees: &[BeaconCommittee],
        attestation: &AttestationElectra<E>,
    ) -> Result<IndexedAttestation<E>, BlockOperationError<Invalid>> {
        let attesting_indices = get_attesting_indices::<E>(
            committees,
            &attestation.aggregation_bits,
            &attestation.committee_bits,
        )?;

        Ok(IndexedAttestation::Electra(IndexedAttestationElectra {
            attesting_indices: VariableList::new(attesting_indices)?,
            data: attestation.data.clone(),
            signature: attestation.signature.clone(),
        }))
    }

    pub fn get_indexed_attestation_from_state<E: EthSpec>(
        beacon_state: &BeaconState<E>,
        attestation: &AttestationElectra<E>,
    ) -> Result<IndexedAttestation<E>, BlockOperationError<Invalid>> {
        let committees = beacon_state.get_beacon_committees_at_slot(attestation.data.slot)?;
        let attesting_indices = get_attesting_indices::<E>(
            &committees,
            &attestation.aggregation_bits,
            &attestation.committee_bits,
        )?;

        Ok(IndexedAttestation::Electra(IndexedAttestationElectra {
            attesting_indices: VariableList::new(attesting_indices)?,
            data: attestation.data.clone(),
            signature: attestation.signature.clone(),
        }))
    }

    /// Shortcut for getting the attesting indices while fetching the committee from the state's cache.
    pub fn get_attesting_indices_from_state<E: EthSpec>(
        state: &BeaconState<E>,
        att: &AttestationElectra<E>,
    ) -> Result<Vec<u64>, BeaconStateError> {
        let committees = state.get_beacon_committees_at_slot(att.data.slot)?;
        get_attesting_indices::<E>(&committees, &att.aggregation_bits, &att.committee_bits)
    }

    /// Returns validator indices which participated in the attestation, sorted by increasing index.
    pub fn get_attesting_indices<E: EthSpec>(
        committees: &[BeaconCommittee],
        aggregation_bits: &BitList<E::MaxValidatorsPerSlot>,
        committee_bits: &BitVector<E::MaxCommitteesPerSlot>,
    ) -> Result<Vec<u64>, BeaconStateError> {
        let mut output: HashSet<u64> = HashSet::new();

        let committee_indices = get_committee_indices::<E>(committee_bits);

        let mut committee_offset = 0;

        let committees_map: HashMap<u64, &BeaconCommittee> = committees
            .iter()
            .map(|committee| (committee.index, committee))
            .collect();

        let committee_count_per_slot = committees.len() as u64;
        let mut participant_count = 0;
        for index in committee_indices {
            if let Some(&beacon_committee) = committees_map.get(&index) {
                // This check is new to the spec's `process_attestation` in Electra.
                if index >= committee_count_per_slot {
                    return Err(BeaconStateError::InvalidCommitteeIndex(index));
                }
                participant_count.safe_add_assign(beacon_committee.committee.len() as u64)?;
                let committee_attesters = beacon_committee
                    .committee
                    .iter()
                    .enumerate()
                    .filter_map(|(i, &index)| {
                        if let Ok(aggregation_bit_index) = committee_offset.safe_add(i) {
                            if aggregation_bits.get(aggregation_bit_index).unwrap_or(false) {
                                return Some(index as u64);
                            }
                        }
                        None
                    })
                    .collect::<HashSet<u64>>();

                output.extend(committee_attesters);

                committee_offset.safe_add_assign(beacon_committee.committee.len())?;
            } else {
                return Err(Error::NoCommitteeFound(index));
            }
        }

        // This check is new to the spec's `process_attestation` in Electra.
        if participant_count as usize != aggregation_bits.len() {
            return Err(BeaconStateError::InvalidBitfield);
        }

        let mut indices = output.into_iter().collect_vec();
        indices.sort_unstable();

        Ok(indices)
    }

    pub fn get_committee_indices<E: EthSpec>(
        committee_bits: &BitVector<E::MaxCommitteesPerSlot>,
    ) -> Vec<CommitteeIndex> {
        committee_bits
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| if bit { Some(index as u64) } else { None })
            .collect()
    }
}

/// Shortcut for getting the attesting indices while fetching the committee from the state's cache.
pub fn get_attesting_indices_from_state<E: EthSpec>(
    state: &BeaconState<E>,
    att: AttestationRef<E>,
) -> Result<Vec<u64>, BeaconStateError> {
    match att {
        AttestationRef::Base(att) => {
            let committee = state.get_beacon_committee(att.data.slot, att.data.index)?;
            attesting_indices_base::get_attesting_indices::<E>(
                committee.committee,
                &att.aggregation_bits,
            )
        }
        AttestationRef::Electra(att) => {
            attesting_indices_electra::get_attesting_indices_from_state::<E>(state, att)
        }
    }
}
