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
    use std::collections::HashSet;

    use crate::per_block_processing::errors::{AttestationInvalid as Invalid, BlockOperationError};
    use safe_arith::SafeArith;
    use types::*;

    /// Compute an Electra IndexedAttestation given a list of committees.
    ///
    /// Committees must be sorted by ascending order 0..committees_per_slot
    pub fn get_indexed_attestation<E: EthSpec>(
        committees: &[BeaconCommittee],
        attestation: &AttestationElectra<E>,
        spec: &ChainSpec,
    ) -> Result<IndexedAttestation<E>, BlockOperationError<Invalid>> {
        let attesting_indices = get_attesting_indices::<E>(
            committees,
            &attestation.aggregation_bits,
            &attestation.committee_bits,
            spec,
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
        spec: &ChainSpec,
    ) -> Result<IndexedAttestation<E>, BlockOperationError<Invalid>> {
        let committees = beacon_state.get_beacon_committees_at_slot(attestation.data.slot)?;
        get_indexed_attestation(&committees, attestation, spec)
    }

    /// Shortcut for getting the attesting indices while fetching the committee from the state's cache.
    pub fn get_attesting_indices_from_state<E: EthSpec>(
        state: &BeaconState<E>,
        att: &AttestationElectra<E>,
        spec: &ChainSpec,
    ) -> Result<Vec<u64>, BeaconStateError> {
        let committees = state.get_beacon_committees_at_slot(att.data.slot)?;
        get_attesting_indices::<E>(
            &committees,
            &att.aggregation_bits,
            &att.committee_bits,
            spec,
        )
    }

    /// Returns a set of the PTC if the attestation slot is post EIP-7732, otherwise returns an empty set.
    pub fn get_ptc_set<E: EthSpec>(
        committees: &[BeaconCommittee],
        spec: &ChainSpec,
    ) -> Result<HashSet<u64>, BeaconStateError> {
        let attestation_slot = committees
            .get(0)
            .map(|committee| committee.slot)
            .ok_or(Error::NoCommitteeFound(0))?;
        if spec
            .fork_name_at_slot::<E>(attestation_slot)
            .eip7732_enabled()
        {
            PTC::<E>::from_committees(committees)
                .map(|ptc| ptc.into_iter().map(|i| i as u64).collect())
        } else {
            Ok(HashSet::new())
        }
    }

    /// Returns validator indices which participated in the attestation, sorted by increasing index.
    ///
    /// Committees must be sorted by ascending order 0..committees_per_slot
    pub fn get_attesting_indices<E: EthSpec>(
        committees: &[BeaconCommittee],
        aggregation_bits: &BitList<E::MaxValidatorsPerSlot>,
        committee_bits: &BitVector<E::MaxCommitteesPerSlot>,
        spec: &ChainSpec,
    ) -> Result<Vec<u64>, BeaconStateError> {
        let mut attesting_indices = vec![];

        let ptc_set = get_ptc_set::<E>(committees, spec)?;
        let committee_indices = get_committee_indices::<E>(committee_bits);

        let mut committee_offset = 0;

        let committee_count_per_slot = committees.len() as u64;
        let mut participant_count = 0;
        for index in committee_indices {
            let beacon_committee = committees
                .get(index as usize)
                .ok_or(Error::NoCommitteeFound(index))?;

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
                // EIP-7732: filter out the PTC
                .filter(|index| !ptc_set.contains(index))
                .collect::<HashSet<u64>>();

            attesting_indices.extend(committee_attesters);
            committee_offset.safe_add_assign(beacon_committee.committee.len())?;
        }

        // This check is new to the spec's `process_attestation` in Electra.
        if participant_count as usize != aggregation_bits.len() {
            return Err(BeaconStateError::InvalidBitfield);
        }

        attesting_indices.sort_unstable();

        Ok(attesting_indices)
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
    spec: &ChainSpec,
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
            attesting_indices_electra::get_attesting_indices_from_state::<E>(state, att, spec)
        }
    }
}
