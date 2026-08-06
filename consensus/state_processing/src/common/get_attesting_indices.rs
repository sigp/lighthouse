use types::*;

pub mod attesting_indices_base {
    use crate::per_block_processing::errors::{AttestationInvalid as Invalid, BlockOperationError};
    use ssz_types::{BitList, VariableList};
    use typenum::U;
    use types::*;

    /// Convert `attestation` to (almost) indexed-verifiable form.
    ///
    /// Spec v0.12.1
    pub fn get_indexed_attestation(
        committee: &[usize],
        attestation: &AttestationBase,
    ) -> Result<IndexedAttestation, BlockOperationError<Invalid>> {
        let attesting_indices = get_attesting_indices(committee, &attestation.aggregation_bits)?;
        Ok(IndexedAttestation::Base(IndexedAttestationBase {
            attesting_indices: VariableList::new(attesting_indices)?,
            data: attestation.data.clone(),
            signature: attestation.signature.clone(),
        }))
    }

    /// Returns validator indices which participated in the attestation, sorted by increasing index.
    pub fn get_attesting_indices(
        committee: &[usize],
        bitlist: &BitList<U<{ Spec::MAX_VALIDATORS_PER_COMMITTEE }>>,
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
    use crate::per_block_processing::errors::{AttestationInvalid as Invalid, BlockOperationError};
    use safe_arith::SafeArith;
    use ssz_types::{BitVector, VariableList};
    use std::collections::HashSet;
    use typenum::U;
    use types::*;

    /// Compute an Electra IndexedAttestation given a list of committees.
    ///
    /// Committees must be sorted by ascending order 0..committees_per_slot
    pub fn get_indexed_attestation(
        committees: &[BeaconCommittee],
        attestation: &AttestationElectra,
    ) -> Result<IndexedAttestation, BlockOperationError<Invalid>> {
        let attesting_indices = get_attesting_indices(
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

    pub fn get_indexed_attestation_from_state(
        beacon_state: &BeaconState,
        attestation: &AttestationElectra,
    ) -> Result<IndexedAttestation, BlockOperationError<Invalid>> {
        let committees = beacon_state.get_beacon_committees_at_slot(attestation.data.slot)?;
        get_indexed_attestation(&committees, attestation)
    }

    /// Shortcut for getting the attesting indices while fetching the committee from the state's cache.
    pub fn get_attesting_indices_from_state(
        state: &BeaconState,
        att: &AttestationElectra,
    ) -> Result<Vec<u64>, BeaconStateError> {
        let committees = state.get_beacon_committees_at_slot(att.data.slot)?;
        get_attesting_indices(&committees, &att.aggregation_bits, &att.committee_bits)
    }

    /// Returns validator indices which participated in the attestation, sorted by increasing index.
    ///
    /// Committees must be sorted by ascending order 0..committees_per_slot
    ///
    /// Generic over the aggregation bitfield type so it can serve both Electra (`BitList`) and
    /// Gloas (`ProgressiveBitList`, EIP-7688) attestations.
    pub fn get_attesting_indices<B: ssz::BitfieldBehaviour>(
        committees: &[BeaconCommittee],
        aggregation_bits: &ssz::Bitfield<B>,
        committee_bits: &BitVector<U<{ Spec::MAX_COMMITTEES_PER_SLOT }>>,
    ) -> Result<Vec<u64>, BeaconStateError> {
        let mut attesting_indices = vec![];

        let committee_indices = get_committee_indices(committee_bits);

        let mut committee_offset = 0;

        let committee_count_per_slot = committees.len() as u64;
        let mut participant_count = 0;
        for committee_index in committee_indices {
            let beacon_committee = committees
                .get(committee_index as usize)
                .ok_or(BeaconStateError::NoCommitteeFound(committee_index))?;

            // This check is new to the spec's `process_attestation` in Electra.
            if committee_index >= committee_count_per_slot {
                return Err(BeaconStateError::InvalidCommitteeIndex(committee_index));
            }
            participant_count.safe_add_assign(beacon_committee.committee.len() as u64)?;
            let committee_attesters = beacon_committee
                .committee
                .iter()
                .enumerate()
                .filter_map(|(i, &index)| {
                    if let Ok(aggregation_bit_index) = committee_offset.safe_add(i)
                        && aggregation_bits.get(aggregation_bit_index) == Ok(true)
                    {
                        return Some(index as u64);
                    }
                    None
                })
                .collect::<HashSet<u64>>();

            // Require at least a single non-zero bit for each attesting committee bitfield.
            // This check is new to the spec's `process_attestation` in Electra.
            if committee_attesters.is_empty() {
                return Err(BeaconStateError::EmptyCommittee);
            }

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

    pub fn get_committee_indices(
        committee_bits: &BitVector<U<{ Spec::MAX_COMMITTEES_PER_SLOT }>>,
    ) -> Vec<CommitteeIndex> {
        committee_bits
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| if bit { Some(index as u64) } else { None })
            .collect()
    }
}

pub mod attesting_indices_gloas {
    use crate::common::attesting_indices_electra;
    use crate::per_block_processing::errors::{AttestationInvalid as Invalid, BlockOperationError};
    use ssz_types::ProgressiveVariableList;
    use types::*;

    /// Compute a Gloas `IndexedAttestation` given a list of committees.
    ///
    /// Committees must be sorted by ascending order 0..committees_per_slot
    pub fn get_indexed_attestation(
        committees: &[BeaconCommittee],
        attestation: &AttestationGloas,
    ) -> Result<IndexedAttestation, BlockOperationError<Invalid>> {
        let attesting_indices = attesting_indices_electra::get_attesting_indices(
            committees,
            &attestation.aggregation_bits,
            &attestation.committee_bits,
        )?;

        Ok(IndexedAttestation::Gloas(IndexedAttestationGloas {
            attesting_indices: ProgressiveVariableList::new(attesting_indices),
            data: attestation.data.clone(),
            signature: attestation.signature.clone(),
        }))
    }

    pub fn get_indexed_attestation_from_state(
        beacon_state: &BeaconState,
        attestation: &AttestationGloas,
    ) -> Result<IndexedAttestation, BlockOperationError<Invalid>> {
        let committees = beacon_state.get_beacon_committees_at_slot(attestation.data.slot)?;
        get_indexed_attestation(&committees, attestation)
    }

    /// Shortcut for getting the attesting indices while fetching the committee from the state's cache.
    pub fn get_attesting_indices_from_state(
        state: &BeaconState,
        att: &AttestationGloas,
    ) -> Result<Vec<u64>, BeaconStateError> {
        let committees = state.get_beacon_committees_at_slot(att.data.slot)?;
        attesting_indices_electra::get_attesting_indices(
            &committees,
            &att.aggregation_bits,
            &att.committee_bits,
        )
    }
}

/// Shortcut for getting the attesting indices while fetching the committee from the state's cache.
pub fn get_attesting_indices_from_state(
    state: &BeaconState,
    att: AttestationRef,
) -> Result<Vec<u64>, BeaconStateError> {
    match att {
        AttestationRef::Base(att) => {
            let committee = state.get_beacon_committee(att.data.slot, att.data.index)?;
            attesting_indices_base::get_attesting_indices(
                committee.committee,
                &att.aggregation_bits,
            )
        }
        AttestationRef::Electra(att) => {
            attesting_indices_electra::get_attesting_indices_from_state(state, att)
        }
        AttestationRef::Gloas(att) => {
            attesting_indices_gloas::get_attesting_indices_from_state(state, att)
        }
    }
}
