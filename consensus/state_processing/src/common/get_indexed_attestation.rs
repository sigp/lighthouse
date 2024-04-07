



pub mod indexed_attestation_base {
    use types::{attestation::AttestationBase, *};
    use crate::per_block_processing::errors::{AttestationInvalid as Invalid, BlockOperationError};
    type IndexedAttestationResult<T> = std::result::Result<T, BlockOperationError<Invalid>>;

    /// Convert `attestation` to (almost) indexed-verifiable form.
    ///
    /// Spec v0.12.1
    pub fn get_indexed_attestation<E: EthSpec>(
        committee: &[usize],
        attestation: &AttestationBase<E>,
    ) -> IndexedAttestationResult<IndexedAttestation<E>> {
        let attesting_indices = get_attesting_indices::<E>(committee, &attestation.aggregation_bits)?;
    
        Ok(IndexedAttestation {
            attesting_indices: VariableList::new(attesting_indices)?,
            data: attestation.data,
            signature: attestation.signature,
        })
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

    /// Shortcut for getting the attesting indices while fetching the committee from the state's cache.
    pub fn get_attesting_indices_from_state<E: EthSpec>(
        state: &BeaconState<E>,
        att: &AttestationBase<E>,
    ) -> Result<Vec<u64>, BeaconStateError> {
        let committee = state.get_beacon_committee(att.data.slot, att.data.index)?;
        get_attesting_indices::<E>(committee.committee, &att.aggregation_bits)
    }
}

pub mod indexed_attestation_electra {

    use std::collections::HashSet;

    use itertools::Itertools;
    use types::{attestation::AttestationElectra, *};
    use crate::per_block_processing::errors::{AttestationInvalid as Invalid, BlockOperationError};
    type IndexedAttestationResult<T> = std::result::Result<T, BlockOperationError<Invalid>>;
    
    pub fn get_indexed_attestation<E: EthSpec>(
        beacon_state: &BeaconState<E>,
        attestation: &AttestationElectra<E>,
    ) -> IndexedAttestationResult<IndexedAttestation<E>> {
        let attesting_indices = get_attesting_indices::<E>(beacon_state, &attestation)?;
    
        Ok(IndexedAttestation {
            attesting_indices: VariableList::new(attesting_indices)?,
            data: attestation.data,
            signature: attestation.signature,
        })
    }

     /// Returns validator indices which participated in the attestation, sorted by increasing index.
     pub fn get_attesting_indices<E: EthSpec>(
        beacon_state: &BeaconState<E>,
        attestation: &AttestationElectra<E>,
    ) -> Result<Vec<u64>, BeaconStateError> {
        let mut output: HashSet<u64> = HashSet::new();

        let committee_indices = get_committee_indices::<E>(attestation.committee_bits);
        let mut committee_offset = 0;

        for index in committee_indices {
    
            let beacon_committee =
                beacon_state.get_beacon_committee(attestation.data.slot, index)?;
    
            let committee_attesters = beacon_committee
                .committee
                .iter()
                .enumerate()
                .filter_map(|(i, &index)| if attestation.aggregation_bits.get(committee_offset + i).unwrap_or(false) { Some(index as u64) } else { None })
                .collect::<HashSet<u64>>();

            output.extend(committee_attesters);

            committee_offset += beacon_committee.committee.len();
    
        }

        Ok(output.into_iter().collect_vec())
    }

    fn get_committee_indices<E: EthSpec>(committee_bits: BitList<E::MaxCommitteesPerSlot>) -> Vec<CommitteeIndex>{
        committee_bits
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| if bit { Some(index as u64) } else { None })
            .collect()
    }
}
