pub mod indexed_attestation_base {
    use crate::per_block_processing::errors::{AttestationInvalid as Invalid, BlockOperationError};
    use types::{attestation::AttestationBase, *};
    type IndexedAttestationResult<T> = std::result::Result<T, BlockOperationError<Invalid>>;

    /// Convert `attestation` to (almost) indexed-verifiable form.
    ///
    /// Spec v0.12.1
    pub fn get_indexed_attestation<E: EthSpec>(
        committee: &[usize],
        attestation: &AttestationBase<E>,
    ) -> IndexedAttestationResult<IndexedAttestation<E>> {
        let attesting_indices =
            get_attesting_indices::<E>(committee, &attestation.aggregation_bits)?;

        Ok(IndexedAttestation {
            attesting_indices: VariableList::new(attesting_indices)?,
            data: attestation.data.clone(),
            signature: attestation.signature.clone(),
        })
    }

    /// Returns validator indices which participated in the attestation, sorted by increasing index.
    pub fn get_attesting_indices<E: EthSpec>(
        committee: &[usize],
        bitlist: &BitList<E::MaxValidatorsPerCommitteePerSlot>,
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

    use std::collections::{HashMap, HashSet};

    use crate::per_block_processing::errors::{AttestationInvalid as Invalid, BlockOperationError};
    use itertools::Itertools;
    use safe_arith::SafeArith;
    use types::{attestation::AttestationElectra, *};
    type IndexedAttestationResult<T> = std::result::Result<T, BlockOperationError<Invalid>>;

    pub fn get_indexed_attestation<E: EthSpec>(
        committees: &[BeaconCommittee],
        attestation: &AttestationElectra<E>,
    ) -> IndexedAttestationResult<IndexedAttestation<E>> {
        let attesting_indices = get_attesting_indices::<E>(
            committees,
            &attestation.aggregation_bits,
            &attestation.committee_bits,
        )?;

        Ok(IndexedAttestation {
            attesting_indices: VariableList::new(attesting_indices)?,
            data: attestation.data.clone(),
            signature: attestation.signature.clone(),
        })
    }

    pub fn get_indexed_attestation_from_state<E: EthSpec>(
        beacon_state: &BeaconState<E>,
        attestation: &AttestationElectra<E>,
    ) -> IndexedAttestationResult<IndexedAttestation<E>> {
        let committees = beacon_state.get_beacon_committees_at_slot(attestation.data.slot)?;
        let attesting_indices = get_attesting_indices::<E>(
            &committees,
            &attestation.aggregation_bits,
            &attestation.committee_bits,
        )?;

        Ok(IndexedAttestation {
            attesting_indices: VariableList::new(attesting_indices)?,
            data: attestation.data.clone(),
            signature: attestation.signature.clone(),
        })
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
        aggregation_bits: &BitList<E::MaxValidatorsPerCommitteePerSlot>,
        committee_bits: &BitVector<E::MaxCommitteesPerSlot>,
    ) -> Result<Vec<u64>, BeaconStateError> {
        let mut output: HashSet<u64> = HashSet::new();

        let committee_indices = get_committee_indices::<E>(committee_bits);
        let committee_offset = 0;

        let committees_map: HashMap<u64, &BeaconCommittee> = committees
            .iter()
            .map(|committee| (committee.index, committee))
            .collect();

        for index in committee_indices {
            if let Some(&beacon_committee) = committees_map.get(&index) {
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

                committee_offset.safe_add(beacon_committee.committee.len())?;
            } else {
                return Err(Error::NoCommitteeFound);
            }

            // TODO(eip7549) what should we do when theres no committee found for a given index?
        }

        Ok(output.into_iter().collect_vec())
    }

    fn get_committee_indices<E: EthSpec>(
        committee_bits: &BitVector<E::MaxCommitteesPerSlot>,
    ) -> Vec<CommitteeIndex> {
        committee_bits
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| if bit { Some(index as u64) } else { None })
            .collect()
    }
}
