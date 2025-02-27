use crate::attestation_verification::Error;
use types::{Attestation, AttestationElectra, BitList, BitVector, EthSpec, SingleAttestation};

pub fn single_attestation_to_attestation<E: EthSpec>(
    single_attestation: &SingleAttestation,
    committee: &[usize],
) -> Result<Attestation<E>, Error> {
    let attester_index = single_attestation.attester_index;
    let committee_index = single_attestation.committee_index;
    let slot = single_attestation.data.slot;

    let aggregation_bit = committee
        .iter()
        .enumerate()
        .find_map(|(i, &validator_index)| {
            if attester_index as usize == validator_index {
                return Some(i);
            }
            None
        })
        .ok_or(Error::AttesterNotInCommittee {
            attester_index,
            committee_index,
            slot,
        })?;

    let mut committee_bits: BitVector<E::MaxCommitteesPerSlot> = BitVector::default();
    committee_bits
        .set(committee_index as usize, true)
        .map_err(|e| Error::Invalid(e.into()))?;

    let mut aggregation_bits =
        BitList::with_capacity(committee.len()).map_err(|e| Error::Invalid(e.into()))?;
    aggregation_bits
        .set(aggregation_bit, true)
        .map_err(|e| Error::Invalid(e.into()))?;

    // TODO(electra): consider eventually allowing conversion to non-Electra attestations as well
    // to maintain invertability (`Attestation` -> `SingleAttestation` -> `Attestation`).
    Ok(Attestation::Electra(AttestationElectra {
        aggregation_bits,
        committee_bits,
        data: single_attestation.data.clone(),
        signature: single_attestation.signature.clone(),
    }))
}
