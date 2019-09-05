use super::get_attesting_indices;
use crate::per_block_processing::errors::{AttestationInvalid as Invalid, BlockOperationError};
use types::*;

type Result<T> = std::result::Result<T, BlockOperationError<Invalid>>;

/// Convert `attestation` to (almost) indexed-verifiable form.
///
/// Spec v0.8.0
pub fn get_indexed_attestation<T: EthSpec>(
    state: &BeaconState<T>,
    attestation: &Attestation<T>,
) -> Result<IndexedAttestation<T>> {
    // Note: we rely on both calls to `get_attesting_indices` to check the bitfield lengths
    // against the committee length
    let attesting_indices =
        get_attesting_indices(state, &attestation.data, &attestation.aggregation_bits)?;

    let custody_bit_1_indices =
        get_attesting_indices(state, &attestation.data, &attestation.custody_bits)?;

    verify!(
        custody_bit_1_indices.is_subset(&attesting_indices),
        Invalid::CustodyBitfieldNotSubset
    );

    let custody_bit_0_indices = &attesting_indices - &custody_bit_1_indices;

    Ok(IndexedAttestation {
        custody_bit_0_indices: VariableList::new(
            custody_bit_0_indices
                .into_iter()
                .map(|x| x as u64)
                .collect(),
        )?,
        custody_bit_1_indices: VariableList::new(
            custody_bit_1_indices
                .into_iter()
                .map(|x| x as u64)
                .collect(),
        )?,
        data: attestation.data.clone(),
        signature: attestation.signature.clone(),
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use itertools::{Either, Itertools};
    use types::test_utils::*;

    #[test]
    fn custody_bitfield_indexing() {
        let validator_count = 128;
        let spec = MinimalEthSpec::default_spec();
        let state_builder =
            TestingBeaconStateBuilder::<MinimalEthSpec>::from_default_keypairs_file_if_exists(
                validator_count,
                &spec,
            );
        let (mut state, keypairs) = state_builder.build();
        state.build_all_caches(&spec).unwrap();
        state.slot += 1;

        let shard = 0;
        let cc = state
            .get_crosslink_committee_for_shard(shard, RelativeEpoch::Current)
            .unwrap();

        // Make a third of the validators sign with custody bit 0, a third with custody bit 1
        // and a third not sign at all.
        assert!(
            cc.committee.len() >= 4,
            "need at least 4 validators per committee for this test to work"
        );
        let (mut bit_0_indices, mut bit_1_indices): (Vec<_>, Vec<_>) = cc
            .committee
            .iter()
            .enumerate()
            .filter(|(i, _)| i % 3 != 0)
            .partition_map(|(i, index)| {
                if i % 3 == 1 {
                    Either::Left(*index)
                } else {
                    Either::Right(*index)
                }
            });
        assert!(!bit_0_indices.is_empty());
        assert!(!bit_1_indices.is_empty());

        let bit_0_keys = bit_0_indices
            .iter()
            .map(|validator_index| &keypairs[*validator_index].sk)
            .collect::<Vec<_>>();
        let bit_1_keys = bit_1_indices
            .iter()
            .map(|validator_index| &keypairs[*validator_index].sk)
            .collect::<Vec<_>>();

        let mut attestation_builder =
            TestingAttestationBuilder::new(&state, &cc.committee, cc.slot, shard, &spec);
        attestation_builder
            .sign(&bit_0_indices, &bit_0_keys, &state.fork, &spec, false)
            .sign(&bit_1_indices, &bit_1_keys, &state.fork, &spec, true);
        let attestation = attestation_builder.build();

        let indexed_attestation = get_indexed_attestation(&state, &attestation).unwrap();

        bit_0_indices.sort();
        bit_1_indices.sort();

        assert!(indexed_attestation
            .custody_bit_0_indices
            .iter()
            .copied()
            .eq(bit_0_indices.iter().map(|idx| *idx as u64)));
        assert!(indexed_attestation
            .custody_bit_1_indices
            .iter()
            .copied()
            .eq(bit_1_indices.iter().map(|idx| *idx as u64)));
    }
}
