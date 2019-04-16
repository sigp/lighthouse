use crate::*;
use tree_hash::TreeHash;

/// Builds an `AttesterSlashing`.
///
/// This struct should **never be used for production purposes.**
pub struct TestingAttesterSlashingBuilder();

impl TestingAttesterSlashingBuilder {
    /// Builds an `AttesterSlashing` that is a double vote.
    ///
    /// The `signer` function is used to sign the double-vote and accepts:
    ///
    /// - `validator_index: u64`
    /// - `message: &[u8]`
    /// - `epoch: Epoch`
    /// - `domain: Domain`
    ///
    /// Where domain is a domain "constant" (e.g., `spec.domain_attestation`).
    pub fn double_vote<F>(validator_indices: &[u64], signer: F) -> AttesterSlashing
    where
        F: Fn(u64, &[u8], Epoch, Domain) -> Signature,
    {
        let double_voted_slot = Slot::new(0);
        let shard = 0;
        let epoch = Epoch::new(0);
        let hash_1 = Hash256::from_low_u64_le(1);
        let hash_2 = Hash256::from_low_u64_le(2);

        let data_1 = AttestationData {
            slot: double_voted_slot,
            beacon_block_root: hash_1,
            source_epoch: epoch,
            source_root: hash_1,
            target_root: hash_1,
            shard,
            previous_crosslink: Crosslink {
                epoch,
                crosslink_data_root: hash_1,
            },
            crosslink_data_root: hash_1,
        };

        let data_2 = AttestationData {
            beacon_block_root: hash_2,
            ..data_1.clone()
        };

        let mut slashable_attestation_1 = SlashableAttestation {
            validator_indices: validator_indices.to_vec(),
            data: data_1,
            custody_bitfield: Bitfield::new(),
            aggregate_signature: AggregateSignature::new(),
        };

        let mut slashable_attestation_2 = SlashableAttestation {
            validator_indices: validator_indices.to_vec(),
            data: data_2,
            custody_bitfield: Bitfield::new(),
            aggregate_signature: AggregateSignature::new(),
        };

        let add_signatures = |attestation: &mut SlashableAttestation| {
            // All validators sign with a `false` custody bit.
            let attestation_data_and_custody_bit = AttestationDataAndCustodyBit {
                data: attestation.data.clone(),
                custody_bit: false,
            };
            let message = attestation_data_and_custody_bit.tree_hash_root();

            for (i, validator_index) in validator_indices.iter().enumerate() {
                attestation.custody_bitfield.set(i, false);
                let signature = signer(*validator_index, &message[..], epoch, Domain::Attestation);
                attestation.aggregate_signature.add(&signature);
            }
        };

        add_signatures(&mut slashable_attestation_1);
        add_signatures(&mut slashable_attestation_2);

        AttesterSlashing {
            slashable_attestation_1,
            slashable_attestation_2,
        }
    }
}
