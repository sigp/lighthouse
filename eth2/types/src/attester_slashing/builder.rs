use crate::*;
use ssz::TreeHash;

pub struct AttesterSlashingBuilder();

impl AttesterSlashingBuilder {
    pub fn double_vote<F>(
        validator_indices: &[u64],
        signer: F,
        spec: &ChainSpec,
    ) -> AttesterSlashing
    where
        F: Fn(u64, &[u8], Epoch, u64) -> Signature,
    {
        let double_voted_slot = Slot::new(0);
        let shard = 0;
        let justified_epoch = Epoch::new(0);
        let epoch = Epoch::new(0);
        let hash_1 = Hash256::from("1".as_bytes());
        let hash_2 = Hash256::from("2".as_bytes());

        let mut slashable_attestation_1 = SlashableAttestation {
            validator_indices: validator_indices.to_vec(),
            data: AttestationData {
                slot: double_voted_slot,
                shard,
                beacon_block_root: hash_1,
                epoch_boundary_root: hash_1,
                shard_block_root: hash_1,
                latest_crosslink: Crosslink {
                    epoch,
                    shard_block_root: hash_1,
                },
                justified_epoch,
                justified_block_root: hash_1,
            },
            custody_bitfield: Bitfield::new(),
            aggregate_signature: AggregateSignature::new(),
        };

        let mut slashable_attestation_2 = SlashableAttestation {
            validator_indices: validator_indices.to_vec(),
            data: AttestationData {
                slot: double_voted_slot,
                shard,
                beacon_block_root: hash_2,
                epoch_boundary_root: hash_2,
                shard_block_root: hash_2,
                latest_crosslink: Crosslink {
                    epoch,
                    shard_block_root: hash_2,
                },
                justified_epoch,
                justified_block_root: hash_2,
            },
            custody_bitfield: Bitfield::new(),
            aggregate_signature: AggregateSignature::new(),
        };

        let add_signatures = |attestation: &mut SlashableAttestation| {
            for (i, validator_index) in validator_indices.iter().enumerate() {
                let attestation_data_and_custody_bit = AttestationDataAndCustodyBit {
                    data: attestation.data.clone(),
                    custody_bit: attestation.custody_bitfield.get(i).unwrap(),
                };
                let message = attestation_data_and_custody_bit.hash_tree_root();
                let signature = signer(
                    *validator_index,
                    &message[..],
                    epoch,
                    spec.domain_attestation,
                );
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
