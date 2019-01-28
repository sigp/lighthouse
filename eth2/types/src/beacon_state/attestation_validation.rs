use crate::{AggregatePublicKey, Attestation, BeaconState, ChainSpec, Fork};
use bls::bls_verify_aggregate;

#[derive(Debug, PartialEq)]
pub enum Error {
    IncludedTooEarly,
    IncludedTooLate,
    WrongJustifiedSlot,
    WrongJustifiedRoot,
    BadLatestCrosslinkRoot,
    BadSignature,
    ShardBlockRootNotZero,
    NoBlockRoot,
}

macro_rules! ensure {
    ($condition: expr, $result: expr) => {
        if !$condition {
            return Err($result);
        }
    };
}

const PHASE_0_CUSTODY_BIT: bool = false;

// TODO: define elsehwere.
const DOMAIN_ATTESTATION: u64 = 1;

impl BeaconState {
    pub fn validate_attestation(
        &self,
        attestation: &Attestation,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        ensure!(
            attestation.data.slot + spec.min_attestation_inclusion_delay <= self.slot,
            Error::IncludedTooEarly
        );
        ensure!(
            attestation.data.slot + spec.epoch_length >= self.slot,
            Error::IncludedTooLate
        );
        if self.justified_slot >= self.slot - (self.slot % spec.epoch_length) {
            ensure!(
                attestation.data.justified_slot == self.justified_slot,
                Error::WrongJustifiedSlot
            );
        } else {
            ensure!(
                attestation.data.justified_slot == self.previous_justified_slot,
                Error::WrongJustifiedSlot
            );
        }
        ensure!(
            attestation.data.justified_block_root
                == *self
                    .get_block_root(attestation.data.justified_slot, &spec)
                    .ok_or(Error::NoBlockRoot)?,
            Error::WrongJustifiedRoot
        );
        ensure!(
            (attestation.data.latest_crosslink_root
                == self.latest_crosslinks[attestation.data.shard as usize].shard_block_root)
                || (attestation.data.shard_block_root
                    == self.latest_crosslinks[attestation.data.shard as usize].shard_block_root),
            Error::BadLatestCrosslinkRoot
        );
        let participants =
            self.get_attestation_participants(&attestation.data, &attestation.aggregation_bitfield);
        let mut group_public_key = AggregatePublicKey::new();
        for participant in participants {
            group_public_key.add(
                self.validator_registry[participant as usize]
                    .pubkey
                    .as_raw(),
            )
        }
        ensure!(
            bls_verify_aggregate(
                &group_public_key,
                &attestation.signable_message(PHASE_0_CUSTODY_BIT),
                &attestation.aggregate_signature,
                get_domain(&self.fork_data, attestation.data.slot, DOMAIN_ATTESTATION)
            ),
            Error::BadSignature
        );
        ensure!(
            attestation.data.shard_block_root == spec.zero_hash,
            Error::ShardBlockRootNotZero
        );
        Ok(())
    }
}

pub fn get_domain(_fork: &Fork, _slot: u64, _domain_type: u64) -> u64 {
    // TODO: stubbed out.
    0
}
