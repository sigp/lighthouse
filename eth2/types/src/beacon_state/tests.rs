#![cfg(test)]

use super::*;
use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
use crate::{
    BeaconState, BeaconStateError, ChainSpec, Deposit, DepositData, DepositInput, Eth1Data,
    Hash256, Keypair,
};
use bls::create_proof_of_possession;
use ssz::{ssz_encode, Decodable};

struct BeaconStateTestBuilder {
    pub genesis_time: u64,
    pub initial_validator_deposits: Vec<Deposit>,
    pub latest_eth1_data: Eth1Data,
    pub spec: ChainSpec,
    pub keypairs: Vec<Keypair>,
}

impl BeaconStateTestBuilder {
    pub fn with_random_validators(validator_count: usize) -> Self {
        let genesis_time = 10_000_000;
        let keypairs: Vec<Keypair> = (0..validator_count)
            .collect::<Vec<usize>>()
            .iter()
            .map(|_| Keypair::random())
            .collect();
        let initial_validator_deposits = keypairs
            .iter()
            .map(|keypair| Deposit {
                branch: vec![], // branch verification is not specified.
                index: 0,       // index verification is not specified.
                deposit_data: DepositData {
                    amount: 32_000_000_000, // 32 ETH (in Gwei)
                    timestamp: genesis_time - 1,
                    deposit_input: DepositInput {
                        pubkey: keypair.pk.clone(),
                        withdrawal_credentials: Hash256::zero(), // Withdrawal not possible.
                        proof_of_possession: create_proof_of_possession(&keypair),
                    },
                },
            })
            .collect();
        let latest_eth1_data = Eth1Data {
            deposit_root: Hash256::zero(),
            block_hash: Hash256::zero(),
        };
        let spec = ChainSpec::foundation();

        Self {
            genesis_time,
            initial_validator_deposits,
            latest_eth1_data,
            spec,
            keypairs,
        }
    }

    pub fn build(&self) -> Result<BeaconState, BeaconStateError> {
        BeaconState::genesis(
            self.genesis_time,
            self.initial_validator_deposits.clone(),
            self.latest_eth1_data.clone(),
            &self.spec,
        )
    }
}

#[test]
pub fn can_produce_genesis_block() {
    let builder = BeaconStateTestBuilder::with_random_validators(2);

    builder.build().unwrap();
}

/// Tests that `get_attestation_participants` is consistent with the result of
/// get_crosslink_committees_at_slot` with a full bitfield.
#[test]
pub fn get_attestation_participants_consistency() {
    let mut rng = XorShiftRng::from_seed([42; 16]);

    let mut builder = BeaconStateTestBuilder::with_random_validators(8);
    builder.spec = ChainSpec::few_validators();

    let mut state = builder.build().unwrap();
    let spec = builder.spec.clone();

    state
        .build_epoch_cache(RelativeEpoch::Previous, &spec)
        .unwrap();
    state
        .build_epoch_cache(RelativeEpoch::Current, &spec)
        .unwrap();
    state.build_epoch_cache(RelativeEpoch::Next, &spec).unwrap();

    for slot in state
        .slot
        .epoch(spec.epoch_length)
        .slot_iter(spec.epoch_length)
    {
        let committees = state.get_crosslink_committees_at_slot(slot, &spec).unwrap();

        for (committee, shard) in committees {
            let mut attestation_data = AttestationData::random_for_test(&mut rng);
            attestation_data.slot = slot;
            attestation_data.shard = *shard;

            let mut bitfield = Bitfield::new();
            for (i, _) in committee.iter().enumerate() {
                bitfield.set(i, true);
            }

            assert_eq!(
                state
                    .get_attestation_participants(&attestation_data, &bitfield, &spec)
                    .unwrap(),
                *committee
            );
        }
    }
}

#[test]
pub fn test_ssz_round_trip() {
    let mut rng = XorShiftRng::from_seed([42; 16]);
    let original = BeaconState::random_for_test(&mut rng);

    let bytes = ssz_encode(&original);
    let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

    assert_eq!(original, decoded);
}

#[test]
pub fn test_hash_tree_root_internal() {
    let mut rng = XorShiftRng::from_seed([42; 16]);
    let original = BeaconState::random_for_test(&mut rng);

    let result = original.hash_tree_root_internal();

    assert_eq!(result.len(), 32);
    // TODO: Add further tests
    // https://github.com/sigp/lighthouse/issues/170
}
