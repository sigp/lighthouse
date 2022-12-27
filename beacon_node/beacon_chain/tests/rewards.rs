#![cfg(test)]

use lazy_static::lazy_static;
use beacon_chain::types::{
    test_utils::TestRandom, BeaconState, BeaconStateAltair, BeaconStateBase, BeaconStateError,
    ChainSpec, CloneConfig, Domain, Epoch, EthSpec, FixedVector, Hash256, Keypair, MainnetEthSpec,
    MinimalEthSpec, RelativeEpoch, Slot
};
use eth2::lighthouse::SyncCommitteeAttestationReward;
use beacon_chain::test_utils::{EphemeralHarnessType, BeaconChainHarness, generate_deterministic_keypairs};

pub const SLOT: Slot = Slot::new(12);
lazy_static! {
    static ref KEYPAIRS: Vec<Keypair> = generate_deterministic_keypairs(8);
}

fn get_harness<E: EthSpec>() -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .keypairs(KEYPAIRS.to_vec())
        .fresh_ephemeral_store()
        .build();

    let state = harness.get_current_state();
    let target_slot = SLOT;

    harness
        .add_attested_blocks_at_slots(
            state,
            Hash256::zero(),
            (1..target_slot.as_u64())
                .map(Slot::new)
                .collect::<Vec<_>>()
                .as_slice(),
            (0..12).collect::<Vec<_>>().as_slice(),
        );

    harness
}

#[tokio::test]
async fn test_sync_committee_rewards() {
    let harness = get_harness::<MainnetEthSpec>();
    let chain = harness.chain.clone();

    let block = chain.block_at_slot(SLOT, beacon_chain::WhenSlotSkipped::None).unwrap().unwrap();

    let mut state = harness.get_current_state();

    let reward_payload = chain
        .compute_sync_committee_rewards(block.message(), &mut state)
        .unwrap();

    assert_eq!(reward_payload.len(), 8);


}
