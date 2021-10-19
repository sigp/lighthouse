#![cfg(not(debug_assertions))]

#[macro_use]
extern crate lazy_static;

use beacon_chain::sync_committee_verification::Error as SyncCommitteeError;
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType, RelativeSyncCommittee};
use int_to_bytes::int_to_bytes32;
use safe_arith::SafeArith;
use store::{SignedContributionAndProof, SyncCommitteeMessage};
use tree_hash::TreeHash;
use types::consts::altair::SYNC_COMMITTEE_SUBNET_COUNT;
use types::{
    AggregateSignature, Epoch, EthSpec, Hash256, Keypair, MainnetEthSpec, SecretKey, Slot,
    SyncSelectionProof, SyncSubnetId, Unsigned,
};

pub type E = MainnetEthSpec;

pub const VALIDATOR_COUNT: usize = 256;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
}

/// Returns a beacon chain harness.
fn get_harness(validator_count: usize) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(Epoch::new(0));
    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .spec(spec)
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_ephemeral_store()
        .build();

    harness.advance_slot();

    harness
}

/// Returns a sync message that is valid for some slot in the given `chain`.
///
/// Also returns some info about who created it.
fn get_valid_sync_committee_message(
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    slot: Slot,
    relative_sync_committee: RelativeSyncCommittee,
) -> (SyncCommitteeMessage, usize, SecretKey, SyncSubnetId) {
    let head_state = harness
        .chain
        .head_beacon_state()
        .expect("should get head state");
    let head_block_root = harness
        .chain
        .head()
        .expect("should get head state")
        .beacon_block_root;
    let (signature, _) = harness
        .make_sync_committee_messages(&head_state, head_block_root, slot, relative_sync_committee)
        .get(0)
        .expect("sync messages should exist")
        .get(0)
        .expect("first sync message should exist")
        .clone();

    (
        signature.clone(),
        signature.validator_index as usize,
        harness.validator_keypairs[signature.validator_index as usize]
            .sk
            .clone(),
        SyncSubnetId::new(0),
    )
}

fn get_valid_sync_contribution(
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    relative_sync_committee: RelativeSyncCommittee,
) -> (SignedContributionAndProof<E>, usize, SecretKey) {
    let head_state = harness
        .chain
        .head_beacon_state()
        .expect("should get head state");

    let head_block_root = harness
        .chain
        .head()
        .expect("should get head state")
        .beacon_block_root;
    let sync_contributions = harness.make_sync_contributions(
        &head_state,
        head_block_root,
        head_state.slot(),
        relative_sync_committee,
    );

    let (_, contribution_opt) = sync_contributions
        .get(0)
        .expect("sync contributions should exist");
    let contribution = contribution_opt
        .as_ref()
        .cloned()
        .expect("signed contribution and proof should exist");

    let aggregator_index = contribution.message.aggregator_index as usize;

    (
        contribution,
        aggregator_index,
        harness.validator_keypairs[aggregator_index].sk.clone(),
    )
}

/// Returns a proof and index for a validator that is **not** an aggregator for the current sync period.
fn get_non_aggregator(
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    slot: Slot,
) -> (usize, SecretKey) {
    let state = &harness.chain.head().expect("should get head").beacon_state;
    let sync_subcommittee_size = E::sync_committee_size()
        .safe_div(SYNC_COMMITTEE_SUBNET_COUNT as usize)
        .expect("should determine sync subcommittee size");
    let sync_committee = state
        .current_sync_committee()
        .expect("should use altair state")
        .clone();
    let non_aggregator_index = sync_committee
        .pubkeys
        .chunks(sync_subcommittee_size)
        .enumerate()
        .find_map(|(subcommittee_index, subcommittee)| {
            subcommittee.iter().find_map(|pubkey| {
                let validator_index = harness
                    .chain
                    .validator_index(&pubkey)
                    .expect("should get validator index")
                    .expect("pubkey should exist in beacon chain");

                let selection_proof = SyncSelectionProof::new::<E>(
                    slot,
                    subcommittee_index as u64,
                    &harness.validator_keypairs[validator_index].sk,
                    &state.fork(),
                    state.genesis_validators_root(),
                    &harness.spec,
                );

                if !selection_proof
                    .is_aggregator::<E>()
                    .expect("should determine aggregator")
                {
                    Some(validator_index)
                } else {
                    None
                }
            })
        })
        .expect("should find at least one non-aggregator");

    let aggregator_sk = harness.validator_keypairs[non_aggregator_index].sk.clone();
    (non_aggregator_index, aggregator_sk)
}

/// Tests verification of `SignedContributionAndProof` from the gossip network.
#[test]
fn aggregated_gossip_verification() {
    let harness = get_harness(VALIDATOR_COUNT);
    let state = harness.get_current_state();

    harness.add_attested_blocks_at_slots(
        state,
        Hash256::zero(),
        &[Slot::new(1), Slot::new(2)],
        (0..VALIDATOR_COUNT).collect::<Vec<_>>().as_slice(),
    );

    let current_slot = harness.chain.slot().expect("should get slot");

    let (valid_aggregate, aggregator_index, aggregator_sk) =
        get_valid_sync_contribution(&harness, RelativeSyncCommittee::Current);

    macro_rules! assert_invalid {
            ($desc: tt, $attn_getter: expr, $($error: pat) |+ $( if $guard: expr )?) => {
                assert!(
                    matches!(
                        harness
                            .chain
                            .verify_sync_contribution_for_gossip($attn_getter)
                            .err()
                            .expect(&format!(
                                "{} should error during verify_sync_contribution_for_gossip",
                                $desc
                            )),
                        $( $error ) |+ $( if $guard )?
                    ),
                    "case: {}",
                    $desc,
                );
            };
        }

    /*
     * The following two tests ensure:
     *
     * The contribution's slot is for the current slot, i.e. contribution.slot == current_slot
     * (with a MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance).
     */

    let future_slot = current_slot + 1;
    assert_invalid!(
        "aggregate from future slot",
        {
            let mut a = valid_aggregate.clone();
            a.message.contribution.slot = future_slot;
            a
        },
        SyncCommitteeError::FutureSlot { message_slot, latest_permissible_slot }
        if message_slot == future_slot && latest_permissible_slot == current_slot
    );

    let early_slot = current_slot
        .as_u64()
        // Subtract an additional slot since the harness will be exactly on the start of the
        // slot and the propagation tolerance will allow an extra slot.
        .checked_sub(2)
        .expect("chain is not sufficiently deep for test")
        .into();
    assert_invalid!(
        "aggregate from past slot",
        {
            let mut a = valid_aggregate.clone();
            a.message.contribution.slot = early_slot;
            a
        },
        SyncCommitteeError::PastSlot {
            message_slot,

            earliest_permissible_slot
        }
        if message_slot == early_slot
            && earliest_permissible_slot == current_slot - 1
    );

    /*
     * The following test ensures:
     *
     * The subcommittee index is in the allowed range,
     * i.e. `contribution.subcommittee_index < SYNC_COMMITTEE_SUBNET_COUNT`.
     */

    assert_invalid!(
        "subcommittee index out of range",
        {
            let mut a = valid_aggregate.clone();
            a.message.contribution.subcommittee_index = SYNC_COMMITTEE_SUBNET_COUNT;
            a
        },
       SyncCommitteeError::InvalidSubcommittee {
                subcommittee_index,
                subcommittee_size,
            }
            if subcommittee_index == SYNC_COMMITTEE_SUBNET_COUNT && subcommittee_size == SYNC_COMMITTEE_SUBNET_COUNT

    );

    /*
     * The following test ensures:
     *
     * The sync contribution has participants.
     */

    assert_invalid!(
        "aggregate with no participants",
        {
            let mut a = valid_aggregate.clone();
            let aggregation_bits = &mut a.message.contribution.aggregation_bits;
            aggregation_bits.difference_inplace(&aggregation_bits.clone());
            assert!(aggregation_bits.is_zero());
            a.message.contribution.signature = AggregateSignature::infinity();
            a
        },
        SyncCommitteeError::EmptyAggregationBitfield
    );

    /*
     * This test ensures:
     *
     * The aggregator signature, signed_contribution_and_proof.signature, is valid.
     */

    assert_invalid!(
        "aggregate with bad signature",
        {
            let mut a = valid_aggregate.clone();

            a.signature = aggregator_sk.sign(Hash256::from_low_u64_be(42));

            a
        },
        SyncCommitteeError::InvalidSignature
    );

    /*
     * The following test ensures:
     *
     * The contribution_and_proof.selection_proof is a valid signature of the `SyncAggregatorSelectionData`
     * derived from the contribution by the validator with index `contribution_and_proof.aggregator_index`.
     */

    assert_invalid!(
        "aggregate with bad selection proof signature",
        {
            let mut a = valid_aggregate.clone();

            // Generate some random signature until happens to be a valid selection proof. We need
            // this in order to reach the signature verification code.
            //
            // Could run for ever, but that seems _really_ improbable.
            let mut i: u64 = 0;
            a.message.selection_proof = loop {
                i += 1;
                let proof: SyncSelectionProof = aggregator_sk
                    .sign(Hash256::from_slice(&int_to_bytes32(i)))
                    .into();
                if proof
                    .is_aggregator::<E>()
                    .expect("should determine aggregator")
                {
                    break proof.into();
                }
            };

            a
        },
        SyncCommitteeError::InvalidSignature
    );

    /*
     * The following test ensures:
     *
     * The aggregate signature is valid for the message `beacon_block_root` and aggregate pubkey
     * derived from the participation info in `aggregation_bits` for the subcommittee specified by
     * the `contribution.subcommittee_index`.
     */

    assert_invalid!(
        "aggregate with bad aggregate signature",
        {
            let mut a = valid_aggregate.clone();

            let mut agg_sig = AggregateSignature::infinity();
            agg_sig.add_assign(&aggregator_sk.sign(Hash256::from_low_u64_be(42)));
            a.message.contribution.signature = agg_sig;

            a
        },
        SyncCommitteeError::InvalidSignature
    );

    let too_high_index = <E as EthSpec>::ValidatorRegistryLimit::to_u64() + 1;
    assert_invalid!(
        "aggregate with too-high aggregator index",
        {
            let mut a = valid_aggregate.clone();
            a.message.aggregator_index = too_high_index;
            a
        },
        SyncCommitteeError::UnknownValidatorIndex(index)
        if index == too_high_index as usize
    );

    /*
     * The following test ensures:
     *
     * The aggregator's validator index is in the declared subcommittee of the current sync
     * committee -- i.e. state.validators[contribution_and_proof.aggregator_index].pubkey in
     * get_sync_subcommittee_pubkeys(state, contribution.subcommittee_index).
     */

    assert_invalid!(
        "aggregate with unknown aggregator index",
        {
            let mut a = valid_aggregate.clone();
            a.message.contribution.subcommittee_index +=1;
            a
        },
        SyncCommitteeError::AggregatorNotInCommittee {
            aggregator_index
        }
        if aggregator_index == valid_aggregate.message.aggregator_index as u64
    );

    /*
     * The following test ensures:
     *
     * `contribution_and_proof.selection_proof` selects the validator as an aggregator for the
     *  slot -- i.e. is_sync_committee_aggregator(contribution_and_proof.selection_proof) returns True.
     */

    let (non_aggregator_index, non_aggregator_sk) = get_non_aggregator(&harness, current_slot);
    assert_invalid!(
        "aggregate from non-aggregator",
        {
            SignedContributionAndProof::from_aggregate(
                non_aggregator_index as u64,
                valid_aggregate.message.contribution.clone(),
                None,
                &non_aggregator_sk,
                &harness.chain.head_info().expect("should get head info").fork,
                harness.chain.genesis_validators_root,
                &harness.chain.spec,
            )
        },
        SyncCommitteeError::InvalidSelectionProof {
            aggregator_index: index
        }
        if index == non_aggregator_index as u64
    );

    // NOTE: from here on, the tests are stateful, and rely on the valid sync contribution having been
    // seen. A refactor to give each test case its own state might be nice at some point
    harness
        .chain
        .verify_sync_contribution_for_gossip(valid_aggregate.clone())
        .expect("should verify sync contribution");

    /*
     * The following test ensures:
     *
     * The sync committee contribution is the first valid contribution received for the aggregator
     * with index contribution_and_proof.aggregator_index for the slot contribution.slot and
     * subcommittee index contribution.subcommittee_index.
     */

    assert_invalid!(
        "aggregate that has already been seen",
        valid_aggregate.clone(),
        SyncCommitteeError::SyncContributionAlreadyKnown(hash)
        if hash == valid_aggregate.message.contribution.tree_hash_root()
    );

    /*
     * The following test ensures:
     *
     * The sync committee contribution is the first valid contribution received for the aggregator
     * with index `contribution_and_proof.aggregator_index` for the slot `contribution.slot` and
     * subcommittee index `contribution.subcommittee_index`.
     */

    assert_invalid!(
        "aggregate from aggregator and subcommittee that has already been seen",
        {
            let mut a = valid_aggregate;
            a.message.contribution.beacon_block_root = Hash256::from_low_u64_le(42);
            a
        },
        SyncCommitteeError::AggregatorAlreadyKnown(index)
        if index == aggregator_index as u64
    );

    /*
     * The following test ensures that:
     *
     * A sync committee contribution for the slot before the sync committee period boundary is verified
     * using the `head_state.next_sync_committee`.
     */

    // Advance to the slot before the 3rd sync committee period because `current_sync_committee = next_sync_committee`
    // at genesis.
    let state = harness.get_current_state();
    let target_slot = Slot::new(
        (2 * harness.spec.epochs_per_sync_committee_period.as_u64() * E::slots_per_epoch()) - 1,
    );

    harness
        .add_attested_block_at_slot(target_slot, state, Hash256::zero(), &[])
        .expect("should add block");

    // **Incorrectly** create a sync contribution using the current sync committee
    let (next_valid_contribution, _, _) =
        get_valid_sync_contribution(&harness, RelativeSyncCommittee::Current);

    assert_invalid!(
        "sync contribution created with incorrect sync committee",
        next_valid_contribution.clone(),
        SyncCommitteeError::InvalidSignature | SyncCommitteeError::AggregatorNotInCommittee { .. }
    );
}

/// Tests the verification conditions for sync committee messages on the gossip network.
#[test]
fn unaggregated_gossip_verification() {
    let harness = get_harness(VALIDATOR_COUNT);
    let state = harness.get_current_state();

    harness.add_attested_blocks_at_slots(
        state,
        Hash256::zero(),
        &[Slot::new(1), Slot::new(2)],
        (0..VALIDATOR_COUNT).collect::<Vec<_>>().as_slice(),
    );

    let current_slot = harness.chain.slot().expect("should get slot");

    let (valid_sync_committee_message, expected_validator_index, validator_sk, subnet_id) =
        get_valid_sync_committee_message(&harness, current_slot, RelativeSyncCommittee::Current);

    macro_rules! assert_invalid {
            ($desc: tt, $attn_getter: expr, $subnet_getter: expr, $($error: pat) |+ $( if $guard: expr )?) => {
                assert!(
                    matches!(
                        harness
                            .chain
                            .verify_sync_committee_message_for_gossip($attn_getter, $subnet_getter)
                            .err()
                            .expect(&format!(
                                "{} should error during verify_sync_committee_message_for_gossip",
                                $desc
                            )),
                        $( $error ) |+ $( if $guard )?
                    ),
                    "case: {}",
                    $desc,
                );
            };
        }

    /*
     * The following test ensures:
     *
     * The subnet_id is valid for the given validator, i.e. subnet_id in
     * compute_subnets_for_sync_committee(state, sync_committee_message.validator_index).
     */
    let id: u64 = subnet_id.into();
    let invalid_subnet_id = SyncSubnetId::new(id + 1);
    assert_invalid!(
        "invalid subnet id",
        {
            valid_sync_committee_message.clone()
        },
        invalid_subnet_id,
        SyncCommitteeError::InvalidSubnetId {
            received,
            expected,
        }
        if received == invalid_subnet_id && expected.contains(&subnet_id)
    );

    /*
     * The following two tests ensure:
     *
     * This signature is within a MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance from the current slot.
     */

    let future_slot = current_slot + 1;
    assert_invalid!(
        "sync message from future slot",
        {
            let mut signature = valid_sync_committee_message.clone();
            signature.slot = future_slot;
            signature
        },
        subnet_id,
        SyncCommitteeError::FutureSlot {
            message_slot,
            latest_permissible_slot,
        }
        if message_slot == future_slot && latest_permissible_slot == current_slot
    );

    // Subtract an additional slot since the harness will be exactly on the start of the
    // slot and the propagation tolerance will allow an extra slot.
    let early_slot = current_slot
        .as_u64()
        .checked_sub(2)
        .expect("chain is not sufficiently deep for test")
        .into();
    assert_invalid!(
        "sync message from past slot",
        {
            let mut signature = valid_sync_committee_message.clone();
            signature.slot = early_slot;
            signature
        },
        subnet_id,
        SyncCommitteeError::PastSlot {
            message_slot,

            earliest_permissible_slot,
        }
        if message_slot == early_slot && earliest_permissible_slot == current_slot - 1
    );

    /*
     * The following test ensures that:
     *
     * The signature is valid for the message beacon_block_root for the validator referenced by
     * validator_index.
     */
    assert_invalid!(
        "sync message with bad signature",
        {
            let mut sync_message = valid_sync_committee_message.clone();

            sync_message.signature = validator_sk.sign(Hash256::from_low_u64_le(424242));

            sync_message
        },
        subnet_id,
        SyncCommitteeError::InvalidSignature
    );

    harness
        .chain
        .verify_sync_committee_message_for_gossip(valid_sync_committee_message.clone(), subnet_id)
        .expect("valid sync message should be verified");

    /*
     * The following test ensures that:
     *
     * There has been no other valid sync committee message for the declared slot for the
     * validator referenced by sync_committee_message.validator_index.
     */
    assert_invalid!(
        "sync message that has already been seen",
        valid_sync_committee_message,
        subnet_id,
        SyncCommitteeError::PriorSyncCommitteeMessageKnown {
            validator_index,
            slot,
        }
        if validator_index == expected_validator_index as u64 && slot == current_slot
    );

    /*
     * The following test ensures that:
     *
     * A sync committee message for the slot before the sync committee period boundary is verified
     * using the `head_state.next_sync_committee`.
     */

    // Advance to the slot before the 3rd sync committee period because `current_sync_committee = next_sync_committee`
    // at genesis.
    let state = harness.get_current_state();
    let target_slot = Slot::new(
        (2 * harness.spec.epochs_per_sync_committee_period.as_u64() * E::slots_per_epoch()) - 1,
    );

    harness
        .add_attested_block_at_slot(target_slot, state, Hash256::zero(), &[])
        .expect("should add block");

    // **Incorrectly** create a sync message using the current sync committee
    let (next_valid_sync_committee_message, _, _, next_subnet_id) =
        get_valid_sync_committee_message(&harness, target_slot, RelativeSyncCommittee::Current);

    assert_invalid!(
        "sync message on incorrect subnet",
        next_valid_sync_committee_message.clone(),
        next_subnet_id,
        SyncCommitteeError::InvalidSubnetId {
            received,
            expected,
        }
        if received == subnet_id && !expected.contains(&subnet_id)
    );
}
