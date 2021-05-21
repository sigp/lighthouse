#![cfg(not(debug_assertions))]

#[macro_use]
extern crate lazy_static;

use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
};
use beacon_chain::{
    sync_committee_verification::Error as SyncCommitteeError, BeaconChain, BeaconChainTypes,
};
use bls::generics::GenericSignature;
use bls::impls::fake_crypto::Signature;
use int_to_bytes::int_to_bytes32;
use safe_arith::SafeArith;
use state_processing::{
    per_block_processing::errors::AttestationValidationError, per_slot_processing,
};
use store::config::StoreConfig;
use store::{SignedContributionAndProof, SyncCommitteeContribution, SyncCommitteeSignature};
use tree_hash::TreeHash;
use types::consts::altair::SYNC_COMMITTEE_SUBNET_COUNT;
use types::{
    test_utils::generate_deterministic_keypair, AggregateSignature, Attestation, BeaconStateError,
    BitList, EthSpec, Hash256, Keypair, MainnetEthSpec, SecretKey, SignedAggregateAndProof, Slot,
    SubnetId, SyncSelectionProof, SyncSubnetId, Unsigned,
};

pub type E = MainnetEthSpec;

//FIXME(sean): is this unnecessarily high?
pub const VALIDATOR_COUNT: usize = 256;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
}

/// Returns a beacon chain harness.
fn get_harness(validator_count: usize) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let mut spec = E::default_spec();
    spec.altair_fork_slot = Some(Slot::new(0));
    let harness = BeaconChainHarness::new(
        MainnetEthSpec,
        Some(spec),
        KEYPAIRS[0..validator_count].to_vec(),
    );

    harness.advance_slot();

    harness
}

/// Returns a sync signature that is valid for some slot in the given `chain`.
///
/// Also returns some info about who created it.
fn get_valid_sync_signature(
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    slot: Slot,
) -> (
    SyncCommitteeSignature,
    usize,
    usize,
    SecretKey,
    SyncSubnetId,
) {
    let head_state = harness
        .chain
        .head_beacon_state()
        .expect("should get head state");
    let head_block_root = harness
        .chain
        .head()
        .expect("should get head state")
        .beacon_block_root;
    let (signature, subcommittee_position) = harness
        .make_sync_signatures(&head_state, head_block_root, slot)
        .get(0)
        .unwrap()
        .get(0)
        .unwrap()
        .clone();

    (
        signature.clone(),
        signature.validator_index as usize,
        subcommittee_position,
        harness.validator_keypairs[signature.validator_index as usize]
            .sk
            .clone(),
        SyncSubnetId::new(0),
    )
}

fn get_valid_sync_contribution(
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    slot: Slot,
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
    let sync_contributions = harness.make_sync_contributions(&head_state, head_block_root, slot);

    let (_, contribution_opt) = sync_contributions.get(0).unwrap();
    let contribution = contribution_opt.as_ref().cloned().unwrap();

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
        .unwrap();
    let sync_committee = state.as_altair().unwrap().current_sync_committee.clone();
    let non_aggregator_index = sync_committee
        .pubkeys
        .chunks(sync_subcommittee_size)
        .enumerate()
        .find_map(|(subcommittee_index, subcommittee)| {
            subcommittee.iter().find_map(|pubkey| {
                let validator_index = harness.chain.validator_index(&pubkey).unwrap().unwrap();

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

/// Tests verification of `SignedAggregateAndProof` from the gossip network.
#[test]
fn aggregated_gossip_verification() {
    let harness = get_harness(VALIDATOR_COUNT);

    //FIXME(sean): could maybe reduce.

    // Extend the chain out a few epochs so we have some chain depth to play with.
    harness.extend_chain(
        MainnetEthSpec::slots_per_epoch() as usize * 3 - 1,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    // Advance into a slot where there have not been blocks or sync signatures produced.
    harness.advance_slot();

    let current_slot = harness.chain.slot().expect("should get slot");

    assert_eq!(
        current_slot % E::slots_per_epoch(),
        0,
        "the test requires a new epoch to avoid already-seen errors"
    );

    let (
        valid_sync_signature,
        _attester_index,
        _attester_committee_index,
        validator_sk,
        _subnet_id,
    ) = get_valid_sync_signature(&harness, current_slot);
    let (valid_aggregate, aggregator_index, aggregator_sk) =
        get_valid_sync_contribution(&harness, current_slot);

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
        SyncCommitteeError::FutureSlot { signature_slot, latest_permissible_slot }
        if signature_slot == future_slot && latest_permissible_slot == current_slot
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
            signature_slot,

            earliest_permissible_slot
        }
        if signature_slot == early_slot
            && earliest_permissible_slot == current_slot - 1
    );

    /*
     * The following test ensures:
     *
     * The block being signed over (contribution.beacon_block_root) has been seen (via both gossip and non-gossip sources).
     */

    let unknown_root = Hash256::from_low_u64_le(424242);
    assert_invalid!(
        "aggregate with unknown head block",
        {
            let mut a = valid_aggregate.clone();
            a.message.contribution.beacon_block_root = unknown_root;
            a
        },
        SyncCommitteeError::UnknownHeadBlock {
            beacon_block_root
        }
        if beacon_block_root == unknown_root
    );

    /*
     * The following test ensures:
     *
     * The attestation has participants.
     * Fixme(sean): this isn't in the spec
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
     * The aggregator signature, signed_aggregate_and_proof.signature, is valid.
     */

    assert_invalid!(
        "aggregate with bad signature",
        {
            let mut a = valid_aggregate.clone();

            a.signature = validator_sk.sign(Hash256::from_low_u64_be(42));

            a
        },
        SyncCommitteeError::InvalidSignature
    );

    /*
     * The following test ensures:
     *
     * The aggregate_and_proof.selection_proof is a valid signature of the aggregate.data.slot by
     * the validator with index aggregate_and_proof.aggregator_index.
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
                let proof: SyncSelectionProof = validator_sk
                    .sign(Hash256::from_slice(&int_to_bytes32(i)))
                    .into();
                if proof.is_aggregator::<E>().unwrap() {
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
     * The signature of aggregate is valid.
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
        SyncCommitteeError::ValidatorIndexTooHigh(index)
        if index == too_high_index as usize
    );

    /*
     * The following test ensures:
     *
     * The aggregator's validator index is in the declared subcommittee of the current sync
     * committee -- i.e. state.validators[contribution_and_proof.aggregator_index].pubkey in
     * get_sync_subcommittee_pubkeys(state, contribution.subcommittee_index).
     */
    // assert_invalid!(
    //     "aggregate with unknown aggregator index",
    //     {
    //         let mut a = valid_aggregate.clone();
    //         a.message.contribution.subcommittee_index += 1;
    //         a
    //     },
    //     // Naively we should think this condition would trigger this error:
    //     //
    //     // AttnError::AggregatorPubkeyUnknown(unknown_validator)
    //     //
    //     // However the following error is triggered first:
    //     SyncCommitteeError::AggregatorNotInCommittee {
    //         aggregator_index
    //     }
    //     if subcommittee_index == non_aggregator_index as u64
    // );

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
                &harness.chain.head_info().unwrap().fork,
                harness.chain.genesis_validators_root,
                &harness.chain.spec,
            )
        },
        SyncCommitteeError::InvalidSelectionProof {
            aggregator_index: index
        }
        if index == non_aggregator_index as u64
    );

    // NOTE: from here on, the tests are stateful, and rely on the valid attestation having been
    // seen. A refactor to give each test case its own state might be nice at some point
    harness
        .chain
        .verify_sync_contribution_for_gossip(valid_aggregate.clone())
        .unwrap();

    /*
     * The following test ensures:
     *
     * Spec v0.12.1
     *
     * The valid aggregate attestation defined by hash_tree_root(aggregate) has not already been
     * seen (via aggregate gossip, within a block, or through the creation of an equivalent
     * aggregate locally).
     */

    assert_invalid!(
        "aggregate that has already been seen",
        valid_aggregate.clone(),
        SyncCommitteeError::AttestationAlreadyKnown(hash)
        if hash == valid_aggregate.message.contribution.tree_hash_root()
    );

    /*
     * The following test ensures:
     *
     * Spec v0.12.1
     *
     * The aggregate is the first valid aggregate received for the aggregator with index
     * aggregate_and_proof.aggregator_index for the epoch aggregate.data.target.epoch.
     */

    assert_invalid!(
        "aggregate from aggregator that has already been seen",
        {
            let mut a = valid_aggregate.clone();
            a.message.contribution.beacon_block_root = Hash256::from_low_u64_le(42);
            a
        },
        SyncCommitteeError::AggregatorAlreadyKnown(index)
        if index == aggregator_index as u64
    );
}

/// Tests the verification conditions for an unaggregated attestation on the gossip network.
#[test]
fn unaggregated_gossip_verification() {
    let harness = get_harness(VALIDATOR_COUNT);

    // Extend the chain out a few epochs so we have some chain depth to play with.
    harness.extend_chain(
        MainnetEthSpec::slots_per_epoch() as usize * 3 - 1,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    // Advance into a slot where there have not been blocks or attestations produced.
    harness.advance_slot();

    let current_slot = harness.chain.slot().expect("should get slot");
    let current_epoch = harness.chain.epoch().expect("should get epoch");

    assert_eq!(
        current_slot % E::slots_per_epoch(),
        0,
        "the test requires a new epoch to avoid already-seen errors"
    );

    let (
        valid_sync_signature,
        expected_validator_index,
        validator_subcommittee_position,
        validator_sk,
        subnet_id,
    ) = get_valid_sync_signature(&harness, current_slot);

    macro_rules! assert_invalid {
        ($desc: tt, $attn_getter: expr, $subnet_getter: expr, $($error: pat) |+ $( if $guard: expr )?) => {
            assert!(
                matches!(
                    harness
                        .chain
                        .verify_sync_signature_for_gossip($attn_getter, Some($subnet_getter))
                        .err()
                        .expect(&format!(
                            "{} should error during verify_sync_signature_for_gossip",
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
     * The subnet_id is valid for the given validator, i.e. subnet_id in compute_subnets_for_sync_committee(state, sync_committee_signature.validator_index).
     */
    let id: u64 = subnet_id.into();
    let invalid_subnet_id = SyncSubnetId::new(id + 1);
    assert_invalid!(
        "invalid subnet id",
        {
            valid_sync_signature.clone()
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
        "sync signature from future slot",
        {
            let mut signature = valid_sync_signature.clone();
            signature.slot = future_slot;
            signature
        },
        subnet_id,
        SyncCommitteeError::FutureSlot {
            signature_slot,
            latest_permissible_slot,
        }
        if signature_slot == future_slot && latest_permissible_slot == current_slot
    );

    // Subtract an additional slot since the harness will be exactly on the start of the
    // slot and the propagation tolerance will allow an extra slot.
    let early_slot = current_slot
        .as_u64()
        .checked_sub(2)
        .expect("chain is not sufficiently deep for test")
        .into();
    assert_invalid!(
        "attestation from past slot",
        {
            let mut signature = valid_sync_signature.clone();
            signature.slot = early_slot;
            signature
        },
        subnet_id,
        SyncCommitteeError::PastSlot {
            signature_slot,

            earliest_permissible_slot,
        }
        if signature_slot == early_slot && earliest_permissible_slot == current_slot - 1
    );

    /*
     * The following test ensures that:
     *
     * The block being signed over (sync_committee_signature.beacon_block_root) has been seen (via both gossip and non-gossip sources).
     */

    let unknown_root = Hash256::from_low_u64_le(424242); // No one wants one of these
    assert_invalid!(
        "attestation with unknown head block",
        {
            let mut signature = valid_sync_signature.clone();
            signature.beacon_block_root = unknown_root;
            signature
        },
        subnet_id,
        SyncCommitteeError::UnknownHeadBlock {
            beacon_block_root,
        }
        if beacon_block_root == unknown_root
    );

    /*
     * The following test ensures that:
     *
     * The signature is valid for the message beacon_block_root for the validator referenced by validator_index.
     */
    assert_invalid!(
        "attestation with bad signature",
        {
            let mut sync_signature = valid_sync_signature.clone();

            sync_signature.signature = validator_sk.sign(Hash256::from_low_u64_le(424242));

            sync_signature
        },
        subnet_id,
        SyncCommitteeError::InvalidSignature
    );

    harness
        .chain
        .verify_sync_signature_for_gossip(valid_sync_signature.clone(), Some(subnet_id))
        .expect("valid attestation should be verified");

    /*
     * The following test ensures that:
     *
     * There has been no other valid sync committee signature for the declared slot for the validator referenced by sync_committee_signature.validator_index.
     */
    assert_invalid!(
        "attestation that has already been seen",
        valid_sync_signature.clone(),
        subnet_id,
        SyncCommitteeError::PriorSyncSignatureKnown {
            validator_index,
            slot,
        }
        if validator_index == expected_validator_index as u64 && slot == current_slot
    );
}
//
// /// Ensures that an attestation that skips epochs can still be processed.
// ///
// /// This also checks that we can do a state lookup if we don't get a hit from the shuffling cache.
// #[test]
// fn attestation_that_skips_epochs() {
//     let harness = get_harness(VALIDATOR_COUNT);
//
//     // Extend the chain out a few epochs so we have some chain depth to play with.
//     harness.extend_chain(
//         MainnetEthSpec::slots_per_epoch() as usize * 3 + 1,
//         BlockStrategy::OnCanonicalHead,
//         AttestationStrategy::SomeValidators(vec![]),
//     );
//
//     let current_slot = harness.chain.slot().expect("should get slot");
//     let current_epoch = harness.chain.epoch().expect("should get epoch");
//
//     let earlier_slot = (current_epoch - 2).start_slot(MainnetEthSpec::slots_per_epoch());
//     let earlier_block = harness
//         .chain
//         .block_at_slot(earlier_slot)
//         .expect("should not error getting block at slot")
//         .expect("should find block at slot");
//
//     let mut state = harness
//         .chain
//         .get_state(&earlier_block.state_root(), Some(earlier_slot))
//         .expect("should not error getting state")
//         .expect("should find state");
//
//     while state.slot() < current_slot {
//         per_slot_processing(&mut state, None, &harness.spec).expect("should process slot");
//     }
//
//     let state_root = state.update_tree_hash_cache().unwrap();
//
//     let (attestation, subnet_id) = harness
//         .get_unaggregated_attestations(
//             &AttestationStrategy::AllValidators,
//             &state,
//             state_root,
//             earlier_block.canonical_root(),
//             current_slot,
//         )
//         .first()
//         .expect("should have at least one committee")
//         .first()
//         .cloned()
//         .expect("should have at least one attestation in committee");
//
//     let block_root = attestation.data.beacon_block_root;
//     let block_slot = harness
//         .chain
//         .store
//         .get_block(&block_root)
//         .expect("should not error getting block")
//         .expect("should find attestation block")
//         .message()
//         .slot();
//
//     assert!(
//         attestation.data.slot - block_slot > E::slots_per_epoch() * 2,
//         "the attestation must skip more than two epochs"
//     );
//
//     harness
//         .chain
//         .verify_unaggregated_attestation_for_gossip(attestation, Some(subnet_id))
//         .expect("should gossip verify attestation that skips slots");
// }
