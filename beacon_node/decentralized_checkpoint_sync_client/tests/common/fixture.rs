use super::E;
use bls::{AggregatePublicKey, Keypair};
use merkle_proof::MerkleTree;
use slot_clock::{ManualSlotClock, SlotClock};
use std::{sync::Arc, time::Duration};
use tree_hash::TreeHash;
use types::{
    BeaconBlockHeader, ChainSpec, Domain, EthSpec, ForkName, Hash256, LightClientBootstrap,
    LightClientBootstrapAltair, LightClientFinalityUpdate, LightClientFinalityUpdateAltair,
    LightClientHeaderAltair, LightClientUpdate, LightClientUpdateAltair, SignedRoot, Slot,
    SyncAggregate, SyncCommittee, test_utils::generate_deterministic_keypair,
};

/// Synthetic state commitments with real Merkle proofs and BLS signatures, not a second verifier.
/// Fixtures enter the production core only through its public verification API.
pub struct Fixture {
    pub spec: ChainSpec,
    pub genesis_validators_root: Hash256,
    pub clock: ManualSlotClock,
    pub trusted_root: Hash256,
    pub bootstrap: LightClientBootstrap<E>,
    pub update: LightClientUpdate<E>,
    pub finality: LightClientFinalityUpdate<E>,
}

impl Fixture {
    pub fn new() -> Self {
        let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
        let genesis_validators_root = Hash256::repeat_byte(42);
        let clock = ManualSlotClock::new(
            Slot::new(0),
            Duration::from_secs(1_000),
            spec.get_slot_duration(),
        );
        clock.set_slot(4);
        let keys: Vec<_> = (0..E::sync_committee_size())
            .map(generate_deterministic_keypair)
            .collect();
        let current_committee = committee(&keys);
        let next_keys: Vec<_> = (100..100 + E::sync_committee_size())
            .map(generate_deterministic_keypair)
            .collect();
        let next_committee = committee(&next_keys);

        // BeaconState current_sync_committee is field 22 in the Altair container (depth 5).
        let bootstrap_tree = state_tree(&[(22, current_committee.tree_hash_root())]);
        let bootstrap_header = header(1, bootstrap_tree.hash());
        let trusted_root = bootstrap_header.beacon.canonical_root();
        let bootstrap = LightClientBootstrap::Altair(LightClientBootstrapAltair {
            header: bootstrap_header,
            current_sync_committee: current_committee,
            current_sync_committee_branch: bootstrap_tree
                .generate_proof(22, 5)
                .unwrap()
                .1
                .try_into()
                .unwrap(),
        });

        let finalized_header = header(2, Hash256::repeat_byte(43));
        // finalized_checkpoint is field 20; its block root is child 1 of the checkpoint.
        let checkpoint = MerkleTree::create(
            &[Hash256::default(), finalized_header.beacon.canonical_root()],
            1,
        );
        let attested_tree = state_tree(&[
            (20, checkpoint.hash()),
            (23, next_committee.tree_hash_root()),
        ]);
        let attested_header = header(3, attested_tree.hash());
        let mut finality_branch = vec![Hash256::default()];
        finality_branch.extend(attested_tree.generate_proof(20, 5).unwrap().1);
        let signature_slot = Slot::new(4);
        let signature_epoch = Slot::new(3).epoch(E::slots_per_epoch());
        let domain = spec.get_domain(
            signature_epoch,
            Domain::SyncCommittee,
            &spec.fork_at_epoch(signature_epoch),
            genesis_validators_root,
        );
        let message = attested_header.beacon.signing_root(domain);
        let mut sync_aggregate = SyncAggregate::new();
        for (index, key) in keys.iter().enumerate() {
            sync_aggregate.sync_committee_bits.set(index, true).unwrap();
            sync_aggregate
                .sync_committee_signature
                .add_assign(&key.sk.sign(message));
        }
        let update = LightClientUpdate::Altair(LightClientUpdateAltair {
            attested_header: attested_header.clone(),
            finalized_header: finalized_header.clone(),
            next_sync_committee: next_committee,
            next_sync_committee_branch: attested_tree
                .generate_proof(23, 5)
                .unwrap()
                .1
                .try_into()
                .unwrap(),
            finality_branch: finality_branch.clone().try_into().unwrap(),
            sync_aggregate: sync_aggregate.clone(),
            signature_slot,
        });
        let finality = LightClientFinalityUpdate::Altair(LightClientFinalityUpdateAltair {
            attested_header,
            finalized_header,
            finality_branch: finality_branch.try_into().unwrap(),
            sync_aggregate,
            signature_slot,
        });
        Self {
            spec,
            genesis_validators_root,
            clock,
            trusted_root,
            bootstrap,
            update,
            finality,
        }
    }
}

fn header(slot: u64, state_root: Hash256) -> LightClientHeaderAltair<E> {
    LightClientHeaderAltair {
        beacon: BeaconBlockHeader {
            slot: Slot::new(slot),
            state_root,
            parent_root: Hash256::repeat_byte(44),
            ..BeaconBlockHeader::empty()
        },
        ..Default::default()
    }
}

fn committee(keys: &[Keypair]) -> Arc<SyncCommittee<E>> {
    let pubkeys: Vec<_> = keys.iter().map(|key| key.pk.clone()).collect();
    Arc::new(SyncCommittee {
        pubkeys: pubkeys
            .iter()
            .map(|key| key.compress())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        aggregate_pubkey: AggregatePublicKey::aggregate(&pubkeys)
            .unwrap()
            .to_public_key()
            .compress(),
    })
}

fn state_tree(fields: &[(usize, Hash256)]) -> MerkleTree {
    let mut leaves = vec![Hash256::default(); 32];
    for &(index, value) in fields {
        leaves[index] = value;
    }
    MerkleTree::create(&leaves, 5)
}
