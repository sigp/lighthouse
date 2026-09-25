use bls::{AggregatePublicKey, Keypair};
use decentralized_checkpoint_sync::{
    LightClientStore, LightClientStoreSchema, initialize_light_client_store,
};
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
pub struct FixtureFor<E: EthSpec> {
    pub spec: ChainSpec,
    pub genesis_validators_root: Hash256,
    pub clock: ManualSlotClock,
    pub trusted_root: Hash256,
    pub bootstrap: LightClientBootstrap<E>,
    pub update: LightClientUpdate<E>,
    pub finality: LightClientFinalityUpdate<E>,
}

impl<E: EthSpec> FixtureFor<E> {
    pub fn store(&self) -> LightClientStore<E> {
        initialize_light_client_store(
            self.trusted_root,
            &self.bootstrap,
            ForkName::Altair,
            LightClientStoreSchema::Altair,
            &self.spec,
        )
        .unwrap()
    }

    pub fn update_for_period(&self, period: u64, participants: usize) -> LightClientUpdate<E> {
        let keys = committee_keys::<E>(period);
        let next_committee = committee(&committee_keys::<E>(period + 1));
        let finalized_slot =
            period * E::slots_per_epoch() * self.spec.epochs_per_sync_committee_period.as_u64() + 2;
        LightClientUpdate::Altair(signed_update(
            finalized_slot,
            &self.spec,
            self.genesis_validators_root,
            &keys,
            next_committee,
            participants,
        ))
    }

    pub fn finality_for_period(
        &self,
        period: u64,
        participants: usize,
    ) -> LightClientFinalityUpdate<E> {
        let LightClientUpdate::Altair(update) = self.update_for_period(period, participants) else {
            unreachable!("fixture uses Altair data");
        };
        finality_update(&update)
    }

    pub fn new() -> Self {
        let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
        let genesis_validators_root = Hash256::repeat_byte(42);
        let clock = ManualSlotClock::new(
            Slot::new(0),
            Duration::from_secs(1_000),
            spec.get_slot_duration(),
        );
        clock.set_slot(4);
        let keys = committee_keys::<E>(0);
        let current_committee = committee(&keys);
        let next_committee = committee(&committee_keys::<E>(1));

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

        let update = signed_update(
            2,
            &spec,
            genesis_validators_root,
            &keys,
            next_committee,
            keys.len(),
        );
        let finality = finality_update(&update);
        Self {
            spec,
            genesis_validators_root,
            clock,
            trusted_root,
            bootstrap,
            update: LightClientUpdate::Altair(update),
            finality,
        }
    }
}

fn finality_update<E: EthSpec>(
    update: &LightClientUpdateAltair<E>,
) -> LightClientFinalityUpdate<E> {
    LightClientFinalityUpdate::Altair(LightClientFinalityUpdateAltair {
        attested_header: update.attested_header.clone(),
        finalized_header: update.finalized_header.clone(),
        finality_branch: update.finality_branch.clone(),
        sync_aggregate: update.sync_aggregate.clone(),
        signature_slot: update.signature_slot,
    })
}

fn signed_update<E: EthSpec>(
    finalized_slot: u64,
    spec: &ChainSpec,
    genesis_validators_root: Hash256,
    keys: &[Keypair],
    next_committee: Arc<SyncCommittee<E>>,
    participants: usize,
) -> LightClientUpdateAltair<E> {
    let finalized_header = header(finalized_slot, Hash256::repeat_byte(43));
    // finalized_checkpoint is field 20; its block root is child 1 of the checkpoint.
    let checkpoint = MerkleTree::create(
        &[Hash256::default(), finalized_header.beacon.canonical_root()],
        1,
    );
    let attested_tree = state_tree(&[
        (20, checkpoint.hash()),
        (23, next_committee.tree_hash_root()),
    ]);
    let attested_header = header(finalized_slot + 1, attested_tree.hash());
    let mut finality_branch = vec![Hash256::default()];
    finality_branch.extend(attested_tree.generate_proof(20, 5).unwrap().1);
    let signature_slot = Slot::new(finalized_slot + 2);
    let signature_epoch = Slot::new(signature_slot.as_u64() - 1).epoch(E::slots_per_epoch());
    let domain = spec.get_domain(
        signature_epoch,
        Domain::SyncCommittee,
        &spec.fork_at_epoch(signature_epoch),
        genesis_validators_root,
    );
    let message = attested_header.beacon.signing_root(domain);
    let mut sync_aggregate = SyncAggregate::new();
    assert!(participants <= keys.len());
    for (index, key) in keys.iter().take(participants).enumerate() {
        sync_aggregate.sync_committee_bits.set(index, true).unwrap();
        sync_aggregate
            .sync_committee_signature
            .add_assign(&key.sk.sign(message));
    }
    LightClientUpdateAltair {
        attested_header,
        finalized_header,
        next_sync_committee: next_committee,
        next_sync_committee_branch: attested_tree
            .generate_proof(23, 5)
            .unwrap()
            .1
            .try_into()
            .unwrap(),
        finality_branch: finality_branch.try_into().unwrap(),
        sync_aggregate,
        signature_slot,
    }
}

fn committee_keys<E: EthSpec>(period: u64) -> Vec<Keypair> {
    let start = 100 * period as usize;
    (start..start + E::sync_committee_size())
        .map(generate_deterministic_keypair)
        .collect()
}

fn header<E: EthSpec>(slot: u64, state_root: Hash256) -> LightClientHeaderAltair<E> {
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

fn committee<E: EthSpec>(keys: &[Keypair]) -> Arc<SyncCommittee<E>> {
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
