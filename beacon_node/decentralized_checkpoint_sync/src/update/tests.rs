use super::*;
use crate::initialize_light_client_store;
use bls::{AggregatePublicKey, AggregateSignature, Keypair, PublicKeyBytes};
use merkle_proof::MerkleTree;
use std::sync::Arc;
use tree_hash::TreeHash;
use types::{
    BeaconBlockHeader, Domain, Epoch, ExecutionBlockHash, ExecutionPayloadHeaderCapella,
    LightClientBootstrap, LightClientBootstrapAltair, LightClientBootstrapCapella,
    LightClientBootstrapDeneb, LightClientBootstrapElectra, LightClientBootstrapFulu,
    LightClientHeaderAltair, LightClientHeaderCapella, LightClientHeaderDeneb,
    LightClientHeaderElectra, LightClientHeaderFulu, LightClientUpdateAltair,
    LightClientUpdateCapella, LightClientUpdateDeneb, LightClientUpdateElectra,
    LightClientUpdateFulu, MinimalEthSpec, SignedRoot, SyncAggregate, SyncCommittee,
    test_utils::generate_deterministic_keypair,
};

type E = MinimalEthSpec;

const FORKS: [ForkName; 6] = [
    ForkName::Altair,
    ForkName::Bellatrix,
    ForkName::Capella,
    ForkName::Deneb,
    ForkName::Electra,
    ForkName::Fulu,
];

macro_rules! with_update {
    ($update:expr, $inner:ident, $body:expr) => {
        match $update {
            LightClientUpdate::Altair($inner) => $body,
            LightClientUpdate::Capella($inner) => $body,
            LightClientUpdate::Deneb($inner) => $body,
            LightClientUpdate::Electra($inner) => $body,
            LightClientUpdate::Fulu($inner) => $body,
        }
    };
}

fn hash(value: u8) -> Hash256 {
    Hash256::from([value; 32])
}

fn state_tree(depth: usize, fields: &[(usize, Hash256)]) -> MerkleTree {
    let mut leaves: Vec<_> = (0..1usize << depth).map(|i| hash(i as u8)).collect();
    for &(index, root) in fields {
        leaves[index] = root;
    }
    MerkleTree::create(&leaves, depth)
}

fn committee(keys: &[Keypair]) -> Arc<SyncCommittee<E>> {
    let public_keys: Vec<_> = keys.iter().map(|key| key.pk.clone()).collect();
    Arc::new(SyncCommittee {
        pubkeys: public_keys
            .iter()
            .map(|key| key.compress())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        aggregate_pubkey: AggregatePublicKey::aggregate(&public_keys)
            .unwrap()
            .to_public_key()
            .compress(),
    })
}

fn header(
    data_fork: ForkName,
    spec: &ChainSpec,
    slot: Slot,
    state_root: Hash256,
) -> LightClientHeader<E> {
    let beacon_fork = spec.fork_name_at_slot::<E>(slot);
    let beacon = BeaconBlockHeader {
        slot,
        state_root,
        parent_root: hash(70),
        ..BeaconBlockHeader::empty()
    };
    macro_rules! post_capella {
        ($header:ident, $variant:ident) => {{
            let mut header = $header::<E> {
                beacon,
                ..Default::default()
            };
            if beacon_fork.capella_enabled() {
                header.execution.block_hash = ExecutionBlockHash(hash(80));
                let execution_root = if beacon_fork.deneb_enabled() {
                    header.execution.tree_hash_root()
                } else {
                    ExecutionPayloadHeaderCapella::<E> {
                        block_hash: ExecutionBlockHash(hash(80)),
                        ..Default::default()
                    }
                    .tree_hash_root()
                };
                let tree = state_tree(4, &[(9, execution_root)]);
                header.beacon.body_root = tree.hash();
                header.execution_branch = tree.generate_proof(9, 4).unwrap().1.try_into().unwrap();
            }
            LightClientHeader::$variant(header)
        }};
    }
    match data_fork {
        ForkName::Altair | ForkName::Bellatrix => {
            LightClientHeader::Altair(LightClientHeaderAltair {
                beacon,
                ..Default::default()
            })
        }
        ForkName::Capella => post_capella!(LightClientHeaderCapella, Capella),
        ForkName::Deneb => post_capella!(LightClientHeaderDeneb, Deneb),
        ForkName::Electra => post_capella!(LightClientHeaderElectra, Electra),
        ForkName::Fulu => post_capella!(LightClientHeaderFulu, Fulu),
        _ => unreachable!("supported test fork"),
    }
}

fn store(
    data_fork: ForkName,
    spec: &ChainSpec,
    slot: Slot,
    committee: Arc<SyncCommittee<E>>,
) -> LightClientStore<E> {
    let beacon_fork = spec.fork_name_at_slot::<E>(slot);
    let depth = if beacon_fork.electra_enabled() { 6 } else { 5 };
    // BeaconState field 22 is current_sync_committee. These indices intentionally do not use
    // production constants, so incorrect generalized indices cannot make both sides agree.
    let tree = state_tree(depth, &[(22, committee.tree_hash_root())]);
    let mut branch = tree.generate_proof(22, depth).unwrap().1;
    if data_fork.electra_enabled() && !beacon_fork.electra_enabled() {
        branch.insert(0, Hash256::default());
    }
    let header = header(data_fork, spec, slot, tree.hash());
    let root = beacon_header(&header).canonical_root();
    macro_rules! bootstrap {
        ($inner:expr, $bootstrap:ident, $variant:ident) => {
            LightClientBootstrap::$variant($bootstrap {
                header: $inner,
                current_sync_committee: committee,
                current_sync_committee_branch: branch.try_into().unwrap(),
            })
        };
    }
    let bootstrap = match header {
        LightClientHeader::Altair(inner) => bootstrap!(inner, LightClientBootstrapAltair, Altair),
        LightClientHeader::Capella(inner) => {
            bootstrap!(inner, LightClientBootstrapCapella, Capella)
        }
        LightClientHeader::Deneb(inner) => bootstrap!(inner, LightClientBootstrapDeneb, Deneb),
        LightClientHeader::Electra(inner) => {
            bootstrap!(inner, LightClientBootstrapElectra, Electra)
        }
        LightClientHeader::Fulu(inner) => bootstrap!(inner, LightClientBootstrapFulu, Fulu),
    };
    initialize_light_client_store(
        root,
        &bootstrap,
        data_fork,
        LightClientStoreSchema::try_from(data_fork).unwrap(),
        spec,
    )
    .unwrap()
}

struct Fixture {
    store: LightClientStore<E>,
    update: LightClientUpdate<E>,
    data_fork: ForkName,
    spec: ChainSpec,
    genesis_root: Hash256,
    current_slot: Slot,
    current_keys: Vec<Keypair>,
    next_keys: Vec<Keypair>,
}

impl Fixture {
    fn new(fork: ForkName) -> Self {
        Self::at_slots(fork, fork.make_genesis_spec(E::default_spec()), 1, 2, 3, 4)
    }

    fn at_slots(
        data_fork: ForkName,
        spec: ChainSpec,
        store_slot: u64,
        finalized_slot: u64,
        attested_slot: u64,
        signature_slot: u64,
    ) -> Self {
        let current_keys: Vec<_> = (0..E::sync_committee_size())
            .map(generate_deterministic_keypair)
            .collect();
        let next_keys: Vec<_> = (100..100 + E::sync_committee_size())
            .map(generate_deterministic_keypair)
            .collect();
        let store = store(
            data_fork,
            &spec,
            Slot::new(store_slot),
            committee(&current_keys),
        );
        let attested = header(
            data_fork,
            &spec,
            Slot::new(attested_slot),
            Hash256::default(),
        );
        let finalized = header(data_fork, &spec, Slot::new(finalized_slot), hash(91));
        macro_rules! update {
            ($attested:expr, $finalized:expr, $update:ident, $variant:ident) => {
                LightClientUpdate::$variant($update {
                    attested_header: $attested,
                    finalized_header: $finalized,
                    next_sync_committee: committee(&next_keys),
                    next_sync_committee_branch: Default::default(),
                    finality_branch: Default::default(),
                    sync_aggregate: SyncAggregate::new(),
                    signature_slot: Slot::new(signature_slot),
                })
            };
        }
        let update = match (attested, finalized) {
            (LightClientHeader::Altair(a), LightClientHeader::Altair(f)) => {
                update!(a, f, LightClientUpdateAltair, Altair)
            }
            (LightClientHeader::Capella(a), LightClientHeader::Capella(f)) => {
                update!(a, f, LightClientUpdateCapella, Capella)
            }
            (LightClientHeader::Deneb(a), LightClientHeader::Deneb(f)) => {
                update!(a, f, LightClientUpdateDeneb, Deneb)
            }
            (LightClientHeader::Electra(a), LightClientHeader::Electra(f)) => {
                update!(a, f, LightClientUpdateElectra, Electra)
            }
            (LightClientHeader::Fulu(a), LightClientHeader::Fulu(f)) => {
                update!(a, f, LightClientUpdateFulu, Fulu)
            }
            _ => unreachable!("matching fixture variants"),
        };
        let mut fixture = Self {
            store,
            update,
            data_fork,
            spec,
            genesis_root: hash(92),
            current_slot: Slot::new(signature_slot),
            current_keys,
            next_keys,
        };
        fixture.refresh_proofs(true, true);
        fixture.sign_all(false);
        fixture
    }

    fn refresh_proofs(&mut self, finality: bool, next_committee: bool) {
        with_update!(&mut self.update, inner, {
            let slot_fork = self
                .spec
                .fork_name_at_slot::<E>(inner.attested_header.beacon.slot);
            let depth = if slot_fork.electra_enabled() { 6 } else { 5 };
            let finalized_root = if inner.finalized_header.beacon.slot == Slot::new(0) {
                Hash256::default()
            } else {
                inner.finalized_header.beacon.canonical_root()
            };
            // Finalized checkpoint is BeaconState field 20, with its root in child 1.
            let checkpoint = MerkleTree::create(&[hash(93), finalized_root], 1);
            let tree = state_tree(
                depth,
                &[
                    (20, checkpoint.hash()),
                    (23, inner.next_sync_committee.tree_hash_root()),
                ],
            );
            let mut finality_branch = vec![hash(93)];
            finality_branch.extend(tree.generate_proof(20, depth).unwrap().1);
            let mut next_branch = tree.generate_proof(23, depth).unwrap().1;
            if self.data_fork.electra_enabled() && !slot_fork.electra_enabled() {
                finality_branch.insert(0, Hash256::default());
                next_branch.insert(0, Hash256::default());
            }
            inner.attested_header.beacon.state_root = tree.hash();
            inner.finality_branch = if finality {
                finality_branch.try_into().unwrap()
            } else {
                Default::default()
            };
            inner.next_sync_committee_branch = if next_committee {
                next_branch.try_into().unwrap()
            } else {
                Default::default()
            };
        });
    }

    fn sign_all(&mut self, next: bool) {
        let indices: Vec<_> = (0..E::sync_committee_size()).collect();
        self.sign_indices(&indices, next);
    }

    fn sign_indices(&mut self, indices: &[usize], next: bool) {
        let domain_slot = *self.update.signature_slot() - 1;
        let epoch = domain_slot.epoch(E::slots_per_epoch());
        let domain = self.spec.get_domain(
            epoch,
            Domain::SyncCommittee,
            &self.spec.fork_at_epoch(epoch),
            self.genesis_root,
        );
        self.sign_with_domain(indices, next, domain);
    }

    fn sign_with_domain(&mut self, indices: &[usize], next: bool, domain: Hash256) {
        let keys = if next {
            &self.next_keys
        } else {
            &self.current_keys
        };
        with_update!(&mut self.update, inner, {
            let message = inner.attested_header.beacon.signing_root(domain);
            let mut aggregate = SyncAggregate::new();
            for &index in indices {
                aggregate.sync_committee_bits.set(index, true).unwrap();
                aggregate
                    .sync_committee_signature
                    .add_assign(&keys[index].sk.sign(message));
            }
            inner.sync_aggregate = aggregate;
        });
    }

    fn learn_next_committee(&mut self) {
        self.store
            .set_next_sync_committee_for_test(committee(&self.next_keys));
    }

    fn assert_result(&mut self, expected: Result<(), LightClientSyncError>) {
        // Include all store fields, not only the checkpoint, to detect partial mutation.
        let before = format!("{:?}", self.store);
        let result = validate_light_client_update(
            &mut self.store,
            &self.update,
            self.data_fork,
            self.current_slot,
            self.genesis_root,
            &self.spec,
        )
        .map(|validated| {
            assert!(std::ptr::eq(validated.update(), &self.update));
            assert!(std::ptr::eq(validated.chain_spec(), &self.spec));
            assert_eq!(validated.data_fork(), self.data_fork);
            assert_eq!(format!("{:?}", validated.store()), before);
        });
        assert_eq!(result, expected, "data fork {:?}", self.data_fork);
        assert_eq!(format!("{:?}", self.store), before);
    }

    fn valid(&mut self) {
        self.assert_result(Ok(()));
    }

    fn invalid(&mut self, error: LightClientSyncError) {
        self.assert_result(Err(error));
    }
}

#[test]
fn validates_real_aggregate_signatures_for_each_supported_fork_without_mutation() {
    for fork in FORKS {
        Fixture::new(fork).valid();
    }
}

#[test]
fn accepts_sparse_participants_and_configured_minimum() {
    for indices in [vec![0], vec![0, 7, 31]] {
        let mut fixture = Fixture::new(ForkName::Altair);
        fixture.sign_indices(&indices, false);
        fixture.spec.min_sync_committee_participants = indices.len() as u64;
        fixture.valid();
        fixture.spec.min_sync_committee_participants += 1;
        fixture.invalid(LightClientSyncError::InsufficientParticipants {
            actual: indices.len(),
            minimum: indices.len() as u64 + 1,
        });
    }
}

#[test]
fn rejects_zero_participants() {
    let mut fixture = Fixture::new(ForkName::Altair);
    fixture.sign_indices(&[], false);
    fixture.invalid(LightClientSyncError::InsufficientParticipants {
        actual: 0,
        minimum: 1,
    });
}

#[test]
fn enforces_each_slot_ordering() {
    for (current, signature, attested, finalized) in
        [(3, 4, 3, 2), (4, 3, 3, 2), (4, 2, 3, 2), (4, 4, 2, 3)]
    {
        let mut fixture = Fixture::new(ForkName::Altair);
        fixture.current_slot = Slot::new(current);
        with_update!(&mut fixture.update, inner, {
            inner.signature_slot = Slot::new(signature);
            inner.attested_header.beacon.slot = Slot::new(attested);
            inner.finalized_header.beacon.slot = Slot::new(finalized);
        });
        fixture.invalid(LightClientSyncError::InvalidUpdateSlots {
            current_slot: Slot::new(current),
            signature_slot: Slot::new(signature),
            attested_slot: Slot::new(attested),
            finalized_slot: Slot::new(finalized),
        });
    }
    let mut fixture = Fixture::at_slots(
        ForkName::Altair,
        ForkName::Altair.make_genesis_spec(E::default_spec()),
        1,
        3,
        3,
        4,
    );
    fixture.valid();
}

#[test]
fn restricts_signature_period_and_selects_next_committee() {
    // Minimal preset: 8 slots per epoch * 8 epochs per committee period = 64 slots.
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let mut fixture = Fixture::at_slots(ForkName::Altair, spec, 1, 2, 63, 64);
    fixture.invalid(LightClientSyncError::InvalidSignaturePeriod {
        store_period: 0,
        signature_period: 1,
    });
    fixture.learn_next_committee();
    fixture.invalid(LightClientSyncError::InvalidSyncCommitteeSignature);
    fixture.sign_all(true);
    fixture.valid();
    with_update!(
        &mut fixture.update,
        inner,
        inner.signature_slot = Slot::new(128)
    );
    fixture.current_slot = Slot::new(128);
    fixture.invalid(LightClientSyncError::InvalidSignaturePeriod {
        store_period: 0,
        signature_period: 2,
    });
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let mut older = Fixture::at_slots(ForkName::Altair, spec, 64, 1, 2, 3);
    older.invalid(LightClientSyncError::InvalidSignaturePeriod {
        store_period: 1,
        signature_period: 0,
    });
}

#[test]
fn accepts_next_period_attestation_and_old_finality_signed_by_next_committee() {
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let mut fixture = Fixture::at_slots(ForkName::Altair, spec, 1, 2, 65, 66);
    fixture.learn_next_committee();
    // The attested period's *next* committee need not equal our currently known next committee.
    with_update!(
        &mut fixture.update,
        inner,
        inner.next_sync_committee = committee(&fixture.current_keys)
    );
    fixture.refresh_proofs(true, true);
    fixture.sign_all(true);
    fixture.valid();
}

#[test]
fn stale_attestation_is_relevant_only_when_providing_unknown_next_committee() {
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let mut fixture = Fixture::at_slots(ForkName::Altair, spec, 3, 2, 3, 4);
    fixture.valid();
    fixture.learn_next_committee();
    fixture.invalid(LightClientSyncError::IrrelevantUpdate);
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let mut fixture = Fixture::at_slots(ForkName::Altair, spec, 3, 2, 3, 4);
    with_update!(&mut fixture.update, inner, {
        inner.next_sync_committee = Arc::new(SyncCommittee::temporary());
    });
    fixture.refresh_proofs(true, false);
    fixture.sign_all(false);
    fixture.invalid(LightClientSyncError::IrrelevantUpdate);
}

#[test]
fn absent_branches_require_default_payloads() {
    for fork in FORKS {
        let mut fixture = Fixture::new(fork);
        with_update!(
            &mut fixture.update,
            inner,
            inner.finality_branch = Default::default()
        );
        fixture.invalid(LightClientSyncError::NonDefaultFinalizedHeader);
        with_update!(
            &mut fixture.update,
            inner,
            inner.finalized_header = Default::default()
        );
        fixture.refresh_proofs(false, true);
        fixture.sign_all(false);
        fixture.valid();
        with_update!(
            &mut fixture.update,
            inner,
            inner.next_sync_committee_branch = Default::default()
        );
        fixture.invalid(LightClientSyncError::NonDefaultNextSyncCommittee);
        with_update!(
            &mut fixture.update,
            inner,
            inner.next_sync_committee = Arc::new(SyncCommittee::temporary())
        );
        fixture.refresh_proofs(false, false);
        fixture.sign_all(false);
        fixture.valid();
    }
}

#[test]
fn genesis_finality_proves_zero_root_and_requires_entire_default_header() {
    for fork in FORKS {
        let mut fixture = Fixture::new(fork);
        with_update!(
            &mut fixture.update,
            inner,
            inner.finalized_header = Default::default()
        );
        fixture.refresh_proofs(true, true);
        fixture.sign_all(false);
        fixture.valid();
        with_update!(
            &mut fixture.update,
            inner,
            inner.finalized_header.beacon.parent_root = hash(94)
        );
        fixture.invalid(LightClientSyncError::NonDefaultFinalizedHeader);
    }
    // Mainnet-style Base genesis: slot-zero default is a sentinel, not an unsupported header.
    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(Epoch::new(1));
    let mut fixture = Fixture::at_slots(ForkName::Altair, spec, 8, 9, 10, 11);
    with_update!(
        &mut fixture.update,
        inner,
        inner.finalized_header = Default::default()
    );
    fixture.refresh_proofs(true, true);
    fixture.sign_all(false);
    fixture.valid();
    fixture.refresh_proofs(false, true);
    fixture.sign_all(false);
    fixture.valid();
}

#[test]
fn rejects_corrupt_merkle_proofs_for_each_fork() {
    for fork in FORKS {
        let mut fixture = Fixture::new(fork);
        with_update!(
            &mut fixture.update,
            inner,
            inner.finality_branch[0] = hash(95)
        );
        fixture.invalid(LightClientSyncError::InvalidFinalityProof);
        fixture.refresh_proofs(true, true);
        with_update!(
            &mut fixture.update,
            inner,
            inner.next_sync_committee_branch[0] = hash(95)
        );
        fixture.invalid(LightClientSyncError::InvalidNextSyncCommitteeProof);
    }
}

#[test]
fn normalized_electra_branches_use_attested_slot_and_require_zero_prefixes() {
    for beacon_fork in [ForkName::Altair, ForkName::Capella, ForkName::Deneb] {
        let spec = beacon_fork.make_genesis_spec(E::default_spec());
        let mut fixture = Fixture::at_slots(ForkName::Electra, spec, 1, 2, 3, 4);
        fixture.valid();
        with_update!(
            &mut fixture.update,
            inner,
            inner.finality_branch[0] = hash(96)
        );
        fixture.invalid(LightClientSyncError::InvalidFinalityProof);
        fixture.refresh_proofs(true, true);
        with_update!(
            &mut fixture.update,
            inner,
            inner.next_sync_committee_branch[0] = hash(96)
        );
        fixture.invalid(LightClientSyncError::InvalidNextSyncCommitteeProof);
    }
}

#[test]
fn rejects_mismatched_known_next_committee_even_with_valid_proof() {
    let mut fixture = Fixture::new(ForkName::Electra);
    fixture.learn_next_committee();
    with_update!(
        &mut fixture.update,
        inner,
        inner.next_sync_committee = committee(&fixture.current_keys)
    );
    fixture.refresh_proofs(true, true);
    fixture.sign_all(false);
    fixture.invalid(LightClientSyncError::NextSyncCommitteeMismatch);
}

#[test]
fn rejects_wrong_signature_root_genesis_domain_and_participant_set() {
    for mutation in 0..5 {
        let mut fixture = Fixture::new(ForkName::Altair);
        match mutation {
            0 => with_update!(
                &mut fixture.update,
                inner,
                inner.attested_header.beacon.parent_root = hash(97)
            ),
            1 => fixture.genesis_root = hash(98),
            2 => {
                let domain = fixture.spec.compute_domain(
                    Domain::BeaconProposer,
                    fixture.spec.altair_fork_version,
                    fixture.genesis_root,
                );
                fixture.sign_with_domain(&[0, 1], false, domain);
            }
            3 => with_update!(
                &mut fixture.update,
                inner,
                inner
                    .sync_aggregate
                    .sync_committee_bits
                    .set(0, false)
                    .unwrap()
            ),
            4 => with_update!(
                &mut fixture.update,
                inner,
                inner.sync_aggregate.sync_committee_signature = AggregateSignature::infinity()
            ),
            _ => unreachable!(),
        }
        fixture.invalid(LightClientSyncError::InvalidSyncCommitteeSignature);
    }
}

#[test]
fn signature_domain_uses_slot_before_signature_at_fork_boundary() {
    let mut spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    spec.bellatrix_fork_epoch = Some(Epoch::new(1));
    let mut fixture = Fixture::at_slots(ForkName::Altair, spec, 1, 2, 7, 8);
    fixture.valid();
    let wrong_domain = fixture.spec.compute_domain(
        Domain::SyncCommittee,
        fixture.spec.bellatrix_fork_version,
        fixture.genesis_root,
    );
    fixture.sign_with_domain(&[0, 1], false, wrong_domain);
    fixture.invalid(LightClientSyncError::InvalidSyncCommitteeSignature);

    let mut spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    spec.bellatrix_fork_epoch = Some(Epoch::new(1));
    let mut fixture = Fixture::at_slots(ForkName::Altair, spec, 1, 2, 7, 9);
    fixture.valid();
    let wrong_domain = fixture.spec.compute_domain(
        Domain::SyncCommittee,
        fixture.spec.altair_fork_version,
        fixture.genesis_root,
    );
    fixture.sign_with_domain(&[0, 1], false, wrong_domain);
    fixture.invalid(LightClientSyncError::InvalidSyncCommitteeSignature);
}

#[test]
fn only_selected_public_keys_are_decompressed_and_verified() {
    let mut fixture = Fixture::new(ForkName::Altair);
    let mut malformed = committee(&fixture.current_keys).as_ref().clone();
    malformed.pubkeys[0] = PublicKeyBytes::empty();
    fixture.store = store(
        fixture.data_fork,
        &fixture.spec,
        Slot::new(1),
        Arc::new(malformed),
    );
    fixture.invalid(LightClientSyncError::InvalidSyncCommitteePublicKey { index: 0 });
    fixture.sign_indices(&[1, 7, 31], false);
    fixture.valid();
    let mut wrong = committee(&fixture.current_keys).as_ref().clone();
    wrong.pubkeys[1] = generate_deterministic_keypair(200).pk.compress();
    fixture.store = store(
        fixture.data_fork,
        &fixture.spec,
        Slot::new(1),
        Arc::new(wrong),
    );
    fixture.invalid(LightClientSyncError::InvalidSyncCommitteeSignature);
}

#[test]
fn preserves_repeated_public_key_multiplicity_in_aggregate_signature() {
    let mut fixture = Fixture::new(ForkName::Altair);
    fixture.current_keys = (0..E::sync_committee_size())
        .map(|_| generate_deterministic_keypair(0))
        .collect();
    fixture.store = store(
        fixture.data_fork,
        &fixture.spec,
        Slot::new(1),
        committee(&fixture.current_keys),
    );
    fixture.sign_indices(&[0, 3, 31], false);
    fixture.valid();
    // One valid signature from that key is insufficient when three committee positions signed.
    fixture.sign_indices(&[0], false);
    with_update!(&mut fixture.update, inner, {
        inner
            .sync_aggregate
            .sync_committee_bits
            .set(3, true)
            .unwrap();
        inner
            .sync_aggregate
            .sync_committee_bits
            .set(31, true)
            .unwrap();
    });
    fixture.invalid(LightClientSyncError::InvalidSyncCommitteeSignature);
}

#[test]
fn accepts_nonzero_pre_altair_finalized_header_with_valid_finality_proof() {
    for data_fork in [
        ForkName::Altair,
        ForkName::Capella,
        ForkName::Deneb,
        ForkName::Electra,
    ] {
        let mut spec = E::default_spec();
        spec.altair_fork_epoch = Some(Epoch::new(1));
        let mut fixture = Fixture::at_slots(data_fork, spec, 8, 2, 10, 11);
        fixture.valid();
        match &mut fixture.update {
            LightClientUpdate::Altair(_) => continue,
            LightClientUpdate::Capella(inner) => {
                inner.finalized_header.execution.block_hash = ExecutionBlockHash(hash(99))
            }
            LightClientUpdate::Deneb(inner) => {
                inner.finalized_header.execution.block_hash = ExecutionBlockHash(hash(99))
            }
            LightClientUpdate::Electra(inner) => {
                inner.finalized_header.execution.block_hash = ExecutionBlockHash(hash(99))
            }
            LightClientUpdate::Fulu(_) => unreachable!(),
        }
        fixture.invalid(LightClientSyncError::NonDefaultExecutionPayload);
    }
}

#[test]
fn validates_execution_proofs_for_both_attested_and_finalized_headers() {
    for finalized in [false, true] {
        let mut fixture = Fixture::new(ForkName::Capella);
        let LightClientUpdate::Capella(inner) = &mut fixture.update else {
            unreachable!()
        };
        let header = if finalized {
            &mut inner.finalized_header
        } else {
            &mut inner.attested_header
        };
        header.execution_branch[0] = hash(100);
        fixture.invalid(LightClientSyncError::InvalidExecutionPayloadProof);
    }
}

#[test]
fn rejects_unsupported_forks_variant_mismatch_and_newer_update_schema() {
    for fork in [ForkName::Base, ForkName::Gloas, ForkName::Heze] {
        let mut fixture = Fixture::new(ForkName::Fulu);
        fixture.data_fork = fork;
        fixture.invalid(LightClientSyncError::UnsupportedFork(fork));
    }
    let mut fixture = Fixture::new(ForkName::Fulu);
    fixture.data_fork = ForkName::Electra;
    fixture.invalid(LightClientSyncError::HeaderVariantMismatch {
        expected: ForkName::Electra,
        actual: ForkName::Fulu,
    });
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let mut fixture = Fixture::at_slots(ForkName::Electra, spec, 1, 2, 3, 4);
    fixture.store = store(
        ForkName::Altair,
        &fixture.spec,
        Slot::new(1),
        committee(&fixture.current_keys),
    );
    fixture.invalid(LightClientSyncError::UpdateSchemaTooNew {
        update_schema: LightClientStoreSchema::Electra,
        store_schema: LightClientStoreSchema::Altair,
    });
}

#[test]
fn stale_previous_period_committee_does_not_make_update_relevant() {
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let mut fixture = Fixture::at_slots(ForkName::Altair, spec, 64, 2, 63, 64);
    fixture.invalid(LightClientSyncError::IrrelevantUpdate);
}

#[test]
fn rejects_zero_period_configuration_without_panicking() {
    let mut fixture = Fixture::new(ForkName::Altair);
    fixture.spec.epochs_per_sync_committee_period = Epoch::new(0);
    fixture.invalid(LightClientSyncError::Arithmetic(ArithError::DivisionByZero));
}

#[test]
fn absent_committee_requires_default_aggregate_public_key_too() {
    let mut fixture = Fixture::new(ForkName::Altair);
    let mut committee = SyncCommittee::temporary();
    committee.aggregate_pubkey = generate_deterministic_keypair(0).pk.compress();
    with_update!(
        &mut fixture.update,
        inner,
        inner.next_sync_committee = Arc::new(committee.clone())
    );
    fixture.refresh_proofs(true, false);
    fixture.sign_all(false);
    fixture.invalid(LightClientSyncError::NonDefaultNextSyncCommittee);
}

#[test]
fn zero_finalized_slot_requires_default_execution_fields_too() {
    let mut fixture = Fixture::new(ForkName::Capella);
    let LightClientUpdate::Capella(inner) = &mut fixture.update else {
        unreachable!()
    };
    inner.finalized_header = Default::default();
    inner.finalized_header.execution.block_hash = ExecutionBlockHash(hash(101));
    fixture.refresh_proofs(true, true);
    fixture.sign_all(false);
    fixture.invalid(LightClientSyncError::NonDefaultFinalizedHeader);
}
