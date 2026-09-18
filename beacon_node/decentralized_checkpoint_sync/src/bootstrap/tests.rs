use super::*;
use merkle_proof::MerkleTree;
use types::{
    BeaconBlockHeader, Epoch, ExecutionBlockHash, ExecutionPayloadHeaderCapella,
    LightClientBootstrapAltair, LightClientBootstrapCapella, LightClientBootstrapDeneb,
    LightClientBootstrapElectra, LightClientBootstrapFulu, LightClientHeaderAltair,
    LightClientHeaderCapella, LightClientHeaderDeneb, LightClientHeaderElectra,
    LightClientHeaderFulu, MinimalEthSpec, Slot, SyncCommittee,
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

macro_rules! with_bootstrap {
    ($bootstrap:expr, $inner:ident, $body:expr) => {
        match $bootstrap {
            LightClientBootstrap::Altair($inner) => $body,
            LightClientBootstrap::Capella($inner) => $body,
            LightClientBootstrap::Deneb($inner) => $body,
            LightClientBootstrap::Electra($inner) => $body,
            LightClientBootstrap::Fulu($inner) => $body,
        }
    };
}

struct Fixture {
    bootstrap: LightClientBootstrap<E>,
    spec: ChainSpec,
    data_fork: ForkName,
    root: Hash256,
}

impl Fixture {
    fn new(fork: ForkName) -> Self {
        Self::at_slot(fork, fork, Slot::new(1))
    }

    fn at_slot(data_fork: ForkName, beacon_fork: ForkName, slot: Slot) -> Self {
        let pubkey = generate_deterministic_keypair(0).pk.compress();
        // These synthetic committee contents exercise Merkle binding, not BLS aggregation.
        let committee = Arc::new(SyncCommittee::<E> {
            pubkeys: vec![pubkey; E::sync_committee_size()].try_into().unwrap(),
            aggregate_pubkey: generate_deterministic_keypair(1).pk.compress(),
        });
        // SSZ field 22 in BeaconState, independent of production generalized-index helpers.
        let depth = if beacon_fork.electra_enabled() { 6 } else { 5 };
        let (state_root, mut branch) = tree_proof(committee.tree_hash_root(), 22, depth);
        if data_fork.electra_enabled() && !beacon_fork.electra_enabled() {
            branch.insert(0, Hash256::default());
        }
        let beacon = BeaconBlockHeader {
            slot,
            state_root,
            parent_root: hash(70),
            ..BeaconBlockHeader::empty()
        };
        macro_rules! post_capella {
            ($bootstrap:ident, $header:ident, $variant:ident) => {{
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
                    // SSZ field 9 in BeaconBlockBody, not the production proof index.
                    let (body_root, execution_branch) = tree_proof(execution_root, 9, 4);
                    header.beacon.body_root = body_root;
                    header.execution_branch = execution_branch.try_into().unwrap();
                }
                LightClientBootstrap::$variant($bootstrap {
                    header,
                    current_sync_committee: committee,
                    current_sync_committee_branch: branch.try_into().unwrap(),
                })
            }};
        }
        let bootstrap = match data_fork {
            ForkName::Altair | ForkName::Bellatrix => {
                LightClientBootstrap::Altair(LightClientBootstrapAltair {
                    header: LightClientHeaderAltair {
                        beacon,
                        ..Default::default()
                    },
                    current_sync_committee: committee,
                    current_sync_committee_branch: branch.try_into().unwrap(),
                })
            }
            ForkName::Capella => post_capella!(
                LightClientBootstrapCapella,
                LightClientHeaderCapella,
                Capella
            ),
            ForkName::Deneb => {
                post_capella!(LightClientBootstrapDeneb, LightClientHeaderDeneb, Deneb)
            }
            ForkName::Electra => post_capella!(
                LightClientBootstrapElectra,
                LightClientHeaderElectra,
                Electra
            ),
            ForkName::Fulu => post_capella!(LightClientBootstrapFulu, LightClientHeaderFulu, Fulu),
            _ => unreachable!("test fixture requires a supported data fork"),
        };
        let root = with_bootstrap!(&bootstrap, inner, inner.header.beacon.canonical_root());
        Self {
            bootstrap,
            spec: beacon_fork.make_genesis_spec(E::default_spec()),
            data_fork,
            root,
        }
    }

    fn initialize(
        &self,
        schema: LightClientStoreSchema,
    ) -> Result<LightClientStore<E>, LightClientSyncError> {
        initialize_light_client_store(
            self.root,
            &self.bootstrap,
            self.data_fork,
            schema,
            &self.spec,
        )
    }

    fn store(&self) -> Result<LightClientStore<E>, LightClientSyncError> {
        self.initialize(LightClientStoreSchema::try_from(self.data_fork).unwrap())
    }
}

fn hash(value: u8) -> Hash256 {
    Hash256::from([value; 32])
}

fn tree_proof(leaf: Hash256, index: usize, depth: usize) -> (Hash256, Vec<Hash256>) {
    let mut leaves: Vec<_> = (1..=1usize << depth).map(|i| hash(i as u8)).collect();
    leaves[index] = leaf;
    let tree = MerkleTree::create(&leaves, depth);
    let (proven_leaf, proof) = tree.generate_proof(index, depth).unwrap();
    assert_eq!(proven_leaf, leaf);
    (tree.hash(), proof)
}

#[test]
fn initializes_each_supported_fork_and_store_defaults() {
    for fork in FORKS {
        let fixture = Fixture::new(fork);
        let store = fixture.store().unwrap();
        let checkpoint = store.verified_checkpoint_header();
        assert_eq!(
            store.store_schema(),
            LightClientStoreSchema::try_from(fork).unwrap()
        );
        assert_eq!(store.spec_finalized_header(), checkpoint.header());
        assert_eq!(store.optimistic_header(), checkpoint.header());
        assert_eq!(checkpoint.beacon_block_root(), fixture.root);
        assert_eq!(checkpoint.slot(), Slot::new(1));
        assert_eq!(checkpoint.fork(), fork);
        with_bootstrap!(&fixture.bootstrap, inner, {
            assert_eq!(
                checkpoint.beacon_state_root(),
                inner.header.beacon.state_root
            );
            assert_eq!(
                store.current_sync_committee(),
                inner.current_sync_committee.as_ref()
            );
        });
        assert!(store.next_sync_committee().is_none());
        assert!(store.best_valid_update().is_none());
        assert_eq!(store.previous_max_active_participants(), 0);
        assert_eq!(store.current_max_active_participants(), 0);
    }
}

#[test]
fn initializes_older_wire_data_in_newer_store() {
    for fork in FORKS {
        let fixture = Fixture::new(fork);
        let store = fixture.initialize(LightClientStoreSchema::Electra).unwrap();
        assert_eq!(store.store_schema(), LightClientStoreSchema::Electra);
        assert_eq!(store.verified_checkpoint_header().fork(), fork);
        let expected = with_bootstrap!(&fixture.bootstrap, inner, inner.header.tree_hash_root());
        assert_eq!(store.spec_finalized_header().tree_hash_root(), expected);
    }
}

#[test]
fn rejects_bootstrap_newer_than_store() {
    let fixture = Fixture::new(ForkName::Electra);
    assert_eq!(
        fixture
            .initialize(LightClientStoreSchema::Deneb)
            .unwrap_err(),
        LightClientSyncError::IncompatibleStoreSchema {
            bootstrap_schema: LightClientStoreSchema::Electra,
            store_schema: LightClientStoreSchema::Deneb,
        }
    );
}

#[test]
fn rejects_mismatched_data_fork() {
    let mut fixture = Fixture::new(ForkName::Fulu);
    fixture.data_fork = ForkName::Electra;
    assert_eq!(
        fixture.store().unwrap_err(),
        LightClientSyncError::HeaderVariantMismatch {
            expected: ForkName::Electra,
            actual: ForkName::Fulu,
        }
    );
}

#[test]
fn rejects_unsupported_data_forks() {
    let mut fixture = Fixture::new(ForkName::Fulu);
    for fork in [ForkName::Base, ForkName::Gloas, ForkName::Heze] {
        fixture.data_fork = fork;
        assert_eq!(
            fixture
                .initialize(LightClientStoreSchema::Electra)
                .unwrap_err(),
            LightClientSyncError::UnsupportedFork(fork)
        );
    }
}

#[test]
fn rejects_unsupported_beacon_forks() {
    let mut fixture = Fixture::new(ForkName::Fulu);
    for fork in [ForkName::Base, ForkName::Gloas, ForkName::Heze] {
        fixture.spec = fork.make_genesis_spec(E::default_spec());
        assert_eq!(
            fixture.store().unwrap_err(),
            LightClientSyncError::UnsupportedFork(fork)
        );
    }
}

#[test]
fn rejects_wrong_trusted_root() {
    let mut fixture = Fixture::new(ForkName::Deneb);
    let actual = fixture.root;
    fixture.root = hash(200);
    assert_eq!(
        fixture.store().unwrap_err(),
        LightClientSyncError::BootstrapRootMismatch {
            expected: fixture.root,
            actual,
        }
    );
}

#[test]
fn trusted_root_is_beacon_root_not_light_client_header_root() {
    let mut fixture = Fixture::new(ForkName::Capella);
    let actual = fixture.root;
    fixture.root = with_bootstrap!(&fixture.bootstrap, inner, inner.header.tree_hash_root());
    assert_ne!(fixture.root, actual);
    assert_eq!(
        fixture.store().unwrap_err(),
        LightClientSyncError::BootstrapRootMismatch {
            expected: fixture.root,
            actual,
        }
    );
}

#[test]
fn rejects_changed_beacon_header() {
    let mut fixture = Fixture::new(ForkName::Altair);
    with_bootstrap!(
        &mut fixture.bootstrap,
        inner,
        inner.header.beacon.proposer_index = 10
    );
    assert!(matches!(
        fixture.store(),
        Err(LightClientSyncError::BootstrapRootMismatch { .. })
    ));
}

#[test]
fn rejects_committee_pubkey_and_aggregate_pubkey_tampering() {
    for fork in FORKS {
        for aggregate in [false, true] {
            let mut fixture = Fixture::new(fork);
            let replacement = generate_deterministic_keypair(2).pk.compress();
            with_bootstrap!(&mut fixture.bootstrap, inner, {
                let committee = Arc::make_mut(&mut inner.current_sync_committee);
                if aggregate {
                    committee.aggregate_pubkey = replacement;
                } else {
                    committee.pubkeys[0] = replacement;
                }
            });
            assert_eq!(
                fixture.store().unwrap_err(),
                LightClientSyncError::InvalidCurrentSyncCommitteeProof
            );
        }
    }
}

#[test]
fn rejects_each_corrupt_committee_branch_node() {
    for fork in FORKS {
        let length = if fork.electra_enabled() { 6 } else { 5 };
        for index in 0..length {
            let mut fixture = Fixture::new(fork);
            with_bootstrap!(
                &mut fixture.bootstrap,
                inner,
                inner.current_sync_committee_branch[index] = hash(201)
            );
            assert_eq!(
                fixture.store().unwrap_err(),
                LightClientSyncError::InvalidCurrentSyncCommitteeProof
            );
        }
    }
}

#[test]
fn rejects_wrong_state_root_even_when_beacon_root_is_trusted() {
    let mut fixture = Fixture::new(ForkName::Electra);
    with_bootstrap!(
        &mut fixture.bootstrap,
        inner,
        inner.header.beacon.state_root = hash(202)
    );
    fixture.root = with_bootstrap!(
        &fixture.bootstrap,
        inner,
        inner.header.beacon.canonical_root()
    );
    assert_eq!(
        fixture.store().unwrap_err(),
        LightClientSyncError::InvalidCurrentSyncCommitteeProof
    );
}

#[test]
fn rejects_execution_proof_despite_matching_trusted_beacon_root() {
    let mut fixture = Fixture::new(ForkName::Capella);
    let LightClientBootstrap::Capella(inner) = &mut fixture.bootstrap else {
        unreachable!()
    };
    inner.header.execution_branch[0] = hash(203);
    assert_eq!(
        fixture.store().unwrap_err(),
        LightClientSyncError::InvalidExecutionPayloadProof
    );
}

#[test]
fn original_bootstrap_mutation_does_not_change_store() {
    let mut fixture = Fixture::new(ForkName::Altair);
    let store = fixture.store().unwrap();
    let committee = store.current_sync_committee().clone();
    with_bootstrap!(&mut fixture.bootstrap, inner, {
        inner.header.beacon.state_root = hash(204);
        Arc::make_mut(&mut inner.current_sync_committee).aggregate_pubkey =
            generate_deterministic_keypair(2).pk.compress();
    });
    assert_eq!(
        store.verified_checkpoint_header().beacon_block_root(),
        fixture.root
    );
    assert_ne!(
        store.verified_checkpoint_header().beacon_state_root(),
        hash(204)
    );
    assert_eq!(store.current_sync_committee(), &committee);
    assert_eq!(
        beacon_header(store.spec_finalized_header()).canonical_root(),
        fixture.root
    );
    assert_eq!(
        beacon_header(store.optimistic_header()).canonical_root(),
        fixture.root
    );
}

#[test]
fn accepts_upgraded_pre_electra_bootstraps() {
    for data_fork in [ForkName::Electra, ForkName::Fulu] {
        for beacon_fork in [ForkName::Altair, ForkName::Capella, ForkName::Deneb] {
            let fixture = Fixture::at_slot(data_fork, beacon_fork, Slot::new(1));
            let store = fixture.store().unwrap();
            assert_eq!(store.verified_checkpoint_header().fork(), beacon_fork);
            assert_eq!(
                store.verified_checkpoint_header().beacon_block_root(),
                fixture.root
            );
        }
    }
}

#[test]
fn rejects_nonzero_normalization_prefix_and_trailing_padding() {
    for trailing in [false, true] {
        let mut fixture = Fixture::at_slot(ForkName::Electra, ForkName::Deneb, Slot::new(1));
        let LightClientBootstrap::Electra(inner) = &mut fixture.bootstrap else {
            unreachable!()
        };
        if trailing {
            inner.current_sync_committee_branch.rotate_left(1);
        } else {
            inner.current_sync_committee_branch[0] = hash(205);
        }
        assert_eq!(
            fixture.store().unwrap_err(),
            LightClientSyncError::InvalidCurrentSyncCommitteeProof
        );
    }
}

#[test]
fn committee_proof_index_changes_at_electra_slot_boundary() {
    let boundary = 2 * E::slots_per_epoch();
    for (slot, beacon_fork) in [
        (boundary - 1, ForkName::Deneb),
        (boundary, ForkName::Electra),
    ] {
        let mut fixture = Fixture::at_slot(ForkName::Electra, beacon_fork, Slot::new(slot));
        fixture.spec = ForkName::Deneb.make_genesis_spec(E::default_spec());
        fixture.spec.electra_fork_epoch = Some(Epoch::new(2));
        assert_eq!(
            fixture.store().unwrap().verified_checkpoint_header().fork(),
            beacon_fork
        );
        fixture.spec.electra_fork_epoch = Some(Epoch::new(if slot == boundary { 3 } else { 1 }));
        assert_eq!(
            fixture.store().unwrap_err(),
            LightClientSyncError::InvalidCurrentSyncCommitteeProof
        );
    }
}

#[test]
fn normalized_proof_rejects_short_branches_without_panicking() {
    let leaf = hash(210);
    let (root, branch) = tree_proof(leaf, 22, 5);
    for length in 0..5 {
        assert_eq!(
            verify_current_sync_committee_proof(leaf, &branch[..length], 54, 5, root),
            Err(LightClientSyncError::InvalidCurrentSyncCommitteeProof)
        );
    }
    let mut normalized = vec![Hash256::default(); 2];
    normalized.extend_from_slice(&branch);
    assert_eq!(
        verify_current_sync_committee_proof(leaf, &normalized, 54, 5, root),
        Ok(())
    );
    normalized[1] = hash(211);
    assert_eq!(
        verify_current_sync_committee_proof(leaf, &normalized, 54, 5, root),
        Err(LightClientSyncError::InvalidCurrentSyncCommitteeProof)
    );
}
