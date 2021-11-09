use crate::{
    interchange::{Interchange, SignedAttestation, SignedBlock},
    test_utils::{pubkey, DEFAULT_GENESIS_VALIDATORS_ROOT},
    SigningRoot, SlashingDatabase,
};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashSet;
use tempfile::tempdir;
use types::{Epoch, Hash256, PublicKeyBytes, Slot};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MultiTestCase {
    pub name: String,
    pub genesis_validators_root: Hash256,
    pub steps: Vec<TestCase>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestCase {
    pub should_succeed: bool,
    pub contains_slashable_data: bool,
    pub interchange: Interchange,
    pub blocks: Vec<TestBlock>,
    pub attestations: Vec<TestAttestation>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestBlock {
    pub pubkey: PublicKeyBytes,
    pub slot: Slot,
    pub signing_root: Hash256,
    pub should_succeed: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestAttestation {
    pub pubkey: PublicKeyBytes,
    pub source_epoch: Epoch,
    pub target_epoch: Epoch,
    pub signing_root: Hash256,
    pub should_succeed: bool,
}

impl MultiTestCase {
    pub fn new(name: &str, steps: Vec<TestCase>) -> Self {
        MultiTestCase {
            name: name.into(),
            genesis_validators_root: DEFAULT_GENESIS_VALIDATORS_ROOT,
            steps,
        }
    }

    pub fn single(name: &str, test_case: TestCase) -> Self {
        Self::new(name, vec![test_case])
    }

    pub fn gvr(mut self, genesis_validators_root: Hash256) -> Self {
        self.genesis_validators_root = genesis_validators_root;
        self
    }

    pub fn run(&self, minify: bool) {
        let dir = tempdir().unwrap();
        let slashing_db_file = dir.path().join("slashing_protection.sqlite");
        let slashing_db = SlashingDatabase::create(&slashing_db_file).unwrap();

        // Now that we are using implicit minification on import, we must always allow
        // false positives.
        let allow_false_positives = true;

        for test_case in &self.steps {
            // If the test case is marked as containing slashable data, then the spec allows us to
            // fail to import the file. However, we minify on import and ignore slashable data, so
            // we should be capable of importing no matter what.
            let allow_import_failure = false;

            let interchange = if minify {
                let minified = test_case.interchange.minify().unwrap();
                check_minification_invariants(&test_case.interchange, &minified);
                minified
            } else {
                test_case.interchange.clone()
            };

            match slashing_db.import_interchange_info(interchange, self.genesis_validators_root) {
                Ok(import_outcomes) => {
                    let none_failed = import_outcomes.iter().all(|o| !o.failed());
                    assert!(
                        none_failed,
                        "test `{}` failed to import some records: {:#?}",
                        self.name, import_outcomes
                    );
                    if !test_case.should_succeed {
                        panic!(
                            "test `{}` succeeded on import when it should have failed",
                            self.name
                        );
                    }
                }
                Err(e) => {
                    if test_case.should_succeed && !allow_import_failure {
                        panic!(
                            "test `{}` failed on import when it should have succeeded, error: {:?}",
                            self.name, e
                        );
                    }
                    break;
                }
            }

            for (i, block) in test_case.blocks.iter().enumerate() {
                match slashing_db.check_and_insert_block_signing_root(
                    &block.pubkey,
                    block.slot,
                    SigningRoot::from(block.signing_root),
                ) {
                    Ok(safe) if !block.should_succeed => {
                        panic!(
                            "block {} from `{}` succeeded when it should have failed: {:?}",
                            i, self.name, safe
                        );
                    }
                    Err(e) if block.should_succeed && !allow_false_positives => {
                        panic!(
                            "block {} from `{}` failed when it should have succeeded: {:?}",
                            i, self.name, e
                        );
                    }
                    _ => (),
                }
            }

            for (i, att) in test_case.attestations.iter().enumerate() {
                match slashing_db.check_and_insert_attestation_signing_root(
                    &att.pubkey,
                    att.source_epoch,
                    att.target_epoch,
                    SigningRoot::from(att.signing_root),
                ) {
                    Ok(safe) if !att.should_succeed => {
                        panic!(
                            "attestation {} from `{}` succeeded when it should have failed: {:?}",
                            i, self.name, safe
                        );
                    }
                    Err(e) if att.should_succeed && !allow_false_positives => {
                        panic!(
                            "attestation {} from `{}` failed when it should have succeeded: {:?}",
                            i, self.name, e
                        );
                    }
                    _ => (),
                }
            }
        }
    }
}

impl TestCase {
    pub fn new(interchange: Interchange) -> Self {
        TestCase {
            should_succeed: true,
            contains_slashable_data: false,
            interchange,
            blocks: vec![],
            attestations: vec![],
        }
    }

    pub fn should_fail(mut self) -> Self {
        self.should_succeed = false;
        self
    }

    pub fn contains_slashable_data(mut self) -> Self {
        self.contains_slashable_data = true;
        self
    }

    pub fn with_blocks(self, blocks: impl IntoIterator<Item = (usize, u64, bool)>) -> Self {
        self.with_signing_root_blocks(
            blocks
                .into_iter()
                .map(|(index, slot, should_succeed)| (index, slot, 0, should_succeed)),
        )
    }

    pub fn with_signing_root_blocks(
        mut self,
        blocks: impl IntoIterator<Item = (usize, u64, u64, bool)>,
    ) -> Self {
        self.blocks.extend(
            blocks
                .into_iter()
                .map(|(pk, slot, signing_root, should_succeed)| TestBlock {
                    pubkey: pubkey(pk),
                    slot: Slot::new(slot),
                    signing_root: Hash256::from_low_u64_be(signing_root),
                    should_succeed,
                }),
        );
        self
    }

    pub fn with_attestations(
        self,
        attestations: impl IntoIterator<Item = (usize, u64, u64, bool)>,
    ) -> Self {
        self.with_signing_root_attestations(
            attestations
                .into_iter()
                .map(|(id, source, target, succeed)| (id, source, target, 0, succeed)),
        )
    }

    pub fn with_signing_root_attestations(
        mut self,
        attestations: impl IntoIterator<Item = (usize, u64, u64, u64, bool)>,
    ) -> Self {
        self.attestations.extend(attestations.into_iter().map(
            |(pk, source, target, signing_root, should_succeed)| TestAttestation {
                pubkey: pubkey(pk),
                source_epoch: Epoch::new(source),
                target_epoch: Epoch::new(target),
                signing_root: Hash256::from_low_u64_be(signing_root),
                should_succeed,
            },
        ));
        self
    }
}

fn check_minification_invariants(interchange: &Interchange, minified: &Interchange) {
    // Metadata should be unchanged.
    assert_eq!(interchange.metadata, minified.metadata);

    // Minified data should contain one entry per *unique* public key.
    let uniq_pubkeys = get_uniq_pubkeys(interchange);
    assert_eq!(uniq_pubkeys, get_uniq_pubkeys(minified));
    assert_eq!(uniq_pubkeys.len(), minified.data.len());

    for &pubkey in uniq_pubkeys.iter() {
        // Minified data should contain 1 block per validator, unless the validator never signed any
        // blocks. All of those blocks should have slots <= the slot of the minified block.
        let original_blocks = get_blocks_of_validator(interchange, pubkey);
        let minified_blocks = get_blocks_of_validator(minified, pubkey);

        if original_blocks.is_empty() {
            assert!(minified_blocks.is_empty());
        } else {
            // Should have exactly 1 block.
            assert_eq!(minified_blocks.len(), 1);

            // That block should have no signing root (it's synthetic).
            let mini_block = minified_blocks.first().unwrap();
            assert_eq!(mini_block.signing_root, None);

            // All original blocks should have slots <= the mini block.
            assert!(original_blocks
                .iter()
                .all(|block| block.slot <= mini_block.slot));
        }

        // Minified data should contain 1 attestation per validator, unless the validator never
        // signed any attestations. All attestations should have source and target <= the source
        // and target of the minified attestation.
        let original_attestations = get_attestations_of_validator(interchange, pubkey);
        let minified_attestations = get_attestations_of_validator(minified, pubkey);

        if original_attestations.is_empty() {
            assert!(minified_attestations.is_empty());
        } else {
            assert_eq!(minified_attestations.len(), 1);

            let mini_attestation = minified_attestations.first().unwrap();
            assert_eq!(mini_attestation.signing_root, None);

            assert!(original_attestations
                .iter()
                .all(|att| att.source_epoch <= mini_attestation.source_epoch
                    && att.target_epoch <= mini_attestation.target_epoch));
        }
    }
}

fn get_uniq_pubkeys(interchange: &Interchange) -> HashSet<PublicKeyBytes> {
    interchange.data.iter().map(|data| data.pubkey).collect()
}

fn get_blocks_of_validator(interchange: &Interchange, pubkey: PublicKeyBytes) -> Vec<&SignedBlock> {
    interchange
        .data
        .iter()
        .filter(|data| data.pubkey == pubkey)
        .flat_map(|data| data.signed_blocks.iter())
        .collect()
}

fn get_attestations_of_validator(
    interchange: &Interchange,
    pubkey: PublicKeyBytes,
) -> Vec<&SignedAttestation> {
    interchange
        .data
        .iter()
        .filter(|data| data.pubkey == pubkey)
        .flat_map(|data| data.signed_attestations.iter())
        .collect()
}
