use crate::{
    interchange::Interchange,
    test_utils::{pubkey, DEFAULT_GENESIS_VALIDATORS_ROOT},
    SigningRoot, SlashingDatabase,
};
use serde_derive::{Deserialize, Serialize};
use tempfile::tempdir;
use types::{Epoch, Hash256, PublicKey, Slot};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MultiTestCase {
    pub name: String,
    pub genesis_validators_root: Hash256,
    pub steps: Vec<TestCase>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestCase {
    pub should_succeed: bool,
    pub allow_partial_import: bool,
    pub interchange: Interchange,
    pub blocks: Vec<TestBlock>,
    pub attestations: Vec<TestAttestation>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestBlock {
    pub pubkey: PublicKey,
    pub slot: Slot,
    pub signing_root: Hash256,
    pub should_succeed: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestAttestation {
    pub pubkey: PublicKey,
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

    pub fn run(&self) {
        let dir = tempdir().unwrap();
        let slashing_db_file = dir.path().join("slashing_protection.sqlite");
        let slashing_db = SlashingDatabase::create(&slashing_db_file).unwrap();

        for test_case in &self.steps {
            match slashing_db.import_interchange_info(
                test_case.interchange.clone(),
                self.genesis_validators_root,
            ) {
                Ok(import_outcomes) => {
                    let failed_records = import_outcomes
                        .iter()
                        .filter(|o| o.failed())
                        .collect::<Vec<_>>();
                    if !test_case.should_succeed {
                        panic!(
                            "test `{}` succeeded on import when it should have failed",
                            self.name
                        );
                    }
                    if !failed_records.is_empty() && !test_case.allow_partial_import {
                        panic!(
                            "test `{}` failed to import some records but should have succeeded: {:#?}",
                            self.name, failed_records,
                        );
                    }
                }
                Err(e) if test_case.should_succeed => {
                    panic!(
                        "test `{}` failed on import when it should have succeeded, error: {:?}",
                        self.name, e
                    );
                }
                _ => (),
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
                    Err(e) if block.should_succeed => {
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
                    Err(e) if att.should_succeed => {
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
            allow_partial_import: false,
            interchange,
            blocks: vec![],
            attestations: vec![],
        }
    }

    pub fn should_fail(mut self) -> Self {
        self.should_succeed = false;
        self
    }

    pub fn allow_partial_import(mut self) -> Self {
        self.allow_partial_import = true;
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
