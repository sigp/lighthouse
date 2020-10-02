use crate::{
    interchange::Interchange,
    test_utils::{pubkey, DEFAULT_GENESIS_VALIDATORS_ROOT},
    SlashingDatabase,
};
use serde_derive::{Deserialize, Serialize};
use tempfile::tempdir;
use types::{Epoch, Hash256, PublicKey, Slot};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestCase {
    pub name: String,
    pub should_succeed: bool,
    pub genesis_validators_root: Hash256,
    pub interchange: Interchange,
    pub blocks: Vec<TestBlock>,
    pub attestations: Vec<TestAttestation>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestBlock {
    pub pubkey: PublicKey,
    pub slot: Slot,
    pub should_succeed: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestAttestation {
    pub pubkey: PublicKey,
    pub source_epoch: Epoch,
    pub target_epoch: Epoch,
    pub should_succeed: bool,
}

impl TestCase {
    pub fn new(name: &str, interchange: Interchange) -> Self {
        TestCase {
            name: name.into(),
            should_succeed: true,
            genesis_validators_root: DEFAULT_GENESIS_VALIDATORS_ROOT,
            interchange,
            blocks: vec![],
            attestations: vec![],
        }
    }

    pub fn gvr(mut self, genesis_validators_root: Hash256) -> Self {
        self.genesis_validators_root = genesis_validators_root;
        self
    }

    pub fn should_fail(mut self) -> Self {
        self.should_succeed = false;
        self
    }

    pub fn with_blocks(mut self, blocks: impl IntoIterator<Item = (usize, u64, bool)>) -> Self {
        self.blocks.extend(
            blocks
                .into_iter()
                .map(|(pk, slot, should_succeed)| TestBlock {
                    pubkey: pubkey(pk),
                    slot: Slot::new(slot),
                    should_succeed,
                }),
        );
        self
    }

    pub fn with_attestations(
        mut self,
        attestations: impl IntoIterator<Item = (usize, u64, u64, bool)>,
    ) -> Self {
        self.attestations.extend(attestations.into_iter().map(
            |(pk, source, target, should_succeed)| TestAttestation {
                pubkey: pubkey(pk),
                source_epoch: Epoch::new(source),
                target_epoch: Epoch::new(target),
                should_succeed,
            },
        ));
        self
    }

    pub fn run(&self) {
        let dir = tempdir().unwrap();
        let slashing_db_file = dir.path().join("slashing_protection.sqlite");
        let slashing_db = SlashingDatabase::create(&slashing_db_file).unwrap();

        match slashing_db.import_interchange_info(&self.interchange, self.genesis_validators_root) {
            Ok(()) if !self.should_succeed => {
                panic!(
                    "test `{}` succeeded on import when it should have failed",
                    self.name
                );
            }
            Err(e) if self.should_succeed => {
                panic!(
                    "test `{}` failed on import when it should have succeeded, error: {:?}",
                    self.name, e
                );
            }
            _ => (),
        }

        for (i, block) in self.blocks.iter().enumerate() {
            match slashing_db.check_and_insert_block_signing_root(
                &block.pubkey,
                block.slot,
                Hash256::random(),
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

        for (i, att) in self.attestations.iter().enumerate() {
            match slashing_db.check_and_insert_attestation_signing_root(
                &att.pubkey,
                att.source_epoch,
                att.target_epoch,
                Hash256::random(),
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
