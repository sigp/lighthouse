#![cfg(test)]

use crate::*;
use tempfile::tempdir;
use types::{
    test_utils::generate_deterministic_keypair, AttestationData, BeaconBlockHeader, Hash256,
};

pub const DEFAULT_VALIDATOR_INDEX: usize = 0;
pub const DEFAULT_DOMAIN: Hash256 = Hash256::zero();

pub fn pubkey(index: usize) -> PublicKey {
    generate_deterministic_keypair(index).pk
}

pub struct Test<T> {
    pubkey: PublicKey,
    data: T,
    domain: Hash256,
    expected: Result<Safe, NotSafe>,
}

impl<T> Test<T> {
    pub fn single(data: T) -> Self {
        Self::with_pubkey(pubkey(DEFAULT_VALIDATOR_INDEX), data)
    }

    pub fn with_pubkey(pubkey: PublicKey, data: T) -> Self {
        Self {
            pubkey,
            data,
            domain: DEFAULT_DOMAIN,
            expected: Ok(Safe::Valid),
        }
    }

    pub fn with_domain(mut self, domain: Hash256) -> Self {
        self.domain = domain;
        self
    }

    pub fn expect_result(mut self, result: Result<Safe, NotSafe>) -> Self {
        self.expected = result;
        self
    }

    pub fn expect_invalid_att(self, error: InvalidAttestation) -> Self {
        self.expect_result(Err(NotSafe::InvalidAttestation(error)))
    }

    pub fn expect_invalid_block(self, error: InvalidBlock) -> Self {
        self.expect_result(Err(NotSafe::InvalidBlock(error)))
    }

    pub fn expect_same_data(self) -> Self {
        self.expect_result(Ok(Safe::SameData))
    }
}

pub struct StreamTest<T> {
    /// Validators to register.
    pub registered_validators: Vec<PublicKey>,
    /// Vector of cases and the value expected when calling `check_and_insert_X`.
    pub cases: Vec<Test<T>>,
}

impl<T> Default for StreamTest<T> {
    fn default() -> Self {
        Self {
            registered_validators: vec![pubkey(DEFAULT_VALIDATOR_INDEX)],
            cases: vec![],
        }
    }
}

impl StreamTest<AttestationData> {
    pub fn run(&self) {
        let dir = tempdir().unwrap();
        let slashing_db_file = dir.path().join("slashing_protection.sqlite");
        let slashing_db = SlashingDatabase::create(&slashing_db_file).unwrap();

        for pubkey in &self.registered_validators {
            slashing_db.register_validator(pubkey).unwrap();
        }

        for (i, test) in self.cases.iter().enumerate() {
            assert_eq!(
                slashing_db.check_and_insert_attestation(&test.pubkey, &test.data, test.domain),
                test.expected,
                "attestation {} not processed as expected",
                i
            );
        }
    }
}

impl StreamTest<BeaconBlockHeader> {
    pub fn run(&self) {
        let dir = tempdir().unwrap();
        let slashing_db_file = dir.path().join("slashing_protection.sqlite");
        let slashing_db = SlashingDatabase::create(&slashing_db_file).unwrap();

        for pubkey in &self.registered_validators {
            slashing_db.register_validator(pubkey).unwrap();
        }

        for (i, test) in self.cases.iter().enumerate() {
            assert_eq!(
                slashing_db.check_and_insert_block_proposal(&test.pubkey, &test.data, test.domain),
                test.expected,
                "attestation {} not processed as expected",
                i
            );
        }
    }
}
