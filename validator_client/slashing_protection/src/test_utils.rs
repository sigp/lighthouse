#![cfg(test)]

use crate::*;
use tempfile::NamedTempFile;
use types::{test_utils::generate_deterministic_keypair, AttestationData, BeaconBlockHeader};

pub const DEFAULT_VALIDATOR_INDEX: usize = 0;

pub type AttestationTest = Test<AttestationData>;
pub type AttestationStreamTest = StreamTest<AttestationData>;
pub type BlockStreamTest = StreamTest<BeaconBlockHeader>;

pub fn pubkey(index: usize) -> PublicKey {
    generate_deterministic_keypair(index).pk
}

pub struct Test<T> {
    pubkey: PublicKey,
    data: T,
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
            expected: Ok(Safe::Valid),
        }
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

impl AttestationStreamTest {
    pub fn run(&self) {
        let slashing_db_file = NamedTempFile::new().expect("couldn't create temporary file");
        let slashing_db = SlashingDatabase::create(slashing_db_file.path()).unwrap();

        for pubkey in &self.registered_validators {
            slashing_db.register_validator(pubkey).unwrap();
        }

        for (i, test) in self.cases.iter().enumerate() {
            assert_eq!(
                slashing_db.check_and_insert_attestation(&test.pubkey, &test.data),
                test.expected,
                "attestation {} not processed as expected",
                i
            );
        }
    }
}

impl BlockStreamTest {
    pub fn run(&self) {
        let slashing_db_file = NamedTempFile::new().expect("couldn't create temporary file");
        let slashing_db = SlashingDatabase::create(slashing_db_file.path()).unwrap();

        for pubkey in &self.registered_validators {
            slashing_db.register_validator(pubkey).unwrap();
        }

        for (i, test) in self.cases.iter().enumerate() {
            assert_eq!(
                slashing_db.check_and_insert_block_proposal(&test.pubkey, &test.data),
                test.expected,
                "attestation {} not processed as expected",
                i
            );
        }
    }
}
