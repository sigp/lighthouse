use crate::*;
use tempfile::{tempdir, TempDir};
use types::{
    test_utils::generate_deterministic_keypair, AttestationData, BeaconBlockHeader, Hash256,
    PublicKeyBytes,
};

pub const DEFAULT_VALIDATOR_INDEX: usize = 0;
pub const DEFAULT_DOMAIN: Hash256 = Hash256::zero();
pub const DEFAULT_GENESIS_VALIDATORS_ROOT: Hash256 = Hash256::zero();

pub fn pubkey(index: usize) -> PublicKeyBytes {
    generate_deterministic_keypair(index).pk.compress()
}

pub struct Test<T> {
    pubkey: PublicKeyBytes,
    data: T,
    domain: Hash256,
    expected: Result<Safe, NotSafe>,
}

impl<T> Test<T> {
    pub fn single(data: T) -> Self {
        Self::with_pubkey(pubkey(DEFAULT_VALIDATOR_INDEX), data)
    }

    pub fn with_pubkey(pubkey: PublicKeyBytes, data: T) -> Self {
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
    pub registered_validators: Vec<PublicKeyBytes>,
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

impl<T> StreamTest<T> {
    /// The number of test cases that are expected to pass processing successfully.
    fn num_expected_successes(&self) -> usize {
        self.cases
            .iter()
            .filter(|case| case.expected.is_ok())
            .count()
    }
}

impl StreamTest<AttestationData> {
    pub fn run(&self) {
        let dir = tempdir().unwrap();
        let slashing_db_file = dir.path().join("slashing_protection.sqlite");
        let slashing_db = SlashingDatabase::create(&slashing_db_file).unwrap();

        for pubkey in &self.registered_validators {
            slashing_db.register_validator(*pubkey).unwrap();
        }

        for (i, test) in self.cases.iter().enumerate() {
            assert_eq!(
                slashing_db.check_and_insert_attestation(&test.pubkey, &test.data, test.domain),
                test.expected,
                "attestation {} not processed as expected",
                i
            );
        }

        roundtrip_database(&dir, &slashing_db, self.num_expected_successes() == 0);
    }
}

impl StreamTest<BeaconBlockHeader> {
    pub fn run(&self) {
        let dir = tempdir().unwrap();
        let slashing_db_file = dir.path().join("slashing_protection.sqlite");
        let slashing_db = SlashingDatabase::create(&slashing_db_file).unwrap();

        for pubkey in &self.registered_validators {
            slashing_db.register_validator(*pubkey).unwrap();
        }

        for (i, test) in self.cases.iter().enumerate() {
            assert_eq!(
                slashing_db.check_and_insert_block_proposal(&test.pubkey, &test.data, test.domain),
                test.expected,
                "attestation {} not processed as expected",
                i
            );
        }

        roundtrip_database(&dir, &slashing_db, self.num_expected_successes() == 0);
    }
}

// This function roundtrips the database, but applies minification in order to be compatible with
// the implicit minification done on import.
fn roundtrip_database(dir: &TempDir, db: &SlashingDatabase, is_empty: bool) {
    let exported = db
        .export_interchange_info(DEFAULT_GENESIS_VALIDATORS_ROOT)
        .unwrap();
    let new_db =
        SlashingDatabase::create(&dir.path().join("roundtrip_slashing_protection.sqlite")).unwrap();
    new_db
        .import_interchange_info(exported.clone(), DEFAULT_GENESIS_VALIDATORS_ROOT)
        .unwrap();
    let reexported = new_db
        .export_interchange_info(DEFAULT_GENESIS_VALIDATORS_ROOT)
        .unwrap();

    assert!(exported
        .minify()
        .unwrap()
        .equiv(&reexported.minify().unwrap()));
    assert_eq!(is_empty, exported.is_empty());
}
