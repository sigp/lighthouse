#![cfg(not(debug_assertions))]

use eth2_wallet::{
    bip39::{Language, Mnemonic, Seed},
    recover_validator_secret, DerivedKey, Error, KeyType, KeystoreError, Wallet, WalletBuilder,
};
use std::fs::File;
use tempfile::tempdir;

const NAME: &str = "Wallet McWalletface";
const SEED: &[u8] = &[42; 42];
const WALLET_PASSWORD: &[u8] = &[43; 43];
const VOTING_KEYSTORE_PASSWORD: &[u8] = &[44; 44];
const WITHDRAWAL_KEYSTORE_PASSWORD: &[u8] = &[45; 45];
const MNEMONIC: &str =
    "enemy fog enlist laundry nurse hungry discover turkey holiday resemble glad discover";

fn wallet_from_seed() -> Wallet {
    WalletBuilder::from_seed_bytes(SEED, WALLET_PASSWORD, NAME.into())
        .expect("should init builder")
        .build()
        .expect("should build wallet")
}

fn recovered_voting_key(wallet: &Wallet, index: u32) -> Vec<u8> {
    let (secret, path) = recover_validator_secret(wallet, WALLET_PASSWORD, index, KeyType::Voting)
        .expect("should recover voting secret");

    assert_eq!(
        format!("{}", path),
        format!("m/12381/3600/{}/0/0", index),
        "path should be as expected"
    );

    secret.as_bytes().to_vec()
}

fn recovered_withdrawal_key(wallet: &Wallet, index: u32) -> Vec<u8> {
    let (secret, path) =
        recover_validator_secret(wallet, WALLET_PASSWORD, index, KeyType::Withdrawal)
            .expect("should recover withdrawal secret");

    assert_eq!(
        format!("{}", path),
        format!("m/12381/3600/{}/0", index),
        "path should be as expected"
    );

    secret.as_bytes().to_vec()
}

fn manually_derived_voting_key(index: u32) -> Vec<u8> {
    DerivedKey::from_seed(SEED)
        .expect("should derive master key")
        .child(12381)
        .child(3600)
        .child(index)
        .child(0)
        .child(0)
        .secret()
        .to_vec()
}

fn manually_derived_withdrawal_key(index: u32) -> Vec<u8> {
    DerivedKey::from_seed(SEED)
        .expect("should derive master key")
        .child(12381)
        .child(3600)
        .child(index)
        .child(0)
        .secret()
        .to_vec()
}

#[test]
fn mnemonic_equality() {
    let m = Mnemonic::from_phrase(MNEMONIC, Language::English).unwrap();

    let from_mnemonic = WalletBuilder::from_mnemonic(&m, WALLET_PASSWORD, NAME.into())
        .expect("should init builder")
        .build()
        .expect("should build wallet");

    let seed = Seed::new(&m, "");

    let from_seed = WalletBuilder::from_seed_bytes(seed.as_bytes(), WALLET_PASSWORD, NAME.into())
        .expect("should init builder")
        .build()
        .expect("should build wallet");

    assert_eq!(
        from_mnemonic
            .decrypt_seed(WALLET_PASSWORD)
            .unwrap()
            .as_bytes(),
        from_seed.decrypt_seed(WALLET_PASSWORD).unwrap().as_bytes(),
        "wallet from mnemonic should match wallet from seed"
    );
}

#[test]
fn metadata() {
    let wallet = wallet_from_seed();
    assert_eq!(wallet.name(), NAME, "name");
    assert_eq!(&wallet.type_field(), "hierarchical deterministic", "name");
    assert_eq!(wallet.nextaccount(), 0, "name");
}

#[test]
fn string_round_trip() {
    let wallet = wallet_from_seed();

    let json = wallet.to_json_string().unwrap();
    let decoded = Wallet::from_json_str(&json).unwrap();

    assert_eq!(
        decoded.decrypt_seed(&[1, 2, 3]).err().unwrap(),
        Error::KeystoreError(KeystoreError::InvalidPassword),
        "should not decrypt with bad password"
    );

    assert_eq!(
        wallet.decrypt_seed(WALLET_PASSWORD).unwrap().as_bytes(),
        decoded.decrypt_seed(WALLET_PASSWORD).unwrap().as_bytes(),
        "should decrypt with good password"
    );
}

#[test]
fn file_round_trip() {
    let wallet = wallet_from_seed();
    let dir = tempdir().unwrap();
    let path = dir.path().join("keystore.json");

    let get_file = || {
        File::options()
            .write(true)
            .read(true)
            .create(true)
            .open(path.clone())
            .expect("should create file")
    };

    wallet
        .to_json_writer(&mut get_file())
        .expect("should write to file");

    let decoded = Wallet::from_json_reader(&mut get_file()).unwrap();

    assert_eq!(
        decoded.decrypt_seed(&[1, 2, 3]).err().unwrap(),
        Error::KeystoreError(KeystoreError::InvalidPassword),
        "should not decrypt with bad password"
    );

    assert_eq!(
        wallet.decrypt_seed(WALLET_PASSWORD).unwrap().as_bytes(),
        decoded.decrypt_seed(WALLET_PASSWORD).unwrap().as_bytes(),
        "should decrypt with good password"
    );
}

#[test]
fn empty_wallet_password() {
    assert_eq!(
        WalletBuilder::from_seed_bytes(SEED, &[], NAME.into())
            .err()
            .expect("should error"),
        Error::EmptyPassword
    )
}

#[test]
fn empty_wallet_seed() {
    assert_eq!(
        WalletBuilder::from_seed_bytes(&[], WALLET_PASSWORD, NAME.into())
            .err()
            .expect("should error"),
        Error::EmptySeed
    )
}

#[test]
fn empty_keystore_password() {
    let mut wallet = wallet_from_seed();

    assert_eq!(wallet.nextaccount(), 0, "initial nextaccount");

    assert_eq!(
        wallet
            .next_validator(WALLET_PASSWORD, &[], WITHDRAWAL_KEYSTORE_PASSWORD,)
            .err()
            .expect("should error"),
        Error::KeystoreError(KeystoreError::EmptyPassword),
        "should fail with empty voting password"
    );

    assert_eq!(wallet.nextaccount(), 0, "next account should not update");

    assert_eq!(
        wallet
            .next_validator(WALLET_PASSWORD, VOTING_KEYSTORE_PASSWORD, &[],)
            .err()
            .expect("should error"),
        Error::KeystoreError(KeystoreError::EmptyPassword),
        "should fail with empty withdrawal password"
    );

    assert_eq!(wallet.nextaccount(), 0, "next account should not update");
}

#[test]
fn key_derivation_from_seed() {
    let mut wallet = wallet_from_seed();

    for i in 0..4 {
        assert_eq!(wallet.nextaccount(), i, "initial nextaccount");

        let keystores = wallet
            .next_validator(
                WALLET_PASSWORD,
                VOTING_KEYSTORE_PASSWORD,
                WITHDRAWAL_KEYSTORE_PASSWORD,
            )
            .expect("should generate keystores");

        assert_eq!(
            keystores.voting.path().unwrap(),
            format!("m/12381/3600/{}/0/0", i),
            "voting path should match"
        );

        assert_eq!(
            keystores.withdrawal.path().unwrap(),
            format!("m/12381/3600/{}/0", i),
            "withdrawal path should match"
        );

        let voting_keypair = keystores
            .voting
            .decrypt_keypair(VOTING_KEYSTORE_PASSWORD)
            .expect("should decrypt voting keypair");

        assert_eq!(
            voting_keypair.sk.serialize().as_ref(),
            &manually_derived_voting_key(i)[..],
            "voting secret should match manually derived"
        );

        assert_eq!(
            voting_keypair.sk.serialize().as_ref(),
            &recovered_voting_key(&wallet, i)[..],
            "voting secret should match recovered"
        );

        let withdrawal_keypair = keystores
            .withdrawal
            .decrypt_keypair(WITHDRAWAL_KEYSTORE_PASSWORD)
            .expect("should decrypt withdrawal keypair");

        assert_eq!(
            withdrawal_keypair.sk.serialize().as_ref(),
            &manually_derived_withdrawal_key(i)[..],
            "withdrawal secret should match manually derived"
        );

        assert_eq!(
            withdrawal_keypair.sk.serialize().as_ref(),
            &recovered_withdrawal_key(&wallet, i)[..],
            "withdrawal secret should match recovered"
        );

        assert_ne!(
            withdrawal_keypair.sk.serialize().as_ref(),
            voting_keypair.sk.serialize().as_bytes(),
            "voting and withdrawal keypairs should be distinct"
        );

        assert_eq!(wallet.nextaccount(), i + 1, "updated nextaccount");
    }
}
