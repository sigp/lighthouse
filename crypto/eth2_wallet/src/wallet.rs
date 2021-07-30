use crate::{
    json_wallet::{
        Aes128Ctr, ChecksumModule, Cipher, CipherModule, Crypto, EmptyMap, EmptyString, JsonWallet,
        Kdf, KdfModule, Sha256Checksum, TypeField, Version,
    },
    KeyType, ValidatorPath,
};
pub use bip39::{Mnemonic, Seed as Bip39Seed};
pub use eth2_key_derivation::{DerivedKey, DerivedKeyError};
use eth2_keystore::{
    decrypt, default_kdf, encrypt, keypair_from_secret, Keystore, KeystoreBuilder, IV_SIZE,
    SALT_SIZE,
};
pub use eth2_keystore::{Error as KeystoreError, PlainText};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
pub use uuid::Uuid;

#[derive(Debug, PartialEq)]
pub enum Error {
    KeystoreError(KeystoreError),
    PathExhausted,
    EmptyPassword,
    EmptySeed,
    InvalidNextAccount { old: u32, new: u32 },
}

impl From<KeystoreError> for Error {
    fn from(e: KeystoreError) -> Error {
        Error::KeystoreError(e)
    }
}

impl From<DerivedKeyError> for Error {
    fn from(e: DerivedKeyError) -> Error {
        match e {
            DerivedKeyError::EmptySeed => Error::EmptySeed,
        }
    }
}

/// Contains the two keystores required for an eth2 validator.
pub struct ValidatorKeystores {
    /// Contains the secret key used for signing every-day consensus messages (blocks,
    /// attestations, etc).
    pub voting: Keystore,
    /// Contains the secret key that should eventually be required for withdrawing stacked ETH.
    pub withdrawal: Keystore,
}

/// Constructs a `Keystore`.
///
/// Generates the KDF `salt` and AES `IV` using `rand::thread_rng()`.
pub struct WalletBuilder<'a> {
    seed: PlainText,
    password: &'a [u8],
    kdf: Kdf,
    cipher: Cipher,
    uuid: Uuid,
    name: String,
    nextaccount: u32,
}

impl<'a> WalletBuilder<'a> {
    /// Creates a new builder for a seed specified as a BIP-39 `Mnemonic` (where the nmemonic itself does
    /// not have a passphrase).
    ///
    /// ## Errors
    ///
    /// Returns `Error::EmptyPassword` if `password == ""`.
    pub fn from_mnemonic(
        mnemonic: &Mnemonic,
        password: &'a [u8],
        name: String,
    ) -> Result<Self, Error> {
        let seed = Bip39Seed::new(mnemonic, "");

        Self::from_seed_bytes(seed.as_bytes(), password, name)
    }

    /// Creates a new builder from a `seed` specified as a byte slice.
    ///
    /// ## Errors
    ///
    /// Returns `Error::EmptyPassword` if `password == ""`.
    pub fn from_seed_bytes(seed: &[u8], password: &'a [u8], name: String) -> Result<Self, Error> {
        if password.is_empty() {
            Err(Error::EmptyPassword)
        } else if seed.is_empty() {
            Err(Error::EmptySeed)
        } else {
            let salt = rand::thread_rng().gen::<[u8; SALT_SIZE]>();
            let iv = rand::thread_rng().gen::<[u8; IV_SIZE]>().to_vec().into();

            Ok(Self {
                seed: seed.to_vec().into(),
                password,
                kdf: default_kdf(salt.to_vec()),
                cipher: Cipher::Aes128Ctr(Aes128Ctr { iv }),
                uuid: Uuid::new_v4(),
                nextaccount: 0,
                name,
            })
        }
    }

    /// Consumes `self`, returning an encrypted `Wallet`.
    pub fn build(self) -> Result<Wallet, Error> {
        Wallet::encrypt(
            self.seed.as_bytes(),
            self.password,
            self.kdf,
            self.cipher,
            self.uuid,
            self.name,
            self.nextaccount,
        )
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Wallet {
    json: JsonWallet,
}

impl Wallet {
    /// Instantiates `Self`, encrypting the `seed` using `password` (via `kdf` and `cipher`).
    ///
    /// The `uuid`, `name` and `nextaccount` are carried through into the created wallet.
    fn encrypt(
        seed: &[u8],
        password: &[u8],
        kdf: Kdf,
        cipher: Cipher,
        uuid: Uuid,
        name: String,
        nextaccount: u32,
    ) -> Result<Self, Error> {
        let (cipher_text, checksum) = encrypt(seed, password, &kdf, &cipher)?;

        Ok(Self {
            json: JsonWallet {
                crypto: Crypto {
                    kdf: KdfModule {
                        function: kdf.function(),
                        params: kdf,
                        message: EmptyString,
                    },
                    checksum: ChecksumModule {
                        function: Sha256Checksum::function(),
                        params: EmptyMap,
                        message: checksum.to_vec().into(),
                    },
                    cipher: CipherModule {
                        function: cipher.function(),
                        params: cipher,
                        message: cipher_text.into(),
                    },
                },
                uuid,
                nextaccount,
                version: Version::one(),
                type_field: TypeField::Hd,
                name,
            },
        })
    }

    /// Produces a `Keystore` (encrypted with `keystore_password`) for the validator at
    /// `self.nextaccount`, incrementing `self.nextaccount` if the keystore was successfully
    /// generated.
    ///
    /// Uses the default encryption settings of `KeystoreBuilder`, not necessarily those that were
    /// used to encrypt `self`.
    ///
    /// ## Errors
    ///
    /// - If `wallet_password` is unable to decrypt `self`.
    /// - If `keystore_password.is_empty()`.
    /// - If `self.nextaccount == u32::max_value()`.
    pub fn next_validator(
        &mut self,
        wallet_password: &[u8],
        voting_keystore_password: &[u8],
        withdrawal_keystore_password: &[u8],
    ) -> Result<ValidatorKeystores, Error> {
        // Helper closure to reduce code duplication when generating keys.
        //
        // It is not a function on `self` to help protect against generating keys without
        // incrementing `nextaccount`.
        let derive = |key_type: KeyType, password: &[u8]| -> Result<Keystore, Error> {
            let (secret, path) =
                recover_validator_secret(self, wallet_password, self.json.nextaccount, key_type)?;

            let keypair = keypair_from_secret(secret.as_bytes())?;

            KeystoreBuilder::new(&keypair, password, format!("{}", path))?
                .build()
                .map_err(Into::into)
        };

        let keystores = ValidatorKeystores {
            voting: derive(KeyType::Voting, voting_keystore_password)?,
            withdrawal: derive(KeyType::Withdrawal, withdrawal_keystore_password)?,
        };

        self.json.nextaccount = self
            .json
            .nextaccount
            .checked_add(1)
            .ok_or(Error::PathExhausted)?;

        Ok(keystores)
    }

    /// Returns the value of the JSON wallet `nextaccount` field.
    ///
    /// This will be the index of the next wallet generated with `Self::next_validator`.
    pub fn nextaccount(&self) -> u32 {
        self.json.nextaccount
    }

    /// Sets the value of the JSON wallet `nextaccount` field.
    ///
    /// This will be the index of the next wallet generated with `Self::next_validator`.
    ///
    /// ## Errors
    ///
    /// Returns `Err(())` if `nextaccount` is less than `self.nextaccount()` without mutating
    /// `self`. This is to protect against duplicate validator generation.
    pub fn set_nextaccount(&mut self, nextaccount: u32) -> Result<(), Error> {
        if nextaccount >= self.nextaccount() {
            self.json.nextaccount = nextaccount;
            Ok(())
        } else {
            Err(Error::InvalidNextAccount {
                old: self.json.nextaccount,
                new: nextaccount,
            })
        }
    }

    /// Returns the value of the JSON wallet `name` field.
    pub fn name(&self) -> &str {
        &self.json.name
    }

    /// Returns the value of the JSON wallet `uuid` field.
    pub fn uuid(&self) -> &Uuid {
        &self.json.uuid
    }

    /// Returns the value of the JSON wallet `type` field.
    pub fn type_field(&self) -> String {
        self.json.type_field.clone().into()
    }

    /// Returns the master seed of this wallet. Care should be taken not to leak this seed.
    pub fn decrypt_seed(&self, password: &[u8]) -> Result<PlainText, Error> {
        decrypt(password, &self.json.crypto).map_err(Into::into)
    }

    /// Encodes `self` as a JSON object.
    pub fn to_json_string(&self) -> Result<String, Error> {
        serde_json::to_string(self)
            .map_err(|e| KeystoreError::UnableToSerialize(format!("{}", e)))
            .map_err(Into::into)
    }

    /// Returns `self` from an encoded JSON object.
    pub fn from_json_str(json_string: &str) -> Result<Self, Error> {
        serde_json::from_str(json_string)
            .map_err(|e| KeystoreError::InvalidJson(format!("{}", e)))
            .map_err(Into::into)
    }

    /// Encodes self as a JSON object to the given `writer`.
    pub fn to_json_writer<W: Write>(&self, writer: W) -> Result<(), Error> {
        serde_json::to_writer(writer, self)
            .map_err(|e| KeystoreError::WriteError(format!("{}", e)))
            .map_err(Into::into)
    }

    /// Instantiates `self` from a JSON `reader`.
    pub fn from_json_reader<R: Read>(reader: R) -> Result<Self, Error> {
        serde_json::from_reader(reader)
            .map_err(|e| KeystoreError::ReadError(format!("{}", e)))
            .map_err(Into::into)
    }
}

/// Returns `(secret, path)` for the `key_type` for the validator at `index`.
///
/// This function should only be used for recovering lost keys, not creating new ones because it
/// does not update `wallet.nextaccount`. Using this function to generate new keys can easily
/// result in the same key being unknowingly generated twice.
///
/// To generate consecutive keys safely, use `Wallet::next_voting_keystore`.
pub fn recover_validator_secret(
    wallet: &Wallet,
    wallet_password: &[u8],
    index: u32,
    key_type: KeyType,
) -> Result<(PlainText, ValidatorPath), Error> {
    let path = ValidatorPath::new(index, key_type);
    let secret = wallet.decrypt_seed(wallet_password)?;
    let master = DerivedKey::from_seed(secret.as_bytes()).map_err(Error::from)?;

    let destination = path.iter_nodes().fold(master, |dk, i| dk.child(*i));

    Ok((destination.secret().to_vec().into(), path))
}

/// Returns `(secret, path)` for the `key_type` for the validator at `index`.
///
/// This function should only be used for key recovery since it can easily lead to key duplication.
pub fn recover_validator_secret_from_mnemonic(
    secret: &[u8],
    index: u32,
    key_type: KeyType,
) -> Result<(PlainText, ValidatorPath), Error> {
    let path = ValidatorPath::new(index, key_type);
    let master = DerivedKey::from_seed(secret).map_err(Error::from)?;

    let destination = path.iter_nodes().fold(master, |dk, i| dk.child(*i));

    Ok((destination.secret().to_vec().into(), path))
}
