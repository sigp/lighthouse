mod derived_key;
mod json_keystore;
mod password;
mod plain_text;

pub use password::Password;
pub use uuid::Uuid;

use bls::{Keypair, PublicKey, SecretKey};
use crypto::{digest::Digest, sha2::Sha256};
use derived_key::DerivedKey;
use hex::FromHexError;
use json_keystore::{
    Aes128Ctr, ChecksumModule, Cipher, CipherModule, Crypto, EmptyMap, HexBytes, JsonKeystore, Kdf,
    KdfModule, Pbkdf2, Prf, Sha256Checksum, Version,
};
use plain_text::PlainText;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use ssz::DecodeError;

/// The byte-length of a BLS secret key.
const SECRET_KEY_LEN: usize = 32;
/// The default byte length of the salt used to seed the KDF.
const SALT_SIZE: usize = 32;
/// The length of the derived key.
const DKLEN: u32 = 32;
// TODO: comment
const IV_SIZE: usize = 16;
// TODO: comment
const HASH_SIZE: usize = 32;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidSecretKeyLen { len: usize, expected: usize },
    InvalidCipherMessageHex(FromHexError),
    InvalidPassword,
    InvalidSecretKeyBytes(DecodeError),
    PublicKeyMismatch,
    EmptyPassword,
    UnableToSerialize,
    InvalidJson(String),
    IncorrectIvSize { expected: usize, len: usize },
}

/// Constructs a `Keystore`.
pub struct KeystoreBuilder<'a> {
    keypair: &'a Keypair,
    password: Password,
    kdf: Kdf,
    cipher: Cipher,
    uuid: Uuid,
}

impl<'a> KeystoreBuilder<'a> {
    /// Creates a new builder.
    ///
    /// ## Errors
    ///
    /// Returns `Error::EmptyPassword` if `password == ""`.
    pub fn new(keypair: &'a Keypair, password: Password) -> Result<Self, Error> {
        if password.as_str() == "" {
            Err(Error::EmptyPassword)
        } else {
            let salt = rand::thread_rng().gen::<[u8; SALT_SIZE]>();
            let iv = rand::thread_rng().gen::<[u8; IV_SIZE]>().to_vec().into();

            Ok(Self {
                keypair,
                password,
                kdf: Kdf::Pbkdf2(Pbkdf2 {
                    dklen: DKLEN,
                    c: 262144,
                    prf: Prf::default(),
                    salt: salt.to_vec().into(),
                }),
                cipher: Cipher::Aes128Ctr(Aes128Ctr { iv }),
                uuid: Uuid::new_v4(),
            })
        }
    }

    /// Consumes `self`, returning a `Keystore`.
    pub fn build(self) -> Result<Keystore, Error> {
        Keystore::encrypt(
            self.keypair,
            self.password,
            self.kdf,
            self.cipher,
            self.uuid,
        )
    }
}

/// Provides a BLS keystore as defined in [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335).
///
/// Use `KeystoreBuilder` to create a new keystore.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Keystore {
    json: JsonKeystore,
}

impl Keystore {
    /// Generate `Keystore` object for a BLS12-381 secret key from a
    /// keypair and password.
    fn encrypt(
        keypair: &Keypair,
        password: Password,
        kdf: Kdf,
        cipher: Cipher,
        uuid: Uuid,
    ) -> Result<Self, Error> {
        // Generate derived key
        let derived_key = derive_key(&password, &kdf);

        let secret = PlainText::from(keypair.sk.as_raw().as_bytes());

        // Encrypt secret.
        let cipher_message: Vec<u8> = match &cipher {
            Cipher::Aes128Ctr(params) => {
                // TODO: sanity checks
                // TODO: check IV size
                let mut cipher_text = vec![0; secret.len()];

                crypto::aes::ctr(
                    crypto::aes::KeySize::KeySize128,
                    derived_key.aes_key(),
                    &get_iv(params.iv.as_bytes())?,
                )
                .process(secret.as_bytes(), &mut cipher_text);
                cipher_text
            }
        };

        Ok(Keystore {
            json: JsonKeystore {
                crypto: Crypto {
                    kdf: KdfModule {
                        function: kdf.function(),
                        params: kdf.clone(),
                        message: HexBytes::empty(),
                    },
                    checksum: ChecksumModule {
                        function: Sha256Checksum::function(),
                        params: EmptyMap,
                        message: generate_checksum(&derived_key, &cipher_message),
                    },
                    cipher: CipherModule {
                        function: cipher.function(),
                        params: cipher.clone(),
                        message: cipher_message.into(),
                    },
                },
                uuid,
                // TODO: Implement `path` according to
                // https://github.com/CarlBeek/EIPs/blob/bls_path/EIPS/eip-2334.md
                // For now, `path` is set to en empty string.
                path: String::new(),
                pubkey: keypair.pk.as_hex_string()[2..].to_string(),
                version: Version::four(),
            },
        })
    }

    /// Regenerate a BLS12-381 `Keypair` from `self` and the correct password.
    ///
    /// ## Errors
    ///
    /// - The provided password is incorrect.
    /// - The keystore is badly formed.
    pub fn decrypt_keypair(&self, password: Password) -> Result<Keypair, Error> {
        let cipher_message = &self.json.crypto.cipher.message;

        // Generate derived key
        let derived_key = derive_key(&password, &self.json.crypto.kdf.params);

        // Mismatching checksum indicates an invalid password.
        if generate_checksum(&derived_key, cipher_message.as_bytes())
            != self.json.crypto.checksum.message
        {
            return Err(Error::InvalidPassword);
        }

        let sk_bytes = match &self.json.crypto.cipher.params {
            Cipher::Aes128Ctr(params) => {
                // cipher.decrypt(&derived_key.aes_key(), &cipher_message)
                let mut pt = PlainText::zero(cipher_message.len());
                crypto::aes::ctr(
                    crypto::aes::KeySize::KeySize128,
                    derived_key.aes_key(),
                    &get_iv(&params.iv.as_bytes())?,
                )
                .process(cipher_message.as_bytes(), pt.as_mut_bytes());
                pt
            }
        };

        // Verify that secret key material is correct length.
        if sk_bytes.len() != SECRET_KEY_LEN {
            return Err(Error::InvalidSecretKeyLen {
                len: sk_bytes.len(),
                expected: SECRET_KEY_LEN,
            });
        }

        // Instantiate a `SecretKey`.
        let sk =
            SecretKey::from_bytes(sk_bytes.as_bytes()).map_err(Error::InvalidSecretKeyBytes)?;

        // Derive a `PublicKey` from `SecretKey`.
        let pk = PublicKey::from_secret_key(&sk);

        // Verify that the derived `PublicKey` matches `self`.
        if pk.as_hex_string()[2..].to_string() != self.json.pubkey {
            return Err(Error::PublicKeyMismatch);
        }

        Ok(Keypair { sk, pk })
    }

    /// Returns the UUID for the keystore.
    pub fn uuid(&self) -> &Uuid {
        &self.json.uuid
    }

    /// Returns `self` encoded as a JSON object.
    pub fn to_json_string(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|_| Error::UnableToSerialize)
    }

    /// Returns `self` encoded as a JSON object.
    pub fn from_json_str(json_string: &str) -> Result<Self, Error> {
        serde_json::from_str(json_string).map_err(|e| Error::InvalidJson(format!("{}", e)))
    }
}

/// Generates a checksum to indicate that the `derived_key` is associated with the
/// `cipher_message`.
fn generate_checksum(derived_key: &DerivedKey, cipher_message: &[u8]) -> HexBytes {
    let mut hasher = Sha256::new();
    hasher.input(derived_key.checksum_slice());
    hasher.input(cipher_message);

    let mut digest = vec![0; HASH_SIZE];
    hasher.result(&mut digest);

    digest.into()
}

/// Derive a private key from the given `password` using the given `kdf` (key derivation function).
fn derive_key(password: &Password, kdf: &Kdf) -> DerivedKey {
    let mut dk = DerivedKey::zero();

    match &kdf {
        Kdf::Pbkdf2(params) => {
            let mut mac = params.prf.mac(password.as_bytes());

            crypto::pbkdf2::pbkdf2(
                &mut mac,
                params.salt.as_bytes(),
                params.c,
                dk.as_mut_bytes(),
            );
        }
        Kdf::Scrypt(params) => {
            // Assert that `n` is power of 2
            debug_assert_eq!(params.n, 2u32.pow(log2_int(params.n)));

            crypto::scrypt::scrypt(
                password.as_bytes(),
                params.salt.as_bytes(),
                &crypto::scrypt::ScryptParams::new(log2_int(params.n) as u8, params.r, params.p),
                dk.as_mut_bytes(),
            );
        }
    }

    dk
}

// TODO: what says IV _must_ be 4 bytes?
fn get_iv(bytes: &[u8]) -> Result<[u8; IV_SIZE], Error> {
    if bytes.len() == IV_SIZE {
        let mut iv = [0; IV_SIZE];
        iv.copy_from_slice(bytes);
        Ok(iv)
    } else {
        Err(Error::IncorrectIvSize {
            expected: IV_SIZE,
            len: bytes.len(),
        })
    }
}

/// Compute floor of log2 of a u32.
fn log2_int(x: u32) -> u32 {
    if x == 0 {
        return 0;
    }
    31 - x.leading_zeros()
}
