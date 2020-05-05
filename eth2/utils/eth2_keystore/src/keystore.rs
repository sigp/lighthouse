//! Provides a JSON keystore for a BLS keypair, as specified by
//! [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335).

use crate::derived_key::DerivedKey;
use crate::json_keystore::{
    Aes128Ctr, ChecksumModule, Cipher, CipherModule, Crypto, EmptyMap, HexBytes, JsonKeystore, Kdf,
    KdfModule, Pbkdf2, Prf, Sha256Checksum, Version,
};
use crate::plain_text::PlainText;
use crate::Password;
use crate::Uuid;
use bls::{Keypair, PublicKey, SecretKey};
use crypto::{digest::Digest, sha2::Sha256};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use ssz::DecodeError;
use std::io::{Read, Write};

/// The byte-length of a BLS secret key.
const SECRET_KEY_LEN: usize = 32;
/// The default byte length of the salt used to seed the KDF.
///
/// NOTE: there is no clear guidance in EIP-2335 regarding the size of this salt. Neither
/// [pbkdf2](https://www.ietf.org/rfc/rfc2898.txt) or [scrypt](https://tools.ietf.org/html/rfc7914)
/// make a clear statement about what size it should be, however 32-bytes certainly seems
/// reasonable and larger than their examples.
const SALT_SIZE: usize = 32;
/// The length of the derived key.
pub const DKLEN: u32 = 32;
/// Size of the IV (initialization vector) used for aes-128-ctr encryption of private key material.
///
/// NOTE: the EIP-2335 test vectors use a 16-byte IV whilst RFC3868 uses an 8-byte IV. Reference:
///
/// - https://tools.ietf.org/html/rfc3686
/// - https://github.com/ethereum/EIPs/issues/2339#issuecomment-623865023
///
/// I (Paul H) have raised with this Carl B., the author of EIP2335 and await a response.
const IV_SIZE: usize = 16;
/// The byte size of a SHA256 hash.
const HASH_SIZE: usize = 32;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidSecretKeyLen { len: usize, expected: usize },
    InvalidPassword,
    InvalidSecretKeyBytes(DecodeError),
    PublicKeyMismatch,
    EmptyPassword,
    UnableToSerialize(String),
    InvalidJson(String),
    WriteError(String),
    ReadError(String),
    IncorrectIvSize { expected: usize, len: usize },
}

/// Constructs a `Keystore`.
pub struct KeystoreBuilder<'a> {
    keypair: &'a Keypair,
    password: Password,
    kdf: Kdf,
    cipher: Cipher,
    uuid: Uuid,
    path: String,
}

impl<'a> KeystoreBuilder<'a> {
    /// Creates a new builder.
    ///
    /// ## Errors
    ///
    /// Returns `Error::EmptyPassword` if `password == ""`.
    pub fn new(keypair: &'a Keypair, password: Password, path: String) -> Result<Self, Error> {
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
                path,
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
            self.path,
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
        path: String,
    ) -> Result<Self, Error> {
        let derived_key = derive_key(&password, &kdf);

        let secret = PlainText::from(keypair.sk.as_raw().as_bytes());

        // Encrypt secret.
        let mut cipher_text = vec![0; secret.len()];
        match &cipher {
            Cipher::Aes128Ctr(params) => {
                crypto::aes::ctr(
                    crypto::aes::KeySize::KeySize128,
                    &derived_key.as_bytes()[0..16],
                    params.iv.as_bytes(),
                )
                .process(secret.as_bytes(), &mut cipher_text);
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
                        message: generate_checksum(&derived_key, &cipher_text),
                    },
                    cipher: CipherModule {
                        function: cipher.function(),
                        params: cipher.clone(),
                        message: cipher_text.into(),
                    },
                },
                uuid,
                path,
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

        let mut plain_text = PlainText::zero(cipher_message.len());
        match &self.json.crypto.cipher.params {
            Cipher::Aes128Ctr(params) => {
                crypto::aes::ctr(
                    crypto::aes::KeySize::KeySize128,
                    &derived_key.as_bytes()[0..16],
                    // NOTE: we do not check the size of the `iv` as there is no guidance about
                    // this on EIP-2335.
                    //
                    // Reference:
                    //
                    // - https://github.com/ethereum/EIPs/issues/2339#issuecomment-623865023
                    params.iv.as_bytes(),
                )
                .process(cipher_message.as_bytes(), plain_text.as_mut_bytes());
            }
        };

        // Verify that secret key material is correct length.
        if plain_text.len() != SECRET_KEY_LEN {
            return Err(Error::InvalidSecretKeyLen {
                len: plain_text.len(),
                expected: SECRET_KEY_LEN,
            });
        }

        // Instantiate a `SecretKey`.
        let sk =
            SecretKey::from_bytes(plain_text.as_bytes()).map_err(Error::InvalidSecretKeyBytes)?;

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

    /// Encodes `self` as a JSON object.
    pub fn to_json_string(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|e| Error::UnableToSerialize(format!("{}", e)))
    }

    /// Returns `self` encoded as a JSON object.
    pub fn from_json_str(json_string: &str) -> Result<Self, Error> {
        serde_json::from_str(json_string).map_err(|e| Error::InvalidJson(format!("{}", e)))
    }

    /// Encodes self as a JSON object to the given `writer`.
    pub fn to_json_writer<W: Write>(&self, writer: W) -> Result<(), Error> {
        serde_json::to_writer(writer, self).map_err(|e| Error::WriteError(format!("{}", e)))
    }

    /// Instantiates `self` from a JSON `reader`.
    pub fn from_json_reader<R: Read>(reader: R) -> Result<Self, Error> {
        serde_json::from_reader(reader).map_err(|e| Error::ReadError(format!("{}", e)))
    }
}

/// Generates a checksum to indicate that the `derived_key` is associated with the
/// `cipher_message`.
fn generate_checksum(derived_key: &DerivedKey, cipher_message: &[u8]) -> HexBytes {
    let mut hasher = Sha256::new();
    hasher.input(&derived_key.as_bytes()[16..32]);
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

/// Compute floor of log2 of a u32.
fn log2_int(x: u32) -> u32 {
    if x == 0 {
        return 0;
    }
    31 - x.leading_zeros()
}
