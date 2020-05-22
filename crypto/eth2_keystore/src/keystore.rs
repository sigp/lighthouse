//! Provides a JSON keystore for a BLS keypair, as specified by
//! [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335).

use crate::derived_key::DerivedKey;
use crate::json_keystore::{
    Aes128Ctr, ChecksumModule, Cipher, CipherModule, Crypto, EmptyMap, EmptyString, JsonKeystore,
    Kdf, KdfModule, Scrypt, Sha256Checksum, Version,
};
use crate::PlainText;
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
/// reasonable and larger than the EITF examples.
pub const SALT_SIZE: usize = 32;
/// The length of the derived key.
pub const DKLEN: u32 = 32;
/// Size of the IV (initialization vector) used for aes-128-ctr encryption of private key material.
///
/// NOTE: the EIP-2335 test vectors use a 16-byte IV whilst RFC3868 uses an 8-byte IV. Reference:
///
/// - https://tools.ietf.org/html/rfc3686
/// - https://github.com/ethereum/EIPs/issues/2339#issuecomment-623865023
///
/// Comment from Carl B, author of EIP-2335:
///
/// AES CTR IV's should be the same length as the internal blocks in my understanding. (The IV is
/// the first block input.)
///
/// As far as I know, AES-128-CTR is not defined by the IETF, but by NIST in SP800-38A.
/// (https://csrc.nist.gov/publications/detail/sp/800-38a/final) The test vectors in this standard
/// are 16 bytes.
pub const IV_SIZE: usize = 16;
/// The byte size of a SHA256 hash.
pub const HASH_SIZE: usize = 32;

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
    InvalidPbkdf2Param,
    InvalidScryptParam,
    IncorrectIvSize { expected: usize, len: usize },
}

/// Constructs a `Keystore`.
pub struct KeystoreBuilder<'a> {
    keypair: &'a Keypair,
    password: &'a [u8],
    kdf: Kdf,
    cipher: Cipher,
    uuid: Uuid,
    path: String,
}

impl<'a> KeystoreBuilder<'a> {
    /// Creates a new builder.
    ///
    /// Generates the KDF `salt` and AES `IV` using `rand::thread_rng()`.
    ///
    /// ## Errors
    ///
    /// Returns `Error::EmptyPassword` if `password == ""`.
    pub fn new(keypair: &'a Keypair, password: &'a [u8], path: String) -> Result<Self, Error> {
        if password.is_empty() {
            Err(Error::EmptyPassword)
        } else {
            let salt = rand::thread_rng().gen::<[u8; SALT_SIZE]>();
            let iv = rand::thread_rng().gen::<[u8; IV_SIZE]>().to_vec().into();

            Ok(Self {
                keypair,
                password,
                kdf: default_kdf(salt.to_vec()),
                cipher: Cipher::Aes128Ctr(Aes128Ctr { iv }),
                uuid: Uuid::new_v4(),
                path,
            })
        }
    }

    /// Build the keystore using the supplied `kdf` instead of `crate::default_kdf`.
    pub fn kdf(mut self, kdf: Kdf) -> Self {
        self.kdf = kdf;
        self
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
        password: &[u8],
        kdf: Kdf,
        cipher: Cipher,
        uuid: Uuid,
        path: String,
    ) -> Result<Self, Error> {
        let secret: PlainText = keypair.sk.as_bytes();

        let (cipher_text, checksum) = encrypt(secret.as_bytes(), password, &kdf, &cipher)?;

        Ok(Keystore {
            json: JsonKeystore {
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
    ///
    /// ## Panics
    ///
    /// May panic if provided unreasonable crypto parameters.
    pub fn decrypt_keypair(&self, password: &[u8]) -> Result<Keypair, Error> {
        let plain_text = decrypt(password, &self.json.crypto)?;

        // Verify that secret key material is correct length.
        if plain_text.len() != SECRET_KEY_LEN {
            return Err(Error::InvalidSecretKeyLen {
                len: plain_text.len(),
                expected: SECRET_KEY_LEN,
            });
        }

        let keypair = keypair_from_secret(plain_text.as_bytes())?;
        // Verify that the derived `PublicKey` matches `self`.
        if keypair.pk.as_hex_string()[2..].to_string() != self.json.pubkey {
            return Err(Error::PublicKeyMismatch);
        }

        Ok(keypair)
    }

    /// Returns the UUID for the keystore.
    pub fn uuid(&self) -> &Uuid {
        &self.json.uuid
    }

    /// Returns the path for the keystore.
    ///
    /// Note: the path is not validated, it is simply whatever string the keystore provided.
    pub fn path(&self) -> &str {
        &self.json.path
    }

    /// Returns the pubkey for the keystore.
    pub fn pubkey(&self) -> &str {
        &self.json.pubkey
    }

    /// Returns the key derivation function for the keystore.
    pub fn kdf(&self) -> &Kdf {
        &self.json.crypto.kdf.params
    }

    /// Encodes `self` as a JSON object.
    pub fn to_json_string(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|e| Error::UnableToSerialize(format!("{}", e)))
    }

    /// Returns `self` from an encoded JSON object.
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

/// Instantiates a BLS keypair from the given `secret`.
///
/// ## Errors
///
/// - If `secret.len() != 32`.
/// - If `secret` does not represent a point in the BLS curve.
pub fn keypair_from_secret(secret: &[u8]) -> Result<Keypair, Error> {
    let sk = SecretKey::from_bytes(secret).map_err(Error::InvalidSecretKeyBytes)?;
    let pk = PublicKey::from_secret_key(&sk);
    Ok(Keypair { sk, pk })
}

/// Returns `Kdf` used by default when creating keystores.
///
/// Currently this is set to scrypt due to its memory hardness properties.
pub fn default_kdf(salt: Vec<u8>) -> Kdf {
    Kdf::Scrypt(Scrypt {
        dklen: DKLEN,
        n: 262144,
        p: 1,
        r: 8,
        salt: salt.into(),
    })
}

/// Returns `(cipher_text, checksum)` for the given `plain_text` encrypted with `Cipher` using a
/// key derived from `password` via the `Kdf` (key derivation function).
///
/// ## Errors
///
/// - The `kdf` is badly formed (e.g., has some values set to zero).
pub fn encrypt(
    plain_text: &[u8],
    password: &[u8],
    kdf: &Kdf,
    cipher: &Cipher,
) -> Result<(Vec<u8>, [u8; HASH_SIZE]), Error> {
    let derived_key = derive_key(&password, &kdf)?;

    // Encrypt secret.
    let mut cipher_text = vec![0; plain_text.len()];
    match &cipher {
        Cipher::Aes128Ctr(params) => {
            crypto::aes::ctr(
                crypto::aes::KeySize::KeySize128,
                &derived_key.as_bytes()[0..16],
                params.iv.as_bytes(),
            )
            .process(plain_text, &mut cipher_text);
        }
    };

    let checksum = generate_checksum(&derived_key, &cipher_text);

    Ok((cipher_text, checksum))
}

/// Regenerate some `plain_text` from the given `password` and `crypto`.
///
/// ## Errors
///
/// - The provided password is incorrect.
/// - The `crypto.kdf` is badly formed (e.g., has some values set to zero).
pub fn decrypt(password: &[u8], crypto: &Crypto) -> Result<PlainText, Error> {
    let cipher_message = &crypto.cipher.message;

    // Generate derived key
    let derived_key = derive_key(password, &crypto.kdf.params)?;

    // Mismatching checksum indicates an invalid password.
    if &generate_checksum(&derived_key, cipher_message.as_bytes())[..]
        != crypto.checksum.message.as_bytes()
    {
        return Err(Error::InvalidPassword);
    }

    let mut plain_text = PlainText::zero(cipher_message.len());
    match &crypto.cipher.params {
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
    Ok(plain_text)
}

/// Generates a checksum to indicate that the `derived_key` is associated with the
/// `cipher_message`.
fn generate_checksum(derived_key: &DerivedKey, cipher_message: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.input(&derived_key.as_bytes()[16..32]);
    hasher.input(cipher_message);

    let mut digest = [0; HASH_SIZE];
    hasher.result(&mut digest);
    digest
}

/// Derive a private key from the given `password` using the given `kdf` (key derivation function).
fn derive_key(password: &[u8], kdf: &Kdf) -> Result<DerivedKey, Error> {
    let mut dk = DerivedKey::zero();

    match &kdf {
        Kdf::Pbkdf2(params) => {
            let mut mac = params.prf.mac(password);

            // RFC2898 declares that `c` must be a "positive integer" and the `crypto` crate panics
            // if it is `0`.
            //
            // Both of these seem fairly convincing that it shouldn't be 0.
            //
            // Reference:
            //
            // https://www.ietf.org/rfc/rfc2898.txt
            //
            // Additionally, we always compute a derived key of 32 bytes so reject anything that
            // says otherwise.
            if params.c == 0 || params.dklen != DKLEN {
                return Err(Error::InvalidPbkdf2Param);
            }

            crypto::pbkdf2::pbkdf2(
                &mut mac,
                params.salt.as_bytes(),
                params.c,
                dk.as_mut_bytes(),
            );
        }
        Kdf::Scrypt(params) => {
            // RFC7914 declares that all these parameters must be greater than 1:
            //
            // - `N`: costParameter.
            // - `r`: blockSize.
            // - `p`: parallelizationParameter
            //
            // Reference:
            //
            // https://tools.ietf.org/html/rfc7914
            //
            // Additionally, we always compute a derived key of 32 bytes so reject anything that
            // says otherwise.
            if params.n <= 1 || params.r == 0 || params.p == 0 || params.dklen != DKLEN {
                return Err(Error::InvalidScryptParam);
            }

            // Ensure that `n` is power of 2.
            if params.n != 2u32.pow(log2_int(params.n)) {
                return Err(Error::InvalidScryptParam);
            }

            crypto::scrypt::scrypt(
                password,
                params.salt.as_bytes(),
                &crypto::scrypt::ScryptParams::new(log2_int(params.n) as u8, params.r, params.p),
                dk.as_mut_bytes(),
            );
        }
    }

    Ok(dk)
}

/// Compute floor of log2 of a u32.
fn log2_int(x: u32) -> u32 {
    if x == 0 {
        return 0;
    }
    31 - x.leading_zeros()
}
