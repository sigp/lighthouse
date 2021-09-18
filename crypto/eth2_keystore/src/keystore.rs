//! Provides a JSON keystore for a BLS keypair, as specified by
//! [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335).

use crate::derived_key::DerivedKey;
use crate::json_keystore::{
    Aes128Ctr, ChecksumModule, Cipher, CipherModule, Crypto, EmptyMap, EmptyString, JsonKeystore,
    Kdf, KdfModule, Scrypt, Sha256Checksum, Version,
};
use crate::Uuid;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{NewCipher, StreamCipher};
use aes::Aes128Ctr as AesCtr;
use bls::{Keypair, PublicKey, SecretKey, ZeroizeHash};
use eth2_key_derivation::PlainText;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::prelude::*;
use scrypt::{
    errors::{InvalidOutputLen, InvalidParams},
    scrypt, Params as ScryptParams,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::iter::FromIterator;
use std::path::Path;
use std::str;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

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
/// The default iteraction count, `c`, for PBKDF2.
pub const DEFAULT_PBKDF2_C: u32 = 262_144;

/// Provides a new-type wrapper around `String` that is zeroized on `Drop`.
///
/// Useful for ensuring that password memory is zeroed-out on drop.
#[derive(Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
#[serde(transparent)]
struct ZeroizeString(String);

impl From<String> for ZeroizeString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl AsRef<[u8]> for ZeroizeString {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::ops::Deref for ZeroizeString {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ZeroizeString {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromIterator<char> for ZeroizeString {
    fn from_iter<T: IntoIterator<Item = char>>(iter: T) -> Self {
        ZeroizeString(String::from_iter(iter))
    }
}

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidSecretKeyLen { len: usize, expected: usize },
    InvalidPassword,
    InvalidPasswordBytes,
    InvalidSecretKeyBytes(bls::Error),
    PublicKeyMismatch,
    EmptyPassword,
    UnableToSerialize(String),
    InvalidJson(String),
    WriteError(String),
    ReadError(String),
    InvalidPbkdf2Param,
    InvalidScryptParam,
    InvalidSaltLength,
    IncorrectIvSize { expected: usize, len: usize },
    ScryptInvalidParams(InvalidParams),
    ScryptInvaidOutputLen(InvalidOutputLen),
}

/// Constructs a `Keystore`.
pub struct KeystoreBuilder<'a> {
    keypair: &'a Keypair,
    password: &'a [u8],
    kdf: Kdf,
    cipher: Cipher,
    uuid: Uuid,
    path: String,
    description: String,
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
                description: "".to_string(),
            })
        }
    }

    /// Build the keystore with a specific description instead of an empty string.
    pub fn description(mut self, description: String) -> Self {
        self.description = description;
        self
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
            self.description,
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
        description: String,
    ) -> Result<Self, Error> {
        let secret: ZeroizeHash = keypair.sk.serialize();

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
                path: Some(path),
                pubkey: keypair.pk.as_hex_string()[2..].to_string(),
                version: Version::four(),
                description: Some(description),
                name: None,
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
        if keypair.pk.as_hex_string()[2..] != self.json.pubkey {
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
    pub fn path(&self) -> Option<String> {
        self.json.path.clone()
    }

    /// Returns the pubkey for the keystore.
    pub fn pubkey(&self) -> &str {
        &self.json.pubkey
    }

    /// Returns the description for the keystore, if the field is present.
    pub fn description(&self) -> Option<&str> {
        self.json.description.as_deref()
    }

    /// Sets the description for the keystore.
    ///
    /// Note: this does not save the keystore to disk.
    pub fn set_description(&mut self, description: String) {
        self.json.description = Some(description)
    }

    /// Returns the pubkey for the keystore, parsed as a `PublicKey` if it parses.
    pub fn public_key(&self) -> Option<PublicKey> {
        serde_json::from_str(&format!("\"0x{}\"", &self.json.pubkey)).ok()
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

    /// Instantiates `self` by reading a JSON file at `path`.
    pub fn from_json_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(path)
            .map_err(|e| Error::ReadError(format!("{}", e)))
            .and_then(Self::from_json_reader)
    }
}

/// Instantiates a BLS keypair from the given `secret`.
///
/// ## Errors
///
/// - If `secret.len() != 32`.
/// - If `secret` does not represent a point in the BLS curve.
pub fn keypair_from_secret(secret: &[u8]) -> Result<Keypair, Error> {
    let sk = SecretKey::deserialize(secret).map_err(Error::InvalidSecretKeyBytes)?;
    let pk = sk.public_key();
    Ok(Keypair::from_components(pk, sk))
}

/// Returns `Kdf` used by default when creating keystores.
///
/// Currently this is set to scrypt due to its memory hardness properties.
pub fn default_kdf(salt: Vec<u8>) -> Kdf {
    Kdf::Scrypt(Scrypt::default_scrypt(salt))
}

/// Returns `(cipher_text, checksum)` for the given `plain_text` encrypted with `Cipher` using a
/// key derived from `password` via the `Kdf` (key derivation function).
/// Normalizes the password into NFKD form and removes control characters as specified in EIP-2335
/// before encryption.
///
/// ## Errors
///
/// - If `kdf` is badly formed (e.g., has some values set to zero).
pub fn encrypt(
    plain_text: &[u8],
    password: &[u8],
    kdf: &Kdf,
    cipher: &Cipher,
) -> Result<(Vec<u8>, [u8; HASH_SIZE]), Error> {
    validate_parameters(kdf)?;
    let mut password = normalize(password)?;

    password.retain(|c| !is_control_character(c));

    let derived_key = derive_key(password.as_ref(), kdf)?;

    // Encrypt secret.
    let mut cipher_text = plain_text.to_vec();
    match &cipher {
        Cipher::Aes128Ctr(params) => {
            // Validate IV
            validate_aes_iv(params.iv.as_bytes())?;

            // AES Encrypt
            let key = GenericArray::from_slice(&derived_key.as_bytes()[0..16]);
            let nonce = GenericArray::from_slice(params.iv.as_bytes());
            let mut cipher = AesCtr::new(key, nonce);
            cipher.apply_keystream(&mut cipher_text);
        }
    };

    let checksum = generate_checksum(&derived_key, &cipher_text);

    Ok((cipher_text, checksum))
}

/// Regenerate some `plain_text` from the given `password` and `crypto`.
/// Normalizes the password into NFKD form and removes control characters as specified in EIP-2335
/// before decryption.
///
/// ## Errors
///
/// - The provided password is incorrect.
/// - The `crypto.kdf` is badly formed (e.g., has some values set to zero).
pub fn decrypt(password: &[u8], crypto: &Crypto) -> Result<PlainText, Error> {
    let mut password = normalize(password)?;

    password.retain(|c| !is_control_character(c));

    validate_parameters(&crypto.kdf.params)?;

    let cipher_message = &crypto.cipher.message;

    // Generate derived key
    let derived_key = derive_key(password.as_ref(), &crypto.kdf.params)?;

    // Mismatching checksum indicates an invalid password.
    if &generate_checksum(&derived_key, cipher_message.as_bytes())[..]
        != crypto.checksum.message.as_bytes()
    {
        return Err(Error::InvalidPassword);
    }

    let mut plain_text = PlainText::from(cipher_message.as_bytes().to_vec());
    match &crypto.cipher.params {
        Cipher::Aes128Ctr(params) => {
            // Validate IV
            validate_aes_iv(params.iv.as_bytes())?;

            // AES Decrypt
            let key = GenericArray::from_slice(&derived_key.as_bytes()[0..16]);
            let nonce = GenericArray::from_slice(params.iv.as_bytes());
            let mut cipher = AesCtr::new(key, nonce);
            cipher.apply_keystream(plain_text.as_mut_bytes());
        }
    };
    Ok(plain_text)
}

/// Returns true if the given char is a control character as specified by EIP 2335 and false otherwise.
fn is_control_character(c: char) -> bool {
    // Note: The control codes specified in EIP 2335 are same as the unicode control characters.
    // (0x00 to 0x1F) + (0x80 to 0x9F) + 0x7F
    c.is_control()
}

/// Takes a slice of bytes and returns a NFKD normalized string representation.
///
/// Returns an error if the bytes are not valid utf8.
fn normalize(bytes: &[u8]) -> Result<ZeroizeString, Error> {
    Ok(str::from_utf8(bytes)
        .map_err(|_| Error::InvalidPasswordBytes)?
        .nfkd()
        .collect::<ZeroizeString>())
}

/// Generates a checksum to indicate that the `derived_key` is associated with the
/// `cipher_message`.
fn generate_checksum(derived_key: &DerivedKey, cipher_message: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(&derived_key.as_bytes()[16..32]);
    hasher.update(cipher_message);

    let mut digest = [0; HASH_SIZE];
    digest.copy_from_slice(&hasher.finalize());
    digest
}

/// Derive a private key from the given `password` using the given `kdf` (key derivation function).
fn derive_key(password: &[u8], kdf: &Kdf) -> Result<DerivedKey, Error> {
    let mut dk = DerivedKey::zero();

    match &kdf {
        Kdf::Pbkdf2(params) => {
            pbkdf2::<Hmac<Sha256>>(
                password,
                params.salt.as_bytes(),
                params.c,
                dk.as_mut_bytes(),
            );
        }
        Kdf::Scrypt(params) => {
            scrypt(
                password,
                params.salt.as_bytes(),
                &ScryptParams::new(log2_int(params.n) as u8, params.r, params.p)
                    .map_err(Error::ScryptInvalidParams)?,
                dk.as_mut_bytes(),
            )
            .map_err(Error::ScryptInvaidOutputLen)?;
        }
    }

    Ok(dk)
}

// Compute floor of log2 of a u32.
fn log2_int(x: u32) -> u32 {
    if x == 0 {
        return 0;
    }
    31 - x.leading_zeros()
}

// We only check the size of the `iv` is non-zero as there is no guidance about
// this on EIP-2335.
//
// Reference:
//
// - https://github.com/ethereum/EIPs/issues/2339#issuecomment-623865023
fn validate_aes_iv(iv: &[u8]) -> Result<(), Error> {
    if iv.is_empty() {
        return Err(Error::IncorrectIvSize {
            expected: IV_SIZE,
            len: iv.len(),
        });
    } else if iv.len() != IV_SIZE {
        eprintln!(
            "WARN: AES IV length incorrect is {}, should be {}",
            iv.len(),
            IV_SIZE
        );
    }
    Ok(())
}

// Validates the kdf parameters to ensure they are sufficiently secure, in addition to
// preventing DoS attacks from excessively large parameters.
fn validate_parameters(kdf: &Kdf) -> Result<(), Error> {
    match kdf {
        Kdf::Pbkdf2(params) => {
            // We always compute a derived key of 32 bytes so reject anything that
            // says otherwise.
            if params.dklen != DKLEN {
                return Err(Error::InvalidPbkdf2Param);
            }

            // NIST Recommends suggests potential use cases where `c` of 10,000,000 is desireable.
            // As it is 10 years old this has been increased to 80,000,000. Larger values will
            // take over 1 minute to execute on an average machine.
            //
            // Reference:
            //
            // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
            if params.c > 80_000_000 {
                return Err(Error::InvalidPbkdf2Param);
            }

            // RFC2898 declares that `c` must be a "positive integer" and the `crypto` crate panics
            // if it is `0`.
            //
            // Reference:
            //
            // https://www.ietf.org/rfc/rfc2898.txt
            if params.c < DEFAULT_PBKDF2_C {
                if params.c == 0 {
                    return Err(Error::InvalidPbkdf2Param);
                }
                eprintln!(
                    "WARN: PBKDF2 parameters are too weak, 'c' is {}, we recommend using {}",
                    params.c, DEFAULT_PBKDF2_C,
                );
            }

            // Validate `salt` length.
            validate_salt(params.salt.as_bytes())?;

            Ok(())
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
            if params.n <= 1 || params.r == 0 || params.p == 0 {
                return Err(Error::InvalidScryptParam);
            }

            // We always compute a derived key of 32 bytes so reject anything that
            // says otherwise.
            if params.dklen != DKLEN {
                return Err(Error::InvalidScryptParam);
            }

            // Ensure that `n` is power of 2.
            if params.n != 2u32.pow(log2_int(params.n)) {
                return Err(Error::InvalidScryptParam);
            }

            // Maximum Parameters
            //
            // Uses a u32 to store value thus maximum memory usage is 4GB.
            //
            // Note: Memory requirements = 128*n*p*r
            let mut npr: u32 = params
                .n
                .checked_mul(params.p)
                .ok_or(Error::InvalidScryptParam)?;
            npr = npr.checked_mul(params.r).ok_or(Error::InvalidScryptParam)?;
            npr = npr.checked_mul(128).ok_or(Error::InvalidScryptParam)?;

            // Minimum Parameters
            let default_kdf = Scrypt::default_scrypt(vec![0u8; 32]);
            let default_npr = 128 * default_kdf.n * default_kdf.p * default_kdf.r;
            if npr < default_npr {
                eprintln!("WARN: Scrypt parameters are too weak (n: {}, p: {}, r: {}), we recommend (n: {}, p: {}, r: {})", params.n, params.p, params.r, default_kdf.n, default_kdf.p, default_kdf.r);
            }

            // Validate `salt` length.
            validate_salt(params.salt.as_bytes())?;

            Ok(())
        }
    }
}

// Validates that the salt is non-zero in length.
// Emits a warning if the salt is outside reasonable bounds.
fn validate_salt(salt: &[u8]) -> Result<(), Error> {
    // Validate `salt` length
    if salt.is_empty() {
        return Err(Error::InvalidSaltLength);
    } else if salt.len() < SALT_SIZE / 2 {
        eprintln!(
            "WARN: Salt is too short {}, we recommend {}",
            salt.len(),
            SALT_SIZE
        );
    } else if salt.len() > SALT_SIZE * 2 {
        eprintln!(
            "WARN: Salt is too long {}, we recommend {}",
            salt.len(),
            SALT_SIZE
        );
    }
    Ok(())
}
