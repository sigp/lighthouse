use crate::json_wallet::{
    Aes128Ctr, ChecksumModule, Cipher, CipherModule, Crypto, EmptyMap, EmptyString, JsonWallet,
    Kdf, KdfModule, Sha256Checksum, TypeField, Version,
};
use eth2_keystore::{decrypt, default_kdf, encrypt, IV_SIZE, SALT_SIZE};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use uuid::Uuid;

pub use eth2_keystore::{Error, PlainText};

/// Constructs a `Keystore`.
pub struct WalletBuilder<'a> {
    seed: &'a [u8],
    password: &'a [u8],
    kdf: Kdf,
    cipher: Cipher,
    uuid: Uuid,
    name: String,
    nextaccount: u32,
}

impl<'a> WalletBuilder<'a> {
    /// Creates a new builder.
    ///
    /// Generates the KDF `salt` and AES `IV` using `rand::thread_rng()`.
    ///
    /// ## Errors
    ///
    /// Returns `Error::EmptyPassword` if `password == ""`.
    pub fn from_seed(seed: &'a [u8], password: &'a [u8], name: String) -> Result<Self, Error> {
        if password.is_empty() {
            Err(Error::EmptyPassword)
        } else {
            let salt = rand::thread_rng().gen::<[u8; SALT_SIZE]>();
            let iv = rand::thread_rng().gen::<[u8; IV_SIZE]>().to_vec().into();

            Ok(Self {
                seed,
                password,
                kdf: default_kdf(salt.to_vec()),
                cipher: Cipher::Aes128Ctr(Aes128Ctr { iv }),
                uuid: Uuid::new_v4(),
                nextaccount: 0,
                name,
            })
        }
    }

    /// Consumes `self`, returning a `Wallet`.
    pub fn build(self) -> Result<Wallet, Error> {
        Wallet::encrypt(
            self.seed,
            self.password,
            self.kdf,
            self.cipher,
            self.uuid,
            self.name,
            self.nextaccount,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Wallet {
    json: JsonWallet,
}

impl Wallet {
    fn encrypt(
        seed: &[u8],
        password: &[u8],
        kdf: Kdf,
        cipher: Cipher,
        uuid: Uuid,
        name: String,
        nextaccount: u32,
    ) -> Result<Self, Error> {
        let (cipher_text, checksum) = encrypt(&seed, &password, &kdf, &cipher)?;

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

    pub fn decrypt_seed(&self, password: &[u8]) -> Result<PlainText, Error> {
        decrypt(password, &self.json.crypto)
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
