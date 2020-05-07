use crate::json_wallet::{
    ChecksumModule, Cipher, CipherModule, Crypto, EmptyMap, EmptyString, JsonWallet, Kdf,
    KdfModule, Sha256Checksum, Version,
};
use eth2_keystore::encrypt;
use uuid::Uuid;

pub use eth2_keystore::{Error, Password, PlainText};

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
                nextaccount: 0,
                version: Version::one(),
                name,
            },
        })
    }

    pub fn decrypt_seed(&self, password: &[u8]) -> Result<>
}
