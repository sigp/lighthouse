use crate::json_wallet::JsonWallet;
use eth2_keystore::{
    encrypt,
    json_keystore::{Cipher, Kdf},
    Password,
};
use uuid::Uuid;

pub use eth2_keystore::Error;

pub struct Wallet {
    json: JsonWallet,
}

impl Wallet {
    pub fn encrypt(
        seed: &[u8],
        password: Password,
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
                title,
            },
        })
    }
}
