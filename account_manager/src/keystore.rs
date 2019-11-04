use crate::cipher::{Cipher, CipherMessage};
use crate::kdf::Kdf;
use crate::module::CryptoModule;
use crypto::digest::Digest;
use crypto::sha2::Sha256;

#[derive(Debug, PartialEq, Clone)]
pub struct Checksum(String);

impl Checksum {
    pub fn gen_checksum(message: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.input(message);
        hasher.result_str()
    }
}

impl CryptoModule for Checksum {
    type Params = ();

    fn function(&self) -> String {
        "sha256".to_string()
    }

    fn params(&self) -> &Self::Params {
        &()
    }

    fn message(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

/// Crypto
pub struct Crypto<K: Kdf, C: Cipher> {
    /// Key derivation function parameters
    pub kdf: K,
    /// Checksum for password verification
    pub checksum: Checksum,
    /// CipherParams parameters
    pub cipher: CipherMessage<C>,
}

impl<K: Kdf, C: Cipher> Crypto<K, C> {
    pub fn encrypt(password: String, secret: &[u8], kdf: K, cipher: C) -> Self {
        // Generate derived key
        let derived_key = kdf.derive_key(&password);
        // Encrypt secret
        let cipher_message = cipher.encrypt(&derived_key[0..16], secret);

        // Generate checksum
        let mut pre_image: Vec<u8> = derived_key[16..32].to_owned(); // last 16 bytes of decryption key
        pre_image.append(&mut cipher_message.clone());
        let checksum = Checksum::gen_checksum(&pre_image);
        Crypto {
            kdf,
            checksum: Checksum(checksum),
            cipher: CipherMessage {
                cipher,
                message: cipher_message,
            },
        }
    }

    pub fn decrypt(&self, password: String) -> Vec<u8> {
        // Genrate derived key
        let derived_key = self.kdf.derive_key(&password);
        // Regenerate checksum
        let mut pre_image: Vec<u8> = derived_key[16..32].to_owned();
        pre_image.append(&mut self.cipher.message.clone());
        let checksum = Checksum::gen_checksum(&pre_image);
        debug_assert_eq!(checksum, self.checksum.0);
        let secret = self
            .cipher
            .cipher
            .decrypt(&derived_key[0..16], &self.cipher.message);
        return secret;
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use parity_crypto::aes::{decrypt_128_ctr, encrypt_128_ctr};
//     use parity_crypto::digest;
//     use parity_crypto::pbkdf2::{sha256, Salt, Secret};

//     #[test]
//     fn test_vector() {
//         let secret_str = "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d";
//         let salt_str = "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3";
//         let iv_str = "264daa3f303d7259501c93d997d84fe6";
//         let password = "testpassword".to_string();

//         let salt = hex::decode(salt_str).unwrap();
//         // let other = derive_key(password.as_bytes(), &salt, 262144, 1, 8);
//         // println!("{:?}", other);
//         let iv = hex::decode(iv_str).unwrap();
//         let kdf = Scrypt {
//             n: 262144,
//             dklen: 32,
//             p: 1,
//             r: 8,
//             salt: salt.to_vec(),
//         };
//         let dk = kdf.derive_key(&password);
//         println!("Dk {}", hex::encode(dk));
//         // let cipher = Aes128Ctr { iv: iv };
//         // let secret = hex::decode(secret_str).unwrap();
//         // let crypto = Crypto::encrypt(password.clone(), &secret, kdf, cipher);
//         // println!("Cipher is {:?}", hex::encode(crypto.cipher.message.clone()));
//         // println!("Checksum is {:?}", crypto.checksum);
//         // let recovered_secret = crypto.decrypt(password);
//         // let recovered_secret_str = hex::encode(recovered_secret);
//         // println!("Secret is {:?}", recovered_secret_str);
//         // assert_eq!(recovered_secret_str, secret_str);
//     }

//     #[test]
//     fn test_keystore() {
//         let password = "testpassword";
//         let secret_str = "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d";
//         let salt_str = "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19";
//         let iv_str = "264daa3f303d7259501c93d997d84fe6";
//         // Derive decryption key from password
//         let iterations = 262144;
//         let dk_len = 32;
//         let salt = hex::decode(salt_str).unwrap();
//         let mut decryption_key = [0; 32];
//         // Run the kdf on the password to derive decryption key
//         sha256(
//             iterations,
//             Salt(&salt),
//             Secret(password.as_bytes()),
//             &mut decryption_key,
//         );
//         // Encryption params
//         let iv = hex::decode(iv_str).unwrap();
//         let mut cipher_message = vec![0; 48];
//         let secret = hex::decode(secret_str).unwrap();
//         // Encrypt bls secret key with first 16 bytes as aes key
//         encrypt_128_ctr(&decryption_key[0..16], &iv, &secret, &mut cipher_message).unwrap();
//         // Generate checksum
//         let mut pre_image: Vec<u8> = decryption_key[16..32].to_owned(); // last 16 bytes of decryption key
//         pre_image.append(&mut cipher_message.clone());
//         let checksum_message: Vec<u8> = digest::sha256(&pre_image).to_owned();

//         println!("Ciphertext: {}", hex::encode(cipher_message));
//         println!("Checksum: {}", hex::encode(checksum_message));
//     }
// }
