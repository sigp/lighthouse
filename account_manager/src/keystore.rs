#[cfg(test)]
mod tests {
    use parity_crypto::aes::{decrypt_128_ctr, encrypt_128_ctr};
    use parity_crypto::digest;
    use parity_crypto::pbkdf2::{sha256, Salt, Secret};
    use rand::prelude::*;
    use types::Keypair;

    struct Keystore {
        // Cipher stuff
        pub cipher_message: Vec<u8>,
        pub iv: Vec<u8>,
        // Checksum stuff
        pub checksum: Vec<u8>,
        // kdf stuff
        pub iterations: u32,
        pub dk_len: u32,
        pub salt: Vec<u8>,
    }

    #[test]
    fn test_keystore() {
        let keypair = Keypair::random();
        let password = "bythepowerofgrayskull";
        // Derive decryption key from password
        let iterations = 1000;
        let dk_len = 32;
        let salt = rand::thread_rng().gen::<[u8; 32]>();
        let mut decryption_key = [0; 32];

        // Run the kdf on the password to derive decryption key
        sha256(
            iterations,
            Salt(&salt),
            Secret(password.as_bytes()),
            &mut decryption_key,
        );
        // Encryption params
        let iv = rand::thread_rng().gen::<[u8; 16]>();
        let mut cipher_message = vec![0; 48];
        // Encrypt bls secret key with first 16 bytes as aes key
        encrypt_128_ctr(
            &decryption_key[0..16],
            &iv,
            &keypair.sk.as_raw().as_bytes(),
            &mut cipher_message,
        )
        .unwrap();
        // Generate checksum
        let mut pre_image: Vec<u8> = decryption_key[16..32].to_owned(); // last 16 bytes of decryption key
        pre_image.append(&mut cipher_message.clone());
        let checksum_message: Vec<u8> = digest::sha256(&pre_image).to_owned();

        // Generate keystore
        let keystore = Keystore {
            cipher_message,
            iv: iv.to_owned().to_vec(),
            checksum: checksum_message,
            iterations,
            dk_len,
            salt: salt.to_owned().to_vec(),
        };

        // Regnerate decryption key
        let mut decryption_key1 = [0; 32];
        sha256(
            keystore.iterations,
            Salt(&keystore.salt),
            Secret(password.as_bytes()),
            &mut decryption_key1,
        );
        // Verify checksum
        let mut dk_slice = decryption_key1[16..32].to_owned();
        dk_slice.append(&mut keystore.cipher_message.clone());
        let checksum: Vec<u8> = digest::sha256(&dk_slice).to_owned();
        assert_eq!(checksum, keystore.checksum);

        // Verify receovered sk
        let mut sk = vec![0; 48];
        decrypt_128_ctr(
            &decryption_key[0..16],
            &keystore.iv,
            &keystore.cipher_message,
            &mut sk,
        )
        .unwrap();
        assert_eq!(sk, keypair.sk.as_raw().as_bytes());
    }
}
