//! Test cases taken from:
//!
//! https://eips.ethereum.org/EIPS/eip-2335

#![cfg(test)]
#![cfg(not(debug_assertions))]

use eth2_keystore::{Keystore, Uuid};

const EXPECTED_SECRET: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
const PASSWORD: &str = "testpassword";

pub fn decode_and_check_sk(json: &str) -> Keystore {
    let keystore = Keystore::from_json_str(json).expect("should decode keystore json");
    let expected_sk = hex::decode(EXPECTED_SECRET).unwrap();
    let keypair = keystore.decrypt_keypair(PASSWORD.as_bytes()).unwrap();
    assert_eq!(
        format!("0x{}", keystore.pubkey()),
        format!("{:?}", keystore.public_key().unwrap())
    );
    assert_eq!(keypair.sk.serialize().as_ref(), &expected_sk[..]);
    keystore
}

#[test]
fn eip2335_test_vector_scrypt() {
    let vector = r#"
            {
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": {
                        "dklen": 32,
                        "n": 262144,
                        "p": 1,
                        "r": 8,
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "149aafa27b041f3523c53d7acba1905fa6b1c90f9fef137568101f44b531a3cb"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "54ecc8863c0550351eee5720f3be6a5d4a016025aa91cd6436cfec938d6a8d30"
                }
            },
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
            "path": "",
            "version": 4
        }
        "#;

    let keystore = decode_and_check_sk(&vector);
    assert_eq!(
        *keystore.uuid(),
        Uuid::parse_str("1d85ae20-35c5-4611-98e8-aa14a633906f").unwrap(),
        "uuid"
    );
    assert_eq!(keystore.path().unwrap(), "", "path");
}

#[test]
fn eip2335_test_vector_pbkdf() {
    let vector = r#"
            {
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "dklen": 32,
                        "c": 262144,
                        "prf": "hmac-sha256",
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "18b148af8e52920318084560fd766f9d09587b4915258dec0676cba5b0da09d8"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "a9249e0ca7315836356e4c7440361ff22b9fe71e2e2ed34fc1eb03976924ed48"
                }
            },
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "path": "m/12381/60/0/0",
            "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
            "version": 4
        }
        "#;

    let keystore = decode_and_check_sk(&vector);
    assert_eq!(
        *keystore.uuid(),
        Uuid::parse_str("64625def-3331-4eea-ab6f-782f3ed16a83").unwrap(),
        "uuid"
    );
    assert_eq!(keystore.path().unwrap(), "m/12381/60/0/0", "path");
}
