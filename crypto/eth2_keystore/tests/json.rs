#![cfg(test)]

use eth2_keystore::{Error, Keystore};

/// A valid keystore we can mutate to ensure our JSON encoding is strict.
///
/// If this test doesn't pass then it all previous tests are unreliable.
#[test]
fn scrypt_reference() {
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

    assert!(Keystore::from_json_str(vector).is_ok());
}

#[test]
fn pbkdf2_reference() {
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

    assert!(Keystore::from_json_str(vector).is_ok());
}

#[test]
fn additional_top_level_key() {
    let vector = r#"
            {
            "cats": 42,
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

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn additional_cipher_key() {
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
                    "cats": 42,
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

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn additional_checksum_key() {
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
                    "cats": 42,
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

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn additional_kdf_key() {
    let vector = r#"
            {
            "crypto": {
                "kdf": {
                    "cats": 42,
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

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn additional_crypto_key() {
    let vector = r#"
            {
            "crypto": {
                "cats": 42,
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

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn bad_version() {
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
            "version": 5
        }
        "#;

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
#[cfg(not(debug_assertions))]
fn json_bad_checksum() {
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
                    "message": "149aafa27b041f3523c53d7acba1905fa6b1c90f9fef137568101f44b531a3cd"
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

    assert_eq!(
        Keystore::from_json_str(vector)
            .unwrap()
            .decrypt_keypair("testpassword".as_bytes())
            .err()
            .unwrap(),
        Error::InvalidPassword
    );
}

#[test]
fn kdf_function() {
    let vector = r#"
            {
            "crypto": {
                "kdf": {
                    "function": "not-scrypt",
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

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn missing_scrypt_param() {
    let vector = r#"
            {
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": {
                        "dklen": 32,
                        "n": 262144,
                        "p": 1,
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

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn additional_scrypt_param() {
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
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
                        "cats": 42
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

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn checksum_function() {
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
                    "function": "not-sha256",
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

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn checksum_params() {
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
                    "params": {
                        "cats": "lol"
                    },
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

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn kdf_message() {
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
                    "message": "1"
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

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn cipher_function() {
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
                    "function": "not-aes-128-ctr",
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

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn additional_cipher_param() {
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
                        "iv": "264daa3f303d7259501c93d997d84fe6",
                        "cat": 42
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

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn missing_cipher_param() {
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
                    "params": {},
                    "message": "54ecc8863c0550351eee5720f3be6a5d4a016025aa91cd6436cfec938d6a8d30"
                }
            },
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
            "path": "",
            "version": 4
        }
        "#;

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn missing_pubkey() {
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
            "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
            "path": "",
            "version": 4
        }
        "#;

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn missing_path() {
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
            "version": 4
        }
        "#;

    assert!(Keystore::from_json_str(vector).is_ok());
}

#[test]
fn missing_version() {
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
            "path": ""
        }
        "#;

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn pbkdf2_bad_hmac() {
    let vector = r#"
            {
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "dklen": 32,
                        "c": 262144,
                        "prf": "bad-hmac-sha256",
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

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn pbkdf2_additional_parameter() {
    let vector = r#"
            {
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "dklen": 32,
                        "c": 262144,
                        "prf": "hmac-sha256",
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
                        "cats": 42
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

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn pbkdf2_missing_parameter() {
    let vector = r#"
            {
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
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

    match Keystore::from_json_str(vector) {
        Err(Error::InvalidJson(_)) => {}
        _ => panic!("expected invalid json error"),
    }
}

#[test]
fn name_field() {
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
            "version": 4,
            "name": "cats"
        }
        "#;

    assert!(Keystore::from_json_str(vector).is_ok());
}
