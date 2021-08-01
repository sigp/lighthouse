use eth2_wallet::{Error, KeystoreError, Wallet};

fn assert_bad_json(json: &str) {
    match Wallet::from_json_str(json) {
        Err(Error::KeystoreError(KeystoreError::InvalidJson(_))) => {}
        _ => panic!("expected invalid json error"),
    }
}

/*
 * Note: the `crypto` object is inherited from the `eth2_keystore` crate so we don't test it here.
 */

#[test]
fn additional_top_level_param() {
    let vector = r#"
	{
	  "crypto": {
	    "checksum": {
	      "function": "sha256",
	      "message": "8bdadea203eeaf8f23c96137af176ded4b098773410634727bd81c4e8f7f1021",
	      "params": {}
	    },
	    "cipher": {
	      "function": "aes-128-ctr",
	      "message": "7f8211b88dfb8694bac7de3fa32f5f84d0a30f15563358133cda3b287e0f3f4a",
	      "params": {
		"iv": "9476702ab99beff3e8012eff49ffb60d"
	      }
	    },
	    "kdf": {
	      "function": "pbkdf2",
	      "message": "",
	      "params": {
		"c": 16,
		"dklen": 32,
		"prf": "hmac-sha256",
		"salt": "dd35b0c08ebb672fe18832120a55cb8098f428306bf5820f5486b514f61eb712"
	      }
	    }
	  },
	  "name": "Test wallet 2",
	  "nextaccount": 0,
	  "type": "hierarchical deterministic",
	  "uuid": "b74559b8-ed56-4841-b25c-dba1b7c9d9d5",
	  "version": 1,
	  "cats": 42
	}
        "#;

    assert_bad_json(vector);
}

#[test]
fn missing_top_level_param() {
    let vector = r#"
	{
	  "crypto": {
	    "checksum": {
	      "function": "sha256",
	      "message": "8bdadea203eeaf8f23c96137af176ded4b098773410634727bd81c4e8f7f1021",
	      "params": {}
	    },
	    "cipher": {
	      "function": "aes-128-ctr",
	      "message": "7f8211b88dfb8694bac7de3fa32f5f84d0a30f15563358133cda3b287e0f3f4a",
	      "params": {
		"iv": "9476702ab99beff3e8012eff49ffb60d"
	      }
	    },
	    "kdf": {
	      "function": "pbkdf2",
	      "message": "",
	      "params": {
		"c": 16,
		"dklen": 32,
		"prf": "hmac-sha256",
		"salt": "dd35b0c08ebb672fe18832120a55cb8098f428306bf5820f5486b514f61eb712"
	      }
	    }
	  },
	  "name": "Test wallet 2",
	  "nextaccount": 0,
	  "type": "hierarchical deterministic",
	  "uuid": "b74559b8-ed56-4841-b25c-dba1b7c9d9d5"
	}
        "#;

    assert_bad_json(vector);
}

#[test]
fn bad_version() {
    let vector = r#"
	{
	  "crypto": {
	    "checksum": {
	      "function": "sha256",
	      "message": "8bdadea203eeaf8f23c96137af176ded4b098773410634727bd81c4e8f7f1021",
	      "params": {}
	    },
	    "cipher": {
	      "function": "aes-128-ctr",
	      "message": "7f8211b88dfb8694bac7de3fa32f5f84d0a30f15563358133cda3b287e0f3f4a",
	      "params": {
		"iv": "9476702ab99beff3e8012eff49ffb60d"
	      }
	    },
	    "kdf": {
	      "function": "pbkdf2",
	      "message": "",
	      "params": {
		"c": 16,
		"dklen": 32,
		"prf": "hmac-sha256",
		"salt": "dd35b0c08ebb672fe18832120a55cb8098f428306bf5820f5486b514f61eb712"
	      }
	    }
	  },
	  "name": "Test wallet 2",
	  "nextaccount": 0,
	  "type": "hierarchical deterministic",
	  "uuid": "b74559b8-ed56-4841-b25c-dba1b7c9d9d5",
	  "version": 2
	}
        "#;

    assert_bad_json(vector);
}

#[test]
fn bad_uuid() {
    let vector = r#"
	{
	  "crypto": {
	    "checksum": {
	      "function": "sha256",
	      "message": "8bdadea203eeaf8f23c96137af176ded4b098773410634727bd81c4e8f7f1021",
	      "params": {}
	    },
	    "cipher": {
	      "function": "aes-128-ctr",
	      "message": "7f8211b88dfb8694bac7de3fa32f5f84d0a30f15563358133cda3b287e0f3f4a",
	      "params": {
		"iv": "9476702ab99beff3e8012eff49ffb60d"
	      }
	    },
	    "kdf": {
	      "function": "pbkdf2",
	      "message": "",
	      "params": {
		"c": 16,
		"dklen": 32,
		"prf": "hmac-sha256",
		"salt": "dd35b0c08ebb672fe18832120a55cb8098f428306bf5820f5486b514f61eb712"
	      }
	    }
	  },
	  "name": "Test wallet 2",
	  "nextaccount": 0,
	  "type": "hierarchical deterministic",
	  "uuid": "!b74559b8-ed56-4841-b25c-dba1b7c9d9d5",
	  "version": 1
	}
        "#;

    assert_bad_json(vector);
}

#[test]
fn bad_type() {
    let vector = r#"
	{
	  "crypto": {
	    "checksum": {
	      "function": "sha256",
	      "message": "8bdadea203eeaf8f23c96137af176ded4b098773410634727bd81c4e8f7f1021",
	      "params": {}
	    },
	    "cipher": {
	      "function": "aes-128-ctr",
	      "message": "7f8211b88dfb8694bac7de3fa32f5f84d0a30f15563358133cda3b287e0f3f4a",
	      "params": {
		"iv": "9476702ab99beff3e8012eff49ffb60d"
	      }
	    },
	    "kdf": {
	      "function": "pbkdf2",
	      "message": "",
	      "params": {
		"c": 16,
		"dklen": 32,
		"prf": "hmac-sha256",
		"salt": "dd35b0c08ebb672fe18832120a55cb8098f428306bf5820f5486b514f61eb712"
	      }
	    }
	  },
	  "name": "Test wallet 2",
	  "nextaccount": 0,
	  "type": "something else",
	  "uuid": "b74559b8-ed56-4841-b25c-dba1b7c9d9d5",
	  "version": 1
	}
        "#;

    assert_bad_json(vector);
}

#[test]
fn more_that_u32_nextaccount() {
    let vector = r#"
	{
	  "crypto": {
	    "checksum": {
	      "function": "sha256",
	      "message": "8bdadea203eeaf8f23c96137af176ded4b098773410634727bd81c4e8f7f1021",
	      "params": {}
	    },
	    "cipher": {
	      "function": "aes-128-ctr",
	      "message": "7f8211b88dfb8694bac7de3fa32f5f84d0a30f15563358133cda3b287e0f3f4a",
	      "params": {
		"iv": "9476702ab99beff3e8012eff49ffb60d"
	      }
	    },
	    "kdf": {
	      "function": "pbkdf2",
	      "message": "",
	      "params": {
		"c": 16,
		"dklen": 32,
		"prf": "hmac-sha256",
		"salt": "dd35b0c08ebb672fe18832120a55cb8098f428306bf5820f5486b514f61eb712"
	      }
	    }
	  },
	  "name": "Test wallet 2",
	  "nextaccount": 4294967297,
	  "type": "hierarchical deterministic",
	  "uuid": "b74559b8-ed56-4841-b25c-dba1b7c9d9d5",
	  "version": 1
	}
        "#;

    assert_bad_json(vector);
}
