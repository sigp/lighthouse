use eth2_keystore::Uuid;
use eth2_wallet::Wallet;

const EXPECTED_SECRET: &str = "147addc7ec981eb2715a22603813271cce540e0b7f577126011eb06249d9227c";
const PASSWORD: &str = "testpassword";

pub fn decode_and_check_seed(json: &str) -> Wallet {
    let wallet = Wallet::from_json_str(json).expect("should decode keystore json");
    let expected_sk = hex::decode(EXPECTED_SECRET).unwrap();
    let seed = wallet.decrypt_seed(PASSWORD.as_bytes()).unwrap();
    assert_eq!(seed.as_bytes(), &expected_sk[..]);
    wallet
}

#[test]
fn eip2386_test_vector_scrypt() {
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
	  "version": 1
	}
        "#;

    let wallet = decode_and_check_seed(vector);
    assert_eq!(
        *wallet.uuid(),
        Uuid::parse_str("b74559b8-ed56-4841-b25c-dba1b7c9d9d5").unwrap(),
        "uuid"
    );
    assert_eq!(wallet.name(), "Test wallet 2", "name");
    assert_eq!(wallet.nextaccount(), 0, "nextaccount");
    assert_eq!(wallet.type_field(), "hierarchical deterministic", "type");
}
