use bip39::{Language, Mnemonic, MnemonicType, Seed};
use eth2_keystore::{keypair_from_secret, Uuid};
use eth2_wallet::{
    recover_validator_secret_from_mnemonic, DerivedKey, Error, KeyType, PlainText, ValidatorPath,
    Wallet,
};
use num_bigint_dig::{BigInt, BigUint, Sign};
use std::str::FromStr;

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

    let wallet = decode_and_check_seed(&vector);
    assert_eq!(
        *wallet.uuid(),
        Uuid::parse_str("b74559b8-ed56-4841-b25c-dba1b7c9d9d5").unwrap(),
        "uuid"
    );
    assert_eq!(wallet.name(), "Test wallet 2", "name");
    assert_eq!(wallet.nextaccount(), 0, "nextaccount");
    assert_eq!(wallet.type_field(), "hierarchical deterministic", "type");
}

// mnemonic -> seed works
// secret -> pk works
// seed -> secret ???

// https://github.com/ethereum/eth2.0-deposit-cli/blob/4ff0754aed188c6e240e93deb160d070ee656a05/tests/test_key_handling/test_key_derivation/test_vectors/mnemonic.json#L435
#[test]
fn test_mnemonic_to_seed() {
    let test_vector_mnemonic = "scheme laugh excite truth fruit unhappy indoor entry kingdom inch hundred barrel sister rebuild ribbon reflect turn three tattoo speed shift guard defy push";
    let test_vector_seed =   hex::decode("afae9b0db878c462b6b6127dc340427df2cb0f354f2dd35160d019678212b56f3de6fb36957a39def0a3618976b4f46b7baa62cb736479cd164df6bad4ed5a3d").unwrap();
    let test_vector_mnemonic_pw = "TREZOR";

    let phrase_mnemonic = Mnemonic::from_phrase(test_vector_mnemonic, Language::English).unwrap();

    let seed = Seed::new(&phrase_mnemonic, test_vector_mnemonic_pw);
    assert_eq!(test_vector_seed.as_slice(), seed.as_bytes());
}

// https://github.com/ethereum/eth2.0-deposit-cli/blob/4ff0754aed188c6e240e93deb160d070ee656a05/tests/test_key_handling/test_keystore.py#L11
#[test]
fn test_secret_to_pk() {
    let test_vector_secret = PlainText::from(
        hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").unwrap(),
    );
    let test_vector_pk ="0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";

    let keypair = keypair_from_secret(test_vector_secret.as_bytes()).unwrap();
    let pk = keypair.pk.to_hex_string();

    assert_eq!(pk, test_vector_pk);
}

// https://github.com/ethereum/eth2.0-deposit-cli/blob/4ff0754aed188c6e240e93deb160d070ee656a05/tests/test_key_handling/test_key_derivation/test_vectors/tree_kdf.json#L4
#[test]
fn test_seed_to_voting_child_secret() {
    let test_vecto_seed = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
    let test_vector_child_sk =
        "20397789859736650942317412262472558107875392172444076792671091975210932703118";
    let result_plaintext = recover_validator_secret_from_mnemonic(
        hex::decode(test_vecto_seed).unwrap().as_slice(),
        0,
        KeyType::Voting,
    )
    .unwrap();
    let result_str = BigInt::from_bytes_be(Sign::Plus, result_plaintext.0.as_bytes()).to_string();

    assert_eq!(test_vector_child_sk, result_str);
}

// https://github.com/ethereum/eth2.0-deposit-cli/blob/4ff0754aed188c6e240e93deb160d070ee656a05/tests/test_key_handling/test_key_derivation/test_vectors/tree_kdf.json#L4
#[test]
fn test_seed_to_parent_secret() {
    let test_vector_seed = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
    let test_vector_parent_sk =
        "6083874454709270928345386274498605044986640685124978867557563392430687146096";

    let master = DerivedKey::from_seed(hex::decode(test_vector_seed).unwrap().as_slice()).unwrap();
    let result = BigInt::from_bytes_be(Sign::Plus, master.secret()).to_string();

    assert_eq!(test_vector_parent_sk, result);
}
