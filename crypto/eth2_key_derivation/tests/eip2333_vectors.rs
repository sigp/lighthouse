#![cfg(test)]

use eth2_key_derivation::DerivedKey;
use num_bigint_dig::BigUint;

/// Contains the test vectors in a format that's easy for us to test against.
struct TestVector {
    seed: Vec<u8>,
    master_sk: Vec<u8>,
    child_index: u32,
    child_sk: Vec<u8>,
}

/// Struct to deal with easy copy-paste from specification test vectors.
struct RawTestVector {
    seed: &'static str,
    master_sk: &'static str,
    child_index: u32,
    child_sk: &'static str,
}

/// Converts from a format that's easy to copy-paste from the spec into a format that's easy to
/// test with.
impl From<RawTestVector> for TestVector {
    fn from(raw: RawTestVector) -> TestVector {
        TestVector {
            seed: hex_to_vec(raw.seed),
            master_sk: int_to_vec(raw.master_sk),
            child_index: raw.child_index,
            child_sk: int_to_vec(raw.child_sk),
        }
    }
}

/// Converts 0x-prefixed hex to bytes.
fn hex_to_vec(hex: &str) -> Vec<u8> {
    hex::decode(&hex[2..]).expect("should decode hex as vec")
}

/// Converts an integer represented as a string to a big-endian byte array.
fn int_to_vec(int_str: &str) -> Vec<u8> {
    BigUint::parse_bytes(int_str.as_bytes(), 10)
        .expect("must be able to parse int")
        .to_bytes_be()
}

/// Asserts that our code matches the given test vector.
fn assert_vector_passes(raw: RawTestVector) {
    let vector: TestVector = raw.into();

    let master = DerivedKey::from_seed(&vector.seed).unwrap();
    assert_eq!(master.secret(), &vector.master_sk[..], "master");

    let child = master.child(vector.child_index);
    assert_eq!(child.secret(), &vector.child_sk[..], "child");
}

/*
 * The following test vectors are obtained from:
 *
 * https://eips.ethereum.org/EIPS/eip-2333
 */

#[test]
fn eip2333_test_case_0() {
    assert_vector_passes(RawTestVector {
        seed: "0xc55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        master_sk: "6083874454709270928345386274498605044986640685124978867557563392430687146096",
        child_index: 0,
        child_sk: "20397789859736650942317412262472558107875392172444076792671091975210932703118",
    })
}

#[test]
fn eip2333_test_case_1() {
    assert_vector_passes(RawTestVector {
        seed: "0x3141592653589793238462643383279502884197169399375105820974944592",
        master_sk: "29757020647961307431480504535336562678282505419141012933316116377660817309383",
        child_index: 3141592653,
        child_sk: "25457201688850691947727629385191704516744796114925897962676248250929345014287",
    })
}

#[test]
fn eip2333_test_case_2() {
    assert_vector_passes(RawTestVector {
        seed: "0x0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00",
        master_sk: "27580842291869792442942448775674722299803720648445448686099262467207037398656",
        child_index: 4294967295,
        child_sk: "29358610794459428860402234341874281240803786294062035874021252734817515685787",
    })
}

#[test]
fn eip2333_test_case_3() {
    assert_vector_passes(RawTestVector {
        seed: "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
        master_sk: "19022158461524446591288038168518313374041767046816487870552872741050760015818",
        child_index: 42,
        child_sk: "31372231650479070279774297061823572166496564838472787488249775572789064611981",
    })
}
