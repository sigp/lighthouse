use crate::{lamport_secret_key::LamportSecretKey, secret_bytes::SecretBytes, SecretHash};
use num_bigint_dig::BigUint;
use ring::hkdf::{KeyType, Prk, Salt, HKDF_SHA256};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// The byte size of a SHA256 hash.
pub const HASH_SIZE: usize = 32;

/// The size of the lamport array.
///
/// Indirectly defined in EIP-2333.
pub const LAMPORT_ARRAY_SIZE: u8 = 255;

/// The order of the BLS 12-381 curve.
///
/// Defined in EIP-2333.
pub const R: &str = "52435875175126190479447740508185965837690552500527637822603658699938581184513";

/// The `L` value used in the `hdkf_mod_r` function.
///
/// In EIP-2333 this value is defined as:
///
/// `ceil((1.5 * ceil(log2(r))) / 8)`
pub const MOD_R_L: usize = 48;

/// A BLS secret key that is derived from some `seed`, or generated as a child from some other
/// `DerivedKey`.
///
/// Implements `Zeroize` on `Drop`.
// It's not strictly necessary that `DerivedKey` implements `Zeroize`, but it seems prudent to be a
// little over-cautious here; we don't require high-speed key generation at this stage.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DerivedKey(SecretHash);

impl DerivedKey {
    /// Instantiates `Self` from some secret seed bytes.
    ///
    /// The key is generated deterministically; the same `seed` will always return the same `Self`.
    ///
    /// ## Errors
    ///
    /// Returns `Err(())` if `seed.is_empty()`, otherwise always returns `Ok(self)`.
    pub fn from_seed(seed: &[u8]) -> Result<Self, ()> {
        if seed.is_empty() {
            Err(())
        } else {
            Ok(Self(derive_master_sk(seed)))
        }
    }

    /// Derives a child key from the secret `Self` at some `index`.
    pub fn child(&self, index: u32) -> DerivedKey {
        Self(derive_child_sk(self.0.as_bytes(), index))
    }

    /// Returns the secret BLS key in `self`.
    pub fn secret(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Derives the "master" BLS secret key from some `seed` bytes.
///
/// Equivalent to `derive_master_SK` in EIP-2333.
fn derive_master_sk(seed: &[u8]) -> SecretHash {
    hkdf_mod_r(seed)
}

/// From the given `parent_sk`, derives a child key at index`.
///
/// Equivalent to `derive_child_SK` in EIP-2333.
fn derive_child_sk(parent_sk: &[u8], index: u32) -> SecretHash {
    let compressed_lamport_pk = parent_sk_to_lamport_pk(parent_sk, index);
    hkdf_mod_r(compressed_lamport_pk.as_bytes())
}

/// From the `ikm` (initial key material), performs a HKDF-Extract and HKDF-Expand to generate a
/// BLS private key within the order of the BLS-381 curve.
///
/// Equivalent to `HKDF_mod_r` in EIP-2333.
fn hkdf_mod_r(ikm: &[u8]) -> SecretHash {
    let prk = hkdf_extract(b"BLS-SIG-KEYGEN-SALT-", ikm);
    let okm = &hkdf_expand(prk, MOD_R_L);
    mod_r(okm.as_bytes())
}

/// Interprets `bytes` as a big-endian integer and returns that integer modulo the order of the
/// BLS-381 curve.
///
/// This function is a part of the `HKDF_mod_r` function in EIP-2333.
fn mod_r(bytes: &[u8]) -> SecretHash {
    let n = BigUint::from_bytes_be(bytes);
    let r = BigUint::parse_bytes(R.as_bytes(), 10).expect("must be able to parse R");
    let x = SecretBytes::from((n % r).to_bytes_be());

    let x_slice = x.as_bytes();

    debug_assert!(x_slice.len() <= HASH_SIZE);

    let mut output = SecretHash::zero();
    output.as_mut_bytes()[HASH_SIZE - x_slice.len()..].copy_from_slice(&x_slice);
    output
}

/// Generates a Lamport public key from the given `ikm` (which is assumed to be a BLS secret key).
///
/// Equivalent to `parent_SK_to_lamport_PK` in EIP-2333.
fn parent_sk_to_lamport_pk(ikm: &[u8], index: u32) -> SecretHash {
    let salt = index.to_be_bytes();
    let not_ikm = flip_bits(ikm);

    let lamports = [
        ikm_to_lamport_sk(&salt, ikm),
        ikm_to_lamport_sk(&salt, not_ikm.as_bytes()),
    ];

    let mut lamport_pk = SecretBytes::zero(HASH_SIZE * LAMPORT_ARRAY_SIZE as usize * 2);
    let pk_bytes = lamport_pk.as_mut_bytes();

    lamports
        .iter()
        .map(LamportSecretKey::iter_chunks)
        .flatten()
        .enumerate()
        .for_each(|(i, chunk)| {
            let mut hasher = Sha256::new();
            hasher.update(chunk);
            pk_bytes[i * HASH_SIZE..(i + 1) * HASH_SIZE].copy_from_slice(&hasher.finalize());
        });

    let mut compressed_lamport_pk = SecretHash::zero();
    let mut hasher = Sha256::new();
    hasher.update(lamport_pk.as_bytes());
    compressed_lamport_pk
        .as_mut_bytes()
        .copy_from_slice(&hasher.finalize());

    compressed_lamport_pk
}

/// Generates a Lamport secret key from the `ikm` (initial key material).
///
/// Equivalent to `IKM_to_lamport_SK` in EIP-2333.
fn ikm_to_lamport_sk(salt: &[u8], ikm: &[u8]) -> LamportSecretKey {
    let prk = hkdf_extract(salt, ikm);
    let okm = hkdf_expand(prk, HASH_SIZE * LAMPORT_ARRAY_SIZE as usize);
    LamportSecretKey::from_bytes(okm.as_bytes())
}

/// Peforms a `HKDF-Extract` on the `ikm` (initial key material) based up on the `salt`.
///
/// Defined in [RFC5869](https://tools.ietf.org/html/rfc5869).
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Prk {
    Salt::new(HKDF_SHA256, salt).extract(ikm)
}

/// Peforms a `HKDF-Expand` on the `pkr` (pseudo-random key), returning `l` bytes.
///
/// Defined in [RFC5869](https://tools.ietf.org/html/rfc5869).
fn hkdf_expand(prk: Prk, l: usize) -> SecretBytes {
    struct ExpandLen(usize);

    impl KeyType for ExpandLen {
        fn len(&self) -> usize {
            self.0
        }
    }

    let mut okm = SecretBytes::zero(l);
    prk.expand(&[], ExpandLen(l))
        .expect("expand len is constant and cannot be too large")
        .fill(okm.as_mut_bytes())
        .expect("fill len is constant and cannot be too large");
    okm
}

/// Flips each bit in the `input`.
///
/// Equivalent to `flip_bits` in EIP-2333.
///
/// ## Panics
///
/// If `input` is not 32-bytes.
fn flip_bits(input: &[u8]) -> SecretHash {
    assert_eq!(input.len(), HASH_SIZE);

    let mut output = SecretHash::zero();
    let output_bytes = output.as_mut_bytes();

    for (i, byte) in input.iter().enumerate() {
        output_bytes[i] = !byte
    }

    output
}

#[cfg(test)]
mod test {
    use super::*;

    /// Contains the test vectors in a format that's easy for us to test against.
    struct TestVector {
        seed: Vec<u8>,
        master_sk: Vec<u8>,
        child_index: u32,
        lamport_0: Vec<Vec<u8>>,
        lamport_1: Vec<Vec<u8>>,
        compressed_lamport_pk: Vec<u8>,
        child_sk: Vec<u8>,
    }

    /// "Test Vector with Intermediate values" from:
    ///
    /// https://eips.ethereum.org/EIPS/eip-2333
    #[test]
    fn eip2333_intermediate_vector() {
        let vectors = TestVector::from(get_raw_vector());

        let master_sk = derive_master_sk(&vectors.seed);
        assert_eq!(
            master_sk.as_bytes(),
            &vectors.master_sk[..],
            "master_sk should match"
        );

        let lamport_0 =
            ikm_to_lamport_sk(&vectors.child_index.to_be_bytes()[..], master_sk.as_bytes());
        assert_eq!(
            lamport_0
                .iter_chunks()
                .map(|c| c.to_vec())
                .collect::<Vec<_>>(),
            vectors.lamport_0,
            "lamport_0 should match"
        );

        let lamport_1 = ikm_to_lamport_sk(
            &vectors.child_index.to_be_bytes()[..],
            flip_bits(master_sk.as_bytes()).as_bytes(),
        );
        assert_eq!(
            lamport_1
                .iter_chunks()
                .map(|c| c.to_vec())
                .collect::<Vec<_>>(),
            vectors.lamport_1,
            "lamport_1 should match"
        );

        let compressed_lamport_pk =
            parent_sk_to_lamport_pk(master_sk.as_bytes(), vectors.child_index);
        assert_eq!(
            compressed_lamport_pk.as_bytes(),
            &vectors.compressed_lamport_pk[..],
            "compressed_lamport_pk should match"
        );

        let child_sk = derive_child_sk(master_sk.as_bytes(), vectors.child_index);
        assert_eq!(
            child_sk.as_bytes(),
            &vectors.child_sk[..],
            "child_sk should match"
        );
    }

    /// Struct to deal with easy copy-paste from specification test vectors.
    struct RawTestVector {
        seed: &'static str,
        master_sk: &'static str,
        child_index: u32,
        lamport_0: Vec<&'static str>,
        lamport_1: Vec<&'static str>,
        compressed_lamport_pk: &'static str,
        child_sk: &'static str,
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

    /// Converts from a format that's easy to copy-paste from the spec into a format that's easy to
    /// test with.
    impl From<RawTestVector> for TestVector {
        fn from(raw: RawTestVector) -> TestVector {
            TestVector {
                seed: hex_to_vec(raw.seed),
                master_sk: int_to_vec(raw.master_sk),
                child_index: raw.child_index,
                lamport_0: raw.lamport_0.into_iter().map(hex_to_vec).collect(),
                lamport_1: raw.lamport_1.into_iter().map(hex_to_vec).collect(),
                compressed_lamport_pk: hex_to_vec(raw.compressed_lamport_pk),
                child_sk: int_to_vec(raw.child_sk),
            }
        }
    }

    /// Returns the copy-paste values from the spec.
    fn get_raw_vector() -> RawTestVector {
        RawTestVector {
        seed: "0xc55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        master_sk:
            "12513733877922233913083619867448865075222526338446857121953625441395088009793",
        child_index: 0,
        lamport_0: vec![
            "0x7b4a587eac94d7f56843e718a04965d4832ef826419b4001a3ad0ba77eb44a3b",
            "0x90f45a712112122429412921ece5c30eb2a6daf739dc9034fc79424daeb5eff6",
            "0xd061c2799de00b2be90eb1cc295f4c31e22d4b45c59a9b9b2554379bea7783cb",
            "0x3ad17e4cda2913b5180557fbe7db04b5ba440ce8bb035ae27878d66fbfa50d2c",
            "0xf5b954490933ad47f8bf612d4a4f329b3aa8914b1b83d59e15e271e2a087e002",
            "0x95d68d505bf4ff3e5149bc5499cf4b2f00686c674a29a8d903f70e569557d867",
            "0x1b59c76d9bb2170b220a87833582ede5970d4a336d91c99a812825afe963e056",
            "0x4310ff73cfbbf7b81c39ecbf1412da33e9388c1a95d71a75e51fe12256551ceb",
            "0xee696343f823e5716e16747f3bbae2fc6de233fe10eea8e45b4579018da0874f",
            "0xae12a437aaa7ae59f7d8328944b6a2b973a43565c55d5807dc2faf223a33aa73",
            "0x2a3ae0b47f145bab629452661ff7741f111272e33ec571030d0eb222e1ed1390",
            "0x1a3ea396e8cbd1d97733ef4753d6840b42c0795d2d693f18e6f0e7b3fff2beb2",
            "0x472429d0643c888bfdfe6e6ccfdeee6d345d60c6710859ac29fc289fd3656347",
            "0xa32d4d955949b8bed0eb20f586d8fd516d6ddec84fbbc36998d692633c349822",
            "0xe5ac8ac5ee1d40e53a7abf36e8269d5d5fce450a87feae8e59f432a44bcc7666",
            "0xddf9e497ed78032fbd72d9b8abd5204d81c3475f29afa44cdf1ded8ea72dd1dc",
            "0x945c62e88fb1e5f3c15ff57cd5eb1586ee93ec5ec80154c5a9c50241c5adae0a",
            "0xc8868b50fc8423c96b7efa1ede4d3203a6b835dbeb6b2ababc58397e6b31d9dd",
            "0x66de9bd86b50e2b6a755310520af655759c1753bff34b79a5cd63d6811fc8c65",
            "0x5b13786c6068df7735343e5591393bea8aee92ac5826d6132bf4f5ebf1098776",
            "0xa2038fc7d8e3cb2eda2bd303cfa76a9e5d8b88293918bec8b2fc03be75684f14",
            "0x47a13f6b2308a50eded830fdee7c504bf49d1fe6a95e337b0825d0d77a520129",
            "0xb534cdddcf1aa1c6b4cbba46d1db31b766d958e0a0306450bc031d1e3ed79d97",
            "0x54aa051b754c31658377f7bff00b7deaa861e74cb12e1eb84216666e19b23d69",
            "0x0220d57f63435948818eb376367b113c188e37451c216380f65d1ad55f73f527",
            "0xf9dd2e391565534a4db84980433bf5a56250f45fe294fce2679bcf115522c081",
            "0x1166591ee2ca59b9f4e525900f085141be8879c66ef18529968babeb87c44814",
            "0xf4fa2e8de39bdbeb29b64d8b440d3a6c9a6ca5bdce543877eaee93c11bd70ab8",
            "0x07f466d73b93db283b3f7bfaf9c39ae296adc376ab307ef12312631d0926790e",
            "0xb2ecff93acb4fa44c1dbf8464b81734a863b6d7142b02f5c008907ea4dc9aaa1",
            "0xa1d9c342f6c293ac6ef8b5013cba82c4bad6ed7024d782948cb23cd490039ba1",
            "0xc7d04a639ba00517ece4dbc5ef4aaf20e0ccde6e4a24c28936fabe93dec594db",
            "0xe3cbb9810472d9dd1cdb5eed2f74b67ea60e973d2d2e897bd64728c9b1aa0679",
            "0xe36884703413958ff2aba7a1f138a26d0ac0a371270f0169219beb00a5add5f0",
            "0xe5ea300a09895b3f98de5232d92a36d5611cbcf9aaf9e7bb20cf6d1696ad1cb4",
            "0xc136cda884e18175ab45148ed4f9d0d1a3c5e11ad0275058e61ae48eb151a81f",
            "0x3ee1101e944c040021187e93b6e0beb1048c75fb74f3fdd67756b1c8517a311f",
            "0x016964fd6fc32b9ad07a630949596715dee84d78230640368ff0929a280cf3a2",
            "0xe33865fc03120b94333bb754fd097dc0f90e69ff6fd221d6aae59fcf2d762d76",
            "0xe80bb3515a09ac6ecb4ec59de22701cdf954b1ae8a677fd85508c5b041f28058",
            "0x3889af7cd325141ec288021ede136652a0411d20364005b9d3ca9102cb368f57",
            "0x18dad0bc975cf8800addd54c7867389d3f7fe1b97d348bd8412a6cbfb75c520a",
            "0x09035218686061ee91bd2ad57dc6fb6da7243b8177a153484524b2b228da5314",
            "0x688fd7a97551c64eae33f91abb073a46eafbbacd5595c6bac2e57dd536acdfe2",
            "0x1fc164dce565a1d0da59cc8048b334cc5eb84bf04de2399ddb847c22a7e32ab7",
            "0xa2a340ba05c8a30dd1cab886a926b761758eba0e41b5c4c5dfd4a42f249655c1",
            "0xc43dffe01479db836a6a1a74564b297fad0d69c6b06cf593f6db9f26b4f307d5",
            "0x73cef7f3ff724a30a79e1dca74cef74954afeefa2e476c4dec65afe50c16c5c4",
            "0xa54002253ab7b95cc5b664b3f08976400475cc56f170b939f6792e730ff5170b",
            "0x9ade43053d41afebc002f09476dffd1b13ecbf67f810791540b92ca56d5e63e4",
            "0x234e7cbfbe45b22a871db26738fa05de09213a925439d7f3e5108132e521b280",
            "0x066b712417332c7cfca871fb1bb5839f0341acf9266229603a3eddbc8a93b59f",
            "0xb5857acdcf636330da2cfcc99c81d9fdbd20c506a3c0e4f4f6a139d2a64f051c",
            "0xe119908a150a49704b6bbba2c470cd619a0ae10dd9736e8d491890e3c8509fff",
            "0xb8a5c5dbb51e6cb73cca95b4ad63ea3c7399cd16b05ab6261535495b3af2ca51",
            "0x05624a1d4d2d2a31160bc48a6314bbf13eaddf56cddb0f0aa4ed3fb87f8b479f",
            "0x483daceff1c3baa0ed0f3be7e534eebf5f4aed424ecd804edfbf5c56b3476b50",
            "0x424d04694e7ae673707c77eb1c6d0996d250cfab6832ee3506a12e0384a3c5c9",
            "0xa11fed0ed8057966bfe7136a15a814d06a516fbc9d44aeef87c509137a26190e",
            "0x3694d22d1bc64658f3adbe2cc9f1716aee889066e0950e0b7a2fd576ed36bb76",
            "0x49a13000a87f39f93d0ae9c3a4cfccbf440c0a75cce4c9d70dac627b6d6958b3",
            "0xb3ff0cdd878d5ac1cb12e7d0b300d649fdd008800d498ae4f9fbf9510c74249a",
            "0xe52a867cfb87d2fe7102d23d8d64925f7b75ca3f7d6bb763f7337352c255e0be",
            "0x6513b372e4e557cca59979e48ec27620e9d7cdb238fcf4a9f19c3ba502963be0",
            "0x9f69d82d4d51736902a987c8b5c30c2b25a895f2af5d2c846667ff6768bcc774",
            "0x049a220dbe3340749f94643a429cb3cba3c92b561dc756a733d652d838728ab3",
            "0x4fa2cd877aa115b476082b11053309f3537fa03d9158085f5f3f4bab6083e6da",
            "0xed12db4069eb9f347735816afcee3fe43d4a6999fef8240b91bf4b05447d734f",
            "0x3ecbe5eda469278f68548c450836a05cc500864664c7dda9b7526f084a891032",
            "0x690d8f928fc61949c22e18cceaa2a446f8e1b65bd2e7af9e0a8e8284134ab3d2",
            "0x99e09167a09f8261e7e8571d19148b7d7a75990d0702d9d582a2e4a96ac34f8e",
            "0x6d33931693ed7c2e1d080b6a37da52c279a06cec5f534305819f7adf7db0afe3",
            "0xc4b735462a9a656e28a52b1d4992ea9dea826b858971d698453a4be534d6bb70",
            "0xedf92b10302dc41f8d362b360f4c2ef551d50e2ded012312c964002d2afc46d7",
            "0x58f6691cca081ae5c3661dd171b87cc49c90359bb03cc0e57e503f7fcf14aefc",
            "0x5d29b8b4ee295a73c4a8618927b3d14b76c7da049133a2257192b10be8c17a6a",
            "0x646802fa42801e0ae24011fb4f62e87219ef1da01f7fc14bf8d6bd2d9e7c21f1",
            "0x23abf45eee65cc4c1e95ccab42ad280a00bb3b14d243e2021a684075f900141e",
            "0x2b1ae95c975bf9c387eae506fdb5e58afd2d198f00a21cd3fddb5855e8021e4d",
            "0x0ef9f6e1c0583493d343e75f9c0c557fa6da0dc12b17a96c5757292916b72ee3",
            "0x04c7fc76195c64a3285af14161077c045ff6ddbb67c0ff91b080f98eb6781e5c",
            "0xba12679b97027d0e7076e6d19086c07792eaa7f78350842fbef8ddf5bcd3ecc0",
            "0xcead458e6799df4d2f6cbf7f13cb3afec3441a354816e3071856ed49cbdbb1a7",
            "0xbe6c56256556bb5c6727a1d9cb641d969677f56bb5ad7f8f7a7c9cfd128427b4",
            "0xc80f11963ff40cb1888054b83c0463d32f737f2e7d42098e639023db0dfc84d4",
            "0xac80006c1296bcfde86697efebb87fb0fddfb70dd34dd2ee4c152482af4687eb",
            "0xbb7d13ce184249df4576fc3d13351e1683500e48726cd4198423f14f9094068b",
            "0x1b2d9c40c55bd7362664fa46c1268e094d56c8193e3d991c08dc7a6e4ca14fa1",
            "0x9bd236254d0565f5b2d24552d4b4d732de43b0adaa64ecd8be3efc6508577591",
            "0x38078cefccc04e8312d79e0636e0e3157434c50a2ad4e3e87cc6584c41eec8b5",
            "0xb5d15a8527ff3fa254ba61ffceb02d2570b53361894f351a9e839c0bb716857d",
            "0x6763dad684bf2e914f40ae0a7ee0cdf12c97f41fc05a485d5991b4daad21a3f8",
            "0xc80363c20df589333ecbe05bd5f2c19942ebc2593626dc50d00835c40fb8d005",
            "0x48502b56ae93acd2794f847cbe825525d5d5f59f0f75c67aff84e5338776b3af",
            "0xfd8e033493ba8af264a855a78ab07f37d936351d2879b95928909ed8df1b4f91",
            "0x11f75bee9eac7356e65ebc7f004ccdc1da80807380d69143293d1421f50b1c97",
            "0x903a88a3ebe84ca1c52a752b1faffa9ca1daedac9cbf1aa70942efc9beb44b79",
            "0x2c0dcd68837f32a69da651045ad836b8cd6b48f2c8c5d73a3bd3bba6148d345a",
            "0x0aa0f49b3476f3fdb6393f2ab601e0009586090b72ee54a525734f51598960d5",
            "0xf7a789f013f702731656c562caa15b04cb7c9957376c4d80b8839167bb7fa626",
            "0x4e0be1b19e305d82db3fd8affd67b0d2559da3edbfb08d19632a5cc46a90ed07",
            "0x3caaccfc546d84d543eaf4f4c50c9c8fd831c12a8de56fdb9dfd04cc082882fe",
            "0x894f6a01fd34f0642077e22981752011678548eb70eb55e8072c1caffc16fe02",
            "0xae7eb54adaa68679348ea3537a49be669d1d61001fbab9fac259ba727dbc9a1a",
            "0x291a1cbdceff957b5a65440ab67fb8672de881230fe3108a15ca487c2662c2c7",
            "0x891d43b867137bf8beb9df4da2d951b5984a266a8cd74ec1593801d005f83f08",
            "0xc558407f6491b37a10835e0ad7ce74f4e368aa49157a28873f7229310cb2d7fd",
            "0x9ce061b0a072e1fe645f3479dac089b5bfb78cfa6cfbe5fd603bcdb504711315",
            "0xa8e30d07b09275115dd96472ecf9bc316581caf307735176ca226d4cd9022925",
            "0x918ee6d2efba7757266577691203f973cf4f4cac10f7d5f86acd2a797ff66583",
            "0xfa31ba95e15d1635d087522f3d0da9cf7acac4ed6d0ac672654032a3c39244a6",
            "0xf2952b58f015d6733af06938cd1f82fbddb3b796823bee7a3dbffa04efc117c2",
            "0x46f8f742d3683de010ede528128d1181e8819f4252474f51371a177bfa518fa4",
            "0x4ca1cc80094f2910cf83a9e65ad70e234690ffb9142793911ec7cf71663545b3",
            "0x381965037b5725c71bfa6989d4c432f6611de8e8ec387f3cfc0dcb1a15191b73",
            "0x2562b88ed3b86ba188be056805a3b7a47cb1a3f630d0e2f39647b0792ec6b7d8",
            "0x565f6d14e7f22724f06d40f54465ad40d265b6de072b34a09d6e37a97a118cd8",
            "0xc2982c861ad3278063b4a5f584eaf866db684cc4e712d64230fc9ee33bb4253b",
            "0xfd806c91927e549d8d400ab7aa68dbe60af988fbabf228483ab0c8de7dab7eee",
            "0xafae6ff16c168a3a3b5c2f1742d3f89fa4777c4bd0108f174014debf8f4d629c",
            "0xaf5a4be694de5e53632be9f1a49bd582bf76002259460719197079c8c4be7e66",
            "0xa8df4a4b4c5bf7a4498a11186f8bb7679137395f28e5c2179589e1c1f26504b5",
            "0xce8b77c64c646bb6023f3efaed21ca2e928e21517422b124362cf8f4d9667405",
            "0x62e67a8c423bc6c6c73e6cd8939c5c1b110f1a38b2ab75566988823762087693",
            "0x7e778f29937daaa272d06c62d6bf3c9c0112d45a3df1689c602d828b5a315a9f",
            "0xe9b5abd46c2377e602ff329050afa08afe152f4b0861db8a887be910ff1570bf",
            "0xa267b1b2ccd5d96ae8a916b0316f06fafb886b3bb41286b20763a656e3ca0052",
            "0xb8ed85a67a64b3453888a10dedf4705bd27719664deff0996a51bb82bc07194f",
            "0x57907c3c88848f9e27bc21dd8e7b9d61de48765f64d0e943e7a6bb94cc2021ab",
            "0xd2f6f1141a3b76bf9bf581d49091142944c7f9f323578f5bdd5522ba32291243",
            "0xc89f104200ed4c5d5f7046d99e68ae6f8ec31e2eeceb568eb05087e3aa546a74",
            "0xc9f367fae45c39299693b134229bb6dd0da112fd1a7d19b7f4772c01e5cbe479",
            "0x64e2d4ad51948764dd578d26357e29e8e4d076d65c05cffdf8211b624fefe9ac",
            "0xf9a9b4e6d5be7fc051df8ecd9c389d16b1af86c749308e6a23f7ff4871f0ba9a",
            "0x0d2b2a228b86ebf9499e1bf7674335087ced2eb35ce0eb90954a0f75751a2bf4",
            "0xff8531b45420a960d6e48ca75d77758c25733abde83cd4a6160beae978aa735e",
            "0xd6d412bd1cb96a2b568d30e7986b7e8994ca92fd65756a758295499e11ea52b6",
            "0xad8533fccbecdd4a0b00d648bfe992360d265f7be70c41d9631cefad5d4fe2f6",
            "0x31fbf2afb8d5cc896d517cfc5201ee24527e8d283f9c37ca10233bef01000a20",
            "0x2fd67b7365efc258131eb410f46bf3b1cbd3e9c76fd6e9c3e86c9ff1054116ff",
            "0xab6aa29f33d18244be26b23abadb39679a8aa56dafc0dd7b87b672df5f5f5db6",
            "0xbad3b0f401ca0a53a3d465de5cecd57769ec9d4df2c04b78f8c342a7ed35bbee",
            "0xbdc24d46e471835d83ce8c5b9ecbe675aab2fd8f7831c548e8efd268c2ee2232",
            "0x87265fabd7397d08f0729f13a2f3a25bbc8c874b6b50f65715c92b62f665f925",
            "0xa379fd268e7ff392c067c2dd823996f72714bf3f936d5eeded71298859f834cb",
            "0xf3ab452c9599ebfbb234f72a86f3062aed12ae1f634abbe542ff60f5cefc1fcf",
            "0x2b17ebb053a3034c07da36ed2ba42c25ad8e61dec87b5527f5e1c755eb55405a",
            "0x305b40321bd67bf48bfd121ee4d5d347268578bd4b8344560046594771a11129",
            "0xe7029c9bea020770d77fe06ca53b521b180ad6a9e747545aadc1c74beef7241c",
            "0xabc357cec0f4351a5ada22483d3b103890392f8d8f9cb8073a61969ed1be4e08",
            "0x97f88c301946508428044d05584dc41af2e6a0de946de7d7f5269c05468afe20",
            "0xbdc08fe8d6f9a05ad8350626b622ad8eec80c52331d154a3860c98676719cfbd",
            "0x161590fc9f7fcf4eaba2f950cf588e6da79e921f139d3c2d7ebe017003a4799e",
            "0x91b658db75bc3d1954bfde2ef4bc12980ff1688e09d0537f170c9ab47c162320",
            "0x76d995f121406a63ce26502e7ec2b653c221cda357694a8d53897a99e6ce731e",
            "0x3d6b2009586aceb7232c01259bb9428523c02b0f42c2100ec0d392418260c403",
            "0x14ca74ecbc8ec0c67444c6cb661a2bce907aa2a1453b11f16002b815b94a1c49",
            "0x553b4dc88554ebe7b0a3bd0813104fd1165a1f950ceace11f5841aa74b756d85",
            "0x4025bf4ad86751a156d447ce3cabafde9b688efcdafd8aa4be69e670f8a06d9e",
            "0x74260cf266997d19225e9a0351a9acfa17471fccdf5edc9ccc3bb0d23ef551c5",
            "0xf9dbca3e16d234e448cf03877746baeb62a8a25c261eff42498b1813565c752a",
            "0x2652ec98e05c1b6920fb6ddc3b57e366d514ffa4b35d068f73b5603c47f68f2f",
            "0x83f090efeb36db91eb3d4dfbb17335c733fce7c64317d0d3324d7caaaf880af5",
            "0x1e86257f1151fb7022ed9ed00fb961a9a9989e58791fb72043bb63ed0811791c",
            "0xd59e4dcc97cba88a48c2a9a2b29f79125099a39f74f4fb418547de8389cd5d15",
            "0x875a19b152fe1eb3fe1de288fa9a84864a84a79bac30b1dbd70587b519a9770e",
            "0x9c9dc2d3c8f2f6814cfc61b42ee0852bbaf3f523e0409dd5df3081b750a5b301",
            "0xf6f7f81c51581c2e5861a00b66c476862424151dd750efeb20b7663d552a2e94",
            "0x723fcb7ca43a42483b31443d4be9b756b34927176f91a391c71d0b774c73a299",
            "0x2b02d8acf63bc8f528706ed4d5463a58e9428d5b71d577fd5daa13ba48ac56cf",
            "0x2ff6911f574c0f0498fc6199da129446b40fca35ccbf362bc76534ba71c7ca22",
            "0x1ef4b959b11bc87b11e4a5f84b4d757c6bdcfad874acec9a6c9eee23dc4bbe1b",
            "0x68e2df9f512be9f64b7e3a2dee462149dac50780073d78b569a20256aea5f751",
            "0xd1a3682e12b90ae1eab27fc5dc2aef3b8e4dbb813925e9a91e58d6c9832767b6",
            "0x75778ccc102d98c5e0b4b83f7d4ef7fe8bc7263cc3317723001cb0b314d1e9e8",
            "0xc7f44e2cead108dc167f0036ac8a278d3549cc3dd5cc067d074ccad9b1d9f8d4",
            "0x4cba0223c5df2796b0ee9fbc084d69f10e6aedda8f0cf86171bebb156ede676c",
            "0x628deda825661f586a5713e43c806fdd55e1a53fbe90a4ddb5f3786570740954",
            "0xfc82a253bc7e0ac96252b238fbb411a54e0adf78d089f804a7fc83a4959b401e",
            "0x72a6491f5daae0ceb85b61a5ed69009dd2a167c64cb35cabf38b846e27268e9d",
            "0xee139a913d4fcf25ba54bb36fc8051b91f2ec73ba820cc193c46fb2f7c37a106",
            "0x7f75021f2b1d0c78859478e27f6f40646b5776c060f1a5f6f0944c840a0121f8",
            "0x5b60a1b78feca1d2602ac8110d263ad6b3663cbf49e6bdc1077b4b80af2feb6f",
            "0xd61f15d80b1e88469b6a76ed6a6a2b94143b6acc3bd717357264818f9f2d5c6d",
            "0xea85da1780b3879a4d81b685ba40b91c060866abd5080b30fbbb41730724a7dd",
            "0xb9b9da9461e83153f3ae0af59fbd61febfde39eb6ac72db5ed014797495d4c26",
            "0xf737762fe8665df8475ff341b3762aaeb90e52974fe5612f5efd0fc1c409d7f8",
            "0xaaa25d934a1d5aa6b2a1863704d7a7f04794ed210883582c1f798be5ca046cf7",
            "0x932f46d0b6444145221b647f9d3801b6cb8b1450a1a531a959abdaacf2b5656b",
            "0xf4a8b0e52f843ad27635c4f5a467fbf98ba06ba9a2b93a8a97170b5c41bf4958",
            "0x196ed380785ee2925307ec904161dc02a4596a55499e5b0a3897f95485b3e74a",
            "0x772e829a405219e4f8cd93a1ef15c250be85c828c1e29ef6b3f7b46958a85b44",
            "0xd66cfc9af9941515d788f9f5e3b56fddb92464173ddb67b83bf265e7ea502170",
            "0xf5b040bfc246425278e2423b1953d8ad518de911cf04d16c67d8580a09f90e62",
            "0xd2d18b2ae8a53dde14b4000e5e7e414505825f50401a3797dd8820cf510dc448",
            "0xc01dcc064e644266739cd0ec7edf92fc2ef8e92e0beedf0e8aa30efcff1644fe",
            "0x24720d325913ba137daf031924ad3bfaa1c8c00a53a2d048fe5667aef45efce3",
            "0x70a24e1c89b3ea78d76ef458d498dcb5b8561d484853b2a8b2adcd61869857df",
            "0x0ff3313997f14e1b1dcd80f1d62c58aaefb19efd7c0ea15dde21aa4e2a516e80",
            "0x960c1f50062a4df851638f42c0259b6e0a0217300884f13a3c5c8d94adb34f21",
            "0xb71ca7cc8578149da556131268f4625b51620dfc3a6e9fbd47f5df03afbd410e",
            "0xa1a3eeec0addec7b9e15f416a07608a1b5d94f0b42d5c203b8ced03a07484f5b",
            "0xa4bb8b059aa122ca4652115b83b17af80cfbea0d3e1e8979a396a667f94e85f3",
            "0x31c4d2f252167fe2a4d41944224a80b2f1afaf76f8dd6a3d52d71751849e44bb",
            "0x79642dd6a255f96c9efe569304d58c327a441448db0431aa81fe072d0d359b52",
            "0x42a4b504714aba1b67defe9458fff0c8cb1f216dcab28263cef67a65693b2036",
            "0xe3d2f6a9d882d0f026ef316940dfcbf131342060ea28944475fe1f56392c9ad2",
            "0x986af9aeff236394a0afa83823e643e76f7624e9bfd47d5468f9b83758a86caa",
            "0xafe2de6ede50ee351d63ed38d1f2ae5203174c731f41bbed95db467461ad5492",
            "0x9ad40f0785fe1c8a5e4c3342b3c91987cd47a862ece6573674b52fa0456f697a",
            "0xde4cde6d0fc6def3a89b79da0e01accdbec049f1c9471d13a5d59286bd679af1",
            "0xecd0d1f70116d6b3ae21c57fb06ad90eed33d040e2c5c3d12714b3be934fa5ce",
            "0x3c53c5bf2d1b1d4038e1f0e8a2e6d12e0d4613d5cd12562578b6909921224c10",
            "0x36087382b37e9e306642cc6e867e0fb2971b6b2b28b6caf2f9c96b790e8db70a",
            "0xa957496d6a4218a19998f90282d05bd93e6baabf55e55e8a5f74a933a4dec045",
            "0x077d6f094e8467a21f02c67753565ec5755156015d4e86f1f82a22f9cf21c869",
            "0x12dd3b1f29e1462ca392c12388a77c58044151154cf86f23873f92a99b6bb762",
            "0x7fdbcdedcc02ecf16657792bd8ef4fa4adeee497f30207d4cc060eb0d528b26b",
            "0x245554b12bf8edf9e9732d6e2fa50958376e355cb695515c94676e64c6e97009",
            "0xccd3b1841b517f7853e35f85471710777e437a8665e352a0b61c7d7083c3babc",
            "0xd970545a326dcd92e31310d1fdce3703dff8ef7c0f3411dfa74fab8b4b0763ac",
            "0xd24163068918e2783f9e79c8f2dcc1c5ebac7796ce63070c364837aac91ee239",
            "0x256a330055357e20691e53ca5be846507c2f02cfde09cafb5809106f0af9180e",
            "0xfa446a5d1876c2051811af2a341a35dbcd3f7f8e2e4f816f501139d27dd7cd82",
            "0xbafbc7a8f871d95736a41e5721605d37e7532e41eb1426897e33a72ed2f0bf1d",
            "0x8055af9a105b6cf17cfeb3f5320e7dab1a6480500ff03a16c437dfec0724c290",
            "0x1de6ee3e989497c1cc7ca1d16b7b01b2f336524aa2f75a823eaa1716c3a1a294",
            "0x12bb9508d646dda515745d104199f71276d188b3e164083ad27dfdcdc68e290b",
            "0x7ea9f9939ad4f3b44fe7b780e0587da4417c34459b2996b3a449bb5b3ff8c8cb",
            "0xa88d2f8f35bc669aa6480ce82571df65fea366834670b4084910c7bb6a735dde",
            "0x9486e045adb387a550b3c7a603c30e07ed8625d322d1158f4c424d30befe4a65",
            "0xb283a70ba539fe1945be096cb90edb993fac77e8bf53616bde35cdcaa04ab732",
            "0xab39a81558e9309831a2caf03e9df22e8233e20b1769f16e613debcdb8e2610f",
            "0x1fc12540473fbbad97c08770c41f517ce19dc7106aa2be2e9b77867046627509",
            "0xec33dbec9d655c4c581e07d1c40a587cf3217bc8168a81521b2d0021bd0ec133",
            "0xc8699e3b41846bc291209bbb9c06f565f66c6ccecbf03ebc27593e798c21fe94",
            "0x240d7eae209c19d453b666c669190db22db06279386aa30710b6edb885f6df94",
            "0xb181c07071a750fc7638dd67e868dddbeeee8e8e0dcbc862539ee2084674a89e",
            "0xb8792555c891b3cbfddda308749122a105938a80909c2013637289e115429625",
            "0xfe3e9e5b4a5271d19a569fee6faee31814e55f156ba843b6e8f8dc439d60e67a",
            "0x912e9ba3b996717f89d58f1e64243d9cca133614394e6ae776e2936cf1a9a859",
            "0xa0671c91a21fdfd50e877afa9fe3974aa3913855a2a478ae2c242bcdb71c73d7",
            "0x5b55d171b346db9ba27b67105b2b4800ca5ba06931ed6bd1bafb89d31e6472e6",
            "0x68438458f1af7bd0103ef33f8bc5853fa857b8c1f84b843882d8c328c595940d",
            "0x21fe319fe8c08c1d00f977d33d4a6f18aecaa1fc7855b157b653d2d3cbd8357f",
            "0x23cce560bc31f68e699ece60f21dd7951c53c292b3f5522b9683eb2b3c85fc53",
            "0x917fa32d172c352e5a77ac079df84401cdd960110c93aa9df51046d1525a9b49",
            "0x3fc397180b65585305b88fe500f2ec17bc4dccb2ec254dbb72ffb40979f14641",
            "0xf35fb569e7a78a1443b673251ac70384abea7f92432953ca9c0f31c356be9bd9",
            "0x7955afa3cd34deb909cd031415e1079f44b76f3d6b0aaf772088445aaff77d08",
            "0x45c0ca029356bf6ecfc845065054c06024977786b6fbfaea74b773d9b26f0e6c",
            "0xe5c1dac2a6181f7c46ab77f2e99a719504cb1f3e3c89d720428d019cb142c156",
            "0x677b0e575afcccf9ddefc9470e96a6cfff155e626600b660247b7121b17b030a",
            "0xbeed763e9a38277efe57b834a946d05964844b1f51dba2c92a5f3b8d0b7c67d0",
            "0x962b17ed1a9343d8ebfae3873162eef13734985f528ca06c90b0c1e68adfdd89",
        ],
        lamport_1: vec![
            "0xb3a3a79f061862f46825c00fec4005fb8c8c3462a1eb0416d0ebe9028436d3a9",
            "0x6692676ce3b07f4c5ad4c67dc2cf1dfa784043a0e95dd6965e59dc00b9eaff2d",
            "0xbf7b849feb312db230e6e2383681b9e35c064e2d037cbc3c9cc9cd49220e80c9",
            "0xa54e391dd3b717ea818f5954eec17b4a393a12830e28fabd62cbcecf509c17dc",
            "0x8d26d800ac3d4453c211ef35e9e5bb23d3b9ede74f26c1c417d6549c3110314d",
            "0xbb8153e24a52398d92480553236850974576876c7da561651bc551498f184d10",
            "0x0d30e0e203dc4197f01f0c1aba409321fbf94ec7216e47ab89a66fb45e295eff",
            "0x01dc81417e36e527776bf37a3f9d74a4cf01a7fb8e1f407f6bd525743865791d",
            "0xa6318e8a57bec438245a6834f44eb9b7fb77def1554d137ea12320fc572f42c9",
            "0xd25db9df4575b595130b6159a2e8040d3879c1d877743d960bf9aa88363fbf9f",
            "0x61bb8baeb2b92a4f47bb2c8569a1c68df31b3469e634d5e74221bc7065f07a96",
            "0xb18962aee4db140c237c24fec7fd073b400b2e56b0d503f8bc74a9114bf183bf",
            "0x205473cc0cdab4c8d0c6aeceda9262c225b9db2b7033babfe48b7e919751a2c6",
            "0xc5aa7df7552e5bb17a08497b82d8b119f93463ccb67282960aee306e0787f228",
            "0x36da99e7d38ce6d7eab90ea109ba26615ad75233f65b3ae5056fba79c0c6682a",
            "0xd68b71bba6266b68aec0df39b7c2311e54d46a3eab35f07a9fe60d70f52eec58",
            "0xbbe56f1274ada484277add5cb8c90ef687d0b69a4c95da29e32730d90a2d059f",
            "0x0982d1d1c15a560339d9151dae5c05e995647624261022bbedce5dce8a220a31",
            "0x8ef54ad546d2c6144fc26e1e2ef92919c676d7a76cfdfb5c6a64f09a54e82e71",
            "0x1e3ac0133eef9cdbeb590f14685ce86180d02b0eea3ef600fd515c38992b1f26",
            "0x642e6b1c4bec3d4ba0ff2f15fbd69dcb57e4ba8785582e1bc2b452f0c139b590",
            "0xca713c8cf4afa9c5d0c2db4fc684a8a233b3b01c219b577f0a053548bedf8201",
            "0xd0569ba4e1f6c02c69018b9877d6a409659cb5e0aa086df107c2cc57aaba62da",
            "0x4ebe68755e14b74973e7f0fa374b87cee9c370439318f5783c734f00bb13e4b5",
            "0x788b5292dc5295ae4d0ea0be345034af97a61eec206fda885bbc0f049678c574",
            "0x0ebd88acd4ae195d1d3982038ced5af1b6f32a07349cf7fffbff3ce410c10df2",
            "0xc7faf0a49234d149036c151381d38427b74bae9bd1601fc71663e603bc15a690",
            "0xc5247bf09ebe9fa4e1013240a1f88c703f25a1437196c71ee02ca3033a61f946",
            "0x719f8c68113d9f9118b4281e1f42c16060def3e3eeef15f0a10620e886dc988f",
            "0x28da4f8d9051a8b4d6158503402bdb6c49ba2fb1174344f97b569c8f640504e6",
            "0x96f6773576af69f7888b40b0a15bc18cc9ec8ca5e1bb88a5de58795c6ddf678e",
            "0x8d80d188a4e7b85607deccf654a58616b6607a0299dd8c3f1165c453fd33d2e4",
            "0x9c08dcc4f914486d33aa24d10b89fd0aabcc635aa2f1715dfb1a18bf4e66692a",
            "0x0ff7045b5f6584cc22c140f064dec0692762aa7b9dfa1defc7535e9a76a83e35",
            "0x8e2dae66fa93857b39929b8fc531a230a7cfdd2c449f9f52675ab5b5176461d5",
            "0xf449017c5d429f9a671d9cc6983aafd0c70dd39b26a142a1d7f0773de091ac41",
            "0xed3d4cab2d44fec0d5125a97b3e365a77620db671ecdda1b3c429048e2ebdae6",
            "0x836a332a84ee2f4f5bf24697df79ed4680b4f3a9d87c50665f46edaeed309144",
            "0x7a79278754a4788e5c1cf3b9145edb55a2ba0428ac1c867912b5406bb7c4ce96",
            "0x51e6e2ba81958328b38fd0f052208178cec82a9c9abd403311234e93aff7fa70",
            "0x217ec3ec7021599e4f34410d2c14a8552fff0bc8f6894ebb52ec79bf6ec80dc9",
            "0x8a95bf197d8e359edabab1a77f5a6d04851263352aa46830f287d4e0564f0be0",
            "0x60d0cbfb87340b7c92831872b48997ce715da91c576296df215070c6c20046d4",
            "0x1739fbca476c540d081b3f699a97387b68af5d14be52a0768d5185bc9b26961b",
            "0xac277974f945a02d89a0f8275e02de9353e960e319879a4ef137676b537a7240",
            "0x959b7640821904ba10efe8561e442fbdf137ccb030aee7472d10095223e320ba",
            "0xdba61c8785a64cb332342ab0510126c92a7d61f6a8178c5860d018d3dad571c6",
            "0xc191fb6a92eb1f1fb9e7eb2bdecd7ec3b2380dd79c3198b3620ea00968f2bd74",
            "0x16ef4e88e182dfc03e17dc9efaa4a9fbf4ff8cb143304a4a7a9c75d306729832",
            "0x39080e4124ca577ff2718dfbcb3415a4220c5a7a4108729e0d87bd05adda5970",
            "0xa29a740eef233956baff06e5b11c90ed7500d7947bada6da1c6b5d9336fc37b6",
            "0x7fda7050e6be2675251d35376bacc895813620d245397ab57812391d503716ee",
            "0x401e0bf36af9992deb87efb6a64aaf0a4bc9f5ad7b9241456b3d5cd650418337",
            "0x814e70c57410e62593ebc351fdeb91522fe011db310fcf07e54ac3f6fefe6be5",
            "0x03c1e52ecbef0d79a4682af142f012dc6b037a51f972a284fc7973b1b2c66dcf",
            "0x57b22fb091447c279f8d47bdcc6a801a946ce78339e8cd2665423dfcdd58c671",
            "0x53aeb39ab6d7d4375dc4880985233cba6a1be144289e13cf0bd04c203257d51b",
            "0x795e5d1af4becbca66c8f1a2e751dcc8e15d7055b6fc09d0e053fa026f16f48f",
            "0x1cd02dcd183103796f7961add835a7ad0ba636842f412643967c58fe9545bee4",
            "0x55fc1550be9abf92cacb630acf58bad11bf734114ebe502978a261cc38a4dd70",
            "0x6a044e0ea5c361d3fb2ca1ba795301e7eb63db4e8a0314638f42e358ea9cfc3e",
            "0x57d9f15d4db199cbcb7cbd6524c52a1b799d52b0277b5a270d2985fcee1e2acb",
            "0x66c78c412e586bd01febc3e4d909cc278134e74d51d6f60e0a55b35df6fb5b09",
            "0x1076799e15a49d6b15c2486032f5e0b50f43c11bc076c401e0779d224e33f6fc",
            "0x5f70e3a2714d8b4483cf3155865ba792197e957f5b3a6234e4c408bf2e55119d",
            "0x9b105b0f89a05eb1ff7caed74cf9573dc55ac8bc4881529487b3700f5842de16",
            "0x1753571b3cfadca4277c59aee89f607d1b1e3a6aa515d9051bafb2f0d8ce0daa",
            "0x4014fff940b0950706926a19906a370ccbd652836dab678c82c539c00989201a",
            "0x0423fa59ee58035a0beb9653841036101b2d5903ddeabddabf697dbc6f168e61",
            "0x78f6781673d991f9138aa1f5142214232d6e3d6986acb6cc7fb000e1a055f425",
            "0x21b8a1f6733b5762499bf2de90c9ef06af1c6c8b3ddb3a04cce949caad723197",
            "0x83847957e909153312b5bd9a1a37db0bd6c72a417024a69df3e18512973a18b4",
            "0x948addf423afd0c813647cfe32725bc55773167d5065539e6a3b50e6ebbdab38",
            "0x0b0485d1bec07504a2e5e3a89addd6f25d497cd37a0c04bc38355f8bdb01cd48",
            "0x31be8bda5143d39ea2655e9eca6a294791ca7854a829904d8574bedc5057ddc4",
            "0x16a0d2d657fadce0d81264320e42e504f4d39b931dff9888f861f3cc78753f99",
            "0xb43786061420c5231bf1ff638cb210f89bf4cd2d3e8bafbf34f497c9a298a13b",
            "0x1f5986cbd7107d2a3cbc1826ec6908d976addbf9ae78f647c1d159cd5397e1bd",
            "0xa883ccdbfd91fad436be7a4e2e74b7796c0aadfe03b7eea036d492eaf74a1a6f",
            "0x5bc9eb77bbbf589db48bca436360d5fc1d74b9195237f11946349951f2a9f7f6",
            "0xb6bc86de74a887a5dceb012d58c62399897141cbcc51bad9cb882f53991f499c",
            "0xa6c3260e7c2dd13f26cf22bf4cd667688142ff7a3511ec895bc8f92ebfa694b6",
            "0xb97da27e17d26608ef3607d83634d6e55736af10cc7e4744940a3e35d926c2ad",
            "0x9df44067c2dc947c2f8e07ecc90ba54db11eac891569061a8a8821f8f9773694",
            "0x865cc98e373800825e2b5ead6c21ac9112ff25a0dc2ab0ed61b16dc30a4a7cd7",
            "0xe06a5b157570c5e010a52f332cacd4e131b7aed9555a5f4b5a1c9c4606caca75",
            "0x824eccb5cf079b5943c4d17771d7f77555a964a106245607cedac33b7a14922e",
            "0xe86f721d7a3b52524057862547fc72de58d88728868f395887057153bccaa566",
            "0x3344e76d79f019459188344fb1744c93565c7a35799621d7f4505f5b6119ac82",
            "0x401b3589bdd1b0407854565329e3f22251657912e27e1fb2d978bf41c435c3ac",
            "0xb12fd0b2567eb14a562e710a6e46eef5e280187bf1411f5573bb86ecbe05e328",
            "0xe6dc27bab027cbd9fbb5d80054a3f25b576bd0b4902527a0fc6d0de0e45a3f9f",
            "0x1de222f0e731001c60518fc8d2be7d7a48cc84e0570f03516c70975fdf7dc882",
            "0xb8ff6563e719fc182e15bbe678cf045696711244aacc7ce4833c72d2d108b1b9",
            "0x53e28ac2df219bcbbc9b90272e623d3f6ca3221e57113023064426eff0e2f4f2",
            "0x8a4e0776f03819e1f35b3325f20f793d026ccae9a769d6e0f987466e00bd1ce7",
            "0x2f65f20089a31f79c2c0ce668991f4440b576ecf05776c1f6abea5e9b14b570f",
            "0x448e124079a48f62d0d79b96d5ed1ffb86610561b10d5c4236280b01f8f1f406",
            "0x419b34eca1440c847f7bff9e948c9913075d8e13c270e67f64380a3f31de9bb2",
            "0x2f6e4fee667acaa81ba8e51172b8329ed936d57e9756fb31f635632dbc2709b7",
            "0xdd5afc79e8540fcee6a896c43887bd59c9de5d61b3d1b86539faeb41a14b251d",
            "0xc707bed926a46cc451a6b05e642b6098368dbdbf14528c4c28733d5d005af516",
            "0x153e850b606eb8a05eacecc04db4b560d007305e664bbfe01595cb69d26b8597",
            "0x1b91cc07570c812bb329d025e85ef520132981337d7ffc3d84003f81a90bf7a7",
            "0x4ca32e77a12951a95356ca348639ebc451170280d979e91b13316844f65ed42a",
            "0xe49ea1998e360bd68771bd69c3cd4cf406b41ccca4386378bec66ea210c40084",
            "0x01aaffbde1a672d253e0e317603c2dc1d0f752100d9e853f840bca96e57f314c",
            "0x170d0befcbbaafb317c8684213a4989368332f66e889824cc4becf148f808146",
            "0x56f973308edf5732a60aa3e7899ae1162c7a2c7b528c3315237e20f9125b34e0",
            "0x66c54fd5f6d480cab0640e9f3ec1a4eafbafc0501528f57bb0d5c78fd03068ef",
            "0xaca6c83f665c64d76fbc4858da9f264ead3b6ecdc3d7437bb800ef7240abffb9",
            "0xf1d4e02e7c85a92d634d16b12dc99e1d6ec9eae3d8dfbca77e7c609e226d0ce7",
            "0x094352545250e843ced1d3c6c7957e78c7d8ff80c470974778930adbe9a4ed1a",
            "0x76efa93070d78b73e12eb1efa7f36d49e7944ddcc3a043b916466ee83dca52ce",
            "0x1772a2970588ddb584eadf02178cdb52a98ab6ea8a4036d29e59f179d7ba0543",
            "0xe4bbf2d97d65331ac9f680f864208a9074d1def3c2433458c808427e0d1d3167",
            "0x8ccfb5252b22c77ea631e03d491ea76eb9b74bc02072c3749f3e9d63323b44df",
            "0x9e212a9bdf4e7ac0730a0cecd0f6cc49afc7e3eca7a15d0f5f5a68f72e45363b",
            "0x52e548ea6445aae3f75509782a7ab1f4f02c2a85cdd0dc928370f8c76ae8802d",
            "0xb62e7d73bf76c07e1a6f822a8544b78c96a6ba4f5c9b792546d94b56ca12c8b9",
            "0x595cb0e985bae9c59af151bc748a50923921a195bbec226a02157f3b2e066f5b",
            "0x1c7aa6b36f402cec990bafefbdbb845fc6c185c7e08b6114a71dd388fe236d32",
            "0x01ee2ff1a1e88858934a420258e9478585b059c587024e5ec0a77944821f798c",
            "0x420a963a139637bffa43cb007360b9f7d305ee46b6a694b0db91db09618fc2e5",
            "0x5a8e2ad20f8da35f7c885e9af93e50009929357f1f4b38a6c3073e8f58fae49e",
            "0x52a405fdd84c9dd01d1da5e9d1c4ba95cb261b53bf714c651767ffa2f9e9ad81",
            "0xa1a334c901a6d5adc8bac20b7df025e906f7c4cfc0996bfe2c62144691c21990",
            "0xb789a00252f0b34bded3cb14ae969effcf3eb29d97b05a578c3be8a9e479c213",
            "0xb9dbf7e9ddb638a515da245845bea53d07becdf3f8d1ec17de11d495624c8eab",
            "0xaf566b41f5ed0c026fa8bc709533d3fa7a5c5d69b03c39971f32e14ab523fa3d",
            "0x8121e0b2d9b106bb2aefd364fd6a450d88b88ee1f5e4aad7c0fcd8508653a112",
            "0x8581c1be74279216b93e0a0d7272f4d6385f6f68be3eef3758d5f68b62ee7b6c",
            "0x85386f009278f9a1f828404fa1bbfa02dfb9d896554f0a52678eb6ec8feadc55",
            "0xf483ed167d92a0035ac65a1cfdb7906e4952f74ae3a1d86324d21f241daffcb7",
            "0x3872485e2a520a350884accd990a1860e789dd0d0664ad14f50186a92c7be7be",
            "0xc6c1a3301933019105f5650cabcb22bfbf221965ffcfc1329315b24ea3d77fd4",
            "0xcee901330a60d212a867805ce0c28f53c6cc718f52156c9e74390d18f5df6280",
            "0xa67ae793b1cd1a828a607bae418755c84dbb61adf00833d4c61a94665363284f",
            "0x80d8159873b517aa6815ccd7c8ed7cfb74f84298d703a6c5a2f9d7d4d984ddde",
            "0x1de5a8b915f2d9b45c97a8e134871e2effb576d05f4922b577ade8e3cd747a79",
            "0x6ea17c5ece9b97dddb8b2101b923941a91e4b35e33d536ab4ff15b647579e1f5",
            "0xcb78631e09bc1d79908ce1d3e0b6768c54b272a1a5f8b3b52485f98d6bba9245",
            "0xd7c38f9d3ffdc626fe996218c008f5c69498a8a899c7fd1d63fbb03e1d2a073f",
            "0x72cdef54267088d466244a92e4e6f10742ae5e6f7f6a615eef0da049a82068f9",
            "0x60b3c490ba8c502656f9c0ed37c47283e74fe1bc7f0e9f651cbc76552a0d88eb",
            "0x56bd0c66987a6f3761d677097be9440ea192c1cb0f5ec38f42789abe347e0ea9",
            "0x3caac3e480f62320028f6f938ee147b4c78e88a183c464a0c9fb0df937ae30c1",
            "0x7a4d2f11bddda1281aba5a160df4b814d23aef07669affe421a861fac2b4ec0f",
            "0x9bb4d11299922dc309a4523959298a666ebe4063a9ee3bad1b93988ed59fb933",
            "0x957323fffbaf8f938354662452115ae5acba1290f0d3f7b2a671f0359c109292",
            "0x877624e31497d32e83559e67057c7a605fb888ed8e31ba68e89e02220eac7096",
            "0x8456546ae97470ff6ea98daf8ae632e59b309bd3ff8e9211f7d21728620ed1e5",
            "0xbacb26f574a00f466ce354e846718ffe3f3a64897d14d5ffb01afcf22f95e72b",
            "0x0228743a6e543004c6617bf2c9a7eba1f92ebd0072fb0383cb2700c3aed38ba0",
            "0x04f093f0f93c594549436860058371fb44e8daf78d6e5f563ba63a46b61ddbf0",
            "0x0ba17c1ec93429ceaff08eb81195c9844821b64f2b5363926c2a6662f83fb930",
            "0xd71605d8446878c677f146837090797e888416cfc9dc4e79ab11776cc6639d3f",
            "0x33dde958dc5a6796138c453224d4d6e7f2ae740cceef3b52a8b669eb4b9691a1",
            "0x3c39838295d1495e90e61ce59f6fcc693b31c292d02d31759719df6fe3214559",
            "0x8aecc66f38644296cf0e6693863d57a243a31a4929130e22ab44cb6157b1af41",
            "0xdf7153a7eab9521f2b37124067166c72de8f342249ac0e0f5350bd32f1251053",
            "0xa498840b58897cf3bed3981b94c86d85536dfebbc437d276031ebd9352e171eb",
            "0xb1df15a081042ab665458223a0449ffc71a10f85f3d977beb20380958fd92262",
            "0x15d3bdbdee2a61b01d7a6b72a5482f6714358eedf4bece7bb8458e100caf8fba",
            "0x0c96b7a0ea09c3ef758424ffb93654ce1520571e32e1f83aecbeded2388c3a7a",
            "0xb4a3a8023266d141ecd7c8a7ca5282a825410b263bc11c7d6cab0587c9b5446e",
            "0xf38f535969d9592416d8329932b3a571c6eacf1763de10fb7b309d3078b9b8d4",
            "0x5a1e7b1c3b3943158341ce6d7f9f74ae481975250d89ae4d69b2fcd4c092eb4e",
            "0xdad31e707d352f6cca78840f402f2ac9292094b51f55048abf0d2badfeff5463",
            "0x097e290170068e014ceda3dd47b28ede57ff7f916940294a13c9d4aa2dc98aad",
            "0x22e2dcedb6bb7f8ace1e43facaa502daa7513e523be98daf82163d2a76a1e0be",
            "0x7ef2b211ab710137e3e8c78b72744bf9de81c2adde007aef6e9ce92a05e7a2c5",
            "0x49b427805fc5186f31fdd1df9d4c3f51962ab74e15229e813072ec481c18c717",
            "0xe60f6caa09fa803d97613d58762e4ff7f22f47d5c30b9d0116cdc6a357de4464",
            "0xab3507b37ee92f026c72cc1559331630bc1c7335b374e4418d0d02687df1a9dd",
            "0x50825ae74319c9adebc8909ed7fc461702db8230c59975e8add09ad5e7a647ab",
            "0x0ee8e9c1d8a527a42fb8c2c8e9e51faf727cffc23ee22b5a95828f2790e87a29",
            "0x675c21c290ddb40bec0302f36fbcd2d1832717a4bc05d113c6118a62bc8f9aca",
            "0x580bafab24f673317b533148d7226d485e211eaa3d6e2be2529a83ca842b58a7",
            "0x540e474776cae597af24c147dc1ae0f70a6233e98cf5c3ce31f38b830b75c99a",
            "0x36eaf9f286e0f356eaaf8d81f71cc52c81d9ebc838c3b4859009f8567a224d16",
            "0x0e2cbbb40954be047d02b1450a3dbd2350506448425dc25fd5faf3a66ee8f5c4",
            "0x7eb0390cfe4c4eb120bbe693e87adc8ecab51d5fd8ce8f911c8ff07fad8cbe20",
            "0xbf77589f5c2ebb465b8d7936f6260a18a243f59bd87390ee22cf579f6f020285",
            "0x695b96bb28693f6928777591ef64146466d27521280a295936a52ec60707c565",
            "0x22a0d018cbd4274caa8b9e7fb132e0a7ed787874046ca683a7d81d1c7c8b8f15",
            "0x84092b122bb35e5ad85407b4b55f33707b86e0238c7970a8583f3c44308ed1d9",
            "0xea346067ca67255235f9cae949f06e4b6c93846a7abc7c8c8cd786e9c4b3e4bc",
            "0xa6df0716b125dc696b5d0e520cb49c1c089397c754efc146792e95bc58cc7159",
            "0x7377b5d3953029fc597fb10bb6479ee34133d38f08783fbb61c7d070f34ea66f",
            "0x7d79b00ffb976a10cd24476a394c8ed22f93837c51a58a3ddc7418153a5a8ea1",
            "0x01e55182e80dff26cc3e06bb736b4a63745bde8ae28c604fa7fb97d99de5f416",
            "0x062a2d5a207f8d540764d09648afecbf5033b13aec239f722b9033a762acf18b",
            "0x48be60a3221d98b4d62f0b89d3bef74c70878dd65c6f79b34c2c36d0ddaa1da0",
            "0x41e11f33543cf045c1a99419379ea31523d153bdf664549286b16207b9648c85",
            "0xeef4d30b4700813414763a199e7cc6ab0faec65ef8b514faa01c6aa520c76334",
            "0xea7cfe990422663417715e7859fc935ca47f47c943a1254044b6bc5934c94bc8",
            "0xbbd3c834e5403b98a0ca346c915a23310f3d58880786628bc6cfbe05ba29c3c5",
            "0xe216379f385bc9995ae0f37f1409a78d475c56b8aeb4ee434326724ec20124f7",
            "0xdd328a1eee19d09b6fef06e252f8ad0ae328fbf900ef745f5950896803a3899d",
            "0xa16fde34b0d743919feb0781eca0c525a499d279119af823cb3a8817000335db",
            "0x7a28d108c59b83b12c85cd9aabc1d1d994a9a0329ae7b64a32aadcd61ebe50e3",
            "0xb28bc82fceae74312eb837a805f0a8a01c0f669b99bb03fde31c4d58bedff89b",
            "0x1b0d8f37d349781e846900b51a90c828aa384afe9b8ee1f88aeb8dba4b3168f2",
            "0xbfd0301ff964c286c3331a30e09e0916da6f484e9c9596dbf1cae3cc902dbf9e",
            "0xbb8254cb9ef6b485b8fb6caeafe45f920affc30f6b9d671e9a454530536f4fef",
            "0xcad2317cf63dfa7147ded5c7e15f5f72e78f42d635e638f1ece6bc722ca3638b",
            "0xb6c6e856fd45117f54775142f2b38f31114539d8943bcbcf823f6c7650c001e4",
            "0x869f1baa35684c8f67a5bc99b294187852e6c85243a2f36481d0891d8b043020",
            "0x14c6ccf145ee40ff56e3810058d2fba9a943ffc7c7087c48a08b2451c13dc788",
            "0x263c1bcb712890f155b7e256cefa4abf92fe4380f3ffc11c627d5e4e30864d18",
            "0x69f4eaf655e31ad7f7a725cd415ce7e45dd4a8396ac416950d42ed33155c3487",
            "0x47e8eec2c5e33c9a54fe1f9b09e7744b614fb16531c36b862aa899424be13b05",
            "0x5c985de270e62c44f0b49157882e8e83641b906ce47959e337fe8423e125a2eb",
            "0x4e13b11e13202439bb5de5eea3bb75d2d7bf90f91411163ade06161a9cf424db",
            "0x583a8fa159bb74fa175d72f4e1705e9a3b8ffe26ec5ad6e720444b99288f1213",
            "0x903d2a746a98dfe2ee2632606d57a9b0fa6d8ccd895bb18c2245fd91f8a43676",
            "0xa35a51330316012d81ec7249e3f2b0c9d7fcbb99dd98c62fe880d0a152587f51",
            "0x33818a7beb91730c7b359b5e23f68a27b429967ea646d1ea99c314353f644218",
            "0x183650af1e0b67f0e7acb59f8c72cc0e60acc13896184db2a3e4613f65b70a8b",
            "0x857ff2974bef960e520937481c2047938a718cea0b709282ed4c2b0dbe2ef8fa",
            "0x95a367ecb9a401e98a4f66f964fb0ece783da86536410a2082c5dbb3fc865799",
            "0x56c606a736ac8268aedadd330d2681e7c7919af0fe855f6c1c3d5c837aa92338",
            "0x5c97f7abf30c6d0d4c23e762c026b94a6052a444df4ed942e91975419f68a3a4",
            "0x0b571de27d2022158a3128ae44d23a8136e7dd2dee74421aa4d6ed15ee1090a0",
            "0xa17f6bc934a2f3c33cea594fee8c96c1290feec934316ebbbd9efab4937bf9f9",
            "0x9ff57d70f27aad7281841e76435285fd27f10dad256b3f5cabde4ddc51b70eff",
            "0xafa3071a847215b3ccdf51954aa7cb3dd2e6e2a39800042fc42009da705508b2",
            "0x5e3bea33e4ac6f7c50a077d19571b1796e403549b1ce7b15e09905a0cc5a4acf",
            "0x0dc7ba994e632ab95f3ecb7848312798810cf761d1c776181882d17fd6dda075",
            "0xb4f7158679dad9f7370a2f64fbe617a40092849d17453b4f50a93ca8c6885844",
            "0x094564b00f53c6f27c121fd8adfe1685b258b259e585a67b57c85efb804c57b2",
            "0x9cd21a4249ba3fccffad550cdb8409dc12d8b74a7192874b6bafe2363886f318",
            "0xbb22e0dad55cb315c564c038686419d40ef7f13af2143a28455bf445f6e10393",
            "0x2a71d5e00821178c2cd39e7501e07da5cca6680eb7cdbe996f52dccafadb3735",
            "0x9619406093b121e044a5b403bb1713ae160aeb52ad441f82dc6c63e4b323b969",
            "0x3b8bd1d82c6d67ae707e19b889f1cb1f7bba912f12ae4284298f3a70c3644c79",
            "0xd7a70c50d47d48785b299dbea01bf03ef18b8495de3c35cb265bc8f3295c4e15",
            "0x8802ecce8dd6b6190af8ac79aafda3479c29f548d65e5798c0ca51a529b19108",
            "0x4b630e1df52ec5fd650f4a4e76b3eeddda39e1e9eab996f6d3f02eefdf690990",
            "0x0bfbff60fcf7f411d469f7f6f0a58ca305fd84eb529ee3ac73c00174793d723e",
            "0x535f78b5f3a99a1c498e2c19dc1acb0fbbaba8972ba1d7d66936c28ab3667ebe",
            "0x06ba92d8129db98fec1b75f9489a394022854f22f2e9b9450b187a6fc0d94a86",
            "0xb7ae275ba10f80fb618a2cf949d5ad2e3ae24eb2eb37dcf1ec8c8b148d3ba27f",
            "0xb275579bcf2584d9794dd3fc7f999902b13d33a9095e1980d506678e9c263de1",
            "0x843ccd52a81e33d03ad2702b4ef68f07ca0419d4495df848bff16d4965689e48",
            "0xde8b779ca7250f0eb867d5abdffd1d28c72a5a884d794383fc93ca40e5bf6276",
            "0x6b789a2befccb8788941c9b006e496b7f1b03dbb8e530ba339db0247a78a2850",
            "0xfccd4dca80bc52f9418f26b0528690255e320055327a34b50caf088235d2f660",
            "0x18479ebfbe86c1e94cd05c70cb6cace6443bd9fdac7e01e9c9535a9e85141f2f",
            "0x5350c8f3296441db954a261238c88a3a0c51ab418a234d566985f2809e211148",
            "0xa5636614135361d03a381ba9f6168e2fd0bd2c1105f9b4e347c414df8759dea3",
            "0xe7bb69e600992e6bd41c88a714f50f450153f1a05d0ddb4213a3fc4ba1f48c3f",
            "0x17b42e81bae19591e22aa2510be06803bcb5c39946c928c977d78f346d3ca86b",
            "0x30a10c07dc9646b7cbb3e1ab722a94d2c53e04c0c19efaaea7dccba1b00f2a20",
        ],
        compressed_lamport_pk:
            "0x672ba456d0257fe01910d3a799c068550e84881c8d441f8f5f833cbd6c1a9356",
        child_sk:
            "7419543105316279183937430842449358701327973165530407166294956473095303972104"
        }
    }
}
