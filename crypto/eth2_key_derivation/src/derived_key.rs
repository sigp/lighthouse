use crate::{lamport_secret_key::LamportSecretKey, secret_bytes::SecretBytes, ZeroizeHash};
use num_bigint_dig::BigUint;
use ring::hkdf::{KeyType, Prk, Salt, HKDF_SHA256};
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
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
/// `ceil((3 * ceil(log2(r))) / 16)`
pub const MOD_R_L: usize = 48;

/// A BLS secret key that is derived from some `seed`, or generated as a child from some other
/// `DerivedKey`.
///
/// Implements `Zeroize` on `Drop`.
// It's not strictly necessary that `DerivedKey` implements `Zeroize`, but it seems prudent to be a
// little over-cautious here; we don't require high-speed key generation at this stage.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DerivedKey(ZeroizeHash);

#[derive(Debug, PartialEq)]
pub enum Error {
    EmptySeed,
}

impl DerivedKey {
    /// Instantiates `Self` from some secret seed bytes.
    ///
    /// The key is generated deterministically; the same `seed` will always return the same `Self`.
    ///
    /// ## Errors
    ///
    /// Returns `Err(Error::EmptySeed)` if `seed.is_empty()`, otherwise always returns `Ok(self)`.
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        if seed.is_empty() {
            Err(Error::EmptySeed)
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
fn derive_master_sk(seed: &[u8]) -> ZeroizeHash {
    hkdf_mod_r(seed)
}

/// From the given `parent_sk`, derives a child key at index`.
///
/// Equivalent to `derive_child_SK` in EIP-2333.
fn derive_child_sk(parent_sk: &[u8], index: u32) -> ZeroizeHash {
    let compressed_lamport_pk = parent_sk_to_lamport_pk(parent_sk, index);
    hkdf_mod_r(compressed_lamport_pk.as_bytes())
}

/// From the `ikm` (initial key material), performs a HKDF-Extract and HKDF-Expand to generate a
/// BLS private key within the order of the BLS-381 curve.
///
/// Equivalent to `HKDF_mod_r` in EIP-2333.
fn hkdf_mod_r(ikm: &[u8]) -> ZeroizeHash {
    // ikm = ikm + I2OSP(0,1)
    let mut ikm_with_postfix = SecretBytes::zero(ikm.len() + 1);
    ikm_with_postfix.as_mut_bytes()[..ikm.len()].copy_from_slice(ikm);

    // info = "" + I2OSP(L, 2)
    let info = u16::try_from(MOD_R_L)
        .expect("MOD_R_L too large")
        .to_be_bytes();

    let mut output = ZeroizeHash::zero();
    let zero_hash = ZeroizeHash::zero();

    let mut salt = b"BLS-SIG-KEYGEN-SALT-".to_vec();
    while output.as_bytes() == zero_hash.as_bytes() {
        let mut hasher = Sha256::new();
        hasher.update(salt.as_slice());
        salt = hasher.finalize().to_vec();

        let prk = hkdf_extract(&salt, ikm_with_postfix.as_bytes());
        let okm = &hkdf_expand(prk, &info, MOD_R_L);

        output = mod_r(okm.as_bytes());
    }
    output
}

/// Interprets `bytes` as a big-endian integer and returns that integer modulo the order of the
/// BLS-381 curve.
///
/// This function is a part of the `HKDF_mod_r` function in EIP-2333.
fn mod_r(bytes: &[u8]) -> ZeroizeHash {
    let n = BigUint::from_bytes_be(bytes);
    let r = BigUint::parse_bytes(R.as_bytes(), 10).expect("must be able to parse R");
    let x = SecretBytes::from((n % r).to_bytes_be());

    let x_slice = x.as_bytes();

    debug_assert!(x_slice.len() <= HASH_SIZE);

    let mut output = ZeroizeHash::zero();
    output.as_mut_bytes()[HASH_SIZE - x_slice.len()..].copy_from_slice(&x_slice);
    output
}

/// Generates a Lamport public key from the given `ikm` (which is assumed to be a BLS secret key).
///
/// Equivalent to `parent_SK_to_lamport_PK` in EIP-2333.
fn parent_sk_to_lamport_pk(ikm: &[u8], index: u32) -> ZeroizeHash {
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

    let mut compressed_lamport_pk = ZeroizeHash::zero();
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
    let okm = hkdf_expand(prk, &[], HASH_SIZE * LAMPORT_ARRAY_SIZE as usize);
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
fn hkdf_expand(prk: Prk, info: &[u8], l: usize) -> SecretBytes {
    struct ExpandLen(usize);

    impl KeyType for ExpandLen {
        fn len(&self) -> usize {
            self.0
        }
    }

    let mut okm = SecretBytes::zero(l);
    prk.expand(&[info], ExpandLen(l))
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
fn flip_bits(input: &[u8]) -> ZeroizeHash {
    assert_eq!(input.len(), HASH_SIZE);

    let mut output = ZeroizeHash::zero();
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
            "6083874454709270928345386274498605044986640685124978867557563392430687146096",
            child_index: 0,
            lamport_0: vec![
                "0xe345d0ad7be270737de05cf036f688f385d5f99c7fddb054837658bdd2ebd519",
                "0x65050bd4db9c77c051f67dcc801bf1cdf33d81131e608505bb3e4523868eb76c",
                "0xc4f8e8d251fbdaed41bdd9c135b9ed5f83a614f49c38fffad67775a16575645a",
                "0x638ad0feace7567255120a4165a687829ca97e0205108b8b73a204fba6a66faa",
                "0xb29f95f64d0fcd0f45f265f15ff7209106ab5f5ce6a566eaa5b4a6f733139936",
                "0xbcfbdd744c391229f340f02c4f2d092b28fe9f1201d4253b9045838dd341a6bf",
                "0x8b9cf3531bfcf0e4acbfd4d7b4ed614fa2be7f81e9f4eaef53bedb509d0b186f",
                "0xb32fcc5c4e2a95fb674fa629f3e2e7d85335f6a4eafe7f0e6bb83246a7eced5f",
                "0xb4fe80f7ac23065e30c3398623b2761ac443902616e67ce55649aaa685d769ce",
                "0xb99354f04cfe5f393193c699b8a93e5e11e6be40ec16f04c739d9b58c1f55bf3",
                "0x93963f58802099ededb7843219efc66a097fab997c1501f8c7491991c780f169",
                "0x430f3b027dbe9bd6136c0f0524a0848dad67b253a11a0e4301b44074ebf82894",
                "0xd635c39b4a40ad8a54d9d49fc8111bd9d11fb65c3b30d8d3eaef7d7556aac805",
                "0x1f7253a6474cf0b2c05b02a7e91269137acddedcb548144821f9a90b10eccbab",
                "0x6e3bdb270b00e7b6eb8b044dbfae07b51ea7806e0d24218c59a807a7fd099c18",
                "0x895488ad2169d8eaae332ce5b0fe1e60ffab70e62e1cb15a2a1487544af0a6e8",
                "0x32d45a99d458c90e173a3087ea3661ab62d429b285089e92806a9663ba825342",
                "0xc15c52106c3177f5848a173076a20d46600ca65958a1e3c7d45a593aaa9670ed",
                "0xd8180c550fbe4cd6d5b676ff75e0728729d8e28a3b521d56152594ac6959d563",
                "0x58fe153fac8f4213aaf175e458435e06304548024bcb845844212c774bdffb2a",
                "0x10fff610a50f4bee5c978f512efa6ab4fafacb65929606951ba5b93eeb617b5a",
                "0x78ac9819799b52eba329f13dd52cf0f6148a80bf04f93341814c4b47bb4aa5ec",
                "0xa5c3339caa433fc11e74d1765bec577a13b054381a44b23c2482e750696876a9",
                "0x9f716640ab5cdc2a5eb016235cddca2dc41fa4ec5acd7e58af628dade99ec376",
                "0x2544364320e67577c4fed8c7c7c839deed93c24076d5343c5b8faca4cc6dc2d8",
                "0x62553e782541f822c589796be5d5c83bfc814819100b2be0710b246f5aa7149c",
                "0x229fb761c46c04b22ba5479f2696be0f936fded68d54dd74bcd736b8ba512afb",
                "0x0af23996a65b98a0ebaf19f3ec0b3ef20177d1bfd6eb958b3bd36e0bdbe04c8c",
                "0x6f0954f9deab52fd4c8d2daba69f73a80dea143dd49d9705c98db3d653adf98c",
                "0xfa9221dd8823919a95b35196c1faeb59713735827f3e84298c25c83ac700c480",
                "0x70c428e3ff9e5e3cda92d6bb85018fb89475c19f526461cca7cda64ebb2ff544",
                "0xdcaac3413e22314f0f402f8058a719b62966b3a7429f890d947be952f2e314ba",
                "0xb6b383cb5ec25afa701234824491916bfe6b09d28cf88185637e2367f0cf6edc",
                "0x7b0d91488fc916aba3e9cb61a5a5645b9def3b02e4884603542f679f602afb8d",
                "0xe9c20abca284acfde70c59584b9852b85c52fa7c263bb981389ff8d638429cd7",
                "0x838524f798daee6507652877feb9597f5c47e9bb5f9aa52a35fb6fff796813b9",
                "0xbe1ca18faf9bf322474fad1b3d9b4f1bc76ae9076e38e6dd2b16e2faf487742b",
                "0xbf02d70f1a8519343a16d24bade7f7222912fd57fe4f739f367dfd99d0337e8e",
                "0xc979eb67c107ff7ab257d1c0f4871adf327a4f2a69e01c42828ea27407caf058",
                "0xf769123d3a3f19eb7b5c3fd4f467a042944a7c5ff8834cebe427f47dbd71460c",
                "0xaefc8edc23257e1168a35999fe3832bcbc25053888cc89c38667482d6748095b",
                "0x8ff399f364d3a2428b1c92213e4fdc5341e7998007da46a5a2f671929b42aaab",
                "0xcf2a3d9e6963b24c5001fbba1e5ae7f45dd6cf520fd24861f745552db86bab48",
                "0xb380e272d7f3091e5c887fa2e7c690c67d59f4d95f8376d150e555da8c738559",
                "0xc006a749b091d91204dbb64f59059d284899de5986a7f84f8877afd5e0e4c253",
                "0x818d8bb9b7da2dafa2ef059f91975e7b6257f5e199d217320de0a576f020de5c",
                "0x7aabf4a1297d2e550a2ee20acb44c1033569e51b6ec09d95b22a8d131e30fd32",
                "0xdd01c80964a5d682418a616fb10810647c9425d150df643c8ddbbe1bfb2768b7",
                "0x1e2354e1d97d1b06eb6cfe9b3e611e8d75b5c57a444523e28a8f72a767eff115",
                "0x989c9a649dca0580256113e49ea0dd232bbfd312f68c272fe7c878acc5da7a2c",
                "0x14ee1efe512826fff9c028f8c7c86708b841f9dbf47ce4598298b01134ebdc1a",
                "0x6f861dba4503f85762d9741fa8b652ce441373f0ef2b7ebbd5a794e48cdab51b",
                "0xda110c9492ffdb87efe790214b7c9f707655a5ec08e5af19fb2ab2acc428e7dc",
                "0x5576aa898f6448d16e40473fcb24c46c609a3fc46a404559faa2d0d34d7d49ce",
                "0x9bd9a35675f2857792bc45893655bfdf905ffeaee942d93ad39fbcadd4ca9e11",
                "0xfa95e4c37db9303d5213890fd984034089cbc9c6d754741625da0aa59cc45ccf",
                "0xfef7d2079713f17b47239b76c8681bf7f800b1bfeac7a53265147579572ddf29",
                "0x39aa7c0fecf9a1ed037c685144745fda16da36f6d2004844cf0e2d608ef6ed0e",
                "0x5530654d502d6ba30f2b16f49cc5818279697308778fd8d40db8e84938144fb6",
                "0xb1beaa36397ba1521d7bf7df16536969d8a716e63510b1b82a715940180eb29f",
                "0x21abe342789f7c15a137afa373f686330c0db8c861572935a3cd8dcf9e4e1d45",
                "0x27b5a1acda55b4e0658887bd884d3203696fcae0e94f19e31bfe931342b1c257",
                "0x58401a02502d7708a812c0c72725f768f5a556480517258069f2d72543cda888",
                "0x4b38f291548f51bee7e4cf8cc5c8aa8f4ad3ec2461dba4ccbab70f1c1bfd7feb",
                "0x9b39a53fdafaaf1d23378e0aa8ae65d38480de69821de2910873eefc9f508568",
                "0x932200566a3563ee9141913d12fd1812cb008cb735724e8610890e101ec10112",
                "0x6a72f70b4ec5491f04780b17c4776a335fcc5bff5073d775150e08521dc74c91",
                "0x86d5c60e627a4b7d5d075b0ba33e779c45f3f46d22ed51f31360afd140851b67",
                "0x5ca2a736bb642abc4104faa781c9aff13d692a400d91dc961aec073889836946",
                "0xa14bca5a262ac46ceac21388a763561fc85fb9db343148d786826930f3e510cd",
                "0x87be03a87a9211504aa70ec149634ee1b97f7732c96377a3c04e98643dcba915",
                "0x8fe283bc19a377823377e9c326374ebb3f29527c12ea77bfb809c18eef8943b0",
                "0x8f519078b39a3969f7e4caeca9839d4e0eccc883b89e4a86d0e1731bfc5e33fc",
                "0x33d7c28c3d26fdfc015a8c2131920e1392ef0aea55505637b54ea63069c7858e",
                "0xe57de7c189fcc9170320c7acedb38798562a48dbc9943b2a8cd3441d58431128",
                "0x513dac46017050f82751a07b6c890f14ec43cadf687f7d202d2369e35b1836b4",
                "0xfd967d9f805bb7e78f7b7caa7692fdd3d6b5109c41ad239a08ad0a38eeb0ac4c",
                "0xf2013e4da9abcc0f03ca505ed94ec097556dbfd659088cd24ec223e02ac43329",
                "0xe0dcfac50633f7417f36231df2c81fa1203d358d5f57e896e1ab4b512196556b",
                "0xf022848130e73fe556490754ef0ecfcdaaf3b9ff16ae1eda7d38c95c4f159ded",
                "0x2147163a3339591ec7831d2412fb2d0588c38da3cd074fa2a4d3e5d21f9f1d2d",
                "0x11ee2404731962bf3238dca0d9759e06d1a5851308b4e6321090886ec5190b69",
                "0xf7679ecd07143f8ac166b66790fa09aed39352c09c0b4766bbe500b1ebace5a5",
                "0xc7a0e95f09076472e101813a95e6ea463c35bd5ee9cfda3e5d5dbccb35888ef0",
                "0xde625d3b547eb71bea5325a0191a592fa92a72e4b718a499fdba32e245ddf37e",
                "0x7e5bdccd95df216e8c59665073249072cb3c9d0aef6b341afc0ca90456942639",
                "0xc27f65fd9f797ede374e06b4ddb6e8aa59c7d6f36301f18b42c48b1889552fe3",
                "0x8175730a52ea571677b035f8e2482239dda1cfbff6bc5cde00603963511a81af",
                "0x09e440f2612dad1259012983dc6a1e24a73581feb1bd69d8a356eea16ba5fd0e",
                "0x59dcc81d594cbe735a495e38953e8133f8b3825fd84767af9e4ea06c49dbabfa",
                "0x6c8480b59a1a958c434b9680edea73b1207077fb9a8a19ea5f9fbbf6f47c4124",
                "0x81f5c89601893b7a5a231a7d37d6ab9aa4c57f174fcfc6b40002fa808714c3a1",
                "0x41ba4d6b4da141fcc1ee0f4b47a209cfd143d34e74fc7016e9956cedeb2db329",
                "0x5e0b5b404c60e9892040feacfb4a84a09c2bc4a8a5f54f3dad5dca4acdc899dc",
                "0xe922eebf1f5f15000d8967d16862ed274390cde808c75137d2fb9c2c0a80e391",
                "0xbf49d31a59a20484f0c08990b2345dfa954509aa1f8901566ab9da052b826745",
                "0xb84e07da828ae668c95d6aa31d4087504c372dbf4b5f8a8e4ded1bcf279fd52b",
                "0x89288bf52d8c4a9561421ad199204d794038c5d19ae9fee765ee2b5470e68e7e",
                "0xf6f618be99b85ec9a80b728454a417c647842215e2160c6fe547dd5a69bd9302",
                "0xdd9adc002f98c9a47c7b704fc0ce0a5c7861a5e2795b6014749cde8bcb8a034b",
                "0xd119a4b2c0db41fe01119115bcc35c4b7dbfdb42ad3cf2cc3f01c83732acb561",
                "0x9c66bc84d416b9193bad9349d8c665a9a06b835f82dc93ae0cccc218f808aad0",
                "0xd4b50eefcd2b5df075f14716cf6f2d26dfc8ae02e3993d711f4a287313038fde",
                "0xaf72bfb346c2f336b8bc100bff4ba35d006a3dad1c5952a0adb40789447f2704",
                "0xc43ca166f01dc955e7b4330227635feb1b0e0076a9c5633ca5c614a620244e5b",
                "0x5efca76970629521cfa053fbbbda8d3679cadc018e2e891043b0f52989cc2603",
                "0x35c57de1c788947f187051ce032ad1e899d9887d865266ec6fcfda49a8578b2b",
                "0x56d4be8a65b257216eab7e756ee547db5a882b4edcd12a84ed114fbd4f5be1f1",
                "0x257e858f8a4c07a41e6987aabaa425747af8b56546f2a3406f60d610bcc1f269",
                "0x40bd9ee36d52717ab22f1f6b0ee4fb38b594f58399e0bf680574570f1b4b8c90",
                "0xcb6ac01c21fc288c12973427c5df6eb8f6aefe64b92a6420c6388acdf36bc096",
                "0xa5716441312151a5f0deb52993a293884c6c8f445054ce1e395c96adeee66c6d",
                "0xe15696477f90113a10e04ba8225c28ad338c3b6bdd7bdeb95c0722921115ec85",
                "0x8faeaa52ca2f1d791cd6843330d16c75eaf6257e4ba236e3dda2bc1a644aee00",
                "0xc847fe595713bf136637ce8b43f9de238762953fed16798878344da909cc76ae",
                "0xb5740dc579594dd110078ce430b9696e6a308078022dde2d7cfe0ef7647b904e",
                "0x551a06d0771fcd3c53aea15aa8bf700047138ef1aa22265bee7fb965a84c9615",
                "0x9a65397a5907d604030508d41477de621ce4a0d79b772e81112d634455e7a4da",
                "0x6462d4cc2262d7faf8856812248dc608ae3d197bf2ef410f00c3ae43f2040995",
                "0x6782b1bd319568e30d54b324ab9ed8fdeac6515e36b609e428a60785e15fb301",
                "0x8bcdcf82c7eb2a07e14db20d80d9d2efea8d40320e121923784c92bf38250a8e",
                "0x46ed84fa17d226d5895e44685747ab82a97246e97d6237014611aaaba65ed268",
                "0x147e87981673326c5a2bdb06f5e90eaaa9583857129451eed6dde0c117fb061f",
                "0x4141d6fe070104c29879523ba6669552f3d457c0929bb878d2751f4ff059b895",
                "0xd866ce4ef226d74841f950fc28cdf2235db21e0e3f07a0c8f807704464db2210",
                "0xa804f9118bf92558f684f90c2bda832a4f51ef771ffb2765cde3ec6f48124f32",
                "0xc436d4a65910124e00cded9a637178914a8fbc090400f3f031c03eac4d0295a5",
                "0x643fdb9243656512316528de04dcc7344ca33783580ad0c3debf8c4a6e7c8bc4",
                "0x7f4a345b41706b281b2de998e91ff62d908eb29fc333ee336221757753c96e23",
                "0x6bdc086a5b11de950cabea33b72d98db886b291c4c2f02d3e997edc36785d249",
                "0xfb10b5b47d374078c0a52bff7174bf1cd14d872c7d20b4a009e2afd3017a9a17",
                "0x1e07e605312db5380afad8f3d7bd602998102fdd39565b618ac177b13a6527e6",
                "0xc3161b5a7b93aabf05652088b0e5b4803a18be693f590744c42c24c7aaaeef48",
                "0xa47e4f25112a7d276313f153d359bc11268b397933a5d5375d30151766bc689a",
                "0xb24260e2eff88716b5bf5cb75ea171ac030f5641a37ea89b3ac45acb30aae519",
                "0x2bcacbebc0a7f34406db2c088390b92ee34ae0f2922dedc51f9227b9afb46636",
                "0xc78c304f6dbe882c99c5e1354ce6077824cd42ed876db6706654551c7472a564",
                "0x6e2ee19d3ee440c78491f4e354a84fa593202e152d623ed899e700728744ac85",
                "0x2a3f438c5dc012aa0997b66f661b8c10f4a0cd7aa5b6e5922b1d73020561b27f",
                "0xd804f755d93173408988b95e9ea0e9feae10d404a090f73d9ff84df96f081cf7",
                "0xe06fda941b6936b8b33f00ffa02c8b05fd78fbec953da61da2043f5644b30a50",
                "0x45ee279b465d53148850a16cc7f6bd33e7627aef554a9418ed012ca8f9717f80",
                "0x9c79348c1bcd6aa2135452491d73564413a247ea8cc38fa7dcc6c43f8a2d61d5",
                "0x7c91e056f89f2a77d3e3642e595bcf4973c3bca68dd2b10f51ca0d8945e4255e",
                "0x669f976ebe38cbd22c5b1f785e14b76809d673d2cb1458983dbda41f5adf966b",
                "0x8bc71e99ffcc119fd8bd604af54c0663b0325a3203a214810fa2c588089ed5a7",
                "0x36b3f1ffeae5d9855e0965eef33f4c5133d99685802ac5ce5e1bb288d308f889",
                "0x0aad33df38b3f31598e04a42ec22f20bf2e2e9472d02371eb1f8a06434621180",
                "0x38c5632b81f90efbc51a729dcae03626a3063aa1f0a102fd0e4326e86a08a732",
                "0x6ea721753348ed799c98ffa330d801e6760c882f720125250889f107915e270a",
                "0xe700dd57ce8a653ce4269e6b1593a673d04d3de8b79b813354ac7c59d1b99adc",
                "0xe9294a24b560d62649ca898088dea35a644d0796906d41673e29e4ea8cd16021",
                "0xf20bb60d13a498a0ec01166bf630246c2f3b7481919b92019e2cfccb331f2791",
                "0xf639a667209acdd66301c8e8c2385e1189b755f00348d614dc92da14e6866b38",
                "0x49041904ee65c412ce2cd66d35570464882f60ac4e3dea40a97dd52ffc7b37a2",
                "0xdb36b16d3a1010ad172fc55976d45df7c03b05eab5432a77be41c2f739b361f8",
                "0x71400cdd2ea78ac1bf568c25a908e989f6d7e2a3690bc869c7c14e09c255d911",
                "0xf0d920b2d8a00b88f78e7894873a189c580747405beef5998912fc9266220d98",
                "0x1a2baefbbd41aa9f1cc5b10e0a7325c9798ba87de6a1302cf668a5de17bc926a",
                "0x449538a20e52fd61777c45d35ff6c2bcb9d9165c7eb02244d521317f07af6691",
                "0x97006755b9050b24c1855a58c4f4d52f01db4633baff4b4ef3d9c44013c5c665",
                "0xe441363a27b26d1fff3288222fa8ed540f8ca5d949ddcc5ff8afc634eec05336",
                "0xed587aa8752a42657fea1e68bc9616c40c68dcbbd5cb8d781e8574043e29ef28",
                "0x47d896133ba81299b8949fbadef1c00313d466827d6b13598685bcbb8776c1d2",
                "0x7786bc2cb2d619d07585e2ea4875f15efa22110e166af87b29d22af37b6c047d",
                "0x956b76194075fe3daf3ca508a6fad161deb05d0026a652929e37c2317239cbc6",
                "0xec9577cb7b85554b2383cc4239d043d14c08d005f0549af0eca6994e203cb4e7",
                "0x0722d0c68d38b23b83330b972254bbf9bfcf32104cc6416c2dad67224ac52887",
                "0x532b19d54fb6d77d96452d3e562b79bfd65175526cd793f26054c5f6f965df39",
                "0x4d62e065e57cbf60f975134a360da29cabdcea7fcfc664cf2014d23c733ab3b4",
                "0x09be0ea6b363fd746b303e482cb4e15ef25f8ae57b7143e64cbd5c4a1d069ebe",
                "0x69dcddc3e05147860d8d0e90d602ac454b609a82ae7bb960ee2ecd1627d77777",
                "0xa5e2ae69d902971000b1855b8066a4227a5be7234ac9513b3c769af79d997df4",
                "0xc287d4bc953dcff359d707caf2ccba8cc8312156eca8aafa261fb72412a0ea28",
                "0xb27584fd151fb30ed338f9cba28cf570f7ca39ebb03eb2e23140423af940bd96",
                "0x7e02928194441a5047af89a6b6555fea218f1df78bcdb5f274911b48d847f5f8",
                "0x9ba611add61ea6ba0d6d494c0c4edd03df9e6c03cafe10738cee8b7f45ce9476",
                "0x62647ec3109ac3db3f3d9ea78516859f0677cdde3ba2f27f00d7fda3a447dd01",
                "0xfa93ff6c25bfd9e17d520addf5ed2a60f1930278ff23866216584853f1287ac1",
                "0x3b391c2aa79c2a42888102cd99f1d2760b74f772c207a39a8515b6d18e66888a",
                "0xcc9ae3c14cbfb40bf01a09bcde913a3ed208e13e4b4edf54549eba2c0c948517",
                "0xc2b8bce78dd4e876da04c54a7053ca8b2bedc8c639cee82ee257c754c0bea2b2",
                "0xdb186f42871f438dba4d43755c59b81a6788cb3b544c0e1a3e463f6c2b6f7548",
                "0xb7f8ba137c7783137c0729de14855e20c2ac4416c33f5cac3b235d05acbab634",
                "0x282987e1f47e254e86d62bf681b0803df61340fdc9a8cf625ef2274f67fc6b5a",
                "0x04aa195b1aa736bf8875777e0aebf88147346d347613b5ab77bef8d1b502c08c",
                "0x3f732c559aee2b1e1117cf1dec4216a070259e4fa573a7dcadfa6aab74aec704",
                "0x72699d1351a59aa73fcede3856838953ee90c6aa5ef5f1f7e21c703fc0089083",
                "0x6d9ce1b8587e16a02218d5d5bed8e8d7da4ac40e1a8b46eeb412df35755c372c",
                "0x4f9c19b411c9a74b8616db1357dc0a7eaf213cb8cd2455a39eb7ae4515e7ff34",
                "0x9163dafa55b2b673fa7770b419a8ede4c7122e07919381225c240d1e90d90470",
                "0x268ff4507b42e623e423494d3bb0bc5c0917ee24996fb6d0ebedec9ce8cd9d5c",
                "0xff6e6169d233171ddc834e572024586eeb5b1bda9cb81e5ad1866dbc53dc75fe",
                "0xb379a9c8279205e8753b6a5c865fbbf70eb998f9005cd7cbde1511f81aed5256",
                "0x3a6b145e35a592e037c0992c9d259ef3212e17dca81045e446db2f3686380558",
                "0x60fb781d7b3137481c601871c1c3631992f4e01d415841b7f5414743dcb4cfd7",
                "0x90541b20b0c2ea49bca847e2db9b7bba5ce15b74e1d29194a12780e73686f3dd",
                "0xe2b0507c13ab66b4b769ad1a1a86834e385b315da2f716f7a7a8ff35a9e8f98c",
                "0xeefe54bc9fa94b921b20e7590979c28a97d8191d1074c7c68a656953e2836a72",
                "0x8676e7f59d6f2ebb0edda746fc1589ef55e07feab00d7008a0f2f6f129b7bb3a",
                "0x78a3d93181b40152bd5a8d84d0df7f2adde5db7529325c13bc24a5b388aed3c4",
                "0xcc0e2d0cba7aaa19c874dbf0393d847086a980628f7459e9204fda39fad375c0",
                "0x6e46a52cd7745f84048998df1a966736d2ac09a95a1c553016fef6b9ec156575",
                "0x204ac2831d2376d4f9c1f5c106760851da968dbfc488dc8a715d1c764c238263",
                "0xbdb8cc7b7e5042a947fca6c000c10b9b584e965c3590f92f6af3fe4fb23e1358",
                "0x4a55e4b8a138e8508e7b11726f617dcf4155714d4600e7d593fd965657fcbd89",
                "0xdfe064bb37f28d97b16d58b575844964205e7606dce914a661f2afa89157c45b",
                "0x560e374fc0edda5848eef7ff06471545fcbdd8aefb2ecddd35dfbb4cb03b7ddf",
                "0x10a66c82e146da5ec6f48b614080741bc51322a60d208a87090ad7c7bf6b71c6",
                "0x62534c7dc682cbf356e6081fc397c0a17221b88508eaeff798d5977f85630d4f",
                "0x0138bba8de2331861275356f6302b0e7424bbc74d88d8c534479e17a3494a15b",
                "0x580c7768bf151175714b4a6f2685dc5bcfeb088706ee7ed5236604888b84d3e4",
                "0xd290adb1a5dfc69da431c1c0c13da3be788363238d7b46bc20185edb45ab9139",
                "0x1689879db6c78eb4d3038ed81be1bc106f8cfa70a7c6245bd4be642bfa02ebd7",
                "0x6064c384002c8b1594e738954ed4088a0430316738def62822d08b2285514918",
                "0x01fd23493f4f1cc3c5ff4e96a9ee386b2a144b50a428a6b5db654072bddadfe7",
                "0xd5d05bb7f23ab0fa2b82fb1fb14ac29c2477d81a85423d0a45a4b7d5bfd81619",
                "0xd72b9a73ae7b24db03b84e01106cea734d4b9d9850b0b7e9d65d6001d859c772",
                "0x156317cb64578db93fee2123749aff58c81eae82b189b0d6f466f91de02b59df",
                "0x5fba299f3b2c099edbac18d785be61852225890fc004bf6be0787d62926a79b3",
                "0x004154f28f685bdbf0f0d6571e7a962a4c29b6c3ebedaaaf66097dfe8ae5f756",
                "0x4b45816f9834c3b289affce7a3dc80056c2b7ffd3e3c250d6dff7f923e7af695",
                "0x6ca53bc37816fff82346946d83bef87860626bbee7fd6ee9a4aeb904d893a11f",
                "0xf48b2f43184358d66d5b5f7dd2b14a741c7441cc7a33ba3ebcc94a7b0192d496",
                "0x3cb98f4baa429250311f93b46e745174f65f901fab4eb8075d380908aaaef650",
                "0x343dfc26b4473b3a20e706a8e87e5202a4e6b96b53ed448afb9180c3f766e5f8",
                "0x1ace0e8a735073bcbaea001af75b681298ef3b84f1dbab46ea52cee95ab0e7f9",
                "0xd239b110dd71460cdbc41ddc99494a7531186c09da2a697d6351c116e667733b",
                "0x22d6955236bd275969b8a6a30c23932670a6067f68e236d2869b6a8b4b493b83",
                "0x53c1c01f8d061ac89187e5815ef924751412e6a6aa4dc8e3abafb1807506b4e0",
                "0x2f56dd20c44d7370b713e7d7a1bfb1a800cac33f8a6157f278e17a943806a1f7",
                "0xc99773d8a5b3e60115896a65ac1d6c15863317d403ef58b90cb89846f4715a7f",
                "0x9f4b6b77c254094621cd336da06fbc6cbb7b8b1d2afa8e537ceca1053c561ef5",
                "0x87944d0b210ae0a6c201cba04e293f606c42ebaed8b4a5d1c33f56863ae7e1b5",
                "0xa7d116d962d03ca31a455f9cda90f33638fb36d3e3506605aa19ead554487a37",
                "0x4042e32e224889efd724899c9edb57a703e63a404129ec99858048fbc12f2ce0",
                "0x36759f7a0faeea1cd4cb91e404e4bf09908de6e53739603d5f0db52b664158a3",
                "0xa4d50d005fb7b9fea8f86f1c92439cc9b8446efef7333ca03a8f6a35b2d49c38",
                "0x80cb7c3e20f619006542edbe71837cdadc12161890a69eea8f41be2ee14c08a3",
                "0xbb3c44e1df45f2bb93fb80e7f82cee886c153ab484c0095b1c18df03523629b4",
                "0x04cb749e70fac3ac60dea779fceb0730b2ec5b915b0f8cf28a6246cf6da5db29",
                "0x4f5189b8f650687e65a962ef3372645432b0c1727563777433ade7fa26f8a728",
                "0x322eddddf0898513697599b68987be5f88c0258841affec48eb17cf3f61248e8",
                "0x6416be41cda27711d9ec22b3c0ed4364ff6975a24a774179c52ef7e6de9718d6",
                "0x0622d31b8c4ac7f2e30448bdadfebd5baddc865e0759057a6bf7d2a2c8b527e2",
                "0x40f096513588cc19c08a69e4a48ab6a43739df4450b86d3ec2fb3c6a743b5485",
                "0x09fcf7d49290785c9ea2d54c3d63f84f6ea0a2e9acfcdbb0cc3a281ce438250e",
                "0x2000a519bf3da827f580982d449b5c70fcc0d4fa232addabe47bb8b1c471e62e",
                "0xf4f80008518e200c40b043f34fb87a6f61b82f8c737bd784292911af3740245e",
                "0x939eaab59f3d2ad49e50a0220080882319db7633274a978ced03489870945a65",
                "0xadcad043d8c753fb10689280b7670f313253f5d719039e250a673d94441ee17c",
                "0x58b7b75f090166b8954c61057074707d7e38d55ce39d9b2251bbc3d72be458f8",
                "0xf61031890c94c5f87229ec608f2a9aa0a3f455ba8094b78395ae312cbfa04087",
                "0x356a55def50139f94945e4ea432e7a9defa5db7975462ebb6ca99601c614ea1d",
                "0x65963bb743d5db080005c4db59e29c4a4e86f92ab1dd7a59f69ea7eaf8e9aa79",
            ],
            lamport_1: vec![
                "0x9c0bfb14de8d2779f88fc8d5b016f8668be9e231e745640096d35dd5f53b0ae2",
                "0x756586b0f3227ab0df6f4b7362786916bd89f353d0739fffa534368d8d793816",
                "0x710108dddc39e579dcf0819f9ad107b3c56d1713530dd94325db1d853a675a37",
                "0x8862b5f428ce5da50c89afb50aa779bb2c4dfe60e6f6a070b3a0208a4a970fe5",
                "0x54a9cd342fa3a4bf685c01d1ce84f3068b0d5b6a58ee22dda8fbac4908bb9560",
                "0x0fa3800efeaddd28247e114a1cf0f86b9014ccae9c3ee5f8488168b1103c1b44",
                "0xbb393428b7ebfe2eda218730f93925d2e80c020d41a29f4746dcbb9138f7233a",
                "0x7b42710942ef38ef2ff8fe44848335f26189c88c22a49fda84a51512ac68cd5d",
                "0x90e99786a3e8b04db95ccd44d01e75558d75f3ddd12a1e9a2c2ce76258bf4813",
                "0x3f6f71e40251728aa760763d25deeae54dc3a9b53807c737deee219120a2230a",
                "0xe56081a7933c6eaf4ef2c5a04e21ab8a3897785dd83a34719d1b62d82cfd00c2",
                "0x76cc54fa15f53e326575a9a2ac0b8ed2869403b6b6488ce4f3934f17db0f6bee",
                "0x1cd9cd1d882ea3830e95162b5de4beb5ddff34fdbf7aec64e83b82a6d11b417c",
                "0xb8ca8ae36d717c448aa27405037e44d9ee28bb8c6cc538a5d22e4535c8befd84",
                "0x5c4492108c25f873a23d5fd7957b3229edc22858e8894febe7428c0831601982",
                "0x907bcd75e7465e9791dc34e684742a2c0dc7007736313a95070a7e6b961c9c46",
                "0xe7134b1511559e6b2440672073fa303ec3915398e75086149eb004f55e893214",
                "0x2ddc2415e4753bfc383d48733e8b2a3f082883595edc5515514ebb872119af09",
                "0xf2ad0f76b08ffa1eee62228ba76f4982fab4fbede5d4752c282c3541900bcd5b",
                "0x0a84a6b15abd1cbc2da7092bf7bac418b8002b7000236dfba7c8335f27e0f1d4",
                "0x97404e02b9ff5478c928e1e211850c08cc553ebac5d4754d13efd92588b1f20d",
                "0xfa6ca3bcff1f45b557cdec34cb465ab06ade397e9d9470a658901e1f0f124659",
                "0x5bd972d55f5472e5b08988ee4bccc7240a8019a5ba338405528cc8a38b29bc21",
                "0x52952e4f96c803bb76749800891e3bfe55f7372facd5b5a587a39ac10b161bcc",
                "0xf96731ae09abcad016fd81dc4218bbb5b2cb5fe2e177a715113f381814007314",
                "0xe7d79e07cf9f2b52623491519a21a0a3d045401a5e7e10dd8873a85076616326",
                "0xe4892f3777a4614ee6770b22098eaa0a3f32c5c44b54ecedacd69789d676dffe",
                "0x20c932574779e2cc57780933d1dc6ce51a5ef920ce5bf681f7647ac751106367",
                "0x057252c573908e227cc07797117701623a4835f4b047dcaa9678105299e48e70",
                "0x20bad780930fa2a036fe1dea4ccbf46ac5b3c489818cdb0f97ae49d6e2f11fbf",
                "0xc0d7dd26ffecdb098585a1694e45a54029bb1e31c7c5209289058efebb4cc91b",
                "0x9a8744beb1935c0abe4b11812fc02748ef7c8cb650db3024dde3c5463e9d8714",
                "0x8ce6eea4585bbeb657b326daa4f01f6aef34954338b3ca42074aedd1110ba495",
                "0x1c85b43f5488b370721290d2faea19d9918d094c99963d6863acdfeeca564363",
                "0xe88a244347e448349e32d0525b40b18533ea227a9d3e9b78a9ff14ce0a586061",
                "0x352ca61efc5b8ff9ee78e738e749142dd1606154801a1449bbb278fa6bcc3dbe",
                "0xa066926f9209220b24ea586fb20eb8199a05a247c82d7af60b380f6237429be7",
                "0x3052337ccc990bfbae26d2f9fe5d7a4eb8edfb83a03203dca406fba9f4509b6e",
                "0x343ce573a93c272688a068d758df53c0161aa7f9b55dec8beced363a38b33069",
                "0x0f16b5593f133b58d706fe1793113a10750e8111eadee65301df7a1e84f782d3",
                "0x808ae8539357e85b648020f1e9d255bc4114bee731a6220d7c5bcb5b85224e03",
                "0x3b2bd97e31909251752ac57eda6015bb05b85f2838d475095cfd146677430625",
                "0xe4f857c93b2d8b250050c7381a6c7c660bd29066195806c8ef11a2e6a6640236",
                "0x23d91589b5070f443ddcefa0838c596518d54928119251ecf3ec0946a8128f52",
                "0xb72736dfad52503c7f5f0c59827fb6ef4ef75909ff9526268abc0f296ee37296",
                "0x80a8c66436d86b8afe87dde7e53a53ef87e057a5d4995963e76d159286de61b6",
                "0xbec92c09ee5e0c84d5a8ba6ca329683ff550ace34631ea607a3a21f99cd36d67",
                "0x83c97c9807b9ba6d9d914ae49dabdb4c55e12e35013f9b179e6bc92d5d62222b",
                "0x8d9c79f6af3920672dc4cf97a297c186e75083d099aeb5c1051207bad0c98964",
                "0x2aaa5944a2bd852b0b1be3166e88f357db097b001c1a71ba92040b473b30a607",
                "0x46693d27ec4b764fbb516017c037c441f4558aebfe972cdcd03da67c98404e19",
                "0x903b25d9e12208438f203c9ae2615b87f41633d5ffda9cf3f124c1c3922ba08f",
                "0x3ec23dc8bc1b49f5c7160d78008f3f235252086a0a0fa3a7a5a3a53ad29ec410",
                "0xa1fe74ceaf3cccd992001583a0783d7d7b7a245ea374f369133585b576b9c6d8",
                "0xb2d6b0fe4932a2e06b99531232398f39a45b0f64c3d4ebeaaebc8f8e50a80607",
                "0xe19893353f9214eebf08e5d83c6d44c24bffe0eceee4dc2e840d42eab0642536",
                "0x5b798e4bc099fa2e2b4b5b90335c51befc9bbab31b4dd02451b0abd09c06ee79",
                "0xbab2cdec1553a408cac8e61d9e6e19fb8ccfb48efe6d02bd49467a26eeeca920",
                "0x1c1a544c28c38e5c423fe701506693511b3bc5f2af9771b9b2243cd8d41bebfc",
                "0x704d6549d99be8cdefeec9a58957f75a2be4af7bc3dc4655fa606e7f3e03b030",
                "0x051330f43fe39b08ed7d82d68c49b36a8bfa31357b546bfb32068712df89d190",
                "0xe69174c7b03896461cab2dfaab33d549e3aac15e6b0f6f6f466fb31dae709b9b",
                "0xe5f668603e0ddbbcde585ac41c54c3c4a681fffb7a5deb205344de294758e6ac",
                "0xca70d5e4c3a81c1f21f246a3f52c41eaef9a683f38eb7c512eac8b385f46cbcd",
                "0x3173a6b882b21cd147f0fc60ef8f24bbc42104caed4f9b154f2d2eafc3a56907",
                "0xc71469c192bf5cc36242f6365727f57a19f924618b8a908ef885d8f459833cc3",
                "0x59c596fc388afd8508bd0f5a1e767f3dda9ed30f6646d15bc59f0b07c4de646f",
                "0xb200faf29368581f551bd351d357b6fa8cbf90bdc73b37335e51cad36b4cba83",
                "0x275cede69b67a9ee0fff1a762345261cb20fa8191470159cc65c7885cfb8313c",
                "0x0ce4ef84916efbe1ba9a0589bed098793b1ea529758ea089fd79151cc9dc7494",
                "0x0f08483bb720e766d60a3cbd902ce7c9d835d3f7fdf6dbe1f37bcf2f0d4764a2",
                "0xb30a73e5db2464e6da47d10667c82926fa91fceb337d89a52db5169008bc6726",
                "0x6b9c50fed1cc404bf2dd6fffbfd18e30a4caa1500bfeb080aa93f78d10331aaf",
                "0xf17c84286df03ce175966f560600dd562e0f59f18f1d1276b4d8aca545d57856",
                "0x11455f2ef96a6b2be69854431ee219806008eb80ea38c81e45b2e58b3f975a20",
                "0x9a61e03e2157a5c403dfcde690f7b7d704dd56ea1716cf14cf7111075a8d6491",
                "0x30312c910ce6b39e00dbaa669f0fb7823a51f20e83eaeb5afa63fb57668cc2f4",
                "0x17c18d261d94fba82886853a4f262b9c8b915ed3263b0052ece5826fd7e7d906",
                "0x2d8f6ea0f5b9d0e4bc1478161f5ed2ad3d8495938b414dcaec9548adbe572671",
                "0x19954625f13d9bab758074bf6dee47484260d29ee118347c1701aaa74abd9848",
                "0x842ef2ad456e6f53d75e91e8744b96398df80350cf7af90b145fea51fbbcf067",
                "0x34a8b0a76ac20308aa5175710fb3e75c275b1ff25dba17c04e3a3e3c48ca222c",
                "0x58efcbe75f32577afe5e9ff827624368b1559c32fcca0cf4fd704af8ce019c63",
                "0x411b4d242ef8f14d92bd8b0b01cb4fa3ca6f29c6f9073cfdd3ce614fa717463b",
                "0xf76dbda66ede5e789314a88cff87ecb4bd9ca418c75417d4d920e0d21a523257",
                "0xd801821a0f87b4520c1b003fe4936b6852c410ee00b46fb0f81621c9ac6bf6b4",
                "0x97ad11d6a29c8cf3c548c094c92f077014de3629d1e9053a25dbfaf7eb55f72d",
                "0xa87012090cd19886d49521d564ab2ad0f18fd489599050c42213bb960c9ee8ff",
                "0x8868d8a26e758d50913f2bf228da0444a206e52853bb42dd8f90f09abe9c859a",
                "0xc257fb0cc9970e02830571bf062a14540556abad2a1a158f17a18f14b8bcbe95",
                "0xfe611ce27238541b14dc174b652dd06719dfbcda846a027f9d1a9e8e9df2c065",
                "0xc9b25ea410f420cc2d4fc6057801d180c6cab959bce56bf6120f555966e6de6d",
                "0x95437f0524ec3c04d4132c83be7f1a603e6f4743a85ede25aa97a1a4e3f3f8fc",
                "0x82a12910104065f35e983699c4b9187aed0ab0ec6146f91728901efecc7e2e20",
                "0x6622dd11e09252004fb5aaa39e283333c0686065f228c48a5b55ee2060dbd139",
                "0x89a2879f25733dab254e4fa6fddb4f04b8ddf018bf9ad5c162aea5c858e6faaa",
                "0x8a71b62075a6011fd9b65d956108fa79cc9ebb8f194d64d3105a164e01cf43a6",
                "0x103f4fe9ce211b6452181371f0dc4a30a557064b684645a4495136f4ebd0936a",
                "0x97914adc5d7ce80147c2f44a6b29d0b495d38dedd8cc299064abcc62ed1ddabc",
                "0x825c481da6c836a8696d7fda4b0563d204a9e7d9e4c47b46ded26db3e2d7d734",
                "0xf8c0637ba4c0a383229f1d730db733bc11d6a4e33214216c23f69ec965dcaaad",
                "0xaed3bdaf0cb12d37764d243ee0e8acdefc399be2cabbf1e51dc43454efd79cbd",
                "0xe8427f56cc5cec8554e2f5f586b57adccbea97d5fc3ef7b8bbe97c2097cf848c",
                "0xba4ad0abd5c14d526357fd0b6f8676ef6126aeb4a6d80cabe1f1281b9d28246c",
                "0x4cff20b72e2ab5af3fafbf9222146949527c25f485ec032f22d94567ff91b22f",
                "0x0d32925d89dd8fed989912afcbe830a4b5f8f7ae1a3e08ff1d3a575a77071d99",
                "0xe51a1cbeae0be5d2fdbc7941aea904d3eade273f7477f60d5dd6a12807246030",
                "0xfb8615046c969ef0fa5e6dc9628c8a9880e86a5dc2f6fc87aff216ea83fcf161",
                "0x64dd705e105c88861470d112c64ca3d038f67660a02d3050ea36c34a9ebf47f9",
                "0xb6ad148095c97528180f60fa7e8609bf5ce92bd562682092d79228c2e6f0750c",
                "0x5bae0cd81f3bd0384ca3143a72068e6010b946462a73299e746ca639c026781c",
                "0xc39a0fc7764fcfc0402b12fb0bbe78fe3633cbfb33c7f849279585a878a26d7c",
                "0x2b752fda1c0c53d685cc91144f78d371db6b766725872b62cc99e1234cca8c1a",
                "0x40ee6b9635d87c95a528757729212a261843ecb06d975de91352d43ca3c7f196",
                "0x75e2005d3726cf8a4bb97ea5287849a361e3f8fdfadc3c1372feed1208c89f6b",
                "0x0976f8ab556153964b58158678a5297da4d6ad92e284da46052a791ee667aee4",
                "0xdbeef07841e41e0672771fb550a5b9233ae8e9256e23fa0d34d5ae5efe067ec8",
                "0xa890f412ab6061c0c5ee661e80d4edc5c36b22fb79ac172ddd5ff26a7dbe9751",
                "0xb666ae07f9276f6d0a33f9efeb3c5cfcba314fbc06e947563db92a40d7a341e8",
                "0x83a082cf97ee78fbd7f31a01ae72e40c2e980a6dab756161544c27da86043528",
                "0xfa726a919c6f8840c456dc77b0fec5adbed729e0efbb9317b75f77ed479c0f44",
                "0xa8606800c54faeab2cbc9d85ff556c49dd7e1a0476027e0f7ce2c1dc2ba7ccbf",
                "0x2796277836ab4c17a584c9f6c7778d10912cb19e541fb75453796841e1f6cd1c",
                "0xf648b8b3c7be06f1f8d9cda13fd6d60f913e5048a8e0b283b110ca427eeb715f",
                "0xa21d00b8fdcd77295d4064e00fbc30bed579d8255e9cf3a9016911d832390717",
                "0xe741afcd98cbb3bb140737ed77bb968ac60d5c00022d722f9f04f56e97235dc9",
                "0xbeecc9638fac39708ec16910e5b02c91f83f6321f6eb658cf8a96353cfb49806",
                "0x912eee6cabeb0fed8d6e6ca0ba61977fd8e09ea0780ff8fbec995e2a85e08b52",
                "0xc665bc0bb121a1229bc56ecc07a7e234fd24c523ea14700aa09e569b5f53ad33",
                "0x39501621c2bdff2f62ab8d8e3fe47fe1701a98c665697c5b750ee1892f11846e",
                "0x03d32e16c3a6c913daefb139f131e1e95a742b7be8e20ee39b785b4772a50e44",
                "0x4f504eb46a82d440f1c952a06f143994bc66eb9e3ed865080cd9dfc6d652b69c",
                "0xad753dc8710a46a70e19189d8fc7f4c773e4d9ccc7a70c354b574fe377328741",
                "0xf7f5464a2d723b81502adb9133a0a4f0589b4134ca595a82e660987c6b011610",
                "0x216b60b1c3e3bb4213ab5d43e04619d13e1ecedbdd65a1752bda326223e3ca3e",
                "0x763664aa96d27b6e2ac7974e3ca9c9d2a702911bc5d550d246631965cf2bd4a2",
                "0x292b5c8c8431b040c04d631f313d4e6b67b5fd3d4b8ac9f2edb09d13ec61f088",
                "0x80db43c2b9e56eb540592f15f5900222faf3f75ce62e78189b5aa98c54568a5e",
                "0x1b5fdf8969bcd4d65e86a2cefb3a673e18d587843f4f50db4e3ee77a0ba2ef1c",
                "0x11e237953fff3e95e6572da50a92768467ffdfd0640d3384aa1c486357e7c24a",
                "0x1fabd4faa8dba44808cc87d0bc389654a98496745578f3d17d134adc7f7b10f3",
                "0x5eca4aa96f20a56197772ae6b600762154ca9d2702cab12664ea47cbff1a440c",
                "0x0b4234f5bb02abcf3b5ce6c44ea85f55ec7db98fa5a7b90abef6dd0df034743c",
                "0x316761e295bf350313c4c92efea591b522f1df4211ce94b22e601f30aefa51ef",
                "0xe93a55ddb4d7dfe02598e8f909ff34b3de40a1c0ac8c7fba48cb604ea60631fb",
                "0xe6e6c877b996857637f8a71d0cd9a6d47fdeb03752c8965766f010073332b087",
                "0xa4f95c8874e611eddd2c4502e4e1196f0f1be90bfc37db35f8588e7d81d34aeb",
                "0x9351710a5633714bb8b2d226e15ba4caa6f50f56c5508e5fa1239d5cc6a7e1aa",
                "0x8d0aef52ec7266f37adb572913a6213b8448caaf0384008373dec525ae6cdff1",
                "0x718e24c3970c85bcb14d2763201812c43abac0a7f16fc5787a7a7b2f37288586",
                "0x3600ce44cebc3ee46b39734532128eaf715c0f3596b554f8478b961b0d6e389a",
                "0x50dd1db7b0a5f6bd2d16252f43254d0f5d009e59f61ebc817c4bbf388519a46b",
                "0x67861ed00f5fef446e1f4e671950ac2ddae1f3b564f1a6fe945e91678724ef03",
                "0x0e332c26e169648bc20b4f430fbf8c26c6edf1a235f978d09d4a74c7b8754aad",
                "0x6c9901015adf56e564dfb51d41a82bde43fb67273b6911c9ef7fa817555c9557",
                "0x53c83391e5e0a024f68d5ade39b7a769f10664e12e4942c236398dd5dbce47a1",
                "0x78619564f0b2399a9fcb229d938bf1e298d62b03b7a37fe6486034185d7f7d27",
                "0x4625f15381a8723452ec80f3dd0293c213ae35de737c508f42427e1735398c3a",
                "0x69542425ddb39d3d3981e76b41173eb1a09500f11164658a3536bf3e292f8b6a",
                "0x82ac4f5bb40aece7d6706f1bdf4dfba5c835c09afba6446ef408d8ec6c09300f",
                "0x740f9180671091b4c5b3ca59b9515bd0fc751f48e488a9f7f4b6848602490e21",
                "0x9a04b08b4115986d8848e80960ad67490923154617cb82b3d88656ec1176c24c",
                "0xf9ffe528eccffad519819d9eef70cef317af33899bcaee16f1e720caf9a98744",
                "0x46da5e1a14b582b237f75556a0fd108c4ea0d55c0edd8f5d06c59a42e57410df",
                "0x098f3429c8ccda60c3b5b9755e5632dd6a3f5297ee819bec8de2d8d37893968a",
                "0x1a5b91af6025c11911ac072a98b8a44ed81f1f3c76ae752bd28004915db6f554",
                "0x8bed50c7cae549ed4f8e05e02aa09b2a614c0af8eec719e4c6f7aee975ec3ec7",
                "0xd86130f624b5dcc116f2dfbb5219b1afde4b7780780decd0b42694e15c1f8d8b",
                "0x4167aa9bc0075f624d25d40eb29139dd2c452ebf17739fab859e14ac6765337a",
                "0xa258ce5db20e91fb2ea30d607ac2f588bdc1924b21bbe39dc881e19889a7f5c6",
                "0xe5ef8b5ab3cc8894452d16dc875b69a55fd925808ac7cafef1cd19485d0bb50a",
                "0x120df2b3975d85b6dfca56bb98a82025ade5ac1d33e4319d2e0105b8de9ebf58",
                "0xc964291dd2e0807a468396ebba3d59cfe385d949f6d6215976fc9a0a11de209a",
                "0xf23f14cb709074b79abe166f159bc52b50de687464df6a5ebf112aa953c95ad5",
                "0x622c092c9bd7e30f880043762e26d8e9c73ab7c0d0806f3c5e472a4152b35a93",
                "0x8a5f090662731e7422bf651187fb89812419ab6808f2c62da213d6944fccfe9f",
                "0xfbea3c0d92e061fd2399606f42647d65cc54191fa46d57b325103a75f5c22ba6",
                "0x2babfbcc08d69b52c3747ddc8dcad4ea5511edabf24496f3ff96a1194d6f680e",
                "0x4d3d019c28c779496b616d85aee201a3d79d9eecf35f728d00bcb12245ace703",
                "0xe76fcee1f08325110436f8d4a95476251326b4827399f9b2ef7e12b7fb9c4ba1",
                "0x4884d9c0bb4a9454ea37926591fc3eed2a28356e0506106a18f093035638da93",
                "0x74c3f303d93d4cc4f0c1eb1b4378d34139220eb836628b82b649d1deb519b1d3",
                "0xacb806670b278d3f0c84ba9c7a68c7df3b89e3451731a55d7351468c7c864c1c",
                "0x8660fb8cd97e585ea7a41bccb22dd46e07eee8bbf34d90f0f0ca854b93b1ebee",
                "0x2fc9c89cdca71a1c0224d469d0c364c96bbd99c1067a7ebe8ef412c645357a76",
                "0x8ec6d5ab6ad7135d66091b8bf269be44c20af1d828694cd8650b5479156fd700",
                "0x50ab4776e8cabe3d864fb7a1637de83f8fbb45d6e49645555ffe9526b27ebd66",
                "0xbf39f5e17082983da4f409f91c7d9059acd02ccbefa69694aca475bb8d40b224",
                "0x3135b3b981c850cc3fe9754ec6af117459d355ad6b0915beb61e84ea735c31bf",
                "0xa7971dab52ce4bf45813223b0695f8e87f64b614c9c5499faac6f842e5c41be9",
                "0x9e480f5617323ab104b4087ac4ef849a5da03427712fb302ac085507c77d8f37",
                "0x57a6d474654d5e8d408159be39ad0e7026e6a4c6a6543e23a63d30610dc8dfc1",
                "0x09eb3e01a5915a4e26d90b4c58bf0cf1e560fdc8ba53faed9d946ad3e9bc78fa",
                "0x29c6d25da80a772310226b1b89d845c7916e4a4bc94d75aa330ec3eaa14b1e28",
                "0x1a1ccfee11edeb989ca02e3cb89f062612a22a69ec816a625835d79370173987",
                "0x1cb63dc541cf7f71c1c4e8cabd2619c3503c0ea1362dec75eccdf1e9efdbfcfc",
                "0xac9dff32a69e75b396a2c250e206b36c34c63b955c9e5732e65eaf7ccca03c62",
                "0x3e1b4f0c3ebd3d38cec389720147746774fc01ff6bdd065f0baf2906b16766a8",
                "0x5cc8bed25574463026205e90aad828521f8e3d440970d7e810d1b46849681db5",
                "0x255185d264509bd3a768bb0d50b568e66eb1fec96d573e33aaacc716d7c8fb93",
                "0xe81b86ba631973918a859ff5995d7840b12511184c2865401f2693a71b9fa07e",
                "0x61e67e42616598da8d36e865b282127c761380d3a56d26b8d35fbbc7641433c5",
                "0x60c62ffef83fe603a34ca20b549522394e650dad5510ae68b6e074f0cd209a56",
                "0x78577f2caf4a54f6065593535d76216f5f4075af7e7a98b79571d33b1822920c",
                "0xfd4cb354f2869c8650200de0fe06f3d39e4dbebf19b0c1c2677da916ea84f44d",
                "0x453769cef6ff9ba2d5c917982a1ad3e2f7e947d9ea228857556af0005665e0b0",
                "0xe567f93f8f88bf1a6b33214f17f5d60c5dbbb531b4ab21b8c0b799b6416891e0",
                "0x7e65a39a17f902a30ceb2469fe21cba8d4e0da9740fcefd5c647c81ff1ae95fa",
                "0x03e4a7eea0cd6fc02b987138ef88e8795b5f839636ca07f6665bbae9e5878931",
                "0xc3558e2b437cf0347cabc63c95fa2710d3f43c65d380feb998511903f9f4dcf0",
                "0xe3a615f80882fb5dfbd08c1d7a8b0a4d3b651d5e8221f99b879cb01d97037a9c",
                "0xb56db4a5fea85cbffaee41f05304689ea321c40d4c108b1146fa69118431d9b2",
                "0xab28e1f077f18117945910c235bc9c6f9b6d2b45e9ef03009053006c637e3e26",
                "0xefcabc1d5659fd6e48430dbfcc9fb4e08e8a9b895f7bf9b3d6c7661bfc44ada2",
                "0xc7547496f212873e7c3631dafaca62a6e95ac39272acf25a7394bac6ea1ae357",
                "0xc482013cb01bd69e0ea9f447b611b06623352e321469f4adc739e3ee189298eb",
                "0x5942f42e91e391bb44bb2c4d40da1906164dbb6d1c184f00fa62899baa0dba2c",
                "0xb4bcb46c80ad4cd603aff2c1baf8f2c896a628a46cc5786f0e58dae846694677",
                "0xd0a7305b995fa8c317c330118fee4bfef9f65f70b54558c0988945b08e90ff08",
                "0x687f801b7f32fdfa7d50274cc7b126efedbdae8de154d36395d33967216f3086",
                "0xeb19ec10ac6c15ffa619fa46792971ee22a9328fa53bd69a10ed6e9617dd1bbf",
                "0xa2bb3f0367f62abdb3a9fa6da34b20697cf214a4ff14fd42826da140ee025213",
                "0x070a76511f32c882374400af59b22d88974a06fbc10d786dd07ca7527ebd8b90",
                "0x8f195689537b446e946b376ec1e9eb5af5b4542ab47be550a5700fa5d81440d5",
                "0x10cc09778699fc8ac109e7e6773f83391eeba2a6db5226fbe953dd8d99126ca5",
                "0x8cc839cb7dc84fd3b8c0c7ca637e86a2f72a8715cc16c7afb597d12da717530b",
                "0xa32504e6cc6fd0ee441440f213f082fcf76f72d36b5e2a0f3b6bdd50cdd825a2",
                "0x8f45151db8878e51eec12c450b69fa92176af21a4543bb78c0d4c27286e74469",
                "0x23f5c465bd35bcd4353216dc9505df68324a27990df9825a242e1288e40a13bb",
                "0x35f409ce748af33c20a6ae693b8a48ba4623de9686f9834e22be4410e637d24f",
                "0xb962e5845c1db624532562597a99e2acc5e434b97d8db0725bdeddd71a98e737",
                "0x0f8364f99f43dd52b4cfa9e426c48f7b6ab18dc40a896e96a09eceebb3363afe",
                "0xa842746868da7644fccdbb07ae5e08c71a6287ab307c4f9717eadb414c9c99f4",
                "0xa59064c6b7fe7d2407792d99ed1218d2dc2f240185fbd8f767997438241b92e9",
                "0xb6ea0d58e8d48e05b9ff4d75b2ebe0bd9752c0e2691882f754be66cdec7628d3",
                "0xf16b78c9d14c52b2b5156690b6ce37a5e09661f49674ad22604c7d3755e564d1",
                "0xbfa8ef74e8a37cd64b8b4a4260c4fc162140603f9c2494b9cf4c1e13de522ed9",
                "0xf4b89f1776ebf30640dc5ec99e43de22136b6ef936a85193ef940931108e408a",
                "0xefb9a4555d495a584dbcc2a50938f6b9827eb014ffae2d2d0aae356a57894de8",
                "0x0627a466d42a26aca72cf531d4722e0e5fc5d491f4527786be4e1b641e693ac2",
                "0x7d10d21542de3d8f074dbfd1a6e11b3df32c36272891aae54053029d39ebae10",
                "0x0f21118ee9763f46cc175a21de876da233b2b3b62c6f06fa2df73f6deccf37f3",
                "0x143213b96f8519c15164742e2350cc66e814c9570634e871a8c1ddae4d31b6b5",
                "0x8d2877120abae3854e00ae8cf5c8c95b3ede10590ab79ce2be7127239507e18d",
                "0xaccd0005d59472ac04192c059ed9c10aea42c4dabec9e581f6cb10b261746573",
                "0x67bc8dd5422f39e741b9995e6e60686e75d6620aa0d745b84191f5dba9b5bb18",
                "0x11b8e95f6a654d4373cefbbac29a90fdd8ae098043d1969b9fa7885318376b34",
                "0x431a0b8a6f08760c942eeff5791e7088fd210f877825ce4dcabe365e03e4a65c",
                "0x704007f11bae513f428c9b0d23593fd2809d0dbc4c331009856135dafec23ce4",
                "0xc06dee39a33a05e30c522061c1d9272381bde3f9e42fa9bd7d5a5c8ef11ec6ec",
                "0x66b4157baaae85db0948ad72882287a80b286df2c40080b8da4d5d3db0a61bd2",
                "0xef1983b1906239b490baaaa8e4527f78a57a0a767d731f062dd09efb59ae8e3d",
                "0xf26d0d5c520cce6688ca5d51dee285af26f150794f2ea9f1d73f6df213d78338",
                "0x8b28838382e6892f59c42a7709d6d38396495d3af5a8d5b0a60f172a6a8940bd",
                "0x261a605fa5f2a9bdc7cffac530edcf976e7ea7af4e443b625fe01ed39dad44b6",
            ],
            compressed_lamport_pk:
            "0xdd635d27d1d52b9a49df9e5c0c622360a4dd17cba7db4e89bce3cb048fb721a5",
            child_sk:
            "20397789859736650942317412262472558107875392172444076792671091975210932703118",
        }
    }
}
