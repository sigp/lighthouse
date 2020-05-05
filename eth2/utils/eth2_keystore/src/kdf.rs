use crypto::sha2::Sha256;
use crypto::{hmac::Hmac, mac::Mac, pbkdf2, scrypt};
use rand::prelude::*;
use serde::{de, Deserialize, Serialize, Serializer};
use std::convert::TryFrom;
use std::default::Default;
use zeroize::Zeroize;

// TODO: verify size of salt
const SALT_SIZE: usize = 32;
const DECRYPTION_KEY_SIZE: usize = 32;
const DKLEN: u32 = 32;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DerivedKey([u8; DECRYPTION_KEY_SIZE]);

impl DerivedKey {
    /// Instantiates `Self` with a all-zeros byte array.
    fn zero() -> Self {
        Self([0; DECRYPTION_KEY_SIZE])
    }

    /// Returns a mutable reference to the underlying byte array.
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Returns the `DK_slice` bytes used for checksum comparison.
    ///
    /// ## Reference
    ///
    /// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2335.md#procedure
    pub fn checksum_slice(&self) -> &[u8] {
        &self.0[16..32]
    }

    /// Returns the aes-128-ctr key.
    ///
    /// Only the first 16 bytes of the decryption_key are used as the AES key.
    ///
    /// ## Reference
    ///
    /// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2335.md#secret-decryption
    pub fn aes_key(&self) -> &[u8] {
        &self.0[0..16]
    }
}

/// Parameters for `pbkdf2` key derivation.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Pbkdf2 {
    pub c: u32,
    pub dklen: u32,
    pub prf: Prf,
    #[serde(serialize_with = "serialize_salt")]
    #[serde(deserialize_with = "deserialize_salt")]
    pub salt: Vec<u8>,
}
impl Default for Pbkdf2 {
    fn default() -> Self {
        let salt = rand::thread_rng().gen::<[u8; SALT_SIZE]>();
        Pbkdf2 {
            dklen: DKLEN,
            c: 262144,
            prf: Prf::default(),
            salt: salt.to_vec(),
        }
    }
}

impl Pbkdf2 {
    /// Derive key from password.
    pub fn derive_key(&self, password: &str) -> DerivedKey {
        let mut dk = DerivedKey::zero();
        let mut mac = self.prf.mac(password.as_bytes());
        pbkdf2::pbkdf2(&mut mac, &self.salt, self.c, dk.as_mut_bytes());
        dk
    }
}

/// Parameters for `scrypt` key derivation.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Scrypt {
    pub dklen: u32,
    pub n: u32,
    pub r: u32,
    pub p: u32,
    #[serde(serialize_with = "serialize_salt")]
    #[serde(deserialize_with = "deserialize_salt")]
    pub salt: Vec<u8>,
}

/// Compute floor of log2 of a u32.
fn log2_int(x: u32) -> u32 {
    if x == 0 {
        return 0;
    }
    31 - x.leading_zeros()
}

impl Scrypt {
    pub fn derive_key(&self, password: &str) -> DerivedKey {
        let mut dk = DerivedKey::zero();
        // Assert that `n` is power of 2
        debug_assert_eq!(self.n, 2u32.pow(log2_int(self.n)));
        let params = scrypt::ScryptParams::new(log2_int(self.n) as u8, self.r, self.p);
        scrypt::scrypt(password.as_bytes(), &self.salt, &params, &mut dk.0);
        dk
    }
}

impl Default for Scrypt {
    fn default() -> Self {
        let salt = rand::thread_rng().gen::<[u8; SALT_SIZE]>();
        Scrypt {
            dklen: DKLEN,
            n: 262144,
            r: 8,
            p: 1,
            salt: salt.to_vec(),
        }
    }
}

/// Serialize `salt` to its hex representation.
fn serialize_salt<S>(x: &Vec<u8>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&hex::encode(x))
}

/// Deserialize `salt` from its hex representation to bytes.
fn deserialize_salt<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct StringVisitor;
    impl<'de> de::Visitor<'de> for StringVisitor {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("String should be hex format")
        }
        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            hex::decode(v).map_err(E::custom)
        }
    }
    deserializer.deserialize_any(StringVisitor)
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Kdf {
    Scrypt(Scrypt),
    Pbkdf2(Pbkdf2),
}

impl Default for Kdf {
    fn default() -> Self {
        Kdf::Pbkdf2(Pbkdf2::default())
    }
}

impl Kdf {
    pub fn function(&self) -> KdfFunction {
        match &self {
            Kdf::Pbkdf2(_) => KdfFunction::Pbkdf2,
            Kdf::Scrypt(_) => KdfFunction::Scrypt,
        }
    }
}

/// Used for ensuring that serde only decodes valid KDF functions.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum KdfFunction {
    Scrypt,
    Pbkdf2,
}

impl Into<String> for KdfFunction {
    fn into(self) -> String {
        match self {
            KdfFunction::Scrypt => "scrypt".into(),
            KdfFunction::Pbkdf2 => "pbkdf2".into(),
        }
    }
}

impl TryFrom<String> for KdfFunction {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_ref() {
            "scrypt" => Ok(KdfFunction::Scrypt),
            "pbkdf2" => Ok(KdfFunction::Pbkdf2),
            other => Err(format!("Unsupported kdf function: {}", other)),
        }
    }
}

/// KDF module representation.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct KdfModule {
    pub function: KdfFunction,
    pub params: Kdf,
    pub message: String,
}

/// PRF for use in `pbkdf2`.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum Prf {
    #[serde(rename = "hmac-sha256")]
    HmacSha256,
}

impl Prf {
    pub fn mac(&self, password: &[u8]) -> impl Mac {
        match &self {
            _hmac_sha256 => Hmac::new(Sha256::new(), password),
        }
    }
}

impl Default for Prf {
    fn default() -> Self {
        Prf::HmacSha256
    }
}
