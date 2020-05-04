use crypto::aes::{ctr, KeySize};
use rand::prelude::*;
use serde::{de, Deserialize, Serialize, Serializer};
use std::default::Default;
use zeroize::Zeroize;

const IV_SIZE: usize = 16;

/// Provides wrapper around `Vec<u8>` that implements zeroize.
#[derive(Zeroize, Clone, PartialEq)]
#[zeroize(drop)]
pub struct PlainText(Vec<u8>);

impl PlainText {
    /// Instantiate self with `len` zeros.
    pub fn zero(len: usize) -> Self {
        Self(vec![0; len])
    }

    /// The byte-length of `self`
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns a reference to the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns a mutable reference to the underlying bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// Convert slice to fixed length array.
/// Returns `None` if slice has len > `IV_SIZE`
fn from_slice(bytes: &[u8]) -> Option<[u8; IV_SIZE]> {
    if bytes.len() != 16 {
        return None;
    }
    let mut array = [0; IV_SIZE];
    let bytes = &bytes[..array.len()];
    array.copy_from_slice(bytes);
    Some(array)
}

/// Cipher module representation.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct CipherModule {
    pub function: String,
    pub params: Cipher,
    pub message: String,
}

/// Parameters for AES128 with ctr mode.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Aes128Ctr {
    #[serde(serialize_with = "serialize_iv")]
    #[serde(deserialize_with = "deserialize_iv")]
    pub iv: [u8; 16],
}

impl Aes128Ctr {
    pub fn encrypt(&self, key: &[u8], pt: &[u8]) -> Vec<u8> {
        // TODO: sanity checks
        let mut ct = vec![0; pt.len()];
        ctr(KeySize::KeySize128, key, &self.iv).process(pt, &mut ct);
        ct
    }

    pub fn decrypt(&self, key: &[u8], ct: &[u8]) -> PlainText {
        // TODO: sanity checks
        let mut pt = PlainText::zero(ct.len());
        ctr(KeySize::KeySize128, key, &self.iv).process(ct, &mut pt.as_mut_bytes());
        pt
    }
}

/// Serialize `iv` to its hex representation.
fn serialize_iv<S>(x: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&hex::encode(x))
}

/// Deserialize `iv` from its hex representation to bytes.
fn deserialize_iv<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
where
    D: de::Deserializer<'de>,
{
    struct StringVisitor;
    impl<'de> de::Visitor<'de> for StringVisitor {
        type Value = [u8; IV_SIZE];
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("String should be hex format and 16 bytes in length")
        }
        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let bytes = hex::decode(v).map_err(E::custom)?;
            from_slice(&bytes).ok_or_else(|| E::custom(format!("IV should have length 16 bytes")))
        }
    }
    deserializer.deserialize_any(StringVisitor)
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Cipher {
    Aes128Ctr(Aes128Ctr),
}

impl Default for Cipher {
    fn default() -> Self {
        let iv = rand::thread_rng().gen::<[u8; IV_SIZE]>();
        Cipher::Aes128Ctr(Aes128Ctr { iv })
    }
}

impl Cipher {
    pub fn function(&self) -> String {
        match &self {
            Cipher::Aes128Ctr(_) => "aes-128-ctr".to_string(),
        }
    }
}
