use crypto::aes::{ctr, KeySize};
use rand::prelude::*;
use serde::{de, Deserialize, Serialize, Serializer};
use std::default::Default;

fn from_slice(bytes: &[u8]) -> [u8; 16] {
    let mut array = [0; 16];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

const IV_SIZE: usize = 16;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct CipherModule {
    pub function: String,
    pub params: Cipher,
    pub message: String,
}

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

    pub fn decrypt(&self, key: &[u8], ct: &[u8]) -> Vec<u8> {
        // TODO: sanity checks
        let mut pt = vec![0; ct.len()];
        ctr(KeySize::KeySize128, key, &self.iv).process(ct, &mut pt);
        pt
    }
}

fn serialize_iv<S>(x: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&hex::encode(x))
}

fn deserialize_iv<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
where
    D: de::Deserializer<'de>,
{
    struct StringVisitor;
    impl<'de> de::Visitor<'de> for StringVisitor {
        type Value = [u8; 16];
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("String should be hex format and 16 bytes in length")
        }
        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let bytes = hex::decode(v).map_err(E::custom)?;
            Ok(from_slice(&bytes))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde() {
        // let json = r#"{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"}"#;
        // let data: Pbkdf2 = serde_json::from_str(&json).unwrap();
        // println!("{:?}", data);
    }
}
