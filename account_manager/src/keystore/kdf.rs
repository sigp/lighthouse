use crypto::sha2::Sha256;
use crypto::{hmac::Hmac, mac::Mac, pbkdf2, scrypt};
use rand::prelude::*;
use serde::{de, Deserialize, Serialize, Serializer};
use std::default::Default;

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
    // TODO: verify size of salt
    fn default() -> Self {
        let salt = rand::thread_rng().gen::<[u8; 32]>();
        Pbkdf2 {
            dklen: 32,
            c: 262144,
            prf: Prf::HmacSha256,
            salt: salt.to_vec(),
        }
    }
}

impl Pbkdf2 {
    pub fn derive_key(&self, password: &str) -> Vec<u8> {
        let mut dk = [0u8; 32];
        let mut mac = self.prf.mac(password.as_bytes());
        pbkdf2::pbkdf2(&mut mac, &self.salt, self.c, &mut dk);
        dk.to_vec()
    }
}

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
const fn num_bits<T>() -> usize {
    std::mem::size_of::<T>() * 8
}

fn log_2(x: u32) -> u32 {
    assert!(x > 0);
    num_bits::<u32>() as u32 - x.leading_zeros() - 1
}

impl Scrypt {
    pub fn derive_key(&self, password: &str) -> Vec<u8> {
        let mut dk = [0u8; 32];
        // TODO: verify `N` is power of 2
        let params = scrypt::ScryptParams::new(log_2(self.n) as u8, self.r, self.p);
        scrypt::scrypt(password.as_bytes(), &self.salt, &params, &mut dk);
        dk.to_vec()
    }
}

impl Default for Scrypt {
    // TODO: verify size of salt
    fn default() -> Self {
        let salt = rand::thread_rng().gen::<[u8; 32]>();
        Scrypt {
            dklen: 32,
            n: 262144,
            r: 8,
            p: 1,
            salt: salt.to_vec(),
        }
    }
}

fn serialize_salt<S>(x: &Vec<u8>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&hex::encode(x))
}

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
    pub fn function(&self) -> String {
        match &self {
            Kdf::Pbkdf2(_) => "pbkdf2".to_string(),
            Kdf::Scrypt(_) => "scrypt".to_string(),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct KdfModule {
    pub function: String,
    pub params: Kdf,
    pub message: String,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum Prf {
    #[serde(rename = "hmac-sha256")]
    HmacSha256,
}

impl Prf {
    // TODO: is password what should be passed here?
    pub fn mac(&self, password: &[u8]) -> impl Mac {
        match &self {
            _hmac_sha256 => Hmac::new(Sha256::new(), password),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde() {
        let json = r#"{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"}"#;
        let data: Pbkdf2 = serde_json::from_str(&json).unwrap();
        println!("{:?}", data);
    }
}
