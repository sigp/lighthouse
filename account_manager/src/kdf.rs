use crate::module::CryptoModule;
use crypto::sha2::Sha256;
use crypto::{hmac::Hmac, mac::Mac, pbkdf2, scrypt};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Pbkdf2 {
    pub c: u32,
    pub dklen: u32,
    pub prf: Prf,
    pub salt: Vec<u8>,
}

impl Kdf for Pbkdf2 {
    fn derive_key(&self, password: &str) -> Vec<u8> {
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
    pub salt: Vec<u8>,
}
const fn num_bits<T>() -> usize {
    std::mem::size_of::<T>() * 8
}

fn log_2(x: u32) -> u32 {
    assert!(x > 0);
    num_bits::<u32>() as u32 - x.leading_zeros() - 1
}

impl Kdf for Scrypt {
    fn derive_key(&self, password: &str) -> Vec<u8> {
        let mut dk = [0u8; 32];
        let params = scrypt::ScryptParams::new(log_2(self.p) as u8, self.r, self.p);
        scrypt::scrypt(password.as_bytes(), &self.salt, &params, &mut dk);
        dk.to_vec()
    }
}

pub trait Kdf: Serialize + DeserializeOwned {
    /// Derive the key from the password
    fn derive_key(&self, password: &str) -> Vec<u8>;
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct KdfModule<K: Kdf> {
    function: String,
    params: Kdf,
    message: String,
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

impl CryptoModule for Scrypt {
    type Params = Scrypt;

    fn function(&self) -> String {
        "scrypt".to_string()
    }

    fn params(&self) -> &Self::Params {
        &self
    }

    fn message(&self) -> Vec<u8> {
        Vec::new()
    }
}

impl CryptoModule for Pbkdf2 {
    type Params = Pbkdf2;

    fn function(&self) -> String {
        "pbkdf2".to_string()
    }

    fn params(&self) -> &Self::Params {
        &self
    }

    fn message(&self) -> Vec<u8> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log() {
        let scrypt = Scrypt {
            dklen: 32,
            n: 262144,
            r: 8,
            p: 1,
            salt: vec![0; 32],
        };

        let p = Pbkdf2 {
            dklen: 32,
            c: 262144,
            prf: Prf::HmacSha256,
            salt: vec![0; 32],
        };
        let serialized = serde_json::to_string(&p).unwrap();
        println!("{}", serialized);
    }
}
