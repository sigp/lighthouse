use crypto::sha2::Sha256;
use crypto::{hmac::Hmac, mac::Mac, pbkdf2, scrypt};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Pbkdf2 {
    pub c: u32,
    pub dklen: u32,
    pub prf: Prf,
    pub salt: Vec<u8>,
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
        let params = scrypt::ScryptParams::new(log_2(self.n) as u8, self.r, self.p);
        scrypt::scrypt(password.as_bytes(), &self.salt, &params, &mut dk);
        dk.to_vec()
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Kdf {
    Scrypt(Scrypt),
    Pbkdf2(Pbkdf2),
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
