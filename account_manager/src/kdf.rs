use crypto::sha2::Sha256;
use crypto::{hmac::Hmac, mac::Mac, pbkdf2, scrypt};

#[derive(Debug, PartialEq, Clone)]
pub enum Prf {
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

#[derive(Debug, PartialEq, Clone)]
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

#[derive(Debug, PartialEq, Clone)]
pub struct Scrypt {
    pub dklen: u32,
    pub n: u32,
    pub r: u32,
    pub p: u32,
    pub salt: Vec<u8>,
}

impl Kdf for Scrypt {
    fn derive_key(&self, password: &str) -> Vec<u8> {
        unimplemented!()
    }
}

pub trait Kdf {
    /// Derive the key from the password
    fn derive_key(&self, password: &str) -> Vec<u8>;
}
