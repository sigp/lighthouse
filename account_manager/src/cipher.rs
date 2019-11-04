use crypto::aes::{ctr, KeySize};
use serde::{Deserialize, Serialize};

const IV_SIZE: usize = 16;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct CipherModule {
    pub function: String,
    pub params: Cipher,
    pub message: String,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Aes128Ctr {
    pub iv: Vec<u8>,
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

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Cipher {
    Aes128Ctr(Aes128Ctr),
}

impl Cipher {
    pub fn function(&self) -> String {
        match &self {
            Cipher::Aes128Ctr(_) => "aes-128-ctr".to_string(),
        }
    }
}
