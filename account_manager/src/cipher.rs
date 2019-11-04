use crate::module::CryptoModule;
use crypto::aes::{ctr, KeySize};
const IV_SIZE: usize = 16;

pub struct CipherMessage<C: Cipher> {
    pub cipher: C,
    pub message: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Aes128Ctr {
    pub iv: Vec<u8>,
}

impl Cipher for Aes128Ctr {
    fn encrypt(&self, key: &[u8], pt: &[u8]) -> Vec<u8> {
        // TODO: sanity checks
        let mut ct = vec![0; pt.len()];
        ctr(KeySize::KeySize128, key, &self.iv).process(pt, &mut ct);
        ct
    }

    fn decrypt(&self, key: &[u8], ct: &[u8]) -> Vec<u8> {
        // TODO: sanity checks
        let mut pt = vec![0; ct.len()];
        ctr(KeySize::KeySize128, key, &self.iv).process(ct, &mut pt);
        pt
    }
}

pub trait Cipher {
    fn encrypt(&self, key: &[u8], pt: &[u8]) -> Vec<u8>;
    fn decrypt(&self, key: &[u8], ct: &[u8]) -> Vec<u8>;
}

impl<C: Cipher> CryptoModule for CipherMessage<C> {
    type Params = C;

    fn function(&self) -> String {
        "aes-128-ctr".to_string()
    }

    fn params(&self) -> &Self::Params {
        &self.cipher
    }

    fn message(&self) -> Vec<u8> {
        self.message.clone()
    }
}
