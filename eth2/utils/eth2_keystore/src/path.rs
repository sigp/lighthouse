use crate::plain_text::PlainText;
use crypto::{digest::Digest, sha2::Sha256};

/// The byte size of a SHA256 hash.
const HASH_SIZE: usize = 32;
/// The digest size (in octets) of the hash function (SHA256)
const K: usize = HASH_SIZE;
/// The size of the lamport array.
const LAMPORT_ARRAY_SIZE: usize = 255;
/// The HKDF output size (in octets)
const L: usize = K * LAMPORT_ARRAY_SIZE;

fn ikm_to_lamport_sk(salt: &[u8], ikm: &[u8]) -> Vec<[u8; HASH_SIZE]> {
    hkdf_expand(hkdf_extract(salt, ikm).as_bytes())
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> PlainText {
    let mut hasher = Sha256::new();
    hasher.input(salt);
    hasher.input(ikm);

    let mut digest = vec![0; HASH_SIZE];
    hasher.result(&mut digest);

    digest.into()
}

fn hkdf_expand(prk: &[u8]) -> Vec<[u8; HASH_SIZE]> {
    let mut okm: Vec<[u8; HASH_SIZE]> = Vec::with_capacity(LAMPORT_ARRAY_SIZE);

    debug_assert!(LAMPORT_ARRAY_SIZE <= u8::max_value() as usize);

    for i in 0..LAMPORT_ARRAY_SIZE {
        let mut hasher = Sha256::new();

        hasher.input(prk);

        if let Some(prev) = okm.last() {
            hasher.input(&prev[..]);
        }

        hasher.input(&[i as u8]);

        let mut digest = [0; HASH_SIZE];
        hasher.result(&mut digest);
        okm.push(digest);
    }

    okm
}
