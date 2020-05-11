use crate::derived_key::{HASH_SIZE, LAMPORT_ARRAY_SIZE};
use std::iter::Iterator;
use zeroize::Zeroize;

/// A Lamport secret key as specified in [EIP-2333](https://eips.ethereum.org/EIPS/eip-2333).
///
/// Implements `Zeroize` on `Drop`.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct LamportSecretKey(Vec<[u8; HASH_SIZE]>);

impl LamportSecretKey {
    /// Instantiates `Self` with all chunks set to zero.
    pub fn zero() -> Self {
        Self(vec![[0; HASH_SIZE]; LAMPORT_ARRAY_SIZE as usize])
    }

    /// Instantiates `Self` from a flat buffer of `HASH_SIZE * LAMPORT_ARRAY_SIZE` bytes.
    ///
    /// ## Panics
    ///
    /// If an incorrect number of bytes is supplied.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(
            bytes.len(),
            HASH_SIZE * LAMPORT_ARRAY_SIZE as usize,
            "incorrect byte length"
        );

        let mut this = Self::zero();

        for i in 0..LAMPORT_ARRAY_SIZE {
            let iu = i as usize;
            this.get_mut_chunk(i)
                .copy_from_slice(&bytes[iu * HASH_SIZE..(iu + 1) * HASH_SIZE])
        }

        this
    }

    /// Returns a reference to the `i`th `HASH_SIZE` chunk of `self`.
    pub fn get_mut_chunk(&mut self, i: u8) -> &mut [u8] {
        &mut self.0[i as usize]
    }

    /// Returns an iterator over `LAMPORT_ARRAY_SIZE` chunks of `HASH_SIZE` bytes.
    pub fn iter_chunks(&self) -> impl Iterator<Item = &[u8; HASH_SIZE]> {
        self.0.iter()
    }
}
