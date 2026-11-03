use silver_hashing::{HashFormat, SszScalar};
use ssz::{Decode, DecodeError, Encode};
use typenum::Unsigned;

use super::ScalarList;

impl<T: SszScalar, N: Unsigned> Encode for ScalarList<T, N> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.write_ssz(buf).expect("Vec writes are infallible");
    }

    fn ssz_bytes_len(&self) -> usize {
        self.len().saturating_mul(size_of::<T>())
    }
}

impl<T: SszScalar, N: Unsigned> Decode for ScalarList<T, N> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::from_ssz_bytes_as(bytes, HashFormat::Fixed)
    }
}

impl<T: SszScalar, N: Unsigned> ScalarList<T, N> {
    pub(super) fn from_ssz_bytes_as(bytes: &[u8], format: HashFormat) -> Result<Self, DecodeError> {
        let chunks = bytes.chunks_exact(size_of::<T>());
        let tail = chunks.remainder().len();
        if tail != 0 {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: bytes.len().saturating_sub(tail),
            });
        }
        let mut values = vec![T::default(); chunks.len()];
        T::read_ssz_slice(&mut values, bytes);
        Self::new(values, format)
            .map_err(|_| DecodeError::BytesInvalid("list longer than SSZ limit".into()))
    }
}
