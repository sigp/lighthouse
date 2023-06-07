use super::*;
use crate::Blob;
use kzg::{BYTES_PER_BLOB, BYTES_PER_FIELD_ELEMENT, FIELD_ELEMENTS_PER_BLOB};
use safe_arith::SafeArith;

impl TestRandom for Blob {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let mut bytes = [0u8; BYTES_PER_BLOB];
        rng.fill_bytes(&mut bytes);
        // Ensure that the blob is canonical by ensuring that
        // each field element contained in the blob is < BLS_MODULUS
        for i in 0..FIELD_ELEMENTS_PER_BLOB {
            let offset = i
                .safe_mul(BYTES_PER_FIELD_ELEMENT)
                .and_then(|o| o.safe_add(BYTES_PER_FIELD_ELEMENT))
                .and_then(|o| o.safe_sub(1))
                .expect("unsafe math while generating random blob");
            if let Some(byte) = bytes.get_mut(offset) {
                *byte = 0;
            }
        }
        Self::from(bytes)
    }
}
