extern crate bytes;

use self::bytes::{BufMut, BytesMut};
use super::ethereum_types::{Address, H256};
use super::{Encodable, SszStream};

/*
 * Note: there is a "to_bytes" function for integers
 * in Rust nightly. When it is in stable, we should
 * use it instead.
 */
macro_rules! impl_encodable_for_uint {
    ($type: ident, $bit_size: expr) => {
        impl Encodable for $type {
            #[allow(clippy::cast_lossless)]
            fn ssz_append(&self, s: &mut SszStream) {
                // Ensure bit size is valid
                assert!(
                    (0 < $bit_size)
                        && ($bit_size % 8 == 0)
                        && (2_u128.pow($bit_size) > *self as u128)
                );

                // Serialize to bytes
                let mut buf = BytesMut::with_capacity($bit_size / 8);

                // Match bit size with encoding
                match $bit_size {
                    8 => buf.put_u8(*self as u8),
                    16 => buf.put_u16_le(*self as u16),
                    32 => buf.put_u32_le(*self as u32),
                    64 => buf.put_u64_le(*self as u64),
                    _ => {}
                }

                // Append bytes to the SszStream
                s.append_encoded_raw(&buf.to_vec());
            }
        }
    };
}

impl_encodable_for_uint!(u8, 8);
impl_encodable_for_uint!(u16, 16);
impl_encodable_for_uint!(u32, 32);
impl_encodable_for_uint!(u64, 64);
impl_encodable_for_uint!(usize, 64);

impl Encodable for H256 {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_encoded_raw(&self.to_vec());
    }
}

impl Encodable for Address {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_encoded_raw(&self.to_vec());
    }
}

impl<T> Encodable for Vec<T>
where
    T: Encodable,
{
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(&self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssz_encode_h256() {
        let h = H256::zero();
        let mut ssz = SszStream::new();
        ssz.append(&h);
        assert_eq!(ssz.drain(), vec![0; 32]);
    }

    #[test]
    fn test_ssz_encode_address() {
        let h = Address::zero();
        let mut ssz = SszStream::new();
        ssz.append(&h);
        assert_eq!(ssz.drain(), vec![0; 20]);
    }

    #[test]
    fn test_ssz_encode_u8() {
        let x: u8 = 0;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0]);

        let x: u8 = 1;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![1]);

        let x: u8 = 100;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![100]);

        let x: u8 = 255;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![255]);
    }

    #[test]
    fn test_ssz_encode_u16() {
        let x: u16 = 1;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![1, 0]);

        let x: u16 = 100;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![100, 0]);

        let x: u16 = 1 << 8;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 1]);

        let x: u16 = 65535;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![255, 255]);
    }

    #[test]
    fn test_ssz_encode_u32() {
        let x: u32 = 1;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![1, 0, 0, 0]);

        let x: u32 = 100;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![100, 0, 0, 0]);

        let x: u32 = 1 << 16;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 1, 0]);

        let x: u32 = 1 << 24;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 0, 1]);

        let x: u32 = !0;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![255, 255, 255, 255]);
    }

    #[test]
    fn test_ssz_encode_u64() {
        let x: u64 = 1;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![1, 0, 0, 0, 0, 0, 0, 0]);

        let x: u64 = 100;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![100, 0, 0, 0, 0, 0, 0, 0]);

        let x: u64 = 1 << 32;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 0, 0, 1, 0, 0, 0]);

        let x: u64 = !0;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![255, 255, 255, 255, 255, 255, 255, 255]);
    }

    #[test]
    fn test_ssz_encode_usize() {
        let x: usize = 1;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![1, 0, 0, 0, 0, 0, 0, 0]);

        let x: usize = 100;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![100, 0, 0, 0, 0, 0, 0, 0]);

        let x: usize = 1 << 32;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 0, 0, 1, 0, 0, 0]);

        let x: usize = !0;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![255, 255, 255, 255, 255, 255, 255, 255]);
    }

    #[test]
    fn test_ssz_mixed() {
        let mut stream = SszStream::new();

        let h = Address::zero();
        let a: u8 = 100;
        let b: u16 = 65535;
        let c: u32 = 1 << 24;

        stream.append(&h);
        stream.append(&a);
        stream.append(&b);
        stream.append(&c);

        let ssz = stream.drain();        
        assert_eq!(ssz[0..20], *vec![0; 20]);
        assert_eq!(ssz[20], 100);
        assert_eq!(ssz[21..23], *vec![255, 255]);
        assert_eq!(ssz[23..27], *vec![0, 0, 0, 1]);
    }
}
