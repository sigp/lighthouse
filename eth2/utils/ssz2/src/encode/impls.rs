use super::{Encodable, SszStream};
use ethereum_types::H256;

macro_rules! impl_encodable_for_uint {
    ($type: ident, $bit_size: expr) => {
        impl Encodable for $type {
            fn is_ssz_fixed_len() -> bool {
                true
            }

            fn ssz_fixed_len() -> usize {
                $bit_size / 8
            }

            fn as_ssz_bytes(&self) -> Vec<u8> {
                self.to_le_bytes().to_vec()
            }
        }
    };
}

impl_encodable_for_uint!(u8, 8);
impl_encodable_for_uint!(u16, 16);
impl_encodable_for_uint!(u32, 32);
impl_encodable_for_uint!(u64, 64);
impl_encodable_for_uint!(usize, 64);

impl<T: Encodable> Encodable for Vec<T> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn as_ssz_bytes(&self) -> Vec<u8> {
        let mut stream = SszStream::new();

        for item in self {
            stream.append(item)
        }

        stream.drain()
    }
}

/*
impl Encodable for bool {
    fn ssz_fixed_len() -> Option<usize> {
        Some(8)
    }

    fn as_ssz_bytes(&self) -> Vec<u8> {
        (*self as u8).to_le_bytes().to_vec()
    }
}

impl Encodable for H256 {
    fn ssz_fixed_len() -> Option<usize> {
        Some(32)
    }

    fn as_ssz_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

macro_rules! impl_encodable_for_u8_array {
    ($len: expr) => {
        impl Encodable for [u8; $len] {
            fn ssz_fixed_len() -> Option<usize> {
                Some($len)
            }

            fn as_ssz_bytes(&self) -> Vec<u8> {
                self.to_vec()
            }
        }
    };
}

impl_encodable_for_u8_array!(4);

macro_rules! impl_encodable_for_u8_array {
    ($len: expr) => {
        impl Encodable for [u8; $len] {

            fn ssz_append(&self, s: &mut SszStream) {
                let bytes: Vec<u8> = self.iter().cloned().collect();
                s.append_encoded_raw(&bytes);
            }
        }
    };
}

impl_encodable_for_u8_array!(4);

impl Encodable for bool {
    fn ssz_append(&self, s: &mut SszStream) {
        let byte = if *self { 0b0000_0001 } else { 0b0000_0000 };
        s.append_encoded_raw(&[byte]);
    }
}

impl Encodable for H256 {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_encoded_raw(self.as_bytes());
    }
}

impl Encodable for Address {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_encoded_raw(self.as_bytes());
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
*/

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssz_encode;

    #[test]
    fn test_vec_of_u8() {
        let vec: Vec<u8> = vec![];
        assert_eq!(vec.as_ssz_bytes(), vec![]);

        let vec: Vec<u8> = vec![1];
        assert_eq!(vec.as_ssz_bytes(), vec![1]);

        let vec: Vec<u8> = vec![0, 1, 2, 3];
        assert_eq!(vec.as_ssz_bytes(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_vec_of_vec_of_u8() {
        let vec: Vec<Vec<u8>> = vec![vec![]];
        assert_eq!(vec.as_ssz_bytes(), vec![0, 0, 0, 0]);

        let vec: Vec<Vec<u8>> = vec![vec![0, 1, 2], vec![11, 22, 33]];
        assert_eq!(
            vec.as_ssz_bytes(),
            vec![3, 0, 0, 0, 3, 0, 0, 0, 0, 1, 2, 11, 22, 33]
        );
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

    /*
    #[test]
    fn test_ssz_encode_h256() {
        let h = H256::zero();
        let mut ssz = SszStream::new();
        ssz.append(&h);
        assert_eq!(ssz.drain(), vec![0; 32]);
    }

    #[test]
    fn test_ssz_mixed() {
        let mut stream = SszStream::new();

        let h = H256::zero();
        let a: u8 = 100;
        let b: u16 = 65535;
        let c: u32 = 1 << 24;

        stream.append(&h);
        stream.append(&a);
        stream.append(&b);
        stream.append(&c);

        let ssz = stream.drain();
        assert_eq!(ssz[0..32], *vec![0; 32]);
        assert_eq!(ssz[32], 100);
        assert_eq!(ssz[33..55], *vec![255, 255]);
        assert_eq!(ssz[55..59], *vec![0, 0, 0, 1]);
    }

    #[test]
    fn test_ssz_encode_bool() {
        let x: bool = false;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0b0000_0000]);

        let x: bool = true;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0b0000_0001]);
    }

    #[test]
    fn test_ssz_encode_u8_array() {
        let x: [u8; 4] = [0, 1, 7, 8];
        let ssz = ssz_encode(&x);
        assert_eq!(ssz, vec![0, 1, 7, 8]);

        let x: [u8; 4] = [255, 255, 255, 255];
        let ssz = ssz_encode(&x);
        assert_eq!(ssz, vec![255, 255, 255, 255]);
    }
    */
}
