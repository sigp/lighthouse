use super::{
    Encodable,
    SszStream
};
use super::ethereum_types::{ H256, U256 };

/*
 * Note: there is a "to_bytes" function for integers
 * in Rust nightly. When it is in stable, we should
 * use it instead.
 */
macro_rules! impl_encodable_for_uint {
    ($type: ident) => {
        impl Encodable for $type {
            fn ssz_append(&self, s: &mut SszStream)
            {
                // Number of bits required to represent this integer.
                // This could be optimised at the expense of complexity.
                let num_bits = {
                    let mut n = *self;
                    let mut r: usize = 0;
                    while n > 0 {
                        n >>= 1;
                        r += 1;
                    }
                    if r == 0 { 1 } else { r }
                };
                // Number of bytes required to represent this bit
                let num_bytes = (num_bits + 8 - 1) / 8;
                let mut ssz_val: Vec<u8> = Vec::with_capacity(num_bytes);
                ssz_val.resize(num_bytes, 0);
                for i in (0..num_bytes).rev() {
                    let offset = (num_bytes - i - 1) * 8;
                    ssz_val[i] = 0_u8 | (self >> offset) as u8
                }
                s.append_encoded_val(&ssz_val);
            }
        }
    }
}

impl_encodable_for_uint!(u8);
impl_encodable_for_uint!(u16);
impl_encodable_for_uint!(u32);
impl_encodable_for_uint!(u64);

impl Encodable for H256 {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_encoded_val(&self.to_vec());
    }
}

impl Encodable for U256 {
    fn ssz_append(&self, s: &mut SszStream) {
        let mut a = [0; 32];
        self.to_big_endian(&mut a);
        s.append_encoded_val(&a.to_vec());
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssz_encode_u8() {
        let x: u16 = 0;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 1, 0]);

        let x: u16 = 1;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 1, 1]);

        let x: u16 = 100;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 1, 100]);

        let x: u16 = 255;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 1, 255]);
    }

    #[test]
    fn test_ssz_encode_u16() {
        let x: u16 = 1;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 1, 1]);

        let x: u16 = 100;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 1, 100]);

        let x: u16 = 1 << 8;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 2, 1, 0]);

        let x: u16 = 65535;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 2, 255, 255]);
    }

    #[test]
    fn test_ssz_encode_u32() {
        let x: u32 = 1;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 1, 1]);

        let x: u32 = 100;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 1, 100]);

        let x: u32 = 1 << 16;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 3, 1, 0, 0]);

        let x: u32 = 1 << 24;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 4, 1, 0, 0, 0]);

        let x: u32 = !0;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 4, 255, 255, 255, 255]);
    }

    #[test]
    fn test_ssz_encode_u64() {
        let x: u64 = 1;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 1, 1]);

        let x: u64 = 100;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 1, 100]);

        let x: u64 = 1 << 32;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 5, 1, 0, 0, 0, 0]);

        let x: u64 = !0;
        let mut ssz = SszStream::new();
        ssz.append(&x);
        assert_eq!(ssz.drain(), vec![0, 0, 8, 255, 255, 255, 255, 255, 255, 255, 255]);
    }
}
