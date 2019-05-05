use super::*;
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

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                buf.extend_from_slice(&self.to_le_bytes());
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

    fn ssz_append(&self, buf: &mut Vec<u8>) {

        if T::is_ssz_fixed_len() {
            buf.reserve(T::ssz_fixed_len() * self.len());

            for item in self {
                item.ssz_append(buf);
            }
        } else {
            /*
            for item in self {
                let mut substream = SszStream::new();

                item.ssz_append(&mut substream);

                s.append_variable_bytes(&substream.drain());
            }
            */
            let mut offset = self.len() * BYTES_PER_LENGTH_OFFSET;
            let mut fixed = Vec::with_capacity(offset);
            let mut variable = vec![];

            for item in self {
                fixed.append(&mut encode_length(offset));
                let mut bytes = item.as_ssz_bytes();
                offset += bytes.len();
                variable.append(&mut bytes);
            }

            buf.append(&mut fixed);
            buf.append(&mut variable);
        }
    }
}

/*
impl Encodable for bool {
    fn ssz_fixed_len() -> Option<usize> {
        Some(8)
    }

    fn ssz_append(&self, s: &mut SszStream) {
        s.append_fixed_bytes(&(self as u8).to_le_bytes());
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
*/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vec_of_u8() {
        let vec: Vec<u8> = vec![];
        assert_eq!(vec.as_ssz_bytes(), vec![]);

        let vec: Vec<u8> = vec![1];
        assert_eq!(vec.as_ssz_bytes(), vec![1]);

        let vec: Vec<u8> = vec![0, 1, 2, 3];
        assert_eq!(vec.as_ssz_bytes(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn vec_of_vec_of_u8() {
        let vec: Vec<Vec<u8>> = vec![];
        assert_eq!(vec.as_ssz_bytes(), vec![]);

        let vec: Vec<Vec<u8>> = vec![vec![]];
        assert_eq!(vec.as_ssz_bytes(), vec![4, 0, 0, 0]);

        let vec: Vec<Vec<u8>> = vec![vec![], vec![]];
        assert_eq!(vec.as_ssz_bytes(), vec![8, 0, 0, 0, 8, 0, 0, 0]);

        let vec: Vec<Vec<u8>> = vec![vec![0, 1, 2], vec![11, 22, 33]];
        assert_eq!(
            vec.as_ssz_bytes(),
            vec![8, 0, 0, 0, 11, 0, 0, 0, 0, 1, 2, 11, 22, 33]
        );
    }

    #[test]
    fn ssz_encode_u8() {
        assert_eq!(0_u8.as_ssz_bytes(), vec![0]);
        assert_eq!(1_u8.as_ssz_bytes(), vec![1]);
        assert_eq!(100_u8.as_ssz_bytes(), vec![100]);
        assert_eq!(255_u8.as_ssz_bytes(), vec![255]);
    }

    #[test]
    fn ssz_encode_u16() {
        assert_eq!(1_u16.as_ssz_bytes(), vec![1, 0]);
        assert_eq!(100_u16.as_ssz_bytes(), vec![100, 0]);
        assert_eq!((1_u16 << 8).as_ssz_bytes(), vec![0, 1]);
        assert_eq!(65535_u16.as_ssz_bytes(), vec![255, 255]);
    }

    #[test]
    fn ssz_encode_u32() {
        assert_eq!(1_u32.as_ssz_bytes(), vec![1, 0, 0, 0]);
        assert_eq!(100_u32.as_ssz_bytes(), vec![100, 0, 0, 0]);
        assert_eq!((1_u32 << 16).as_ssz_bytes(), vec![0, 0, 1, 0]);
        assert_eq!((1_u32 << 24).as_ssz_bytes(), vec![0, 0, 0, 1]);
        assert_eq!((!0_u32).as_ssz_bytes(), vec![255, 255, 255, 255]);
    }

    #[test]
    fn ssz_encode_u64() {
        assert_eq!(1_u64.as_ssz_bytes(), vec![1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            (!0_u64).as_ssz_bytes(),
            vec![255, 255, 255, 255, 255, 255, 255, 255]
        );
    }

    #[test]
    fn ssz_encode_usize() {
        assert_eq!(1_usize.as_ssz_bytes(), vec![1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            (!0_usize).as_ssz_bytes(),
            vec![255, 255, 255, 255, 255, 255, 255, 255]
        );
    }

    /*
    #[test]
    fn ssz_encode_h256() {
        let h = H256::zero();
        let mut ssz = SszStream::new();
        ssz.append(&h);
        assert_eq!(ssz.drain(), vec![0; 32]);
    }

    #[test]
    fn ssz_mixed() {
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
    fn ssz_encode_bool() {
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
    fn ssz_encode_u8_array() {
        let x: [u8; 4] = [0, 1, 7, 8];
        let ssz = ssz_encode(&x);
        assert_eq!(ssz, vec![0, 1, 7, 8]);

        let x: [u8; 4] = [255, 255, 255, 255];
        let ssz = ssz_encode(&x);
        assert_eq!(ssz, vec![255, 255, 255, 255]);
    }
    */
}
