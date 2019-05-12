mod decode;
mod encode;

pub use decode::{
    impls::decode_list_of_variable_length_items, Decodable, DecodeError, SszDecoderBuilder,
};
pub use encode::{Encodable, SszEncoder};

pub const BYTES_PER_LENGTH_OFFSET: usize = 4;
pub const MAX_LENGTH_VALUE: usize = (1 << (BYTES_PER_LENGTH_OFFSET * 8)) - 1;

/// Convenience function to SSZ encode an object supporting ssz::Encode.
///
/// Equivalent to `val.as_ssz_bytes()`.
pub fn ssz_encode<T>(val: &T) -> Vec<u8>
where
    T: Encodable,
{
    val.as_ssz_bytes()
}

#[macro_export]
macro_rules! impl_encode_via_from {
    ($impl_type: ty, $from_type: ty) => {
        impl Encodable for $impl_type {
            fn is_ssz_fixed_len() -> bool {
                <$from_type as Encodable>::is_ssz_fixed_len()
            }

            fn ssz_fixed_len() -> usize {
                <$from_type as Encodable>::ssz_fixed_len()
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                let conv: $from_type = self.clone().into();

                conv.ssz_append(buf)
            }
        }
    };
}

#[macro_export]
macro_rules! impl_decode_via_from {
    ($impl_type: ty, $from_type: tt) => {
        impl Decodable for $impl_type {
            fn is_ssz_fixed_len() -> bool {
                <$from_type as Decodable>::is_ssz_fixed_len()
            }

            fn ssz_fixed_len() -> usize {
                <$from_type as Decodable>::ssz_fixed_len()
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
                $from_type::from_ssz_bytes(bytes).and_then(|dec| Ok(dec.into()))
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate as ssz;

    #[derive(PartialEq, Debug, Clone, Copy)]
    struct Wrapper(u64);

    impl From<u64> for Wrapper {
        fn from(x: u64) -> Wrapper {
            Wrapper(x)
        }
    }

    impl From<Wrapper> for u64 {
        fn from(x: Wrapper) -> u64 {
            x.0
        }
    }

    impl_encode_via_from!(Wrapper, u64);
    impl_decode_via_from!(Wrapper, u64);

    #[test]
    fn impl_encode_via_from() {
        let check_encode = |a: u64, b: Wrapper| assert_eq!(a.as_ssz_bytes(), b.as_ssz_bytes());

        check_encode(0, Wrapper(0));
        check_encode(1, Wrapper(1));
        check_encode(42, Wrapper(42));
    }

    #[test]
    fn impl_decode_via_from() {
        let check_decode = |bytes: Vec<u8>| {
            let a = u64::from_ssz_bytes(&bytes).unwrap();
            let b = Wrapper::from_ssz_bytes(&bytes).unwrap();

            assert_eq!(a, b.into())
        };

        check_decode(vec![0, 0, 0, 0, 0, 0, 0, 0]);
        check_decode(vec![1, 0, 0, 0, 0, 0, 0, 0]);
        check_decode(vec![1, 0, 0, 0, 2, 0, 0, 0]);
    }
}
