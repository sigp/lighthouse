/// Implements `Encode` for `$impl_type` using an implementation of `From<$impl_type> for
/// $from_type`.
///
/// In effect, this allows for easy implementation of `Encode` for some type that implements a
/// `From` conversion into another type that already has `Encode` implemented.
#[macro_export]
macro_rules! impl_encode_via_from {
    ($impl_type: ty, $from_type: ty) => {
        impl ssz::Encode for $impl_type {
            fn is_ssz_fixed_len() -> bool {
                <$from_type as ssz::Encode>::is_ssz_fixed_len()
            }

            fn ssz_fixed_len() -> usize {
                <$from_type as ssz::Encode>::ssz_fixed_len()
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                let conv: $from_type = self.clone().into();

                conv.ssz_append(buf)
            }
        }
    };
}

/// Implements `Decode` for `$impl_type` using an implementation of `From<$impl_type> for
/// $from_type`.
///
/// In effect, this allows for easy implementation of `Decode` for some type that implements a
/// `From` conversion into another type that already has `Decode` implemented.
#[macro_export]
macro_rules! impl_decode_via_from {
    ($impl_type: ty, $from_type: tt) => {
        impl ssz::Decode for $impl_type {
            fn is_ssz_fixed_len() -> bool {
                <$from_type as ssz::Decode>::is_ssz_fixed_len()
            }

            fn ssz_fixed_len() -> usize {
                <$from_type as ssz::Decode>::ssz_fixed_len()
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
                $from_type::from_ssz_bytes(bytes).and_then(|dec| Ok(dec.into()))
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use crate as ssz;
    use ssz::{Decode, Encode};

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
