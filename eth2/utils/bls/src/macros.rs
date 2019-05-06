macro_rules! impl_ssz {
    ($type: ident, $byte_size: expr, $item_str: expr) => {
        impl ssz::Encodable for $type {
            fn is_ssz_fixed_len() -> bool {
                true
            }

            fn ssz_fixed_len() -> usize {
                $byte_size
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                buf.append(&mut self.as_bytes())
            }
        }

        impl ssz::Decodable for $type {
            fn is_ssz_fixed_len() -> bool {
                true
            }

            fn ssz_fixed_len() -> usize {
                $byte_size
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
                let len = bytes.len();
                let expected = <Self as ssz::Decodable>::ssz_fixed_len();

                if len != expected {
                    Err(ssz::DecodeError::InvalidByteLength { len, expected })
                } else {
                    $type::from_bytes(bytes)
                }
            }
        }
    };
}
