mod decode;
mod encode;
mod macros;

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
