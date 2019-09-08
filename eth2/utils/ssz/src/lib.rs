//! Provides encoding (serialization) and decoding (deserialization) in the SimpleSerialize (SSZ)
//! format designed for use in Ethereum 2.0.
//!
//! Adheres to the Ethereum 2.0 [SSZ
//! specification](https://github.com/ethereum/eth2.0-specs/blob/v0.8.1/specs/simple-serialize.md)
//! at v0.8.1 .
//!
//! ## Example
//!
//! ```rust
//! use ssz_derive::{Encode, Decode};
//! use ssz::{Decode, Encode};
//!
//! #[derive(PartialEq, Debug, Encode, Decode)]
//! struct Foo {
//!     a: u64,
//!     b: Vec<u16>,
//! }
//!
//! fn main() {
//!     let foo = Foo {
//!         a: 42,
//!         b: vec![1, 3, 3, 7]
//!     };
//!
//!     let ssz_bytes: Vec<u8> = foo.as_ssz_bytes();
//!
//!     let decoded_foo = Foo::from_ssz_bytes(&ssz_bytes).unwrap();
//!
//!     assert_eq!(foo, decoded_foo);
//! }
//!
//! ```
//!
//! See `examples/` for manual implementations of the `Encode` and `Decode` traits.

mod decode;
mod encode;

pub use decode::{
    impls::decode_list_of_variable_length_items, Decode, DecodeError, SszDecoder, SszDecoderBuilder,
};
pub use encode::{Encode, SszEncoder};

/// The number of bytes used to represent an offset.
pub const BYTES_PER_LENGTH_OFFSET: usize = 4;
/// The maximum value that can be represented using `BYTES_PER_LENGTH_OFFSET`.
#[cfg(target_pointer_width = "32")]
pub const MAX_LENGTH_VALUE: usize = (std::u32::MAX >> (8 * (4 - BYTES_PER_LENGTH_OFFSET))) as usize;
#[cfg(target_pointer_width = "64")]
pub const MAX_LENGTH_VALUE: usize = (std::u64::MAX >> (8 * (8 - BYTES_PER_LENGTH_OFFSET))) as usize;

/// Convenience function to SSZ encode an object supporting ssz::Encode.
///
/// Equivalent to `val.as_ssz_bytes()`.
pub fn ssz_encode<T>(val: &T) -> Vec<u8>
where
    T: Encode,
{
    val.as_ssz_bytes()
}
