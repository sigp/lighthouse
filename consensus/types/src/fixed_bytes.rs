use alloy_primitives::{Address, FixedBytes};
use safe_arith::SafeArith;

pub trait FixedBytesExtended {
    fn from_low_u64_be(value: u64) -> Self;
    fn from_low_u64_le(value: u64) -> Self;
    fn zero() -> Self;
}

impl<const N: usize> FixedBytesExtended for FixedBytes<N> {
    fn from_low_u64_be(value: u64) -> Self {
        let value_bytes = value.to_be_bytes();
        let mut buffer = [0x0; N];
        let bytes_to_copy = value_bytes.len().min(buffer.len());
        // Panic-free because bytes_to_copy <= buffer.len()
        let start_index = buffer
            .len()
            .safe_sub(bytes_to_copy)
            .expect("byte_to_copy <= buffer.len()");
        // Panic-free because start_index <= buffer.len()
        // and bytes_to_copy <= value_bytes.len()
        buffer
            .get_mut(start_index..)
            .expect("start_index <= buffer.len()")
            .copy_from_slice(
                value_bytes
                    .get(..bytes_to_copy)
                    .expect("bytes_to_copy <= value_byte.len()"),
            );
        Self::from(buffer)
    }

    fn from_low_u64_le(value: u64) -> Self {
        let value_bytes = value.to_le_bytes();
        let mut buffer = [0x0; N];
        let bytes_to_copy = value_bytes.len().min(buffer.len());
        // Panic-free because bytes_to_copy <= buffer.len()
        // and bytes_to_copy <= value_bytes.len()
        buffer
            .get_mut(..bytes_to_copy)
            .expect("bytes_to_copy <= buffer.len()")
            .copy_from_slice(
                value_bytes
                    .get(..bytes_to_copy)
                    .expect("bytes_to_copy <= value_byte.len()"),
            );
        Self::from(buffer)
    }

    fn zero() -> Self {
        Self::ZERO
    }
}

impl FixedBytesExtended for Address {
    fn from_low_u64_be(value: u64) -> Self {
        FixedBytes::<20>::from_low_u64_be(value).into()
    }

    fn from_low_u64_le(value: u64) -> Self {
        FixedBytes::<20>::from_low_u64_le(value).into()
    }

    fn zero() -> Self {
        FixedBytes::<20>::zero().into()
    }
}
