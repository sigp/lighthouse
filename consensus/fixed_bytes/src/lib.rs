use alloy_primitives::FixedBytes;
use safe_arith::SafeArith;

pub type Hash64 = alloy_primitives::B64;
pub type Hash256 = alloy_primitives::B256;
pub type Uint256 = alloy_primitives::U256;
pub type Address = alloy_primitives::Address;

pub trait UintExtended {
    fn to_i64(self) -> i64;
}

pub trait FixedBytesExtended {
    fn from_low_u64_be(value: u64) -> Self;
    fn from_low_u64_le(value: u64) -> Self;
    fn to_low_u64_le(&self) -> u64;
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
            .expect("bytes_to_copy <= buffer.len()");
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
        // Panic-free because bytes_to_copy <= buffer.len(),
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

    /// Trims FixedBytes<N> to its first 8 bytes and converts to u64
    fn to_low_u64_le(&self) -> u64 {
        let mut result = [0u8; 8];
        let bytes = self.as_slice();
        // Panic-free because result.len() == bytes[0..8].len()
        result.copy_from_slice(&bytes[0..8]);
        u64::from_le_bytes(result)
    }
}

impl FixedBytesExtended for alloy_primitives::Address {
    fn from_low_u64_be(value: u64) -> Self {
        FixedBytes::<20>::from_low_u64_be(value).into()
    }

    fn from_low_u64_le(value: u64) -> Self {
        FixedBytes::<20>::from_low_u64_le(value).into()
    }

    fn zero() -> Self {
        FixedBytes::<20>::zero().into()
    }

    fn to_low_u64_le(&self) -> u64 {
        FixedBytes::<20>::to_low_u64_le(self)
    }
}

impl UintExtended for Uint256 {
    /// Trims the Uint256 to its first 8 bytes and converts to i64
    fn to_i64(self) -> i64 {
        let mut result = [0u8; 8];
        let bytes = self.to_le_bytes::<32>();
        // Panic-free because result.len() == bytes[0..8].len()
        result.copy_from_slice(&bytes[0..8]);
        i64::from_le_bytes(result)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloy_primitives::bytes::Buf;

    #[test]
    fn from_low_u64_be() {
        let values = [0, 1, 0xff, 1 << 16, u64::MAX, u64::MAX - 1];
        for value in values {
            assert_eq!(
                (&Hash256::from_low_u64_be(value).as_slice()[24..]).get_u64(),
                value
            );
        }
    }

    #[test]
    fn from_low_u64_le() {
        let values = [0, 1, 0xff, 1 << 16, u64::MAX, u64::MAX - 1];
        for value in values {
            assert_eq!(
                u64::from_le_bytes(
                    Hash256::from_low_u64_le(value).as_slice()[0..8]
                        .try_into()
                        .unwrap()
                ),
                value
            );
        }
    }

    #[test]
    fn to_low_u64_le() {
        let values = [0, 1, 0xff, 1 << 16, u64::MAX, u64::MAX - 1];
        for value in values {
            assert_eq!(Hash256::from_low_u64_le(value).to_low_u64_le(), value);
        }
    }

    #[test]
    fn to_i64_in_range() {
        let values = [0, 1, 0xff, 1 << 16, i64::MAX, i64::MAX - 1];
        for value in values {
            assert_eq!(Uint256::from(value).to_i64(), value);
        }
    }

    #[test]
    fn to_i64_out_of_range() {
        let values = [u128::MAX, 1 << 70, 1 << 80, i64::MAX as u128 + 1];
        for value in values {
            assert_eq!(
                Uint256::from(value).to_i64(),
                i64::from_le_bytes(value.to_le_bytes()[0..8].try_into().unwrap())
            );
        }
    }
}
