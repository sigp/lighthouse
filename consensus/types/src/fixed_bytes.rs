use byteorder::ByteOrder;


// TODO(alloy) review panic issues
pub trait FixedBytesExtended {
    /// The given u64 value is interpreted as big endian.
    /// Ignores the most significant bits of the given value if the hash type has less than 8 bytes.
    fn from_low_u64_be(value: u64) -> Self;
    fn from_low_u64_le(value: u64) -> Self;
    fn zero() -> Self;
}

impl FixedBytesExtended for alloy_primitives::B256 {

    fn from_low_u64_be(value: u64) -> Self {
        let mut buf = [0x0; 8];
        byteorder::BigEndian::write_u64(&mut buf, value);
        let capped = std::cmp::min(Self::len_bytes(), 8);
        let mut bytes = [0x0; std::mem::size_of::<Self>()];
        bytes[(Self::len_bytes() - capped)..].copy_from_slice(&buf[..capped]);
		Self::from_slice(&bytes)
    }

    fn from_low_u64_le(value: u64) -> Self {
        let mut buf = [0x0; 8];
        byteorder::LittleEndian::write_u64(&mut buf, value);
        let capped = std::cmp::min(Self::len_bytes(), 8);
        let mut bytes = [0x0; std::mem::size_of::<Self>()];
        bytes[(Self::len_bytes() - capped)..].copy_from_slice(&buf[..capped]);
		Self::from_slice(&bytes)
    }

    fn zero() -> Self {
        alloy_primitives::B256::ZERO
    }
}


// https://github.com/paritytech/parity-common/blob/d5e9c1d5b52e7a43f843855a0f4fbc319929a681/fixed-hash/src/hash.rs#L401-L411
impl FixedBytesExtended for alloy_primitives::Address {
    fn from_low_u64_be(value: u64) -> Self {
        let mut buf = [0x0; 8];
        byteorder::BigEndian::write_u64(&mut buf, value);
        let capped = std::cmp::min(Self::len_bytes(), 8);
        let mut bytes = [0x0; std::mem::size_of::<Self>()];
        bytes[(Self::len_bytes() - capped)..].copy_from_slice(&buf[..capped]);
		Self::from_slice(&bytes)
    }

    fn from_low_u64_le(value: u64) -> Self {
        let mut buf = [0x0; 8];
        byteorder::LittleEndian::write_u64(&mut buf, value);
        let capped = std::cmp::min(Self::len_bytes(), 8);
        let mut bytes = [0x0; std::mem::size_of::<Self>()];
        bytes[(Self::len_bytes() - capped)..].copy_from_slice(&buf[..capped]);
		Self::from_slice(&bytes)
    }

    fn zero() -> Self {
        alloy_primitives::Address::ZERO
    }
}