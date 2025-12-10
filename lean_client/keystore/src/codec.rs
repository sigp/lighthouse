/// Re-export leanSig's serialization traits for backwards compatibility
pub use leansig::serialization::Serializable;

/// Encode a value using leanSig's canonical serialization.
pub fn encode_to_vec<T>(value: &T) -> Vec<u8>
where
    T: Serializable,
{
    value.to_bytes()
}

/// Decode a value using leanSig's canonical serialization.
pub fn decode_from_slice<T>(bytes: &[u8]) -> Result<T, ssz::DecodeError>
where
    T: Serializable,
{
    T::from_bytes(bytes)
}
