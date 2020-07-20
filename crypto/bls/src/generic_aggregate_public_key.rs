use crate::{Error, PUBLIC_KEY_BYTES_LEN};

/// Implemented on some struct from a BLS library so it may be used internally in this crate.
pub trait TAggregatePublicKey: Sized + Clone {
    /// Initialize `Self` to the infinity value which can then have other public keys aggregated
    /// upon it.
    fn infinity() -> Self;

    /// Serialize `self` as compressed bytes.
    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN];

    /// Deserialize `self` from compressed bytes.
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
}

/*
 * Note: there is no immediate need for a `GenericAggregatePublicKey` struct.
 */
