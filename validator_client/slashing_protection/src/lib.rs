mod attestation_tests;
mod block_tests;
mod extra_interchange_tests;
pub mod interchange_test;
mod parallel_tests;
mod registration_tests;
mod slashing_database;
pub mod test_utils;

pub use crate::slashing_database::{SUPPORTED_INTERCHANGE_FORMAT_VERSION, SlashingDatabase};
use types::{Hash256, PublicKeyBytes};

/// The filename within the `validators` directory that contains the slashing protection DB.
pub const SLASHING_PROTECTION_FILENAME: &str = "slashing_protection.sqlite";

#[cfg(test)]
mod test {
    use eip_3076::SigningRoot;
    use types::FixedBytesExtended;

    use super::*;

    #[test]
    #[allow(clippy::eq_op)]
    fn signing_root_partial_eq() {
        let h0 = SigningRoot(Hash256::zero());
        let h1 = SigningRoot(Hash256::repeat_byte(1));
        let h2 = SigningRoot(Hash256::repeat_byte(2));
        assert_ne!(h0, h0);
        assert_ne!(h0, h1);
        assert_ne!(h1, h0);
        assert_eq!(h1, h1);
        assert_ne!(h1, h2);
    }
}
