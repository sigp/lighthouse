extern crate bls_aggregates;

pub use self::bls_aggregates::AggregateSignature;
pub use self::bls_aggregates::AggregatePublicKey;
pub use self::bls_aggregates::Signature;
pub use self::bls_aggregates::Keypair;
pub use self::bls_aggregates::PublicKey;
pub use self::bls_aggregates::SecretKey;

pub const BLS_AGG_SIG_BYTE_SIZE: usize = 97;
