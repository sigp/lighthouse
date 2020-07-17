mod blst;
mod fake_crypto;
mod milagro;

/// Defines all the fundamental BLS points which should be exported by this crate by making
/// concrete the generic type parameters using the points from some external BLS library (e.g.,
/// Milagro, BLST).
macro_rules! define_mod {
    ($name: ident, $mod: path) => {
        pub mod $name {
            use $mod as bls_variant;

            use crate::generic_aggregate_public_key::GenericAggregatePublicKey;
            use crate::generic_aggregate_signature::GenericAggregateSignature;
            use crate::generic_keypair::GenericKeypair;
            use crate::generic_public_key::GenericPublicKey;
            use crate::generic_public_key_bytes::GenericPublicKeyBytes;
            use crate::generic_secret_key::GenericSecretKey;
            use crate::generic_signature::GenericSignature;
            use crate::generic_signature_bytes::GenericSignatureBytes;

            pub use bls_variant::{verify_signature_sets, SignatureSet};

            pub type PublicKey = GenericPublicKey<bls_variant::PublicKey>;
            pub type AggregatePublicKey =
                GenericAggregatePublicKey<bls_variant::AggregatePublicKey>;
            pub type PublicKeyBytes = GenericPublicKeyBytes<bls_variant::PublicKey>;
            pub type Signature = GenericSignature<bls_variant::PublicKey, bls_variant::Signature>;
            pub type AggregateSignature = GenericAggregateSignature<
                bls_variant::PublicKey,
                bls_variant::AggregatePublicKey,
                bls_variant::Signature,
                bls_variant::AggregateSignature,
            >;
            pub type SignatureBytes =
                GenericSignatureBytes<bls_variant::PublicKey, bls_variant::Signature>;
            pub type SecretKey = GenericSecretKey<
                bls_variant::Signature,
                bls_variant::PublicKey,
                bls_variant::SecretKey,
            >;
            pub type Keypair = GenericKeypair<
                bls_variant::PublicKey,
                bls_variant::SecretKey,
                bls_variant::Signature,
            >;
        }
    };
}

define_mod!(milagro_implementations, super::milagro::types);
define_mod!(blst_implementations, super::blst::types);
define_mod!(fake_crypto_implementations, super::fake_crypto::types);

#[cfg(all(
    feature = "milagro",
    not(feature = "fake_crypto"),
    not(feature = "supranatural")
))]
pub use milagro_implementations::*;

#[cfg(all(
    feature = "supranatural",
    not(feature = "fake_crypto"),
    not(feature = "milagro")
))]
pub use blst_implementations::*;

#[cfg(feature = "fake_crypto")]
pub use fake_crypto_implementations::*;
