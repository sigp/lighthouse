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

            pub use bls_variant::{verify_signature_sets, SignatureSet};

            pub type PublicKey = crate::public_key::GenericPublicKey<bls_variant::PublicKey>;
            pub type AggregatePublicKey = crate::aggregate_public_key::GenericAggregatePublicKey<
                bls_variant::AggregatePublicKey,
            >;
            pub type PublicKeyBytes =
                crate::public_key_bytes::GenericPublicKeyBytes<bls_variant::PublicKey>;
            pub type Signature =
                crate::signature::GenericSignature<bls_variant::PublicKey, bls_variant::Signature>;
            pub type AggregateSignature = crate::aggregate_signature::GenericAggregateSignature<
                bls_variant::PublicKey,
                bls_variant::AggregatePublicKey,
                bls_variant::Signature,
                bls_variant::AggregateSignature,
            >;
            pub type SignatureBytes = crate::signature_bytes::GenericSignatureBytes<
                bls_variant::PublicKey,
                bls_variant::Signature,
            >;
            pub type SecretKey = crate::secret_key::GenericSecretKey<
                bls_variant::Signature,
                bls_variant::PublicKey,
                bls_variant::SecretKey,
            >;
            pub type Keypair = crate::keypair::Keypair<
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
