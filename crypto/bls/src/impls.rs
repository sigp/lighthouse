mod fake_crypto;
mod milagro;

pub mod milagro_implementations {
    pub use super::milagro::{verify_signature_sets, SignatureSet};

    use super::milagro::milagro;

    pub type PublicKey = crate::public_key::PublicKey<milagro::PublicKey>;
    pub type AggregatePublicKey =
        crate::aggregate_public_key::AggregatePublicKey<milagro::AggregatePublicKey>;
    pub type PublicKeyBytes = crate::public_key_bytes::PublicKeyBytes<milagro::PublicKey>;
    pub type Signature = crate::signature::Signature<milagro::PublicKey, milagro::Signature>;
    pub type AggregateSignature = crate::aggregate_signature::AggregateSignature<
        milagro::PublicKey,
        milagro::AggregatePublicKey,
        milagro::Signature,
        milagro::AggregateSignature,
    >;
    pub type SignatureBytes =
        crate::signature_bytes::SignatureBytes<milagro::PublicKey, milagro::Signature>;
    pub type SecretKey =
        crate::secret_key::SecretKey<milagro::Signature, milagro::PublicKey, milagro::SecretKey>;
    pub type Keypair =
        crate::keypair::Keypair<milagro::PublicKey, milagro::SecretKey, milagro::Signature>;
}

macro_rules! define_mod {
    ($name: ident, $mod: path) => {
        pub mod $name {
            use $mod as bls_variant;

            pub use bls_variant::{verify_signature_sets, SignatureSet};

            pub type PublicKey = crate::public_key::PublicKey<bls_variant::PublicKey>;
            pub type PublicKeyBytes =
                crate::public_key_bytes::PublicKeyBytes<bls_variant::PublicKey>;
            pub type Signature =
                crate::signature::Signature<bls_variant::PublicKey, bls_variant::Signature>;
            pub type SignatureBytes = crate::signature_bytes::SignatureBytes<
                bls_variant::PublicKey,
                bls_variant::Signature,
            >;
            pub type SecretKey = crate::secret_key::SecretKey<
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

#[cfg(feature = "milagro")]
pub use milagro_implementations::*;

define_mod!(fake_crypto_implementations, super::fake_crypto);
#[cfg(feature = "fake_crypto")]
pub use fake_crypto_implementations::*;
