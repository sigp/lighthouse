mod fake_crypto;
mod herumi;
mod milagro;

macro_rules! define_mod {
    ($name: ident, $mod: path) => {
        pub mod $name {
            use $mod as bls_variant;

            pub type PublicKey = crate::public_key::PublicKey<bls_variant::PublicKey>;
            pub type PublicKeyBytes =
                crate::public_key_bytes::PublicKeyBytes<bls_variant::PublicKey>;
            pub type Signature =
                crate::signature::Signature<bls_variant::PublicKey, bls_variant::Signature>;
            pub type SignatureBytes = crate::signature_bytes::SignatureBytes<
                bls_variant::Signature,
                bls_variant::PublicKey,
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

define_mod!(herumi_implementations, super::herumi);
#[cfg(feature = "herumi")]
pub use herumi_implementations::*;

define_mod!(fake_crypto_implementations, super::fake_crypto);
#[cfg(feature = "fake_crypto")]
pub use fake_crypto_implementations::*;

define_mod!(milagro_implementations, super::milagro);
#[cfg(feature = "milagro")]
pub use milagro_implementations::*;
