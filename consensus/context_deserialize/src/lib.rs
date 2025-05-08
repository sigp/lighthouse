pub mod impls;
pub mod milhouse;
pub mod ssz_impls;

extern crate serde;
use serde::de::Deserializer;

/// General-purpose deserialization trait that accepts extra context `C`.
pub trait ContextDeserialize<'de, C>: Sized {
    fn context_deserialize<D>(deserializer: D, context: C) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>;
}
