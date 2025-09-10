mod impls;

#[cfg(feature = "derive")]
pub use context_deserialize_derive::context_deserialize;

use serde::de::Deserializer;

/// General-purpose deserialization trait that accepts extra context `C`.
pub trait ContextDeserialize<'de, C>: Sized {
    fn context_deserialize<D>(deserializer: D, context: C) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>;
}
