use serde::de::Deserializer;

/// General-purpose deserialization trait that accepts extra context `C`.
pub trait ContextDeserialize<'de, C>: Sized {
    fn context_deserialize<D>(
        deserializer: D,
        context: C,
    ) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>;
}

/// Blanket impl for ordinary `serde::Deserialize` types
/// when `Context = ()`.
impl<'de, T> ContextDeserialize<'de, ()> for T
where
    T: serde::Deserialize<'de>,
{
    fn context_deserialize<D>(
        deserializer: D,
        _context: (),
    ) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer)
    }
}
