use crate::ContextDeserialize;
use milhouse::{List, Value, Vector};
use serde::de::Deserializer;
use ssz_types::typenum::Unsigned;

impl<'de, C, T, N> ContextDeserialize<'de, C> for List<T, N>
where
    T: ContextDeserialize<'de, C> + Value,
    N: Unsigned,
    C: Clone,
{
    fn context_deserialize<D>(deserializer: D, context: C) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // First deserialize as a Vec.
        // This is not the most efficient implementation as it allocates a temporary Vec. In future
        // we could write a more performant implementation using `List::builder()`.
        let vec = Vec::<T>::context_deserialize(deserializer, context)?;

        // Then convert to List, which will check the length.
        List::new(vec)
            .map_err(|e| serde::de::Error::custom(format!("Failed to create List: {:?}", e)))
    }
}

impl<'de, C, T, N> ContextDeserialize<'de, C> for Vector<T, N>
where
    T: ContextDeserialize<'de, C> + Value,
    N: Unsigned,
    C: Clone,
{
    fn context_deserialize<D>(deserializer: D, context: C) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // First deserialize as a List
        let list = List::<T, N>::context_deserialize(deserializer, context)?;

        // Then convert to Vector, which will check the length
        Vector::try_from(list).map_err(|e| {
            serde::de::Error::custom(format!("Failed to convert List to Vector: {:?}", e))
        })
    }
}
