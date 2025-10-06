use crate::ContextDeserialize;
use serde::{
    de::{Deserializer, Error},
    Deserialize,
};
use ssz_types::{
    length::{Fixed, Variable},
    typenum::Unsigned,
    Bitfield, FixedVector,
};

impl<'de, C, T, N> ContextDeserialize<'de, C> for FixedVector<T, N>
where
    T: ContextDeserialize<'de, C>,
    N: Unsigned,
    C: Clone,
{
    fn context_deserialize<D>(deserializer: D, context: C) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = Vec::<T>::context_deserialize(deserializer, context)?;
        FixedVector::new(vec).map_err(|e| D::Error::custom(format!("{:?}", e)))
    }
}

impl<'de, C, N> ContextDeserialize<'de, C> for Bitfield<Variable<N>>
where
    N: Unsigned + Clone,
{
    fn context_deserialize<D>(deserializer: D, _context: C) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Bitfield::<Variable<N>>::deserialize(deserializer)
            .map_err(|e| D::Error::custom(format!("{:?}", e)))
    }
}

impl<'de, C, N> ContextDeserialize<'de, C> for Bitfield<Fixed<N>>
where
    N: Unsigned + Clone,
{
    fn context_deserialize<D>(deserializer: D, _context: C) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Bitfield::<Fixed<N>>::deserialize(deserializer)
            .map_err(|e| D::Error::custom(format!("{:?}", e)))
    }
}
