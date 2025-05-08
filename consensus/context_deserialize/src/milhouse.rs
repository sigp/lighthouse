use crate::ContextDeserialize;
use milhouse::{List, Value, Vector};
use serde::de::{DeserializeSeed, Deserializer, SeqAccess, Visitor};
use ssz_types::typenum::Unsigned;
use std::marker::PhantomData;

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
        // Our Visitor, which owns one copy of the context C
        struct ListVisitor<C, T, N> {
            context: C,
            _marker: PhantomData<(T, N)>,
        }

        impl<'de, C, T, N> Visitor<'de> for ListVisitor<C, T, N>
        where
            C: Clone,
            T: ContextDeserialize<'de, C> + Value,
            N: Unsigned,
        {
            type Value = List<T, N>;

            fn expecting(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                fmt.write_str("a sequence of context‐deserialized elements")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<List<T, N>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));

                // for each element, we clone the context and hand it to the seed
                while let Some(elem) = seq.next_element_seed(ContextSeed {
                    context: self.context.clone(),
                    _marker: PhantomData,
                })? {
                    out.push(elem);
                }

                List::new(out).map_err(|e| {
                    serde::de::Error::custom(format!("Failed to create List: {:?}", e))
                })
            }
        }

        // A little seed that hands the deserializer + context into T::context_deserialize
        struct ContextSeed<C, T> {
            context: C,
            _marker: PhantomData<T>,
        }

        impl<'de, C, T> DeserializeSeed<'de> for ContextSeed<C, T>
        where
            C: Clone,
            T: ContextDeserialize<'de, C>,
        {
            type Value = T;

            fn deserialize<D>(self, deserializer: D) -> Result<T, D::Error>
            where
                D: Deserializer<'de>,
            {
                T::context_deserialize(deserializer, self.context)
            }
        }

        deserializer.deserialize_seq(ListVisitor {
            context,
            _marker: PhantomData,
        })
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
