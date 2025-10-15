use crate::ContextDeserialize;
use serde::de::{Deserialize, DeserializeSeed, Deserializer, SeqAccess, Visitor};
use std::marker::PhantomData;
use std::sync::Arc;

impl<'de, C, T> ContextDeserialize<'de, T> for Arc<C>
where
    C: ContextDeserialize<'de, T>,
{
    fn context_deserialize<D>(deserializer: D, context: T) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Arc::new(C::context_deserialize(deserializer, context)?))
    }
}

impl<'de, T, C> ContextDeserialize<'de, C> for Vec<T>
where
    T: ContextDeserialize<'de, C>,
    C: Clone,
{
    fn context_deserialize<D>(deserializer: D, context: C) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Our Visitor, which owns one copy of the context T
        struct ContextVisitor<C, T> {
            context: T,
            _marker: PhantomData<C>,
        }

        impl<'de, C, T> Visitor<'de> for ContextVisitor<C, T>
        where
            C: ContextDeserialize<'de, T>,
            T: Clone,
        {
            type Value = Vec<C>;

            fn expecting(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                fmt.write_str("a sequence of context‐deserialized elements")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Vec<C>, A::Error>
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
                Ok(out)
            }
        }

        // A little seed that hands the deserializer + context into C::context_deserialize
        struct ContextSeed<T, C> {
            context: C,
            _marker: PhantomData<T>,
        }

        impl<'de, T, C> DeserializeSeed<'de> for ContextSeed<T, C>
        where
            T: ContextDeserialize<'de, C>,
            C: Clone,
        {
            type Value = T;

            fn deserialize<D>(self, deserializer: D) -> Result<T, D::Error>
            where
                D: Deserializer<'de>,
            {
                T::context_deserialize(deserializer, self.context)
            }
        }

        deserializer.deserialize_seq(ContextVisitor {
            context,
            _marker: PhantomData,
        })
    }
}

macro_rules! trivial_deserialize {
    ($($t:ty),* $(,)?) => {
        $(
            impl<'de, T> ContextDeserialize<'de, T> for $t {
                fn context_deserialize<D>(deserializer: D, _context: T) -> Result<Self, D::Error>
                where
                    D: Deserializer<'de>,
                {
                    <$t>::deserialize(deserializer)
                }
            }
        )*
    };
}

trivial_deserialize!(bool, u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, f32, f64);
