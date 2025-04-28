use serde::de::{DeserializeSeed, Deserializer, SeqAccess, Visitor};
use std::marker::PhantomData;
use std::sync::Arc;
/// General-purpose deserialization trait that accepts extra context `C`.
pub trait ContextDeserialize<'de, C>: Sized {
    fn context_deserialize<D>(deserializer: D, context: C) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>;
}

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

impl<'de, C, T> ContextDeserialize<'de, T> for Vec<C>
where
    C: ContextDeserialize<'de, T>,
    T: Clone,
{
    fn context_deserialize<D>(deserializer: D, context: T) -> Result<Self, D::Error>
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
        struct ContextSeed<C, T> {
            context: T,
            _marker: PhantomData<C>,
        }

        impl<'de, C, T> DeserializeSeed<'de> for ContextSeed<C, T>
        where
            C: ContextDeserialize<'de, T>,
            T: Clone,
        {
            type Value = C;

            fn deserialize<D>(self, deserializer: D) -> Result<C, D::Error>
            where
                D: Deserializer<'de>,
            {
                C::context_deserialize(deserializer, self.context)
            }
        }

        deserializer.deserialize_seq(ContextVisitor {
            context,
            _marker: PhantomData,
        })
    }
}
