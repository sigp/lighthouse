//! Formats some integer types using quotes.
//!
//! E.g., `1` serializes as `"1"`.
//!
//! Quotes can be optional during decoding.

use serde::{Deserializer, Serializer};
use serde_derive::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::marker::PhantomData;

macro_rules! define_mod {
    ($int: ty, $visit_fn: ident) => {
        /// Serde support for deserializing quoted integers.
        ///
        /// Configurable so that quotes are either required or optional.
        pub struct QuotedIntVisitor<T> {
            require_quotes: bool,
            _phantom: PhantomData<T>,
        }

        impl<'a, T> serde::de::Visitor<'a> for QuotedIntVisitor<T>
        where
            T: From<$int> + Into<$int> + Copy + TryFrom<u64>,
        {
            type Value = T;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                if self.require_quotes {
                    write!(formatter, "a quoted integer")
                } else {
                    write!(formatter, "a quoted or unquoted integer")
                }
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                s.parse::<$int>()
                    .map(T::from)
                    .map_err(serde::de::Error::custom)
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if self.require_quotes {
                    Err(serde::de::Error::custom(
                        "received unquoted integer when quotes are required",
                    ))
                } else {
                    T::try_from(v).map_err(|_| serde::de::Error::custom("invalid integer"))
                }
            }
        }

        /// Wrapper type for requiring quotes on a `$int`-like type.
        ///
        /// Unlike using `serde(with = "quoted_$int::require_quotes")` this is composable, and can be nested
        /// inside types like `Option`, `Result` and `Vec`.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
        #[serde(transparent)]
        pub struct Quoted<T>
        where
            T: From<$int> + Into<$int> + Copy + TryFrom<u64>,
        {
            #[serde(with = "require_quotes")]
            pub value: T,
        }

        /// Compositional wrapper type that allows quotes or no quotes.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
        #[serde(transparent)]
        pub struct MaybeQuoted<T>
        where
            T: From<$int> + Into<$int> + Copy + TryFrom<u64>,
        {
            #[serde(with = "self")]
            pub value: T,
        }

        /// Serialize with quotes.
        pub fn serialize<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
            T: From<$int> + Into<$int> + Copy,
        {
            let v: $int = (*value).into();
            serializer.serialize_str(&format!("{}", v))
        }

        /// Deserialize with or without quotes.
        pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
        where
            D: Deserializer<'de>,
            T: From<$int> + Into<$int> + Copy + TryFrom<u64>,
        {
            deserializer.deserialize_any(QuotedIntVisitor {
                require_quotes: false,
                _phantom: PhantomData,
            })
        }

        /// Requires quotes when deserializing.
        ///
        /// Usage: `#[serde(with = "quoted_u64::require_quotes")]`.
        pub mod require_quotes {
            pub use super::serialize;
            use super::*;

            pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
            where
                D: Deserializer<'de>,
                T: From<$int> + Into<$int> + Copy + TryFrom<u64>,
            {
                deserializer.deserialize_any(QuotedIntVisitor {
                    require_quotes: true,
                    _phantom: PhantomData,
                })
            }
        }

        #[cfg(test)]
        mod test {
            use super::*;

            #[test]
            fn require_quotes() {
                let x = serde_json::from_str::<Quoted<$int>>("\"8\"").unwrap();
                assert_eq!(x.value, 8);
                serde_json::from_str::<Quoted<$int>>("8").unwrap_err();
            }
        }
    };
}

pub mod quoted_u8 {
    use super::*;

    define_mod!(u8, visit_u8);
}

pub mod quoted_u32 {
    use super::*;

    define_mod!(u32, visit_u32);
}

pub mod quoted_u64 {
    use super::*;

    define_mod!(u64, visit_u64);
}
