//! Formats some integer types using quotes.
//!
//! E.g., `1` serializes as `"1"`.
//!
//! Quotes can be optional during decoding.

use ethereum_types::U256;
use serde::{Deserializer, Serializer};
use serde_derive::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::marker::PhantomData;

macro_rules! define_mod {
    ($int: ty) => {
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

    define_mod!(u8);
}

pub mod quoted_u32 {
    use super::*;

    define_mod!(u32);
}

pub mod quoted_u64 {
    use super::*;

    define_mod!(u64);
}

pub mod quoted_i64 {
    use super::*;

    define_mod!(i64);
}

pub mod quoted_u256 {
    use super::*;

    struct U256Visitor;

    impl<'de> serde::de::Visitor<'de> for U256Visitor {
        type Value = U256;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a quoted U256 integer")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            U256::from_dec_str(v).map_err(serde::de::Error::custom)
        }
    }

    /// Serialize with quotes.
    pub fn serialize<S>(value: &U256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}", value))
    }

    /// Deserialize with quotes.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(U256Visitor)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(transparent)]
    struct WrappedU256(#[serde(with = "quoted_u256")] U256);

    #[test]
    fn u256_with_quotes() {
        assert_eq!(
            &serde_json::to_string(&WrappedU256(U256::one())).unwrap(),
            "\"1\""
        );
        assert_eq!(
            serde_json::from_str::<WrappedU256>("\"1\"").unwrap(),
            WrappedU256(U256::one())
        );
    }

    #[test]
    fn u256_without_quotes() {
        serde_json::from_str::<WrappedU256>("1").unwrap_err();
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(transparent)]
    struct WrappedI64(#[serde(with = "quoted_i64")] i64);

    #[test]
    fn negative_i64_with_quotes() {
        assert_eq!(
            serde_json::from_str::<WrappedI64>("\"-200\"").unwrap().0,
            -200
        );
        assert_eq!(
            serde_json::to_string(&WrappedI64(-12_500)).unwrap(),
            "\"-12500\""
        );
    }

    // It would be OK if this worked, but we don't need it to (i64s should always be quoted).
    #[test]
    fn negative_i64_without_quotes() {
        serde_json::from_str::<WrappedI64>("-200").unwrap_err();
    }
}
