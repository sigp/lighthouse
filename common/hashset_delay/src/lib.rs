//! This crate provides a single type (its counter-part HashMapDelay has been removed as it
//! currently is not in use in lighthouse):
//! - `HashSetDelay`
//!
//! # HashSetDelay
//!
//! This is similar to a `HashMapDelay` except the mapping maps to the expiry time. This
//! allows users to add objects and check their expiry deadlines before the `Stream`
//! consumes them.

mod hashset_delay;
pub use crate::hashset_delay::HashSetDelay;
