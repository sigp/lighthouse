//! This crate provides two objects:
//! - `HashMapDelay`
//! - `HashSetDelay`
//!
//! # HashMapDelay
//!
//! This provides a `HashMap` coupled with a `DelayQueue`. Objects that are inserted into
//! the map are inserted with an expiry. `Stream` is implemented on the `HashMapDelay`
//! which return objects that have expired. These objects are removed from the mapping.
//!
//! # HashSetDelay
//!
//! This is similar to a `HashMapDelay` except the mapping maps to the expiry time. This
//! allows users to add objects and check their expiry deadlines before the `Stream`
//! consumes them.

mod hashmap_delay;
mod hashset_delay;

pub use crate::hashmap_delay::HashMapDelay;
pub use crate::hashset_delay::HashSetDelay;
