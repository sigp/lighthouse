//! A library to provide fast and efficient LRU Cache's without updating.

mod space;
mod time;

pub use space::LRUCache;
pub use time::LRUTimeCache;
