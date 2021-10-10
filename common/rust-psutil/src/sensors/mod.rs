//! Temperatures and Fans.
//!
//! For battery information, check out [rust-battery](https://github.com/svartalf/rust-battery).

mod fan_sensor;
mod sys;
mod temperature_sensor;

pub use fan_sensor::*;
pub use sys::*;
pub use temperature_sensor::*;
