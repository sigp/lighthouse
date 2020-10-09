//! This crate contains functions that are common across multiple `warp` HTTP servers in the
//! Lighthouse project. E.g., the `http_api` and `http_metrics` crates.

pub mod reject;
pub mod reply;
pub mod task;
