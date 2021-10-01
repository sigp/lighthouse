#![cfg(not(debug_assertions))] // Tests are too slow in debug.
#![recursion_limit = "256"]

pub mod common;
pub mod fork_tests;
pub mod interactive_tests;
pub mod tests;
