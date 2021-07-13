//! This crate checks properties of the target architecture to ensure that it's compatible with
//! Lighthouse.
use static_assertions::assert_cfg;

// In many places we assume `usize` and `u64` have the same in-memory representation.
// We also use memory-mapped files extensively which are only really viable with 64-bit addressing.
// It's unlikely we will want to support 128-bit architectures any time soon.
assert_cfg!(
    target_pointer_width = "64",
    "Lighthouse requires a 64-bit CPU and operating system",
);
