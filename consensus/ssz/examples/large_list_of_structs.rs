//! Encode and decode a list many times.
//!
//! Useful for `cargo flamegraph`.

use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};

#[derive(Clone, Copy, Encode, Decode)]
pub struct FixedLen {
    a: u64,
    b: u64,
    c: u64,
    d: u64,
}

fn main() {
    let fixed_len = FixedLen {
        a: 42,
        b: 42,
        c: 42,
        d: 42,
    };

    let vec: Vec<FixedLen> = vec![fixed_len; 8196];

    let output: Vec<Vec<u64>> = (0..40_000)
        .map(|_| Vec::from_ssz_bytes(&vec.as_ssz_bytes()).unwrap())
        .collect();

    println!("{}", output.len());
}
