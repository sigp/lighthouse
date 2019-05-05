//! Encode and decode a list 10,000 times.
//!
//! Useful for `cargo flamegraph`.

use ssz::{Decodable, Encodable};

fn main() {
    let vec: Vec<u64> = vec![4242; 8196];

    let output: Vec<Vec<u64>> = (0..10_000)
        .into_iter()
        .map(|_| Vec::from_ssz_bytes(&vec.as_ssz_bytes()).unwrap())
        .collect();

    println!("{}", output.len());
}
