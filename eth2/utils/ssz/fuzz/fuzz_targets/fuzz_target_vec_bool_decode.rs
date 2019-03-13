#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;

use ssz::{DecodeError, Decodable};

// Fuzz ssz_decode()
fuzz_target!(|data: &[u8]| {
    let _result: Result<(Vec<bool>, usize), DecodeError> = Decodable::ssz_decode(data, 0);
});
