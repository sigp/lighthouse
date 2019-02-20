#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;

use ssz::{DecodeError, Decodable, Encodable};

// Fuzz ssz_decode(u8)
fuzz_target!(|data: &[u8]| {
    let result: Result<(u8, usize), DecodeError> = Decodable::ssz_decode(data, 0);
});
