#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ethereum_types;
extern crate ssz;

use ssz::{decode, DecodeError, Decodable};

// Fuzz ssz_decode()
fuzz_target!(|data: &[u8]| {
    let _result: Result<Vec<u8>, DecodeError> = decode(data);
});
