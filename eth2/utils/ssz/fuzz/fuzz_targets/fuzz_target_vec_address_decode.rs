#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ethereum_types;
extern crate ssz;

use ethereum_types::{Address};
use ssz::{DecodeError, Decodable};

// Fuzz ssz_decode()
fuzz_target!(|data: &[u8]| {
    let _result: Result<(Vec<Address>, usize), DecodeError> = Decodable::ssz_decode(data, 0);
});
