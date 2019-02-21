#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ethereum_types;
extern crate ssz;

use ethereum_types::{Address, H256};
use ssz::SszStream;

// Fuzz ssz_decode()
fuzz_target!(|data: &[u8]| {

    let mut ssz = SszStream::new();
    let data_vec = data.to_vec();
    ssz.append(&data_vec);
});
