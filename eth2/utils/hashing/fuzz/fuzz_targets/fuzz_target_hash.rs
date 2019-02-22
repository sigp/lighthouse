#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate hashing;

use hashing::hash;

fuzz_target!(|data: &[u8]| {
    let _result = hash(data);
});
