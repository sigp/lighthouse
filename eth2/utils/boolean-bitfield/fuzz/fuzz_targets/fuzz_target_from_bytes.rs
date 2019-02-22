#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate boolean_bitfield;

use boolean_bitfield::BooleanBitfield;

fuzz_target!(|data: &[u8]| {
    let _result = BooleanBitfield::from_bytes(data);
});
