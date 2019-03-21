#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate boolean_bitfield;
extern crate ssz;

use boolean_bitfield::BooleanBitfield;
use ssz::SszStream;

fuzz_target!(|data: &[u8]| {
    let bitfield = BooleanBitfield::from_bytes(data);
    let mut ssz = SszStream::new();
    ssz.append(&bitfield);
});
