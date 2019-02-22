#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate boolean_bitfield;
extern crate ssz;

use boolean_bitfield::BooleanBitfield;
use ssz::{Decodable, DecodeError};

fuzz_target!(|data: &[u8]| {
    let result: Result<(BooleanBitfield, usize), DecodeError> = <_>::ssz_decode(data, 0);
});
