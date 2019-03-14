#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;

use ssz::SszStream;

// Fuzz ssz_encode (via ssz_append)
fuzz_target!(|data: &[u8]| {
    let mut ssz = SszStream::new();
    let mut val_bool = 0;
    if data.len() >= 1 {
        val_bool = data[0] % u8::pow(2, 6);
    }

    ssz.append(&val_bool);
    let ssz = ssz.drain();

    // TODO: change to little endian bytes
    // https://github.com/sigp/lighthouse/issues/215
    assert_eq!(val_bool, ssz[0] % u8::pow(2, 6));
    assert_eq!(ssz.len(), 1);
});
