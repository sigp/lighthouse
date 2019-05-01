#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;

use ssz::SszStream;

// Fuzz ssz_encode (via ssz_append)
fuzz_target!(|data: &[u8]| {
    let mut ssz = SszStream::new();
    let mut number_u8 = 0;
    if data.len() >= 1 {
        number_u8 = data[0];
    }

    ssz.append(&number_u8);
    let ssz = ssz.drain();

    assert_eq!(number_u8, ssz[0]);
    assert_eq!(ssz.len(), 1);
});
