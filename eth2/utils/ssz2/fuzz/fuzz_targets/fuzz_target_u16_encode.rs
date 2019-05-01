#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;

use ssz::SszStream;

// Fuzz ssz_encode (via ssz_append)
fuzz_target!(|data: &[u8]| {
    let mut ssz = SszStream::new();
    let mut number_u16 = 0;
    if data.len() >= 2 {
        number_u16 = u16::from_be_bytes([data[0], data[1]]);
    }

    ssz.append(&number_u16);
    let ssz = ssz.drain();

    assert_eq!(ssz.len(), 2);
    assert_eq!(number_u16, u16::from_le_bytes([ssz[0], ssz[1]]));
});
