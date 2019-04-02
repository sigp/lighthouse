#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;

use ssz::SszStream;

// Fuzz ssz_encode (via ssz_append)
fuzz_target!(|data: &[u8]| {
    let mut ssz = SszStream::new();
    let mut number_u32 = 0;
    if data.len() >= 4 {
        number_u32 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    }

    ssz.append(&number_u32);
    let ssz = ssz.drain();

    assert_eq!(ssz.len(), 4);
    assert_eq!(number_u32, u32::from_le_bytes([ssz[0], ssz[1], ssz[2], ssz[3]]));
});
