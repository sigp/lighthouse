#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;

use ssz::SszStream;

// Fuzz ssz_encode (via ssz_append)
fuzz_target!(|data: &[u8]| {
    let mut ssz = SszStream::new();
    let mut number_usize = 0;
    if data.len() >= 8 {
        number_usize = u64::from_le_bytes([
            data[0],
            data[1],
            data[2],
            data[3],
            data[4],
            data[5],
            data[6],
            data[7],
            ]) as usize;
    }

    ssz.append(&number_usize);
    let ssz = ssz.drain();

    assert_eq!(ssz.len(), 8);
    assert_eq!(number_usize, u64::from_le_bytes([
        ssz[0],
        ssz[1],
        ssz[2],
        ssz[3],
        ssz[4],
        ssz[5],
        ssz[6],
        ssz[7],
        ]) as usize);
});
