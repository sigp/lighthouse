#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;

use ssz::SszStream;

// Fuzz ssz_encode (via ssz_append)
fuzz_target!(|data: &[u8]| {
    let mut ssz = SszStream::new();
    let mut number_u64 = 0;
    if data.len() >= 8 {
        number_u64 = u64::from_be_bytes([
            data[0],
            data[1],
            data[2],
            data[3],
            data[4],
            data[5],
            data[6],
            data[7],
            ]);
    }

    ssz.append(&number_u64);
    let ssz = ssz.drain();

    // TODO: change to little endian bytes
    // https://github.com/sigp/lighthouse/issues/215
    assert_eq!(ssz.len(), 8);
    assert_eq!(number_u64, u64::from_be_bytes([
        ssz[0],
        ssz[1],
        ssz[2],
        ssz[3],
        ssz[4],
        ssz[5],
        ssz[6],
        ssz[7],
        ]));
});
