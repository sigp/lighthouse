#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ethereum_types;
extern crate ssz;

use ethereum_types::Address;
use ssz::SszStream;

// Fuzz ssz_encode (via ssz_append)
fuzz_target!(|data: &[u8]| {
    let mut ssz = SszStream::new();
    if data.len() >= 20 {
        let hash = Address::from_slice(&data[..20]);
        ssz.append(&hash);
        let ssz = ssz.drain();

        assert_eq!(data[..20], ssz[..20]);
        assert_eq!(ssz.len(), 20);
    }
});
