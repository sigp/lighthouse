#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ethereum_types;
extern crate ssz;

use ethereum_types::H256;
use ssz::SszStream;

// Fuzz ssz_encode (via ssz_append)
fuzz_target!(|data: &[u8]| {
    let mut ssz = SszStream::new();
    if data.len() >= 32 {
        let hash = H256::from_slice(&data[..32]);
        ssz.append(&hash);
        let ssz = ssz.drain();

        assert_eq!(data[..32], ssz[..32]);
        assert_eq!(ssz.len(), 32);
    }
});
