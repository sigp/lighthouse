#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;

use ssz::{DecodeError, decode};

// Fuzz decode()
fuzz_target!(|data: &[u8]| {
    // Note: we assume architecture is 64 bit -> usize == 64 bits
    let result: Result<usize, DecodeError> = decode(data);
    if data.len() == 8 {
        // Valid result
        let number_usize = result.unwrap();
        let val = u64::from_le_bytes([
            data[0],
            data[1],
            data[2],
            data[3],
            data[4],
            data[5],
            data[6],
            data[7],
            ]);
        assert_eq!(number_usize, val as usize);
    } else {
        // Length less then 8 should return error
        assert!(result.is_err());
    }
});
