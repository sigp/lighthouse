#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ethereum_types;
extern crate ssz;

use ethereum_types::Address;
use ssz::{DecodeError, decode};

// Fuzz ssz_decode()
fuzz_target!(|data: &[u8]| {
    let result: Result<Address, DecodeError> = decode(data);
    if data.len() == 20 {
        // Should have valid result
        let address = result.unwrap();
        assert_eq!(address, Address::from_slice(&data[..20]));
    } else {
        // Length of less than 32 should return error
        assert!(result.is_err());
    }
});
