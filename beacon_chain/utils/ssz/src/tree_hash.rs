extern crate blake2_rfc;

use self::blake2_rfc::blake2s::blake2s;

/**
 * Extends data length to a power of 2 by minimally right-zero-padding
 */
fn extend_to_power_of_2(data: &mut Vec<u8>) {
    let len = data.len();
    let new_len = len.next_power_of_two();
    if new_len > len {
        data.append(&mut vec![0; new_len - len]);
    }
}

fn hash(data: Vec<u8>) -> Vec<u8> {
    let result = blake2s(32, &[], data.as_slice());
    result.as_bytes().to_vec()
}

// fn list_to_glob() {}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extend_to_power_of_2() {
        let mut data = vec![1, 2, 3, 4, 5];

        // an array length of 5 should be extended to
        // a length of 8 (the next power of 2) by right
        // padding it with 3 zeros
        extend_to_power_of_2(&mut data);
        assert_eq!(data, [1, 2, 3, 4, 5, 0, 0, 0]);
    }
}
