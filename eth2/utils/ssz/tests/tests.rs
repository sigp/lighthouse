use ssz::{Decodable, Encodable};
use ssz_derive::{Decode, Encode};

/*
fn round_trip<T: Encodable + Decodable + std::fmt::Debug + PartialEq>(items: Vec<T>) {
    for item in items {
        let encoded = &item.as_ssz_bytes();
        dbg!(encoded);
        assert_eq!(T::from_ssz_bytes(&encoded), Ok(item));
    }
}

#[test]
fn vec_u16_round_trip() {
    let items: Vec<Vec<u16>> = vec![
        vec![],
        vec![255],
        vec![0, 1, 2],
        vec![100; 64],
        vec![255, 0, 255],
    ];

    round_trip(items);
}

#[test]
fn vec_of_vec_u16_round_trip() {
    let items: Vec<Vec<Vec<u16>>> = vec![
        vec![],
        vec![vec![]],
        vec![vec![1, 2, 3]],
        vec![vec![], vec![]],
        vec![vec![], vec![1, 2, 3]],
        vec![vec![1, 2, 3], vec![1, 2, 3]],
        vec![vec![1, 2, 3], vec![], vec![1, 2, 3]],
        vec![vec![], vec![], vec![1, 2, 3]],
        vec![vec![], vec![1], vec![1, 2, 3]],
        vec![vec![], vec![1], vec![1, 2, 3]],
    ];

    round_trip(items);
}

#[derive(Debug, PartialEq, Encode, Decode)]
struct FixedLen {
    a: u16,
    b: u64,
    c: u32,
}

#[test]
fn fixed_len_struct_encoding() {
    let items: Vec<FixedLen> = vec![
        FixedLen { a: 0, b: 0, c: 0 },
        FixedLen { a: 1, b: 1, c: 1 },
        FixedLen { a: 1, b: 0, c: 1 },
    ];

    let expected_encodings = vec![
        //  | u16--| u64----------------------------| u32----------|
        vec![00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00],
        vec![01, 00, 01, 00, 00, 00, 00, 00, 00, 00, 01, 00, 00, 00],
        vec![01, 00, 00, 00, 00, 00, 00, 00, 00, 00, 01, 00, 00, 00],
    ];

    for i in 0..items.len() {
        assert_eq!(
            items[i].as_ssz_bytes(),
            expected_encodings[i],
            "Failed on {}",
            i
        );
    }
}

#[test]
fn vec_of_fixed_len_struct() {
    let items: Vec<FixedLen> = vec![
        FixedLen { a: 0, b: 0, c: 0 },
        FixedLen { a: 1, b: 1, c: 1 },
        FixedLen { a: 1, b: 0, c: 1 },
    ];

    round_trip(items);
}

#[derive(Debug, PartialEq, Encode, Decode)]
struct VariableLen {
    a: u16,
    b: Vec<u16>,
    c: u32,
}

#[test]
fn variable_len_struct_encoding() {
    let items: Vec<VariableLen> = vec![
        VariableLen {
            a: 0,
            b: vec![],
            c: 0,
        },
        VariableLen {
            a: 1,
            b: vec![0],
            c: 1,
        },
        VariableLen {
            a: 1,
            b: vec![0, 1, 2],
            c: 1,
        },
    ];

    let expected_encodings = vec![
        //   00..................................09
        //  | u16--| vec offset-----| u32------------| vec payload --------|
        vec![00, 00, 10, 00, 00, 00, 00, 00, 00, 00],
        vec![01, 00, 10, 00, 00, 00, 01, 00, 00, 00, 00, 00],
        vec![
            01, 00, 10, 00, 00, 00, 01, 00, 00, 00, 00, 00, 01, 00, 02, 00,
        ],
    ];

    for i in 0..items.len() {
        assert_eq!(
            items[i].as_ssz_bytes(),
            expected_encodings[i],
            "Failed on {}",
            i
        );
    }
}

#[test]
fn vec_of_variable_len_struct() {
    let items: Vec<VariableLen> = vec![
        VariableLen {
            a: 0,
            b: vec![],
            c: 0,
        },
        VariableLen {
            a: 255,
            b: vec![0, 1, 2, 3],
            c: 99,
        },
        VariableLen {
            a: 255,
            b: vec![0],
            c: 99,
        },
        VariableLen {
            a: 50,
            b: vec![0],
            c: 0,
        },
    ];

    round_trip(items);
}
*/
