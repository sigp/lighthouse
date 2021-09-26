use ethereum_types::H256;
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};

mod round_trip {
    use super::*;

    fn round_trip<T: Encode + Decode + std::fmt::Debug + PartialEq>(items: Vec<T>) {
        for item in items {
            let encoded = &item.as_ssz_bytes();
            assert_eq!(item.ssz_bytes_len(), encoded.len());
            assert_eq!(T::from_ssz_bytes(encoded), Ok(item));
        }
    }

    #[test]
    fn bool() {
        let items: Vec<bool> = vec![true, false];

        round_trip(items);
    }

    #[test]
    fn u8_array_4() {
        let items: Vec<[u8; 4]> = vec![[0, 0, 0, 0], [1, 0, 0, 0], [1, 2, 3, 4], [1, 2, 0, 4]];

        round_trip(items);
    }

    #[test]
    fn h256() {
        let items: Vec<H256> = vec![H256::zero(), H256::from([1; 32]), H256::random()];

        round_trip(items);
    }

    #[test]
    fn vec_of_h256() {
        let items: Vec<Vec<H256>> = vec![
            vec![],
            vec![H256::zero(), H256::from([1; 32]), H256::random()],
        ];

        round_trip(items);
    }

    #[test]
    fn vec_u16() {
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
    fn vec_of_vec_u16() {
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
    #[allow(clippy::zero_prefixed_literal)]
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
    fn fixed_len_excess_bytes() {
        let fixed = FixedLen { a: 1, b: 2, c: 3 };

        let mut bytes = fixed.as_ssz_bytes();
        bytes.append(&mut vec![0]);

        assert_eq!(
            FixedLen::from_ssz_bytes(&bytes),
            Err(DecodeError::InvalidByteLength {
                len: 15,
                expected: 14,
            })
        );
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
    #[allow(clippy::zero_prefixed_literal)]
    fn offset_into_fixed_bytes() {
        let bytes = vec![
            //  1   2   3   4   5   6   7   8   9   10  11  12  13  14  15
            //      | offset        | u32           | variable
            01, 00, 09, 00, 00, 00, 01, 00, 00, 00, 00, 00, 01, 00, 02, 00,
        ];

        assert_eq!(
            VariableLen::from_ssz_bytes(&bytes),
            Err(DecodeError::OffsetIntoFixedPortion(9))
        );
    }

    #[test]
    fn variable_len_excess_bytes() {
        let variable = VariableLen {
            a: 1,
            b: vec![2],
            c: 3,
        };

        let mut bytes = variable.as_ssz_bytes();
        bytes.append(&mut vec![0]);

        // The error message triggered is not so helpful, it's caught by a side-effect. Just
        // checking there is _some_ error is fine.
        assert!(VariableLen::from_ssz_bytes(&bytes).is_err());
    }

    #[test]
    #[allow(clippy::zero_prefixed_literal)]
    fn first_offset_skips_byte() {
        let bytes = vec![
            //  1   2   3   4   5   6   7   8   9   10  11  12  13  14  15
            //      | offset        | u32           | variable
            01, 00, 11, 00, 00, 00, 01, 00, 00, 00, 00, 00, 01, 00, 02, 00,
        ];

        assert_eq!(
            VariableLen::from_ssz_bytes(&bytes),
            Err(DecodeError::OffsetSkipsVariableBytes(11))
        );
    }

    #[test]
    #[allow(clippy::zero_prefixed_literal)]
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

    #[derive(Debug, PartialEq, Encode, Decode)]
    struct ThreeVariableLen {
        a: u16,
        b: Vec<u16>,
        c: Vec<u16>,
        d: Vec<u16>,
    }

    #[test]
    fn three_variable_len() {
        let vec: Vec<ThreeVariableLen> = vec![ThreeVariableLen {
            a: 42,
            b: vec![0],
            c: vec![1],
            d: vec![2],
        }];

        round_trip(vec);
    }

    #[test]
    #[allow(clippy::zero_prefixed_literal)]
    fn offsets_decreasing() {
        let bytes = vec![
            //  1   2   3   4   5   6   7   8   9   10  11  12  13  14  15
            //      | offset        | offset        | offset        | variable
            01, 00, 14, 00, 00, 00, 15, 00, 00, 00, 14, 00, 00, 00, 00, 00,
        ];

        assert_eq!(
            ThreeVariableLen::from_ssz_bytes(&bytes),
            Err(DecodeError::OffsetsAreDecreasing(14))
        );
    }

    #[test]
    fn tuple_u8_u16() {
        let vec: Vec<(u8, u16)> = vec![
            (0, 0),
            (0, 1),
            (1, 0),
            (u8::max_value(), u16::max_value()),
            (0, u16::max_value()),
            (u8::max_value(), 0),
            (42, 12301),
        ];

        round_trip(vec);
    }

    #[test]
    fn tuple_vec_vec() {
        let vec: Vec<(u64, Vec<u8>, Vec<Vec<u16>>)> = vec![
            (0, vec![], vec![vec![]]),
            (99, vec![101], vec![vec![], vec![]]),
            (
                42,
                vec![12, 13, 14],
                vec![vec![99, 98, 97, 96], vec![42, 44, 46, 48, 50]],
            ),
        ];

        round_trip(vec);
    }
}

mod derive_macro {
    use ssz::{Decode, Encode};
    use ssz_derive::{Decode, Encode};
    use std::fmt::Debug;

    fn assert_encode<T: Encode>(item: &T, bytes: &[u8]) {
        assert_eq!(item.as_ssz_bytes(), bytes);
    }

    fn assert_encode_decode<T: Encode + Decode + PartialEq + Debug>(item: &T, bytes: &[u8]) {
        assert_encode(item, bytes);
        assert_eq!(T::from_ssz_bytes(bytes).unwrap(), *item);
    }

    #[derive(PartialEq, Debug, Encode, Decode)]
    #[ssz(enum_behaviour = "union")]
    enum TwoFixedUnion {
        U8(u8),
        U16(u16),
    }

    #[derive(PartialEq, Debug, Encode, Decode)]
    struct TwoFixedUnionStruct {
        a: TwoFixedUnion,
    }

    #[test]
    fn two_fixed_union() {
        let eight = TwoFixedUnion::U8(1);
        let sixteen = TwoFixedUnion::U16(1);

        assert_encode_decode(&eight, &[0, 1]);
        assert_encode_decode(&sixteen, &[1, 1, 0]);

        assert_encode_decode(&TwoFixedUnionStruct { a: eight }, &[4, 0, 0, 0, 0, 1]);
        assert_encode_decode(&TwoFixedUnionStruct { a: sixteen }, &[4, 0, 0, 0, 1, 1, 0]);
    }

    #[derive(PartialEq, Debug, Encode, Decode)]
    struct VariableA {
        a: u8,
        b: Vec<u8>,
    }

    #[derive(PartialEq, Debug, Encode, Decode)]
    struct VariableB {
        a: Vec<u8>,
        b: u8,
    }

    #[derive(PartialEq, Debug, Encode)]
    #[ssz(enum_behaviour = "transparent")]
    enum TwoVariableTrans {
        A(VariableA),
        B(VariableB),
    }

    #[derive(PartialEq, Debug, Encode)]
    struct TwoVariableTransStruct {
        a: TwoVariableTrans,
    }

    #[derive(PartialEq, Debug, Encode, Decode)]
    #[ssz(enum_behaviour = "union")]
    enum TwoVariableUnion {
        A(VariableA),
        B(VariableB),
    }

    #[derive(PartialEq, Debug, Encode, Decode)]
    struct TwoVariableUnionStruct {
        a: TwoVariableUnion,
    }

    #[test]
    fn two_variable_trans() {
        let trans_a = TwoVariableTrans::A(VariableA {
            a: 1,
            b: vec![2, 3],
        });
        let trans_b = TwoVariableTrans::B(VariableB {
            a: vec![1, 2],
            b: 3,
        });

        assert_encode(&trans_a, &[1, 5, 0, 0, 0, 2, 3]);
        assert_encode(&trans_b, &[5, 0, 0, 0, 3, 1, 2]);

        assert_encode(
            &TwoVariableTransStruct { a: trans_a },
            &[4, 0, 0, 0, 1, 5, 0, 0, 0, 2, 3],
        );
        assert_encode(
            &TwoVariableTransStruct { a: trans_b },
            &[4, 0, 0, 0, 5, 0, 0, 0, 3, 1, 2],
        );
    }

    #[test]
    fn two_variable_union() {
        let union_a = TwoVariableUnion::A(VariableA {
            a: 1,
            b: vec![2, 3],
        });
        let union_b = TwoVariableUnion::B(VariableB {
            a: vec![1, 2],
            b: 3,
        });

        assert_encode_decode(&union_a, &[0, 1, 5, 0, 0, 0, 2, 3]);
        assert_encode_decode(&union_b, &[1, 5, 0, 0, 0, 3, 1, 2]);

        assert_encode_decode(
            &TwoVariableUnionStruct { a: union_a },
            &[4, 0, 0, 0, 0, 1, 5, 0, 0, 0, 2, 3],
        );
        assert_encode_decode(
            &TwoVariableUnionStruct { a: union_b },
            &[4, 0, 0, 0, 1, 5, 0, 0, 0, 3, 1, 2],
        );
    }

    #[derive(PartialEq, Debug, Encode, Decode)]
    #[ssz(enum_behaviour = "union")]
    enum TwoVecUnion {
        A(Vec<u8>),
        B(Vec<u8>),
    }

    #[test]
    fn two_vec_union() {
        assert_encode_decode(&TwoVecUnion::A(vec![]), &[0]);
        assert_encode_decode(&TwoVecUnion::B(vec![]), &[1]);

        assert_encode_decode(&TwoVecUnion::A(vec![0]), &[0, 0]);
        assert_encode_decode(&TwoVecUnion::B(vec![0]), &[1, 0]);

        assert_encode_decode(&TwoVecUnion::A(vec![0, 1]), &[0, 0, 1]);
        assert_encode_decode(&TwoVecUnion::B(vec![0, 1]), &[1, 0, 1]);
    }
}
