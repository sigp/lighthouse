use ssz::{Decodable, Encodable};

fn round_trip<T: Encodable + Decodable + std::fmt::Debug + PartialEq>(item: T) {
    let encoded = &item.as_ssz_bytes();
    dbg!(encoded);
    assert_eq!(T::from_ssz_bytes(&encoded), Ok(item));
}

#[test]
fn vec_u16_round_trip() {
    round_trip::<Vec<u16>>(vec![]);
    round_trip::<Vec<u16>>(vec![255]);
    round_trip::<Vec<u16>>(vec![0, 1, 2]);
    round_trip::<Vec<u16>>(vec![100; 64]);
}

#[test]
fn vec_of_vec_u16_round_trip() {
    round_trip::<Vec<Vec<u16>>>(vec![]);
    round_trip::<Vec<Vec<u16>>>(vec![vec![]]);
    round_trip::<Vec<Vec<u16>>>(vec![vec![1, 2, 3]]);
    round_trip::<Vec<Vec<u16>>>(vec![vec![], vec![]]);
    round_trip::<Vec<Vec<u16>>>(vec![vec![], vec![1, 2, 3]]);
    round_trip::<Vec<Vec<u16>>>(vec![vec![1, 2, 3], vec![1, 2, 3]]);
    round_trip::<Vec<Vec<u16>>>(vec![vec![1, 2, 3], vec![], vec![1, 2, 3]]);
    round_trip::<Vec<Vec<u16>>>(vec![vec![], vec![], vec![1, 2, 3]]);
    round_trip::<Vec<Vec<u16>>>(vec![vec![], vec![1], vec![1, 2, 3]]);
    round_trip::<Vec<Vec<u16>>>(vec![vec![], vec![1], vec![1, 2, 3]]);
}
