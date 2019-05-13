use ssz::Encodable;
use ssz_derive::Encode;

#[derive(Debug, PartialEq, Encode)]
pub struct Foo {
    a: u16,
    b: Vec<u8>,
    c: u16,
}

#[test]
fn encode() {
    let foo = Foo {
        a: 42,
        b: vec![0, 1, 2, 3],
        c: 11,
    };

    let bytes = vec![42, 0, 8, 0, 0, 0, 11, 0, 0, 1, 2, 3];

    assert_eq!(foo.as_ssz_bytes(), bytes);
}
