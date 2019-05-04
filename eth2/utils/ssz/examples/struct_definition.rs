use ssz::{Decodable, DecodeError, Encodable, SszDecoderBuilder, SszStream};

#[derive(Debug, PartialEq)]
pub struct Foo {
    a: u16,
    b: Vec<u8>,
    c: u16,
}

impl Encodable for Foo {
    fn is_ssz_fixed_len() -> bool {
        <u16 as Encodable>::is_ssz_fixed_len() && <Vec<u16> as Encodable>::is_ssz_fixed_len()
    }

    fn as_ssz_bytes(&self) -> Vec<u8> {
        let mut stream = SszStream::new();

        stream.append(&self.a);
        stream.append(&self.b);
        stream.append(&self.c);

        stream.drain()
    }
}

impl Decodable for Foo {
    fn is_ssz_fixed_len() -> bool {
        <u16 as Decodable>::is_ssz_fixed_len() && <Vec<u16> as Decodable>::is_ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);

        builder.register_type::<u16>()?;
        builder.register_type::<Vec<u8>>()?;
        builder.register_type::<u16>()?;

        let mut decoder = builder.build()?;

        Ok(Self {
            a: decoder.decode_next()?,
            b: decoder.decode_next()?,
            c: decoder.decode_next()?,
        })
    }
}

fn main() {
    let foo = Foo {
        a: 42,
        b: vec![0, 1, 2, 3],
        c: 11,
    };

    let bytes = vec![42, 0, 8, 0, 0, 0, 11, 0, 0, 1, 2, 3];

    assert_eq!(foo.as_ssz_bytes(), bytes);

    let decoded_foo = Foo::from_ssz_bytes(&bytes).unwrap();

    assert_eq!(foo, decoded_foo);
}
