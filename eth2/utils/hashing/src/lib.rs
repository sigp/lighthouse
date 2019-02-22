use tiny_keccak::Keccak;

pub fn hash(input: &[u8]) -> Vec<u8> {
    let mut keccak = Keccak::new_keccak256();
    keccak.update(input);
    let mut result = vec![0; 32];
    keccak.finalize(result.as_mut_slice());
    result
}

pub fn merkle_root(values: &[Vec<u8>]) -> Vec<u8> {
    let values_len = values.len();
    let mut o: Vec<Vec<u8>> = vec![vec![0]; values_len];

    o.append(&mut values.to_vec());

    println!("o {:?}", o);

    for i in (0..values_len).rev() {
        let mut current_value: Vec<u8> = o[i * 2].clone();
        current_value.append(&mut o[i * 2 + 1].clone());

        o[i] = hash(&current_value[..]);
        println!("i {:?}", i);
        print!("   ");
        println!("o[i * 2] {} -- {:?}", i * 2, o[i * 2]);
        print!("   ");
        println!("o[i * 2 + 1] {} -- {:?}", i * 2 + 1, o[i * 2 + 1]);
    }

//    println!("{:?}", o);

    o[1].clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::From;

    #[test]
    fn test_hashing() {
        let input: Vec<u8> = From::from("hello");

        let output = hash(input.as_ref());
        let expected = &[
            0x1c, 0x8a, 0xff, 0x95, 0x06, 0x85, 0xc2, 0xed, 0x4b, 0xc3, 0x17, 0x4f, 0x34, 0x72,
            0x28, 0x7b, 0x56, 0xd9, 0x51, 0x7b, 0x9c, 0x94, 0x81, 0x27, 0x31, 0x9a, 0x09, 0xa7,
            0xa3, 0x6d, 0xea, 0xc8,
        ];

        println!("{:?}", expected);
        println!("{:?}", output);
        assert_eq!(expected, output.as_slice());
    }

    #[test]
    fn test_merkle_root() {
        let mut input = vec![
            "a".as_bytes().to_vec(),
            "b".as_bytes().to_vec(),
            "c".as_bytes().to_vec(),
            "d".as_bytes().to_vec()
        ];

        let output = merkle_root(&input[..]);

        let mut leaf_1_2: Vec<u8> = input[0].clone(); // a
        leaf_1_2.append(&mut input[1].clone()); // b

        let mut leaf_3_4: Vec<u8> = input[2].clone(); // c
        leaf_3_4.append(&mut input[3].clone()); // d

        let node_1 = hash(&leaf_1_2[..]);
        let node_2 = hash(&leaf_3_4[..]);

        let mut root: Vec<u8> = node_1.clone(); // ab
        root.append(&mut node_2.clone()); // cd

        let mr = hash(&root[..]);

        let expected = &[183, 91, 96, 122, 144, 174, 84, 92, 97, 156, 140, 192, 66, 221, 55, 229, 234, 48, 118, 7, 61, 207, 39, 125, 150, 32, 94, 90, 19, 88, 122, 163];

        print!("    ");
        print!("    ");
        print!("    ");
        print!("    ");
        print!("    ");
        print!("origional input");
        println!("{:?}", input);
        print!("NODE #1 HASH                              ");
        println!("{:?}", node_1);
        print!("NODE #2 HASH                              ");
        println!("{:?}", node_2);
        print!("ROOT HASH                              ");
        println!("{:?}", root);
        print!("                                                                                                                        ");
        println!("{:?}", expected);

        assert_eq!(expected, output.as_slice());

    }
}
