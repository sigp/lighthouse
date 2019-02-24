use crate::hash;

pub fn merkle_root(values: &[Vec<u8>]) -> Vec<u8> {
    let values_len = values.len();
    let mut o: Vec<Vec<u8>> = vec![vec![0]; values_len];

    o.append(&mut values.to_vec());

    for i in (0..values_len).rev() {
        let mut current_value: Vec<u8> = o[i * 2].clone();
        current_value.append(&mut o[i * 2 + 1].clone());

        o[i] = hash(&current_value[..]);
    }

    o[1].clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root() {
        let input = vec![
            "a".as_bytes().to_vec(),
            "b".as_bytes().to_vec(),
            "c".as_bytes().to_vec(),
            "d".as_bytes().to_vec()
        ];

        let output = merkle_root(&input[..]);

        // merkle root of [[a],[b],[c],[d]]
        let expected = &[
            183, 91, 96, 122, 144, 174, 84, 92, 97, 156, 140, 192, 66, 221, 55, 229,
            234, 48, 118, 7, 61, 207, 39, 125, 150, 32, 94, 90, 19, 88, 122, 163,
        ];
        assert_eq!(expected, output.as_slice());
    }
}
