#![cfg(test)]
use eth2_interop_keypairs::{be_private_key, keypair};
use num_bigint::BigUint;

#[test]
fn reference_private_keys() {
    // Sourced from:
    //
    // https://github.com/ethereum/eth2.0-pm/blob/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start/keygen_test_vector.yaml
    let reference = [
        "16808672146709759238327133555736750089977066230599028589193936481731504400486",
        "37006103240406073079686739739280712467525465637222501547219594975923976982528",
        "22330876536127119444572216874798222843352868708084730796787004036811744442455",
        "17048462031355941381150076874414096388968985457797372268770826099852902060945",
        "28647806952216650698330424381872693846361470773871570637461872359310549743691",
        "2416304019107052589452838695606585506736351107897780798170812672519914514344",
        "7300215445567548136411883691093515822872548648751398235557229381530420545683",
        "26495790445032093722332687600112008700915252495659977774957922313678954054133",
        "2908643403277969554503670470854573663206729491025062456164283925661321952518",
        "19554639423851580804889717218680781396599791537051606512605582393920758869044",
    ];
    reference.iter().enumerate().for_each(|(i, reference)| {
        let bytes = be_private_key(i);
        let num = BigUint::from_bytes_be(&bytes);
        assert_eq!(&num.to_str_radix(10), reference)
    });
}

#[test]
fn reference_public_keys() {
    // Sourced from:
    //
    // https://github.com/ethereum/eth2.0-pm/blob/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start/keygen_test_vector.yaml
    let reference = [
        "qZp27XeW974i1bfoXe63xWd+iOUR4LM3YY+MTrYTSbS/LRU/ZJ97UzWf6LlKOORM",
        "uJvrxpl2lyajGMjplxvTFxKXxhrqSmV4p6T5S1R9y6W6wWqJEItrah/jaV0ah0oL",
        "o6MrD4tN24PxoKhT2B3XJd/ld9T0w9uOzlLOKwJuyoSBXBp+jpKk3j11VzO/fkqb",
        "iMFB33fNnY16cadcgmxBqcnwPG7hsYDz54UvaigAmd7TUbWNZuZTr45CgWpNj1Mu",
        "gSg7eiDhykYOvZu9dwBdVXNwyrsfmkT1MMTExmIw9nX434tMKBiFGqfXeoDKWkpe",
        "qwvdoPhfhC9DG+rM8SUL8f17pRtBAP1kNktkAf2oW7AGmz5xW1iBloTn/AsQpyo0",
        "mXfxyLcxqNVVgUa/uGyuomQ088WHi1ib8oCkLJFZ5wDp3w5AhilsILAR0ueMJ9Nz",
        "qNTHwneVpyWWExfvWVOnAy7W2Dc524sOinI1PRuLRDlCf376LInKoDzJ8o+Muris",
        "ptMQ27+rmiJFD1mZP4ekzl22Ij87Xx8w0sTscYki1ADgs8d0HejlmWD3JBGg7hCn",
        "mJNBPAAoOj+e2f2YRd2hzqOCKNIlZ/lUHczDV+VKLWpuIEEDySVky8BfSQWsfEk6",
    ];
    reference.iter().enumerate().for_each(|(i, reference)| {
        let pair = keypair(i);
        let reference = base64::decode(reference).expect("Reference should be valid base64");

        assert_eq!(
            reference.len(),
            48,
            "Reference should be 48 bytes (public key size)"
        );

        assert_eq!(pair.pk.as_bytes(), reference);
    });
}
