use crate::*;
use rand::RngCore;
use ssz_types::typenum::Unsigned;

mod address;
mod aggregate_signature;
mod bitfield;
mod hash256;
mod public_key;
mod public_key_bytes;
mod secret_key;
mod signature;
mod signature_bytes;

pub trait TestRandom {
    fn random_for_test(rng: &mut impl RngCore) -> Self;
}

impl TestRandom for bool {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        (rng.next_u32() % 2) == 1
    }
}

impl TestRandom for u64 {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        rng.next_u64()
    }
}

impl TestRandom for u32 {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        rng.next_u32()
    }
}

impl TestRandom for usize {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        rng.next_u32() as usize
    }
}

impl<U> TestRandom for Vec<U>
where
    U: TestRandom,
{
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let mut output = vec![];

        for _ in 0..(usize::random_for_test(rng) % 4) {
            output.push(<U>::random_for_test(rng));
        }

        output
    }
}

impl<T, N: Unsigned> TestRandom for FixedVector<T, N>
where
    T: TestRandom + Default,
{
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let mut output = vec![];

        for _ in 0..(usize::random_for_test(rng) % std::cmp::min(4, N::to_usize())) {
            output.push(<T>::random_for_test(rng));
        }

        output.into()
    }
}

impl<T, N: Unsigned> TestRandom for VariableList<T, N>
where
    T: TestRandom,
{
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let mut output = vec![];

        if N::to_usize() != 0 {
            for _ in 0..(usize::random_for_test(rng) % std::cmp::min(4, N::to_usize())) {
                output.push(<T>::random_for_test(rng));
            }
        }

        output.into()
    }
}

macro_rules! impl_test_random_for_u8_array {
    ($len: expr) => {
        impl TestRandom for [u8; $len] {
            fn random_for_test(rng: &mut impl RngCore) -> Self {
                let mut bytes = [0; $len];
                rng.fill_bytes(&mut bytes);
                bytes
            }
        }
    };
}

impl_test_random_for_u8_array!(4);
impl_test_random_for_u8_array!(32);
impl_test_random_for_u8_array!(48);
impl_test_random_for_u8_array!(96);
