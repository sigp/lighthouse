use rand::RngCore;

mod address;
mod aggregate_signature;
mod bitfield;
mod hash256;
mod public_key;
mod secret_key;
mod signature;

pub trait TestRandom<T>
where
    T: RngCore,
{
    fn random_for_test(rng: &mut T) -> Self;
}

impl<T: RngCore> TestRandom<T> for bool {
    fn random_for_test(rng: &mut T) -> Self {
        (rng.next_u32() % 2) == 1
    }
}

impl<T: RngCore> TestRandom<T> for u64 {
    fn random_for_test(rng: &mut T) -> Self {
        rng.next_u64()
    }
}

impl<T: RngCore> TestRandom<T> for u32 {
    fn random_for_test(rng: &mut T) -> Self {
        rng.next_u32()
    }
}

impl<T: RngCore> TestRandom<T> for usize {
    fn random_for_test(rng: &mut T) -> Self {
        rng.next_u32() as usize
    }
}

impl<T: RngCore, U> TestRandom<T> for Vec<U>
where
    U: TestRandom<T>,
{
    fn random_for_test(rng: &mut T) -> Self {
        let mut output = vec![];

        for _ in 0..(usize::random_for_test(rng) % 4) {
            output.push(<U>::random_for_test(rng));
        }

        output
    }
}

macro_rules! impl_test_random_for_u8_array {
    ($len: expr) => {
        impl<T: RngCore> TestRandom<T> for [u8; $len] {
            fn random_for_test(rng: &mut T) -> Self {
                let mut bytes = [0; $len];
                rng.fill_bytes(&mut bytes);
                bytes
            }
        }
    };
}

impl_test_random_for_u8_array!(4);
