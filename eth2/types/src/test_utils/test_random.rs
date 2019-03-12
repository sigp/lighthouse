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
        vec![
            <U>::random_for_test(rng),
            <U>::random_for_test(rng),
            <U>::random_for_test(rng),
        ]
    }
}
