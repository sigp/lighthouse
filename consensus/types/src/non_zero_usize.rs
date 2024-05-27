use std::num::NonZeroUsize;

pub const fn new_non_zero_usize(x: usize) -> NonZeroUsize {
    match NonZeroUsize::new(x) {
        Some(n) => n,
        None => panic!("Expected a non zero usize."),
    }
}
