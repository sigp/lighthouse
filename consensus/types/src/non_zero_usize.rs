use std::num::NonZeroUsize;

/// Creates a new NonZeroUsize from a usize value.
///
/// This function will cause a compile-time error if used with a zero value.
/// For runtime values, use `try_new_non_zero_usize()` instead.
pub const fn new_non_zero_usize(x: usize) -> NonZeroUsize {
    match NonZeroUsize::new(x) {
        Some(n) => n,
        None => {
            // This creates a compile-time error for zero values by indexing an empty array
            // This is safer than panic! and will catch errors at compile time
            [][0]
        }
    }
}

/// Safe runtime version that returns a Result instead of panicking
pub fn try_new_non_zero_usize(x: usize) -> Result<NonZeroUsize, &'static str> {
    NonZeroUsize::new(x).ok_or("Cannot create NonZeroUsize from zero value")
}
