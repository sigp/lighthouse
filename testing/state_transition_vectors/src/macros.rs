/// Provides:
///
/// - `fn vectors()`: allows for getting a `Vec<TestVector>` of all vectors for exporting.
/// - `mod tests`: runs all the test vectors locally.
macro_rules! vectors_and_tests {
    ($($name: ident, $test: expr),*) => {
        pub fn vectors() -> Vec<TestVector> {
            let mut vec = vec![];

            $(
                vec.push($test.test_vector(stringify!($name).into()));
            )*

            vec
        }

        #[cfg(all(test, not(debug_assertions)))]
        mod tests {
            use super::*;
            $(
                #[test]
                fn $name() {
                    $test.run();
                }
            )*
        }
    };
}
