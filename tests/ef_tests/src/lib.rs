use error::Error;
use ethereum_types::{U128, U256};
use serde_derive::Deserialize;
use ssz::Decode;
use std::fmt::Debug;
use test_decode::TestDecode;

pub use crate::error::*;
pub use crate::ssz_generic::*;

mod error;
mod ssz_generic;
mod ssz_static;
mod test_decode;

#[derive(Debug, Deserialize)]
pub struct TestDoc<T> {
    pub title: String,
    pub summary: String,
    pub forks_timeline: String,
    pub forks: Vec<String>,
    pub config: String,
    pub runner: String,
    pub handler: String,
    pub test_cases: Vec<T>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct TestCaseResult<T> {
    pub case_index: usize,
    pub case: T,
    pub result: Result<(), Error>,
}

pub trait Test<T> {
    fn test(&self) -> Vec<TestCaseResult<T>>;
}

/// Compares `result` with `expected`.
///
/// If `expected.is_none()` then `result` is expected to be `Err`. Otherwise, `T` in `result` and
/// `expected` must be equal.
fn compare_result<T, E>(result: Result<T, E>, expected: Option<T>) -> Result<(), Error>
where
    T: PartialEq<T> + Debug,
    E: Debug,
{
    match (result, expected) {
        // Pass: The should have failed and did fail.
        (Err(_), None) => Ok(()),
        // Fail: The test failed when it should have produced a result (fail).
        (Err(e), Some(expected)) => Err(Error::NotEqual(format!(
            "Got {:?} expected {:?}",
            e, expected
        ))),
        // Fail: The test produced a result when it should have failed (fail).
        (Ok(result), None) => Err(Error::DidntFail(format!("Got {:?}", result))),
        // Potential Pass: The test should have produced a result, and it did.
        (Ok(result), Some(expected)) => {
            if result == expected {
                Ok(())
            } else {
                Err(Error::NotEqual(format!(
                    "Got {:?} expected {:?}",
                    result, expected
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
