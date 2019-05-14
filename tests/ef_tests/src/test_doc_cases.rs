use super::*;

mod ssz_generic;
// mod ssz_static;

pub use ssz_generic::*;

#[derive(Debug, Deserialize)]
pub struct TestDocCases<T> {
    pub test_cases: Vec<T>,
}
