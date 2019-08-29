use types::EthSpec;

pub use case_result::CaseResult;
pub use cases::Case;
pub use error::Error;
pub use handler::*;
pub use yaml_decode::YamlDecode;

mod bls_setting;
mod case_result;
mod cases;
mod error;
mod handler;
mod results;
mod type_name;
mod yaml_decode;

/// Defined where an object can return the results of some test(s) adhering to the Ethereum
/// Foundation testing format.
pub trait EfTest {
    /// Returns the results of executing one or more tests.
    fn test_results(&self) -> Vec<CaseResult>;
}
