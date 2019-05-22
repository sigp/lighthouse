#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// The value in the test didn't match our value.
    NotEqual(String),
    /// The test specified a failure and we did not experience one.
    DidntFail(String),
    /// Failed to parse the test (internal error).
    FailedToParseTest(String),
}
