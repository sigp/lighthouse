#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// The value in the test didn't match our value.
    NotEqual(String),
    /// The test specified a failure and we did not experience one.
    DidntFail(String),
    /// Failed to parse the test (internal error).
    FailedToParseTest(String),
    /// Test case contained invalid BLS data.
    InvalidBLSInput(String),
    /// Skipped the test because the BLS setting was mismatched.
    SkippedBls,
    /// Skipped the test because it's known to fail.
    SkippedKnownFailure,
    /// The test failed due to some internal error preventing the test from running.
    InternalError(String),
}

impl Error {
    pub fn name(&self) -> &str {
        match self {
            Error::NotEqual(_) => "NotEqual",
            Error::DidntFail(_) => "DidntFail",
            Error::FailedToParseTest(_) => "FailedToParseTest",
            Error::InvalidBLSInput(_) => "InvalidBLSInput",
            Error::SkippedBls => "SkippedBls",
            Error::SkippedKnownFailure => "SkippedKnownFailure",
            Error::InternalError(_) => "InternalError",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Error::NotEqual(m) => m.as_str(),
            Error::DidntFail(m) => m.as_str(),
            Error::FailedToParseTest(m) => m.as_str(),
            Error::InvalidBLSInput(m) => m.as_str(),
            Error::InternalError(m) => m.as_str(),
            _ => self.name(),
        }
    }

    pub fn is_skipped(&self) -> bool {
        matches!(self, Error::SkippedBls | Error::SkippedKnownFailure)
    }
}
