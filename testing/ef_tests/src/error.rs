#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// The value in the test didn't match our value.
    NotEqual(String),
    /// The test specified a failure and we did not experience one.
    DidntFail(String),
    /// Failed to parse the test (internal error).
    FailedToParseTest(String),
    /// Skipped the test because the BLS setting was mismatched.
    SkippedBls,
    /// Skipped the test because it's known to fail.
    SkippedKnownFailure,
}

impl Error {
    pub fn name(&self) -> &str {
        match self {
            Error::NotEqual(_) => "NotEqual",
            Error::DidntFail(_) => "DidntFail",
            Error::FailedToParseTest(_) => "FailedToParseTest",
            Error::SkippedBls => "SkippedBls",
            Error::SkippedKnownFailure => "SkippedKnownFailure",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Error::NotEqual(m) => m.as_str(),
            Error::DidntFail(m) => m.as_str(),
            Error::FailedToParseTest(m) => m.as_str(),
            _ => self.name(),
        }
    }

    pub fn is_skipped(&self) -> bool {
        match self {
            Error::SkippedBls | Error::SkippedKnownFailure => true,
            _ => false,
        }
    }
}
