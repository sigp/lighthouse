#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// The value in the test didn't match our value.
    NotEqual(String),
    /// The test specified a failure and we did not experience one.
    DidntFail(String),
    /// Failed to parse the test (internal error).
    FailedToParseTest(String),
}

impl Error {
    pub fn name(&self) -> &str {
        match self {
            Error::NotEqual(_) => "NotEqual",
            Error::DidntFail(_) => "DidntFail",
            Error::FailedToParseTest(_) => "FailedToParseTest",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Error::NotEqual(m) => m.as_str(),
            Error::DidntFail(m) => m.as_str(),
            Error::FailedToParseTest(m) => m.as_str(),
        }
    }
}
