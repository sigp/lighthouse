use error_chain::error_chain;

error_chain! {
   links  { }

   errors {
    SystemTimeError(t: String ) {
        description("Error reading system time"),
        display("SystemTimeError: '{}'", t)
    }
   }
}

#[derive(PartialEq, Debug, Clone)]
pub enum ValidatorError {
    InvalidConfiguration(String),
    BeaconNodeError(BeaconNodeError),
    SignatureError(String),
    SlashingError(String),
    SystemError(String),
}

impl From<url::ParseError> for ValidatorError {
    fn from(e: url::ParseError) -> ValidatorError {
        ValidatorError::InvalidConfiguration(format!("Invalid URL: {:?}", e))
    }
}

impl From<BeaconNodeError> for ValidatorError {
    fn from(e: BeaconNodeError) -> ValidatorError {
        ValidatorError::BeaconNodeError(e)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum BeaconNodeError {
    RemoteFailure(String),
    DecodeFailure(String),
}

#[derive(Debug, PartialEq, Clone)]
pub enum PublishOutcome {
    Valid,
    Invalid(String),
    Rejected(String),
}
