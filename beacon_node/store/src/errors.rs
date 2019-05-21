use ssz::DecodeError;

#[derive(Debug, PartialEq)]
pub enum Error {
    SszDecodeError(DecodeError),
    DBError { message: String },
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Error {
        Error::SszDecodeError(e)
    }
}

impl From<DBError> for Error {
    fn from(e: DBError) -> Error {
        Error::DBError { message: e.message }
    }
}

#[derive(Debug)]
pub struct DBError {
    pub message: String,
}

impl DBError {
    pub fn new(message: String) -> Self {
        Self { message }
    }
}
