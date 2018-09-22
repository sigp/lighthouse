// Collection of custom errors

#[derive(Debug,PartialEq)]
pub enum ParameterError {
    IntWrapping,
    OutOfBounds,
    InvalidInput(String),
}
