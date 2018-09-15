// Collection of custom errors 

#[derive(Debug,PartialEq)]
pub enum AttestationValidationError { 
    SlotTooHigh,
    SlotTooLow(String),
    IncorrectBitField,
    NonZeroTrailingBits,
    AggregateSignatureFail
}


