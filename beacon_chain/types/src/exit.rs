use bls::AggregateSignature;

#[derive(Debug, PartialEq, Clone)]
pub struct Exit {
    pub slot: u64,
    pub validator_index: u32,
    pub signature: AggregateSignature,
}
