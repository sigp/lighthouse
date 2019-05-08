use crate::*;
use fixed_len_vec::typenum::{Unsigned, U8192};

pub trait BeaconStateTypes {
    type NumLatestRandaoMixes: Unsigned + Clone + Sync + Send;
}

#[derive(Clone, PartialEq, Debug)]
pub struct FoundationStateParams;

impl BeaconStateTypes for FoundationStateParams {
    type NumLatestRandaoMixes = U8192;
}

pub type FoundationBeaconState = BeaconState<FoundationStateParams>;

#[derive(Clone, PartialEq, Debug)]
pub struct FewValidatorsStateParams;

impl BeaconStateTypes for FewValidatorsStateParams {
    type NumLatestRandaoMixes = U8192;
}

pub type FewValidatorsBeaconState = BeaconState<FewValidatorsStateParams>;
