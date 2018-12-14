use super::deposit_parameters::DepositParameters;

pub struct DepositData {
    pub deposit_parameter: DepositInput,
    pub value: u64,
    pub timestamp: u64
}
