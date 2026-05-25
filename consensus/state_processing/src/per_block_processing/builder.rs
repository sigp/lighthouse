use types::{builder::BuilderIndex, consts::gloas::BUILDER_INDEX_FLAG};

pub fn is_builder_index(validator_index: u64) -> bool {
    validator_index & BUILDER_INDEX_FLAG != 0
}

pub fn convert_builder_index_to_validator_index(builder_index: BuilderIndex) -> u64 {
    builder_index | BUILDER_INDEX_FLAG
}

pub fn convert_validator_index_to_builder_index(validator_index: u64) -> BuilderIndex {
    validator_index & !BUILDER_INDEX_FLAG
}
