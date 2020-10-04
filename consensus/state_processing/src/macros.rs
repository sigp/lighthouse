macro_rules! verify {
    ($condition: expr, $result: expr) => {
        if !$condition {
            return Err(crate::per_block_processing::errors::BlockOperationError::invalid($result));
        }
    };
}

macro_rules! block_verify {
    ($condition: expr, $result: expr) => {
        if !$condition {
            return Err($result);
        }
    };
}
