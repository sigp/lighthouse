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

macro_rules! safe_add_assign {
    ($a: expr, $b: expr) => {
        $a = $a.saturating_add($b);
    };
}
macro_rules! safe_sub_assign {
    ($a: expr, $b: expr) => {
        $a = $a.saturating_sub($b);
    };
}
