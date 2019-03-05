#[macro_use]
macro_rules! ensure {
    ($condition: expr, $result: ident) => {
        if !$condition {
            return Err(Error::Invalid(Invalid::$result));
        }
    };
}
