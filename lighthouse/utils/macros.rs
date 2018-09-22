#[macro_export]
macro_rules! assert_error {
    ($exp: expr, $err: expr) => {
        if !$exp {
            return Err($err);
        }
    }
}


