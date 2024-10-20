#[macro_export]
macro_rules! crit {
    ($($arg:tt)*) => {
        tracing::error!(error_type = "crit",  $($arg)*);
    };
}
