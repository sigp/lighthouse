macro_rules! try_future {
    ($expr:expr) => {
        match $expr {
            core::result::Result::Ok(val) => val,
            core::result::Result::Err(err) => return Err(std::convert::From::from(err)),
        }
    };
    ($expr:expr,) => {
        $crate::try_future!($expr)
    };
}
